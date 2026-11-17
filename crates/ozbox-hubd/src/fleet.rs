//! The three seams of sealed key delivery (ADR 0042 section 5), backed for real:
//!
//! * [`EnrolAttestations`]: the key a worker's delivery is sealed to is the one its **enrolment attested** (a registrar signed it,
//!   the worker proved it holds the channel key); never one `main` merely reported.
//! * [`ServiceIssuer`]: ADR 0029's release path for development and staging values. `main`'s secrets service reads the named
//!   values and seals them to the attested key; the hub relays sealed bytes and never holds a value. Production is refused here
//!   in front of the service, and the service refuses it again (decision D2).
//! * [`ServiceDeliveryStore`]: a worker's own secrets service opens a delivery with its delivery key, keeps it in its reserved
//!   store, and deletes it on revoke, task end and loss of the hub. The hub agent never holds a plaintext.

use std::sync::Arc;

use ozbox_core::approval::SignedEnvelope;
use ozbox_core::hub::approvals::{ApprovalService, DecisionBody, ServicePin};
use ozbox_core::hub::approver_sync::SignedApprovers;
use ozbox_core::hub::keys::{
    issuer_guard, Attestations, AttestedKey, DeliveryStore, KeyDelivery, KeyIssuer, ReleaseRequest,
    Released, CODE_ISSUER, CODE_STORE,
};
use serde_json::json;

use crate::daemon::Hubd;
use crate::ops::KeyOps;

/// A worker's attested delivery key, read from the roster enrolment made.
pub struct EnrolAttestations {
    pub hubd: Arc<Hubd>,
}

impl Attestations for EnrolAttestations {
    fn delivery_key(&self, worker: &str) -> Option<AttestedKey> {
        let st = self.hubd.state().ok()?;
        let rec = st.enrol.roster.get(worker)?;
        Some(AttestedKey {
            public: rec.identity.delivery_public.clone(),
            fp: rec.identity.delivery_fp(),
        })
    }
}

/// The release path, through `main`'s secrets service (the supervisor socket).
pub struct ServiceIssuer {
    pub ops: Arc<dyn KeyOps>,
}

impl KeyIssuer for ServiceIssuer {
    fn release(&self, r: &ReleaseRequest<'_>) -> Result<Released, &'static str> {
        // D2 in front of the service; the service refuses again before it reads anything
        issuer_guard(r).map_err(|e| e.code)?;
        let v = self
            .ops
            .call(json!({
                "op": "hub_release",
                "request_id": r.request_id,
                "worker": r.worker,
                "orchestration": r.orchestration,
                "feature": r.feature,
                "env": r.env,
                "names": r.names,
                "to_public": r.to.public,
                "to_fp": r.to.fp,
            }))
            .map_err(|_| CODE_ISSUER)?;
        let sealed = v["sealed"]
            .as_str()
            .and_then(ozbox_core::channel::wire::unhex)
            .ok_or(CODE_ISSUER)?;
        let names: Vec<String> =
            serde_json::from_value(v["names"].clone()).map_err(|_| CODE_ISSUER)?;
        Ok(Released {
            env: v["env"].as_str().unwrap_or_default().to_string(),
            names,
            sealed,
        })
    }
}

/// A worker's service as the hub agent reaches it. `worker` is this worker's name on the channel.
pub struct ServiceDeliveryStore {
    pub ops: Arc<dyn KeyOps>,
    pub worker: String,
}

impl DeliveryStore for ServiceDeliveryStore {
    fn store_delivery(&self, d: &KeyDelivery) -> Result<(), &'static str> {
        self.ops
            .call(json!({
                "op": "hub_store_delivery",
                "request_id": d.request_id,
                "worker": self.worker,
                "orchestration": d.orchestration,
                "feature": d.feature,
                "env": d.env,
                "names": d.names,
                "key_fp": d.key_fp,
                "sealed": ozbox_core::channel::wire::hex(&d.sealed),
            }))
            .map(|_| ())
            .map_err(|_| CODE_STORE)
    }

    fn delete_task(&self, orchestration: &str, feature: &str) {
        let _ = self.ops.call(json!({
            "op": "hub_delivery_delete",
            "orchestration": orchestration,
            "feature": feature,
        }));
    }

    fn delete_all(&self) {
        let _ = self
            .ops
            .call(json!({"op": "hub_delivery_delete", "all": true}));
    }
}

/// A worker's approval service as the hub agent reaches it: the worker's own secrets service on the supervisor's socket, where the
/// request journal and the envelope key live (ADR 0041). The agent holds none of it.
///
/// * `pending` asks for the signed envelopes of the requests pending now; the agent announces them to `main`, which shows a card
///   only if the envelope verifies against the key it pinned at enrolment.
/// * `decide_from_fleet` hands the service a decision `main` relayed. **The service verifies it**, against an approver set only root
///   can write, over a challenge computed from its own ids; the agent only carries it, and an answer it does not understand is a
///   refusal. A service that does not answer (no request journal turned on) decides nothing and announces nothing.
pub struct ServiceApprovals {
    pub ops: Arc<dyn KeyOps>,
}

impl ApprovalService for ServiceApprovals {
    fn pending(&self, _now: u64) -> Vec<SignedEnvelope> {
        self.ops
            .call(json!({"op": "areq_hub_pending"}))
            .ok()
            .and_then(|v| serde_json::from_value(v["envelopes"].clone()).ok())
            .unwrap_or_default()
    }

    fn decide_from_fleet(
        &mut self,
        hub: &str,
        d: &DecisionBody,
        _now: u64,
    ) -> Result<String, String> {
        let v = self
            .ops
            .call(json!({"op": "areq_hub_decide", "hub": hub, "decision": d}))
            .map_err(|e| e.0)?;
        v["state"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| "the approval service's answer is not valid".to_string())
    }

    fn set_approvers(&mut self, s: &SignedApprovers, _now: u64) -> Result<u64, String> {
        let v = self
            .ops
            .call(json!({"op": "areq_hub_take_approvers", "signed": s}))
            .map_err(|e| e.0)?;
        v["seq"]
            .as_u64()
            .ok_or_else(|| "the approval service's answer is not valid".to_string())
    }
}

/// The pin of this box's approval service (its ids and the public half of its envelope key), for enrolment to offer. `None` when
/// the service keeps no request journal: the worker then enrols with no approval service, and nothing it asks is shown as a request.
pub fn service_pin(ops: &dyn KeyOps) -> Option<ServicePin> {
    ops.call(json!({"op": "areq_hub_pin"}))
        .ok()
        .and_then(|v| serde_json::from_value(v["pin"].clone()).ok())
}
