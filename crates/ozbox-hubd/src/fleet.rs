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
