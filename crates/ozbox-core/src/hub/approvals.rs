//! The approval path over the worker channel (ADR 0042 section 8, ADR 0041 section 3.2): a request filed on a worker comes back to
//! `main` as a card, the person decides it once on `main`'s dashboard, and the decision travels back to the worker, whose **own
//! service** verifies it before anything moves.
//!
//! The rule this module keeps is ADR 0044's: **a message can ask and never grant.**
//!
//! * The worker sends `approval.request`: its service's **signed envelope** of a pending request, and nothing else. `main` verifies the
//!   signature against the key it pinned for that worker's service at enrolment, recomputes the digest from the signed subject, and
//!   shows a card only for a pending, unexpired request. An envelope that says "approved" is not a decision: it is refused.
//! * `main` sends `approval.decision`: the request id, the digest, the outcome and, for an approval, the person's **passkey assertion**.
//!   It has no field that grants: the body is read with unknown fields refused, so `"approved": true`, a grant or a token beside it
//!   is refused by the worker's screen before it is held, and nothing in the body is believed except the signed bytes of the
//!   assertion.
//! * The worker's service checks the assertion itself: a credential in the **approver set** pinned on the worker by a route `main`
//!   cannot write, the challenge of ADR 0041 section 3 computed from **the worker's own** box id, store id, request id and digest,
//!   the dashboard's origin, a touch and user verification, a counter that never goes back, and an assertion used once. Then the
//!   request book's own rules run again. `main` never approves by attestation: a compromised `main` can relay, delay, hide or deny,
//!   and it cannot make a worker approve.
//! * The Production tier (D1, D2) and the scopes ADR 0041 section 3.2 keeps to a laptop key with presence (`import`, `policy`,
//!   `tunnel-token`, `box-secrets`, `host-guard`, `signer-enroll`) are never decided by a passkey from `main`. Only `guard-override`
//!   is, in this release. A **Deny of a pending request** needs no assertion (fail safe: `main` can deny by silence anyway).
//! * A worker never decides: a worker that sends `approval.decision` is quarantined by the hub (the kind is the hub's alone).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::engine::{Hub, HubError, HubState};
use super::wire::{Ext, Kind, PROFILE};
use crate::approval::{
    Ctx, DecideInput, Envelope, Factor, Filing, Outcome, PasskeyEvidence, Request, RequestBook,
    Requester, Role, Scope, SignedEnvelope, SocketClass, State, Surface,
};
use crate::approval_subject::{decide_challenge, from_hex, to_hex, Ids, Subject};
use crate::approval_verify::{verify_webauthn_assertion, ExpectedRp};

/// The most cards `main` keeps per worker. A worker that files more has the oldest dropped from the view (the request stays on the
/// worker, which is the store; the hub pulls the live list again).
pub const MAX_CARDS_PER_WORKER: usize = 64;

/// The interval after which a worker announces a pending request again (ADR 0042 section 6: the hub does not rely on one delivery).
pub const ANNOUNCE_EVERY_MS: u64 = 30_000;

/// The audit words of this path (ADR 0042 section 9).
pub const AUDIT_SHOWN: &str = "hub.approval.shown";
pub const AUDIT_RELAYED: &str = "hub.approval.relayed";
pub const AUDIT_REJECTED: &str = "hub.approval.rejected";
pub const AUDIT_WORKER_DECIDED: &str = "worker.approval.decided";
pub const AUDIT_WORKER_REFUSED: &str = "worker.approval.refused";

/// The worker's screen code for an `approval.decision` body that is not exactly a [`DecisionBody`] (a grant, a token, any extra field).
pub const CODE_NOT_A_DECISION: &str = "not-a-decision";

/// The hub's refusal code when it will not relay a decision (said to the person at once; the worker would refuse it anyway).
pub const CODE_RELAY_REFUSED: &str = "approval-relay-refused";

/// What `main` pinned for a worker's approval service at enrolment: the ids its digests are computed with and the public half of its
/// envelope key. Never taken from a message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServicePin {
    pub ids: Ids,
    /// Ed25519, hex.
    pub envelope_key_hex: String,
}

/// The body of `approval.request`: the worker service's signed envelope and nothing else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestBody {
    pub signed: SignedEnvelope,
}

/// The body of `approval.decision`. It names a request and carries evidence; **no field grants anything.** Unknown fields are refused,
/// so nothing can ride along beside it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionBody {
    pub request_id: String,
    pub subject_digest: String,
    pub outcome: Outcome,
    /// The person as `main` names them, kept only as a claim: the worker reads who decided from its own approver set.
    pub claimed_person: String,
    /// The passkey assertion over the worker's challenge. Required to approve or revoke; absent on a relayed Deny.
    #[serde(default)]
    pub passkey: Option<PasskeyEvidence>,
}

/// A card on `main`: a pending request a worker filed, as its signed envelope said it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Card {
    pub signed: SignedEnvelope,
    /// What [`SignedEnvelope::verify`] read out of the signed text: never a copy the message carried beside it.
    pub envelope: Envelope,
    pub received_ms: u64,
    /// The outcome `main` relayed, if any. A relay is not a decision: the worker's answer is what counts.
    #[serde(default)]
    pub relayed: Option<Outcome>,
}

/// One approver the laptop put on a worker: a passkey credential, its person and role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approver {
    pub credential_id: String,
    /// The P-256 public point (SEC1 uncompressed), hex.
    pub public_key_hex: String,
    pub person: String,
    pub role: Role,
}

/// The approver set a worker trusts, delivered by a route `main` cannot write (ADR 0042 section 8: the setup identity's parameter path
/// on AWS, the laptop's apply on Hetzner). It expires; a worker refuses decisions on an expired set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApproverSet {
    pub seq: u64,
    pub expires_ms: u64,
    /// `main`'s dashboard: the relying party id and the exact origin an assertion must name.
    pub rp: ExpectedRp,
    pub approvers: Vec<Approver>,
}

/// The scopes a passkey on `main`'s dashboard may decide on a worker (ADR 0041 section 3.2). Everything else is a laptop key with
/// presence, or root, and a Production use is refused outright (D2).
pub fn fleet_may_decide(scope: Scope) -> bool {
    matches!(scope, Scope::GuardOverride)
}

/// Why a card cannot be decided from `main`'s dashboard, in the words the card shows; `None` when it can.
pub fn not_decidable_here(env: &Envelope) -> Option<&'static str> {
    if env.subject.production() || env.subject.production_looking() || env.scope == Scope::SecretUse
    {
        Some("Production on a worker is never decided from main's dashboard: it is decided with a laptop key with presence, and no worker receives Production in this release")
    } else if !fleet_may_decide(env.scope) {
        Some("this change is decided with a laptop key with presence, or by root, never from main's dashboard")
    } else {
        None
    }
}

/// What the dashboard shows and signs for a card. Derived from the signed fields: the card's text and the challenge both come from
/// the envelope `main` verified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxItem {
    pub worker: String,
    pub request_id: String,
    pub scope: Scope,
    pub subject_digest: String,
    pub expires_at_ms: u64,
    pub display: Vec<crate::approval_subject::DisplayField>,
    /// The challenge to approve, hex: `H(ozbox-approval-decide-v1, the worker's box id, store id, request id, digest, "approve")`.
    pub approve_challenge: String,
    pub deny_challenge: String,
    pub decidable_here: bool,
    pub why_not: Option<String>,
    pub relayed: Option<Outcome>,
    /// The worker's ids, so a browser can recompute the challenge itself and refuse a card whose digest does not match.
    pub box_id: String,
    pub store_id: String,
}

impl HubState {
    /// Pin a worker's approval service (done at enrolment, from the attested key; never from a message).
    pub fn pin_service(&mut self, worker: &str, pin: ServicePin) {
        self.service_pins.insert(worker.to_string(), pin);
    }

    /// The fleet inbox: every pending, unexpired card, oldest first. A view; the store is the worker's.
    pub fn inbox(&self, now: u64) -> Vec<InboxItem> {
        let mut out = Vec::new();
        for (worker, p) in &self.peers {
            let Some(pin) = self.service_pins.get(worker) else {
                continue;
            };
            for c in p.approvals.values() {
                if c.envelope.expires_at_ms <= now {
                    continue;
                }
                let Some(d) = digest32(&c.envelope.subject_digest) else {
                    continue;
                };
                let why = not_decidable_here(&c.envelope);
                out.push(InboxItem {
                    worker: worker.clone(),
                    request_id: c.envelope.id.clone(),
                    scope: c.envelope.scope,
                    subject_digest: c.envelope.subject_digest.clone(),
                    expires_at_ms: c.envelope.expires_at_ms,
                    display: c.envelope.subject.display(),
                    approve_challenge: to_hex(&decide_challenge(
                        &pin.ids,
                        &c.envelope.id,
                        &d,
                        "approve",
                    )),
                    deny_challenge: to_hex(&decide_challenge(&pin.ids, &c.envelope.id, &d, "deny")),
                    decidable_here: why.is_none(),
                    why_not: why.map(str::to_string),
                    relayed: c.relayed,
                    box_id: pin.ids.box_id.clone(),
                    store_id: pin.ids.store_id.clone(),
                });
            }
        }
        out.sort_by_key(|i| i.expires_at_ms);
        out
    }
}

fn digest32(hex: &str) -> Option<[u8; 32]> {
    let v = from_hex(hex).filter(|v| v.len() == 32)?;
    let mut d = [0u8; 32];
    d.copy_from_slice(&v);
    Some(d)
}

/// Take an `approval.request` from a worker (called by the hub's receive path once the channel's checks have passed).
pub(crate) fn take_request(st: &mut HubState, from: &str, plain: &[u8], now: u64) {
    let reject = |st: &mut HubState, why: &str| {
        st.note(now, AUDIT_REJECTED, format!("worker={from} reason={why}"));
    };
    let Some(pin) = st.service_pins.get(from).cloned() else {
        // an unpinned worker's service cannot be checked, so nothing it files is shown as if it could
        return reject(st, "unpinned");
    };
    let Ok(body) = serde_json::from_slice::<RequestBody>(plain) else {
        return reject(st, "malformed");
    };
    let Ok(env) = body.signed.verify(&pin.envelope_key_hex, &pin.ids) else {
        return reject(st, "signature");
    };
    if env.state != State::Pending {
        // an envelope that says approved (or anything else) is not a decision: a worker never approves
        return reject(st, "not-pending");
    }
    if env.expires_at_ms <= now {
        return reject(st, "expired");
    }
    let peer = st.peers.entry(from.to_string()).or_default();
    let fresh = !peer.approvals.contains_key(&env.id);
    let id = env.id.clone();
    let digest16: String = env.subject_digest.chars().take(16).collect();
    let scope = env.scope;
    let relayed = peer.approvals.get(&id).and_then(|c| c.relayed);
    peer.approvals.insert(
        id.clone(),
        Card {
            signed: body.signed,
            envelope: env,
            received_ms: now,
            relayed,
        },
    );
    while peer.approvals.len() > MAX_CARDS_PER_WORKER {
        let oldest = peer
            .approvals
            .iter()
            .min_by_key(|(_, c)| c.received_ms)
            .map(|(k, _)| k.clone());
        if let Some(k) = oldest {
            peer.approvals.remove(&k);
        }
    }
    if fresh {
        st.note(
            now,
            AUDIT_SHOWN,
            format!(
                "worker={from} request={id} scope={} digest={digest16}",
                scope.as_str()
            ),
        );
    }
}

impl Hub<'_> {
    /// Relay a person's decision to the worker that filed the request. The hub checks only what it can (the card exists, the digest is
    /// the card's, an approval carries an assertion, the tier may be decided here) so a person is told at once; **the worker's own
    /// service is the one that verifies**, and the hub has no way to make a decision of its own.
    pub fn relay_decision(
        &self,
        st: &mut HubState,
        worker: &str,
        d: &DecisionBody,
        now: u64,
    ) -> Result<(), HubError> {
        if !self.roster.contains_key(worker) {
            return Err(HubError::NotAWorker(worker.to_string()));
        }
        let refuse = |m: &str| {
            Err(HubError::Refused(super::refusal::Refusal {
                code: CODE_RELAY_REFUSED,
                message: m.to_string(),
            }))
        };
        let Some(card) = st
            .peers
            .get(worker)
            .and_then(|p| p.approvals.get(&d.request_id))
            .cloned()
        else {
            return refuse("there is no such request from that worker");
        };
        if card.envelope.expires_at_ms <= now {
            return refuse("that request has expired");
        }
        if card.envelope.subject_digest != d.subject_digest {
            return refuse("that decision is for another version of the request");
        }
        if d.outcome != Outcome::Deny {
            if d.passkey.is_none() {
                return refuse("an approval carries the person's passkey assertion");
            }
            if let Some(why) = not_decidable_here(&card.envelope) {
                return refuse(why);
            }
        }
        let body = serde_json::to_vec(d)
            .map_err(|_| HubError::Wire(super::wire::WireError::SendFailed))?;
        st.core
            .enqueue(
                &PROFILE,
                worker,
                Kind::ApprovalDecision.name(),
                Ext::at(0).encode(),
                body,
            )
            .map_err(HubError::Backlog)?;
        if let Some(c) = st
            .peers
            .get_mut(worker)
            .and_then(|p| p.approvals.get_mut(&d.request_id))
        {
            c.relayed = Some(d.outcome);
        }
        let digest16: String = d.subject_digest.chars().take(16).collect();
        st.note(
            now,
            AUDIT_RELAYED,
            format!(
                "worker={worker} request={} digest={digest16} outcome={}",
                d.request_id,
                d.outcome.word()
            ),
        );
        if !self.deferred {
            self.flush(st, worker, now).map_err(HubError::Wire)?;
        }
        Ok(())
    }
}

/// The worker's approval service, as the hub agent reaches it (ADR 0041 section 7: `list`, `get` and the relay of a signed decision;
/// never `file`, never `spend`). The real one is the worker's secrets service over its hub-agent socket; [`MemApprovals`] is the
/// in-memory one.
pub trait ApprovalService {
    /// The signed envelopes of the requests pending on this box.
    fn pending(&self, now: u64) -> Vec<SignedEnvelope>;
    /// Verify and apply a decision `main` relayed. Returns the request's new state word, or why it was refused.
    fn decide_from_fleet(
        &mut self,
        hub: &str,
        d: &DecisionBody,
        now: u64,
    ) -> Result<String, String>;
}

/// Turn a relayed decision into the request book's input, verifying everything the worker can: the request, the digest, the tier,
/// the approver set and the assertion's signature over this worker's own challenge. The book then applies its own rules again
/// (the role's cell, the counter, the assertion used once).
pub fn verify_fleet_decision(
    set: Option<&ApproverSet>,
    ids: &Ids,
    req: &Request,
    d: &DecisionBody,
    hub: &str,
    now: u64,
) -> Result<DecideInput, String> {
    if req.subject_digest != d.subject_digest {
        return Err("that decision is for another request or another version of it".into());
    }
    let via = Some(format!("fleet:{hub}"));
    if d.outcome == Outcome::Deny && req.state == State::Pending {
        // fail safe: main could deny by silence anyway, so a relayed Deny needs no credential
        return Ok(DecideInput {
            class: SocketClass::HubAgent,
            outcome: Outcome::Deny,
            surface: Surface::HubRelay,
            factor: Factor::ChatDeny,
            decider: format!("fleet:{hub}"),
            role: None,
            evidence: crate::approval::Evidence::default(),
            key: None,
            passkey_rp: None,
            via_fleet: via,
        });
    }
    if d.outcome == Outcome::Approve {
        if req.subject.production()
            || req.subject.production_looking()
            || req.scope == Scope::SecretUse
        {
            return Err("Production is never decided from main for a worker (D1, D2)".into());
        }
        if !fleet_may_decide(req.scope) {
            return Err("this change is decided with a laptop key with presence, or by root, never from main".into());
        }
    }
    let set =
        set.ok_or("this worker has no approver set pinned, so it decides nothing from main")?;
    if set.expires_ms <= now {
        return Err(
            "this worker's approver set has expired; it decides nothing until it is renewed".into(),
        );
    }
    let p = d
        .passkey
        .as_ref()
        .ok_or("a decision from main carries the person's passkey assertion")?;
    let who = set
        .approvers
        .iter()
        .find(|a| a.credential_id == p.credential_id)
        .ok_or("that passkey is not in this worker's approver set")?;
    if who.role == Role::Viewer {
        return Err("a viewer cannot decide a request".into());
    }
    // the outcome word the assertion was made for: a revoke of an approved request is signed as `revoke`
    let outcome = if req.state == State::Approved {
        Outcome::Revoke
    } else {
        d.outcome
    };
    if outcome == Outcome::Revoke && d.outcome == Outcome::Approve {
        return Err("that request is already approved".into());
    }
    let digest = digest32(&req.subject_digest).ok_or("the request is damaged")?;
    let challenge = decide_challenge(ids, &req.id, &digest, outcome.word());
    let public = from_hex(&who.public_key_hex).ok_or("the approver's key is damaged")?;
    let ad = from_hex(&p.authenticator_data).ok_or("the assertion is incomplete")?;
    let cd = from_hex(&p.client_data).ok_or("the assertion is incomplete")?;
    let sig = from_hex(&p.signature).ok_or("the assertion is incomplete")?;
    let (flags, _counter) =
        verify_webauthn_assertion(&public, &set.rp, &challenge, &ad, &cd, &sig)?;
    if flags & 0x01 == 0 || flags & 0x04 == 0 {
        return Err("a decision from main needs a touch and user verification".into());
    }
    Ok(DecideInput {
        // the worker's service plays the verifier's part here: it has checked the signature above, against its own pinned set
        class: SocketClass::Supervisor,
        outcome: d.outcome,
        surface: Surface::Dashboard,
        factor: Factor::Passkey,
        decider: who.person.clone(),
        role: Some(who.role),
        evidence: crate::approval::Evidence {
            passkey: Some(p.clone()),
            laptop: None,
        },
        key: None,
        passkey_rp: Some(set.rp.clone()),
        via_fleet: via,
    })
}

/// An in-memory approval service for a worker: a request book, the key its envelopes are signed with, and the pinned approver set.
/// Tests and the in-process fleet use it; a box uses its secrets service.
pub struct MemApprovals {
    pub book: RequestBook,
    pub ctx: Ctx,
    pub approvers: Option<ApproverSet>,
    key: ring::signature::Ed25519KeyPair,
}

impl MemApprovals {
    pub fn new(ids: Ids) -> Result<MemApprovals, String> {
        let rng = ring::rand::SystemRandom::new();
        let pk = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| "a key could not be made".to_string())?;
        let key = ring::signature::Ed25519KeyPair::from_pkcs8(pk.as_ref())
            .map_err(|_| "a key could not be made".to_string())?;
        Ok(MemApprovals {
            book: RequestBook::new("epoch-1".into()),
            ctx: Ctx {
                ids,
                enrolled: true,
                ever_key: false,
                ever_presence_key: false,
            },
            approvers: None,
            key,
        })
    }

    /// What `main` pins for this service at enrolment.
    pub fn pin(&self) -> ServicePin {
        use ring::signature::KeyPair;
        ServicePin {
            ids: self.ctx.ids.clone(),
            envelope_key_hex: to_hex(self.key.public_key().as_ref()),
        }
    }

    /// File a request, as the box's own gate does.
    pub fn file(
        &mut self,
        now: u64,
        id: &str,
        subject: Subject,
        requester: Requester,
    ) -> Result<Request, String> {
        let f = Filing {
            id: id.to_string(),
            subject,
            requester,
            reason: None,
            derived: crate::approval::Derived::default(),
        };
        Ok(self.book.file(&self.ctx, now, f)?.request)
    }

    pub fn sign(&self, r: &Request) -> Result<SignedEnvelope, String> {
        let canonical = SignedEnvelope::canonical_of(&r.envelope(&self.ctx.ids))?;
        let msg = SignedEnvelope::signed_message(&canonical);
        Ok(SignedEnvelope {
            signature: to_hex(self.key.sign(msg.as_bytes()).as_ref()),
            alg: "ed25519".into(),
            canonical,
        })
    }

    pub fn state_of(&self, id: &str) -> Option<State> {
        self.book.get(id).map(|r| r.state)
    }
}

impl ApprovalService for MemApprovals {
    fn pending(&self, now: u64) -> Vec<SignedEnvelope> {
        self.book
            .requests
            .iter()
            .filter(|r| {
                r.state == State::Pending && r.expires_at_ms > now && r.epoch == self.book.epoch
            })
            .filter_map(|r| self.sign(r).ok())
            .collect()
    }

    fn decide_from_fleet(
        &mut self,
        hub: &str,
        d: &DecisionBody,
        now: u64,
    ) -> Result<String, String> {
        let req = self
            .book
            .get(&d.request_id)
            .cloned()
            .ok_or(crate::approval::NOT_FOUND)?;
        let input =
            verify_fleet_decision(self.approvers.as_ref(), &self.ctx.ids, &req, d, hub, now)?;
        let r = self.book.decide(&self.ctx, now, &d.request_id, input)?;
        Ok(r.state.as_str().to_string())
    }
}

/// What a worker announced and when, so it repeats an announcement every [`ANNOUNCE_EVERY_MS`] and no more often.
pub type Announced = BTreeMap<String, u64>;
