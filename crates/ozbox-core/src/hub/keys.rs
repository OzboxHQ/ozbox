//! Keys to a worker **by name**, sealed to its attested key (ADR 0042 section 5; decision D2).
//!
//! The path, and the one thing each part may do:
//!
//! 1. **The worker asks by name.** The hub agent sends a `blocked` message whose body is a [`KeyAsk`]: the task, and the names it
//!    is waiting for. Names only: never a value, never an environment (the environment is the one the task was assigned with).
//! 2. **The hub checks the ask, then asks the issuer** ([`Hub::deliver_keys`]): the worker is in the roster and not quarantined,
//!    the task was assigned to it, every name is in the declaration the task was assigned with, the declaration is not
//!    Production by environment or by name (D2, on the hub), and the worker's key-delivery key was attested by something `main`
//!    cannot write ([`Attestations`]). Only then is the [`KeyIssuer`] asked, and only after [`issuer_guard`] has refused
//!    Production again in front of it (D2, at the issuer). The issuer is ADR 0029's sealed-delivery path: the secrets service reads
//!    the values and seals them to the attested key; the hub never holds a value, only the sealed bytes it relays.
//! 3. **The hub checks the issuer's answer** says the same environment and names that were asked, and relays it as `keys.deliver`.
//! 4. **The worker checks again** ([`crate::hub::worker::WorkerEnd::poll_keys`]): Production is refused on the worker too (D2,
//!    on the worker), the task must be one it holds, the names in its declaration; then the sealed bytes go to the worker's
//!    service ([`DeliveryStore::store_delivery`]), which alone can open them. The hub agent cannot.
//! 5. **They end with the task**: `keys.revoke`, `task.end`, and **at once on loss of the hub**
//!    ([`crate::hub::worker::WorkerEnd::hub_lost`]).
//!
//! What is **not** checked here: the delivered **value** (whether a value looks like Production, and an environment signed by
//! `main`'s secrets service rather than the hub). That check needs the plaintext and so belongs to the worker's service, inside
//! `store_delivery`, and is not built in this release (ADR 0042 "H3a"); the label checks above are three, and each stands alone.

use std::collections::BTreeSet;

use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

use super::engine::{Hub, HubError, HubState};
use super::refusal::{refuse_production, KeyDeclaration, Refusal, AUDIT_REFUSED, MAX_NAMES};
use super::wire::{Ext, Kind, PROFILE};
use crate::approval_subject::{to_hex, Encoder};

/// The audit word for a delivery the hub relayed: worker, task, the names, the environment, the key it was sealed to.
pub const AUDIT_DELIVERED: &str = "hub.keys.delivered";
/// The audit word for a revocation the hub sent.
pub const AUDIT_REVOKED: &str = "hub.keys.revoked";
/// The worker's audit words.
pub const AUDIT_STORED: &str = "worker.keys.stored";
pub const AUDIT_DELETED: &str = "worker.keys.deleted";

/// The task was not assigned to this worker (or not by this hub).
pub const CODE_NOT_ASSIGNED: &str = "task-not-assigned";
/// A name the ask lists is not in the task's declaration.
pub const CODE_NOT_DECLARED: &str = "name-not-declared";
/// The worker has no attested key-delivery key: nothing is sealed to a key `main` merely reported.
pub const CODE_NOT_ATTESTED: &str = "not-attested";
/// The issuer refused (its own code is kept in the audit line, never its text).
pub const CODE_ISSUER: &str = "issuer-refused";
/// The issuer's answer names another environment or other names than were asked.
pub const CODE_ISSUER_MISMATCH: &str = "issuer-answer-mismatch";
/// The ask itself is malformed (no names, too many, a duplicate, a name that is not a name).
pub const CODE_ASK_INVALID: &str = "ask-invalid";
/// A `keys.deliver` or `keys.revoke` body that is not exactly the shape this release defines. Refused by the worker's screen, so
/// nothing of it is held.
pub const CODE_DELIVERY_INVALID: &str = "delivery-invalid";
/// The worker's service refused to store a delivery.
pub const CODE_STORE: &str = "store-refused";

/// The `info` purpose a delivery is sealed under (ADR 0042 section 1: the key-delivery key's own purpose, so a delivery never opens
/// as a channel body, and the reverse).
pub const DELIVERY_PURPOSE: &str = "hub-key-delivery";

/// The most key asks the hub keeps per worker before serving them; past it an ask is refused and audited.
pub const MAX_PENDING_ASKS: usize = 16;

/// The `waiting` word of a key ask.
pub const WAITING_KEYS: &str = "keys";

/// What a worker asks for: the names one task is waiting for. The body of a `blocked` message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyAsk {
    /// Always [`WAITING_KEYS`]: a `blocked` body that says anything else is not a key ask.
    pub waiting: String,
    pub orchestration: String,
    pub feature: String,
    pub names: Vec<String>,
}

impl KeyAsk {
    pub fn new(orchestration: &str, feature: &str, names: &[String]) -> KeyAsk {
        KeyAsk {
            waiting: WAITING_KEYS.to_string(),
            orchestration: orchestration.to_string(),
            feature: feature.to_string(),
            names: names.to_vec(),
        }
    }

    /// A `blocked` body that is exactly a key ask, or `None`.
    pub fn parse(plain: &[u8]) -> Option<KeyAsk> {
        serde_json::from_slice::<KeyAsk>(plain)
            .ok()
            .filter(|a| a.waiting == WAITING_KEYS)
    }
}

/// A worker's key-delivery key, as an attestation vouched for it (ADR 0042 section 2): the public half and its fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedKey {
    pub public: String,
    pub fp: String,
}

/// Where the hub learns a worker's attested key-delivery key. The real one reads the attestation the registrar signed (enrolment);
/// it never answers with a key `main` reported on its own word.
pub trait Attestations: Send + Sync {
    fn delivery_key(&self, worker: &str) -> Option<AttestedKey>;
}

/// What the hub asks the issuer for. Names, never a value.
#[derive(Debug, Clone, Copy)]
pub struct ReleaseRequest<'a> {
    pub request_id: &'a str,
    pub worker: &'a str,
    pub orchestration: &'a str,
    pub feature: &'a str,
    pub env: &'a str,
    pub names: &'a [String],
    pub to: &'a AttestedKey,
}

/// What the issuer answers: the labels it released under, and the values sealed to the attested key (opaque to the hub).
#[derive(Clone, PartialEq, Eq)]
pub struct Released {
    pub env: String,
    pub names: Vec<String>,
    pub sealed: Vec<u8>,
}

impl std::fmt::Debug for Released {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // the sealed bytes are never printed, not even as a ciphertext
        write!(
            f,
            "Released {{ env: {}, names: {:?}, sealed: {} bytes }}",
            self.env,
            self.names,
            self.sealed.len()
        )
    }
}

/// The release path of ADR 0029 for development and staging values: `main`'s secrets service reads the named values and seals them
/// to the attested key. Production never comes out of it for a worker ([`issuer_guard`] runs in front of it, and an
/// implementation calls it again itself). An error is a short code, never the issuer's text.
pub trait KeyIssuer: Send + Sync {
    fn release(&self, r: &ReleaseRequest<'_>) -> Result<Released, &'static str>;
}

/// D2 at the issuer: Production by environment or by name is refused before anything is read. The hub calls it in front of every
/// release, and an issuer implementation calls it again as its own first line, so neither depends on the other.
pub fn issuer_guard(r: &ReleaseRequest<'_>) -> Result<(), Refusal> {
    if r.names.is_empty() {
        return Err(Refusal {
            code: CODE_ASK_INVALID,
            message: "a release names no key".into(),
        });
    }
    refuse_production(&KeyDeclaration {
        env: r.env.to_string(),
        names: r.names.to_vec(),
    })
}

/// The authenticated data a delivery is sealed with, so sealed bytes for one worker, task, request or set of names do not open for
/// another. The issuer seals with it and the worker's service opens with it.
pub fn delivery_aad(
    request_id: &str,
    worker: &str,
    orchestration: &str,
    feature: &str,
    env: &str,
    names: &[String],
) -> Vec<u8> {
    let mut e = Encoder::new("ozbox-hub-delivery-v1");
    e.text(request_id)
        .text(worker)
        .text(orchestration)
        .text(feature)
        .text(env)
        .count(names.len());
    for n in names {
        e.text(n);
    }
    e.bytes().to_vec()
}

/// The body of `keys.deliver`: labels, and the sealed bytes the worker's service alone opens.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyDelivery {
    pub orchestration: String,
    pub feature: String,
    pub env: String,
    pub names: Vec<String>,
    pub request_id: String,
    /// The fingerprint of the attested key the values are sealed to.
    pub key_fp: String,
    #[serde(with = "crate::channel::wire::hex_bytes")]
    pub sealed: Vec<u8>,
}

impl std::fmt::Debug for KeyDelivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "KeyDelivery {{ task: {}/{}, env: {}, names: {:?}, request: {}, key: {}, sealed: {} bytes }}",
            self.orchestration,
            self.feature,
            self.env,
            self.names,
            self.request_id,
            self.key_fp,
            self.sealed.len()
        )
    }
}

/// The body of `keys.revoke` and of `task.end`: the task whose keys the worker deletes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyRevoke {
    pub orchestration: String,
    pub feature: String,
}

/// The worker's service, as the hub agent reaches it: it stores a delivery it alone can open, and deletes. The hub agent never
/// holds a plaintext.
pub trait DeliveryStore {
    /// Store the sealed values for a task. The service opens them with its key-delivery key and keeps them in its run-scoped store;
    /// it refuses (with a short code) anything that does not open for it.
    fn store_delivery(&self, d: &KeyDelivery) -> Result<(), &'static str>;
    /// Delete one task's keys.
    fn delete_task(&self, orchestration: &str, feature: &str);
    /// Delete every key this worker holds (loss of the hub, quarantine).
    fn delete_all(&self);
}

/// The key the hub files a task's declaration under.
pub fn task_key(orchestration: &str, feature: &str) -> String {
    format!("{orchestration}/{feature}")
}

fn request_id() -> String {
    let mut b = [0u8; 12];
    while SystemRandom::new().fill(&mut b).is_err() {}
    to_hex(&b)
}

/// Whether a list of names is a valid ask: present, bounded, no duplicates, each a printable name.
pub fn names_ok(names: &[String]) -> bool {
    let set: BTreeSet<&String> = names.iter().collect();
    !names.is_empty()
        && names.len() <= MAX_NAMES
        && set.len() == names.len()
        && names
            .iter()
            .all(|n| !n.is_empty() && n.len() <= 128 && n.bytes().all(|b| b.is_ascii_graphic()))
}

impl Hub<'_> {
    fn refuse(
        &self,
        st: &mut HubState,
        now: u64,
        worker: &str,
        feature: &str,
        code: &'static str,
        message: &str,
    ) -> HubError {
        st.core.note(
            now,
            AUDIT_REFUSED,
            None,
            format!("side=hub worker={worker} task={feature} code={code}"),
        );
        HubError::Refused(Refusal {
            code,
            message: message.to_string(),
        })
    }

    /// Deliver the keys a worker asked for by name, through the issuer, sealed to its attested key. Every refusal is audited before
    /// it is returned, with names and codes only.
    pub fn deliver_keys(
        &self,
        st: &mut HubState,
        worker: &str,
        ask: &KeyAsk,
        attest: &dyn Attestations,
        issuer: &dyn KeyIssuer,
        now: u64,
    ) -> Result<(), HubError> {
        if !self.roster.contains_key(worker) {
            return Err(HubError::NotAWorker(worker.to_string()));
        }
        let peer = st.peers.entry(worker.to_string()).or_default();
        if let Some(why) = &peer.quarantined {
            return Err(HubError::Quarantined(format!("{worker}: {why}")));
        }
        let feature = ask.feature.clone();
        if ask.waiting != WAITING_KEYS || !names_ok(&ask.names) {
            return Err(self.refuse(
                st,
                now,
                worker,
                &feature,
                CODE_ASK_INVALID,
                "a key ask must name each key once, by a valid name",
            ));
        }
        let Some(decl) = peer
            .declared
            .get(&task_key(&ask.orchestration, &ask.feature))
            .cloned()
        else {
            return Err(self.refuse(
                st,
                now,
                worker,
                &feature,
                CODE_NOT_ASSIGNED,
                "that task was not handed to this worker",
            ));
        };
        if ask.names.iter().any(|n| !decl.names.contains(n)) {
            return Err(self.refuse(
                st,
                now,
                worker,
                &feature,
                CODE_NOT_DECLARED,
                "a worker is given only the keys its task declared, by name",
            ));
        }
        // D2 on the hub: the environment the task was assigned with, and the names asked
        let asked = KeyDeclaration {
            env: decl.env.clone(),
            names: ask.names.clone(),
        };
        if let Err(r) = refuse_production(&asked) {
            return Err(self.refuse(st, now, worker, &feature, r.code, &r.message));
        }
        let Some(to) = attest.delivery_key(worker) else {
            return Err(self.refuse(
                st,
                now,
                worker,
                &feature,
                CODE_NOT_ATTESTED,
                "this worker's key-delivery key has no attestation, so nothing is sealed to it",
            ));
        };
        let rid = request_id();
        let req = ReleaseRequest {
            request_id: &rid,
            worker,
            orchestration: &ask.orchestration,
            feature: &ask.feature,
            env: &decl.env,
            names: &ask.names,
            to: &to,
        };
        // D2 at the issuer, run here in front of it so a release of Production is never even asked for
        if let Err(r) = issuer_guard(&req) {
            return Err(self.refuse(st, now, worker, &feature, r.code, &r.message));
        }
        let rel = match issuer.release(&req) {
            Ok(rel) => rel,
            Err(code) => {
                st.core.note(
                    now,
                    AUDIT_REFUSED,
                    None,
                    format!(
                        "side=hub worker={worker} task={feature} code={CODE_ISSUER} issuer={}",
                        if crate::channel::wire::word_ok(code) {
                            code
                        } else {
                            "-"
                        }
                    ),
                );
                return Err(HubError::Refused(Refusal {
                    code: CODE_ISSUER,
                    message: "the issuer refused the release".into(),
                }));
            }
        };
        // the issuer's answer must be the release that was asked for, and never Production
        let answered = KeyDeclaration {
            env: rel.env.clone(),
            names: rel.names.clone(),
        };
        if rel.env != decl.env
            || rel.names != ask.names
            || rel.sealed.is_empty()
            || refuse_production(&answered).is_err()
        {
            return Err(self.refuse(
                st,
                now,
                worker,
                &feature,
                CODE_ISSUER_MISMATCH,
                "the issuer's answer is not the release that was asked for",
            ));
        }
        let body = KeyDelivery {
            orchestration: ask.orchestration.clone(),
            feature: ask.feature.clone(),
            env: rel.env,
            names: rel.names,
            request_id: rid.clone(),
            key_fp: to.fp.clone(),
            sealed: rel.sealed,
        };
        let plain = serde_json::to_vec(&body).map_err(|_| {
            HubError::Wire(super::wire::WireError::Channel(
                crate::channel::wire::WireError::SealFailed,
            ))
        })?;
        st.core
            .enqueue(
                &PROFILE,
                worker,
                Kind::KeysDeliver.name(),
                Ext::at(0).encode(),
                plain,
            )
            .map_err(HubError::Backlog)?;
        st.core.note(
            now,
            AUDIT_DELIVERED,
            None,
            format!(
                "worker={worker} task={feature} orchestration={} env={} names={} key={} request={rid}",
                ask.orchestration,
                decl.env,
                ask.names.join(","),
                to.fp
            ),
        );
        if !self.deferred {
            self.flush(st, worker, now).map_err(HubError::Wire)?;
        }
        Ok(())
    }

    /// Serve every key ask the workers have sent since the last call. Returns how many were delivered; each refusal is audited.
    pub fn serve_key_asks(
        &self,
        st: &mut HubState,
        attest: &dyn Attestations,
        issuer: &dyn KeyIssuer,
        now: u64,
    ) -> usize {
        let pending: Vec<(String, KeyAsk)> = st
            .peers
            .iter_mut()
            .flat_map(|(w, p)| {
                std::mem::take(&mut p.key_asks)
                    .into_iter()
                    .map(move |a| (w.clone(), a))
                    .collect::<Vec<_>>()
            })
            .collect();
        pending
            .iter()
            .filter(|(w, a)| self.deliver_keys(st, w, a, attest, issuer, now).is_ok())
            .count()
    }

    /// Tell a worker to delete one task's keys.
    pub fn revoke_keys(
        &self,
        st: &mut HubState,
        worker: &str,
        orchestration: &str,
        feature: &str,
        now: u64,
    ) -> Result<(), HubError> {
        if !self.roster.contains_key(worker) {
            return Err(HubError::NotAWorker(worker.to_string()));
        }
        let body = serde_json::to_vec(&KeyRevoke {
            orchestration: orchestration.to_string(),
            feature: feature.to_string(),
        })
        .unwrap_or_default();
        st.core
            .enqueue(
                &PROFILE,
                worker,
                Kind::KeysRevoke.name(),
                Ext::at(0).encode(),
                body,
            )
            .map_err(HubError::Backlog)?;
        st.core.note(
            now,
            AUDIT_REVOKED,
            None,
            format!("worker={worker} task={feature} orchestration={orchestration}"),
        );
        if !self.deferred {
            self.flush(st, worker, now).map_err(HubError::Wire)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
