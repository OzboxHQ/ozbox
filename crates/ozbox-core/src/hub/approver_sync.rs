//! The owner's approvers, carried to a worker (ADR 0042 section 8).
//!
//! A worker decides a relayed approval only with a credential in its **approver set**, and `main` must never be able to change who
//! is in it. So the set is signed by the owner's own computer, and the worker's service checks that signature itself, against a
//! laptop approval key the **box already trusts** (ADR 0041 section 3.1: pinned at creation or enrolled by an approval), before it
//! writes anything. `main` only carries the bytes.
//!
//! The pattern is B4-20's laptop-signed approver set: an Ed25519 signature over `tag + "\n" + the set's JSON text, exactly as
//! sent`; nothing is re-serialized, so there is no second encoding to disagree about. Differences, each on purpose:
//!
//! * a **different tag**, so a signature made for a fleet change can never be replayed as a hub set, and the reverse;
//! * the body names **one worker** (its approval service's box id and store id), so a set signed for one worker is no use on another;
//! * it carries the service's own shape ([`ApproverSet`]: a sequence number that only goes up, an expiry, the relying party), so the
//!   worker's existing decision check runs on it unchanged.
//!
//! The credentials come from the same record the dashboard lists (`CredentialRecord`, the shape `ozbox fleet approvers sign` reads).
//!
//! Pure: no clock, no files, no network.

use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};

use super::approvals::{Approver, ApproverSet};
use crate::approval::Role;
use crate::approval_subject::{from_hex, Ids};
use crate::approval_verify::ExpectedRp;

/// The domain tag of the signed bytes.
pub const APPROVERS_TAG: &str = "ozbox-hub-approvers-v1";
/// A set larger than this is refused unread.
pub const MAX_SET_BYTES: usize = 16 * 1024;
/// The most people one set names.
pub const MAX_APPROVERS: usize = 32;
/// The longest a set may be valid for. A set that must be renewed is a set a stolen laptop cannot use for ever.
pub const MAX_VALID_MS: u64 = 90 * 24 * 60 * 60 * 1000;
/// How far ahead of the worker's clock a set may be dated.
pub const SKEW_MS: u64 = 5 * 60 * 1000;

/// One credential as the owner's record lists it (the shape `ozbox fleet approvers sign` reads).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRecord {
    pub credential_id: String,
    pub person: String,
    pub role: Role,
    /// An uncompressed P-256 point, hex.
    pub public_key: String,
    pub rp: ExpectedRp,
}

/// What the computer signs for one worker: the service's ids, the set and when it was made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetBody {
    pub box_id: String,
    pub store_id: String,
    pub issued_ms: u64,
    pub set: ApproverSet,
}

/// A body and the computer's signature over its exact text. This is the body of a `pins.set` message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedApprovers {
    /// The body's JSON, exactly the text that was signed.
    pub body: String,
    /// The Ed25519 signature, hex.
    pub signature: String,
}

/// What is signed: the tag, a newline and the body's text.
pub fn signed_bytes(body: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(APPROVERS_TAG.len() + 1 + body.len());
    v.extend_from_slice(APPROVERS_TAG.as_bytes());
    v.push(b'\n');
    v.extend_from_slice(body.as_bytes());
    v
}

impl SetBody {
    /// The text to sign. The computer calls this once and signs the result.
    pub fn to_text(&self) -> Result<String, String> {
        serde_json::to_string(self).map_err(|_| "the approver set cannot be written".to_string())
    }
}

/// Build the set for one worker from the owner's credential records. Every record must name the same relying party (the dashboard's):
/// a mixed list is refused, never guessed at.
pub fn build_set(
    target: &Ids,
    records: &[CredentialRecord],
    version: u64,
    valid_ms: u64,
    now: u64,
) -> Result<SetBody, String> {
    let first = records.first().ok_or("the credentials file names nobody")?;
    if records.len() > MAX_APPROVERS {
        return Err("the credentials file names too many people".into());
    }
    if records.iter().any(|r| r.rp != first.rp) {
        return Err("the credentials name more than one dashboard".into());
    }
    if valid_ms == 0 || valid_ms > MAX_VALID_MS {
        return Err("the set must be valid for between one day and ninety days".into());
    }
    if version == 0 {
        return Err("the version starts at 1".into());
    }
    let approvers = records
        .iter()
        .map(|r| Approver {
            credential_id: r.credential_id.clone(),
            public_key_hex: r.public_key.clone(),
            person: r.person.clone(),
            role: r.role,
        })
        .collect();
    Ok(SetBody {
        box_id: target.box_id.clone(),
        store_id: target.store_id.clone(),
        issued_ms: now,
        set: ApproverSet {
            seq: version,
            expires_ms: now.saturating_add(valid_ms),
            rp: first.rp.clone(),
            approvers,
        },
    })
}

/// Why a set was refused, in words that name no key.
pub const REFUSED_SIZE: &str = "that approver list is too large";
pub const REFUSED_SIGNATURE: &str = "that approver list was not signed by your computer";
pub const REFUSED_UNREADABLE: &str = "that approver list is not readable";
pub const REFUSED_OTHER_WORKER: &str = "that approver list is for another box";
pub const REFUSED_SHAPE: &str = "that approver list is not valid";
pub const REFUSED_EXPIRED: &str = "that approver list has expired or is dated in the future";
pub const REFUSED_NO_KEY: &str =
    "this box has no trusted computer key to check an approver list against";

impl SignedApprovers {
    /// Check the signature against the laptop approval keys this box already trusts (`trusted`, public halves in hex), that the body
    /// is for **this** service, and that its content is sane; return the set. The rule that a version never goes back is the
    /// caller's, because it needs what is held.
    pub fn verify(&self, trusted: &[String], ids: &Ids, now: u64) -> Result<ApproverSet, String> {
        if self.body.len() > MAX_SET_BYTES {
            return Err(REFUSED_SIZE.into());
        }
        if trusted.is_empty() {
            return Err(REFUSED_NO_KEY.into());
        }
        let sig = from_hex(&self.signature)
            .filter(|s| s.len() == 64)
            .ok_or(REFUSED_SIGNATURE)?;
        let msg = signed_bytes(&self.body);
        let signed = trusted.iter().any(|k| {
            from_hex(k).is_some_and(|pk| {
                UnparsedPublicKey::new(&ED25519, pk)
                    .verify(&msg, &sig)
                    .is_ok()
            })
        });
        if !signed {
            return Err(REFUSED_SIGNATURE.into());
        }
        let b: SetBody = serde_json::from_str(&self.body).map_err(|_| REFUSED_UNREADABLE)?;
        if b.box_id != ids.box_id || b.store_id != ids.store_id {
            return Err(REFUSED_OTHER_WORKER.into());
        }
        let s = &b.set;
        if s.seq == 0
            || s.approvers.is_empty()
            || s.approvers.len() > MAX_APPROVERS
            || s.expires_ms <= b.issued_ms
            || s.expires_ms - b.issued_ms > MAX_VALID_MS
            || s.approvers.iter().any(|a| {
                a.credential_id.is_empty()
                    || a.credential_id.len() > 1024
                    || a.public_key_hex.len() > 200
                    || a.person.len() > 64
            })
        {
            return Err(REFUSED_SHAPE.into());
        }
        if s.expires_ms <= now || b.issued_ms > now.saturating_add(SKEW_MS) {
            return Err(REFUSED_EXPIRED.into());
        }
        Ok(b.set)
    }
}

/// What the owner's computer hands `main` to carry: one signed set per worker, by the worker's name on the channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub sets: Vec<BundleEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleEntry {
    pub worker: String,
    pub signed: SignedApprovers,
}

/// What the hub knows about each worker's set: what it sent and what the worker said back. The worker's word is information for the
/// person; **the worker's own service is the authority** and a hub that lied here changes nobody's approvals.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Track {
    /// The version last sent to this worker, and when.
    pub sent_seq: u64,
    pub sent_ms: u64,
    /// The version the worker last said it holds, and when.
    pub held_seq: u64,
    pub held_ms: u64,
    /// The worker's last refusal, in its own words (a sentence, never a key), and when.
    pub refused: Option<String>,
    pub refused_ms: u64,
}

/// The state words a worker reports.
pub const STATE_HELD: &str = "approvers";
pub const STATE_REFUSED: &str = "approvers-refused";
/// The audit words.
pub const AUDIT_SENT: &str = "hub.approvers.sent";
pub const AUDIT_HUB_REFUSED: &str = "hub.approvers.refused";
pub const AUDIT_WORKER_SET: &str = "worker.approvers.set";
pub const AUDIT_WORKER_REFUSED: &str = "worker.approvers.refused";
/// The worker's screen code for a `pins.set` body that is not exactly a [`SignedApprovers`].
pub const CODE_NOT_AN_APPROVER_SET: &str = "not-an-approver-set";

use super::engine::{Hub, HubError, HubState, StatusBody};
use super::wire::{Ext, Kind, PROFILE};

/// The hub's own early check of a body before it sends one: readable, for the ids this worker's service pinned at enrolment, and
/// newer than what it last sent. This is for the person's benefit (told at once); **the worker verifies everything again** and
/// believes nothing the hub checked. Returns the version.
pub fn precheck(st: &HubState, worker: &str, s: &SignedApprovers) -> Result<u64, String> {
    if s.body.len() > MAX_SET_BYTES {
        return Err(REFUSED_SIZE.into());
    }
    let b: SetBody = serde_json::from_str(&s.body).map_err(|_| REFUSED_UNREADABLE)?;
    if let Some(pin) = st.service_pins.get(worker) {
        if pin.ids.box_id != b.box_id || pin.ids.store_id != b.store_id {
            return Err(REFUSED_OTHER_WORKER.into());
        }
    } else {
        return Err(
            "that worker has no approval service pinned, so it cannot take an approver list".into(),
        );
    }
    // against what the worker said it holds, so a list that was refused or lost can be sent again; an older one is refused here and
    // by the worker's own service whatever the hub believes
    let held = st.peers.get(worker).map_or(0, |p| p.approvers.held_seq);
    if b.set.seq <= held {
        return Err("that approver list is not newer than the one the worker holds".into());
    }
    Ok(b.set.seq)
}

/// Take a worker's account of its approver set (`state` `approvers` with `seq=N`, or `approvers-refused` with its sentence). Returns
/// whether the status was one of these, so the caller does not file it as a feature's.
pub(crate) fn take_status(st: &mut HubState, from: &str, s: &StatusBody, now: u64) -> bool {
    if s.orchestration != "-" || s.feature != "-" {
        return false;
    }
    match s.state.as_str() {
        STATE_HELD => {
            let seq = s
                .text
                .strip_prefix("seq=")
                .and_then(|n| n.parse::<u64>().ok())
                .unwrap_or(0);
            let t = &mut st.peers.entry(from.to_string()).or_default().approvers;
            if seq > t.held_seq {
                t.held_seq = seq;
                t.held_ms = now;
                t.refused = None;
            }
            true
        }
        STATE_REFUSED => {
            let t = &mut st.peers.entry(from.to_string()).or_default().approvers;
            t.refused = Some(
                s.text
                    .chars()
                    .filter(|c| !c.is_control())
                    .take(160)
                    .collect(),
            );
            t.refused_ms = now;
            true
        }
        _ => false,
    }
}

impl Hub<'_> {
    /// Carry the owner's signed approver list to a worker as `pins.set`. The hub signs nothing and can change nothing: the worker's
    /// own service verifies the owner's signature against a key the box already trusts, and refuses a list that is unsigned, forged,
    /// for another box, expired, or not newer than the one it holds.
    pub fn send_approvers(
        &self,
        st: &mut HubState,
        worker: &str,
        signed: &SignedApprovers,
        now: u64,
    ) -> Result<u64, HubError> {
        if !self.roster.contains_key(worker) {
            return Err(HubError::NotAWorker(worker.to_string()));
        }
        let refuse = |m: String| {
            Err(HubError::Refused(super::refusal::Refusal {
                code: CODE_APPROVERS_REFUSED,
                message: m,
            }))
        };
        let seq = match precheck(st, worker, signed) {
            Ok(n) => n,
            Err(m) => {
                st.note(now, AUDIT_HUB_REFUSED, format!("worker={worker}"));
                return refuse(m);
            }
        };
        let body = serde_json::to_vec(signed)
            .map_err(|_| HubError::Wire(super::wire::WireError::SendFailed))?;
        st.core
            .enqueue(
                &PROFILE,
                worker,
                Kind::PinsSet.name(),
                Ext::at(0).encode(),
                body,
            )
            .map_err(HubError::Backlog)?;
        let t = &mut st.peers.entry(worker.to_string()).or_default().approvers;
        t.sent_seq = seq;
        t.sent_ms = now;
        st.note(now, AUDIT_SENT, format!("worker={worker} seq={seq}"));
        if !self.deferred {
            self.flush(st, worker, now).map_err(HubError::Wire)?;
        }
        Ok(seq)
    }
}

/// The hub's refusal code when it will not send an approver list (said to the person at once).
pub const CODE_APPROVERS_REFUSED: &str = "approvers-refused";
