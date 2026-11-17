//! Worker enrolment and key attestation (ADR 0042 section 2, "Identity and attestation, and how a worker joins").
//!
//! A worker joins in three steps, and each mutation is **planned, then applied** (ADR 0002):
//!
//! 1. **Invite.** When `main` creates a worker, the hub plans an invite (the worker's name, its box id, the provider and what
//!    binds the worker to the machine it was created as), then applies it. Applying makes a **one-use enrolment token** (24
//!    random bytes, valid 30 minutes, bound to the worker's name) and returns it **once**, to be placed where only the new box can
//!    read it. The hub keeps only the token's MAC, made by the secrets service; never the token.
//! 2. **Request.** The worker's hub agent presents the token, its public identity, an **attestation** and a **proof**. The
//!    attestation is a record signed by a **registrar** whose key the setup identity pinned in a file `main` cannot write
//!    (on AWS the claim service, on Hetzner and on own machines the laptop). The proof is the worker's channel signing key's
//!    signature over this hub's identity, the worker's name, the attestation and a fresh time and nonce: the worker holds the key
//!    the attestation names. The request is screened and held as **pending**; nothing is in the roster yet.
//! 3. **Enrol.** The hub plans the enrolment (what will be recorded, from whom) and applies it: the checks run again, the key
//!    goes into the roster, and the token is burnt.
//!
//! Refused, each with its own code: an unknown box, a wrong or expired token, an unknown registrar or a forged attestation, an
//! attestation for another hub or another machine, a **Production box** (anything not attested as a worker, or attested for a
//! Production environment, or `main` itself), a key that is not the attested one, a replayed attestation or proof, a key or a
//! box another worker already has, and a second enrolment of a worker (a key cannot be swapped this way). No refusal, plan,
//! audit word or error carries the token, a private key or a MAC.

use std::collections::BTreeMap;

use ozbox_core::approval_subject::{is_production_environment, to_hex, Encoder};
use ozbox_core::channel::wire::{fingerprint, hex, unhex, word_ok, MAX_SKEW_MS};
use ozbox_core::hub::approvals::ServicePin;
use ring::digest::{digest, SHA256};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::verify_ed25519;
use crate::identity::{Identity, ATTESTATION_TAG, ENROL_PROOF_TAG};
use crate::keys::SignPurpose;
use crate::ops::KeyOps;

/// How long an enrolment token is valid.
pub const TOKEN_TTL_MS: u64 = 30 * 60 * 1000;
/// The token's length in bytes.
pub const TOKEN_BYTES: usize = 24;
/// The oldest attestation a hub accepts.
pub const ATTESTATION_MAX_AGE_MS: u64 = 30 * 60 * 1000;
/// How long an applied attestation and proof are remembered, so neither is taken twice.
pub const SEEN_KEEP_MS: u64 = 7 * 24 * 60 * 60 * 1000;

pub const CODE_MALFORMED: &str = "malformed";
pub const CODE_UNKNOWN_BOX: &str = "unknown-box";
pub const CODE_TOKEN_EXPIRED: &str = "token-expired";
pub const CODE_BAD_TOKEN: &str = "bad-token";
pub const CODE_UNKNOWN_REGISTRAR: &str = "unknown-registrar";
pub const CODE_BAD_ATTESTATION: &str = "bad-attestation";
pub const CODE_STALE: &str = "stale";
pub const CODE_PRODUCTION_BOX: &str = "production-box";
pub const CODE_WRONG_HUB: &str = "wrong-hub";
pub const CODE_BINDING: &str = "binding-mismatch";
pub const CODE_WRONG_KEY: &str = "wrong-key";
pub const CODE_REPLAYED: &str = "replayed-attestation";
pub const CODE_DUPLICATE: &str = "duplicate-key";
pub const CODE_ALREADY: &str = "already-enrolled";
pub const CODE_STALE_PLAN: &str = "stale-plan";
pub const CODE_NOTHING_PENDING: &str = "nothing-pending";
pub const CODE_SERVICE: &str = "secrets-service";

/// The class an attestation must name. Anything else (`main`, a missing or unknown class) is refused: only a box positively
/// attested as a worker may become one.
pub const WORKER_CLASS: &str = "worker";

/// Why an enrolment step was refused. The code is the audit word; the message is for a person. Neither carries a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub code: &'static str,
    pub message: String,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Refusal {}

fn no(code: &'static str, message: &str) -> Refusal {
    Refusal {
        code,
        message: message.to_string(),
    }
}

/// Where a worker runs, which decides who may attest it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    /// The claim service registers the worker's keys under its bound pool role, and binds them to the instance.
    Aws,
    /// The laptop registers the keys after checking the creation secret's MAC; bound to the Cloud Network address.
    Hetzner,
    /// The laptop adopts or creates the machine and signs for it.
    Own,
}

impl Provider {
    pub fn word(self) -> &'static str {
        match self {
            Provider::Aws => "aws",
            Provider::Hetzner => "hetzner",
            Provider::Own => "own",
        }
    }
}

/// A registrar the setup identity pinned: who may sign attestations, for which provider. Public keys only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registrar {
    pub provider: Provider,
    /// Ed25519, hex.
    pub public: String,
}

impl Registrar {
    pub fn fingerprint(&self) -> String {
        unhex(&self.public)
            .map(|b| fingerprint(&b))
            .unwrap_or_default()
    }
}

/// The registrars file: written by root from what the laptop pinned, read by the hub, never written by `main`'s hub logic.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registrars {
    pub registrars: Vec<Registrar>,
}

impl Registrars {
    fn find(&self, fp: &str, provider: Provider) -> Option<&Registrar> {
        self.registrars
            .iter()
            .find(|r| r.provider == provider && r.fingerprint() == fp)
    }
}

/// What a registrar vouches for. ADR 0042's record: the machine, the box, the orchestration, the parent hub, and the worker's
/// key fingerprints; plus the class and environment the box was created for, the time and a nonce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    pub provider: Provider,
    /// The instance id (AWS) or the machine id (Hetzner, own).
    pub machine: String,
    pub box_id: String,
    /// [`WORKER_CLASS`], or the attestation is refused.
    pub class: String,
    /// The environment the box was created for. A Production one is refused.
    pub environment: String,
    pub orchestration: String,
    /// The identity fingerprint of the hub this worker may join.
    pub hub_identity_fp: String,
    /// The worker's identity fingerprint (all four keys; its service key).
    pub identity_fp: String,
    pub channel_fp: String,
    pub delivery_fp: String,
    /// The worker's address on the provider's private network (Hetzner's binding); empty elsewhere.
    #[serde(default)]
    pub private_address: String,
    pub issued_ms: u64,
    /// 16 random bytes, hex.
    pub nonce: String,
    pub registrar_fp: String,
    /// The registrar's Ed25519 signature over [`Attestation::signing_bytes`], hex.
    #[serde(default)]
    pub signature: String,
}

impl Attestation {
    /// The bytes a registrar signs: every field but the signature, in this order, under [`ATTESTATION_TAG`].
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new(ATTESTATION_TAG);
        e.text(self.provider.word())
            .text(&self.machine)
            .text(&self.box_id)
            .text(&self.class)
            .text(&self.environment)
            .text(&self.orchestration)
            .text(&self.hub_identity_fp)
            .text(&self.identity_fp)
            .text(&self.channel_fp)
            .text(&self.delivery_fp)
            .text(&self.private_address)
            .u64(self.issued_ms)
            .text(&self.nonce)
            .text(&self.registrar_fp);
        e.bytes().to_vec()
    }

    /// What names this attestation in the replay set: the digest of what was signed and the signature.
    pub fn digest(&self) -> String {
        let mut e = Encoder::new(ATTESTATION_TAG);
        e.field(&self.signing_bytes()).text(&self.signature);
        to_hex(&e.digest())
    }

    fn shaped(&self) -> bool {
        let opt_word = |s: &str| s.is_empty() || word_ok(s);
        word_ok(&self.box_id)
            && opt_word(&self.machine)
            && word_ok(&self.class)
            && word_ok(&self.environment)
            && word_ok(&self.orchestration)
            && self.private_address.len() <= 64
            && self.nonce.len() == 32
            && unhex(&self.nonce).is_some()
            && unhex(&self.signature).is_some_and(|s| s.len() == 64)
    }
}

/// The bytes a worker's channel key signs to prove it holds the attested key, for this hub, now.
pub fn proof_bytes(
    hub_identity_fp: &str,
    worker: &str,
    attestation_digest: &str,
    proof_ms: u64,
    nonce: &str,
) -> Vec<u8> {
    let mut e = Encoder::new(ENROL_PROOF_TAG);
    e.text(hub_identity_fp)
        .text(worker)
        .text(attestation_digest)
        .u64(proof_ms)
        .text(nonce);
    e.bytes().to_vec()
}

/// [`proof_bytes`] for a request that also offers the worker's approval-service pin: the same bytes, then the pin's fields under a
/// marker, so the proof (signed by the attested channel key) covers the pin and the pin cannot be swapped on the way to the hub.
/// With no pin it is exactly [`proof_bytes`].
pub fn proof_bytes_pinned(
    hub_identity_fp: &str,
    worker: &str,
    attestation_digest: &str,
    proof_ms: u64,
    nonce: &str,
    pin: Option<&ServicePin>,
) -> Vec<u8> {
    let mut e = Encoder::new(ENROL_PROOF_TAG);
    e.text(hub_identity_fp)
        .text(worker)
        .text(attestation_digest)
        .u64(proof_ms)
        .text(nonce);
    if let Some(p) = pin {
        e.text("service-pin")
            .text(&p.ids.box_id)
            .text(&p.ids.store_id)
            .text(&p.envelope_key_hex);
    }
    e.bytes().to_vec()
}

/// What a worker presents. The token is a secret: it is never printed (see the `Debug` below) and never kept by the hub.
#[derive(Clone, Serialize, Deserialize)]
pub struct EnrolRequest {
    pub worker: String,
    pub token: Zeroizing<String>,
    pub identity: Identity,
    pub attestation: Attestation,
    pub proof_ms: u64,
    /// 16 random bytes, hex.
    pub proof_nonce: String,
    /// Hex.
    pub proof_sig: String,
    /// The worker's approval service: the ids its digests are computed with and the public half of the key its request envelopes are
    /// signed with. Public. It is covered by the proof, so only the attested key can offer it; the owner confirms it in the
    /// enrolment plan, and `main` pins it from the roster, never from a message ([`ozbox_core::hub::approvals`]).
    #[serde(default)]
    pub service_pin: Option<ServicePin>,
}

impl std::fmt::Debug for EnrolRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // the token is never printed
        f.debug_struct("EnrolRequest")
            .field("worker", &self.worker)
            .field("identity_fp", &self.identity.identity_fp())
            .field("box_id", &self.attestation.box_id)
            .finish_non_exhaustive()
    }
}

fn random_hex(n: usize) -> Result<String, Refusal> {
    let mut b = Zeroizing::new(vec![0u8; n]);
    getrandom::getrandom(&mut b)
        .map_err(|_| no(CODE_SERVICE, "no random numbers are available"))?;
    Ok(hex(&b))
}

/// The worker's side: make the request from its own service (the proof is signed there) and the token it was given.
pub fn make_request(
    ops: &dyn KeyOps,
    worker: &str,
    token: &str,
    attestation: Attestation,
    hub_identity_fp: &str,
    now: u64,
) -> Result<EnrolRequest, Refusal> {
    make_request_with_pin(ops, worker, token, attestation, hub_identity_fp, now, None)
}

/// [`make_request`] that also offers the worker's approval service for the owner to pin.
pub fn make_request_with_pin(
    ops: &dyn KeyOps,
    worker: &str,
    token: &str,
    attestation: Attestation,
    hub_identity_fp: &str,
    now: u64,
    service_pin: Option<ServicePin>,
) -> Result<EnrolRequest, Refusal> {
    let identity = ops
        .identity()
        .map_err(|_| no(CODE_SERVICE, "the worker's secrets service did not answer"))?;
    let nonce = random_hex(16)?;
    let bytes = proof_bytes_pinned(
        hub_identity_fp,
        worker,
        &attestation.digest(),
        now,
        &nonce,
        service_pin.as_ref(),
    );
    let sig = ops.sign(SignPurpose::EnrolProof, &bytes).map_err(|_| {
        no(
            CODE_SERVICE,
            "the worker's secrets service did not sign the proof",
        )
    })?;
    Ok(EnrolRequest {
        worker: worker.to_string(),
        token: Zeroizing::new(token.to_string()),
        identity,
        attestation,
        proof_ms: now,
        proof_nonce: nonce,
        proof_sig: hex(&sig),
        service_pin,
    })
}

/// An invite the hub made: who may enrol, as which box, bound to what. The token itself is not here, only its MAC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invite {
    pub worker: String,
    pub box_id: String,
    pub provider: Provider,
    /// The instance id the hub created (AWS), or the machine id; empty when the provider does not bind by machine.
    pub machine: String,
    /// The Cloud Network address (Hetzner); empty elsewhere.
    pub private_address: String,
    pub orchestration: String,
    /// The secrets service's MAC of the token, hex. Never the token.
    pub token_tag: String,
    pub expires_ms: u64,
}

/// What an invite will do, before it is done. No token: the token is made at apply and returned once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvitePlan {
    pub worker: String,
    pub box_id: String,
    pub provider: Provider,
    pub machine: String,
    pub private_address: String,
    pub orchestration: String,
    pub valid_for_ms: u64,
    pub steps: Vec<String>,
    pub based_on: String,
}

/// A screened request, waiting for its enrolment to be planned and applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pending {
    pub worker: String,
    pub identity: Identity,
    pub attestation: Attestation,
    pub proof_nonce: String,
    /// The MAC of the token that was presented (compared again at apply), hex.
    pub token_tag: String,
    pub received_ms: u64,
    /// The approval service the worker offered (covered by its proof). Pinned on `main` only when the owner applies the enrolment.
    #[serde(default)]
    pub service_pin: Option<ServicePin>,
}

/// What an enrolment will record, before it is recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrolPlan {
    pub worker: String,
    pub box_id: String,
    pub provider: Provider,
    pub machine: String,
    pub registrar_fp: String,
    pub identity_fp: String,
    pub channel_fp: String,
    pub delivery_fp: String,
    pub steps: Vec<String>,
    pub based_on: String,
}

/// A worker in the roster: the keys its enrolment attested, and who attested them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterRecord {
    pub worker: String,
    pub box_id: String,
    pub provider: Provider,
    pub machine: String,
    pub orchestration: String,
    pub identity: Identity,
    pub identity_fp: String,
    pub channel_fp: String,
    pub registrar_fp: String,
    pub enrolled_ms: u64,
    /// The worker's approval service as its enrolment pinned it (the ids and the public envelope key), or none when the worker
    /// offered none. `main` reads its pin from here and nowhere else.
    #[serde(default)]
    pub service_pin: Option<ServicePin>,
}

/// Everything enrolment keeps. Plain data; it persists inside the daemon's state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrolState {
    pub invites: BTreeMap<String, Invite>,
    pub pending: BTreeMap<String, Pending>,
    pub roster: BTreeMap<String, RosterRecord>,
    /// Attestation digests and proof nonces already taken, with when.
    pub seen: BTreeMap<String, u64>,
}

/// What the checks need from outside.
pub struct Ctx<'a> {
    /// The hub's own service, as `ozbox-hubd` reaches it (the token's MAC).
    pub ops: &'a dyn KeyOps,
    pub registrars: &'a Registrars,
    /// The hub's identity fingerprint.
    pub hub_identity_fp: &'a str,
    /// The hub's own box id: `main` never enrols as its own worker.
    pub hub_box_id: &'a str,
    pub now: u64,
}

/// What an invite is planned from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteSpec {
    pub worker: String,
    pub box_id: String,
    pub provider: Provider,
    #[serde(default)]
    pub machine: String,
    #[serde(default)]
    pub private_address: String,
    pub orchestration: String,
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn sha(bytes: &[u8]) -> String {
    to_hex(digest(&SHA256, bytes).as_ref())
}

impl EnrolState {
    /// Forget replay entries older than the window.
    pub fn prune(&mut self, now: u64) {
        self.seen
            .retain(|_, at| now.saturating_sub(*at) < SEEN_KEEP_MS);
    }

    /// The digest of what an invite or an enrolment depends on: the roster's keys, the invites and the pending requests.
    pub fn based_on(&self) -> String {
        let roster: Vec<(&String, &String, &String)> = self
            .roster
            .values()
            .map(|r| (&r.worker, &r.identity_fp, &r.box_id))
            .collect();
        let invites: Vec<(&String, &String, &String, u64)> = self
            .invites
            .values()
            .map(|i| (&i.worker, &i.box_id, &i.token_tag, i.expires_ms))
            .collect();
        let pending: Vec<(&String, String)> = self
            .pending
            .values()
            .map(|p| (&p.worker, p.attestation.digest()))
            .collect();
        sha(&serde_json::to_vec(&(roster, invites, pending)).unwrap_or_default())
    }

    /// Plan an invite. Refused for a malformed spec, a worker or box already enrolled, or a binding the provider needs but the spec
    /// does not name. An unexpired invite for the same worker is replaced by applying (the old token stops working).
    pub fn plan_invite(&self, s: &InviteSpec, hub_box_id: &str) -> Result<InvitePlan, Refusal> {
        let opt_word = |x: &str| x.is_empty() || word_ok(x);
        if !word_ok(&s.worker)
            || !word_ok(&s.box_id)
            || !word_ok(&s.orchestration)
            || !opt_word(&s.machine)
            || s.private_address.len() > 64
        {
            return Err(no(CODE_MALFORMED, "the invite is not valid"));
        }
        if s.box_id == hub_box_id {
            return Err(no(
                CODE_PRODUCTION_BOX,
                "main is the hub and never one of its own workers",
            ));
        }
        if self.roster.contains_key(&s.worker) {
            return Err(no(CODE_ALREADY, "that worker is already enrolled"));
        }
        if self.roster.values().any(|r| r.box_id == s.box_id) {
            return Err(no(
                CODE_DUPLICATE,
                "that box is already a worker under another name",
            ));
        }
        let binding = match s.provider {
            Provider::Aws => !s.machine.is_empty(),
            Provider::Hetzner => !s.private_address.is_empty(),
            Provider::Own => true,
        };
        if !binding {
            return Err(no(
                CODE_BINDING,
                "the invite does not name what binds the worker to its machine (the instance on AWS, the private address on Hetzner)",
            ));
        }
        let mut steps = vec![format!(
            "make a one-use enrolment token for worker {} (box {}), valid 30 minutes; the hub keeps only its MAC",
            s.worker, s.box_id
        )];
        steps.push(format!(
            "accept only an attestation from a pinned {} registrar for orchestration {}",
            s.provider.word(),
            s.orchestration
        ));
        if self.invites.contains_key(&s.worker) {
            steps.push(format!("replace the earlier invite for {}", s.worker));
        }
        Ok(InvitePlan {
            worker: s.worker.clone(),
            box_id: s.box_id.clone(),
            provider: s.provider,
            machine: s.machine.clone(),
            private_address: s.private_address.clone(),
            orchestration: s.orchestration.clone(),
            valid_for_ms: TOKEN_TTL_MS,
            steps,
            based_on: self.based_on(),
        })
    }

    /// Apply a planned invite: make the token, keep its MAC, and return the token **once**.
    pub fn apply_invite(
        &mut self,
        plan: &InvitePlan,
        ops: &dyn KeyOps,
        now: u64,
    ) -> Result<Zeroizing<String>, Refusal> {
        if plan.based_on != self.based_on() {
            return Err(no(
                CODE_STALE_PLAN,
                "the roster changed since this plan was made; plan again",
            ));
        }
        let token = Zeroizing::new(random_hex(TOKEN_BYTES)?);
        let tag = ops
            .mac(token.as_bytes())
            .map_err(|_| no(CODE_SERVICE, "the secrets service did not answer"))?;
        self.pending.remove(&plan.worker);
        self.invites.insert(
            plan.worker.clone(),
            Invite {
                worker: plan.worker.clone(),
                box_id: plan.box_id.clone(),
                provider: plan.provider,
                machine: plan.machine.clone(),
                private_address: plan.private_address.clone(),
                orchestration: plan.orchestration.clone(),
                token_tag: hex(&tag),
                expires_ms: now.saturating_add(TOKEN_TTL_MS),
            },
        );
        Ok(token)
    }

    /// Screen a request and hold it as pending. Nothing is in the roster until the enrolment is planned and applied. Sending the
    /// same request again while it is pending is not a replay.
    pub fn receive(&mut self, cx: &Ctx<'_>, req: &EnrolRequest) -> Result<(), Refusal> {
        self.prune(cx.now);
        if let Some(p) = self.pending.get(&req.worker) {
            if p.attestation == req.attestation
                && p.identity == req.identity
                && p.proof_nonce == req.proof_nonce
            {
                return Ok(());
            }
        }
        let pending = self.screen(cx, req)?;
        self.pending.insert(req.worker.clone(), pending);
        Ok(())
    }

    fn screen(&self, cx: &Ctx<'_>, req: &EnrolRequest) -> Result<Pending, Refusal> {
        let a = &req.attestation;
        let Some(id) = req.identity.checked() else {
            return Err(no(CODE_MALFORMED, "the request's keys are not valid"));
        };
        if !word_ok(&req.worker)
            || !a.shaped()
            || req.proof_nonce.len() != 32
            || unhex(&req.proof_nonce).is_none()
            || req.token.len() != TOKEN_BYTES * 2
        {
            return Err(no(CODE_MALFORMED, "the request is not valid"));
        }
        if self.roster.contains_key(&req.worker) {
            return Err(no(
                CODE_ALREADY,
                "that worker is already enrolled; its key is not replaced by a second enrolment",
            ));
        }
        let digest = a.digest();
        let used = |k: &str| {
            self.seen.contains_key(k)
                || self.pending.values().any(|p| {
                    p.worker != req.worker && (p.attestation.digest() == k || p.proof_nonce == k)
                })
        };
        if used(&digest)
            || used(&req.proof_nonce)
            || self
                .seen
                .contains_key(&format!("removed:{}", id.identity_fp()))
        {
            return Err(no(
                CODE_REPLAYED,
                "that attestation or proof was already used",
            ));
        }
        let Some(inv) = self
            .invites
            .get(&req.worker)
            .filter(|i| i.box_id == a.box_id)
        else {
            return Err(no(CODE_UNKNOWN_BOX, "this hub is not expecting that box"));
        };
        if cx.now > inv.expires_ms {
            return Err(no(
                CODE_TOKEN_EXPIRED,
                "the enrolment token has expired; invite the worker again",
            ));
        }
        let tag = cx
            .ops
            .mac(req.token.as_bytes())
            .map_err(|_| no(CODE_SERVICE, "the secrets service did not answer"))?;
        if !unhex(&inv.token_tag).is_some_and(|want| ct_eq(&want, &tag)) {
            return Err(no(
                CODE_BAD_TOKEN,
                "the enrolment token is not the one this hub issued",
            ));
        }
        if a.provider != inv.provider {
            return Err(no(
                CODE_BINDING,
                "the attestation is for another provider than the invite",
            ));
        }
        let Some(reg) = cx.registrars.find(&a.registrar_fp, a.provider) else {
            return Err(no(
                CODE_UNKNOWN_REGISTRAR,
                "the attestation is not from a registrar this hub's setup pinned",
            ));
        };
        let sig = unhex(&a.signature).unwrap_or_default();
        if !verify_ed25519(&reg.public, &a.signing_bytes(), &sig) {
            return Err(no(
                CODE_BAD_ATTESTATION,
                "the attestation's signature does not verify",
            ));
        }
        if a.issued_ms.saturating_add(ATTESTATION_MAX_AGE_MS) < cx.now
            || a.issued_ms > cx.now.saturating_add(MAX_SKEW_MS)
        {
            return Err(no(
                CODE_STALE,
                "the attestation is too old, or from the future",
            ));
        }
        // decision D2 on enrolment: only a box positively attested as a worker, for a non-Production environment, and never main
        if a.class != WORKER_CLASS
            || is_production_environment(&a.environment)
            || a.box_id == cx.hub_box_id
        {
            return Err(no(
                CODE_PRODUCTION_BOX,
                "that box is not attested as a non-Production worker; a Production box is never a worker",
            ));
        }
        if a.hub_identity_fp != cx.hub_identity_fp {
            return Err(no(CODE_WRONG_HUB, "the attestation is for another hub"));
        }
        let bound = a.orchestration == inv.orchestration
            && match a.provider {
                Provider::Aws => !inv.machine.is_empty() && a.machine == inv.machine,
                Provider::Hetzner => {
                    !inv.private_address.is_empty() && a.private_address == inv.private_address
                }
                Provider::Own => inv.machine.is_empty() || a.machine == inv.machine,
            };
        if !bound {
            return Err(no(
                CODE_BINDING,
                "the attestation names another machine, address or orchestration than the hub created",
            ));
        }
        if a.identity_fp != id.identity_fp()
            || a.channel_fp != id.channel_fp()
            || a.delivery_fp != id.delivery_fp()
        {
            return Err(no(
                CODE_WRONG_KEY,
                "the keys presented are not the keys attested",
            ));
        }
        if req.proof_ms.abs_diff(cx.now) > MAX_SKEW_MS {
            return Err(no(CODE_STALE, "the proof is too old, or from the future"));
        }
        if let Some(pin) = &req.service_pin {
            if !word_ok(&pin.ids.box_id)
                || !word_ok(&pin.ids.store_id)
                || pin.envelope_key_hex.len() != 64
                || unhex(&pin.envelope_key_hex).is_none()
            {
                return Err(no(
                    CODE_MALFORMED,
                    "the approval service's pin is not valid",
                ));
            }
        }
        let bytes = proof_bytes_pinned(
            cx.hub_identity_fp,
            &req.worker,
            &digest,
            req.proof_ms,
            &req.proof_nonce,
            req.service_pin.as_ref(),
        );
        let psig = unhex(&req.proof_sig).unwrap_or_default();
        if !verify_ed25519(&id.sign_public, &bytes, &psig) {
            return Err(no(
                CODE_WRONG_KEY,
                "the proof was not signed by the attested key",
            ));
        }
        let clash = |box_id: &str, machine: &str, ifp: &str, cfp: &str| {
            box_id == a.box_id
                || (!machine.is_empty() && machine == a.machine)
                || ifp == id.identity_fp()
                || cfp == id.channel_fp()
        };
        if self
            .roster
            .values()
            .any(|r| clash(&r.box_id, &r.machine, &r.identity_fp, &r.channel_fp))
            || self.pending.values().any(|p| {
                p.worker != req.worker
                    && clash(
                        &p.attestation.box_id,
                        &p.attestation.machine,
                        &p.identity.identity_fp(),
                        &p.identity.channel_fp(),
                    )
            })
        {
            return Err(no(
                CODE_DUPLICATE,
                "another worker already has that key or that box",
            ));
        }
        Ok(Pending {
            worker: req.worker.clone(),
            identity: id,
            attestation: a.clone(),
            proof_nonce: req.proof_nonce.clone(),
            token_tag: hex(&tag),
            received_ms: cx.now,
            service_pin: req.service_pin.clone(),
        })
    }

    /// Plan the enrolment of a pending worker.
    pub fn plan_enrol(&self, worker: &str) -> Result<EnrolPlan, Refusal> {
        let p = self.pending.get(worker).ok_or_else(|| {
            no(
                CODE_NOTHING_PENDING,
                "no request from that worker is waiting",
            )
        })?;
        let a = &p.attestation;
        Ok(EnrolPlan {
            worker: worker.to_string(),
            box_id: a.box_id.clone(),
            provider: a.provider,
            machine: a.machine.clone(),
            registrar_fp: a.registrar_fp.clone(),
            identity_fp: p.identity.identity_fp(),
            channel_fp: p.identity.channel_fp(),
            delivery_fp: p.identity.delivery_fp(),
            steps: vec![
                format!(
                    "add worker {worker} (box {}) to the roster with key {}, attested by {} registrar {}",
                    a.box_id,
                    p.identity.channel_fp(),
                    a.provider.word(),
                    a.registrar_fp
                ),
                match &p.service_pin {
                    Some(pin) => format!(
                        "pin {worker}'s approval service: box {} store {} envelope key {} (a request is shown only if it is signed by this key)",
                        pin.ids.box_id,
                        pin.ids.store_id,
                        pin.envelope_key_hex.chars().take(16).collect::<String>()
                    ),
                    None => format!(
                        "pin no approval service for {worker}: nothing it asks will be shown as a request"
                    ),
                },
                format!("burn the enrolment token for {worker}"),
            ],
            based_on: self.based_on(),
        })
    }

    /// Apply a planned enrolment: the checks again, then the roster, then the token burnt. Returns the new record.
    pub fn apply_enrol(&mut self, cx: &Ctx<'_>, plan: &EnrolPlan) -> Result<RosterRecord, Refusal> {
        self.prune(cx.now);
        if plan.based_on != self.based_on() {
            return Err(no(
                CODE_STALE_PLAN,
                "the roster changed since this plan was made; plan again",
            ));
        }
        let p = self.pending.get(&plan.worker).cloned().ok_or_else(|| {
            no(
                CODE_NOTHING_PENDING,
                "no request from that worker is waiting",
            )
        })?;
        let inv = self
            .invites
            .get(&plan.worker)
            .filter(|i| i.box_id == p.attestation.box_id)
            .ok_or_else(|| no(CODE_UNKNOWN_BOX, "this hub is not expecting that box"))?;
        if cx.now > inv.expires_ms {
            return Err(no(
                CODE_TOKEN_EXPIRED,
                "the enrolment token has expired; invite the worker again",
            ));
        }
        let (Some(a), Some(b)) = (unhex(&inv.token_tag), unhex(&p.token_tag)) else {
            return Err(no(
                CODE_BAD_TOKEN,
                "the enrolment token is not the one this hub issued",
            ));
        };
        if !ct_eq(&a, &b) {
            return Err(no(
                CODE_BAD_TOKEN,
                "the enrolment token is not the one this hub issued",
            ));
        }
        if cx
            .registrars
            .find(&p.attestation.registrar_fp, p.attestation.provider)
            .is_none()
        {
            return Err(no(
                CODE_UNKNOWN_REGISTRAR,
                "the registrar that attested this worker is no longer pinned",
            ));
        }
        let rec = RosterRecord {
            worker: p.worker.clone(),
            box_id: p.attestation.box_id.clone(),
            provider: p.attestation.provider,
            machine: p.attestation.machine.clone(),
            orchestration: p.attestation.orchestration.clone(),
            identity_fp: p.identity.identity_fp(),
            channel_fp: p.identity.channel_fp(),
            identity: p.identity.clone(),
            registrar_fp: p.attestation.registrar_fp.clone(),
            enrolled_ms: cx.now,
            service_pin: p.service_pin.clone(),
        };
        self.seen.insert(p.attestation.digest(), cx.now);
        self.seen.insert(p.proof_nonce.clone(), cx.now);
        self.pending.remove(&plan.worker);
        self.invites.remove(&plan.worker);
        self.roster.insert(plan.worker.clone(), rec.clone());
        Ok(rec)
    }

    /// Take a worker out of the roster (it is destroyed or drained). Its key is not accepted again, under any name, for the replay
    /// window ([`SEEN_KEEP_MS`]).
    pub fn remove(&mut self, worker: &str, now: u64) -> bool {
        match self.roster.remove(worker) {
            Some(r) => {
                self.seen.insert(format!("removed:{}", r.identity_fp), now);
                true
            }
            None => false,
        }
    }
}
