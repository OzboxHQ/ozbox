//! The AWS registrar: the claim service's path (ADR 0042, "Identity and attestation").
//!
//! **What it proves.** A worker on EC2 sends the registrar its **instance identity document** (the PKCS#7 `rsa2048` signature
//! AWS writes at `/latest/dynamic/instance-identity/rsa2048`, with the document inside it), the one-use enrolment token it
//! reads from its own parameter path, its public keys, and a **proof** signed by its own channel key. The registrar then
//! checks, in this order, each with its own refusal code:
//!
//! 1. the signature is AWS's, by the published certificate for the document's own region (`bad-signature`, `unknown-region`);
//! 2. the region is one this setup allows (`wrong-region`) and the account is this setup's (`wrong-account`);
//! 3. the instance was launched recently enough (`stale-document`: AWS stamps `pendingTime`, the launch, not the signing);
//! 4. the claim is fresh (`stale-claim`);
//! 5. the claim service's own table knows the instance (`unknown-instance`) and reserved it for **this worker**
//!    (`wrong-instance`), as a worker and not as `main`, and not for Production (`production-box`);
//! 6. the token is the one the claim service wrote to that box's parameter path (`bad-token`);
//! 7. the proof was made by the key the worker presents, for the hub the reservation names (`wrong-key`);
//! 8. the claim was not seen before (`replayed-claim`) and that instance was not attested before (`already-attested`: a key is
//!    never swapped by a second claim).
//!
//! Then it signs an [`Attestation`] naming the instance, the box, the orchestration, the hub and the worker's key fingerprints.
//!
//! **What it does not prove.** The document is not a secret: any process on the instance that can reach the metadata service
//! can read it, and it carries no signing time. So the document alone is a claim to be *an* instance, and what makes the claim
//! the worker's is the token (readable only through the box's pool role), the reservation, the freshness of the signed claim and
//! the proof. The metadata guard (who may read user data and the document) is a control on the box, not here.
//! The claim service itself (its function, its table, its key) is not built in this crate: this is the logic it calls.

use std::collections::BTreeMap;

use ozbox_core::approval_subject::{is_production_environment, to_hex, Encoder};
use ozbox_core::channel::wire::{hex, unhex, word_ok, MAX_SKEW_MS};
use ring::digest::{digest, SHA256};
use ring::signature::{UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA256};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::aws_certs::CERTS;
use super::der;
use super::*;
use crate::crypto::verify_ed25519;
use crate::enrol::{proof_bytes, Attestation, Provider, Refusal, WORKER_CLASS};
use crate::identity::Identity;
use crate::keys::SignPurpose;
use crate::ops::KeyOps;

/// The tag a claim's digest is made under, so it can never equal an attestation's digest.
pub const CLAIM_TAG: &str = "ozbox-registrar-aws-claim-v1";
/// The longest PKCS#7 accepted (they are about 1.5 KB).
pub const MAX_PKCS7_B64: usize = 16 * 1024;
/// How long a claim and its replay record are kept.
pub const SEEN_KEEP_MS: u64 = 7 * 24 * 60 * 60 * 1000;
/// The oldest instance (since launch) that may still enrol, unless the setup says otherwise.
pub const DEFAULT_MAX_INSTANCE_AGE_MS: u64 = 24 * 60 * 60 * 1000;

/// AWS's published certificates by region: the RSA public key (DER) of each.
#[derive(Debug, Clone)]
pub struct AwsCerts(BTreeMap<String, Vec<u8>>);

impl AwsCerts {
    /// The table in [`super::aws_certs`]. Fails if any certificate is not a 2048-bit RSA one: a bad table never half-loads.
    pub fn published() -> Result<Self, String> {
        let mut m = BTreeMap::new();
        for (region, _, b64) in CERTS {
            let der = der::base64_decode(b64).ok_or("a pinned certificate is not base64")?;
            let (key, bits) =
                der::certificate_rsa_key(&der).ok_or("a pinned certificate has no RSA key")?;
            if bits != 2048 {
                return Err("a pinned certificate is not 2048-bit".into());
            }
            m.insert((*region).to_string(), key);
        }
        Ok(AwsCerts(m))
    }

    /// For tests: one certificate (base64 DER) for each listed region, in place of AWS's.
    pub fn from_test_cert(regions: &[&str], cert_b64: &str) -> Result<Self, String> {
        let der = der::base64_decode(cert_b64).ok_or("not base64")?;
        let (key, _) = der::certificate_rsa_key(&der).ok_or("no RSA key")?;
        Ok(AwsCerts(
            regions
                .iter()
                .map(|r| ((*r).to_string(), key.clone()))
                .collect(),
        ))
    }

    pub fn regions(&self) -> Vec<&str> {
        self.0.keys().map(String::as_str).collect()
    }
}

/// What the setup pins for the registrar: this account, these regions, and how old an instance may be.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AwsPolicy {
    /// The 12-digit account the boxes live in.
    pub account: String,
    pub regions: Vec<String>,
    #[serde(default = "default_age")]
    pub max_instance_age_ms: u64,
}

fn default_age() -> u64 {
    DEFAULT_MAX_INSTANCE_AGE_MS
}

/// What the claim service's table holds for an instance it launched and bound (ADR 0040, section 4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimRecord {
    pub instance_id: String,
    pub worker: String,
    pub box_id: String,
    pub orchestration: String,
    /// The identity fingerprint of the hub this worker may join.
    pub hub_identity_fp: String,
    /// [`WORKER_CLASS`] for a worker. Anything else is never attested.
    pub class: String,
    /// The environment the box was created for. Not a known non-Production one means Production, and is refused.
    pub environment: String,
    /// SHA-256 of the enrolment token the claim service wrote to the box's parameter path, hex. Never the token.
    pub token_sha256: String,
}

/// The claim service's reservation table, as the registrar reads it.
pub trait ClaimTable {
    fn lookup(&self, instance_id: &str) -> Option<ClaimRecord>;
}

/// What a worker sends. The token is a secret: it is never printed and the registrar never keeps it.
#[derive(Clone, Serialize, Deserialize)]
pub struct AwsClaim {
    pub worker: String,
    pub token: Zeroizing<String>,
    pub identity: Identity,
    /// The `rsa2048` signature from the metadata service, base64, as AWS writes it (no header or footer).
    pub pkcs7: String,
    pub claim_ms: u64,
    /// 16 random bytes, hex.
    pub nonce: String,
    /// The worker's channel key's signature over [`claim_proof_bytes`], hex.
    pub proof_sig: String,
}

impl std::fmt::Debug for AwsClaim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsClaim")
            .field("worker", &self.worker)
            .field("identity_fp", &self.identity.identity_fp())
            .finish_non_exhaustive()
    }
}

fn sha(bytes: &[u8]) -> Vec<u8> {
    digest(&SHA256, bytes).as_ref().to_vec()
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// What names a claim: the worker, the hub, the signed document, the key and the time and nonce. A different tag from every
/// other digest here.
pub fn claim_digest(
    worker: &str,
    hub_identity_fp: &str,
    pkcs7: &[u8],
    identity_fp: &str,
    claim_ms: u64,
    nonce: &str,
) -> String {
    let mut e = Encoder::new(CLAIM_TAG);
    e.text(worker)
        .text(hub_identity_fp)
        .field(&sha(pkcs7))
        .text(identity_fp)
        .u64(claim_ms)
        .text(nonce);
    to_hex(&e.digest())
}

/// The bytes the worker's channel key signs to prove it holds the key it asks to have attested. They are the hub's enrolment-proof
/// bytes with the claim's digest in the attestation's place, so the secrets service signs them under the purpose it already has;
/// the digest's tag makes them unusable as an enrolment proof.
pub fn claim_proof_bytes(
    hub_identity_fp: &str,
    worker: &str,
    claim_digest: &str,
    claim_ms: u64,
    nonce: &str,
) -> Vec<u8> {
    proof_bytes(hub_identity_fp, worker, claim_digest, claim_ms, nonce)
}

/// The worker's side: make the claim from its own service. `pkcs7` is what the metadata service returned; `hub_identity_fp`
/// is the hub fingerprint it pinned at first boot.
pub fn make_claim(
    ops: &dyn KeyOps,
    worker: &str,
    token: &str,
    pkcs7: &str,
    hub_identity_fp: &str,
    now: u64,
) -> Result<AwsClaim, Refusal> {
    let identity = ops
        .identity()
        .map_err(|_| no(CODE_SIGNER, "the worker's secrets service did not answer"))?;
    let raw = der::base64_decode(pkcs7)
        .ok_or_else(|| no(CODE_MALFORMED, "the signature is not base64"))?;
    let nonce = random_hex(16)?;
    let d = claim_digest(
        worker,
        hub_identity_fp,
        &raw,
        &identity.identity_fp(),
        now,
        &nonce,
    );
    let sig = ops
        .sign(
            SignPurpose::EnrolProof,
            &claim_proof_bytes(hub_identity_fp, worker, &d, now, &nonce),
        )
        .map_err(|_| no(CODE_SIGNER, "the worker's secrets service did not sign"))?;
    Ok(AwsClaim {
        worker: worker.to_string(),
        token: Zeroizing::new(token.to_string()),
        identity,
        pkcs7: pkcs7.to_string(),
        claim_ms: now,
        nonce,
        proof_sig: hex(&sig),
    })
}

/// What the registrar remembers between claims: claims it has seen, and instances it has attested. Plain data; the claim service
/// persists it beside its table.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrarState {
    pub seen: BTreeMap<String, u64>,
    /// Instance id to the identity fingerprint attested for it.
    pub attested: BTreeMap<String, String>,
}

impl RegistrarState {
    pub fn prune(&mut self, now: u64) {
        self.seen
            .retain(|_, at| now.saturating_sub(*at) < SEEN_KEEP_MS);
    }
}

/// The fields of the signed document the registrar reads. Unknown fields are ignored: AWS adds some.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Document {
    account_id: String,
    instance_id: String,
    region: String,
    pending_time: String,
}

/// The AWS registrar.
pub struct AwsRegistrar<'a> {
    pub certs: &'a AwsCerts,
    pub policy: &'a AwsPolicy,
    pub table: &'a dyn ClaimTable,
    pub signer: &'a dyn AttestSigner,
}

fn instance_id_ok(s: &str) -> bool {
    s.len() >= 10
        && s.len() <= 21
        && s.starts_with("i-")
        && s[2..].bytes().all(|b| b.is_ascii_hexdigit())
}

fn account_ok(s: &str) -> bool {
    s.len() == 12 && s.bytes().all(|b| b.is_ascii_digit())
}

fn region_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 24
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

impl AwsRegistrar<'_> {
    /// Verify a claim and sign the attestation for it. `now` is the registrar's own clock.
    pub fn attest(
        &self,
        state: &mut RegistrarState,
        claim: &AwsClaim,
        now: u64,
    ) -> Result<Attestation, Refusal> {
        state.prune(now);
        let malformed = || no(CODE_MALFORMED, "the claim is not valid");
        let Some(id) = claim.identity.checked() else {
            return Err(malformed());
        };
        if !word_ok(&claim.worker)
            || claim.nonce.len() != 32
            || unhex(&claim.nonce).is_none()
            || claim.token.len() != crate::enrol::TOKEN_BYTES * 2
            || claim.pkcs7.len() > MAX_PKCS7_B64
            || !account_ok(&self.policy.account)
        {
            return Err(malformed());
        }
        let raw = der::base64_decode(&claim.pkcs7).ok_or_else(malformed)?;
        let sd = der::signed_data(&raw).ok_or_else(malformed)?;
        if sd.content.len() > 4096 {
            return Err(malformed());
        }
        let doc: Document = serde_json::from_slice(&sd.content).map_err(|_| malformed())?;
        if !instance_id_ok(&doc.instance_id)
            || !account_ok(&doc.account_id)
            || !region_ok(&doc.region)
        {
            return Err(malformed());
        }
        // 1. AWS's signature, by the certificate of the region the document names
        let Some(key) = self.certs.0.get(&doc.region) else {
            return Err(no(
                CODE_UNKNOWN_REGION,
                "there is no published certificate for that region",
            ));
        };
        let covered = match &sd.message_digest {
            Some(want) if !ct_eq(want, &sha(&sd.content)) => {
                return Err(no(CODE_BAD_SIGNATURE, "the signature does not verify"))
            }
            _ => &sd.signed_bytes,
        };
        if UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, key)
            .verify(covered, &sd.signature)
            .is_err()
        {
            return Err(no(CODE_BAD_SIGNATURE, "the signature does not verify"));
        }
        // 2. this setup's account and regions
        if !self.policy.regions.contains(&doc.region) {
            return Err(no(
                CODE_WRONG_REGION,
                "the instance is not in an allowed region",
            ));
        }
        if doc.account_id != self.policy.account {
            return Err(no(
                CODE_WRONG_ACCOUNT,
                "the instance is not in this setup's account",
            ));
        }
        // 3. the instance's age
        let pending = der::rfc3339_ms(&doc.pending_time).ok_or_else(malformed)?;
        if pending > now.saturating_add(MAX_SKEW_MS)
            || now.saturating_sub(pending) > self.policy.max_instance_age_ms
        {
            return Err(no(
                CODE_STALE_DOCUMENT,
                "the instance was launched too long ago to enrol",
            ));
        }
        // 4. the claim's own freshness and replay
        if claim.claim_ms.abs_diff(now) > MAX_SKEW_MS {
            return Err(no(
                CODE_STALE_CLAIM,
                "the claim is too old, or from the future",
            ));
        }
        let Some(rec) = self.table.lookup(&doc.instance_id) else {
            return Err(no(
                CODE_UNKNOWN_INSTANCE,
                "the claim service did not reserve that instance",
            ));
        };
        // 5. the reservation is this worker's, as a non-Production worker
        if rec.instance_id != doc.instance_id || rec.worker != claim.worker {
            return Err(no(
                CODE_WRONG_INSTANCE,
                "that instance was reserved for another worker",
            ));
        }
        if rec.class != WORKER_CLASS || is_production_environment(&rec.environment) {
            return Err(no(
                CODE_PRODUCTION_BOX,
                "that box is not a non-Production worker; a Production box is never attested",
            ));
        }
        // 6. the token
        let want = unhex(&rec.token_sha256).unwrap_or_default();
        if !ct_eq(&want, &sha(claim.token.as_bytes())) {
            return Err(no(
                CODE_BAD_TOKEN,
                "the enrolment token is not the one reserved",
            ));
        }
        // 7. the key proof, for the hub the reservation names
        let d = claim_digest(
            &claim.worker,
            &rec.hub_identity_fp,
            &raw,
            &id.identity_fp(),
            claim.claim_ms,
            &claim.nonce,
        );
        let bytes = claim_proof_bytes(
            &rec.hub_identity_fp,
            &claim.worker,
            &d,
            claim.claim_ms,
            &claim.nonce,
        );
        let sig = unhex(&claim.proof_sig).unwrap_or_default();
        if !verify_ed25519(&id.sign_public, &bytes, &sig) {
            return Err(no(
                CODE_WRONG_KEY,
                "the proof was not made by the presented key for this hub",
            ));
        }
        // 8. once
        if state.seen.contains_key(&d) {
            return Err(no(CODE_REPLAYED_CLAIM, "that claim was already used"));
        }
        if state.attested.contains_key(&doc.instance_id) {
            return Err(no(
                CODE_ALREADY_ATTESTED,
                "that instance already has an attestation; a key is not swapped by a second claim",
            ));
        }
        let a = Attestation {
            provider: Provider::Aws,
            machine: doc.instance_id.clone(),
            box_id: rec.box_id.clone(),
            class: rec.class.clone(),
            environment: rec.environment.clone(),
            orchestration: rec.orchestration.clone(),
            hub_identity_fp: rec.hub_identity_fp.clone(),
            identity_fp: id.identity_fp(),
            channel_fp: id.channel_fp(),
            delivery_fp: id.delivery_fp(),
            private_address: String::new(),
            issued_ms: now,
            nonce: random_hex(16)?,
            registrar_fp: String::new(),
            signature: String::new(),
        };
        let signed = sign_attestation(self.signer, a)?;
        state.seen.insert(d, now);
        state.attested.insert(doc.instance_id, id.identity_fp());
        Ok(signed)
    }
}
