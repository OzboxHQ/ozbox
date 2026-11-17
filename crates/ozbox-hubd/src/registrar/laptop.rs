//! Your own computer as the registrar, for workers with no cloud identity (ADR 0042, "Identity and attestation": Hetzner and own
//! machines).
//!
//! `main` **prepares a request** from public facts only (the machine, the box, the orchestration, the hub's fingerprint, the
//! worker's public keys). Your computer **plans** what it would sign, shows it, and signs only after you confirm (ADR 0002). The
//! signing key lives in your computer's own store and is never on a box.
//!
//! * **Hetzner.** The request carries a **creation proof**: an HMAC over the worker's keys under the one-time creation secret your
//!   computer generated and placed in the worker's user data after planning. A worker that did not get that secret cannot make
//!   it, and `main`, which never saw the secret, cannot forge it. The worker is also bound to its private address.
//! * **Own machines.** There is no secret to prove with. The plan shows the worker's key fingerprints so you can compare them with
//!   what you read from the machine over your own route, and your confirmation is the proof.
//!
//! **A box is never a registrar.** [`apply`] refuses on a machine that looks like a box, and the registrars file on `main` pins
//! only your computer's public key. The box user and agents have neither the key nor the file.

use std::path::PathBuf;

use ozbox_core::approval_subject::{is_production_environment, to_hex, Encoder};
use ozbox_core::channel::wire::{hex, unhex, word_ok};
use ring::hmac;
use serde::{Deserialize, Serialize};

use super::*;
use crate::enrol::{Attestation, Provider, Refusal, WORKER_CLASS};
use crate::identity::Identity;

/// The tag a plan's binding digest and a creation proof are made under.
pub const REQUEST_TAG: &str = "ozbox-registrar-laptop-request-v1";

/// What `main` prepares. Public facts only: nothing here is a secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaptopRequest {
    /// `hetzner` or `own`.
    pub provider: Provider,
    /// The machine's id (the server id on Hetzner).
    #[serde(default)]
    pub machine: String,
    pub box_id: String,
    pub orchestration: String,
    pub hub_identity_fp: String,
    /// The worker's address on the Cloud Network (Hetzner); empty for a machine you own.
    #[serde(default)]
    pub private_address: String,
    pub class: String,
    pub environment: String,
    pub identity: Identity,
    /// Hetzner: the worker's HMAC over its keys under the creation secret, hex. Empty for a machine you own.
    #[serde(default)]
    pub creation_proof: String,
}

impl LaptopRequest {
    /// Everything the request says, in one digest: what a plan is bound to, and what a creation proof covers (without itself).
    fn bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new(REQUEST_TAG);
        e.text(self.provider.word())
            .text(&self.machine)
            .text(&self.box_id)
            .text(&self.orchestration)
            .text(&self.hub_identity_fp)
            .text(&self.private_address)
            .text(&self.class)
            .text(&self.environment)
            .text(&self.identity.identity_fp())
            .text(&self.identity.channel_fp())
            .text(&self.identity.delivery_fp());
        e.bytes().to_vec()
    }

    fn digest(&self) -> String {
        let mut e = Encoder::new(REQUEST_TAG);
        e.field(&self.bytes()).text(&self.creation_proof);
        to_hex(&e.digest())
    }
}

/// The worker's side on Hetzner: the proof it sends back to your computer, made with the creation secret it found in user data.
pub fn creation_proof(secret: &[u8], req: &LaptopRequest) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    hex(hmac::sign(&key, &req.bytes()).as_ref())
}

/// What signing would do, before it is done. No secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaptopPlan {
    pub provider: Provider,
    pub box_id: String,
    pub machine: String,
    pub orchestration: String,
    pub hub_identity_fp: String,
    pub identity_fp: String,
    pub channel_fp: String,
    pub delivery_fp: String,
    pub steps: Vec<String>,
    /// The request's digest: a different request is a different plan.
    pub based_on: String,
}

/// Where a box shows itself. Your computer has none of these.
#[derive(Debug, Clone)]
pub struct Site {
    pub box_markers: Vec<PathBuf>,
}

impl Default for Site {
    fn default() -> Self {
        Site {
            box_markers: vec![
                PathBuf::from("/etc/ozbox"),
                PathBuf::from("/run/ozbox-secrets"),
            ],
        }
    }
}

impl Site {
    fn is_a_box(&self) -> bool {
        self.box_markers.iter().any(|p| p.exists())
    }
}

fn check(req: &LaptopRequest) -> Result<(), Refusal> {
    let opt = |s: &str| s.is_empty() || word_ok(s);
    if !word_ok(&req.box_id)
        || !word_ok(&req.orchestration)
        || !opt(&req.machine)
        || req.private_address.len() > 64
        || !word_ok(&req.class)
        || !word_ok(&req.environment)
        || req.hub_identity_fp.is_empty()
        || req.identity.checked().is_none()
    {
        return Err(no(CODE_MALFORMED, "the request is not valid"));
    }
    match req.provider {
        Provider::Aws => {
            return Err(no(
                CODE_UNSUPPORTED_PROVIDER,
                "AWS workers are attested by the claim service, not by your computer",
            ))
        }
        Provider::Hetzner
            if req.private_address.is_empty() || unhex(&req.creation_proof).is_none() =>
        {
            return Err(no(
                CODE_BAD_CREATION_PROOF,
                "a Hetzner worker needs its private address and a creation proof",
            ))
        }
        Provider::Own if req.machine.is_empty() => {
            return Err(no(CODE_MALFORMED, "name the machine you own"))
        }
        _ => {}
    }
    if req.class != WORKER_CLASS || is_production_environment(&req.environment) {
        return Err(no(
            CODE_PRODUCTION_BOX,
            "that box is not a non-Production worker; a Production box is never attested",
        ));
    }
    Ok(())
}

/// Plan what signing would do. Nothing is signed.
pub fn plan(req: &LaptopRequest) -> Result<LaptopPlan, Refusal> {
    check(req)?;
    let id = &req.identity;
    let how = match req.provider {
        Provider::Hetzner => format!(
            "check the creation proof (an HMAC under the one-time creation secret you made) and bind the worker to private address {}",
            req.private_address
        ),
        _ => "no creation secret exists for a machine you own: compare the key fingerprints below with what you read from the machine yourself".to_string(),
    };
    Ok(LaptopPlan {
        provider: req.provider,
        box_id: req.box_id.clone(),
        machine: req.machine.clone(),
        orchestration: req.orchestration.clone(),
        hub_identity_fp: req.hub_identity_fp.clone(),
        identity_fp: id.identity_fp(),
        channel_fp: id.channel_fp(),
        delivery_fp: id.delivery_fp(),
        steps: vec![
            how,
            format!(
                "sign, with your computer's registrar key, an attestation that {} worker box {} for orchestration {} holds keys {} / {} / {}, valid for 30 minutes, for hub {} only",
                req.provider.word(),
                req.box_id,
                req.orchestration,
                id.identity_fp(),
                id.channel_fp(),
                id.delivery_fp(),
                req.hub_identity_fp
            ),
            "hand the signed attestation back; the hub still checks it, the invite's token and the worker's own proof".to_string(),
        ],
        based_on: req.digest(),
    })
}

/// Apply a confirmed plan: check the plan still matches the request, check the creation proof (Hetzner), refuse on a box, sign.
/// `creation_secret` is the one-time secret your computer made for this worker; it is read here and never kept or printed.
pub fn apply(
    plan: &LaptopPlan,
    req: &LaptopRequest,
    signer: &dyn AttestSigner,
    creation_secret: Option<&[u8]>,
    site: &Site,
    now: u64,
) -> Result<Attestation, Refusal> {
    if site.is_a_box() {
        return Err(no(
            CODE_NOT_ON_A_BOX,
            "attestations are signed on your own computer, never on a box",
        ));
    }
    check(req)?;
    if plan.based_on != req.digest() {
        return Err(no(
            CODE_STALE_PLAN,
            "the request changed since this plan was made; plan again",
        ));
    }
    if req.provider == Provider::Hetzner {
        let proof = unhex(&req.creation_proof).unwrap_or_default();
        let ok = creation_secret.is_some_and(|s| {
            hmac::verify(&hmac::Key::new(hmac::HMAC_SHA256, s), &req.bytes(), &proof).is_ok()
        });
        if !ok {
            return Err(no(
                CODE_BAD_CREATION_PROOF,
                "the creation proof is not the one the creation secret makes",
            ));
        }
    }
    let id = &req.identity;
    let a = Attestation {
        provider: req.provider,
        machine: req.machine.clone(),
        box_id: req.box_id.clone(),
        class: req.class.clone(),
        environment: req.environment.clone(),
        orchestration: req.orchestration.clone(),
        hub_identity_fp: req.hub_identity_fp.clone(),
        identity_fp: id.identity_fp(),
        channel_fp: id.channel_fp(),
        delivery_fp: id.delivery_fp(),
        private_address: req.private_address.clone(),
        issued_ms: now,
        nonce: random_hex(16)?,
        registrar_fp: String::new(),
        signature: String::new(),
    };
    sign_attestation(signer, a)
}
