//! The registrars that vouch for a worker's box identity (ADR 0042, "Identity and attestation", and its registrars amendment).
//!
//! The hub accepts a worker's keys only with an **attestation** signed by a registrar the setup identity pinned
//! ([`crate::enrol`]). This module builds the registrars:
//!
//! * [`aws`]: the claim-service path. A worker proves it is the EC2 instance it claims with the instance identity document AWS
//!   signed; the registrar checks AWS's signature against AWS's published certificates ([`aws_certs`]), the account, the region,
//!   the instance's age and the one-use token, binds the claim to the worker's own key, and signs the attestation. No AWS API call.
//! * [`laptop`]: your own computer as the registrar for Hetzner and for machines you own, after a plan you confirm.
//! * [`pins`]: `ozbox hub repin`, the plan-then-apply change of which registrars `main` trusts.
//!
//! A registrar's private key is never in this crate's state, a plan, a refusal or `Debug` output; it sits behind [`AttestSigner`].

pub mod aws;
pub mod aws_certs;
pub mod der;
#[cfg(test)]
mod fixtures;
pub mod laptop;
pub mod pins;
#[cfg(test)]
mod tests;

use ozbox_core::channel::wire::{fingerprint, hex, unhex};
use ring::signature::{Ed25519KeyPair, KeyPair};
use zeroize::Zeroizing;

use crate::enrol::{Attestation, Refusal};
pub use crate::enrol::{
    CODE_BAD_TOKEN, CODE_MALFORMED, CODE_PRODUCTION_BOX, CODE_STALE_PLAN, CODE_WRONG_KEY,
};

/// Refusal codes the registrars add to the hub's own ([`crate::enrol`]). Each has its own test.
pub const CODE_BAD_SIGNATURE: &str = "bad-signature";
pub const CODE_UNKNOWN_REGION: &str = "unknown-region";
pub const CODE_WRONG_REGION: &str = "wrong-region";
pub const CODE_WRONG_ACCOUNT: &str = "wrong-account";
pub const CODE_STALE_DOCUMENT: &str = "stale-document";
pub const CODE_STALE_CLAIM: &str = "stale-claim";
pub const CODE_UNKNOWN_INSTANCE: &str = "unknown-instance";
pub const CODE_WRONG_INSTANCE: &str = "wrong-instance";
pub const CODE_REPLAYED_CLAIM: &str = "replayed-claim";
pub const CODE_ALREADY_ATTESTED: &str = "already-attested";
pub const CODE_SIGNER: &str = "signer";
pub const CODE_NOT_ON_A_BOX: &str = "refused-on-a-box";
pub const CODE_BAD_CREATION_PROOF: &str = "bad-creation-proof";
pub const CODE_UNSUPPORTED_PROVIDER: &str = "unsupported-provider";
pub const CODE_NOT_ROOT: &str = "not-root";
pub const CODE_BAD_PIN: &str = "bad-pin";
pub const CODE_NO_SUCH_PIN: &str = "no-such-pin";
pub const CODE_DUPLICATE_PIN: &str = "duplicate-pin";
pub const CODE_WRITE: &str = "write";

pub(crate) fn no(code: &'static str, message: &str) -> Refusal {
    Refusal {
        code,
        message: message.to_string(),
    }
}

/// What signs an attestation. The claim service holds one; your computer holds the other. Never a box.
pub trait AttestSigner {
    /// The Ed25519 public key, hex: what `ozbox hub repin` pins.
    fn public_hex(&self) -> String;
    /// An Ed25519 signature over `bytes`.
    fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>, String>;
}

/// An Ed25519 key made from a seed. The seed is wiped when this is dropped and is never printed.
pub struct SeedSigner {
    pair: Ed25519KeyPair,
}

impl SeedSigner {
    /// From a 32-byte seed in hex.
    pub fn from_seed_hex(seed: &Zeroizing<String>) -> Result<Self, String> {
        let bytes = Zeroizing::new(unhex(seed).ok_or("the seed is not hex")?);
        let pair =
            Ed25519KeyPair::from_seed_unchecked(&bytes).map_err(|_| "the seed is not 32 bytes")?;
        Ok(SeedSigner { pair })
    }

    /// A new random key, and its seed (hex) for the store that will keep it.
    pub fn generate() -> Result<(Zeroizing<String>, SeedSigner), String> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(&mut *seed).map_err(|_| "no random numbers are available")?;
        let s = Zeroizing::new(hex(&*seed));
        let signer = SeedSigner::from_seed_hex(&s)?;
        Ok((s, signer))
    }
}

impl std::fmt::Debug for SeedSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SeedSigner")
            .field("fingerprint", &fingerprint(self.pair.public_key().as_ref()))
            .finish_non_exhaustive()
    }
}

impl AttestSigner for SeedSigner {
    fn public_hex(&self) -> String {
        hex(self.pair.public_key().as_ref())
    }
    fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        Ok(self.pair.sign(bytes).as_ref().to_vec())
    }
}

/// The fingerprint a pin and an attestation name a registrar by.
pub fn registrar_fingerprint(signer: &dyn AttestSigner) -> String {
    unhex(&signer.public_hex())
        .map(|b| fingerprint(&b))
        .unwrap_or_default()
}

/// Fill the registrar's fingerprint and signature into a finished record. The record's own fields are not changed.
pub(crate) fn sign_attestation(
    signer: &dyn AttestSigner,
    mut a: Attestation,
) -> Result<Attestation, Refusal> {
    a.registrar_fp = registrar_fingerprint(signer);
    a.signature = String::new();
    let sig = signer
        .sign(&a.signing_bytes())
        .map_err(|_| no(CODE_SIGNER, "the registrar's key did not sign"))?;
    a.signature = hex(&sig);
    Ok(a)
}

pub(crate) fn random_hex(n: usize) -> Result<String, Refusal> {
    let mut b = vec![0u8; n];
    getrandom::getrandom(&mut b).map_err(|_| no(CODE_SIGNER, "no random numbers are available"))?;
    Ok(hex(&b))
}
