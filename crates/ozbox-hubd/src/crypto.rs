//! The real signer, sealer and verifier behind `ozbox_core`'s channel seams ([`Signer`], [`Sealer`], [`Verifier`]).
//!
//! * [`ServiceSigner`] asks the secrets service to sign: no private key is ever in this process.
//! * [`ServiceSealer`] seals with HPKE (`ozbox-seal`, ADR 0029 Amendment 9) to the receiver's **attested** sealing key, found by
//!   the fingerprint the roster names, and asks the service to open what was sealed to this end.
//! * [`DirectoryVerifier`] checks Ed25519 against the **attested** signing key found by that fingerprint.
//!
//! The roster names a peer by one string, its channel fingerprint ([`Identity::channel_fp`]); the [`Directory`] maps that
//! fingerprint to the keys an enrolment attested. A fingerprint the directory does not hold seals nothing and verifies nothing.
//! This keeps the channel's seams exactly as they are (a peer is named by one opaque string) while the keys behind it are real.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use ozbox_core::channel::wire::{unhex, Sealer, Signer, Verifier, WireError};
use ring::signature::{UnparsedPublicKey, ED25519};

use crate::identity::Identity;
use crate::keys::{channel_info, SignPurpose};
use crate::ops::KeyOps;

/// Channel fingerprint to the attested public keys. Shared by the sealer, the verifier and whoever enrols.
#[derive(Clone, Default)]
pub struct Directory(Arc<RwLock<BTreeMap<String, Identity>>>);

impl Directory {
    /// Add (or replace) the keys for one end, under its channel fingerprint. An identity that is not well formed is refused.
    pub fn insert(&self, id: &Identity) -> bool {
        let Some(id) = id.checked() else {
            return false;
        };
        match self.0.write() {
            Ok(mut m) => {
                m.insert(id.channel_fp(), id);
                true
            }
            Err(_) => false,
        }
    }

    pub fn remove(&self, channel_fp: &str) {
        if let Ok(mut m) = self.0.write() {
            m.remove(channel_fp);
        }
    }

    pub fn get(&self, channel_fp: &str) -> Option<Identity> {
        self.0.read().ok()?.get(channel_fp).cloned()
    }

    pub fn len(&self) -> usize {
        self.0.read().map(|m| m.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Signs worker-channel envelopes through the secrets service.
pub struct ServiceSigner {
    pub ops: Arc<dyn KeyOps>,
}

impl Signer for ServiceSigner {
    fn sign(&self, canonical: &[u8]) -> Result<Vec<u8>, WireError> {
        // the service refuses anything else too; refusing here first keeps a wrong call from reaching it at all
        if !SignPurpose::Envelope.admits(canonical) {
            return Err(WireError::SignFailed);
        }
        self.ops
            .sign(SignPurpose::Envelope, canonical)
            .map_err(|_| WireError::SignFailed)
    }
}

/// Seals to a peer's attested key; opens through the secrets service.
pub struct ServiceSealer {
    pub ops: Arc<dyn KeyOps>,
    pub dir: Directory,
}

impl Sealer for ServiceSealer {
    fn seal(&self, receiver_fp: &str, aad: &[u8], plain: &[u8]) -> Result<Vec<u8>, WireError> {
        let id = self.dir.get(receiver_fp).ok_or(WireError::SealFailed)?;
        let pk = ozbox_seal::public_from_hex(&id.seal_public).map_err(|_| WireError::SealFailed)?;
        let (enc, ct) = ozbox_seal::seal(&pk, &channel_info(receiver_fp), aad, plain)
            .map_err(|_| WireError::SealFailed)?;
        let mut out = enc;
        out.extend_from_slice(&ct);
        Ok(out)
    }

    fn open(&self, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, WireError> {
        self.ops
            .open(aad, sealed)
            .map(|z| z.to_vec())
            .map_err(|_| WireError::BadSeal)
    }
}

/// Verifies a signature with the signing key attested for a channel fingerprint.
pub struct DirectoryVerifier {
    pub dir: Directory,
}

impl Verifier for DirectoryVerifier {
    fn verify(&self, sender_fp: &str, canonical: &[u8], signature: &[u8]) -> bool {
        let Some(pk) = self
            .dir
            .get(sender_fp)
            .and_then(|id| unhex(&id.sign_public))
        else {
            return false;
        };
        UnparsedPublicKey::new(&ED25519, pk)
            .verify(canonical, signature)
            .is_ok()
    }
}

/// Verify an Ed25519 signature with a public key in hex.
pub fn verify_ed25519(public_hex: &str, msg: &[u8], sig: &[u8]) -> bool {
    unhex(public_hex).is_some_and(|pk| {
        UnparsedPublicKey::new(&ED25519, pk)
            .verify(msg, sig)
            .is_ok()
    })
}
