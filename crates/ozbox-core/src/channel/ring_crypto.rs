//! Ed25519 signing for a channel end, through `ring`. The private half is held by [`RingSigner`] and never printed.

use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};

use super::wire::{hex, unhex, Signer, Verifier, WireError};

/// A new Ed25519 key: the PKCS#8 bytes to store (a secret) and the public key in hex.
pub fn generate() -> Result<(Vec<u8>, String), String> {
    let rng = SystemRandom::new();
    let doc = Ed25519KeyPair::generate_pkcs8(&rng).map_err(|_| "no random numbers".to_string())?;
    let pair = Ed25519KeyPair::from_pkcs8(doc.as_ref())
        .map_err(|_| "key could not be made".to_string())?;
    Ok((doc.as_ref().to_vec(), hex(pair.public_key().as_ref())))
}

pub struct RingSigner {
    pair: Ed25519KeyPair,
}

impl RingSigner {
    pub fn from_pkcs8(bytes: &[u8]) -> Result<Self, String> {
        Ed25519KeyPair::from_pkcs8(bytes)
            .map(|pair| RingSigner { pair })
            .map_err(|_| "the signing key is not valid".to_string())
    }

    pub fn public_hex(&self) -> String {
        hex(self.pair.public_key().as_ref())
    }
}

impl Signer for RingSigner {
    fn sign(&self, canonical: &[u8]) -> Result<Vec<u8>, WireError> {
        Ok(self.pair.sign(canonical).as_ref().to_vec())
    }
}

/// Verifies against the **public key the pin holds** (hex).
pub struct RingVerifier;

impl Verifier for RingVerifier {
    fn verify(&self, signer_public_hex: &str, canonical: &[u8], signature: &[u8]) -> bool {
        let Some(pk) = unhex(signer_public_hex) else {
            return false;
        };
        UnparsedPublicKey::new(&ED25519, pk)
            .verify(canonical, signature)
            .is_ok()
    }
}
