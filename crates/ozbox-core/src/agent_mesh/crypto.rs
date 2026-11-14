//! Ed25519 signing for the mesh, through `ring`. The private half is held by [`RingSigner`] and never printed.

use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};

use super::wire::{Signer, Verifier};

/// A new Ed25519 key: the PKCS#8 bytes to store (a secret) and the public key in hex.
pub fn generate() -> Result<(Vec<u8>, String), String> {
    let rng = SystemRandom::new();
    let doc = Ed25519KeyPair::generate_pkcs8(&rng).map_err(|_| "no random numbers".to_string())?;
    let pair = Ed25519KeyPair::from_pkcs8(doc.as_ref())
        .map_err(|_| "key could not be made".to_string())?;
    Ok((doc.as_ref().to_vec(), to_hex(pair.public_key().as_ref())))
}

pub fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// The fingerprint a person compares when pinning: SHA-256 of the public key, first 16 bytes, groups of eight hex digits.
pub fn fingerprint(public_hex: &str) -> String {
    let d = ring::digest::digest(&ring::digest::SHA256, public_hex.as_bytes());
    let hex = to_hex(&d.as_ref()[..16]);
    hex.as_bytes()
        .chunks(8)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join("-")
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
        to_hex(self.pair.public_key().as_ref())
    }
}

impl Signer for RingSigner {
    fn sign(&self, canonical: &[u8]) -> Result<Vec<u8>, String> {
        Ok(self.pair.sign(canonical).as_ref().to_vec())
    }
}

pub struct RingVerifier;

impl Verifier for RingVerifier {
    fn verify(&self, signer_public_hex: &str, canonical: &[u8], signature: &[u8]) -> bool {
        let Some(pk) = from_hex(signer_public_hex) else {
            return false;
        };
        UnparsedPublicKey::new(&ED25519, pk)
            .verify(canonical, signature)
            .is_ok()
    }
}
