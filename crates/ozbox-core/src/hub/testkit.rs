//! Test helpers for the hub's approval path: a WebAuthn credential that makes real P-256 assertions, as an owner's authenticator
//! would on `main`'s dashboard. For tests and the in-process fleet harness only; nothing on a box uses it.

use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

use crate::approval::PasskeyEvidence;
use crate::approval_subject::to_hex;
use crate::approval_verify::ExpectedRp;

/// The relying party the test dashboard uses.
pub fn test_rp() -> ExpectedRp {
    ExpectedRp {
        rp_id: "dash.example.com".into(),
        origin: "https://dash.example.com".into(),
    }
}

/// A WebAuthn credential, as the owner's authenticator holds it.
pub struct Passkey {
    pub id: String,
    key: EcdsaKeyPair,
}

impl Passkey {
    pub fn new(id: &str) -> Option<Passkey> {
        let rng = SystemRandom::new();
        let pk = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).ok()?;
        Some(Passkey {
            id: id.into(),
            key: EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pk.as_ref(), &rng)
                .ok()?,
        })
    }

    /// The public point (SEC1 uncompressed), hex: what an approver set lists.
    pub fn public_hex(&self) -> String {
        to_hex(self.key.public_key().as_ref())
    }

    /// What a browser makes for `challenge` on `rp`: authenticator data with the flags and counter, client data, a signature.
    pub fn assert(
        &self,
        rp: &ExpectedRp,
        challenge: &[u8; 32],
        flags: u8,
        counter: u32,
    ) -> Option<PasskeyEvidence> {
        let mut ad = ring::digest::digest(&ring::digest::SHA256, rp.rp_id.as_bytes())
            .as_ref()
            .to_vec();
        ad.push(flags);
        ad.extend_from_slice(&counter.to_be_bytes());
        let cd = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"{}"}}"#,
            b64url(challenge),
            rp.origin
        )
        .into_bytes();
        let mut payload = ad.clone();
        payload.extend_from_slice(ring::digest::digest(&ring::digest::SHA256, &cd).as_ref());
        let sig = self.key.sign(&SystemRandom::new(), &payload).ok()?;
        Some(PasskeyEvidence {
            credential_id: self.id.clone(),
            authenticator_data: to_hex(&ad),
            client_data: to_hex(&cd),
            signature: to_hex(sig.as_ref()),
        })
    }
}

/// Unpadded base64url, as a WebAuthn client data challenge is written.
pub fn b64url(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for c in b.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..=c.len() {
            out.push(char::from(A[((n >> (18 - 6 * i)) & 63) as usize]));
        }
    }
    out
}
