//! Checking a signature on a challenge, by the keys the issuer pins. Ed25519 (a laptop key, the recovery key) and an ES256
//! WebAuthn assertion (a passkey). What is signed is always the issuer's own message, which names the box, the store, the
//! service key's fingerprint and the exact request; nothing the box sends is signed instead of it.

use ring::digest::{digest, SHA256};
use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1, ED25519};

/// The message a laptop key signs: the issuer's request message, as bytes.
pub fn verify_ed25519(public: &[u8], message: &[u8], signature: &[u8]) -> bool {
    public.len() == 32
        && UnparsedPublicKey::new(&ED25519, public)
            .verify(message, signature)
            .is_ok()
}

/// A WebAuthn assertion's three parts, as bytes.
pub struct Assertion<'a> {
    pub authenticator_data: &'a [u8],
    pub client_data_json: &'a [u8],
    pub signature: &'a [u8],
}

/// Why a passkey assertion was refused. Words for the log, never for a guess at which part was close.
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    Shape,
    Challenge,
    Origin,
    RelyingParty,
    NoUserPresence,
    NoUserVerification,
    Signature,
    Counter,
}

fn b64url(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for c in bytes.chunks(3) {
        let n = c.iter().fold(0u32, |a, b| (a << 8) | u32::from(*b)) << (8 * (3 - c.len()));
        for i in 0..=c.len() {
            out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

/// The challenge a passkey is asked to sign for a message: the SHA-256 of the message, as base64url (what the browser puts
/// in `clientDataJSON`).
pub fn passkey_challenge(message: &[u8]) -> String {
    b64url(digest(&SHA256, message).as_ref())
}

/// Check an ES256 assertion for `message`. `public` is the uncompressed P-256 point (65 bytes); `rp_id` is the relying party
/// the passkey was made for; `origin` is the exact origin the dashboard is served from. User presence **and** user
/// verification are both required (a touch is not enough for Production). `last_counter` is the highest counter seen for this
/// passkey; a counter that goes backwards is a cloned key. Returns the counter to record.
pub fn verify_passkey(
    public: &[u8],
    rp_id: &str,
    origin: &str,
    message: &[u8],
    a: &Assertion<'_>,
    last_counter: u32,
) -> Result<u32, Refused> {
    let ad = a.authenticator_data;
    if public.len() != 65 || public[0] != 4 || ad.len() < 37 {
        return Err(Refused::Shape);
    }
    let cd: serde_json::Value =
        serde_json::from_slice(a.client_data_json).map_err(|_| Refused::Shape)?;
    if cd["type"].as_str() != Some("webauthn.get") {
        return Err(Refused::Shape);
    }
    if cd["challenge"].as_str() != Some(passkey_challenge(message).as_str()) {
        return Err(Refused::Challenge);
    }
    if cd["origin"].as_str() != Some(origin) {
        return Err(Refused::Origin);
    }
    if ad[..32] != digest(&SHA256, rp_id.as_bytes()).as_ref()[..] {
        return Err(Refused::RelyingParty);
    }
    if ad[32] & 0x01 == 0 {
        return Err(Refused::NoUserPresence);
    }
    if ad[32] & 0x04 == 0 {
        return Err(Refused::NoUserVerification);
    }
    let counter = u32::from_be_bytes([ad[33], ad[34], ad[35], ad[36]]);
    if (counter != 0 || last_counter != 0) && counter <= last_counter {
        return Err(Refused::Counter);
    }
    let mut signed = ad.to_vec();
    signed.extend_from_slice(digest(&SHA256, a.client_data_json).as_ref());
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public)
        .verify(&signed, a.signature)
        .map_err(|_| Refused::Signature)?;
    Ok(counter)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, Ed25519KeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

    pub fn ed25519() -> (Ed25519KeyPair, Vec<u8>) {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let public = kp.public_key().as_ref().to_vec();
        (kp, public)
    }

    pub struct Passkey {
        pub pair: EcdsaKeyPair,
        pub public: Vec<u8>,
    }

    pub fn passkey() -> Passkey {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let public = pair.public_key().as_ref().to_vec();
        Passkey { pair, public }
    }

    /// A browser's assertion for `message`, with the flags and counter the test chooses.
    pub fn assert_for(
        k: &Passkey,
        rp_id: &str,
        origin: &str,
        message: &[u8],
        flags: u8,
        counter: u32,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut ad = digest(&SHA256, rp_id.as_bytes()).as_ref().to_vec();
        ad.push(flags);
        ad.extend_from_slice(&counter.to_be_bytes());
        let cd = serde_json::json!({"type": "webauthn.get", "challenge": passkey_challenge(message), "origin": origin})
            .to_string()
            .into_bytes();
        let mut signed = ad.clone();
        signed.extend_from_slice(digest(&SHA256, &cd).as_ref());
        let sig = k.pair.sign(&SystemRandom::new(), &signed).unwrap();
        (ad, cd, sig.as_ref().to_vec())
    }

    const RP: &str = "dash.example.com";
    const ORIGIN: &str = "https://dash.example.com";

    #[test]
    fn a_laptop_signature_verifies_only_for_its_key_and_its_message() {
        let (kp, public) = ed25519();
        let (_, other) = ed25519();
        let sig = kp.sign(b"message");
        assert!(verify_ed25519(&public, b"message", sig.as_ref()));
        assert!(!verify_ed25519(&public, b"other", sig.as_ref()));
        assert!(!verify_ed25519(&other, b"message", sig.as_ref()));
        assert!(!verify_ed25519(&public[..31], b"message", sig.as_ref()));
        assert!(!verify_ed25519(&public, b"message", &[0u8; 64]));
    }

    #[test]
    fn a_passkey_assertion_verifies_when_every_part_is_right() {
        let k = passkey();
        let (ad, cd, sig) = assert_for(&k, RP, ORIGIN, b"msg", 0x05, 7);
        let a = Assertion {
            authenticator_data: &ad,
            client_data_json: &cd,
            signature: &sig,
        };
        assert_eq!(verify_passkey(&k.public, RP, ORIGIN, b"msg", &a, 6), Ok(7));
    }

    #[test]
    fn a_passkey_assertion_is_refused_for_each_thing_that_can_be_wrong() {
        let k = passkey();
        let other = passkey();
        let check =
            |flags: u8, counter: u32, last: u32, rp: &str, origin: &str, msg: &[u8], key: &[u8]| {
                let (ad, cd, sig) = assert_for(&k, rp, origin, b"msg", flags, counter);
                let a = Assertion {
                    authenticator_data: &ad,
                    client_data_json: &cd,
                    signature: &sig,
                };
                verify_passkey(key, RP, ORIGIN, msg, &a, last)
            };
        assert_eq!(
            check(0x05, 1, 0, RP, ORIGIN, b"other message", &k.public),
            Err(Refused::Challenge)
        );
        assert_eq!(
            check(0x05, 1, 0, RP, "https://evil.example", b"msg", &k.public),
            Err(Refused::Origin)
        );
        assert_eq!(
            check(0x05, 1, 0, "evil.example", ORIGIN, b"msg", &k.public),
            Err(Refused::RelyingParty)
        );
        assert_eq!(
            check(0x04, 1, 0, RP, ORIGIN, b"msg", &k.public),
            Err(Refused::NoUserPresence)
        );
        assert_eq!(
            check(0x01, 1, 0, RP, ORIGIN, b"msg", &k.public),
            Err(Refused::NoUserVerification)
        );
        assert_eq!(
            check(0x05, 5, 5, RP, ORIGIN, b"msg", &k.public),
            Err(Refused::Counter)
        );
        assert_eq!(
            check(0x05, 3, 5, RP, ORIGIN, b"msg", &k.public),
            Err(Refused::Counter)
        );
        assert_eq!(
            check(0x05, 1, 0, RP, ORIGIN, b"msg", &other.public),
            Err(Refused::Signature)
        );
        assert_eq!(
            check(0x05, 1, 0, RP, ORIGIN, b"msg", &k.public[..64]),
            Err(Refused::Shape)
        );
        // an authenticator that never counts is allowed, as long as it never starts to
        assert_eq!(check(0x05, 0, 0, RP, ORIGIN, b"msg", &k.public), Ok(0));
        assert_eq!(
            check(0x05, 0, 3, RP, ORIGIN, b"msg", &k.public),
            Err(Refused::Counter)
        );
    }

    #[test]
    fn a_damaged_assertion_is_a_shape_error() {
        let k = passkey();
        let (ad, _, sig) = assert_for(&k, RP, ORIGIN, b"msg", 0x05, 1);
        let a = Assertion {
            authenticator_data: &ad[..10],
            client_data_json: b"{}",
            signature: &sig,
        };
        assert_eq!(
            verify_passkey(&k.public, RP, ORIGIN, b"msg", &a, 0),
            Err(Refused::Shape)
        );
        let a = Assertion {
            authenticator_data: &ad,
            client_data_json: b"not json",
            signature: &sig,
        };
        assert_eq!(
            verify_passkey(&k.public, RP, ORIGIN, b"msg", &a, 0),
            Err(Refused::Shape)
        );
    }
}
