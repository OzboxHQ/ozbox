//! WebAuthn relying-party checks (registration and assertion) on `ring`, with no attestation trust: Oz Box asks for
//! `attestation: "none"` and trusts the key the person registers, the way a passkey sign-in does.
//!
//! Required on every ceremony: the exact origin, the relying-party id hash, the challenge, user presence AND user
//! verification. Supported keys: ES256 (-7), EdDSA (-8), RS256 (-257).

use ring::digest::{digest, SHA256};
use ring::signature::{
    UnparsedPublicKey, ECDSA_P256_SHA256_ASN1, ED25519, RSA_PKCS1_2048_8192_SHA256,
};
use serde_json::{json, Value as Json};

use super::b64::{decode_url, encode_url};
use super::cbor::{self, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebAuthnError {
    BadInput,
    WrongType,
    WrongChallenge,
    WrongOrigin,
    WrongRp,
    NotVerified,
    UnsupportedKey,
    BadSignature,
    CounterRegression,
    BadCredential,
}

impl std::fmt::Display for WebAuthnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::BadInput => "the passkey response could not be read",
            Self::WrongType => "the passkey response is for a different step",
            Self::WrongChallenge => "the passkey response does not match this request",
            Self::WrongOrigin => "the passkey response came from a different site",
            Self::WrongRp => "the passkey belongs to a different site",
            Self::NotVerified => "the passkey did not confirm that you are present and verified",
            Self::UnsupportedKey => "this kind of passkey is not supported",
            Self::BadSignature => "the passkey signature is not valid",
            Self::CounterRegression => "this passkey looks cloned and was refused",
            Self::BadCredential => "the passkey is not the one expected",
        })
    }
}

#[derive(Debug, Clone)]
pub struct Rp {
    /// The relying-party id: the host of the public origin.
    pub id: String,
    /// The exact origin (`https://host[:port]`) a browser reports.
    pub origin: String,
    pub name: String,
}

/// A registered passkey as stored. `key` is the verification key in the form `ring` takes for `alg`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Passkey {
    /// Base64url credential id.
    pub id: String,
    pub alg: i64,
    pub key: String,
    pub sign_count: u32,
    pub name: String,
    pub created_ms: u64,
    pub last_used_ms: u64,
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    super::b64::ct_eq_bytes(a, b)
}

struct ClientData {
    raw: Vec<u8>,
}

fn check_client_data(
    rp: &Rp,
    kind: &str,
    challenge: &[u8],
    b64: &str,
) -> Result<ClientData, WebAuthnError> {
    let raw = decode_url(b64).ok_or(WebAuthnError::BadInput)?;
    if raw.len() > 4096 {
        return Err(WebAuthnError::BadInput);
    }
    let v: Json = serde_json::from_slice(&raw).map_err(|_| WebAuthnError::BadInput)?;
    if v["type"].as_str() != Some(kind) {
        return Err(WebAuthnError::WrongType);
    }
    let got = v["challenge"].as_str().ok_or(WebAuthnError::BadInput)?;
    if !ct_eq(got.as_bytes(), encode_url(challenge).as_bytes()) {
        return Err(WebAuthnError::WrongChallenge);
    }
    if v["origin"].as_str() != Some(rp.origin.as_str()) || v["crossOrigin"] == Json::Bool(true) {
        return Err(WebAuthnError::WrongOrigin);
    }
    Ok(ClientData { raw })
}

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_AT: u8 = 0x40;

struct AuthData<'a> {
    flags: u8,
    counter: u32,
    rest: &'a [u8],
}

fn check_auth_data<'a>(rp: &Rp, ad: &'a [u8]) -> Result<AuthData<'a>, WebAuthnError> {
    if ad.len() < 37 {
        return Err(WebAuthnError::BadInput);
    }
    let want = digest(&SHA256, rp.id.as_bytes());
    if !ct_eq(&ad[..32], want.as_ref()) {
        return Err(WebAuthnError::WrongRp);
    }
    let flags = ad[32];
    if flags & FLAG_UP == 0 || flags & FLAG_UV == 0 {
        return Err(WebAuthnError::NotVerified);
    }
    Ok(AuthData {
        flags,
        counter: u32::from_be_bytes([ad[33], ad[34], ad[35], ad[36]]),
        rest: &ad[37..],
    })
}

fn der_len(n: usize, out: &mut Vec<u8>) {
    if n < 128 {
        out.push(n as u8);
    } else if n < 256 {
        out.extend_from_slice(&[0x81, n as u8]);
    } else {
        out.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]);
    }
}

fn der_uint(bytes: &[u8], out: &mut Vec<u8>) {
    let b: &[u8] = match bytes.iter().position(|&x| x != 0) {
        Some(i) => &bytes[i..],
        None => &[0],
    };
    let pad = b[0] & 0x80 != 0;
    out.push(0x02);
    der_len(b.len() + usize::from(pad), out);
    if pad {
        out.push(0);
    }
    out.extend_from_slice(b);
}

/// `RSAPublicKey ::= SEQUENCE { n INTEGER, e INTEGER }`.
pub fn rsa_public_key_der(n: &[u8], e: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    der_uint(n, &mut body);
    der_uint(e, &mut body);
    let mut out = vec![0x30];
    der_len(body.len(), &mut out);
    out.extend(body);
    out
}

/// A COSE key to (alg, key bytes `ring` verifies with).
pub fn cose_to_key(cose: &Value) -> Result<(i64, Vec<u8>), WebAuthnError> {
    let alg = cose
        .get_int(3)
        .and_then(Value::as_int)
        .ok_or(WebAuthnError::UnsupportedKey)?;
    let kty = cose
        .get_int(1)
        .and_then(Value::as_int)
        .ok_or(WebAuthnError::UnsupportedKey)?;
    let bytes = |k: i64| cose.get_int(k).and_then(Value::as_bytes);
    match (alg, kty) {
        (-7, 2) => {
            if cose.get_int(-1).and_then(Value::as_int) != Some(1) {
                return Err(WebAuthnError::UnsupportedKey);
            }
            let (x, y) = (bytes(-2), bytes(-3));
            match (x, y) {
                (Some(x), Some(y)) if x.len() == 32 && y.len() == 32 => {
                    let mut k = vec![0x04];
                    k.extend_from_slice(x);
                    k.extend_from_slice(y);
                    Ok((alg, k))
                }
                _ => Err(WebAuthnError::UnsupportedKey),
            }
        }
        (-8, 1) => match (cose.get_int(-1).and_then(Value::as_int), bytes(-2)) {
            (Some(6), Some(x)) if x.len() == 32 => Ok((alg, x.to_vec())),
            _ => Err(WebAuthnError::UnsupportedKey),
        },
        (-257, 3) => match (bytes(-1), bytes(-2)) {
            (Some(n), Some(e)) if (256..=1024).contains(&n.len()) && !e.is_empty() => {
                Ok((alg, rsa_public_key_der(n, e)))
            }
            _ => Err(WebAuthnError::UnsupportedKey),
        },
        _ => Err(WebAuthnError::UnsupportedKey),
    }
}

pub struct NewPasskey {
    pub id: String,
    pub alg: i64,
    pub key: Vec<u8>,
    pub sign_count: u32,
}

/// Check a registration response and return the new credential.
pub fn verify_registration(
    rp: &Rp,
    challenge: &[u8],
    client_data_b64: &str,
    attestation_b64: &str,
    credential_id_b64: &str,
) -> Result<NewPasskey, WebAuthnError> {
    check_client_data(rp, "webauthn.create", challenge, client_data_b64)?;
    let att = decode_url(attestation_b64).ok_or(WebAuthnError::BadInput)?;
    if att.len() > 16 * 1024 {
        return Err(WebAuthnError::BadInput);
    }
    let (obj, used) = cbor::decode(&att).ok_or(WebAuthnError::BadInput)?;
    if used != att.len() {
        return Err(WebAuthnError::BadInput);
    }
    let ad = obj
        .get_text("authData")
        .and_then(Value::as_bytes)
        .ok_or(WebAuthnError::BadInput)?;
    let a = check_auth_data(rp, ad)?;
    if a.flags & FLAG_AT == 0 || a.rest.len() < 18 {
        return Err(WebAuthnError::BadInput);
    }
    let id_len = usize::from(u16::from_be_bytes([a.rest[16], a.rest[17]]));
    if id_len == 0 || id_len > 1023 || a.rest.len() < 18 + id_len {
        return Err(WebAuthnError::BadInput);
    }
    let cred_id = &a.rest[18..18 + id_len];
    let want = decode_url(credential_id_b64).ok_or(WebAuthnError::BadInput)?;
    if !ct_eq(cred_id, &want) {
        return Err(WebAuthnError::BadCredential);
    }
    let (cose, _) = cbor::decode(&a.rest[18 + id_len..]).ok_or(WebAuthnError::BadInput)?;
    let (alg, key) = cose_to_key(&cose)?;
    Ok(NewPasskey {
        id: encode_url(cred_id),
        alg,
        key,
        sign_count: a.counter,
    })
}

/// Check an assertion against a stored passkey. Returns the new signature counter.
pub fn verify_assertion(
    rp: &Rp,
    challenge: &[u8],
    pk: &Passkey,
    client_data_b64: &str,
    auth_data_b64: &str,
    signature_b64: &str,
) -> Result<u32, WebAuthnError> {
    verify_assertion_with(
        rp,
        challenge,
        pk,
        client_data_b64,
        auth_data_b64,
        signature_b64,
        true,
    )
}

/// Check an assertion's signature, relying party, origin, challenge, presence and verification, **without** the counter
/// check: for evidence that was stored when it was made and is checked again later (a delegation), by which time the
/// passkey's counter has moved on. A new assertion is always checked by [`verify_assertion`].
pub fn verify_stored_assertion(
    rp: &Rp,
    challenge: &[u8],
    pk: &Passkey,
    client_data_b64: &str,
    auth_data_b64: &str,
    signature_b64: &str,
) -> Result<u32, WebAuthnError> {
    verify_assertion_with(
        rp,
        challenge,
        pk,
        client_data_b64,
        auth_data_b64,
        signature_b64,
        false,
    )
}

fn verify_assertion_with(
    rp: &Rp,
    challenge: &[u8],
    pk: &Passkey,
    client_data_b64: &str,
    auth_data_b64: &str,
    signature_b64: &str,
    check_counter: bool,
) -> Result<u32, WebAuthnError> {
    let cd = check_client_data(rp, "webauthn.get", challenge, client_data_b64)?;
    let ad = decode_url(auth_data_b64).ok_or(WebAuthnError::BadInput)?;
    let sig = decode_url(signature_b64).ok_or(WebAuthnError::BadInput)?;
    let a = check_auth_data(rp, &ad)?;
    let mut signed = ad.clone();
    signed.extend_from_slice(digest(&SHA256, &cd.raw).as_ref());
    let key = decode_url(&pk.key).ok_or(WebAuthnError::UnsupportedKey)?;
    let alg: &dyn ring::signature::VerificationAlgorithm = match pk.alg {
        -7 => &ECDSA_P256_SHA256_ASN1,
        -8 => &ED25519,
        -257 => &RSA_PKCS1_2048_8192_SHA256,
        _ => return Err(WebAuthnError::UnsupportedKey),
    };
    UnparsedPublicKey::new(alg, &key)
        .verify(&signed, &sig)
        .map_err(|_| WebAuthnError::BadSignature)?;
    // A counter that does not move forward means a cloned authenticator. Many passkeys always report 0: allow that.
    if check_counter && (pk.sign_count != 0 || a.counter != 0) && a.counter <= pk.sign_count {
        return Err(WebAuthnError::CounterRegression);
    }
    Ok(a.counter)
}

/// `PublicKeyCredentialCreationOptions` as the browser takes them (binary fields base64url).
pub fn registration_options(
    rp: &Rp,
    user_handle: &[u8],
    user_name: &str,
    challenge: &[u8],
    exclude: &[String],
) -> Json {
    json!({
        "rp": { "id": rp.id, "name": rp.name },
        "user": { "id": encode_url(user_handle), "name": user_name, "displayName": user_name },
        "challenge": encode_url(challenge),
        "pubKeyCredParams": [{"type":"public-key","alg":-7},{"type":"public-key","alg":-8},{"type":"public-key","alg":-257}],
        "timeout": 120000,
        "attestation": "none",
        "excludeCredentials": exclude.iter().map(|id| json!({"type":"public-key","id":id})).collect::<Vec<_>>(),
        "authenticatorSelection": { "residentKey": "required", "requireResidentKey": true, "userVerification": "required" },
    })
}

/// `PublicKeyCredentialRequestOptions`. An empty `allow` is a discoverable-credential sign-in.
pub fn assertion_options(rp: &Rp, challenge: &[u8], allow: &[String]) -> Json {
    json!({
        "rpId": rp.id,
        "challenge": encode_url(challenge),
        "timeout": 120000,
        "userVerification": "required",
        "allowCredentials": allow.iter().map(|id| json!({"type":"public-key","id":id})).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
pub mod testkit {
    //! A software authenticator for tests: makes a P-256 key and produces the bytes a browser would.
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

    pub fn cbor_bytes(b: &[u8], out: &mut Vec<u8>) {
        assert!(b.len() < 256);
        out.extend_from_slice(&[0x58, b.len() as u8]);
        out.extend_from_slice(b);
    }

    pub struct Authenticator {
        pub kp: EcdsaKeyPair,
        pub cred_id: Vec<u8>,
        pub counter: u32,
        pub flags: u8,
    }

    impl Authenticator {
        pub fn new() -> Self {
            let rng = SystemRandom::new();
            let pkcs8 =
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
            let kp =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
                    .unwrap();
            Self {
                kp,
                cred_id: (1..=32).collect(),
                counter: 0,
                flags: FLAG_UP | FLAG_UV,
            }
        }

        fn cose(&self) -> Vec<u8> {
            let pk = self.kp.public_key().as_ref();
            let mut c = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21];
            cbor_bytes(&pk[1..33], &mut c);
            c.push(0x22);
            cbor_bytes(&pk[33..65], &mut c);
            c
        }

        pub fn client_data(kind: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
            serde_json::to_vec(&json!({"type": kind, "challenge": encode_url(challenge), "origin": origin, "crossOrigin": false})).unwrap()
        }

        fn auth_data(&self, rp_id: &str, with_key: bool) -> Vec<u8> {
            let mut ad = digest(&SHA256, rp_id.as_bytes()).as_ref().to_vec();
            ad.push(if with_key {
                self.flags | FLAG_AT
            } else {
                self.flags
            });
            ad.extend_from_slice(&self.counter.to_be_bytes());
            if with_key {
                ad.extend_from_slice(&[0u8; 16]);
                ad.extend_from_slice(&(self.cred_id.len() as u16).to_be_bytes());
                ad.extend_from_slice(&self.cred_id);
                ad.extend(self.cose());
            }
            ad
        }

        /// (clientDataJSON, attestationObject), both base64url.
        pub fn register(&self, rp: &Rp, challenge: &[u8]) -> (String, String) {
            let cd = Self::client_data("webauthn.create", challenge, &rp.origin);
            let ad = self.auth_data(&rp.id, true);
            let mut obj = vec![0xa3, 0x63];
            obj.extend_from_slice(b"fmt");
            obj.extend_from_slice(&[0x64]);
            obj.extend_from_slice(b"none");
            obj.push(0x67);
            obj.extend_from_slice(b"attStmt");
            obj.push(0xa0);
            obj.push(0x68);
            obj.extend_from_slice(b"authData");
            obj.extend_from_slice(&[0x59, (ad.len() >> 8) as u8, ad.len() as u8]);
            obj.extend_from_slice(&ad);
            (encode_url(&cd), encode_url(&obj))
        }

        /// (clientDataJSON, authenticatorData, signature), base64url.
        pub fn assert(&mut self, rp: &Rp, challenge: &[u8]) -> (String, String, String) {
            self.counter += 1;
            let cd = Self::client_data("webauthn.get", challenge, &rp.origin);
            let ad = self.auth_data(&rp.id, false);
            let mut signed = ad.clone();
            signed.extend_from_slice(digest(&SHA256, &cd).as_ref());
            let sig = self.kp.sign(&SystemRandom::new(), &signed).unwrap();
            (encode_url(&cd), encode_url(&ad), encode_url(sig.as_ref()))
        }

        pub fn passkey(&self, np: &NewPasskey) -> Passkey {
            Passkey {
                id: np.id.clone(),
                alg: np.alg,
                key: encode_url(&np.key),
                sign_count: np.sign_count,
                name: "test".into(),
                created_ms: 0,
                last_used_ms: 0,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::Authenticator;
    use super::*;

    fn rp() -> Rp {
        Rp {
            id: "box.example.com".into(),
            origin: "https://box.example.com".into(),
            name: "Oz Box".into(),
        }
    }

    fn registered(a: &Authenticator, challenge: &[u8]) -> Passkey {
        let (cd, att) = a.register(&rp(), challenge);
        let np = verify_registration(&rp(), challenge, &cd, &att, &encode_url(&a.cred_id)).unwrap();
        a.passkey(&np)
    }

    #[test]
    fn a_registration_and_assertions_with_a_software_authenticator() {
        let mut a = Authenticator::new();
        let pk = registered(&a, b"reg-challenge-1234567890");
        assert_eq!(pk.alg, -7);
        let (cd, ad, sig) = a.assert(&rp(), b"login-challenge");
        let n = verify_assertion(&rp(), b"login-challenge", &pk, &cd, &ad, &sig).unwrap();
        assert_eq!(n, 1);
        // a replay of the same assertion against the advanced counter is refused
        let mut pk2 = pk.clone();
        pk2.sign_count = 1;
        assert_eq!(
            verify_assertion(&rp(), b"login-challenge", &pk2, &cd, &ad, &sig),
            Err(WebAuthnError::CounterRegression)
        );
    }

    #[test]
    fn every_binding_is_checked() {
        let mut a = Authenticator::new();
        let ch = b"challenge-abc";
        let pk = registered(&a, b"reg");
        let (cd, ad, sig) = a.assert(&rp(), ch);
        let go = |rp: &Rp, ch: &[u8], pk: &Passkey, cd: &str, ad: &str, sig: &str| {
            verify_assertion(rp, ch, pk, cd, ad, sig)
        };
        // wrong challenge
        assert_eq!(
            go(&rp(), b"other", &pk, &cd, &ad, &sig),
            Err(WebAuthnError::WrongChallenge)
        );
        // wrong origin
        let evil = Rp {
            origin: "https://evil.example".into(),
            ..rp()
        };
        assert_eq!(
            go(&evil, ch, &pk, &cd, &ad, &sig),
            Err(WebAuthnError::WrongOrigin)
        );
        // wrong relying party id
        let other = Rp {
            id: "evil.example".into(),
            ..rp()
        };
        let cd2 = encode_url(&Authenticator::client_data(
            "webauthn.get",
            ch,
            &other.origin,
        ));
        assert_eq!(
            go(&other, ch, &pk, &cd2, &ad, &sig),
            Err(WebAuthnError::WrongRp)
        );
        // a different key's signature
        let mut b = Authenticator::new();
        let (cdb, adb, sigb) = b.assert(&rp(), ch);
        assert_eq!(
            go(&rp(), ch, &pk, &cdb, &adb, &sigb),
            Err(WebAuthnError::BadSignature)
        );
        // a tampered signature byte
        let mut bad = decode_url(&sig).unwrap();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert_eq!(
            go(&rp(), ch, &pk, &cd, &ad, &encode_url(&bad)),
            Err(WebAuthnError::BadSignature)
        );
        // a registration type used as an assertion
        let creation = encode_url(&Authenticator::client_data(
            "webauthn.create",
            ch,
            &rp().origin,
        ));
        assert_eq!(
            go(&rp(), ch, &pk, &creation, &ad, &sig),
            Err(WebAuthnError::WrongType)
        );
    }

    #[test]
    fn user_verification_and_presence_are_required() {
        let mut a = Authenticator::new();
        a.flags = FLAG_UP; // no user verification
        let (cd, att) = a.register(&rp(), b"c");
        assert_eq!(
            verify_registration(&rp(), b"c", &cd, &att, &encode_url(&a.cred_id)).err(),
            Some(WebAuthnError::NotVerified)
        );
        a.flags = FLAG_UV; // no presence
        let (cd, att) = a.register(&rp(), b"c");
        assert_eq!(
            verify_registration(&rp(), b"c", &cd, &att, &encode_url(&a.cred_id)).err(),
            Some(WebAuthnError::NotVerified)
        );
        // the credential id must be the one in the attested data
        let ok = Authenticator::new();
        let (cd, att) = ok.register(&rp(), b"c");
        assert_eq!(
            verify_registration(&rp(), b"c", &cd, &att, &encode_url(b"other")).err(),
            Some(WebAuthnError::BadCredential)
        );
    }

    #[test]
    fn the_rsa_key_der_is_well_formed() {
        let der = rsa_public_key_der(&[0x80, 1], &[1, 0, 1]);
        assert_eq!(
            der,
            vec![0x30, 0x0a, 0x02, 0x03, 0x00, 0x80, 0x01, 0x02, 0x03, 1, 0, 1]
        );
    }

    #[test]
    fn options_ask_for_resident_keys_and_user_verification() {
        let o = registration_options(&rp(), b"u1", "owner", b"ch", &["id1".into()]);
        assert_eq!(o["authenticatorSelection"]["residentKey"], "required");
        assert_eq!(o["authenticatorSelection"]["userVerification"], "required");
        assert_eq!(o["attestation"], "none");
        assert_eq!(o["excludeCredentials"][0]["id"], "id1");
        let g = assertion_options(&rp(), b"ch", &[]);
        assert_eq!(g["userVerification"], "required");
        assert_eq!(g["allowCredentials"].as_array().map(Vec::len), Some(0));
    }
}
