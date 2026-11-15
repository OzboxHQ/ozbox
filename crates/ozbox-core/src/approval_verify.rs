//! Verifying the evidence of a decision (ADR 0041 §3).
//!
//! The book never takes the flags, the counter or the challenge of a decision from the caller. A laptop decision is
//! accepted only through [`verify_laptop`], which checks the signature with the key the service holds, over the exact bytes
//! the format says, and **parses user presence, user verification, the counter and the challenge out of those signed
//! bytes**. The result, [`VerifiedLaptop`], has private fields: only this module can make one, so a rule can only read a
//! flag that a signature covered. A passkey assertion's signature is checked by the supervisor in this release (the service
//! holds no credential key yet); [`verify_passkey_bytes`] still derives the challenge, the flags and the counter from the
//! signed bytes instead of trusting separate fields.
//!
//! Formats (one per key type, never a guess):
//! - `ed25519`: an Ed25519 signature over the bytes of [`crate::approval_subject::decide_message`]. No presence.
//! - `sk-ssh-ed25519` and `ecdsa-sk`: a signature over `SHA-256(application) || flags || counter (4 bytes, big-endian) ||
//!   SHA-256(message)`, the message being the same text and the application `ssh:`. The evidence's `authenticator_data`
//!   is `flags || counter` (5 bytes), which the signature covers. The ECDSA signature is ASN.1 DER.
//! - `webauthn-p256`: an ECDSA P-256 (ASN.1 DER) signature over `authenticatorData || SHA-256(clientDataJSON)`, the
//!   evidence's `signed_message` being the clientDataJSON; its `challenge` must be this request's challenge.
//!
//! Anything that is not one of those, or that cannot be verified, is refused.

use ring::digest::{digest, SHA256};
use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1, ED25519};

use crate::approval::{KeyType, KeyView, LaptopEvidence, PasskeyEvidence, SignatureFormat};
use crate::approval_subject::{decide_challenge, decide_message, from_hex, Ids};

/// The application string of an `sk` key's signature (OpenSSH's default). A key made with another one (`ssh-keygen -O
/// application=ssh:work`) hashes that instead, so the key's record keeps it ([`KeyView::application`]).
pub const SSH_SK_APPLICATION: &str = "ssh:";

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;

/// The relying party a WebAuthn assertion must be for: its id (the rpIdHash in the authenticator data is `SHA-256` of it) and
/// the exact origin its clientDataJSON names (ADR 0041 §3). For a dashboard passkey it is what the supervisor
/// verified the assertion against (the service holds no credential key until phase 5); for a laptop `webauthn-p256` key it
/// is the one recorded with the key at enrolment.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExpectedRp {
    pub rp_id: String,
    pub origin: String,
}

/// Check a WebAuthn assertion is for the relying party: the rpIdHash, the exact origin, and not a cross-origin frame.
fn check_rp(authenticator_data: &[u8], client_data: &[u8], rp: &ExpectedRp) -> Result<(), String> {
    if rp.rp_id.is_empty() || rp.origin.is_empty() {
        return Err("the relying party this assertion must be for is not known".into());
    }
    if authenticator_data.len() < 32 || authenticator_data[..32] != sha(rp.rp_id.as_bytes())[..] {
        return Err("that assertion is for another relying party".into());
    }
    let v: serde_json::Value = serde_json::from_slice(client_data)
        .map_err(|_| "the assertion's client data is not valid".to_string())?;
    if v["origin"].as_str() != Some(rp.origin.as_str()) {
        return Err("that assertion is from another origin".into());
    }
    if v["crossOrigin"].as_bool() == Some(true) {
        return Err("that assertion was made in a cross-origin frame".into());
    }
    Ok(())
}

/// What the signature is expected to be about, built by the service from its own record of the request.
#[derive(Debug, Clone)]
pub struct Expected {
    challenge: [u8; 32],
    message: String,
}

impl Expected {
    pub fn new(ids: &Ids, request_id: &str, digest: &[u8; 32], outcome: &str) -> Self {
        Expected {
            challenge: decide_challenge(ids, request_id, digest, outcome),
            message: decide_message(ids, request_id, digest, outcome),
        }
    }

    pub fn challenge(&self) -> &[u8; 32] {
        &self.challenge
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

/// What a laptop signature proved, parsed from the bytes it covered. Only [`verify_laptop`] makes one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedLaptop {
    up: bool,
    uv: bool,
    counter: Option<u32>,
}

impl VerifiedLaptop {
    pub fn up(&self) -> bool {
        self.up
    }
    pub fn uv(&self) -> bool {
        self.uv
    }
    pub fn counter(&self) -> Option<u32> {
        self.counter
    }
}

/// What a passkey assertion's bytes say (the signature is the supervisor's to check in this release).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedPasskey {
    up: bool,
    uv: bool,
    counter: u32,
}

impl VerifiedPasskey {
    pub fn up(&self) -> bool {
        self.up
    }
    pub fn uv(&self) -> bool {
        self.uv
    }
    pub fn counter(&self) -> u32 {
        self.counter
    }
}

fn sha(b: &[u8]) -> Vec<u8> {
    digest(&SHA256, b).as_ref().to_vec()
}

/// RFC 4648 base64url without padding (what a clientDataJSON's challenge is). `None` for any other character.
pub fn base64url_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

/// The challenge a clientDataJSON carries, and whether it is a `webauthn.get` (an assertion, never a creation).
fn client_challenge(client_data: &[u8]) -> Result<Vec<u8>, String> {
    let v: serde_json::Value = serde_json::from_slice(client_data)
        .map_err(|_| "the assertion's client data is not valid".to_string())?;
    if v["type"].as_str() != Some("webauthn.get") {
        return Err("the assertion's client data is not for a sign-in".into());
    }
    let c = v["challenge"]
        .as_str()
        .ok_or("the assertion names no challenge")?;
    base64url_decode(c).ok_or_else(|| "the assertion's challenge is not valid".to_string())
}

/// The flags and the counter of a WebAuthn authenticator data (at least 37 bytes: rpIdHash, flags, counter).
fn parse_auth_data(ad: &[u8]) -> Result<(u8, u32), String> {
    if ad.len() < 37 {
        return Err("the authenticator data is too short".into());
    }
    Ok((ad[32], u32::from_be_bytes([ad[33], ad[34], ad[35], ad[36]])))
}

/// Verify a security key's signature over `message` as ssh-agent produces it for a raw message: the payload is
/// `SHA-256(application) || flags || counter (4 bytes, big-endian) || SHA-256(message)`. `sig` is Ed25519's 64 bytes, or an
/// ASN.1 DER ECDSA signature (see [`parse_agent_sk_signature`] for how an agent's `mpint r, mpint s` becomes one). This is the
/// layout the vectors made by OpenSSH's own `ssh-agent` and `sk-dummy` provider are checked against (`testdata/`).
pub fn verify_sk_payload(
    key_type: KeyType,
    public: &[u8],
    application: &str,
    flags: u8,
    counter: u32,
    message: &[u8],
    sig: &[u8],
) -> Result<(), String> {
    let mut payload = sha(application.as_bytes());
    payload.push(flags);
    payload.extend_from_slice(&counter.to_be_bytes());
    payload.extend_from_slice(&sha(message));
    let alg: &dyn ring::signature::VerificationAlgorithm = match key_type {
        KeyType::SkEd25519 => &ED25519,
        KeyType::EcdsaSk => &ECDSA_P256_SHA256_ASN1,
        _ => return Err("that is not a security key".into()),
    };
    UnparsedPublicKey::new(alg, public)
        .verify(&payload, sig)
        .map_err(|_| "that signature is not valid for this request".to_string())
}

/// Verify a WebAuthn assertion's signature (`authenticatorData || SHA-256(clientDataJSON)`, ASN.1 DER ECDSA P-256) with the
/// public point, and that it is for `rp` and carries `challenge`. Returns the flags and the counter it signed.
pub fn verify_webauthn_assertion(
    public: &[u8],
    rp: &ExpectedRp,
    challenge: &[u8; 32],
    authenticator_data: &[u8],
    client_data: &[u8],
    sig: &[u8],
) -> Result<(u8, u32), String> {
    let (flags, counter) = parse_auth_data(authenticator_data)?;
    if client_challenge(client_data)? != challenge {
        return Err("that assertion is for another request, another outcome or another box".into());
    }
    check_rp(authenticator_data, client_data, rp)?;
    let mut payload = authenticator_data.to_vec();
    payload.extend_from_slice(&sha(client_data));
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public)
        .verify(&payload, sig)
        .map_err(|_| "that signature is not valid for this request".to_string())?;
    Ok((flags, counter))
}

/// What ssh-agent answers to a sign request for an `sk` key: `string(algorithm) || string(signature) || byte flags || uint32
/// counter`. For `ecdsa-sk` the signature string is `mpint r || mpint s`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentSkSignature {
    /// Ed25519's 64 bytes, or the ASN.1 DER the verifier takes.
    pub sig: Vec<u8>,
    pub flags: u8,
    pub counter: u32,
}

fn ssh_string(b: &[u8]) -> Option<(&[u8], &[u8])> {
    let n = u32::from_be_bytes(b.get(..4)?.try_into().ok()?) as usize;
    let end = 4usize.checked_add(n)?;
    Some((b.get(4..end)?, b.get(end..)?))
}

/// An SSH `mpint` as the unsigned big-endian integer it holds (no leading zeros), for DER.
fn mpint_unsigned(b: &[u8]) -> Option<&[u8]> {
    let b = &b[b.iter().position(|x| *x != 0)?..];
    (b.len() <= 33).then_some(b)
}

fn der_int(b: &[u8], out: &mut Vec<u8>) {
    out.push(0x02);
    let pad = b[0] & 0x80 != 0;
    out.push((b.len() + usize::from(pad)) as u8);
    if pad {
        out.push(0);
    }
    out.extend_from_slice(b);
}

/// Parse an agent's signature blob for an `sk` key, and say which algorithm name it carries.
pub fn parse_agent_sk_signature(
    key_type: KeyType,
    blob: &[u8],
) -> Result<AgentSkSignature, String> {
    let bad = || "the agent's signature is not in the form an sk key makes".to_string();
    let want_alg: &[u8] = match key_type {
        KeyType::SkEd25519 => b"sk-ssh-ed25519@openssh.com",
        KeyType::EcdsaSk => b"sk-ecdsa-sha2-nistp256@openssh.com",
        _ => return Err(bad()),
    };
    let (alg, rest) = ssh_string(blob).ok_or_else(bad)?;
    if alg != want_alg {
        return Err(bad());
    }
    let (sig, rest) = ssh_string(rest).ok_or_else(bad)?;
    if rest.len() != 5 {
        return Err(bad());
    }
    let (flags, counter) = (
        rest[0],
        u32::from_be_bytes([rest[1], rest[2], rest[3], rest[4]]),
    );
    let sig = if key_type == KeyType::SkEd25519 {
        if sig.len() != 64 {
            return Err(bad());
        }
        sig.to_vec()
    } else {
        let (r, rest) = ssh_string(sig).ok_or_else(bad)?;
        let (s, rest) = ssh_string(rest).ok_or_else(bad)?;
        if !rest.is_empty() {
            return Err(bad());
        }
        let (r, s) = (
            mpint_unsigned(r).ok_or_else(bad)?,
            mpint_unsigned(s).ok_or_else(bad)?,
        );
        let mut body = Vec::new();
        der_int(r, &mut body);
        der_int(s, &mut body);
        let mut der = vec![0x30, body.len() as u8];
        der.extend_from_slice(&body);
        der
    };
    Ok(AgentSkSignature {
        sig,
        flags,
        counter,
    })
}

/// Verify a laptop key's decision. The key is the service's own record of it (its type and public half); the evidence is
/// what the laptop sent. Refuses a signature that is over another request's message, another outcome or another box, a
/// format that does not belong to the key's type, and anything it cannot check.
pub fn verify_laptop(
    key: &KeyView,
    e: &LaptopEvidence,
    want: &Expected,
) -> Result<VerifiedLaptop, String> {
    let public = from_hex(&key.public_half).ok_or("that key's record is damaged")?;
    let sig = from_hex(&e.signature)
        .filter(|s| !s.is_empty() && s.len() <= 256)
        .ok_or("the signature is not valid")?;
    let signed_message = from_hex(&e.signed_message).ok_or("the signed message is not valid")?;
    let wrong = || "that signature is not valid for this request".to_string();
    match (key.key_type, e.signature_format) {
        (KeyType::Ed25519, SignatureFormat::Ed25519Message) => {
            if signed_message != want.message.as_bytes() {
                return Err(
                    "that signature is over another request, another outcome or another box".into(),
                );
            }
            UnparsedPublicKey::new(&ED25519, &public)
                .verify(&signed_message, &sig)
                .map_err(|_| wrong())?;
            Ok(VerifiedLaptop {
                up: false,
                uv: false,
                counter: None,
            })
        }
        (KeyType::SkEd25519 | KeyType::EcdsaSk, SignatureFormat::SshSk) => {
            if signed_message != want.message.as_bytes() {
                return Err(
                    "that signature is over another request, another outcome or another box".into(),
                );
            }
            let ad = from_hex(e.authenticator_data.as_deref().unwrap_or(""))
                .filter(|a| a.len() == 5)
                .ok_or("a security key's decision carries its flags and counter")?;
            let counter = u32::from_be_bytes([ad[1], ad[2], ad[3], ad[4]]);
            verify_sk_payload(
                key.key_type,
                &public,
                key.application.as_deref().unwrap_or(SSH_SK_APPLICATION),
                ad[0],
                counter,
                &signed_message,
                &sig,
            )?;
            Ok(VerifiedLaptop {
                up: ad[0] & FLAG_UP != 0,
                uv: ad[0] & FLAG_UV != 0,
                counter: Some(counter),
            })
        }
        (KeyType::WebauthnP256, SignatureFormat::WebauthnAssertion) => {
            let ad = from_hex(e.authenticator_data.as_deref().unwrap_or(""))
                .ok_or("the authenticator data is not valid")?;
            // the relying party was recorded with the key at enrolment: no record, no decision
            let rp = key
                .rp
                .as_ref()
                .ok_or("that key has no relying party on record")?;
            let (flags, counter) = verify_webauthn_assertion(
                &public,
                rp,
                &want.challenge,
                &ad,
                &signed_message,
                &sig,
            )?;
            Ok(VerifiedLaptop {
                up: flags & FLAG_UP != 0,
                uv: flags & FLAG_UV != 0,
                counter: Some(counter),
            })
        }
        _ => Err("that signature's format does not belong to that kind of key".into()),
    }
}

/// What a passkey assertion's own bytes say: the challenge from its clientDataJSON (which must be `want`), user presence,
/// user verification and the counter from its authenticator data. There is no separate `challenge` or `counter` input.
pub fn verify_passkey_bytes(
    p: &PasskeyEvidence,
    want: &[u8; 32],
    rp: &ExpectedRp,
) -> Result<VerifiedPasskey, String> {
    let ad = from_hex(&p.authenticator_data).ok_or("the assertion is incomplete")?;
    let client = from_hex(&p.client_data).ok_or("the assertion is incomplete")?;
    let (flags, counter) = parse_auth_data(&ad)?;
    if client_challenge(&client)? != want {
        return Err("that assertion is for another request, another change or another box".into());
    }
    check_rp(&ad, &client, rp)?;
    if flags & FLAG_UP == 0 {
        return Err("that assertion was made without a touch (user presence)".into());
    }
    Ok(VerifiedPasskey {
        up: true,
        uv: flags & FLAG_UV != 0,
        counter,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) mod tests;
