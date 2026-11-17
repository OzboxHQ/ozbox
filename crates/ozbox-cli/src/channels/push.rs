//! Web push to the installed dashboard: no third-party account, no keys to paste. The fleet makes one VAPID signing
//! key (RFC 8292) the first time it is needed and keeps it in the secret store; each browser or installed app that
//! turns notifications on hands over a push subscription, which is kept in the secret store too (its address is a
//! capability: anyone holding it can send to that device).
//!
//! A payload is encrypted for the one device with the `aes128gcm` content coding of RFC 8291 (message encryption for web
//! push, built on RFC 8188). The browser's push service sees only ciphertext.
//!
//! * Message encryption: <https://www.rfc-editor.org/rfc/rfc8291>
//! * VAPID: <https://www.rfc-editor.org/rfc/rfc8292>
//! * Encrypted content-encoding: <https://www.rfc-editor.org/rfc/rfc8188>
//!
//! The encryption is split so that the key agreement (which `ring` only allows with a fresh random key) is separate
//! from everything after it, which is deterministic and is tested against the example in RFC 8291 section 5.

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};
use ring::agreement::{agree_ephemeral, EphemeralPrivateKey, UnparsedPublicKey, ECDH_P256};
use ring::hkdf::{Salt, HKDF_SHA256};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

use super::{clip, Ctx, SendResult};
use crate::netguard::{Guard, HttpRequest};
use crate::notice::render::{Push, Renderer};
use crate::notice::Notice;
use crate::notify::{Alert, Severity};
use crate::serve::auth::b64;

/// What a send reports when the push service says the device is gone (HTTP 404 or 410): the caller forgets it.
pub const GONE: &str = "that device is no longer subscribed";

const RECORD_SIZE: u32 = 4096;
const MAX_PAYLOAD: usize = 3000;
/// How long the push service may hold a message for a device that is off: a day.
const TTL_SECONDS: u32 = 86_400;

struct Len(usize);
impl ring::hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

fn expand(prk: &ring::hkdf::Prk, info: &[u8], out: &mut [u8]) -> Result<(), String> {
    prk.expand(&[info], Len(out.len()))
        .and_then(|okm| okm.fill(out))
        .map_err(|_| "the message could not be encrypted".to_string())
}

/// Everything after the key agreement. Deterministic: the same inputs give the same message.
pub fn encrypt_with(
    ecdh_secret: &[u8],
    as_public: &[u8],
    ua_public: &[u8],
    auth_secret: &[u8],
    salt: &[u8; 16],
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    // PRK_key = HKDF-Extract(salt = auth_secret, IKM = ecdh_secret); IKM = HKDF-Expand(PRK_key, key_info, 32)
    let prk_key = Salt::new(HKDF_SHA256, auth_secret).extract(ecdh_secret);
    let mut key_info = b"WebPush: info\0".to_vec();
    key_info.extend_from_slice(ua_public);
    key_info.extend_from_slice(as_public);
    let mut ikm = [0u8; 32];
    expand(&prk_key, &key_info, &mut ikm)?;
    let prk = Salt::new(HKDF_SHA256, salt).extract(&ikm);
    let mut cek = [0u8; 16];
    expand(&prk, b"Content-Encoding: aes128gcm\0", &mut cek)?;
    let mut nonce = [0u8; 12];
    expand(&prk, b"Content-Encoding: nonce\0", &mut nonce)?;
    // One record: the data, then the delimiter 0x02 that marks the last record.
    let mut record = plaintext.to_vec();
    record.push(2);
    let key = LessSafeKey::new(
        UnboundKey::new(&AES_128_GCM, &cek)
            .map_err(|_| "the message could not be encrypted".to_string())?,
    );
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::empty(),
        &mut record,
    )
    .map_err(|_| "the message could not be encrypted".to_string())?;
    // Header: salt, record size, key id length, key id (the sender's public key).
    let mut out = Vec::with_capacity(21 + as_public.len() + record.len());
    out.extend_from_slice(salt);
    out.extend_from_slice(&RECORD_SIZE.to_be_bytes());
    out.push(as_public.len() as u8);
    out.extend_from_slice(as_public);
    out.extend_from_slice(&record);
    Ok(out)
}

/// Encrypt a payload for one subscription (its P-256 public key and 16-byte auth secret, both base64url).
pub fn encrypt(p256dh_b64: &str, auth_b64: &str, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let ua_public = b64::decode_url(p256dh_b64).ok_or("the device's key is not valid")?;
    let auth = b64::decode_url(auth_b64).ok_or("the device's auth secret is not valid")?;
    if ua_public.len() != 65 || ua_public[0] != 4 || auth.len() != 16 {
        return Err("the device's key is not valid".into());
    }
    let rng = SystemRandom::new();
    let private = EphemeralPrivateKey::generate(&ECDH_P256, &rng)
        .map_err(|_| "the message could not be encrypted".to_string())?;
    let as_public = private
        .compute_public_key()
        .map_err(|_| "the message could not be encrypted".to_string())?
        .as_ref()
        .to_vec();
    let mut salt = [0u8; 16];
    rng.fill(&mut salt)
        .map_err(|_| "the message could not be encrypted".to_string())?;
    let secret = agree_ephemeral(
        private,
        &UnparsedPublicKey::new(&ECDH_P256, &ua_public),
        |s| s.to_vec(),
    )
    .map_err(|_| "the device's key is not valid".to_string())?;
    encrypt_with(&secret, &as_public, &ua_public, &auth, &salt, plaintext)
}

// ---------- VAPID ----------

/// A new signing key: (PKCS#8 as base64url for the secret store, the public key as base64url for the browser).
pub fn generate_vapid() -> Result<(String, String), String> {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
        .map_err(|_| "a signing key could not be made".to_string())?;
    let public = vapid_public(&b64::encode_url(pkcs8.as_ref()))?;
    Ok((b64::encode_url(pkcs8.as_ref()), public))
}

fn key_pair(pkcs8_b64: &str) -> Result<EcdsaKeyPair, String> {
    let der = b64::decode_url(pkcs8_b64).ok_or("the signing key is not valid")?;
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &der, &SystemRandom::new())
        .map_err(|_| "the signing key is not valid".to_string())
}

/// The public key a browser needs to subscribe (`applicationServerKey`), base64url of the uncompressed point.
pub fn vapid_public(pkcs8_b64: &str) -> Result<String, String> {
    Ok(b64::encode_url(key_pair(pkcs8_b64)?.public_key().as_ref()))
}

fn origin_of(endpoint: &str) -> Option<String> {
    let rest = endpoint.strip_prefix("https://")?;
    let host = rest.split(['/', '?', '#']).next()?;
    Some(format!("https://{host}"))
}

/// The `Authorization` header value of RFC 8292: a signed token naming the push service, valid for 12 hours.
pub fn vapid_authorization(
    pkcs8_b64: &str,
    endpoint: &str,
    subject: &str,
    now_secs: u64,
) -> Result<String, String> {
    let kp = key_pair(pkcs8_b64)?;
    let aud = origin_of(endpoint).ok_or("the device's address is not valid")?;
    let header = b64::encode_url(br#"{"typ":"JWT","alg":"ES256"}"#);
    let claims = b64::encode_url(
        serde_json::json!({ "aud": aud, "exp": now_secs + 12 * 3600, "sub": subject })
            .to_string()
            .as_bytes(),
    );
    let signing_input = format!("{header}.{claims}");
    let sig = kp
        .sign(&SystemRandom::new(), signing_input.as_bytes())
        .map_err(|_| "the message could not be signed".to_string())?;
    Ok(format!(
        "vapid t={signing_input}.{}, k={}",
        b64::encode_url(sig.as_ref()),
        b64::encode_url(kp.public_key().as_ref())
    ))
}

// ---------- sending ----------

/// What the notification shows and opens: the notice's push rendering, with the alert's tag and time.
pub fn payload(a: &Alert, n: &Notice) -> Vec<u8> {
    let p = Push::render(n);
    let v = serde_json::json!({
        "title": p.title,
        "body": p.body,
        "url": p.path,
        "tag": clip(&a.key, 100),
        "urgent": a.severity == Severity::Urgent,
        "ts": a.ts_ms,
    });
    let mut s = v.to_string();
    if s.len() > MAX_PAYLOAD {
        s = serde_json::json!({ "title": clip(&p.title, 60), "url": p.path, "tag": clip(&a.key, 100), "ts": a.ts_ms })
            .to_string();
    }
    s.into_bytes()
}

pub fn request(authorization: &str, endpoint: &str, body: Vec<u8>, urgent: bool) -> HttpRequest {
    let mut r = HttpRequest::new("POST", endpoint, Guard::Public)
        .header("Authorization", authorization)
        .header("Content-Encoding", "aes128gcm")
        .header("Content-Type", "application/octet-stream")
        .header("TTL", TTL_SECONDS.to_string())
        .header("Urgency", if urgent { "high" } else { "normal" });
    r.body = Some(body);
    r
}

pub fn interpret(status: u16, _body: &str) -> SendResult {
    match status {
        200..=299 => Ok("sent".into()),
        404 | 410 => Err(GONE.into()),
        400 | 401 | 403 => Err("the push service refused the message".into()),
        413 => Err("the message was too big for the push service".into()),
        s => Err(super::http_detail(s)),
    }
}

/// Send to one stored device. `device` is the id the secrets are named after.
pub fn send(
    ctx: &Ctx,
    device: &str,
    subject: &str,
    a: &Alert,
    n: &Notice,
    now_secs: u64,
) -> SendResult {
    let vapid = ctx.need("vapid-private-key", "push signing key")?;
    let endpoint = ctx.need(&format!("push-endpoint-{device}"), "device address")?;
    let key = ctx.need(&format!("push-key-{device}"), "device key")?;
    let auth = ctx.need(&format!("push-auth-{device}"), "device auth secret")?;
    let body = encrypt(&key, &auth, &payload(a, n))?;
    let authz = vapid_authorization(&vapid, &endpoint, subject, now_secs)?;
    ctx.call(
        request(&authz, &endpoint, body, a.severity == Severity::Urgent),
        interpret,
    )
}

/// The signing key, made on first use.
pub fn ensure_vapid(ctx: &Ctx) -> Result<String, String> {
    if let Some(k) = ctx.secret("vapid-private-key")? {
        return Ok(k);
    }
    let (private, _) = generate_vapid()?;
    ctx.secrets
        .set("vapid-private-key", &private)
        .map_err(|e| e.to_string())?;
    Ok(private)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::channels::testing::rig;
    use crate::notify::test_alert;
    use crate::secrets::SecretStore;

    fn d(s: &str) -> Vec<u8> {
        b64::decode_url(s).unwrap()
    }

    // The example of RFC 8291 section 5 (Appendix A of the draft): a message "When I grow up, I want to be a
    // watermelon" encrypted for a user agent.
    const PLAINTEXT: &str = "V2hlbiBJIGdyb3cgdXAsIEkgd2FudCB0byBiZSBhIHdhdGVybWVsb24";
    const AS_PUBLIC: &str =
        "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8";
    const UA_PUBLIC: &str =
        "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4";
    const AUTH: &str = "BTBZMqHH6r4Tts7J_aSIgg";
    const SALT: &str = "DGv6ra1nlYgDCS1FRnbzlw";
    const ECDH: &str = "kyrL1jIIOHEzg3sM2ZWRHDRB62YACZhhSlknJ672kSs";
    const BODY: &str = "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN";

    #[test]
    fn the_encryption_after_the_key_agreement_matches_the_rfc_8291_example() {
        let salt: [u8; 16] = d(SALT).try_into().unwrap();
        let out = encrypt_with(
            &d(ECDH),
            &d(AS_PUBLIC),
            &d(UA_PUBLIC),
            &d(AUTH),
            &salt,
            &d(PLAINTEXT),
        )
        .unwrap();
        assert_eq!(b64::encode_url(&out), BODY);
    }

    /// Receiver side, written from the RFC, to prove the sender's output is decryptable and that the key agreement
    /// produces the secret both sides compute.
    fn decrypt(
        ua_private: EphemeralPrivateKey,
        ua_public: &[u8],
        auth: &[u8],
        body: &[u8],
    ) -> Vec<u8> {
        let salt = &body[..16];
        assert_eq!(
            u32::from_be_bytes(body[16..20].try_into().unwrap()),
            RECORD_SIZE
        );
        let idlen = usize::from(body[20]);
        let as_public = &body[21..21 + idlen];
        let ct = &body[21 + idlen..];
        let secret = agree_ephemeral(
            ua_private,
            &UnparsedPublicKey::new(&ECDH_P256, as_public),
            |s| s.to_vec(),
        )
        .unwrap();
        let prk_key = Salt::new(HKDF_SHA256, auth).extract(&secret);
        let mut info = b"WebPush: info\0".to_vec();
        info.extend_from_slice(ua_public);
        info.extend_from_slice(as_public);
        let mut ikm = [0u8; 32];
        expand(&prk_key, &info, &mut ikm).unwrap();
        let prk = Salt::new(HKDF_SHA256, salt).extract(&ikm);
        let (mut cek, mut nonce) = ([0u8; 16], [0u8; 12]);
        expand(&prk, b"Content-Encoding: aes128gcm\0", &mut cek).unwrap();
        expand(&prk, b"Content-Encoding: nonce\0", &mut nonce).unwrap();
        let key = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &cek).unwrap());
        let mut buf = ct.to_vec();
        let plain = key
            .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut buf)
            .unwrap();
        let end = plain.iter().rposition(|b| *b == 2).unwrap();
        plain[..end].to_vec()
    }

    #[test]
    fn a_message_round_trips_through_a_real_key_agreement() {
        let rng = SystemRandom::new();
        let ua = EphemeralPrivateKey::generate(&ECDH_P256, &rng).unwrap();
        let ua_public = ua.compute_public_key().unwrap().as_ref().to_vec();
        let mut auth = [0u8; 16];
        rng.fill(&mut auth).unwrap();
        let body = encrypt(
            &b64::encode_url(&ua_public),
            &b64::encode_url(&auth),
            b"{\"title\":\"Disk full\"}",
        )
        .unwrap();
        assert_eq!(
            decrypt(ua, &ua_public, &auth, &body),
            b"{\"title\":\"Disk full\"}"
        );
        // Two messages never share a salt or a sender key.
        let again = encrypt(&b64::encode_url(&ua_public), &b64::encode_url(&auth), b"x").unwrap();
        assert_ne!(body[..16], again[..16]);
    }

    #[test]
    fn a_bad_subscription_key_is_refused() {
        for (k, a) in [("not base64!", AUTH), (UA_PUBLIC, "short"), ("AAAA", AUTH)] {
            assert!(encrypt(k, a, b"x").is_err());
        }
    }

    #[test]
    fn the_vapid_token_is_a_valid_es256_jwt_for_the_push_service_origin() {
        let (private, public) = generate_vapid().unwrap();
        assert_eq!(vapid_public(&private).unwrap(), public);
        assert_eq!(d(&public).len(), 65);
        let h = vapid_authorization(
            &private,
            "https://fcm.googleapis.com/fcm/send/abc",
            "mailto:ops@example.com",
            1_000,
        )
        .unwrap();
        let rest = h.strip_prefix("vapid t=").unwrap();
        let (jwt, k) = rest.split_once(", k=").unwrap();
        assert_eq!(k, public);
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        let claims: serde_json::Value = serde_json::from_slice(&d(parts[1])).unwrap();
        assert_eq!(claims["aud"], "https://fcm.googleapis.com");
        assert_eq!(claims["sub"], "mailto:ops@example.com");
        assert_eq!(claims["exp"], 1_000 + 43_200);
        let sig = d(parts[2]);
        assert_eq!(sig.len(), 64);
        let signed = format!("{}.{}", parts[0], parts[1]);
        let pk = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_FIXED,
            d(&public),
        );
        assert!(pk.verify(signed.as_bytes(), &sig).is_ok());
        assert!(vapid_authorization(
            &private,
            "http://plain.example/x",
            "mailto:a@example.com",
            0
        )
        .is_err());
    }

    #[test]
    fn sending_uses_the_stored_device_the_guard_and_the_right_headers() {
        let g = rig();
        let rng = SystemRandom::new();
        let ua = EphemeralPrivateKey::generate(&ECDH_P256, &rng).unwrap();
        let ua_public = ua.compute_public_key().unwrap();
        let mut auth = [0u8; 16];
        rng.fill(&mut auth).unwrap();
        ensure_vapid(&g.ctx).unwrap();
        g.secrets
            .set(
                "push-endpoint-dev1",
                "https://updates.push.services.mozilla.com/wpush/v2/abc",
            )
            .unwrap();
        g.secrets
            .set("push-key-dev1", &b64::encode_url(ua_public.as_ref()))
            .unwrap();
        g.secrets
            .set("push-auth-dev1", &b64::encode_url(&auth))
            .unwrap();
        g.http.reply(201, "");
        let mut a = test_alert(5);
        a.severity = Severity::Urgent;
        assert_eq!(
            send(
                &g.ctx,
                "dev1",
                "mailto:ops@example.com",
                &a,
                &a.notice_for(None),
                100
            ),
            Ok("sent".into())
        );
        let r = &g.http.requests()[0];
        assert_eq!(r.guard, Guard::Public);
        let h = |n: &str| {
            r.headers
                .iter()
                .find(|(k, _)| k == n)
                .map(|(_, v)| v.clone())
        };
        assert_eq!(h("Content-Encoding").as_deref(), Some("aes128gcm"));
        assert_eq!(h("Urgency").as_deref(), Some("high"));
        assert_eq!(h("TTL").as_deref(), Some("86400"));
        assert!(h("Authorization").unwrap().starts_with("vapid t="));
        let plain = decrypt(ua, ua_public.as_ref(), &auth, r.body.as_ref().unwrap());
        let v: serde_json::Value = serde_json::from_slice(&plain).unwrap();
        assert_eq!(v["title"], "Test alert from Oz Box");
        assert_eq!(v["urgent"], true);
    }

    #[test]
    fn a_gone_device_is_reported_so_it_can_be_forgotten() {
        assert_eq!(interpret(410, ""), Err(GONE.to_string()));
        assert_eq!(interpret(404, ""), Err(GONE.to_string()));
        assert_eq!(interpret(201, ""), Ok("sent".into()));
        assert!(crate::channels::retryable(&interpret(503, "").unwrap_err()));
        assert!(!crate::channels::retryable(
            &interpret(403, "").unwrap_err()
        ));
    }

    #[test]
    fn the_payload_stays_small() {
        let mut a = test_alert(1);
        a.body = "x".repeat(10_000);
        assert!(payload(&a, &a.notice_for(None)).len() < MAX_PAYLOAD);
    }
}
