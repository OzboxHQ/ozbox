//! RFC 6238 time-based one-time passwords (HMAC-SHA1, 30 s, 6 digits).

use ring::hmac;

use super::b64::{decode_base32, encode_base32};

pub const STEP_S: u64 = 30;

/// The store name of a person's authenticator secret. One function, read by the dashboard's sign-in and by the secrets
/// service when it checks a code that approves a request (ADR 0041), so the two cannot drift apart.
pub fn secret_name(user: &str) -> String {
    format!("totp-{user}")
}

pub fn new_secret() -> Result<String, String> {
    let mut b = [0u8; 20];
    getrandom::getrandom(&mut b).map_err(|_| "no randomness".to_string())?;
    Ok(encode_base32(&b))
}

/// The code for a counter value (RFC 4226 dynamic truncation).
pub fn hotp(secret: &[u8], counter: u64, digits: u32) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let tag = hmac::sign(&key, &counter.to_be_bytes());
    let h = tag.as_ref();
    let off = (h[h.len() - 1] & 0x0f) as usize;
    let bin = (u32::from(h[off] & 0x7f) << 24)
        | (u32::from(h[off + 1]) << 16)
        | (u32::from(h[off + 2]) << 8)
        | u32::from(h[off + 3]);
    format!(
        "{:0width$}",
        bin % 10u32.pow(digits),
        width = digits as usize
    )
}

fn ct_eq(a: &str, b: &str) -> bool {
    super::b64::ct_eq_bytes(a.as_bytes(), b.as_bytes())
}

/// Check a six-digit code at `now_s`, allowing one step of clock drift either way. Returns the accepted step, so the
/// caller can refuse the same code twice.
pub fn verify(
    secret_b32: &str,
    code: &str,
    now_s: u64,
    last_used_step: Option<u64>,
) -> Option<u64> {
    let secret = decode_base32(secret_b32)?;
    let code = code.trim().replace(' ', "");
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let now_step = now_s / STEP_S;
    let mut hit = None;
    // Every candidate is compared, so timing does not reveal which one matched.
    for step in [now_step.saturating_sub(1), now_step, now_step + 1] {
        let ok = ct_eq(&hotp(&secret, step, 6), &code);
        let fresh = match last_used_step {
            Some(l) => step > l,
            None => true,
        };
        if ok && fresh {
            hit = Some(step);
        }
    }
    hit
}

/// `otpauth://` URI for an authenticator app. `issuer` and `account` are percent-encoded.
pub fn otpauth_uri(issuer: &str, account: &str, secret_b32: &str) -> String {
    fn enc(s: &str) -> String {
        s.bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
                    (b as char).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect()
    }
    format!(
        "otpauth://totp/{}:{}?secret={secret_b32}&issuer={}&algorithm=SHA1&digits=6&period=30",
        enc(issuer),
        enc(account),
        enc(issuer)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 appendix B, SHA-1, secret "12345678901234567890", 8 digits.
    #[test]
    fn rfc6238_vectors() {
        let s = b"12345678901234567890";
        for (t, code) in [
            (59u64, "94287082"),
            (1111111109, "07081804"),
            (1111111111, "14050471"),
            (1234567890, "89005924"),
            (2000000000, "69279037"),
            (20000000000, "65353130"),
        ] {
            assert_eq!(hotp(s, t / 30, 8), code, "t={t}");
        }
    }

    #[test]
    fn verify_allows_drift_and_refuses_replay_and_junk() {
        let secret = encode_base32(b"12345678901234567890");
        let code = hotp(b"12345678901234567890", 1000, 6);
        assert_eq!(verify(&secret, &code, 1000 * 30 + 5, None), Some(1000));
        assert_eq!(verify(&secret, &code, 1001 * 30 + 5, None), Some(1000));
        assert_eq!(verify(&secret, &code, 1003 * 30, None), None);
        assert_eq!(verify(&secret, &code, 1000 * 30, Some(1000)), None);
        assert_eq!(verify(&secret, "12345", 1000 * 30, None), None);
        assert_eq!(verify(&secret, "abcdef", 1000 * 30, None), None);
        assert!(otpauth_uri("Oz Box", "a b@x", "AAAA").contains("a%20b%40x"));
    }
}
