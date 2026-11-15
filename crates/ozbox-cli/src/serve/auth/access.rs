//! Cloudflare Access: a request header is only a claim until its JWT is checked against the team's published keys,
//! the application's audience and the clock. This module checks it; nothing trusts the bare header.

use ring::signature::{UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA256};
use serde_json::Value;

use super::b64::decode_url;
use super::webauthn::rsa_public_key_der;

#[derive(Debug, Clone)]
pub struct Jwk {
    pub kid: String,
    pub key_der: Vec<u8>,
}

/// Parse a `certs` document (`{"keys":[{kid,kty,n,e,...}]}`); keys that are not RSA are ignored.
pub fn parse_jwks(body: &str) -> Vec<Jwk> {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return Vec::new();
    };
    v["keys"]
        .as_array()
        .map(|keys| {
            keys.iter()
                .filter_map(|k| {
                    if k["kty"].as_str() != Some("RSA") {
                        return None;
                    }
                    let n = decode_url(k["n"].as_str()?)?;
                    let e = decode_url(k["e"].as_str()?)?;
                    Some(Jwk {
                        kid: k["kid"].as_str()?.to_string(),
                        key_der: rsa_public_key_der(&n, &e),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

pub fn jwt_kid(token: &str) -> Option<String> {
    let h = token.split('.').next()?;
    let v: Value = serde_json::from_slice(&decode_url(h)?).ok()?;
    v["kid"].as_str().map(String::from)
}

#[derive(Debug, PartialEq, Eq)]
pub enum AccessError {
    Malformed,
    NoKey,
    BadSignature,
    Expired,
    Audience,
    Issuer,
}

/// Verify the token and return the e-mail it vouches for.
pub fn verify_jwt(
    token: &str,
    keys: &[Jwk],
    team_domain: &str,
    audience: &str,
    now_s: u64,
) -> Result<String, AccessError> {
    if token.len() > 8192 {
        return Err(AccessError::Malformed);
    }
    let mut parts = token.split('.');
    let (h, p, s) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s), None) => (h, p, s),
        _ => return Err(AccessError::Malformed),
    };
    let header: Value = serde_json::from_slice(&decode_url(h).ok_or(AccessError::Malformed)?)
        .map_err(|_| AccessError::Malformed)?;
    if header["alg"].as_str() != Some("RS256") {
        return Err(AccessError::Malformed);
    }
    let kid = header["kid"].as_str().ok_or(AccessError::Malformed)?;
    let key = keys
        .iter()
        .find(|k| k.kid == kid)
        .ok_or(AccessError::NoKey)?;
    let sig = decode_url(s).ok_or(AccessError::Malformed)?;
    UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &key.key_der)
        .verify(format!("{h}.{p}").as_bytes(), &sig)
        .map_err(|_| AccessError::BadSignature)?;
    let c: Value = serde_json::from_slice(&decode_url(p).ok_or(AccessError::Malformed)?)
        .map_err(|_| AccessError::Malformed)?;
    let exp = c["exp"].as_u64().ok_or(AccessError::Malformed)?;
    if now_s >= exp || c["nbf"].as_u64().is_some_and(|n| now_s + 60 < n) {
        return Err(AccessError::Expired);
    }
    let aud_ok = match &c["aud"] {
        Value::String(a) => a == audience,
        Value::Array(a) => a.iter().any(|x| x.as_str() == Some(audience)),
        _ => false,
    };
    if !aud_ok {
        return Err(AccessError::Audience);
    }
    if c["iss"].as_str() != Some(&format!("https://{team_domain}")) {
        return Err(AccessError::Issuer);
    }
    c["email"]
        .as_str()
        .map(|e| e.to_ascii_lowercase())
        .ok_or(AccessError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::super::b64::encode_url;
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{RsaKeyPair, RSA_PKCS1_SHA256};
    use serde_json::json;

    // A throwaway 2048-bit key used only by this test (generated for it; protects nothing).
    const TEST_KEY_PKCS8_B64: &str = include_str!("testdata/access_test_key.pk8.b64");

    fn keypair() -> RsaKeyPair {
        let der = super::super::b64::decode_std(TEST_KEY_PKCS8_B64.trim()).unwrap();
        RsaKeyPair::from_der(&der).unwrap()
    }

    fn jwk(kp: &RsaKeyPair, kid: &str) -> Jwk {
        // ring exposes the public key as RSAPublicKey DER already.
        Jwk {
            kid: kid.into(),
            key_der: kp.public().as_ref().to_vec(),
        }
    }

    fn token(kp: &RsaKeyPair, kid: &str, claims: Value) -> String {
        let h = encode_url(json!({"alg":"RS256","kid":kid}).to_string().as_bytes());
        let p = encode_url(claims.to_string().as_bytes());
        let mut sig = vec![0u8; kp.public().modulus_len()];
        kp.sign(
            &RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            format!("{h}.{p}").as_bytes(),
            &mut sig,
        )
        .unwrap();
        format!("{h}.{p}.{}", encode_url(&sig))
    }

    #[test]
    fn a_token_is_trusted_only_when_every_check_passes() {
        let kp = keypair();
        let keys = [jwk(&kp, "k1")];
        let good = json!({"aud":["AUD"],"iss":"https://team.cloudflareaccess.com","exp":2000,"email":"Alice@Example.com"});
        let ok = |t: &str, now| verify_jwt(t, &keys, "team.cloudflareaccess.com", "AUD", now);
        assert_eq!(
            ok(&token(&kp, "k1", good.clone()), 1000).as_deref(),
            Ok("alice@example.com")
        );
        assert_eq!(
            ok(&token(&kp, "k1", good.clone()), 2000),
            Err(AccessError::Expired)
        );
        assert_eq!(
            ok(&token(&kp, "zz", good.clone()), 1000),
            Err(AccessError::NoKey)
        );
        let mut bad_aud = good.clone();
        bad_aud["aud"] = json!(["OTHER"]);
        assert_eq!(
            ok(&token(&kp, "k1", bad_aud), 1000),
            Err(AccessError::Audience)
        );
        let mut bad_iss = good.clone();
        bad_iss["iss"] = json!("https://evil.cloudflareaccess.com");
        assert_eq!(
            ok(&token(&kp, "k1", bad_iss), 1000),
            Err(AccessError::Issuer)
        );
        // a tampered payload fails the signature
        let t = token(&kp, "k1", good.clone());
        let mut parts: Vec<String> = t.split('.').map(String::from).collect();
        parts[1] = encode_url(json!({"aud":["AUD"],"iss":"https://team.cloudflareaccess.com","exp":2000,"email":"mallory@example.com"}).to_string().as_bytes());
        assert_eq!(ok(&parts.join("."), 1000), Err(AccessError::BadSignature));
        // alg none / garbage
        let none = format!(
            "{}.{}.",
            encode_url(br#"{"alg":"none"}"#),
            encode_url(good.to_string().as_bytes())
        );
        assert_eq!(ok(&none, 1000), Err(AccessError::Malformed));
        assert_eq!(ok("a.b", 1000), Err(AccessError::Malformed));
        // a key from another key pair
        let other = [Jwk {
            kid: "k1".into(),
            key_der: rsa_public_key_der(&[0x80; 256], &[1, 0, 1]),
        }];
        assert_eq!(
            verify_jwt(
                &token(&kp, "k1", good),
                &other,
                "team.cloudflareaccess.com",
                "AUD",
                1000
            ),
            Err(AccessError::BadSignature)
        );
    }

    #[test]
    fn jwks_parsing_keeps_rsa_keys_only() {
        let body = json!({"keys":[{"kid":"a","kty":"RSA","n":encode_url(&[0x80;256]),"e":"AQAB"},{"kid":"b","kty":"EC"}]}).to_string();
        let k = parse_jwks(&body);
        assert_eq!(k.len(), 1);
        assert_eq!(k[0].kid, "a");
        assert!(parse_jwks("nope").is_empty());
        assert_eq!(
            jwt_kid(&format!("{}.x.y", encode_url(br#"{"kid":"abc"}"#))).as_deref(),
            Some("abc")
        );
    }
}
