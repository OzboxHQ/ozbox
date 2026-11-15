//! Sign-in with GitHub (the device flow: no secret, no callback) and Google (the web flow with PKCE, the client
//! secret kept in the secret store). Only the person's identity is read; every token is dropped as soon as it has
//! been used. Both are the deployer's own OAuth apps: Oz Box ships no client of its own.

use ring::digest::{digest, SHA256};
use serde_json::Value;

use super::b64::{decode_url, encode_url};
use crate::netguard::{Guard, HttpClient, HttpRequest};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthError {
    /// The provider could not be reached or answered with something unreadable.
    Provider,
    /// The provider refused (bad client id, device flow switched off on the app, bad code).
    Refused,
    /// The identity the provider returned is not acceptable (unverified e-mail, wrong audience, replay).
    Identity,
}

pub fn pct(s: &str) -> String {
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

fn form(pairs: &[(&str, &str)]) -> Vec<u8> {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", pct(k), pct(v)))
        .collect::<Vec<_>>()
        .join("&")
        .into_bytes()
}

fn post_form(
    http: &dyn HttpClient,
    url: &str,
    pairs: &[(&str, &str)],
) -> Result<(u16, Value), OAuthError> {
    let mut req = HttpRequest::new("POST", url, Guard::Public)
        .header("Accept", "application/json")
        .header("Content-Type", "application/x-www-form-urlencoded");
    req.body = Some(form(pairs));
    let r = http.send(&req).map_err(|_| OAuthError::Provider)?;
    let v = serde_json::from_str(&r.body).map_err(|_| OAuthError::Provider)?;
    Ok((r.status, v))
}

#[derive(Debug, Clone)]
pub struct DeviceStart {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in: u64,
    pub interval: u64,
}

pub fn github_device_start(
    http: &dyn HttpClient,
    client_id: &str,
) -> Result<DeviceStart, OAuthError> {
    // No scope: reading the person's own id and login needs none.
    let (status, v) = post_form(
        http,
        "https://github.com/login/device/code",
        &[("client_id", client_id)],
    )?;
    if status != 200 || v.get("error").is_some() {
        return Err(OAuthError::Refused);
    }
    let s = |k: &str| v[k].as_str().map(String::from);
    let uri = s("verification_uri").ok_or(OAuthError::Provider)?;
    // The address shown to a person must be GitHub's.
    if !uri.starts_with("https://github.com/") {
        return Err(OAuthError::Provider);
    }
    Ok(DeviceStart {
        device_code: s("device_code").ok_or(OAuthError::Provider)?,
        user_code: s("user_code").ok_or(OAuthError::Provider)?,
        verification_uri: uri,
        expires_in: v["expires_in"].as_u64().unwrap_or(900).clamp(30, 1800),
        interval: v["interval"].as_u64().unwrap_or(5).clamp(1, 60),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Poll {
    Pending,
    SlowDown(u64),
    Expired,
    Denied,
    Token(String),
}

pub fn github_device_poll(
    http: &dyn HttpClient,
    client_id: &str,
    device_code: &str,
) -> Result<Poll, OAuthError> {
    let (_, v) = post_form(
        http,
        "https://github.com/login/oauth/access_token",
        &[
            ("client_id", client_id),
            ("device_code", device_code),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ],
    )?;
    if let Some(t) = v["access_token"].as_str() {
        return Ok(Poll::Token(t.to_string()));
    }
    match v["error"].as_str() {
        Some("authorization_pending") => Ok(Poll::Pending),
        Some("slow_down") => Ok(Poll::SlowDown(
            v["interval"].as_u64().unwrap_or(10).clamp(1, 120),
        )),
        Some("expired_token") => Ok(Poll::Expired),
        Some("access_denied") => Ok(Poll::Denied),
        Some(_) => Err(OAuthError::Refused),
        None => Err(OAuthError::Provider),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubUser {
    pub id: u64,
    pub login: String,
}

pub fn github_user(http: &dyn HttpClient, token: &str) -> Result<GithubUser, OAuthError> {
    let req = HttpRequest::new("GET", "https://api.github.com/user", Guard::Public)
        .header("Authorization", format!("Bearer {token}"))
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "ozbox")
        .header("X-GitHub-Api-Version", "2022-11-28");
    let r = http.send(&req).map_err(|_| OAuthError::Provider)?;
    if !r.ok() {
        return Err(OAuthError::Refused);
    }
    let v: Value = serde_json::from_str(&r.body).map_err(|_| OAuthError::Provider)?;
    match (v["id"].as_u64(), v["login"].as_str()) {
        (Some(id), Some(login)) if !login.is_empty() => Ok(GithubUser {
            id,
            login: login.to_ascii_lowercase(),
        }),
        _ => Err(OAuthError::Provider),
    }
}

pub fn pkce_challenge(verifier: &str) -> String {
    encode_url(digest(&SHA256, verifier.as_bytes()).as_ref())
}

pub fn google_auth_url(
    client_id: &str,
    redirect_uri: &str,
    state: &str,
    nonce: &str,
    verifier: &str,
) -> String {
    format!(
        "https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id={}&redirect_uri={}&scope=openid%20email&state={}&nonce={}&code_challenge={}&code_challenge_method=S256&prompt=select_account",
        pct(client_id),
        pct(redirect_uri),
        pct(state),
        pct(nonce),
        pct(&pkce_challenge(verifier)),
    )
}

#[allow(clippy::too_many_arguments)]
/// Exchange the code (the token endpoint answers over TLS, so the id token needs no signature check here) and return
/// the verified e-mail address.
pub fn google_identity(
    http: &dyn HttpClient,
    client_id: &str,
    client_secret: &str,
    code: &str,
    verifier: &str,
    redirect_uri: &str,
    nonce: &str,
    now_s: u64,
) -> Result<String, OAuthError> {
    let (status, v) = post_form(
        http,
        "https://oauth2.googleapis.com/token",
        &[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("redirect_uri", redirect_uri),
            ("code_verifier", verifier),
        ],
    )?;
    if status != 200 {
        return Err(OAuthError::Refused);
    }
    let idt = v["id_token"].as_str().ok_or(OAuthError::Provider)?;
    id_token_email(idt, client_id, nonce, now_s)
}

pub fn id_token_email(
    id_token: &str,
    client_id: &str,
    nonce: &str,
    now_s: u64,
) -> Result<String, OAuthError> {
    let payload = id_token.split('.').nth(1).ok_or(OAuthError::Provider)?;
    let c: Value = serde_json::from_slice(&decode_url(payload).ok_or(OAuthError::Provider)?)
        .map_err(|_| OAuthError::Provider)?;
    let iss_ok = matches!(
        c["iss"].as_str(),
        Some("https://accounts.google.com") | Some("accounts.google.com")
    );
    let aud_ok = c["aud"].as_str() == Some(client_id);
    let nonce_ok = c["nonce"]
        .as_str()
        .is_some_and(|n| super::b64::ct_eq_bytes(n.as_bytes(), nonce.as_bytes()));
    let fresh = c["exp"].as_u64().is_some_and(|e| e > now_s);
    // `email_verified` is a boolean, but has been seen as the string "true".
    let verified =
        c["email_verified"] == Value::Bool(true) || c["email_verified"].as_str() == Some("true");
    if !(iss_ok && aud_ok && nonce_ok && fresh && verified) {
        return Err(OAuthError::Identity);
    }
    c["email"]
        .as_str()
        .map(|e| e.to_ascii_lowercase())
        .ok_or(OAuthError::Identity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netguard::FakeHttp;
    use serde_json::json;

    #[test]
    fn pkce_matches_the_rfc_vector() {
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn the_google_url_carries_state_nonce_pkce_and_the_exact_redirect() {
        let u = google_auth_url(
            "cid",
            "https://box.example.com/auth/google/callback",
            "ST",
            "NO",
            "ver",
        );
        for p in [
            "state=ST",
            "nonce=NO",
            "code_challenge_method=S256",
            "redirect_uri=https%3A%2F%2Fbox.example.com%2Fauth%2Fgoogle%2Fcallback",
            "client_id=cid",
            "scope=openid%20email",
        ] {
            assert!(u.contains(p), "{u}");
        }
        assert!(!u.contains("ver&") && !u.ends_with("ver"));
    }

    fn token(claims: Value) -> String {
        format!(
            "{}.{}.sig",
            encode_url(b"{}"),
            encode_url(claims.to_string().as_bytes())
        )
    }

    #[test]
    fn an_id_token_must_be_for_this_app_fresh_nonced_and_verified() {
        let good = json!({"iss":"https://accounts.google.com","aud":"cid","nonce":"n1","exp":2000,"email":"A@x.com","email_verified":true});
        assert_eq!(
            id_token_email(&token(good.clone()), "cid", "n1", 1000).as_deref(),
            Ok("a@x.com")
        );
        let with = |k: &str, v: Value| {
            let mut c = good.clone();
            c[k] = v;
            id_token_email(&token(c), "cid", "n1", 1000)
        };
        assert_eq!(
            with("email_verified", json!(false)),
            Err(OAuthError::Identity)
        );
        assert_eq!(with("aud", json!("other")), Err(OAuthError::Identity));
        assert_eq!(with("nonce", json!("n2")), Err(OAuthError::Identity));
        assert_eq!(with("exp", json!(900)), Err(OAuthError::Identity));
        assert_eq!(
            with("iss", json!("https://evil.example")),
            Err(OAuthError::Identity)
        );
    }

    #[test]
    fn the_device_flow_handles_every_answer_and_never_sends_a_secret() {
        let h = FakeHttp::default();
        h.reply(200, r#"{"device_code":"DC","user_code":"ABCD-1234","verification_uri":"https://github.com/login/device","expires_in":900,"interval":5}"#);
        let d = github_device_start(&h, "Iv1.test").unwrap();
        assert_eq!((d.user_code.as_str(), d.interval), ("ABCD-1234", 5));
        for (body, want) in [
            (r#"{"error":"authorization_pending"}"#, Poll::Pending),
            (r#"{"error":"slow_down","interval":10}"#, Poll::SlowDown(10)),
            (r#"{"error":"expired_token"}"#, Poll::Expired),
            (r#"{"error":"access_denied"}"#, Poll::Denied),
            (
                r#"{"access_token":"gho_x","token_type":"bearer"}"#,
                Poll::Token("gho_x".into()),
            ),
        ] {
            h.reply(200, body);
            assert_eq!(github_device_poll(&h, "Iv1.test", "DC"), Ok(want));
        }
        h.reply(200, r#"{"error":"unauthorized_client"}"#);
        assert_eq!(github_device_poll(&h, "x", "DC"), Err(OAuthError::Refused));
        // a verification address that is not GitHub's is refused
        h.reply(
            200,
            r#"{"device_code":"D","user_code":"U","verification_uri":"https://evil.example/x"}"#,
        );
        assert!(github_device_start(&h, "c").is_err());
        for r in h.requests() {
            let body = String::from_utf8_lossy(r.body.as_deref().unwrap_or(&[])).into_owned();
            assert!(!body.contains("client_secret"), "{body}");
            assert!(r.url.starts_with("https://github.com/"));
        }
        h.reply(200, r#"{"id":4242,"login":"Alice"}"#);
        assert_eq!(
            github_user(&h, "gho_x").unwrap(),
            GithubUser {
                id: 4242,
                login: "alice".into()
            }
        );
    }
}
