//! A small, native AWS client for the calls a box makes about its own secrets: no `aws` command, no SDK (ADR 0008).
//!
//! The box image does not carry the AWS CLI (its installer's signature cannot be verified, so `ozbox tools` refuses it), so
//! anything the secrets service needs from AWS must work without it. This module is the one place that does:
//!
//! * **Credentials** come from the environment (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`) or, on a
//!   box, from the instance's role through IMDSv2 (a token first, then the role's credentials). They are kept in memory
//!   only, until a minute before their stated expiry, and zeroized when dropped. Profiles and single sign-on are not read:
//!   a box's store is opened by the box's role.
//! * **Requests** are AWS JSON (`application/x-amz-json-1.1`, an `X-Amz-Target`) signed with SigV4 by
//!   [`crate::broker_cloud::sign_v4`], the signer that is checked against AWS's published test vector.
//! * **Errors** are one of two kinds ([`Failure`]): the service's own access-denied answer, or anything else. Nothing from the
//!   service, the credentials or the request is in an error.
//!
//! Not verified against the real services in CI: every test here talks to loopback fakes.

use std::io::Read;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use zeroize::{Zeroize, Zeroizing};

use crate::broker_cloud::{sign_v4, AwsKeys};
use crate::netguard::{Guard, HttpRequest};

/// The instance metadata service.
pub const IMDS_BASE: &str = "http://169.254.169.254";
/// Credentials are renewed this long before they expire.
const RENEW_BEFORE: u64 = 60;
const IMDS_TIMEOUT: Duration = Duration::from_secs(3);
const CALL_TIMEOUT: Duration = Duration::from_secs(10);
/// No answer from AWS is read past this many bytes.
const MAX_ANSWER: u64 = 256 * 1024;

/// Why a call did not give an answer. Only the service's own refusal is told apart: it is the one failure a person fixes by
/// changing a policy, where every other (a timeout, a throttle, no network, no credentials) is a reason to try again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// The service answered `AccessDeniedException`.
    Denied,
    Unavailable,
}

struct Creds {
    access_key_id: String,
    secret_access_key: Zeroizing<String>,
    session_token: Option<Zeroizing<String>>,
    /// Unix seconds; `None` for keys from the environment (they do not say).
    expires: Option<u64>,
}

impl Drop for Creds {
    fn drop(&mut self) {
        self.access_key_id.zeroize();
    }
}

/// The JSON a role's credentials come back as. Only these fields are read.
#[derive(Deserialize)]
struct RoleCreds {
    #[serde(rename = "Code", default)]
    code: String,
    #[serde(rename = "AccessKeyId", default)]
    access_key_id: String,
    #[serde(rename = "SecretAccessKey", default)]
    secret_access_key: String,
    #[serde(rename = "Token", default)]
    token: String,
    #[serde(rename = "Expiration", default)]
    expiration: String,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

/// A signed-JSON client for the box's own role.
pub struct AwsJson {
    imds: String,
    /// Read `AWS_ACCESS_KEY_ID` and friends first. Off for a client built for a test, so a developer's own keys never answer.
    env_creds: bool,
    creds: Mutex<Option<Creds>>,
}

impl AwsJson {
    pub fn new() -> Self {
        Self {
            imds: IMDS_BASE.into(),
            env_creds: true,
            creds: Mutex::new(None),
        }
    }

    /// A client reading only the metadata service at `imds` (a loopback fake in tests).
    #[cfg(test)]
    pub fn with_imds(imds: &str) -> Self {
        Self {
            imds: imds.trim_end_matches('/').to_string(),
            env_creds: false,
            creds: Mutex::new(None),
        }
    }

    fn imds_get(&self, path: &str, token: &str) -> Result<String, Failure> {
        let agent = ureq::AgentBuilder::new()
            .timeout(IMDS_TIMEOUT)
            .redirects(0)
            .build();
        agent
            .get(&format!("{}{path}", self.imds))
            .set("X-aws-ec2-metadata-token", token)
            .call()
            .map_err(|_| Failure::Unavailable)?
            .into_string()
            .map_err(|_| Failure::Unavailable)
    }

    fn imds_token(&self) -> Result<Zeroizing<String>, Failure> {
        let agent = ureq::AgentBuilder::new()
            .timeout(IMDS_TIMEOUT)
            .redirects(0)
            .build();
        let t = agent
            .put(&format!("{}/latest/api/token", self.imds))
            .set("X-aws-ec2-metadata-token-ttl-seconds", "60")
            .send_bytes(&[])
            .map_err(|_| Failure::Unavailable)?
            .into_string()
            .map_err(|_| Failure::Unavailable)?;
        Ok(Zeroizing::new(t))
    }

    /// The region this machine is in, from the metadata service.
    pub fn imds_region(&self) -> Option<String> {
        let tok = self.imds_token().ok()?;
        let r = self
            .imds_get("/latest/meta-data/placement/region", &tok)
            .ok()?;
        let r = r.trim();
        valid_region(r).then(|| r.to_string())
    }

    fn fetch_creds(&self) -> Result<Creds, Failure> {
        if let (true, Some(id), Some(secret)) = (
            self.env_creds,
            env("AWS_ACCESS_KEY_ID"),
            env("AWS_SECRET_ACCESS_KEY"),
        ) {
            return Ok(Creds {
                access_key_id: id,
                secret_access_key: Zeroizing::new(secret),
                session_token: env("AWS_SESSION_TOKEN").map(Zeroizing::new),
                expires: None,
            });
        }
        let tok = self.imds_token()?;
        let role = self.imds_get("/latest/meta-data/iam/security-credentials/", &tok)?;
        let role = role.lines().next().unwrap_or("").trim().to_string();
        if role.is_empty()
            || !role
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+=,.@_-".contains(&b))
        {
            return Err(Failure::Unavailable);
        }
        let body = Zeroizing::new(self.imds_get(
            &format!("/latest/meta-data/iam/security-credentials/{role}"),
            &tok,
        )?);
        let c: RoleCreds = serde_json::from_str(&body).map_err(|_| Failure::Unavailable)?;
        let secret = Zeroizing::new(c.secret_access_key);
        let token = Zeroizing::new(c.token);
        if (!c.code.is_empty() && c.code != "Success")
            || c.access_key_id.is_empty()
            || secret.is_empty()
        {
            return Err(Failure::Unavailable);
        }
        let expires = c
            .expiration
            .parse::<jiff::Timestamp>()
            .ok()
            .and_then(|t| u64::try_from(t.as_second()).ok());
        Ok(Creds {
            access_key_id: c.access_key_id,
            secret_access_key: secret,
            session_token: (!token.is_empty()).then_some(token),
            expires,
        })
    }

    fn with_creds<T>(
        &self,
        f: impl FnOnce(&AwsKeys<'_>) -> Result<T, Failure>,
    ) -> Result<T, Failure> {
        let mut guard = self.creds.lock().map_err(|_| Failure::Unavailable)?;
        let usable = guard
            .as_ref()
            .is_some_and(|c| c.expires.is_none_or(|e| e > now() + RENEW_BEFORE));
        if !usable {
            *guard = Some(self.fetch_creds()?);
        }
        let Some(c) = guard.as_ref() else {
            return Err(Failure::Unavailable);
        };
        let keys = AwsKeys {
            access_key_id: &c.access_key_id,
            secret_access_key: &c.secret_access_key,
            session_token: c.session_token.as_deref().map(String::as_str),
        };
        let out = f(&keys);
        if matches!(out, Err(Failure::Unavailable)) {
            // an expired or revoked session is one of the reasons: fetch again next time
            *guard = None;
        }
        out
    }

    /// One signed call. `base` is the service's address (`https://kms.us-east-1.amazonaws.com`); `body` is the JSON request,
    /// zeroized here. The answer is the response body, for the caller to zeroize.
    pub fn call(
        &self,
        base: &str,
        region: &str,
        service: &str,
        target: &str,
        body: Zeroizing<Vec<u8>>,
    ) -> Result<Zeroizing<Vec<u8>>, Failure> {
        let host = base
            .strip_prefix("https://")
            .or_else(|| base.strip_prefix("http://"))
            .ok_or(Failure::Unavailable)?
            .trim_end_matches('/');
        let mut req = HttpRequest::new("POST", format!("https://{host}/"), Guard::Public);
        req.body = Some(body.to_vec());
        let signed = self.with_creds(|keys| {
            sign_v4(&req, keys, region, service, now()).map_err(|_| Failure::Unavailable)
        });
        if let Some(b) = req.body.as_mut() {
            b.zeroize();
        }
        let signed = signed?;
        let agent = ureq::AgentBuilder::new()
            .timeout(CALL_TIMEOUT)
            .redirects(0)
            .build();
        let mut r = agent
            .post(&format!("{}/", base.trim_end_matches('/')))
            .set("Content-Type", "application/x-amz-json-1.1")
            .set("X-Amz-Target", target);
        for (k, v) in &signed {
            r = r.set(k, v);
        }
        match r.send_bytes(&body) {
            Ok(resp) => {
                let mut out = Zeroizing::new(Vec::new());
                resp.into_reader()
                    .take(MAX_ANSWER)
                    .read_to_end(&mut out)
                    .map_err(|_| Failure::Unavailable)?;
                Ok(out)
            }
            Err(ureq::Error::Status(_, resp)) => {
                let header = resp.header("x-amzn-ErrorType").map(str::to_string);
                let mut text = Zeroizing::new(Vec::new());
                let _ = resp.into_reader().take(64 * 1024).read_to_end(&mut text);
                let named = header.or_else(|| {
                    serde_json::from_slice::<serde_json::Value>(&text)
                        .ok()
                        .and_then(|v| v.get("__type").and_then(|t| t.as_str()).map(str::to_string))
                });
                if named.as_deref().is_some_and(is_access_denied) {
                    Err(Failure::Denied)
                } else {
                    self.forget();
                    Err(Failure::Unavailable)
                }
            }
            Err(_) => Err(Failure::Unavailable),
        }
    }

    fn forget(&self) {
        if let Ok(mut g) = self.creds.lock() {
            *g = None;
        }
    }
}

impl Default for AwsJson {
    fn default() -> Self {
        Self::new()
    }
}

/// `AccessDeniedException`, however AWS spells the type (`com.amazon.coral.service#AccessDeniedException:http://...`). Only
/// the exact name counts: `AccessDenied` (S3's) and anything merely containing it do not.
fn is_access_denied(name: &str) -> bool {
    let name = name.rsplit('#').next().unwrap_or(name);
    name.split(':').next() == Some("AccessDeniedException")
}

/// A region name: lowercase letters, digits and dashes, as AWS spells them.
pub fn valid_region(r: &str) -> bool {
    !r.is_empty()
        && r.len() <= 32
        && r.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// A service's address in a region (`https://kms.us-east-1.amazonaws.com`; `.com.cn` in China).
pub fn service_base(service: &str, region: &str) -> String {
    let suffix = if region.starts_with("cn-") {
        "amazonaws.com.cn"
    } else {
        "amazonaws.com"
    };
    format!("https://{service}.{region}.{suffix}")
}

/// Loopback fakes of the metadata service and the key service, for tests here and in the secrets store's. Nothing leaves the
/// machine and no real credential is involved.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) mod fakes {
    use std::io::Cursor;
    use std::sync::{Arc, Mutex};

    use tiny_http::{Header, Response, Server};

    pub const ACCESS_KEY: &str = "AKIAFAKEFAKEFAKE0000";
    pub const SECRET_KEY: &str = "fake-secret-access-key-sentinel-0000000000";
    pub const SESSION_TOKEN: &str = "fake-session-token-sentinel";

    #[derive(Clone, Debug)]
    pub struct Seen {
        pub method: String,
        pub url: String,
        pub headers: Vec<(String, String)>,
        pub body: String,
    }

    impl Seen {
        pub fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        }
    }

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum Kms {
        Works,
        Denied,
        Throttled,
        ServerError,
    }

    pub struct Fake {
        pub imds: String,
        pub kms: String,
        pub imds_seen: Arc<Mutex<Vec<Seen>>>,
        pub kms_seen: Arc<Mutex<Vec<Seen>>>,
        pub mode: Arc<Mutex<Kms>>,
        /// The `Expiration` the metadata service reports.
        pub expiration: Arc<Mutex<String>>,
        /// Whether the metadata service answers at all.
        pub imds_up: Arc<Mutex<bool>>,
    }

    fn seen_of(r: &mut tiny_http::Request) -> Seen {
        let mut body = String::new();
        let _ = std::io::Read::read_to_string(r.as_reader(), &mut body);
        Seen {
            method: r.method().to_string(),
            url: r.url().to_string(),
            headers: r
                .headers()
                .iter()
                .map(|h| (h.field.as_str().to_string(), h.value.as_str().to_string()))
                .collect(),
            body,
        }
    }

    fn text(s: &str) -> Response<Cursor<Vec<u8>>> {
        Response::from_string(s)
    }

    fn json(code: u16, s: &str) -> Response<Cursor<Vec<u8>>> {
        Response::from_string(s)
            .with_status_code(code)
            .with_header(Header::from_bytes("Content-Type", "application/x-amz-json-1.1").unwrap())
    }

    impl Fake {
        pub fn start() -> Self {
            let f = Fake {
                imds: String::new(),
                kms: String::new(),
                imds_seen: Arc::default(),
                kms_seen: Arc::default(),
                mode: Arc::new(Mutex::new(Kms::Works)),
                expiration: Arc::new(Mutex::new("2099-01-01T00:00:00Z".into())),
                imds_up: Arc::new(Mutex::new(true)),
            };
            let imds_srv = Server::http("127.0.0.1:0").unwrap();
            let kms_srv = Server::http("127.0.0.1:0").unwrap();
            let imds = format!("http://{}", imds_srv.server_addr().to_ip().unwrap());
            let kms = format!("http://{}", kms_srv.server_addr().to_ip().unwrap());
            let (seen, exp, up) = (f.imds_seen.clone(), f.expiration.clone(), f.imds_up.clone());
            std::thread::spawn(move || {
                for mut r in imds_srv.incoming_requests() {
                    let s = seen_of(&mut r);
                    seen.lock().unwrap().push(s.clone());
                    if !*up.lock().unwrap() {
                        let _ = r.respond(text("down").with_status_code(503));
                        continue;
                    }
                    let tok_ok = s.header("x-aws-ec2-metadata-token") == Some("imds-token");
                    let resp = match (s.method.as_str(), s.url.as_str()) {
                        ("PUT", "/latest/api/token") => text("imds-token"),
                        (_, _) if !tok_ok => text("unauthorized").with_status_code(401),
                        ("GET", "/latest/meta-data/iam/security-credentials/") => {
                            text("fake-role\n")
                        }
                        ("GET", "/latest/meta-data/iam/security-credentials/fake-role") => {
                            text(&format!(
                                r#"{{"Code":"Success","AccessKeyId":"{ACCESS_KEY}","SecretAccessKey":"{SECRET_KEY}","Token":"{SESSION_TOKEN}","Expiration":"{}"}}"#,
                                exp.lock().unwrap()
                            ))
                        }
                        ("GET", "/latest/meta-data/placement/region") => text("eu-west-2"),
                        _ => text("no").with_status_code(404),
                    };
                    let _ = r.respond(resp);
                }
            });
            let (seen, mode) = (f.kms_seen.clone(), f.mode.clone());
            std::thread::spawn(move || {
                for mut r in kms_srv.incoming_requests() {
                    let s = seen_of(&mut r);
                    seen.lock().unwrap().push(s.clone());
                    let m = *mode.lock().unwrap();
                    let resp = match m {
                        Kms::Denied => json(
                            400,
                            r#"{"__type":"AccessDeniedException","message":"User: arn:aws:sts::123456789012:assumed-role/x is not authorized"}"#,
                        ),
                        Kms::Throttled => json(400, r#"{"__type":"ThrottlingException"}"#),
                        Kms::ServerError => json(500, "boom"),
                        Kms::Works => {
                            let v: serde_json::Value = serde_json::from_str(&s.body).unwrap();
                            if s.header("x-amz-target") == Some("TrentService.Encrypt") {
                                let pt = v["Plaintext"].as_str().unwrap_or("");
                                json(
                                    200,
                                    &format!(
                                        r#"{{"CiphertextBlob":"{}"}}"#,
                                        super::b64_of(format!("CT:{pt}").as_bytes())
                                    ),
                                )
                            } else {
                                let ct = super::b64_dec(v["CiphertextBlob"].as_str().unwrap_or(""));
                                let ct = String::from_utf8(ct).unwrap_or_default();
                                match ct.strip_prefix("CT:") {
                                    Some(pt) => json(200, &format!(r#"{{"Plaintext":"{pt}"}}"#)),
                                    None => json(400, r#"{"__type":"InvalidCiphertextException"}"#),
                                }
                            }
                        }
                    };
                    let _ = r.respond(resp);
                }
            });
            Fake { imds, kms, ..f }
        }
    }
}

#[cfg(test)]
fn b64_of(b: &[u8]) -> String {
    crate::serve::auth::b64::encode_std(b)
}

#[cfg(test)]
fn b64_dec(s: &str) -> Vec<u8> {
    crate::serve::auth::b64::decode_std(s).unwrap_or_default()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn only_the_exact_access_denied_name_is_a_refusal() {
        for (n, want) in [
            ("AccessDeniedException", true),
            ("com.amazon.coral.service#AccessDeniedException", true),
            ("AccessDeniedException:http://internal.amazon.com/", true),
            ("AccessDenied", false),
            ("NotAccessDeniedException", false),
            ("ThrottlingException", false),
            ("", false),
        ] {
            assert_eq!(is_access_denied(n), want, "{n}");
        }
    }

    #[test]
    fn addresses_and_regions() {
        assert_eq!(
            service_base("kms", "us-east-1"),
            "https://kms.us-east-1.amazonaws.com"
        );
        assert_eq!(
            service_base("kms", "cn-north-1"),
            "https://kms.cn-north-1.amazonaws.com.cn"
        );
        assert!(valid_region("eu-west-2") && !valid_region("") && !valid_region("US-EAST-1"));
        assert!(!valid_region("a.b") && !valid_region("a/b"));
    }
}
