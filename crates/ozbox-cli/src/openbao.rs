//! A small, native OpenBao (and Vault) KV version 2 client, for a box's own secrets and its store-key escrow: no `bao`
//! command (the box image does not carry it) and no SDK (ADR 0008).
//!
//! * **Address**: `BAO_ADDR`, `https://host` or `https://host:port`, which a root-written file gives the secrets user's units.
//!   Only https is spoken, and the server's certificate is verified against the program's built-in public roots (the same
//!   ones every other call uses). A vault behind a private certificate authority is not reached (a known limit).
//! * **Token**: `BAO_TOKEN`, read from the environment at the moment of each request and never kept: it is in one
//!   zeroized local for the length of the call, sent only as the `X-Vault-Token` header, and never in an argument, a URL, a
//!   log or an error.
//! * **Requests**: `GET /v1/<mount>/metadata/<path>?list=true` (list), `GET /v1/<mount>/data/<path>` (read) and
//!   `POST /v1/<mount>/data/<path>` with `{"data": {...}}` (write a new version). Every path segment is checked to be a plain
//!   word first, so nothing from a vault's answer can steer a request elsewhere.
//! * **Errors** are one of [`Failure`]: nothing from the server, the token or the path is in one.
//!
//! Not verified against a real vault in CI: every test talks to a loopback fake.

use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use zeroize::{Zeroize, Zeroizing};

const CALL_TIMEOUT: Duration = Duration::from_secs(10);
/// No answer from the vault is read past this many bytes.
const MAX_ANSWER: u64 = 256 * 1024;

/// Why a request gave no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// The vault refused the token (HTTP 401 or 403): a policy or token to fix, not a reason to try again.
    Denied,
    /// Nothing is at that path (HTTP 404).
    NotFound,
    /// No token, no network, a timeout, a server error or an answer that is not the vault's: worth trying again.
    Unavailable,
}

type TokenSource = Arc<dyn Fn() -> Option<Zeroizing<String>> + Send + Sync>;

/// A secret's string fields, values zeroized when dropped.
pub type Fields = Vec<(String, Zeroizing<String>)>;

/// A client for one vault address. Cheap to clone; it holds no secret.
#[derive(Clone)]
pub struct Bao {
    addr: String,
    token: TokenSource,
}

impl std::fmt::Debug for Bao {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bao")
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

impl PartialEq for Bao {
    fn eq(&self, other: &Self) -> bool {
        self.addr == other.addr
    }
}

impl Eq for Bao {}

/// `https://host` or `https://host:port`, lowercase, as the box's declaration accepts it.
pub fn valid_addr(addr: &str) -> bool {
    let Some(rest) = addr.strip_prefix("https://") else {
        return false;
    };
    let (host, port) = rest
        .split_once(':')
        .map_or((rest, None), |(h, p)| (h, Some(p)));
    let host_ok = !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
        && !host.starts_with(['.', '-'])
        && !host.ends_with(['.', '-']);
    let port_ok =
        port.is_none_or(|p| (2..=5).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit()));
    host_ok && port_ok
}

/// A mount or a path segment: letters, digits, `-`, `_` and `.`, never `.` or `..` on its own.
pub fn plain_segment(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 100
        && s != "."
        && s != ".."
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

/// A path of plain segments, without leading or trailing slashes.
pub fn plain_path(p: &str) -> bool {
    !p.is_empty() && p.len() <= 200 && p.split('/').all(plain_segment)
}

#[derive(Deserialize)]
struct ListAnswer {
    data: ListData,
}

#[derive(Deserialize)]
struct ListData {
    #[serde(default)]
    keys: Vec<String>,
}

#[derive(Deserialize)]
struct ReadAnswer {
    data: ReadData,
}

#[derive(Deserialize)]
struct ReadData {
    /// `null` for a version that was deleted.
    #[serde(default)]
    data: Option<serde_json::Map<String, serde_json::Value>>,
}

impl Bao {
    /// A client for `addr`, with the token read from `BAO_TOKEN` at each request. `None` if the address is not one.
    pub fn new(addr: &str) -> Option<Self> {
        valid_addr(addr).then(|| Self {
            addr: addr.to_string(),
            token: Arc::new(|| {
                std::env::var("BAO_TOKEN")
                    .ok()
                    .filter(|t| !t.is_empty())
                    .map(Zeroizing::new)
            }),
        })
    }

    /// The client the environment names (`BAO_ADDR`).
    pub fn from_env() -> Option<Self> {
        Self::new(&std::env::var("BAO_ADDR").ok()?)
    }

    /// A client for a loopback fake, with its own token source.
    #[cfg(test)]
    pub fn for_test(addr: &str, token: TokenSource) -> Self {
        Self {
            addr: addr.trim_end_matches('/').to_string(),
            token,
        }
    }

    fn url(&self, kind: &str, mount: &str, path: &str) -> Result<String, Failure> {
        if !plain_segment(mount) || !plain_path(path) {
            return Err(Failure::Unavailable);
        }
        Ok(format!("{}/v1/{mount}/{kind}/{path}", self.addr))
    }

    /// One request. The token is fetched now and dropped (zeroized) when the call returns.
    fn send(
        &self,
        method: &str,
        url: &str,
        body: Option<&[u8]>,
    ) -> Result<Zeroizing<Vec<u8>>, Failure> {
        // plain http is for the loopback fakes in tests only: a real vault is always https
        #[cfg(not(test))]
        if !url.starts_with("https://") {
            return Err(Failure::Unavailable);
        }
        let mut token = (self.token)().ok_or(Failure::Unavailable)?;
        let agent = ureq::AgentBuilder::new()
            .timeout(CALL_TIMEOUT)
            .redirects(0)
            .build();
        let req = agent
            .request(method, url)
            .set("X-Vault-Token", token.as_str())
            .set("X-Vault-Request", "true");
        token.zeroize();
        let answer = match body {
            Some(b) => req.set("Content-Type", "application/json").send_bytes(b),
            None => req.call(),
        };
        match answer {
            Ok(resp) => {
                let mut out = Zeroizing::new(Vec::new());
                resp.into_reader()
                    .take(MAX_ANSWER)
                    .read_to_end(&mut out)
                    .map_err(|_| Failure::Unavailable)?;
                Ok(out)
            }
            Err(ureq::Error::Status(401 | 403, _)) => Err(Failure::Denied),
            Err(ureq::Error::Status(404, _)) => Err(Failure::NotFound),
            Err(_) => Err(Failure::Unavailable),
        }
    }

    /// The keys directly under `path` (a folder ends in `/`). Nothing there is an empty list.
    pub fn list(&self, mount: &str, path: &str) -> Result<Vec<String>, Failure> {
        let url = format!("{}?list=true", self.url("metadata", mount, path)?);
        match self.send("GET", &url, None) {
            Ok(body) => serde_json::from_slice::<ListAnswer>(&body)
                .map(|a| a.data.keys)
                .map_err(|_| Failure::Unavailable),
            Err(Failure::NotFound) => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    /// The newest version of the secret at `path`, as its string fields; `None` when there is none (or it was deleted).
    pub fn read(&self, mount: &str, path: &str) -> Result<Option<Fields>, Failure> {
        let url = self.url("data", mount, path)?;
        let body = match self.send("GET", &url, None) {
            Ok(b) => b,
            Err(Failure::NotFound) => return Ok(None),
            Err(e) => return Err(e),
        };
        // the parser's own words could quote the text it choked on: only "unavailable" is said
        let mut answer: ReadAnswer =
            serde_json::from_slice(&body).map_err(|_| Failure::Unavailable)?;
        let Some(map) = answer.data.data.take() else {
            return Ok(None);
        };
        Ok(Some(
            map.into_iter()
                .filter_map(|(k, v)| match v {
                    serde_json::Value::String(s) => Some((k, Zeroizing::new(s))),
                    _ => None,
                })
                .collect(),
        ))
    }

    /// Write `pairs` as a new version of the secret at `path` (the whole secret, as `bao kv put` does).
    pub fn write(&self, mount: &str, path: &str, pairs: &[(&str, &str)]) -> Result<(), Failure> {
        let url = self.url("data", mount, path)?;
        let data: serde_json::Map<String, serde_json::Value> = pairs
            .iter()
            .map(|(k, v)| {
                (
                    (*k).to_string(),
                    serde_json::Value::String((*v).to_string()),
                )
            })
            .collect();
        let body = Zeroizing::new(
            serde_json::to_vec(&serde_json::json!({ "data": data }))
                .map_err(|_| Failure::Unavailable)?,
        );
        self.send("POST", &url, Some(&body)).map(|_| ())
    }
}

/// A loopback vault for tests here and in the callers': it records every request and answers KV v2 the way OpenBao does, from
/// a map of `<mount>/<path>` to fields. Only the token [`fakes::TOKEN`] is accepted.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) mod fakes {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use tiny_http::{Response, Server};

    use crate::aws_native::fakes::{seen_of, Seen};

    pub const TOKEN: &str = "s.SENTINEL-bao-token-0123456789";

    pub struct Vault {
        pub addr: String,
        pub seen: Arc<Mutex<Vec<Seen>>>,
        /// `<mount>/<path>` to its fields.
        pub data: Arc<Mutex<BTreeMap<String, BTreeMap<String, String>>>>,
        /// When set, every request gets this status and body instead.
        pub force: Arc<Mutex<Option<(u16, String)>>>,
    }

    impl Vault {
        pub fn start() -> Self {
            let srv = Server::http("127.0.0.1:0").unwrap();
            let addr = format!("http://{}", srv.server_addr().to_ip().unwrap());
            let v = Vault {
                addr,
                seen: Arc::default(),
                data: Arc::default(),
                force: Arc::default(),
            };
            let (seen, data, force) = (v.seen.clone(), v.data.clone(), v.force.clone());
            std::thread::spawn(move || {
                for mut r in srv.incoming_requests() {
                    let s = seen_of(&mut r);
                    seen.lock().unwrap().push(s.clone());
                    if let Some((code, body)) = force.lock().unwrap().clone() {
                        let _ = r.respond(Response::from_string(body).with_status_code(code));
                        continue;
                    }
                    if s.header("x-vault-token") != Some(TOKEN) {
                        let _ = r.respond(
                            Response::from_string(r#"{"errors":["permission denied"]}"#)
                                .with_status_code(403),
                        );
                        continue;
                    }
                    let (path, query) = s.url.split_once('?').unwrap_or((&s.url, ""));
                    let mut parts = path.trim_start_matches("/v1/").splitn(3, '/');
                    let (mount, kind, rest) = (
                        parts.next().unwrap_or(""),
                        parts.next().unwrap_or(""),
                        parts.next().unwrap_or(""),
                    );
                    let key = format!("{mount}/{rest}");
                    let d = data.lock().unwrap();
                    let (code, body) = match (s.method.as_str(), kind, query) {
                        ("GET", "metadata", "list=true") => {
                            let prefix = format!("{key}/");
                            let mut keys: Vec<String> = d
                                .keys()
                                .filter_map(|k| k.strip_prefix(&prefix))
                                .map(|r| match r.split_once('/') {
                                    Some((dir, _)) => format!("{dir}/"),
                                    None => r.to_string(),
                                })
                                .collect();
                            keys.dedup();
                            if keys.is_empty() {
                                (404, r#"{"errors":[]}"#.to_string())
                            } else {
                                (200, serde_json::json!({"data": {"keys": keys}}).to_string())
                            }
                        }
                        ("GET", "data", "") => match d.get(&key) {
                            Some(f) => (
                                200,
                                serde_json::json!({"data": {"data": f, "metadata": {"version": 1}}})
                                    .to_string(),
                            ),
                            None => (404, r#"{"errors":[]}"#.to_string()),
                        },
                        ("POST", "data", "") => {
                            drop(d);
                            let v: serde_json::Value = serde_json::from_str(&s.body).unwrap();
                            let fields: BTreeMap<String, String> = v["data"]
                                .as_object()
                                .unwrap()
                                .iter()
                                .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
                                .collect();
                            data.lock().unwrap().insert(key, fields);
                            (200, r#"{"data":{"version":2}}"#.to_string())
                        }
                        _ => (405, "{}".to_string()),
                    };
                    let _ = r.respond(Response::from_string(body).with_status_code(code));
                }
            });
            v
        }

        pub fn put(&self, key: &str, fields: &[(&str, &str)]) {
            self.data.lock().unwrap().insert(
                key.to_string(),
                fields
                    .iter()
                    .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                    .collect(),
            );
        }

        pub fn client(&self) -> super::Bao {
            super::Bao::for_test(
                &self.addr,
                Arc::new(|| Some(zeroize::Zeroizing::new(TOKEN.to_string()))),
            )
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const SENTINEL: &str = "SENTINEL-vault-value-abcdef0123";

    #[test]
    fn addresses_and_segments_are_plain_or_refused() {
        for a in [
            "https://vault.example.com",
            "https://vault.example.com:8200",
            "https://10.0.0.5:8200",
        ] {
            assert!(valid_addr(a), "{a}");
        }
        for a in [
            "http://vault.example.com",
            "https://",
            "https://vault.example.com/v1",
            "https://Vault.example.com",
            "https://vault.example.com:1",
            "https://vault.example.com:abc",
            "https://a@b.example.com",
            "https://-x.example.com",
        ] {
            assert!(!valid_addr(a), "{a}");
        }
        assert!(Bao::new("http://vault.example.com").is_none());
        assert!(plain_path("ozbox/dev/_escrow/dev-1"));
        for p in ["", "a//b", "a/../b", "/a", "a/", "a?b", "a b", "a%2fb", "."] {
            assert!(!plain_path(p), "{p}");
        }
    }

    #[test]
    fn requests_have_the_kv_version_2_shapes_and_carry_the_token_only_as_a_header() {
        let v = fakes::Vault::start();
        v.put("secret/ozbox/main/app/staging", &[("K", SENTINEL)]);
        let b = v.client();
        assert_eq!(b.list("secret", "ozbox/main").unwrap(), ["app/"]);
        let got = b.read("secret", "ozbox/main/app/staging").unwrap().unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!((got[0].0.as_str(), got[0].1.as_str()), ("K", SENTINEL));
        b.write("secret", "ozbox/_escrow/b1", &[("kek", SENTINEL)])
            .unwrap();
        let seen = v.seen.lock().unwrap();
        assert_eq!(
            seen.iter()
                .map(|s| format!("{} {}", s.method, s.url))
                .collect::<Vec<_>>(),
            [
                "GET /v1/secret/metadata/ozbox/main?list=true",
                "GET /v1/secret/data/ozbox/main/app/staging",
                "POST /v1/secret/data/ozbox/_escrow/b1",
            ]
        );
        for s in seen.iter() {
            assert_eq!(s.header("x-vault-token"), Some(fakes::TOKEN));
            assert!(!s.url.contains(fakes::TOKEN));
            assert!(!s.body.contains(fakes::TOKEN));
        }
        let post: serde_json::Value = serde_json::from_str(&seen[2].body).unwrap();
        assert_eq!(post, serde_json::json!({"data": {"kek": SENTINEL}}));
        assert_eq!(seen[2].header("content-type"), Some("application/json"));
    }

    #[test]
    fn nothing_there_is_empty_or_none_and_a_refusal_or_an_outage_is_an_error_with_nothing_in_it() {
        let v = fakes::Vault::start();
        let b = v.client();
        assert!(b.list("secret", "none").unwrap().is_empty());
        assert!(b.read("secret", "none/here").unwrap().is_none());
        // a wrong token is refused
        let wrong = Bao::for_test(
            &v.addr,
            Arc::new(|| Some(Zeroizing::new("s.other".to_string()))),
        );
        assert_eq!(wrong.list("secret", "x"), Err(Failure::Denied));
        // no token at all: nothing is sent
        let n = v.seen.lock().unwrap().len();
        let none = Bao::for_test(&v.addr, Arc::new(|| None));
        assert_eq!(none.read("secret", "x"), Err(Failure::Unavailable));
        assert_eq!(v.seen.lock().unwrap().len(), n);
        // a server error, and an answer that is not the vault's, that both quote the token and a value
        for (code, body) in [
            (500, format!("boom {} {SENTINEL}", fakes::TOKEN)),
            (200, format!(r#"{{"data":"{SENTINEL}"#)),
        ] {
            *v.force.lock().unwrap() = Some((code, body));
            let e = b.read("secret", "x").unwrap_err();
            assert_eq!(e, Failure::Unavailable);
            assert!(!format!("{e:?}").contains(SENTINEL));
        }
        // a path from a vault's answer that is not plain is never requested
        *v.force.lock().unwrap() = None;
        let n = v.seen.lock().unwrap().len();
        assert_eq!(b.read("secret", "a/../b"), Err(Failure::Unavailable));
        assert_eq!(b.list("sec ret", "a"), Err(Failure::Unavailable));
        assert_eq!(v.seen.lock().unwrap().len(), n);
        // the debug form names the address only
        assert!(!format!("{b:?}").contains(fakes::TOKEN));
    }

    #[test]
    fn the_token_is_read_at_each_request_never_kept() {
        let v = fakes::Vault::start();
        v.put("secret/a/b", &[("K", "v")]);
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c = calls.clone();
        let b = Bao::for_test(
            &v.addr,
            Arc::new(move || {
                c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Some(Zeroizing::new(fakes::TOKEN.to_string()))
            }),
        );
        b.read("secret", "a/b").unwrap();
        b.read("secret", "a/b").unwrap();
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[test]
    fn nothing_here_runs_a_program() {
        // a guard on the source: the defect this replaces was a program the image does not carry. Only the code before the
        // tests is read; the needles are built so this file passes.
        let src = include_str!("openbao.rs");
        let code = src.split("\n#[cfg(test)]").next().unwrap();
        for needle in [
            ["Command", "Spec"].concat(),
            ["Command", "::new("].concat(),
            ["\"b", "ao\""].concat(),
        ] {
            assert!(!code.contains(&needle), "{needle}");
        }
    }
}
