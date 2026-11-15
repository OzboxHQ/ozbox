//! The credential broker: how a run reaches a model provider without ever holding the provider's key.
//!
//! Agents are untrusted: anything the box user can read, an agent can read, and a run's environment is readable through
//! `/proc`. So a run is never given a long-lived vendor key. Instead it gets
//!
//! - a **per-run token** (`ozrt_...`): bound to one run and one provider, capped at what the run may still spend, and
//!   valid only until the run ends (the supervisor revokes it when the run stops, pauses or finishes) or six hours pass,
//!   whichever is first; and
//! - a **base URL** that points at this broker, a loopback listener (`http://127.0.0.1:<port>/<provider id>`).
//!
//! The engine talks to the broker as if it were the provider. The broker checks the token, reads the real key from the
//! [`SecretStore`] **at the moment of the request**, puts it in the one header that provider uses, and forwards the request
//! through the same address checks as every other outbound call (`netguard`). The key is held in a local variable for
//! that request, never stored, logged, returned or put in an error, and any echo of it in a provider's answer is removed
//! before the answer goes back to the run. Tokens are kept only as an HMAC under a key that lives in this process's
//! memory, so a stored token cannot be used and a token from another start of the server is worthless.
//!
//! The broker also sees every answer, so it is where **usage** is counted: input, output and cached tokens, parsed from
//! the provider's own reply (plain or streamed), with the model, against the run. The supervisor drains them with
//! [`Broker::drain_usage`]. It does not rely on what the engine says about itself.
//!
//! Limits of this first slice, stated plainly: the broker runs inside the process that holds the secret store (on a laptop
//! that is the OS keychain's owner, not an agent), replies are relayed whole rather than streamed token by token, and only
//! the providers that take an API key are brokered. Hosting the broker as its own system user on a box, so that even the
//! box user cannot reach its memory, is the next step; the identity for it is created by the image.

use std::collections::BTreeMap;
use std::io::Read;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ring::hmac;
use serde_json::{json, Value};

use crate::models::key_name;
use crate::netguard::{send_raw, HttpError, HttpRequest, RawResponse};
use crate::secrets::SecretStore;
use crate::settings::{ModelKind, ModelProvider, ModelsConfig};

/// The longest a token lives even if its run never ends cleanly.
pub const MAX_TOKEN_TTL_MS: u64 = 6 * 3600 * 1000;
const MAX_BODY: usize = 8 * 1024 * 1024;
const MAX_ANSWER: u64 = 32 * 1024 * 1024;

/// Sends one request on. The real one is `netguard`; tests use a fake that records what it was given.
pub trait Upstream: Send + Sync {
    fn forward(&self, req: &HttpRequest) -> Result<RawResponse, HttpError>;
}

pub struct NetUpstream;

impl Upstream for NetUpstream {
    fn forward(&self, req: &HttpRequest) -> Result<RawResponse, HttpError> {
        send_raw(req, MAX_ANSWER)
    }
}

/// What a run is handed instead of a key.
#[derive(Clone)]
pub struct IssuedToken {
    pub token: String,
    /// `http://127.0.0.1:<port>/<provider id>`: the run's base URL for this provider.
    pub base_url: String,
}

/// A token is worth one run: it prints as nothing.
impl std::fmt::Debug for IssuedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedToken")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

/// What the broker saw one call use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerUsage {
    pub run_id: String,
    pub provider_id: String,
    pub model: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cached_input_tokens: u64,
}

struct Grant {
    run_id: String,
    provider_id: String,
    expires_ms: u64,
    /// What the run may still spend through this token, in millionths of a dollar; none = no limit.
    cap_micros: Option<u64>,
    spent_micros: u64,
    /// A model answered in a form the broker could not count. A run with a spend limit stops there: its limit could no
    /// longer be kept.
    unmetered: bool,
}

#[derive(Default)]
struct State {
    grants: BTreeMap<String, Grant>,
    usage: Vec<BrokerUsage>,
    models: ModelsConfig,
}

pub struct Broker {
    port: u16,
    hmac: hmac::Key,
    state: Mutex<State>,
    secrets: Arc<dyn SecretStore>,
    upstream: Arc<dyn Upstream>,
    /// Set where the broker runs apart from whoever configures it (the box's secrets service): see [`Pins`].
    pins: Option<Pins>,
    /// Short-lived bearer tokens fetched for cloud-account providers (Azure Entra, Google), in memory only.
    tokens: crate::broker_cloud::TokenCache,
}

/// What the run side needs from a broker. Two things implement it: [`Broker`] itself, in the process that holds the
/// secret store (a laptop), and the client of the box's secrets service (`secrets_service::RemoteBroker`), where the
/// broker runs as another user and the key never comes within reach of the box user.
pub trait RunBroker: Send + Sync {
    fn port(&self) -> u16;
    fn set_models(&self, cfg: &ModelsConfig);
    fn issue(
        &self,
        run_id: &str,
        provider: &ModelProvider,
        cap_micros: Option<u64>,
        now_ms: u64,
    ) -> Result<IssuedToken, String>;
    fn revoke_run(&self, run_id: &str);
    fn drain_usage(&self, run_id: &str) -> Vec<BrokerUsage>;
}

impl RunBroker for Broker {
    fn port(&self) -> u16 {
        Broker::port(self)
    }
    fn set_models(&self, cfg: &ModelsConfig) {
        Broker::set_models(self, cfg);
    }
    fn issue(
        &self,
        run_id: &str,
        provider: &ModelProvider,
        cap_micros: Option<u64>,
        now_ms: u64,
    ) -> Result<IssuedToken, String> {
        Broker::issue(self, run_id, provider, cap_micros, now_ms)
    }
    fn revoke_run(&self, run_id: &str) {
        Broker::revoke_run(self, run_id);
    }
    fn drain_usage(&self, run_id: &str) -> Vec<BrokerUsage> {
        Broker::drain_usage(self, run_id)
    }
}

/// Where each key may be sent, remembered by whoever holds the key. The provider list is configuration the box user can
/// write, so a hostile process could rename a provider's address to its own host and have the broker attach the real key
/// there. A provider's endpoint is therefore pinned to the key it was first used with (the key's SHA-256, never the key):
/// the same key to a different address is refused, and saving a new key is the confirmation that the address may change.
pub struct Pins {
    path: Option<std::path::PathBuf>,
    map: Mutex<BTreeMap<String, (String, String)>>,
}

impl Pins {
    pub fn new(path: Option<std::path::PathBuf>) -> Pins {
        let map = path
            .as_deref()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|t| serde_json::from_str::<BTreeMap<String, (String, String)>>(&t).ok())
            .unwrap_or_default();
        Pins {
            path,
            map: Mutex::new(map),
        }
    }

    fn check(&self, id: &str, endpoint: &str, key: &str) -> Result<(), String> {
        let fp = hex(ring::digest::digest(&ring::digest::SHA256, key.as_bytes()).as_ref());
        let mut m = lock(&self.map);
        match m.get(id) {
            Some((e, f)) if *f == fp && e != endpoint => Err(
                "this provider's address changed since its key was saved; save the key again to confirm the new address"
                    .into(),
            ),
            Some((e, f)) if *f == fp && e == endpoint => Ok(()),
            _ => {
                m.insert(id.to_string(), (endpoint.to_string(), fp));
                if let Some(path) = &self.path {
                    if let Ok(text) = serde_json::to_string(&*m) {
                        let tmp = path.with_extension("tmp");
                        if std::fs::write(&tmp, text).is_ok() {
                            #[cfg(unix)]
                            {
                                use std::os::unix::fs::PermissionsExt;
                                let _ = std::fs::set_permissions(
                                    &tmp,
                                    std::fs::Permissions::from_mode(0o600),
                                );
                            }
                            let _ = std::fs::rename(&tmp, path);
                        }
                    }
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProxyRequest {
    pub method: String,
    /// Path and query, as received.
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ProxyResponse {
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
}

fn error(status: u16, message: &str) -> ProxyResponse {
    ProxyResponse {
        status,
        content_type: "application/json".into(),
        body: json!({ "error": { "type": "ozbox_broker", "message": message } })
            .to_string()
            .into_bytes(),
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Where a provider's API lives (no trailing slash). `None` for the kinds that do not take an API key.
pub fn upstream_base(p: &ModelProvider) -> Option<String> {
    Some(match p.kind {
        ModelKind::Anthropic => "https://api.anthropic.com".into(),
        ModelKind::Openai => "https://api.openai.com".into(),
        ModelKind::Google => "https://generativelanguage.googleapis.com".into(),
        ModelKind::Openrouter => "https://openrouter.ai/api".into(),
        ModelKind::Mistral => "https://api.mistral.ai".into(),
        ModelKind::Groq => "https://api.groq.com/openai".into(),
        ModelKind::Together => "https://api.together.xyz".into(),
        ModelKind::OpenaiCompatible => p.base_url.as_deref()?.trim_end_matches('/').to_string(),
        // the person's own cloud account: the address comes from fields validated when the provider was saved
        ModelKind::Bedrock => format!(
            "https://bedrock-runtime.{}.amazonaws.com",
            crate::model_providers::valid_region(p.region.as_deref()?)?
        ),
        ModelKind::AzureOpenai => format!(
            "https://{}.openai.azure.com",
            crate::model_providers::valid_resource(p.resource.as_deref()?)?
        ),
        ModelKind::Vertex => "https://aiplatform.googleapis.com".into(),
    })
}

/// Whether runs can reach this provider through the broker.
pub fn brokerable(p: &ModelProvider) -> bool {
    upstream_base(p).is_some()
}

fn header<'a>(h: &'a [(String, String)], name: &str) -> Option<&'a str> {
    h.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// The run token a request carries, from whichever header the engine's SDK uses.
fn presented_token(h: &[(String, String)]) -> Option<&str> {
    header(h, "x-api-key")
        .or_else(|| header(h, "x-goog-api-key"))
        .or_else(|| header(h, "api-key"))
        .or_else(|| {
            header(h, "authorization").and_then(|v| {
                v.strip_prefix("Bearer ")
                    .or_else(|| v.strip_prefix("bearer "))
            })
        })
        .map(str::trim)
        .filter(|t| !t.is_empty())
}

/// Headers the broker never passes on: the run's own credentials (it adds the real one), and hop-by-hop ones.
fn dropped(name: &str) -> bool {
    name.to_ascii_lowercase().starts_with("x-amz-")
        || [
            "authorization",
            "x-api-key",
            "x-goog-api-key",
            "api-key",
            "host",
            "content-length",
            "connection",
            "accept-encoding",
            "transfer-encoding",
            "proxy-authorization",
            "cookie",
        ]
        .iter()
        .any(|d| name.eq_ignore_ascii_case(d))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Tokens counted from one reply (or the pieces of a streamed one).
#[derive(Default, Debug, PartialEq, Eq)]
struct Seen {
    model: Option<String>,
    input: u64,
    output: u64,
    cached: u64,
    any: bool,
}

impl Seen {
    fn merge(&mut self, o: Seen) {
        if !o.any {
            return;
        }
        self.any = true;
        self.input = self.input.max(o.input);
        self.output = self.output.max(o.output);
        self.cached = self.cached.max(o.cached);
        if o.model.is_some() {
            self.model = o.model;
        }
    }
}

fn n(v: &Value, ptr: &str) -> Option<u64> {
    v.pointer(ptr).and_then(Value::as_u64)
}

/// The usage in one JSON value, in whichever provider shape it has.
fn seen_in(v: &Value) -> Seen {
    let model = v
        .get("model")
        .or_else(|| v.pointer("/message/model"))
        .or_else(|| v.get("modelVersion"))
        .and_then(Value::as_str)
        .map(|m| m.chars().take(100).collect());
    // Anthropic: input_tokens + cache creation, cache reads counted apart
    for base in ["/usage", "/message/usage"] {
        if let Some(u) = v.pointer(base) {
            if u.get("input_tokens").is_some() || u.get("output_tokens").is_some() {
                let input = n(v, &format!("{base}/input_tokens")).unwrap_or(0)
                    + n(v, &format!("{base}/cache_creation_input_tokens")).unwrap_or(0);
                return Seen {
                    model,
                    input,
                    output: n(v, &format!("{base}/output_tokens")).unwrap_or(0),
                    cached: n(v, &format!("{base}/cache_read_input_tokens")).unwrap_or(0),
                    any: true,
                };
            }
            // OpenAI shape: the prompt count includes the cached part
            if u.get("prompt_tokens").is_some() || u.get("completion_tokens").is_some() {
                let prompt = n(v, &format!("{base}/prompt_tokens")).unwrap_or(0);
                let cached =
                    n(v, &format!("{base}/prompt_tokens_details/cached_tokens")).unwrap_or(0);
                return Seen {
                    model,
                    input: prompt.saturating_sub(cached),
                    output: n(v, &format!("{base}/completion_tokens")).unwrap_or(0),
                    cached,
                    any: true,
                };
            }
        }
    }
    if let Some(u) = v.get("usageMetadata") {
        let prompt = u
            .get("promptTokenCount")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let cached = u
            .get("cachedContentTokenCount")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        return Seen {
            model,
            input: prompt.saturating_sub(cached),
            output: u
                .get("candidatesTokenCount")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            cached,
            any: true,
        };
    }
    Seen::default()
}

/// The usage in a whole answer: one JSON document, or a server-sent-events stream of them.
fn parse_usage(body: &[u8]) -> Seen {
    let Ok(text) = std::str::from_utf8(body) else {
        return event_stream_usage(body);
    };
    if let Ok(v) = serde_json::from_str::<Value>(text) {
        return seen_in(&v);
    }
    let mut all = Seen::default();
    for line in text.lines() {
        if let Some(data) = line.strip_prefix("data:") {
            if let Ok(v) = serde_json::from_str::<Value>(data.trim()) {
                all.merge(seen_in(&v));
            }
        }
    }
    if all.any {
        all
    } else {
        event_stream_usage(body)
    }
}

/// Bedrock's streamed answers are AWS event-stream frames, binary, each holding `{"bytes":"<base64 of a JSON chunk>"}`;
/// the chunks are the model's own stream (Anthropic's message events carry the usage).
fn event_stream_usage(body: &[u8]) -> Seen {
    const NEEDLE: &[u8] = b"{\"bytes\":\"";
    let mut all = Seen::default();
    let mut i = 0;
    while let Some(at) = body[i..].windows(NEEDLE.len()).position(|w| w == NEEDLE) {
        let start = i + at + NEEDLE.len();
        let Some(len) = body[start..].iter().position(|b| *b == b'"') else {
            break;
        };
        if let Some(chunk) = std::str::from_utf8(&body[start..start + len])
            .ok()
            .and_then(crate::serve::auth::b64::decode_std)
        {
            if let Ok(v) = serde_json::from_slice::<Value>(&chunk) {
                all.merge(seen_in(&v));
            }
        }
        i = start + len;
    }
    all
}

impl Broker {
    /// The loopback port the broker listens on (for the reverse forward that lets a box reach it).
    pub fn port(&self) -> u16 {
        self.port
    }

    /// A broker that is not listening: tests and [`Broker::start`] build on it.
    pub fn new(secrets: Arc<dyn SecretStore>, upstream: Arc<dyn Upstream>, port: u16) -> Broker {
        let mut k = [0u8; 32];
        // No secure random source means no broker: tokens would be guessable.
        let ok = getrandom::getrandom(&mut k).is_ok();
        let b = Broker {
            port,
            hmac: hmac::Key::new(hmac::HMAC_SHA256, &k),
            state: Mutex::new(State::default()),
            secrets,
            upstream,
            pins: None,
            tokens: crate::broker_cloud::TokenCache::default(),
        };
        if !ok {
            lock(&b.state).grants.clear();
        }
        b
    }

    /// Whether `p`'s key may be sent to the address `p` names now (see [`Pins`]). Always yes where there are no pins.
    pub fn endpoint_ok(&self, p: &ModelProvider) -> Result<(), String> {
        let (Some(pins), Some(base)) = (&self.pins, upstream_base(p)) else {
            return Ok(());
        };
        let Ok(Some(key)) = self.secrets.get(&key_name(&p.id)) else {
            return Ok(()); // no key, nothing to protect
        };
        pins.check(&p.id, &format!("{:?}|{base}", p.kind), &key)
    }

    /// Start listening on a loopback port chosen by the system and answer requests on a background thread.
    pub fn start(
        secrets: Arc<dyn SecretStore>,
        upstream: Arc<dyn Upstream>,
    ) -> Result<Arc<Broker>, String> {
        Broker::start_with(secrets, upstream, None)
    }

    /// [`Broker::start`], remembering where each key may go in `pins_path` (the secrets service does this).
    pub fn start_with(
        secrets: Arc<dyn SecretStore>,
        upstream: Arc<dyn Upstream>,
        pins_path: Option<std::path::PathBuf>,
    ) -> Result<Arc<Broker>, String> {
        let server = tiny_http::Server::http("127.0.0.1:0")
            .map_err(|_| "the credential broker could not listen on this computer".to_string())?;
        let port = server
            .server_addr()
            .to_ip()
            .map(|a| a.port())
            .ok_or_else(|| "the credential broker has no address".to_string())?;
        let mut inner = Broker::new(secrets, upstream, port);
        if pins_path.is_some() {
            inner.pins = Some(Pins::new(pins_path));
        }
        let broker = Arc::new(inner);
        let b = Arc::clone(&broker);
        std::thread::spawn(move || {
            for mut rq in server.incoming_requests() {
                let b = Arc::clone(&b);
                std::thread::spawn(move || {
                    let mut body = Vec::new();
                    let _ = rq
                        .as_reader()
                        .take(MAX_BODY as u64 + 1)
                        .read_to_end(&mut body);
                    let headers = rq
                        .headers()
                        .iter()
                        .map(|h| (h.field.to_string(), h.value.to_string()))
                        .collect();
                    let req = ProxyRequest {
                        method: rq.method().to_string(),
                        path: rq.url().to_string(),
                        headers,
                        body,
                    };
                    let r = b.handle(&req, crate::serve::unix_ms());
                    let mut resp =
                        tiny_http::Response::from_data(r.body).with_status_code(r.status);
                    if let Ok(h) = tiny_http::Header::from_bytes(
                        &b"Content-Type"[..],
                        r.content_type.as_bytes(),
                    ) {
                        resp = resp.with_header(h);
                    }
                    let _ = rq.respond(resp);
                });
            }
        });
        Ok(broker)
    }

    /// The store the broker reads keys from.
    pub fn secrets(&self) -> Arc<dyn SecretStore> {
        Arc::clone(&self.secrets)
    }

    /// Add `p` to the providers the broker serves, or replace the one with its id.
    pub fn upsert_provider(&self, p: &ModelProvider) {
        let mut st = lock(&self.state);
        match st.models.providers.iter_mut().find(|q| q.id == p.id) {
            Some(q) => *q = p.clone(),
            None => st.models.providers.push(p.clone()),
        }
    }

    /// The provider list the broker may serve (refreshed by whoever owns the settings).
    pub fn set_models(&self, cfg: &ModelsConfig) {
        lock(&self.state).models = cfg.clone();
    }

    /// A token for one run and one provider. `cap_micros` is what the run may still spend; the token lapses with the run
    /// (see [`Broker::revoke_run`]) or after [`MAX_TOKEN_TTL_MS`].
    pub fn issue(
        &self,
        run_id: &str,
        provider: &ModelProvider,
        cap_micros: Option<u64>,
        now_ms: u64,
    ) -> Result<IssuedToken, String> {
        if !brokerable(provider) {
            return Err(format!(
                "{} cannot be used by runs yet: runs reach providers through the credential broker, which does not support this type",
                provider.label
            ));
        }
        self.endpoint_ok(provider)?;
        let mut raw = [0u8; 32];
        getrandom::getrandom(&mut raw)
            .map_err(|_| "no secure random source for a run token".to_string())?;
        let token = format!("ozrt_{}", hex(&raw));
        let id = hex(hmac::sign(&self.hmac, token.as_bytes()).as_ref());
        let mut st = lock(&self.state);
        st.grants.retain(|_, g| g.expires_ms > now_ms);
        st.grants.insert(
            id,
            Grant {
                run_id: run_id.to_string(),
                provider_id: provider.id.clone(),
                expires_ms: now_ms + MAX_TOKEN_TTL_MS,
                cap_micros,
                spent_micros: 0,
                unmetered: false,
            },
        );
        Ok(IssuedToken {
            token,
            base_url: format!("http://127.0.0.1:{}/{}", self.port, provider.id),
        })
    }

    /// The run ended (finished, paused, stopped or failed): every token it held stops working now.
    pub fn revoke_run(&self, run_id: &str) {
        lock(&self.state).grants.retain(|_, g| g.run_id != run_id);
    }

    /// What the broker saw this run use since the last call.
    pub fn drain_usage(&self, run_id: &str) -> Vec<BrokerUsage> {
        let mut st = lock(&self.state);
        let (mine, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut st.usage)
            .into_iter()
            .partition(|u| u.run_id == run_id);
        st.usage = rest;
        mine
    }

    #[cfg(test)]
    pub fn holds_token_for(&self, run_id: &str) -> bool {
        lock(&self.state)
            .grants
            .values()
            .any(|g| g.run_id == run_id)
    }

    /// Answer one request from a run.
    pub fn handle(&self, req: &ProxyRequest, now_ms: u64) -> ProxyResponse {
        if req.body.len() > MAX_BODY {
            return error(413, "that request is too large");
        }
        let Some(token) = presented_token(&req.headers) else {
            return error(401, "no run token was sent");
        };
        let id = hex(hmac::sign(&self.hmac, token.as_bytes()).as_ref());
        // path: /<provider id>/<rest>
        let path = req.path.strip_prefix('/').unwrap_or(&req.path);
        let (pid, rest) = match path.split_once('/') {
            Some((p, r)) => (p, format!("/{r}")),
            None => (path, "/".to_string()),
        };
        if rest.contains("..") || rest.bytes().any(|b| b.is_ascii_control() || b == b' ') {
            return error(400, "that path is not allowed");
        }
        // check the grant and take what the request needs, then release the lock for the network call
        let (provider, run_id, over) = {
            let st = lock(&self.state);
            let Some(g) = st.grants.get(&id).filter(|g| g.expires_ms > now_ms) else {
                return error(
                    401,
                    "this run token is not valid; it may belong to a run that has ended",
                );
            };
            if g.provider_id != pid {
                return error(403, "this run token is not for that provider");
            }
            let Some(p) = st.models.providers.iter().find(|p| p.id == pid).cloned() else {
                return error(404, "that provider is no longer set up");
            };
            let over = g.cap_micros.is_some_and(|c| g.spent_micros >= c);
            let blind = g.cap_micros.is_some() && g.unmetered;
            (p, g.run_id.clone(), (over, blind))
        };
        if over.0 {
            return error(402, "this run has reached its spend limit");
        }
        if over.1 {
            return error(
                402,
                "this run has a spend limit, and its provider answered in a form the broker cannot count, so it stops here",
            );
        }
        // Only a model's answers and its model list: never the rest of what the account's credential can do.
        let endpoint = match crate::broker_paths::allowed(provider.kind, &req.method, &rest) {
            Ok(k) => k,
            Err(e) => return error(403, e),
        };
        let Some(base) = upstream_base(&provider) else {
            return error(404, "that provider cannot be used through the broker");
        };
        if let Err(e) = self.endpoint_ok(&provider) {
            return error(403, &e);
        }
        // the real key: read now, used for this request, never kept
        let key = match self.secrets.get(&key_name(&provider.id)) {
            Ok(Some(k)) => k,
            Ok(None) if crate::model_providers::key_optional(&provider) => String::new(),
            _ => return error(502, "the provider's key is not available"),
        };
        // a cloud account's credentials may be structured (see `broker_cloud`); the key stays in this function
        let cred = if crate::model_providers::own_cloud(provider.kind) && !key.is_empty() {
            match crate::broker_cloud::parse(provider.kind, &key) {
                Ok(c) => c,
                Err(e) => return error(502, &e),
            }
        } else {
            crate::broker_cloud::Cred::Plain(key.clone())
        };
        let (base, rest) = if provider.kind == ModelKind::Vertex {
            let rest = crate::broker_cloud::vertex_project_path(&rest, cred.project());
            // the account's own project went in: the path must still be one the broker relays
            if crate::broker_paths::allowed(provider.kind, &req.method, &rest).is_err() {
                return error(403, "the broker relays a model's answers and its model list only, not that endpoint");
            }
            (crate::broker_cloud::vertex_base(&rest), rest)
        } else {
            (base, rest)
        };
        let mut up = HttpRequest::new(
            match req.method.as_str() {
                "GET" => "GET",
                "POST" => "POST",
                _ => return error(405, "only GET and POST are relayed"),
            },
            format!("{base}{rest}"),
            crate::model_providers::guard(&provider),
        );
        up.timeout = Duration::from_secs(600);
        for (k, v) in &req.headers {
            if !dropped(k) {
                up.headers.push((k.clone(), v.clone()));
            }
        }
        // the body is set first: a signature covers it
        if !req.body.is_empty() {
            up.body = Some(req.body.clone());
        }
        if !key.is_empty() {
            let ctx = crate::broker_cloud::Ctx {
                kind: provider.kind,
                provider_id: &provider.id,
                region: provider.region.as_deref(),
                now_ms,
            };
            let fetch = |r: &HttpRequest| {
                self.upstream
                    .forward(r)
                    .map(|a| (a.status, a.body))
                    .map_err(|e| e.to_string())
            };
            if let Err(e) =
                crate::broker_cloud::authorize(&mut up, &ctx, &cred, &self.tokens, &fetch)
            {
                return error(502, &e);
            }
        }
        let asked_model = serde_json::from_slice::<Value>(&req.body)
            .ok()
            .and_then(|v| v.get("model").and_then(Value::as_str).map(str::to_string));
        let answer = self.upstream.forward(&up);
        drop(up);
        let r = match answer {
            Ok(r) => r,
            Err(e) => return error(502, &e.to_string()),
        };
        // an echo of the key in the provider's answer is removed before the run sees it
        let mut body = r.body;
        let mut known = cred.secrets();
        known.extend(crate::broker_cloud::cached_tokens(&self.tokens));
        for k in known.iter().filter(|k| k.len() >= 8) {
            body = scrub(body, k.as_bytes());
        }
        if (200..300).contains(&r.status) {
            let seen = parse_usage(&body);
            if seen.any {
                self.count(&id, &run_id, &provider, asked_model, seen);
            } else if endpoint == crate::broker_paths::Kind::Generation {
                if let Some(g) = lock(&self.state).grants.get_mut(&id) {
                    g.unmetered = true;
                }
            }
        }
        ProxyResponse {
            status: r.status,
            content_type: r.content_type.unwrap_or_else(|| "application/json".into()),
            body,
        }
    }

    fn count(&self, id: &str, run_id: &str, p: &ModelProvider, asked: Option<String>, seen: Seen) {
        let model = seen
            .model
            .or(asked)
            .unwrap_or_else(|| "unknown".to_string());
        let usage = BrokerUsage {
            run_id: run_id.to_string(),
            provider_id: p.id.clone(),
            model,
            input_tokens: seen.input,
            output_tokens: seen.output,
            cached_input_tokens: seen.cached,
        };
        let mut st = lock(&self.state);
        let micros = crate::model_usage::cost_of(
            &st.models,
            &ozbox_core::ModelUsage {
                ts_ms: 1,
                box_name: None,
                engine: None,
                provider_id: usage.provider_id.clone(),
                model: usage.model.clone(),
                input_tokens: usage.input_tokens,
                output_tokens: usage.output_tokens,
                cached_input_tokens: usage.cached_input_tokens,
            },
        )
        .map(|usd| (usd * 1_000_000.0).round() as u64)
        .unwrap_or(0);
        if let Some(g) = st.grants.get_mut(id) {
            g.spent_micros += micros;
        }
        st.usage.push(usage);
    }
}

fn scrub(body: Vec<u8>, key: &[u8]) -> Vec<u8> {
    if key.is_empty() || body.len() < key.len() {
        return body;
    }
    let mut out = Vec::with_capacity(body.len());
    let mut i = 0;
    while i < body.len() {
        if body[i..].starts_with(key) {
            out.extend_from_slice(b"[key]");
            i += key.len();
        } else {
            out.push(body[i]);
            i += 1;
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) mod tests {
    use super::*;
    use crate::secrets::MemorySecrets;
    use std::collections::VecDeque;

    const KEY: &str = "sk-SENTINEL-broker-0123456789";
    const NOW: u64 = 1_800_000_000_000;

    #[derive(Default)]
    pub struct FakeUpstream {
        pub sent: Mutex<Vec<HttpRequest>>,
        pub replies: Mutex<VecDeque<Result<RawResponse, HttpError>>>,
    }

    impl FakeUpstream {
        pub fn reply(&self, status: u16, ct: &str, body: &str) {
            lock(&self.replies).push_back(Ok(RawResponse {
                status,
                body: body.as_bytes().to_vec(),
                content_type: Some(ct.into()),
            }));
        }
    }

    impl Upstream for FakeUpstream {
        fn forward(&self, req: &HttpRequest) -> Result<RawResponse, HttpError> {
            lock(&self.sent).push(req.clone());
            lock(&self.replies)
                .pop_front()
                .unwrap_or(Err(HttpError::Transport("no scripted reply")))
        }
    }

    fn provider(id: &str, kind: ModelKind) -> ModelProvider {
        ModelProvider {
            id: id.into(),
            kind,
            label: id.into(),
            base_url: None,
            local_endpoint: false,
            monthly_cap_usd: None,
            region: None,
            resource: None,
            hosted_on: None,
        }
    }

    fn rig() -> (Arc<Broker>, Arc<FakeUpstream>) {
        let secrets = Arc::new(MemorySecrets::default());
        secrets.set("model-key-anth", KEY).unwrap();
        secrets.set("model-key-oa", KEY).unwrap();
        let up = Arc::new(FakeUpstream::default());
        let b = Arc::new(Broker::new(secrets, up.clone(), 4242));
        let cfg = ModelsConfig {
            providers: vec![
                provider("anth", ModelKind::Anthropic),
                provider("oa", ModelKind::Openai),
                provider("br", ModelKind::Bedrock),
            ],
            ..Default::default()
        };
        b.set_models(&cfg);
        (b, up)
    }

    fn call(
        b: &Broker,
        path: &str,
        token: &str,
        header: &str,
        body: &str,
        now: u64,
    ) -> ProxyResponse {
        let value = if header == "authorization" {
            format!("Bearer {token}")
        } else {
            token.to_string()
        };
        b.handle(
            &ProxyRequest {
                method: "POST".into(),
                path: path.into(),
                headers: vec![
                    (header.into(), value),
                    ("anthropic-version".into(), "2023-06-01".into()),
                    ("Content-Type".into(), "application/json".into()),
                ],
                body: body.as_bytes().to_vec(),
            },
            now,
        )
    }

    const ANSWER: &str = r#"{"model":"claude-sonnet-4-5","content":[],"usage":{"input_tokens":120,"output_tokens":30,"cache_read_input_tokens":50}}"#;

    #[test]
    fn the_real_key_is_added_for_the_provider_and_the_run_only_ever_holds_the_token() {
        let (b, up) = rig();
        let t = b
            .issue("t1", &provider("anth", ModelKind::Anthropic), None, NOW)
            .unwrap();
        assert!(t.token.starts_with("ozrt_") && !t.token.contains("SENTINEL"));
        assert_eq!(t.base_url, "http://127.0.0.1:4242/anth");
        up.reply(200, "application/json", ANSWER);
        let r = call(
            &b,
            "/anth/v1/messages",
            &t.token,
            "x-api-key",
            r#"{"model":"claude-sonnet-4-5"}"#,
            NOW,
        );
        assert_eq!(r.status, 200);
        let sent = lock(&up.sent).clone();
        assert_eq!(sent[0].url, "https://api.anthropic.com/v1/messages");
        let hdr = |k: &str| {
            sent[0]
                .headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(k))
                .map(|(_, v)| v.clone())
        };
        assert_eq!(
            hdr("x-api-key").as_deref(),
            Some(KEY),
            "the real key goes upstream"
        );
        assert_eq!(hdr("anthropic-version").as_deref(), Some("2023-06-01"));
        assert!(
            sent[0].headers.iter().all(|(_, v)| !v.contains("ozrt_")),
            "the run's token is not passed on"
        );
        // the key is in nothing the run can see: not the answer, not the issued values, not a debug print
        assert!(!String::from_utf8_lossy(&r.body).contains("SENTINEL"));
        assert!(!format!("{t:?}").contains(&t.token));
    }

    /// A run's token buys a model's answers, never the rest of what the provider's credential can do: refused before the
    /// key is read or anything is sent.
    #[test]
    fn a_path_that_is_not_inference_is_refused_and_nothing_goes_upstream() {
        let (b, up) = rig();
        let t = b
            .issue("t1", &provider("oa", ModelKind::Openai), None, NOW)
            .unwrap();
        for path in [
            "/oa/v1/files",
            "/oa/v1/fine_tuning/jobs",
            "/oa/v1/chat/completions?x=1",
        ] {
            let r = call(&b, path, &t.token, "authorization", "{}", NOW);
            assert_eq!(r.status, 403, "{path}");
        }
        assert!(lock(&up.sent).is_empty());
    }

    /// A run with a spend limit stops once its provider answers in a form the broker cannot count; a limit that cannot be
    /// kept is not offered. Bedrock's binary event stream is counted.
    #[test]
    fn a_capped_run_stops_at_an_answer_the_broker_cannot_count_and_a_bedrock_stream_is_counted() {
        let (b, up) = rig();
        let t = b
            .issue(
                "t1",
                &provider("anth", ModelKind::Anthropic),
                Some(5_000_000),
                NOW,
            )
            .unwrap();
        up.reply(200, "application/json", r#"{"content":[]}"#);
        assert_eq!(
            call(&b, "/anth/v1/messages", &t.token, "x-api-key", "{}", NOW).status,
            200
        );
        up.reply(200, "application/json", ANSWER);
        let r = call(&b, "/anth/v1/messages", &t.token, "x-api-key", "{}", NOW);
        assert_eq!(r.status, 402);
        assert!(String::from_utf8_lossy(&r.body).contains("cannot count"));
        // the event stream: a binary prelude, then the chunk as base64 JSON
        let chunk = crate::serve::auth::b64::encode_std(
            br#"{"type":"message_delta","usage":{"output_tokens":7,"input_tokens":3}}"#,
        );
        let mut body = vec![0u8, 0, 0, 0x5a, 0xff, 0xfe];
        body.extend_from_slice(format!(r#"{{"bytes":"{chunk}","p":"abc"}}"#).as_bytes());
        body.extend_from_slice(&[0x9c, 0x01]);
        let seen = parse_usage(&body);
        assert!(seen.any && seen.output == 7 && seen.input == 3);
    }

    #[test]
    fn an_echo_of_the_key_in_a_provider_error_is_removed() {
        let (b, up) = rig();
        let t = b
            .issue("t1", &provider("oa", ModelKind::Openai), None, NOW)
            .unwrap();
        up.reply(
            401,
            "application/json",
            &format!(r#"{{"error":"bad key {KEY} given"}}"#),
        );
        let r = call(
            &b,
            "/oa/v1/chat/completions",
            &t.token,
            "authorization",
            "{}",
            NOW,
        );
        assert_eq!(r.status, 401);
        let text = String::from_utf8(r.body).unwrap();
        assert!(
            !text.contains("SENTINEL") && text.contains("[key]"),
            "{text}"
        );
        let sent = lock(&up.sent).clone();
        let auth = sent[0]
            .headers
            .iter()
            .find(|(n, _)| n == "Authorization")
            .unwrap();
        assert_eq!(auth.1, format!("Bearer {KEY}"));
    }

    #[test]
    fn a_token_is_for_one_provider_and_a_bad_or_missing_one_is_refused() {
        let (b, up) = rig();
        let t = b
            .issue("t1", &provider("anth", ModelKind::Anthropic), None, NOW)
            .unwrap();
        assert_eq!(
            call(&b, "/oa/v1/models", &t.token, "x-api-key", "{}", NOW).status,
            403
        );
        assert_eq!(
            call(&b, "/anth/v1/messages", "ozrt_nope", "x-api-key", "{}", NOW).status,
            401
        );
        let none = b.handle(
            &ProxyRequest {
                method: "POST".into(),
                path: "/anth/v1/messages".into(),
                headers: vec![],
                body: vec![],
            },
            NOW,
        );
        assert_eq!(none.status, 401);
        assert_eq!(
            call(&b, "/anth/v1/../../x", &t.token, "x-api-key", "{}", NOW).status,
            400
        );
        assert!(lock(&up.sent).is_empty(), "nothing reached the provider");
    }

    #[test]
    fn a_run_token_stops_working_when_the_run_ends_and_after_its_lifetime() {
        let (b, up) = rig();
        let p = provider("anth", ModelKind::Anthropic);
        let t = b.issue("t1", &p, None, NOW).unwrap();
        up.reply(200, "application/json", ANSWER);
        assert_eq!(
            call(&b, "/anth/v1/messages", &t.token, "x-api-key", "{}", NOW).status,
            200
        );
        assert!(b.holds_token_for("t1"));
        b.revoke_run("t1");
        assert!(!b.holds_token_for("t1"));
        assert_eq!(
            call(
                &b,
                "/anth/v1/messages",
                &t.token,
                "x-api-key",
                "{}",
                NOW + 1
            )
            .status,
            401
        );
        // a token that was never revoked still lapses
        let t2 = b.issue("t2", &p, None, NOW).unwrap();
        assert_eq!(
            call(
                &b,
                "/anth/v1/messages",
                &t2.token,
                "x-api-key",
                "{}",
                NOW + MAX_TOKEN_TTL_MS + 1
            )
            .status,
            401
        );
        // and another run's revocation does not touch it
        let t3 = b.issue("t3", &p, None, NOW).unwrap();
        b.revoke_run("t2");
        up.reply(200, "application/json", ANSWER);
        assert_eq!(
            call(&b, "/anth/v1/messages", &t3.token, "x-api-key", "{}", NOW).status,
            200
        );
    }

    #[test]
    fn usage_is_counted_from_the_answer_and_the_spend_cap_stops_the_run_token() {
        let (b, up) = rig();
        let cfg = ModelsConfig {
            providers: vec![provider("oa", ModelKind::Openai)],
            ..Default::default()
        };
        b.set_models(&cfg);
        // $0.0025 allowed: one call of 1M input tokens at gpt-4o prices ($2.50) is far over it
        let t = b
            .issue("t1", &provider("oa", ModelKind::Openai), Some(2_500), NOW)
            .unwrap();
        up.reply(
            200,
            "application/json",
            r#"{"model":"gpt-4o","usage":{"prompt_tokens":1000000,"completion_tokens":0,"prompt_tokens_details":{"cached_tokens":200000}}}"#,
        );
        assert_eq!(
            call(
                &b,
                "/oa/v1/chat/completions",
                &t.token,
                "authorization",
                "{}",
                NOW
            )
            .status,
            200
        );
        let u = b.drain_usage("t1");
        assert_eq!(u.len(), 1);
        assert_eq!(
            (
                u[0].provider_id.as_str(),
                u[0].model.as_str(),
                u[0].input_tokens,
                u[0].output_tokens,
                u[0].cached_input_tokens
            ),
            ("oa", "gpt-4o", 800_000, 0, 200_000)
        );
        assert!(b.drain_usage("t1").is_empty(), "drained once");
        let r = call(
            &b,
            "/oa/v1/chat/completions",
            &t.token,
            "authorization",
            "{}",
            NOW,
        );
        assert_eq!(
            r.status, 402,
            "over its cap, no second call reaches the provider"
        );
        assert_eq!(lock(&up.sent).len(), 1);
    }

    #[test]
    fn streamed_answers_are_counted_in_each_providers_shape() {
        let anthropic = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-opus-4\",\"usage\":{\"input_tokens\":25,\"output_tokens\":1}}}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":77}}\n\n";
        let s = parse_usage(anthropic.as_bytes());
        assert_eq!(
            (s.input, s.output, s.model.as_deref()),
            (25, 77, Some("claude-opus-4"))
        );
        let google = "data: {\"candidates\":[],\"usageMetadata\":{\"promptTokenCount\":10,\"candidatesTokenCount\":2}}\n\ndata: {\"usageMetadata\":{\"promptTokenCount\":10,\"candidatesTokenCount\":9},\"modelVersion\":\"gemini-2.5-flash\"}\n\n";
        let s = parse_usage(google.as_bytes());
        assert_eq!(
            (s.input, s.output, s.model.as_deref()),
            (10, 9, Some("gemini-2.5-flash"))
        );
        assert!(!parse_usage(b"not json at all").any);
    }

    #[test]
    fn providers_that_take_no_api_key_are_not_brokered_and_say_why() {
        let (b, _) = rig();
        let e = b
            .issue("t1", &provider("br", ModelKind::Bedrock), None, NOW)
            .unwrap_err();
        assert!(e.contains("credential broker"), "{e}");
    }

    #[test]
    fn a_missing_provider_key_is_a_clean_error_that_names_no_value() {
        let secrets = Arc::new(MemorySecrets::default());
        let up = Arc::new(FakeUpstream::default());
        let b = Broker::new(secrets, up.clone(), 1);
        let cfg = ModelsConfig {
            providers: vec![provider("anth", ModelKind::Anthropic)],
            ..Default::default()
        };
        b.set_models(&cfg);
        let t = b
            .issue("t1", &provider("anth", ModelKind::Anthropic), None, NOW)
            .unwrap();
        let r = call(&b, "/anth/v1/messages", &t.token, "x-api-key", "{}", NOW);
        assert_eq!(r.status, 502);
        assert!(lock(&up.sent).is_empty());
    }

    #[test]
    fn it_answers_over_a_real_loopback_socket() {
        let secrets = Arc::new(MemorySecrets::default());
        secrets.set("model-key-anth", KEY).unwrap();
        let up = Arc::new(FakeUpstream::default());
        let b = Broker::start(secrets, up.clone()).unwrap();
        let cfg = ModelsConfig {
            providers: vec![provider("anth", ModelKind::Anthropic)],
            ..Default::default()
        };
        b.set_models(&cfg);
        let t = b
            .issue(
                "t1",
                &provider("anth", ModelKind::Anthropic),
                None,
                crate::serve::unix_ms(),
            )
            .unwrap();
        up.reply(200, "application/json", ANSWER);
        let agent = ureq::AgentBuilder::new().build();
        let resp = agent
            .post(&format!("{}/v1/messages", t.base_url))
            .set("x-api-key", &t.token)
            .send_string(r#"{"model":"m"}"#)
            .unwrap();
        assert_eq!(resp.status(), 200);
        let text = resp.into_string().unwrap();
        assert!(text.contains("input_tokens") && !text.contains("SENTINEL"));
        assert_eq!(b.drain_usage("t1").len(), 1);
        let denied = agent
            .post(&format!("{}/v1/messages", t.base_url))
            .set("x-api-key", "ozrt_wrong")
            .send_string("{}");
        assert!(matches!(denied, Err(ureq::Error::Status(401, _))));
    }
}
