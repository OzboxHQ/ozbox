//! Signing in to the dashboard when it runs on a shared machine (`ozbox serve --public-behind-tunnel`).
//!
//! The server still listens on loopback only; a tunnel carries the traffic. Instead of the local access token, a
//! request needs a signed-in session: a passkey (the default, nothing to set up), or GitHub / Google / Cloudflare
//! Access followed by a second factor (a passkey or an authenticator-app code). Nobody can sign in who is not on the
//! allow-list set at set-up. No passwords exist anywhere. A destructive change asks for a fresh passkey first.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod access;
pub mod approval;
pub mod b64;
pub mod cbor;
pub mod config;
pub mod oauth;
pub mod ratelimit;
pub mod roles;
pub mod session;
pub mod state;
pub mod totp;
pub mod webauthn;

mod routes;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::netguard::HttpClient;
use crate::secrets::SecretStore;

use self::config::AuthConfig;
use self::ratelimit::RateLimiter;
use self::session::Sessions;
use self::state::AuthState;
use self::webauthn::Passkey;
use super::{Req, Resp};

const CEREMONY_TTL_MS: u64 = 5 * 60_000;
const FLOW_CAP: usize = 64;
pub const CSRF_HEADER: &str = "x-ozbox-csrf";

pub(crate) enum Purpose {
    Login,
    Second { session: String },
    StepUp { session: String },
    Register { session: String, user: String },
}

pub(crate) struct Ceremony {
    pub challenge: Vec<u8>,
    pub purpose: Purpose,
    pub expires_ms: u64,
}

pub(crate) struct GhFlow {
    pub device_code: String,
    pub interval_s: u64,
    pub next_poll_ms: u64,
    pub expires_ms: u64,
}

pub(crate) struct GoogleTxn {
    pub state: String,
    pub nonce: String,
    pub verifier: String,
    pub expires_ms: u64,
}

pub(crate) struct Inner {
    pub state: AuthState,
    pub sessions: Sessions,
    pub ceremonies: HashMap<String, Ceremony>,
    pub gh: HashMap<String, GhFlow>,
    pub txns: HashMap<String, GoogleTxn>,
    pub setup_code: Option<(String, u64)>,
    pub limiter: RateLimiter,
    pub jwks: Option<(Vec<access::Jwk>, u64)>,
}

pub struct Auth {
    pub(crate) cfg: AuthConfig,
    pub(crate) inner: Mutex<Inner>,
    pub(crate) secrets: Arc<dyn SecretStore>,
    pub(crate) http: Arc<dyn HttpClient>,
    pub(crate) clock: Box<dyn Fn() -> u64 + Send + Sync>,
    pub(crate) state_path: Option<PathBuf>,
    /// Called each time a person enrols a passkey or an authenticator (the box's dashboard closes the secrets service's first-day
    /// window with it: `secrets_ingress::close_setup_window`). Idempotent on the other side.
    pub(crate) on_enrolled: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

fn ct_eq(a: &str, b: &str) -> bool {
    b64::ct_eq_bytes(a.as_bytes(), b.as_bytes())
}

impl Auth {
    /// A server for `cfg`. A state file that exists and cannot be read is refused (see [`AuthState::try_load`]).
    pub fn try_new(
        cfg: AuthConfig,
        state_path: Option<PathBuf>,
        secrets: Arc<dyn SecretStore>,
        http: Arc<dyn HttpClient>,
        clock: Box<dyn Fn() -> u64 + Send + Sync>,
    ) -> Result<Self, String> {
        let state = match state_path.as_deref() {
            Some(p) => AuthState::try_load(p)?,
            None => AuthState::default(),
        };
        Ok(Self::build(cfg, state_path, secrets, http, clock, state))
    }

    /// As [`Auth::try_new`], starting from an empty state when the file cannot be read (for tests).
    #[cfg(test)]
    pub fn new(
        cfg: AuthConfig,
        state_path: Option<PathBuf>,
        secrets: Arc<dyn SecretStore>,
        http: Arc<dyn HttpClient>,
        clock: Box<dyn Fn() -> u64 + Send + Sync>,
    ) -> Self {
        let state = state_path
            .as_deref()
            .map(AuthState::load)
            .unwrap_or_default();
        Self::build(cfg, state_path, secrets, http, clock, state)
    }

    fn build(
        cfg: AuthConfig,
        state_path: Option<PathBuf>,
        secrets: Arc<dyn SecretStore>,
        http: Arc<dyn HttpClient>,
        clock: Box<dyn Fn() -> u64 + Send + Sync>,
        mut state: AuthState,
    ) -> Self {
        // A role chosen at the dashboard belongs to somebody on the list. When a person is taken off it, their chosen role
        // goes with them, so that adding them again later gives them what the file says, not an old owner's role.
        let mut pruned = false;
        for (id, u) in state.users.iter_mut() {
            if u.role.is_some() && !cfg.file.users.iter().any(|f| &f.id == id) {
                u.role = None;
                pruned = true;
            }
        }
        if pruned {
            if let Some(p) = &state_path {
                let _ = state.save(p);
            }
        }
        // Sessions live beside the auth state, so a restart does not sign everyone out.
        let mut sessions = match &state_path {
            Some(p) => Sessions::persistent(
                p.with_file_name("sessions.json"),
                clock(),
                cfg.idle_ms,
                cfg.absolute_ms,
            ),
            None => Sessions::default(),
        };
        // Somebody taken off the list is signed out at the next start.
        sessions.retain_users(|u| cfg.file.users.iter().any(|f| f.id == u));
        Self {
            cfg,
            inner: Mutex::new(Inner {
                state,
                sessions,
                ceremonies: HashMap::new(),
                gh: HashMap::new(),
                txns: HashMap::new(),
                setup_code: None,
                limiter: RateLimiter::new(5 * 60_000),
                jwks: None,
            }),
            secrets,
            http,
            clock,
            state_path,
            on_enrolled: Mutex::new(None),
        }
    }

    /// What to do each time a person enrols a passkey or an authenticator (see the field).
    pub fn set_on_enrolled(&self, f: Arc<dyn Fn() + Send + Sync>) {
        *self.on_enrolled.lock().unwrap_or_else(|e| e.into_inner()) = Some(f);
    }

    /// A person enrolled a passkey or an authenticator: say so to whoever asked ([`Auth::set_on_enrolled`]).
    pub(crate) fn note_enrolled(&self) {
        let f = self
            .on_enrolled
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(f) = f {
            f();
        }
    }

    pub(crate) fn now(&self) -> u64 {
        (self.clock)()
    }

    pub(crate) fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn save(&self, inner: &Inner) {
        let _ = self.save_checked(inner);
    }

    /// Write the state, and say whether it was written. Used where reporting success for a change that was lost would be
    /// wrong (a role).
    pub(crate) fn save_checked(&self, inner: &Inner) -> std::io::Result<()> {
        match &self.state_path {
            Some(p) => inner.state.save(p),
            None => Ok(()),
        }
    }

    /// Whether anyone has a passkey or an authenticator enrolled: a second factor exists to approve with.
    pub fn has_second_factor(&self) -> bool {
        self.lock()
            .state
            .users
            .values()
            .any(|u| !u.passkeys.is_empty() || u.totp)
    }

    /// When nobody has a passkey or an authenticator yet, make a one-time setup code the first person can use to
    /// enrol one (printed once on the machine's own console). `None` when someone is already enrolled.
    pub fn issue_setup_code(&self) -> Option<String> {
        let mut inner = self.lock();
        if inner
            .state
            .users
            .values()
            .any(|u| !u.passkeys.is_empty() || u.totp)
        {
            return None;
        }
        // Ten characters from a 32-letter alphabet (no 0/O/1/I): 256 is a multiple of 32, so every byte maps evenly.
        const ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        let mut raw = [0u8; 10];
        getrandom::getrandom(&mut raw).ok()?;
        let chars: Vec<char> = raw
            .iter()
            .map(|b| ALPHABET[usize::from(b % 32)] as char)
            .collect();
        let code = format!(
            "{}-{}",
            chars[..5].iter().collect::<String>(),
            chars[5..].iter().collect::<String>()
        );
        inner.setup_code = Some((session::key_of(&code), self.now() + 30 * 60_000));
        Some(code)
    }

    fn cookie_id(req: &Req) -> Option<&str> {
        session::cookie_value(req.headers.get("cookie")?, session::COOKIE)
    }

    /// Host and Origin must be this server's public address, exactly.
    pub(crate) fn origin_ok(&self, req: &Req) -> Option<Resp> {
        match req.headers.get("host") {
            Some(h) if h.eq_ignore_ascii_case(&self.cfg.host) => {}
            _ => {
                return Some(Resp::error(
                    403,
                    "bad_host",
                    "this server answers only on its own address",
                ))
            }
        }
        let state_changing = !matches!(req.method.as_str(), "GET" | "HEAD");
        match req.headers.get("origin") {
            Some(o) if o == &self.cfg.rp.origin => None,
            Some(_) => Some(Resp::error(
                403,
                "bad_origin",
                "cross-origin requests are not allowed",
            )),
            // A browser always sends Origin on a change; a request without one is not a page of ours.
            None if state_changing => Some(Resp::error(
                403,
                "bad_origin",
                "cross-origin requests are not allowed",
            )),
            None => None,
        }
    }

    /// `Some` refuses the request. With `need_auth`, a full session and (for a change) its CSRF token are required.
    pub fn guard(&self, req: &Req, need_auth: bool) -> Option<Resp> {
        if let Some(r) = self.origin_ok(req) {
            return Some(r);
        }
        if !need_auth {
            return None;
        }
        let now = self.now();
        let Some(id) = Self::cookie_id(req) else {
            return Some(Resp::error(401, "unauthorized", "sign in to continue"));
        };
        let mut inner = self.lock();
        let Some((_, s)) = inner
            .sessions
            .touch(id, now, self.cfg.idle_ms, self.cfg.absolute_ms)
        else {
            return Some(Resp::error(401, "unauthorized", "sign in to continue"));
        };
        if s.level != session::Level::Full {
            return Some(Resp::error(
                401,
                "unauthorized",
                "finish signing in to continue",
            ));
        }
        if !matches!(req.method.as_str(), "GET" | "HEAD") {
            let ok = req
                .headers
                .get(CSRF_HEADER)
                .is_some_and(|h| ct_eq(h, &s.csrf));
            if !ok {
                return Some(Resp::error(
                    403,
                    "csrf",
                    "the request did not come from the dashboard",
                ));
            }
        }
        None
    }

    /// The storage key of the fully signed-in session this request carries, if any (no Origin or CSRF check: for a
    /// navigation that only asks for something to be handed over, never for a change).
    pub fn full_session_key(&self, req: &Req) -> Option<String> {
        let id = Self::cookie_id(req)?;
        let now = self.now();
        let mut inner = self.lock();
        let (key, s) = inner
            .sessions
            .touch(id, now, self.cfg.idle_ms, self.cfg.absolute_ms)?;
        (s.level == session::Level::Full).then_some(key)
    }

    /// Is the session stored under `key` still signed in?
    pub fn session_alive(&self, key: &str) -> bool {
        self.lock()
            .sessions
            .alive(key, self.now(), self.cfg.absolute_ms)
    }

    /// Who is signed in on this request, if anyone.
    pub fn person(&self, req: &Req) -> Option<String> {
        let id = Self::cookie_id(req)?;
        let now = self.now();
        let mut inner = self.lock();
        inner
            .sessions
            .touch(id, now, self.cfg.idle_ms, self.cfg.absolute_ms)
            .map(|(_, s)| s.user)
            .filter(|u| self.cfg.file.users.iter().any(|f| &f.id == u))
    }

    /// Has this session shown a passkey within the step-up window?
    pub fn step_up_fresh(&self, req: &Req) -> bool {
        let now = self.now();
        let Some(id) = Self::cookie_id(req) else {
            return false;
        };
        let mut inner = self.lock();
        inner
            .sessions
            .touch(id, now, self.cfg.idle_ms, self.cfg.absolute_ms)
            .is_some_and(|(_, s)| {
                s.last_stepup_ms
                    .is_some_and(|t| now.saturating_sub(t) < self.cfg.stepup_ms)
            })
    }

    pub(crate) fn user_passkeys(inner: &Inner, user: &str) -> Vec<Passkey> {
        inner
            .state
            .users
            .get(user)
            .map(|u| u.passkeys.clone())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests;
