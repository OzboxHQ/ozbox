//! The `/auth/...` endpoints.

use serde::Deserialize;
use serde_json::{json, Value};

use super::access;
use super::b64::{decode_url, encode_url};
use super::config::UserEntry;
use super::oauth::{self, OAuthError, Poll};
use super::session::{self, Level, Session};
use super::totp;
use super::webauthn::{self, Passkey};
use super::{Auth, Ceremony, GhFlow, GoogleTxn, Inner, Purpose, CEREMONY_TTL_MS, FLOW_CAP};
use crate::serve::{Req, Resp};

/// Who may call an `/auth` route. These routes are answered before the dashboard's request guard, so each one is listed
/// here with what it needs; one that is not listed is refused, and a test fails if the router answers a route this table
/// does not name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthAccess {
    /// Part of signing in: nobody is signed in yet, or the route checks its own proof (a cookie, a code).
    Public,
    /// Anyone signed in, about their own account.
    Own,
    /// An owner, with a fresh passkey (the route asks for it): it changes how everybody signs in.
    Owner,
}

/// Every `/auth` route as `METHOD path`, a path segment that is an id written `*`.
pub(crate) const AUTH_ROUTES: &[(&str, AuthAccess)] = &[
    ("GET session", AuthAccess::Public),
    ("POST passkey/login/options", AuthAccess::Public),
    ("POST passkey/login/verify", AuthAccess::Public),
    ("POST passkey/register/options", AuthAccess::Public),
    ("POST passkey/register/verify", AuthAccess::Public),
    ("POST second/passkey/options", AuthAccess::Public),
    ("POST second/passkey/verify", AuthAccess::Public),
    ("POST stepup/options", AuthAccess::Own),
    ("POST stepup/verify", AuthAccess::Own),
    ("POST stepup/totp", AuthAccess::Own),
    ("POST second/totp", AuthAccess::Public),
    ("POST totp/setup", AuthAccess::Own),
    ("POST totp/confirm", AuthAccess::Own),
    ("DELETE totp", AuthAccess::Own),
    ("POST bootstrap", AuthAccess::Public),
    ("POST github/start", AuthAccess::Public),
    ("POST github/poll", AuthAccess::Public),
    ("GET google/start", AuthAccess::Public),
    ("GET google/callback", AuthAccess::Public),
    ("POST access/exchange", AuthAccess::Public),
    ("GET account", AuthAccess::Own),
    ("DELETE passkeys/*", AuthAccess::Own),
    ("DELETE sessions/*", AuthAccess::Own),
    ("POST signout", AuthAccess::Own),
    ("POST signout-all", AuthAccess::Own),
    ("PUT config/github", AuthAccess::Owner),
    ("PUT config/google", AuthAccess::Owner),
];

/// What `method segs` needs, or `None` for a route that does not exist.
pub(crate) fn auth_access(method: &str, segs: &[&str]) -> Option<AuthAccess> {
    let shown: Vec<&str> = match segs {
        [first @ ("passkeys" | "sessions"), _] => vec![*first, "*"],
        other => other.to_vec(),
    };
    let key = format!("{method} {}", shown.join("/"));
    AUTH_ROUTES.iter().find(|(k, _)| *k == key).map(|(_, a)| *a)
}

/// A response and the extra headers (cookies, a redirect) that go with it.
pub struct Out {
    pub resp: Resp,
    pub headers: Vec<(String, String)>,
}

impl Out {
    pub fn of(resp: Resp) -> Out {
        Out {
            resp,
            headers: Vec::new(),
        }
    }

    fn json(v: Value) -> Out {
        Out::of(Resp::json(200, &v))
    }

    fn err(status: u16, code: &str, message: &str) -> Out {
        Out::of(Resp::error(status, code, message))
    }

    fn header(mut self, k: &str, v: String) -> Out {
        self.headers.push((k.to_string(), v));
        self
    }

    fn redirect(to: &str) -> Out {
        let mut r = Resp::error(303, "redirect", "see other");
        r.body = Vec::new();
        Out::of(r).header("Location", to.to_string())
    }
}

type R<T> = Result<T, Out>;

const MAX_VERIFY_PER_WINDOW: usize = 20;

fn parse<T: for<'de> Deserialize<'de>>(req: &Req) -> R<T> {
    serde_json::from_slice(&req.body)
        .map_err(|_| Out::err(400, "bad_request", "the request body is not valid"))
}

fn tokenize() -> R<String> {
    session::random_token(24)
        .ok_or_else(|| Out::err(500, "internal", "could not make a random value"))
}

fn short(key: &str) -> String {
    key.chars().take(12).collect()
}

#[derive(Deserialize)]
struct CredBody {
    ceremony: String,
    credential: Value,
    #[serde(default)]
    name: Option<String>,
}

fn s<'a>(v: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut cur = v;
    for p in path {
        cur = cur.get(*p)?;
    }
    cur.as_str()
}

impl Auth {
    // ---- helpers -------------------------------------------------------------------------------------------

    fn limited(&self, inner: &mut Inner, key: &str, max: usize) -> R<()> {
        if inner.limiter.hit_n(key, self.now(), max) {
            Ok(())
        } else {
            Err(Out::err(
                429,
                "too_many_attempts",
                "too many attempts; wait a few minutes and try again",
            ))
        }
    }

    fn allowed_user(&self, f: impl Fn(&UserEntry) -> bool) -> Option<&UserEntry> {
        self.cfg.file.users.iter().find(|u| f(u))
    }

    fn user_entry(&self, id: &str) -> Option<&UserEntry> {
        self.allowed_user(|u| u.id == id)
    }

    fn github_client(&self, inner: &Inner) -> Option<String> {
        inner
            .state
            .github_client_id
            .clone()
            .or_else(|| self.cfg.file.github.client_id.clone())
            .filter(|c| !c.is_empty())
    }

    fn google_client(&self, inner: &Inner) -> Option<String> {
        inner
            .state
            .google_client_id
            .clone()
            .or_else(|| self.cfg.file.google.client_id.clone())
            .filter(|c| !c.is_empty())
    }

    fn google_secret_set(&self) -> bool {
        self.secrets.exists("google-client-secret").unwrap_or(false)
    }

    fn cookie_of(req: &Req) -> Option<&str> {
        req.headers
            .get("cookie")
            .and_then(|h| session::cookie_value(h, session::COOKIE))
    }

    fn require(
        &self,
        inner: &mut Inner,
        req: &Req,
        levels: &[Level],
        csrf: bool,
    ) -> R<(String, Session)> {
        let now = self.now();
        let unauth = || Out::err(401, "unauthorized", "sign in to continue");
        let id = Self::cookie_of(req).ok_or_else(unauth)?;
        let (key, s) = inner
            .sessions
            .touch(id, now, self.cfg.idle_ms, self.cfg.absolute_ms)
            .ok_or_else(unauth)?;
        if !levels.contains(&s.level) {
            return Err(Out::err(
                403,
                "wrong_step",
                "that is not available at this point of signing in",
            ));
        }
        if csrf && !matches!(req.method.as_str(), "GET" | "HEAD") {
            let ok = req
                .headers
                .get(super::CSRF_HEADER)
                .is_some_and(|h| super::b64::ct_eq_bytes(h.as_bytes(), s.csrf.as_bytes()));
            if !ok {
                return Err(Out::err(
                    403,
                    "csrf",
                    "the request did not come from the dashboard",
                ));
            }
        }
        Ok((key, s))
    }

    fn fresh(&self, s: &Session) -> bool {
        s.last_stepup_ms
            .is_some_and(|t| self.now().saturating_sub(t) < self.cfg.stepup_ms)
    }

    /// The signed-in person must be an owner (the role may change settings). Their role is read now, not at sign-in.
    fn owner_only(&self, req: &Req) -> Result<(), Out> {
        let mut inner = self.lock();
        let (_, sess) = self.require(&mut inner, req, &[Level::Full], true)?;
        let role = self.roles_in(&inner).get(&sess.user).copied();
        match role {
            Some(r)
                if ozbox_core::roles::allowed(r, ozbox_core::permissions::Action::SettingsChange) =>
            {
                Ok(())
            }
            Some(r) => Err(Out::err(
                403,
                "role_forbidden",
                &format!(
                    "you are signed in as a {}, and a {} cannot change how people sign in. Ask an owner",
                    r.name(),
                    r.name()
                ),
            )),
            None => Err(Out::err(401, "unauthorized", "sign in to continue")),
        }
    }

    fn require_fresh(&self, s: &Session) -> R<()> {
        if self.fresh(s) {
            Ok(())
        } else {
            Err(Out::err(
                403,
                "step_up_required",
                "confirm with your passkey to continue",
            ))
        }
    }

    fn session_cookie(&self, id: &str, now: u64, created: u64) -> String {
        let left = (created + self.cfg.absolute_ms).saturating_sub(now) / 1000;
        session::set_cookie(session::COOKIE, id, left, "Strict")
    }

    /// Start a session for `user` at `level` and return the response carrying its cookie.
    fn start_session(
        &self,
        inner: &mut Inner,
        user: &str,
        level: Level,
        via: &'static str,
        stepup: bool,
    ) -> R<Out> {
        let now = self.now();
        let csrf = tokenize()?;
        let s = Session {
            user: user.to_string(),
            level,
            created_ms: now,
            last_seen_ms: now,
            last_stepup_ms: stepup.then_some(now),
            csrf,
            via,
            pending_totp: None,
        };
        let id = inner
            .sessions
            .create(s, now, self.cfg.idle_ms, self.cfg.absolute_ms)
            .ok_or_else(|| Out::err(503, "busy", "too many people are signed in"))?;
        Ok(self.status_out(inner, Some(&id), now))
    }

    /// First factor passed: the second is a passkey/code, or enrolment when there is none yet.
    fn first_factor(&self, inner: &mut Inner, user: &str, via: &'static str) -> R<Out> {
        let has = inner
            .state
            .users
            .get(user)
            .is_some_and(|u| !u.passkeys.is_empty() || u.totp);
        let level = if has {
            Level::NeedsSecondFactor
        } else {
            Level::EnrollRequired
        };
        self.start_session(inner, user, level, via, false)
    }

    /// Upgrade a session after its second factor: a new cookie id (no fixation), level Full.
    fn upgrade(&self, inner: &mut Inner, key: &str, stepup: bool) -> R<Out> {
        let now = self.now();
        if let Some(s) = inner.sessions.get_mut(key) {
            s.level = Level::Full;
            if stepup {
                s.last_stepup_ms = Some(now);
            }
        }
        let id = inner
            .sessions
            .rotate(key)
            .ok_or_else(|| Out::err(401, "unauthorized", "sign in to continue"))?;
        Ok(self.status_out(inner, Some(&id), now))
    }

    fn methods(&self, inner: &Inner) -> Value {
        let gh_any = self.cfg.file.users.iter().any(|u| u.github.is_some());
        let go_any = self.cfg.file.users.iter().any(|u| u.google.is_some());
        json!({
            "passkey": true,
            "github": gh_any && self.github_client(inner).is_some(),
            "google": go_any && self.google_client(inner).is_some() && self.google_secret_set(),
            "access": self.cfg.file.access.is_some(),
            "setup_code": inner.setup_code.as_ref().is_some_and(|(_, exp)| *exp > self.now()),
        })
    }

    /// `GET /auth/session`'s body, with a cookie when `new_id` is given.
    fn status_out(&self, inner: &mut Inner, new_id: Option<&str>, now: u64) -> Out {
        let methods = self.methods(inner);
        let mut body = json!({ "mode": "session", "state": "signed_out", "methods": methods, "stepup_window_s": self.cfg.stepup_ms / 1000 });
        let mut cookie = None;
        let id = new_id.map(String::from);
        if let Some(id) = id {
            if let Some((_, sess)) =
                inner
                    .sessions
                    .touch(&id, now, self.cfg.idle_ms, self.cfg.absolute_ms)
            {
                cookie = Some(self.session_cookie(&id, now, sess.created_ms));
                self.fill_status(inner, &sess, &mut body);
            }
        }
        let out = Out::json(body);
        match cookie {
            Some(c) => out.header("Set-Cookie", c),
            None => out,
        }
    }

    fn fill_status(&self, inner: &Inner, s: &Session, body: &mut Value) {
        let us = inner.state.users.get(&s.user);
        body["state"] = json!(match s.level {
            Level::Full => "signed_in",
            Level::NeedsSecondFactor => "needs_second_factor",
            Level::EnrollRequired => "enroll_required",
        });
        body["user"] = json!({ "id": s.user, "label": self.user_entry(&s.user).map(|u| u.label.clone()).unwrap_or_default() });
        body["csrf"] = json!(s.csrf);
        let role = self
            .roles_in(inner)
            .get(&s.user)
            .copied()
            .unwrap_or(ozbox_core::roles::Role::Viewer);
        body["role"] = json!(role.name());
        body["can"] = json!(ozbox_core::roles::capabilities(role));
        body["second_factors"] = json!({
            "passkey": us.is_some_and(|u| !u.passkeys.is_empty()),
            "totp": us.is_some_and(|u| u.totp),
        });
        body["stepup_fresh"] = json!(self.fresh(s));
    }

    // ---- routing -------------------------------------------------------------------------------------------

    pub fn route(&self, req: &Req) -> Option<Out> {
        if !(req.path == "/auth" || req.path.starts_with("/auth/")) {
            return None;
        }
        if let Some(r) = self.origin_ok(req) {
            return Some(Out::of(r));
        }
        let segs: Vec<&str> = req
            .path
            .trim_start_matches('/')
            .split('/')
            .skip(1)
            .filter(|s| !s.is_empty())
            .collect();
        let m = req.method.as_str();
        match auth_access(m, &segs) {
            None => return Some(Out::err(404, "not_found", "no such endpoint")),
            Some(AuthAccess::Owner) => {
                if let Err(e) = self.owner_only(req) {
                    return Some(e);
                }
            }
            Some(_) => {}
        }
        let r = match (m, segs.as_slice()) {
            ("GET", ["session"]) => self.get_session(req),
            ("POST", ["passkey", "login", "options"]) => self.login_options(),
            ("POST", ["passkey", "login", "verify"]) => self.login_verify(req),
            ("POST", ["passkey", "register", "options"]) => self.register_options(req),
            ("POST", ["passkey", "register", "verify"]) => self.register_verify(req),
            ("POST", ["second", "passkey", "options"]) => self.assert_options(req, false),
            ("POST", ["second", "passkey", "verify"]) => self.assert_verify(req, false),
            ("POST", ["stepup", "options"]) => self.assert_options(req, true),
            ("POST", ["stepup", "verify"]) => self.assert_verify(req, true),
            ("POST", ["stepup", "totp"]) => self.stepup_totp(req),
            ("POST", ["second", "totp"]) => self.second_totp(req),
            ("POST", ["totp", "setup"]) => self.totp_setup(req),
            ("POST", ["totp", "confirm"]) => self.totp_confirm(req),
            ("DELETE", ["totp"]) => self.totp_remove(req),
            ("POST", ["bootstrap"]) => self.bootstrap(req),
            ("POST", ["github", "start"]) => self.github_start(),
            ("POST", ["github", "poll"]) => self.github_poll(req),
            ("GET", ["google", "start"]) => self.google_start(),
            ("GET", ["google", "callback"]) => self.google_callback(req),
            ("POST", ["access", "exchange"]) => self.access_exchange(req),
            ("GET", ["account"]) => self.account(req),
            ("DELETE", ["passkeys", id]) => self.passkey_remove(req, id),
            ("DELETE", ["sessions", id]) => self.session_revoke(req, id),
            ("POST", ["signout"]) => self.signout(req, false),
            ("POST", ["signout-all"]) => self.signout(req, true),
            ("PUT", ["config", "github"]) => self.config_github(req),
            ("PUT", ["config", "google"]) => self.config_google(req),
            _ => Err(Out::err(404, "not_found", "no such endpoint")),
        };
        Some(r.unwrap_or_else(|e| e))
    }

    // ---- status --------------------------------------------------------------------------------------------

    fn get_session(&self, req: &Req) -> R<Out> {
        let now = self.now();
        let mut inner = self.lock();
        let mut body = json!({ "mode": "session", "state": "signed_out", "methods": self.methods(&inner), "stepup_window_s": self.cfg.stepup_ms / 1000 });
        if let Some(id) = Self::cookie_of(req) {
            if let Some((_, s)) =
                inner
                    .sessions
                    .touch(id, now, self.cfg.idle_ms, self.cfg.absolute_ms)
            {
                self.fill_status(&inner, &s, &mut body);
            }
        }
        inner
            .sessions
            .sweep(now, self.cfg.idle_ms, self.cfg.absolute_ms);
        Ok(Out::json(body))
    }

    // ---- passkeys ------------------------------------------------------------------------------------------

    fn new_ceremony(&self, inner: &mut Inner, purpose: Purpose) -> R<(String, Vec<u8>)> {
        let now = self.now();
        inner.ceremonies.retain(|_, c| c.expires_ms > now);
        if inner.ceremonies.len() >= 256 {
            return Err(Out::err(503, "busy", "too many sign-ins are in progress"));
        }
        let id = tokenize()?;
        let mut challenge = vec![0u8; 32];
        getrandom::getrandom(&mut challenge)
            .map_err(|_| Out::err(500, "internal", "could not make a random value"))?;
        inner.ceremonies.insert(
            id.clone(),
            Ceremony {
                challenge: challenge.clone(),
                purpose,
                expires_ms: now + CEREMONY_TTL_MS,
            },
        );
        Ok((id, challenge))
    }

    fn take_ceremony(&self, inner: &mut Inner, id: &str) -> R<Ceremony> {
        let c = inner
            .ceremonies
            .remove(id)
            .ok_or_else(|| Out::err(400, "expired", "this sign-in step expired; start again"))?;
        if c.expires_ms <= self.now() {
            return Err(Out::err(
                400,
                "expired",
                "this sign-in step expired; start again",
            ));
        }
        Ok(c)
    }

    fn login_options(&self) -> R<Out> {
        let mut inner = self.lock();
        self.limited(&mut inner, "options", 60)?;
        let (id, ch) = self.new_ceremony(&mut inner, Purpose::Login)?;
        Ok(Out::json(
            json!({ "ceremony": id, "options": webauthn::assertion_options(&self.cfg.rp, &ch, &[]) }),
        ))
    }

    /// Verify an assertion against the passkeys in `candidates`; returns (user, credential index) after updating
    /// the counter.
    fn check_assertion(
        &self,
        inner: &mut Inner,
        c: &Ceremony,
        cred: &Value,
        only_user: Option<&str>,
    ) -> R<String> {
        let id = s(cred, &["id"])
            .ok_or_else(|| Out::err(400, "bad_request", "the passkey response is missing"))?;
        self.limited(inner, "verify", MAX_VERIFY_PER_WINDOW * 3)?;
        self.limited(inner, &format!("cred:{id}"), 10)?;
        let refuse = || Out::err(401, "passkey_refused", "that passkey was not accepted");
        let found = inner.state.users.iter().find_map(|(u, st)| {
            st.passkeys
                .iter()
                .position(|p| p.id == id)
                .map(|i| (u.clone(), i))
        });
        let (user, idx) = found.ok_or_else(refuse)?;
        if only_user.is_some_and(|o| o != user) {
            return Err(refuse());
        }
        // The user handle, when the authenticator returns one, must be this person.
        if let Some(h) = s(cred, &["response", "userHandle"]).filter(|h| !h.is_empty()) {
            if decode_url(h).as_deref() != Some(user.as_bytes()) {
                return Err(refuse());
            }
        }
        let pk = inner
            .state
            .users
            .get(&user)
            .map(|u| u.passkeys[idx].clone())
            .ok_or_else(refuse)?;
        let get = |k: &str| s(cred, &["response", k]).unwrap_or("");
        let n = webauthn::verify_assertion(
            &self.cfg.rp,
            &c.challenge,
            &pk,
            get("clientDataJSON"),
            get("authenticatorData"),
            get("signature"),
        )
        .map_err(|_| refuse())?;
        let now = self.now();
        if let Some(p) = inner
            .state
            .users
            .get_mut(&user)
            .and_then(|u| u.passkeys.get_mut(idx))
        {
            p.sign_count = n;
            p.last_used_ms = now;
        }
        self.save(inner);
        inner.limiter.clear(&format!("cred:{id}"));
        Ok(user)
    }

    fn login_verify(&self, req: &Req) -> R<Out> {
        let b: CredBody = parse(req)?;
        let mut inner = self.lock();
        let c = self.take_ceremony(&mut inner, &b.ceremony)?;
        if !matches!(c.purpose, Purpose::Login) {
            return Err(Out::err(
                400,
                "bad_request",
                "the sign-in step does not match",
            ));
        }
        let user = self.check_assertion(&mut inner, &c, &b.credential, None)?;
        if self.user_entry(&user).is_none() {
            return Err(Out::err(
                403,
                "not_allowed",
                "this account is not allowed to sign in",
            ));
        }
        // A passkey is possession plus a verified person: it is the whole sign-in, and a fresh step-up.
        self.start_session(&mut inner, &user, Level::Full, "passkey", true)
    }

    fn register_options(&self, req: &Req) -> R<Out> {
        let mut inner = self.lock();
        let (key, sess) =
            self.require(&mut inner, req, &[Level::EnrollRequired, Level::Full], true)?;
        if sess.level == Level::Full {
            self.require_fresh(&sess)?;
        }
        let exclude: Vec<String> = Self::user_passkeys(&inner, &sess.user)
            .into_iter()
            .map(|p| p.id)
            .collect();
        let label = self
            .user_entry(&sess.user)
            .map(|u| u.label.clone())
            .unwrap_or_else(|| sess.user.clone());
        let (id, ch) = self.new_ceremony(
            &mut inner,
            Purpose::Register {
                session: key,
                user: sess.user.clone(),
            },
        )?;
        let options = webauthn::registration_options(
            &self.cfg.rp,
            sess.user.as_bytes(),
            &label,
            &ch,
            &exclude,
        );
        Ok(Out::json(json!({ "ceremony": id, "options": options })))
    }

    fn register_verify(&self, req: &Req) -> R<Out> {
        let b: CredBody = parse(req)?;
        let mut inner = self.lock();
        let (key, sess) =
            self.require(&mut inner, req, &[Level::EnrollRequired, Level::Full], true)?;
        let c = self.take_ceremony(&mut inner, &b.ceremony)?;
        let Purpose::Register { session, user } = &c.purpose else {
            return Err(Out::err(
                400,
                "bad_request",
                "the sign-in step does not match",
            ));
        };
        if *session != key || *user != sess.user {
            return Err(Out::err(
                400,
                "bad_request",
                "the sign-in step does not match",
            ));
        }
        self.limited(&mut inner, "verify", MAX_VERIFY_PER_WINDOW * 3)?;
        let get = |k: &str| s(&b.credential, &["response", k]).unwrap_or("");
        let np = webauthn::verify_registration(
            &self.cfg.rp,
            &c.challenge,
            get("clientDataJSON"),
            get("attestationObject"),
            s(&b.credential, &["id"]).unwrap_or(""),
        )
        .map_err(|e| Out::err(400, "passkey_refused", &e.to_string()))?;
        if inner
            .state
            .users
            .values()
            .any(|u| u.passkeys.iter().any(|p| p.id == np.id))
        {
            return Err(Out::err(
                409,
                "already_registered",
                "that passkey is already registered",
            ));
        }
        let now = self.now();
        let name: String = b
            .name
            .unwrap_or_default()
            .chars()
            .filter(|c| !c.is_control())
            .take(40)
            .collect();
        let st = inner.state.users.entry(sess.user.clone()).or_default();
        if st.passkeys.len() >= 10 {
            return Err(Out::err(
                409,
                "too_many",
                "ten passkeys is the most one person can register",
            ));
        }
        st.passkeys.push(Passkey {
            id: np.id,
            alg: np.alg,
            key: encode_url(&np.key),
            sign_count: np.sign_count,
            name: if name.is_empty() {
                format!("Passkey {}", st.passkeys.len() + 1)
            } else {
                name
            },
            created_ms: now,
            last_used_ms: now,
        });
        self.save(&inner);
        if sess.level == Level::EnrollRequired {
            return self.upgrade(&mut inner, &key, true);
        }
        Ok(Out::json(json!({ "ok": true })))
    }

    /// Options for a passkey check by someone already in a session: the second factor (`stepup` false) or a fresh
    /// confirmation (`stepup` true).
    fn assert_options(&self, req: &Req, stepup: bool) -> R<Out> {
        let mut inner = self.lock();
        let levels = if stepup {
            vec![Level::Full]
        } else {
            vec![Level::NeedsSecondFactor]
        };
        let (key, sess) = self.require(&mut inner, req, &levels, true)?;
        let ids: Vec<String> = Self::user_passkeys(&inner, &sess.user)
            .into_iter()
            .map(|p| p.id)
            .collect();
        if ids.is_empty() {
            return Err(Out::err(
                409,
                "no_passkey",
                "no passkey is registered for this account",
            ));
        }
        let purpose = if stepup {
            Purpose::StepUp { session: key }
        } else {
            Purpose::Second { session: key }
        };
        let (id, ch) = self.new_ceremony(&mut inner, purpose)?;
        Ok(Out::json(
            json!({ "ceremony": id, "options": webauthn::assertion_options(&self.cfg.rp, &ch, &ids) }),
        ))
    }

    fn assert_verify(&self, req: &Req, stepup: bool) -> R<Out> {
        let b: CredBody = parse(req)?;
        let mut inner = self.lock();
        let levels = if stepup {
            vec![Level::Full]
        } else {
            vec![Level::NeedsSecondFactor]
        };
        let (key, sess) = self.require(&mut inner, req, &levels, true)?;
        let c = self.take_ceremony(&mut inner, &b.ceremony)?;
        let ok = match &c.purpose {
            Purpose::StepUp { session } => stepup && *session == key,
            Purpose::Second { session } => !stepup && *session == key,
            _ => false,
        };
        if !ok {
            return Err(Out::err(
                400,
                "bad_request",
                "the sign-in step does not match",
            ));
        }
        self.check_assertion(&mut inner, &c, &b.credential, Some(&sess.user))?;
        self.upgrade(&mut inner, &key, true)
    }

    // ---- authenticator app ---------------------------------------------------------------------------------

    fn totp_secret_name(user: &str) -> String {
        format!("totp-{user}")
    }

    #[allow(clippy::type_complexity)]
    fn check_totp(&self, inner: &mut Inner, user: &str, code: &str) -> R<()> {
        self.limited(inner, &format!("totp:{user}"), 8)?;
        self.limited(inner, "verify", MAX_VERIFY_PER_WINDOW * 3)?;
        let refuse = || Out::err(401, "code_refused", "that code was not accepted");
        let secret = self
            .secrets
            .get(&Self::totp_secret_name(user))
            .ok()
            .flatten()
            .ok_or_else(refuse)?;
        let last = inner.state.users.get(user).and_then(|u| u.totp_last_step);
        let step = totp::verify(&secret, code, self.now() / 1000, last).ok_or_else(refuse)?;
        if let Some(u) = inner.state.users.get_mut(user) {
            u.totp_last_step = Some(step);
        }
        self.save(inner);
        inner.limiter.clear(&format!("totp:{user}"));
        Ok(())
    }

    fn second_totp(&self, req: &Req) -> R<Out> {
        #[derive(Deserialize)]
        struct B {
            code: String,
        }
        let b: B = parse(req)?;
        let mut inner = self.lock();
        let (key, sess) = self.require(&mut inner, req, &[Level::NeedsSecondFactor], true)?;
        self.check_totp(&mut inner, &sess.user, &b.code)?;
        self.upgrade(&mut inner, &key, false)
    }

    /// A step-up for someone with no passkey: a fresh authenticator code stands in.
    fn stepup_totp(&self, req: &Req) -> R<Out> {
        #[derive(Deserialize)]
        struct B {
            code: String,
        }
        let b: B = parse(req)?;
        let mut inner = self.lock();
        let (key, sess) = self.require(&mut inner, req, &[Level::Full], true)?;
        if inner
            .state
            .users
            .get(&sess.user)
            .is_some_and(|u| !u.passkeys.is_empty())
        {
            return Err(Out::err(
                403,
                "passkey_required",
                "use your passkey to confirm",
            ));
        }
        self.check_totp(&mut inner, &sess.user, &b.code)?;
        self.upgrade(&mut inner, &key, true)
    }

    fn totp_setup(&self, req: &Req) -> R<Out> {
        let mut inner = self.lock();
        let (key, sess) =
            self.require(&mut inner, req, &[Level::EnrollRequired, Level::Full], true)?;
        if sess.level == Level::Full {
            self.require_fresh(&sess)?;
        }
        let secret = totp::new_secret()
            .map_err(|_| Out::err(500, "internal", "could not make a random value"))?;
        let label = format!("{}@{}", sess.user, self.cfg.rp.id);
        let uri = totp::otpauth_uri(&self.cfg.rp.name, &label, &secret);
        if let Some(s) = inner.sessions.get_mut(&key) {
            s.pending_totp = Some(secret.clone());
        }
        // Shown once, now: it is how the app is set up. It is never returned again.
        Ok(Out::json(json!({ "secret": secret, "otpauth_uri": uri })))
    }

    fn totp_confirm(&self, req: &Req) -> R<Out> {
        #[derive(Deserialize)]
        struct B {
            code: String,
        }
        let b: B = parse(req)?;
        let mut inner = self.lock();
        let (key, sess) =
            self.require(&mut inner, req, &[Level::EnrollRequired, Level::Full], true)?;
        self.limited(&mut inner, &format!("totp:{}", sess.user), 8)?;
        let secret = sess
            .pending_totp
            .clone()
            .ok_or_else(|| Out::err(409, "no_setup", "start the authenticator setup first"))?;
        let step = totp::verify(&secret, &b.code, self.now() / 1000, None)
            .ok_or_else(|| Out::err(401, "code_refused", "that code was not accepted"))?;
        self.secrets
            .set(&Self::totp_secret_name(&sess.user), &secret)
            .map_err(|_| Out::err(500, "secret_store", "the secret could not be stored"))?;
        let u = inner.state.users.entry(sess.user.clone()).or_default();
        u.totp = true;
        u.totp_last_step = Some(step);
        if let Some(s) = inner.sessions.get_mut(&key) {
            s.pending_totp = None;
        }
        self.save(&inner);
        if sess.level == Level::EnrollRequired {
            return self.upgrade(&mut inner, &key, false);
        }
        Ok(Out::json(json!({ "ok": true })))
    }

    fn totp_remove(&self, req: &Req) -> R<Out> {
        let mut inner = self.lock();
        let (_, sess) = self.require(&mut inner, req, &[Level::Full], true)?;
        self.require_fresh(&sess)?;
        let us = inner
            .state
            .users
            .get(&sess.user)
            .cloned()
            .unwrap_or_default();
        if us.passkeys.is_empty() {
            return Err(Out::err(
                409,
                "last_factor",
                "this is your only second factor; add a passkey first",
            ));
        }
        let _ = self.secrets.delete(&Self::totp_secret_name(&sess.user));
        if let Some(u) = inner.state.users.get_mut(&sess.user) {
            u.totp = false;
            u.totp_last_step = None;
        }
        self.save(&inner);
        Ok(Out::json(json!({ "ok": true })))
    }

    // ---- first factors -------------------------------------------------------------------------------------

    fn bootstrap(&self, req: &Req) -> R<Out> {
        #[derive(Deserialize)]
        struct B {
            code: String,
            user: String,
        }
        let b: B = parse(req)?;
        let mut inner = self.lock();
        self.limited(&mut inner, "setup-code", 5)?;
        let refuse = || Out::err(401, "code_refused", "that setup code was not accepted");
        let now = self.now();
        let (hash, exp) = inner.setup_code.clone().ok_or_else(refuse)?;
        let given = session::key_of(&b.code.trim().to_ascii_uppercase());
        if exp <= now || !super::ct_eq(&given, &hash) || self.user_entry(&b.user).is_none() {
            return Err(refuse());
        }
        inner.setup_code = None;
        self.first_factor(&mut inner, &b.user, "setup code")
    }

    fn github_start(&self) -> R<Out> {
        let mut inner = self.lock();
        self.limited(&mut inner, "github-start", 10)?;
        let client = self
            .github_client(&inner)
            .ok_or_else(|| Out::err(404, "not_configured", "GitHub sign-in is not set up"))?;
        let now = self.now();
        inner.gh.retain(|_, f| f.expires_ms > now);
        if inner.gh.len() >= FLOW_CAP {
            return Err(Out::err(503, "busy", "too many sign-ins are in progress"));
        }
        drop(inner);
        let d = oauth::github_device_start(self.http.as_ref(), &client).map_err(|e| match e {
            OAuthError::Refused => Out::err(502, "github_refused", "GitHub refused the request; check the client id and that device flow is enabled on the OAuth app"),
            _ => Out::err(502, "github_unreachable", "GitHub could not be reached"),
        })?;
        let flow = tokenize()?;
        let mut inner = self.lock();
        inner.gh.insert(
            flow.clone(),
            GhFlow {
                device_code: d.device_code,
                interval_s: d.interval,
                next_poll_ms: now + d.interval * 1000,
                expires_ms: now + d.expires_in * 1000,
            },
        );
        Ok(Out::json(json!({
            "flow": flow, "user_code": d.user_code, "verification_uri": d.verification_uri,
            "interval": d.interval, "expires_in": d.expires_in,
        })))
    }

    fn github_poll(&self, req: &Req) -> R<Out> {
        #[derive(Deserialize)]
        struct B {
            flow: String,
        }
        let b: B = parse(req)?;
        let now = self.now();
        let mut inner = self.lock();
        let client = self
            .github_client(&inner)
            .ok_or_else(|| Out::err(404, "not_configured", "GitHub sign-in is not set up"))?;
        let (device, interval) = {
            let Some(f) = inner.gh.get_mut(&b.flow) else {
                return Ok(Out::json(json!({ "status": "expired" })));
            };
            if f.expires_ms <= now {
                inner.gh.remove(&b.flow);
                return Ok(Out::json(json!({ "status": "expired" })));
            }
            if now < f.next_poll_ms {
                // Asked sooner than GitHub's interval: answer from here without bothering GitHub.
                return Ok(Out::json(
                    json!({ "status": "pending", "interval": f.interval_s }),
                ));
            }
            f.next_poll_ms = now + f.interval_s * 1000;
            (f.device_code.clone(), f.interval_s)
        };
        drop(inner);
        let polled = oauth::github_device_poll(self.http.as_ref(), &client, &device);
        let mut inner = self.lock();
        match polled {
            Err(_) => Ok(Out::json(
                json!({ "status": "pending", "interval": interval }),
            )),
            Ok(Poll::Pending) => Ok(Out::json(
                json!({ "status": "pending", "interval": interval }),
            )),
            Ok(Poll::SlowDown(i)) => {
                if let Some(f) = inner.gh.get_mut(&b.flow) {
                    f.interval_s = i;
                    f.next_poll_ms = now + i * 1000;
                }
                Ok(Out::json(json!({ "status": "slow_down", "interval": i })))
            }
            Ok(Poll::Expired) => {
                inner.gh.remove(&b.flow);
                Ok(Out::json(json!({ "status": "expired" })))
            }
            Ok(Poll::Denied) => {
                inner.gh.remove(&b.flow);
                Ok(Out::json(json!({ "status": "denied" })))
            }
            Ok(Poll::Token(token)) => {
                inner.gh.remove(&b.flow);
                drop(inner);
                // Identity only: the token is used for this one read and then dropped.
                let user = oauth::github_user(self.http.as_ref(), &token);
                drop(token);
                let mut inner = self.lock();
                let gh = user.map_err(|_| {
                    Out::err(502, "github_unreachable", "GitHub could not be reached")
                })?;
                let not_allowed =
                    || Out::err(403, "not_allowed", "this account is not allowed to sign in");
                let entry = self
                    .allowed_user(|u| u.github.as_deref() == Some(gh.login.as_str()))
                    .ok_or_else(not_allowed)?;
                let id = entry.id.clone();
                let pinned = inner.state.users.get(&id).and_then(|u| u.github_id);
                if pinned.is_some_and(|p| p != gh.id) {
                    return Err(not_allowed());
                }
                inner.state.users.entry(id.clone()).or_default().github_id = Some(gh.id);
                self.save(&inner);
                let out = self.first_factor(&mut inner, &id, "github")?;
                Ok(out)
            }
        }
    }

    fn google_start(&self) -> R<Out> {
        let mut inner = self.lock();
        self.limited(&mut inner, "google-start", 10)?;
        let client = self
            .google_client(&inner)
            .filter(|_| self.google_secret_set())
            .ok_or_else(|| Out::err(404, "not_configured", "Google sign-in is not set up"))?;
        let now = self.now();
        inner.txns.retain(|_, t| t.expires_ms > now);
        if inner.txns.len() >= FLOW_CAP {
            return Err(Out::err(503, "busy", "too many sign-ins are in progress"));
        }
        let (txn, state, nonce, verifier) = (tokenize()?, tokenize()?, tokenize()?, tokenize()?);
        let url = oauth::google_auth_url(
            &client,
            &format!("{}/auth/google/callback", self.cfg.rp.origin),
            &state,
            &nonce,
            &verifier,
        );
        inner.txns.insert(
            txn.clone(),
            GoogleTxn {
                state,
                nonce,
                verifier,
                expires_ms: now + 10 * 60_000,
            },
        );
        // Lax, not Strict: the return from Google is a cross-site navigation and a Strict cookie would not come back.
        Ok(Out::redirect(&url).header(
            "Set-Cookie",
            session::set_cookie(session::OAUTH_COOKIE, &txn, 600, "Lax"),
        ))
    }

    fn google_callback(&self, req: &Req) -> R<Out> {
        // Every ending goes to a fixed address with a fixed code; nothing from the request is reflected.
        let fail = |code: &str| {
            Out::redirect(&format!("/?signin={code}"))
                .header("Set-Cookie", session::clear_cookie(session::OAUTH_COOKIE))
        };
        let q = crate::serve::parse_query(&req.query);
        let txn_id = req
            .headers
            .get("cookie")
            .and_then(|h| session::cookie_value(h, session::OAUTH_COOKIE))
            .map(String::from);
        let mut inner = self.lock();
        let Some(txn) = txn_id.and_then(|t| inner.txns.remove(&t)) else {
            return Ok(fail("expired"));
        };
        if txn.expires_ms <= self.now() {
            return Ok(fail("expired"));
        }
        let state_ok = q.get("state").is_some_and(|s| super::ct_eq(s, &txn.state));
        let code = q.get("code").filter(|c| !c.is_empty() && c.len() < 2048);
        if !state_ok || q.contains_key("error") {
            return Ok(fail("refused"));
        }
        let Some(code) = code else {
            return Ok(fail("refused"));
        };
        let (Some(client), Ok(Some(secret))) = (
            self.google_client(&inner),
            self.secrets.get("google-client-secret"),
        ) else {
            return Ok(fail("not_configured"));
        };
        if self.limited(&mut inner, "google-callback", 20).is_err() {
            return Ok(fail("too_many"));
        }
        drop(inner);
        let email = oauth::google_identity(
            self.http.as_ref(),
            &client,
            &secret,
            code,
            &txn.verifier,
            &format!("{}/auth/google/callback", self.cfg.rp.origin),
            &txn.nonce,
            self.now() / 1000,
        );
        let mut inner = self.lock();
        let Ok(email) = email else {
            return Ok(fail("refused"));
        };
        let Some(entry) = self.allowed_user(|u| u.google.as_deref() == Some(email.as_str())) else {
            return Ok(fail("not_allowed"));
        };
        let id = entry.id.clone();
        let out = self.first_factor(&mut inner, &id, "google")?;
        let cookie_headers: Vec<(String, String)> = out.headers.clone();
        let mut r = Out::redirect("/");
        r.headers.extend(cookie_headers);
        r.headers.push((
            "Set-Cookie".into(),
            session::clear_cookie(session::OAUTH_COOKIE),
        ));
        Ok(r)
    }

    fn access_exchange(&self, req: &Req) -> R<Out> {
        let cfg =
            self.cfg.file.access.clone().ok_or_else(|| {
                Out::err(404, "not_configured", "Cloudflare Access is not set up")
            })?;
        let token = req
            .headers
            .get("cf-access-jwt-assertion")
            .ok_or_else(|| {
                Out::err(
                    401,
                    "access_refused",
                    "no Cloudflare Access token on this request",
                )
            })?
            .clone();
        let now = self.now();
        let mut inner = self.lock();
        self.limited(&mut inner, "access", 20)?;
        let refuse = || {
            Out::err(
                401,
                "access_refused",
                "the Cloudflare Access token was not accepted",
            )
        };
        let kid = access::jwt_kid(&token).ok_or_else(refuse)?;
        let known = inner.jwks.as_ref().is_some_and(|(k, at)| {
            now.saturating_sub(*at) < 3_600_000 && k.iter().any(|x| x.kid == kid)
        });
        if !known {
            let recent = inner
                .jwks
                .as_ref()
                .is_some_and(|(_, at)| now.saturating_sub(*at) < 60_000);
            if recent {
                return Err(refuse());
            }
            drop(inner);
            let url = format!("https://{}/cdn-cgi/access/certs", cfg.team_domain);
            let r = self
                .http
                .send(&crate::netguard::HttpRequest::new(
                    "GET",
                    url,
                    crate::netguard::Guard::Public,
                ))
                .map_err(|_| {
                    Out::err(
                        502,
                        "access_unreachable",
                        "Cloudflare Access keys could not be fetched",
                    )
                })?;
            let keys = access::parse_jwks(&r.body);
            inner = self.lock();
            inner.jwks = Some((keys, now));
        }
        let keys = inner
            .jwks
            .as_ref()
            .map(|(k, _)| k.clone())
            .unwrap_or_default();
        let email = access::verify_jwt(&token, &keys, &cfg.team_domain, &cfg.audience, now / 1000)
            .map_err(|_| refuse())?;
        let entry = self
            .allowed_user(|u| u.access_email.as_deref() == Some(email.as_str()))
            .ok_or_else(|| {
                Out::err(403, "not_allowed", "this account is not allowed to sign in")
            })?;
        let id = entry.id.clone();
        // Access applied its own identity policy (which should require two-factor); it is the whole sign-in.
        self.start_session(&mut inner, &id, Level::Full, "access", false)
    }

    // ---- account ---------------------------------------------------------------------------------------------

    fn account(&self, req: &Req) -> R<Out> {
        let mut inner = self.lock();
        let (key, sess) = self.require(&mut inner, req, &[Level::Full], false)?;
        let us = inner
            .state
            .users
            .get(&sess.user)
            .cloned()
            .unwrap_or_default();
        let sessions: Vec<Value> = inner
            .sessions
            .of_user(&sess.user)
            .iter()
            .map(|(k, s)| json!({ "id": short(k), "created_ms": s.created_ms, "last_seen_ms": s.last_seen_ms, "via": s.via, "current": *k == key }))
            .collect();
        let passkeys: Vec<Value> = us
            .passkeys
            .iter()
            .map(|p| json!({ "id": p.id, "name": p.name, "created_ms": p.created_ms, "last_used_ms": p.last_used_ms }))
            .collect();
        let roles = self.roles_in(&inner);
        let my_role = roles.get(&sess.user).copied();
        let is_owner = my_role.is_some_and(|r| {
            ozbox_core::roles::allowed(r, ozbox_core::permissions::Action::SettingsChange)
        });
        // The accounts people sign in with are an owner's to see; everyone else gets a label and a role.
        let people: Vec<Value> = self
            .cfg
            .file
            .users
            .iter()
            .map(|u| {
                let role = roles.get(&u.id).copied().unwrap_or(ozbox_core::roles::Role::Viewer);
                if is_owner {
                    json!({ "id": u.id, "label": u.label, "github": u.github, "google": u.google, "role": role.name() })
                } else {
                    json!({ "id": u.id, "label": u.label, "role": role.name() })
                }
            })
            .collect();
        Ok(Out::json(json!({
            "user": { "id": sess.user, "label": self.user_entry(&sess.user).map(|u| u.label.clone()) },
            "passkeys": passkeys,
            "totp": us.totp,
            "sessions": sessions,
            "people": people,
            "providers": {
                "github": { "client_id": self.github_client(&inner) },
                "google": { "client_id": self.google_client(&inner), "secret_set": self.google_secret_set() },
                "access": self.cfg.file.access.as_ref().map(|a| json!({ "team_domain": a.team_domain })),
            },
            "public_origin": self.cfg.rp.origin,
            "callback_url": format!("{}/auth/google/callback", self.cfg.rp.origin),
            "stepup_fresh": self.fresh(&sess),
            "role": my_role.map(|r| r.name()),
            "can_configure_providers": is_owner,
        })))
    }

    fn passkey_remove(&self, req: &Req, id: &str) -> R<Out> {
        let mut inner = self.lock();
        let (_, sess) = self.require(&mut inner, req, &[Level::Full], true)?;
        self.require_fresh(&sess)?;
        let us = inner
            .state
            .users
            .get(&sess.user)
            .cloned()
            .unwrap_or_default();
        if !us.passkeys.iter().any(|p| p.id == id) {
            return Err(Out::err(404, "not_found", "no such passkey"));
        }
        if us.passkeys.len() == 1 && !us.totp {
            return Err(Out::err(
                409,
                "last_factor",
                "this is your only second factor; add another first",
            ));
        }
        if let Some(u) = inner.state.users.get_mut(&sess.user) {
            u.passkeys.retain(|p| p.id != id);
        }
        self.save(&inner);
        Ok(Out::json(json!({ "ok": true })))
    }

    fn session_revoke(&self, req: &Req, id: &str) -> R<Out> {
        let mut inner = self.lock();
        let (own, sess) = self.require(&mut inner, req, &[Level::Full], true)?;
        let matches: Vec<String> = inner
            .sessions
            .of_user(&sess.user)
            .into_iter()
            .map(|(k, _)| k)
            .filter(|k| id.len() >= 8 && k.starts_with(id))
            .collect();
        match matches.as_slice() {
            [k] => {
                let current = *k == own;
                inner.sessions.remove(k);
                let out = Out::json(json!({ "ok": true }));
                Ok(if current {
                    out.header("Set-Cookie", session::clear_cookie(session::COOKIE))
                } else {
                    out
                })
            }
            _ => Err(Out::err(404, "not_found", "no such session")),
        }
    }

    fn signout(&self, req: &Req, everywhere: bool) -> R<Out> {
        let mut inner = self.lock();
        let (key, sess) = self.require(
            &mut inner,
            req,
            &[Level::Full, Level::NeedsSecondFactor, Level::EnrollRequired],
            true,
        )?;
        if everywhere {
            inner.sessions.remove_user(&sess.user);
        } else {
            inner.sessions.remove(&key);
        }
        Ok(Out::json(json!({ "ok": true }))
            .header("Set-Cookie", session::clear_cookie(session::COOKIE)))
    }

    // ---- provider settings ---------------------------------------------------------------------------------

    fn client_id_ok(s: &str) -> bool {
        !s.is_empty()
            && s.len() <= 200
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-~:/@".contains(&b))
    }

    fn config_github(&self, req: &Req) -> R<Out> {
        #[derive(Deserialize)]
        struct B {
            client_id: String,
        }
        let b: B = parse(req)?;
        let mut inner = self.lock();
        let (_, sess) = self.require(&mut inner, req, &[Level::Full], true)?;
        self.require_fresh(&sess)?;
        let id = b.client_id.trim().to_string();
        if !Self::client_id_ok(&id) {
            return Err(Out::err(400, "bad_request", "that is not a client id"));
        }
        inner.state.github_client_id = Some(id);
        self.save(&inner);
        Ok(Out::json(json!({ "ok": true })))
    }

    fn config_google(&self, req: &Req) -> R<Out> {
        #[derive(Deserialize)]
        struct B {
            client_id: String,
            /// Write-only: stored in the secret store and never returned.
            client_secret: Option<String>,
        }
        let b: B = parse(req)?;
        let mut inner = self.lock();
        let (_, sess) = self.require(&mut inner, req, &[Level::Full], true)?;
        self.require_fresh(&sess)?;
        let id = b.client_id.trim().to_string();
        if !Self::client_id_ok(&id) {
            return Err(Out::err(400, "bad_request", "that is not a client id"));
        }
        if let Some(sec) = b.client_secret.as_deref().filter(|s| !s.is_empty()) {
            self.secrets
                .set("google-client-secret", sec)
                .map_err(|_| Out::err(400, "bad_request", "that secret cannot be stored"))?;
        }
        inner.state.google_client_id = Some(id);
        self.save(&inner);
        Ok(Out::json(json!({ "ok": true })))
    }
}
