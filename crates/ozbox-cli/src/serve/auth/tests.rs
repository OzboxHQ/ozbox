//! Sign-in end to end, against a software authenticator, a scripted GitHub / Google and an injected clock.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use serde_json::{json, Value};

use super::b64::{decode_url, encode_url};
use super::config::{AccessCfg, AuthConfig, AuthFile, ClientCfg, UserEntry};
use super::webauthn::testkit::Authenticator;
use super::{totp, Auth};
use crate::netguard::FakeHttp;
use crate::secrets::{MemorySecrets, SecretStore};
use crate::serve::Req;

const ORIGIN: &str = "https://box.example.com";
const HOST: &str = "box.example.com";
const T0: u64 = 1_800_000_000_000;

struct Rig {
    auth: Arc<Auth>,
    clock: Arc<AtomicU64>,
    http: Arc<FakeHttp>,
    secrets: Arc<MemorySecrets>,
    _dir: tempfile::TempDir,
}

fn rig_with(access: Option<AccessCfg>) -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let file = AuthFile {
        public_origin: ORIGIN.into(),
        users: vec![
            UserEntry {
                id: "owner".into(),
                label: "Owner".into(),
                github: Some("owner-gh".into()),
                google: Some("owner@example.com".into()),
                access_email: Some("owner@example.com".into()),
                ..Default::default()
            },
            UserEntry {
                id: "friend".into(),
                github: Some("friend-gh".into()),
                ..Default::default()
            },
        ],
        github: ClientCfg {
            client_id: Some("Iv1.testclient".into()),
        },
        google: ClientCfg {
            client_id: Some("google-client".into()),
        },
        access,
        ..Default::default()
    };
    let clock = Arc::new(AtomicU64::new(T0));
    let http = Arc::new(FakeHttp::default());
    let secrets = Arc::new(MemorySecrets::default());
    secrets
        .set("google-client-secret", "SENTINEL-GOOGLE-SECRET")
        .unwrap();
    let c = clock.clone();
    let auth = Arc::new(Auth::new(
        AuthConfig::new(file).unwrap(),
        Some(dir.path().join("auth-state.json")),
        secrets.clone(),
        http.clone(),
        Box::new(move || c.load(Ordering::SeqCst)),
    ));
    Rig {
        auth,
        clock,
        http,
        secrets,
        _dir: dir,
    }
}

fn rig() -> Rig {
    rig_with(None)
}

#[derive(Debug)]
struct Reply {
    status: u16,
    body: Value,
    set_cookies: Vec<String>,
    location: Option<String>,
}

impl Reply {
    /// The session id a `Set-Cookie` carries.
    fn session(&self) -> Option<String> {
        self.set_cookies
            .iter()
            .find_map(|c| {
                c.strip_prefix("__Host-ozbox_session=")
                    .map(|r| r.split(';').next().unwrap_or("").to_string())
            })
            .filter(|s| !s.is_empty())
    }

    fn state(&self) -> &str {
        self.body["state"].as_str().unwrap_or("")
    }
}

struct Client {
    cookie: Option<String>,
    csrf: String,
}

impl Client {
    fn new() -> Self {
        Client {
            cookie: None,
            csrf: String::new(),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn request(
    method: &str,
    path: &str,
    query: &str,
    body: &Value,
    cookie: Option<&str>,
    csrf: &str,
    host: &str,
    origin: Option<&str>,
) -> Req {
    let mut headers = HashMap::new();
    headers.insert("host".to_string(), host.to_string());
    if let Some(o) = origin {
        headers.insert("origin".to_string(), o.to_string());
    }
    if let Some(c) = cookie {
        headers.insert("cookie".to_string(), c.to_string());
    }
    if !csrf.is_empty() {
        headers.insert("x-ozbox-csrf".to_string(), csrf.to_string());
    }
    Req {
        method: method.into(),
        path: path.into(),
        query: query.into(),
        headers,
        body: if body.is_null() {
            Vec::new()
        } else {
            body.to_string().into_bytes()
        },
    }
}

impl Rig {
    fn send(&self, c: &mut Client, method: &str, path: &str, body: Value) -> Reply {
        let (p, q) = path.split_once('?').unwrap_or((path, ""));
        let cookie = c
            .cookie
            .as_ref()
            .map(|s| format!("__Host-ozbox_session={s}"));
        let req = request(
            method,
            p,
            q,
            &body,
            cookie.as_deref(),
            &c.csrf,
            HOST,
            Some(ORIGIN),
        );
        let out = self.auth.route(&req).expect("an /auth route");
        let r = Reply {
            status: out.resp.status,
            body: serde_json::from_slice(&out.resp.body).unwrap_or(Value::Null),
            set_cookies: out
                .headers
                .iter()
                .filter(|(k, _)| k == "Set-Cookie")
                .map(|(_, v)| v.clone())
                .collect(),
            location: out
                .headers
                .iter()
                .find(|(k, _)| k == "Location")
                .map(|(_, v)| v.clone()),
        };
        if let Some(id) = r.session() {
            c.cookie = Some(id);
        }
        if let Some(t) = r.body["csrf"].as_str() {
            c.csrf = t.to_string();
        }
        r
    }

    fn guard_status(&self, c: &Client, method: &str, with_csrf: bool) -> u16 {
        let cookie = c
            .cookie
            .as_ref()
            .map(|s| format!("__Host-ozbox_session={s}"));
        let req = request(
            method,
            "/v1/boxes",
            "",
            &Value::Null,
            cookie.as_deref(),
            if with_csrf { &c.csrf } else { "" },
            HOST,
            Some(ORIGIN),
        );
        self.auth.guard(&req, true).map_or(200, |r| r.status)
    }

    fn advance(&self, ms: u64) {
        self.clock.fetch_add(ms, Ordering::SeqCst);
    }

    /// Sign a first person in with the printed setup code and a software passkey; returns the signed-in client.
    fn enrol(&self, authn: &Authenticator, user: &str) -> Client {
        let code = self.auth.issue_setup_code().expect("a setup code");
        let mut c = Client::new();
        let r = self.send(
            &mut c,
            "POST",
            "/auth/bootstrap",
            json!({"code": code, "user": user}),
        );
        assert_eq!(
            (r.status, r.state()),
            (200, "enroll_required"),
            "{:?}",
            r.body
        );
        let opts = self.send(
            &mut c,
            "POST",
            "/auth/passkey/register/options",
            Value::Null,
        );
        assert_eq!(opts.status, 200, "{:?}", opts.body);
        let ch = decode_url(opts.body["options"]["challenge"].as_str().unwrap()).unwrap();
        let (cd, att) = authn.register(&self.auth.cfg.rp, &ch);
        let r = self.send(
            &mut c,
            "POST",
            "/auth/passkey/register/verify",
            json!({"ceremony": opts.body["ceremony"], "name": "Laptop", "credential": {"id": encode_url(&authn.cred_id), "response": {"clientDataJSON": cd, "attestationObject": att}}}),
        );
        assert_eq!((r.status, r.state()), (200, "signed_in"), "{:?}", r.body);
        c
    }

    fn passkey_login(&self, authn: &mut Authenticator) -> (Client, Reply) {
        let mut c = Client::new();
        let o = self.send(&mut c, "POST", "/auth/passkey/login/options", Value::Null);
        let ch = decode_url(o.body["options"]["challenge"].as_str().unwrap()).unwrap();
        let (cd, ad, sig) = authn.assert(&self.auth.cfg.rp, &ch);
        let r = self.send(
            &mut c,
            "POST",
            "/auth/passkey/login/verify",
            json!({"ceremony": o.body["ceremony"], "credential": {"id": encode_url(&authn.cred_id), "response": {"clientDataJSON": cd, "authenticatorData": ad, "signature": sig, "userHandle": encode_url(b"owner")}}}),
        );
        (c, r)
    }
}

#[test]
fn the_setup_code_enrols_a_passkey_and_the_session_cookie_is_locked_down() {
    let r = rig();
    let authn = Authenticator::new();
    let code = r.auth.issue_setup_code().unwrap();
    let mut c = Client::new();
    // a wrong code, then the right one for a person who is not on the list
    assert_eq!(
        r.send(
            &mut c,
            "POST",
            "/auth/bootstrap",
            json!({"code": "WRONG-CODE", "user": "owner"})
        )
        .status,
        401
    );
    assert_eq!(
        r.send(
            &mut c,
            "POST",
            "/auth/bootstrap",
            json!({"code": code, "user": "stranger"})
        )
        .status,
        401
    );
    let signed = r.enrol(&authn, "owner");
    assert!(
        r.auth.issue_setup_code().is_none(),
        "no code once someone is enrolled"
    );
    assert_eq!(r.guard_status(&signed, "GET", false), 200);
    // the cookie flags, on a fresh sign-in
    let mut a2 = authn;
    let (_, login) = r.passkey_login(&mut a2);
    let cookie = login
        .set_cookies
        .iter()
        .find(|c| c.starts_with("__Host-ozbox_session="))
        .unwrap();
    for f in ["Secure", "HttpOnly", "SameSite=Strict", "Path=/"] {
        assert!(cookie.contains(f), "{cookie}");
    }
    assert!(!cookie.contains("Domain"));
}

#[test]
fn a_setup_code_is_single_use_and_rate_limited() {
    let r = rig();
    let code = r.auth.issue_setup_code().unwrap();
    let mut c = Client::new();
    assert_eq!(
        r.send(
            &mut c,
            "POST",
            "/auth/bootstrap",
            json!({"code": code, "user": "owner"})
        )
        .status,
        200
    );
    assert_eq!(
        r.send(
            &mut Client::new(),
            "POST",
            "/auth/bootstrap",
            json!({"code": code, "user": "owner"})
        )
        .status,
        401
    );
    let r2 = rig();
    r2.auth.issue_setup_code().unwrap();
    let codes: Vec<u16> = (0..7)
        .map(|_| {
            r2.send(
                &mut Client::new(),
                "POST",
                "/auth/bootstrap",
                json!({"code": "AAAAA-BBBBB", "user": "owner"}),
            )
            .status
        })
        .collect();
    assert_eq!(&codes[..5], &[401; 5]);
    assert_eq!(codes[5], 429);
    // expiry
    let r3 = rig();
    let code = r3.auth.issue_setup_code().unwrap();
    r3.advance(31 * 60_000);
    assert_eq!(
        r3.send(
            &mut Client::new(),
            "POST",
            "/auth/bootstrap",
            json!({"code": code, "user": "owner"})
        )
        .status,
        401
    );
}

#[test]
fn a_passkey_login_is_the_whole_sign_in_and_a_replay_is_refused() {
    let r = rig();
    let mut authn = Authenticator::new();
    let first = r.enrol(&authn, "owner");
    let (c, login) = r.passkey_login(&mut authn);
    assert_eq!((login.status, login.state()), (200, "signed_in"));
    assert_eq!(login.body["user"]["id"], "owner");
    assert_eq!(r.guard_status(&c, "GET", false), 200);
    // The enrolment session id is not the login's: sessions are not shared.
    assert_ne!(first.cookie, c.cookie);
    // a ceremony cannot be used twice
    let mut cl = Client::new();
    let o = r.send(&mut cl, "POST", "/auth/passkey/login/options", Value::Null);
    let ch = decode_url(o.body["options"]["challenge"].as_str().unwrap()).unwrap();
    let (cd, ad, sig) = authn.assert(&r.auth.cfg.rp, &ch);
    let body = json!({"ceremony": o.body["ceremony"], "credential": {"id": encode_url(&authn.cred_id), "response": {"clientDataJSON": cd, "authenticatorData": ad, "signature": sig}}});
    assert_eq!(
        r.send(&mut cl, "POST", "/auth/passkey/login/verify", body.clone())
            .status,
        200
    );
    assert_eq!(
        r.send(
            &mut Client::new(),
            "POST",
            "/auth/passkey/login/verify",
            body
        )
        .status,
        400
    );
    // an unknown credential
    let mut other = Authenticator::new();
    let o = r.send(
        &mut Client::new(),
        "POST",
        "/auth/passkey/login/options",
        Value::Null,
    );
    let ch = decode_url(o.body["options"]["challenge"].as_str().unwrap()).unwrap();
    let (cd, ad, sig) = other.assert(&r.auth.cfg.rp, &ch);
    let bad = json!({"ceremony": o.body["ceremony"], "credential": {"id": encode_url(&other.cred_id), "response": {"clientDataJSON": cd, "authenticatorData": ad, "signature": sig}}});
    assert_eq!(
        r.send(
            &mut Client::new(),
            "POST",
            "/auth/passkey/login/verify",
            bad
        )
        .status,
        401
    );
}

#[test]
fn state_changes_need_the_csrf_token_and_the_exact_origin_and_host() {
    let r = rig();
    let mut authn = Authenticator::new();
    r.enrol(&authn, "owner");
    let (c, _) = r.passkey_login(&mut authn);
    assert_eq!(r.guard_status(&c, "POST", false), 403, "no csrf token");
    assert_eq!(r.guard_status(&c, "POST", true), 200);
    let cookie = format!("__Host-ozbox_session={}", c.cookie.clone().unwrap());
    for (host, origin, want) in [
        ("evil.example", Some(ORIGIN), 403),
        (HOST, Some("https://evil.example"), 403),
        (HOST, Some("http://box.example.com"), 403),
        (HOST, None, 403), // a change with no Origin
    ] {
        let req = request(
            "POST",
            "/v1/apply",
            "",
            &Value::Null,
            Some(&cookie),
            &c.csrf,
            host,
            origin,
        );
        assert_eq!(
            r.auth.guard(&req, true).map(|x| x.status),
            Some(want),
            "{host} {origin:?}"
        );
    }
    // a read with no Origin (a plain navigation) is fine; no cookie is not
    let req = request(
        "GET",
        "/v1/boxes",
        "",
        &Value::Null,
        Some(&cookie),
        "",
        HOST,
        None,
    );
    assert!(r.auth.guard(&req, true).is_none());
    let req = request("GET", "/v1/boxes", "", &Value::Null, None, "", HOST, None);
    assert_eq!(r.auth.guard(&req, true).map(|x| x.status), Some(401));
    // a made-up cookie
    let req = request(
        "GET",
        "/v1/boxes",
        "",
        &Value::Null,
        Some("__Host-ozbox_session=nope"),
        "",
        HOST,
        None,
    );
    assert_eq!(r.auth.guard(&req, true).map(|x| x.status), Some(401));
}

#[test]
fn step_up_needs_a_passkey_within_five_minutes() {
    let r = rig();
    let mut authn = Authenticator::new();
    r.enrol(&authn, "owner");
    let (mut c, _) = r.passkey_login(&mut authn);
    let step = |r: &Rig, c: &Client| {
        let cookie = format!("__Host-ozbox_session={}", c.cookie.clone().unwrap());
        r.auth.step_up_fresh(&request(
            "POST",
            "/v1/apply",
            "",
            &Value::Null,
            Some(&cookie),
            &c.csrf,
            HOST,
            Some(ORIGIN),
        ))
    };
    assert!(step(&r, &c), "the login itself is a fresh passkey");
    r.advance(4 * 60_000);
    assert!(step(&r, &c));
    r.advance(2 * 60_000);
    assert!(!step(&r, &c), "six minutes on, it is stale");
    // sensitive account changes are refused until it is renewed
    let g = r.send(
        &mut c,
        "PUT",
        "/auth/config/github",
        json!({"client_id": "Iv1.new"}),
    );
    assert_eq!(
        (g.status, g.body["code"].as_str()),
        (403, Some("step_up_required"))
    );
    let o = r.send(&mut c, "POST", "/auth/stepup/options", Value::Null);
    assert_eq!(o.status, 200, "{:?}", o.body);
    let ch = decode_url(o.body["options"]["challenge"].as_str().unwrap()).unwrap();
    // a passkey for a different ceremony does not count
    let (cd, ad, sig) = authn.assert(&r.auth.cfg.rp, b"some-other-challenge");
    let wrong = json!({"ceremony": o.body["ceremony"], "credential": {"id": encode_url(&authn.cred_id), "response": {"clientDataJSON": cd, "authenticatorData": ad, "signature": sig}}});
    assert_eq!(
        r.send(&mut c, "POST", "/auth/stepup/verify", wrong).status,
        401
    );
    assert!(!step(&r, &c));
    let o = r.send(&mut c, "POST", "/auth/stepup/options", Value::Null);
    let ch2 = decode_url(o.body["options"]["challenge"].as_str().unwrap()).unwrap();
    assert_ne!(ch, ch2);
    let (cd, ad, sig) = authn.assert(&r.auth.cfg.rp, &ch2);
    let ok = json!({"ceremony": o.body["ceremony"], "credential": {"id": encode_url(&authn.cred_id), "response": {"clientDataJSON": cd, "authenticatorData": ad, "signature": sig}}});
    let v = r.send(&mut c, "POST", "/auth/stepup/verify", ok);
    assert_eq!(v.status, 200, "{:?}", v.body);
    assert!(step(&r, &c));
    assert_eq!(
        r.send(
            &mut c,
            "PUT",
            "/auth/config/github",
            json!({"client_id": "Iv1.new"})
        )
        .status,
        200
    );
}

/// Saving, starting, stopping and restarting the tunnel decide who can reach the dashboard at all, so in sign-in mode
/// each needs a passkey shown a moment ago, exactly like a change that cannot be undone.
#[test]
fn the_tunnel_can_only_be_changed_with_a_fresh_passkey() {
    use crate::serve::access::AccessCtx;
    use crate::tunnel::testing::{env, FakeSpawner};
    use crate::tunnel::{build, runner::Runner, TunnelFile};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    let r = rig();
    r.secrets
        .set("tunnel-token-cloudflare", "SENTINEL-TUNNEL")
        .unwrap();
    let mut authn = Authenticator::new();
    r.enrol(&authn, "owner");
    let (mut c, _) = r.passkey_login(&mut authn);

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tunnel.toml");
    let sp = Arc::new(FakeSpawner::default());
    let (sp2, secrets) = (Arc::clone(&sp), r.secrets.clone());
    let mut app = crate::serve::App::new(
        Box::new(ozbox_provider_fake::open(dir.path())),
        true,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7878),
        "unused-token".into(),
    )
    .with_secrets(r.secrets.clone())
    .with_auth(r.auth.clone())
    .with_access(AccessCtx {
        tunnel_path: Some(path.clone()),
        public_url: Some(ORIGIN.into()),
        factory: Some(Box::new(move |file: &TunnelFile| {
            let e = env(
                Arc::clone(&sp2),
                Arc::new(ozbox_core::RecordingRunner::new()),
                Arc::clone(&secrets),
            );
            Ok(Runner::new(
                build(file, &e)?,
                &file.public_url,
                Arc::new(FakeHttp::default()),
                None,
                7878,
                0,
            ))
        })),
        ..Default::default()
    });
    let mut go = |c: &Client, method: &str, p: &str, body: Value| -> (u16, Option<String>) {
        let cookie = format!("__Host-ozbox_session={}", c.cookie.clone().unwrap());
        let resp = app.handle(&request(
            method,
            p,
            "",
            &body,
            Some(&cookie),
            &c.csrf,
            HOST,
            Some(ORIGIN),
        ));
        let v: Value = serde_json::from_slice(&resp.body).unwrap_or(Value::Null);
        (resp.status, v["code"].as_str().map(String::from))
    };
    let put = json!({"provider":"cloudflare","public_url":ORIGIN});
    let tunnel = "/v1/dashboard-access/tunnel";

    // a fresh passkey (the sign-in itself): every change goes through
    assert_eq!(go(&c, "PUT", tunnel, put.clone()).0, 200);
    assert_eq!(
        go(&c, "POST", &format!("{tunnel}/start"), Value::Null).0,
        200
    );
    assert_eq!(sp.spawned.lock().unwrap().len(), 1);

    // six minutes later none of them is allowed, and nothing changed
    r.advance(6 * 60_000);
    let denied = (403, Some("step_up_required".to_string()));
    assert_eq!(go(&c, "PUT", tunnel, put.clone()), denied);
    assert_eq!(go(&c, "DELETE", tunnel, Value::Null), denied);
    for action in ["start", "stop", "restart"] {
        assert_eq!(
            go(&c, "POST", &format!("{tunnel}/{action}"), Value::Null),
            denied,
            "{action}"
        );
    }
    assert_eq!(sp.spawned.lock().unwrap().len(), 1, "nothing was restarted");
    assert!(
        sp.alive.load(Ordering::SeqCst),
        "and the tunnel was not stopped"
    );
    assert!(path.exists(), "nor the settings removed");
    // reading is not a change
    assert_eq!(go(&c, "GET", "/v1/dashboard-access", Value::Null).0, 200);

    // showing the passkey again renews it
    let o = r.send(&mut c, "POST", "/auth/stepup/options", Value::Null);
    let ch = decode_url(o.body["options"]["challenge"].as_str().unwrap()).unwrap();
    let (cd, ad, sig) = authn.assert(&r.auth.cfg.rp, &ch);
    let ok = json!({"ceremony": o.body["ceremony"], "credential": {"id": encode_url(&authn.cred_id), "response": {"clientDataJSON": cd, "authenticatorData": ad, "signature": sig}}});
    assert_eq!(
        r.send(&mut c, "POST", "/auth/stepup/verify", ok).status,
        200
    );
    assert_eq!(
        go(&c, "POST", &format!("{tunnel}/stop"), Value::Null).0,
        200
    );
    assert!(!sp.alive.load(Ordering::SeqCst));
}

fn github_user_replies(r: &Rig, login: &str, id: u64) {
    r.http.reply(
        200,
        r#"{"access_token":"gho_SENTINEL","token_type":"bearer"}"#,
    );
    r.http
        .reply(200, &json!({"id": id, "login": login}).to_string());
}

fn github_start(r: &Rig, c: &mut Client) -> Reply {
    r.http.reply(200, r#"{"device_code":"DEVSECRET","user_code":"WXYZ-1234","verification_uri":"https://github.com/login/device","expires_in":900,"interval":5}"#);
    r.send(c, "POST", "/auth/github/start", Value::Null)
}

#[test]
fn github_device_flow_polls_at_the_servers_pace_and_ends_in_an_enrolment_step() {
    let r = rig();
    let mut c = Client::new();
    let s = github_start(&r, &mut c);
    assert_eq!(
        (s.status, s.body["user_code"].as_str()),
        (200, Some("WXYZ-1234"))
    );
    assert!(
        !s.body.to_string().contains("DEVSECRET"),
        "the device code never reaches the browser"
    );
    let flow = s.body["flow"].clone();
    // too soon: answered here, GitHub is not asked
    let n = r.http.requests().len();
    let p = r.send(&mut c, "POST", "/auth/github/poll", json!({"flow": flow}));
    assert_eq!(p.body["status"], "pending");
    assert_eq!(r.http.requests().len(), n);
    // on time: pending, then slow_down raises the interval, then the person approves
    r.advance(5_100);
    r.http.reply(200, r#"{"error":"authorization_pending"}"#);
    assert_eq!(
        r.send(&mut c, "POST", "/auth/github/poll", json!({"flow": flow}))
            .body["status"],
        "pending"
    );
    r.advance(5_100);
    r.http.reply(200, r#"{"error":"slow_down","interval":10}"#);
    let sd = r.send(&mut c, "POST", "/auth/github/poll", json!({"flow": flow}));
    assert_eq!(
        (sd.body["status"].as_str(), sd.body["interval"].as_u64()),
        (Some("slow_down"), Some(10))
    );
    r.advance(10_100);
    github_user_replies(&r, "Owner-GH", 4242);
    let done = r.send(&mut c, "POST", "/auth/github/poll", json!({"flow": flow}));
    // nobody has a second factor yet: only enrolment is allowed, and the API is still closed
    assert_eq!(
        (done.status, done.state()),
        (200, "enroll_required"),
        "{:?}",
        done.body
    );
    assert_eq!(r.guard_status(&c, "GET", false), 401);
    let sent: String = r
        .http
        .requests()
        .iter()
        .map(|q| {
            format!(
                "{} {}",
                q.url,
                String::from_utf8_lossy(q.body.as_deref().unwrap_or(&[]))
            )
        })
        .collect();
    assert!(!sent.contains("client_secret"));
    // the flow is spent
    assert_eq!(
        r.send(&mut c, "POST", "/auth/github/poll", json!({"flow": flow}))
            .body["status"],
        "expired"
    );
}

#[test]
fn github_denied_expired_and_not_on_the_list_all_stop_cleanly() {
    let r = rig();
    let mut c = Client::new();
    let flow = github_start(&r, &mut c).body["flow"].clone();
    r.advance(5_100);
    r.http.reply(200, r#"{"error":"access_denied"}"#);
    assert_eq!(
        r.send(&mut c, "POST", "/auth/github/poll", json!({"flow": flow}))
            .body["status"],
        "denied"
    );
    let flow = github_start(&r, &mut c).body["flow"].clone();
    r.advance(901_000);
    assert_eq!(
        r.send(&mut c, "POST", "/auth/github/poll", json!({"flow": flow}))
            .body["status"],
        "expired"
    );
    // a real GitHub account that is not allowed
    let flow = github_start(&r, &mut c).body["flow"].clone();
    r.advance(5_100);
    github_user_replies(&r, "mallory", 666);
    let p = r.send(&mut c, "POST", "/auth/github/poll", json!({"flow": flow}));
    assert_eq!(
        (p.status, p.body["code"].as_str()),
        (403, Some("not_allowed"))
    );
    assert!(p.session().is_none());
    // not configured at all
    let bare = {
        let mut f = AuthFile {
            public_origin: ORIGIN.into(),
            users: vec![UserEntry {
                id: "a".into(),
                github: Some("a".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        f.github.client_id = None;
        Arc::new(Auth::new(
            AuthConfig::new(f).unwrap(),
            None,
            Arc::new(MemorySecrets::default()),
            Arc::new(FakeHttp::default()),
            Box::new(|| T0),
        ))
    };
    let req = request(
        "POST",
        "/auth/github/start",
        "",
        &Value::Null,
        None,
        "",
        HOST,
        Some(ORIGIN),
    );
    assert_eq!(bare.route(&req).unwrap().resp.status, 404);
}

#[test]
fn a_github_login_is_pinned_to_its_numeric_id() {
    let r = rig();
    let mut c = Client::new();
    for (id, want) in [(4242u64, 200u16), (999, 403)] {
        let flow = github_start(&r, &mut c).body["flow"].clone();
        r.advance(5_100);
        github_user_replies(&r, "owner-gh", id);
        assert_eq!(
            r.send(
                &mut Client::new(),
                "POST",
                "/auth/github/poll",
                json!({"flow": flow})
            )
            .status,
            want,
            "id {id}"
        );
    }
}

#[test]
fn oauth_is_followed_by_a_required_second_factor_when_one_exists() {
    let r = rig();
    let mut authn = Authenticator::new();
    r.enrol(&authn, "owner");
    let mut c = Client::new();
    let flow = github_start(&r, &mut c).body["flow"].clone();
    r.advance(5_100);
    github_user_replies(&r, "owner-gh", 4242);
    let done = r.send(&mut c, "POST", "/auth/github/poll", json!({"flow": flow}));
    assert_eq!(done.state(), "needs_second_factor");
    assert_eq!(
        r.guard_status(&c, "GET", false),
        401,
        "the first factor alone opens nothing"
    );
    // the wrong passkey (another person's, or a stranger's) does not finish it
    let o = r.send(&mut c, "POST", "/auth/second/passkey/options", Value::Null);
    let ch = decode_url(o.body["options"]["challenge"].as_str().unwrap()).unwrap();
    let (cd, ad, sig) = authn.assert(&r.auth.cfg.rp, &ch);
    let v = r.send(&mut c, "POST", "/auth/second/passkey/verify", json!({"ceremony": o.body["ceremony"], "credential": {"id": encode_url(&authn.cred_id), "response": {"clientDataJSON": cd, "authenticatorData": ad, "signature": sig}}}));
    assert_eq!((v.status, v.state()), (200, "signed_in"), "{:?}", v.body);
    assert_eq!(r.guard_status(&c, "GET", false), 200);
    // a passkey ceremony from one session cannot be used by another
    let mut c2 = Client::new();
    let flow = github_start(&r, &mut c2).body["flow"].clone();
    r.advance(5_100);
    github_user_replies(&r, "owner-gh", 4242);
    r.send(&mut c2, "POST", "/auth/github/poll", json!({"flow": flow}));
    let o2 = r.send(&mut c2, "POST", "/auth/second/passkey/options", Value::Null);
    let ch2 = decode_url(o2.body["options"]["challenge"].as_str().unwrap()).unwrap();
    let (cd, ad, sig) = authn.assert(&r.auth.cfg.rp, &ch2);
    let body = json!({"ceremony": o2.body["ceremony"], "credential": {"id": encode_url(&authn.cred_id), "response": {"clientDataJSON": cd, "authenticatorData": ad, "signature": sig}}});
    let stolen = r.send(&mut c, "POST", "/auth/second/passkey/verify", body);
    assert_ne!(stolen.status, 200);
}

#[test]
fn an_authenticator_app_can_be_the_second_factor_and_its_secret_is_write_only() {
    let r = rig();
    // github first (nobody enrolled): enrol an authenticator app
    let mut c = Client::new();
    let flow = github_start(&r, &mut c).body["flow"].clone();
    r.advance(5_100);
    github_user_replies(&r, "owner-gh", 4242);
    assert_eq!(
        r.send(&mut c, "POST", "/auth/github/poll", json!({"flow": flow}))
            .state(),
        "enroll_required"
    );
    let setup = r.send(&mut c, "POST", "/auth/totp/setup", Value::Null);
    let secret = setup.body["secret"].as_str().unwrap().to_string();
    assert!(setup.body["otpauth_uri"]
        .as_str()
        .unwrap()
        .starts_with("otpauth://totp/"));
    let wrong = r.send(
        &mut c,
        "POST",
        "/auth/totp/confirm",
        json!({"code": "000000"}),
    );
    assert_eq!(wrong.status, 401);
    let key = super::b64::decode_base32(&secret).unwrap();
    let code = totp::hotp(&key, r.clock.load(Ordering::SeqCst) / 1000 / 30, 6);
    let ok = r.send(&mut c, "POST", "/auth/totp/confirm", json!({"code": code}));
    assert_eq!((ok.status, ok.state()), (200, "signed_in"), "{:?}", ok.body);
    assert_eq!(
        r.secrets.get("totp-owner").unwrap().as_deref(),
        Some(secret.as_str())
    );
    // the secret is in no later response
    let acct = r.send(&mut c, "GET", "/auth/account", Value::Null);
    let sess = r.send(&mut c, "GET", "/auth/session", Value::Null);
    for body in [acct.body.to_string(), sess.body.to_string()] {
        assert!(
            !body.contains(&secret) && !body.contains("SENTINEL"),
            "{body}"
        );
    }
    assert_eq!(acct.body["totp"], true);
    // a later sign-in through GitHub is held for the code, which works once per window
    r.advance(61_000);
    let mut c2 = Client::new();
    let flow = github_start(&r, &mut c2).body["flow"].clone();
    r.advance(5_100);
    github_user_replies(&r, "owner-gh", 4242);
    assert_eq!(
        r.send(&mut c2, "POST", "/auth/github/poll", json!({"flow": flow}))
            .state(),
        "needs_second_factor"
    );
    let code = totp::hotp(&key, r.clock.load(Ordering::SeqCst) / 1000 / 30, 6);
    assert_eq!(
        r.send(
            &mut c2,
            "POST",
            "/auth/second/totp",
            json!({"code": "123456"})
        )
        .status,
        401
    );
    let v = r.send(&mut c2, "POST", "/auth/second/totp", json!({"code": code}));
    assert_eq!((v.status, v.state()), (200, "signed_in"));
    // the same code cannot be replayed on another session
    let mut c3 = Client::new();
    let flow = github_start(&r, &mut c3).body["flow"].clone();
    r.advance(5_100);
    github_user_replies(&r, "owner-gh", 4242);
    r.send(&mut c3, "POST", "/auth/github/poll", json!({"flow": flow}));
    assert_eq!(
        r.send(&mut c3, "POST", "/auth/second/totp", json!({"code": code}))
            .status,
        401
    );
}

fn google_id_token(email: &str, nonce: &str, verified: bool) -> String {
    let claims = json!({"iss":"https://accounts.google.com","aud":"google-client","nonce":nonce,"exp": (T0 / 1000) + 3000,"email":email,"email_verified":verified});
    format!(
        "{}.{}.sig",
        encode_url(b"{}"),
        encode_url(claims.to_string().as_bytes())
    )
}

fn google_start(r: &Rig) -> (Reply, String, String, String) {
    let mut c = Client::new();
    let s = r.send(&mut c, "GET", "/auth/google/start", Value::Null);
    assert_eq!(s.status, 303, "{:?}", s.body);
    let loc = s.location.clone().unwrap();
    let q = |k: &str| {
        loc.split(&format!("{k}="))
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap()
            .to_string()
    };
    let txn = s
        .set_cookies
        .iter()
        .find_map(|c| {
            c.strip_prefix("__Host-ozbox_oauth=")
                .map(|v| v.split(';').next().unwrap().to_string())
        })
        .unwrap();
    (s, q("state"), q("nonce"), txn)
}

fn google_callback(r: &Rig, txn: Option<&str>, query: &str) -> Reply {
    let cookie = txn.map(|t| format!("__Host-ozbox_oauth={t}"));
    let req = request(
        "GET",
        "/auth/google/callback",
        query,
        &Value::Null,
        cookie.as_deref(),
        "",
        HOST,
        None,
    );
    let out = r.auth.route(&req).unwrap();
    Reply {
        status: out.resp.status,
        body: Value::Null,
        set_cookies: out
            .headers
            .iter()
            .filter(|(k, _)| k == "Set-Cookie")
            .map(|(_, v)| v.clone())
            .collect(),
        location: out
            .headers
            .iter()
            .find(|(k, _)| k == "Location")
            .map(|(_, v)| v.clone()),
    }
}

#[test]
fn google_uses_state_pkce_a_lax_transaction_cookie_and_the_exact_redirect() {
    let r = rig();
    let (s, _, _, txn) = google_start(&r);
    let loc = s.location.unwrap();
    assert!(loc.starts_with("https://accounts.google.com/"));
    assert!(loc.contains("redirect_uri=https%3A%2F%2Fbox.example.com%2Fauth%2Fgoogle%2Fcallback"));
    assert!(loc.contains("code_challenge_method=S256") && !loc.contains("SENTINEL"));
    let oauth_cookie = s
        .set_cookies
        .iter()
        .find(|c| c.starts_with("__Host-ozbox_oauth="))
        .unwrap();
    assert!(
        oauth_cookie.contains("SameSite=Lax")
            && oauth_cookie.contains("HttpOnly")
            && oauth_cookie.contains("Secure")
    );
    // a wrong state, a missing cookie, an error from Google: all end at a fixed address
    let bad = google_callback(&r, Some(&txn), "code=abc&state=WRONG");
    assert_eq!(
        (bad.status, bad.location.as_deref()),
        (303, Some("/?signin=refused"))
    );
    let (_, state, nonce, txn) = google_start(&r);
    assert_eq!(
        google_callback(&r, None, &format!("code=abc&state={state}"))
            .location
            .as_deref(),
        Some("/?signin=expired")
    );
    assert_eq!(
        google_callback(
            &r,
            Some(&txn),
            &format!("error=access_denied&state={state}")
        )
        .location
        .as_deref(),
        Some("/?signin=refused")
    );
    // the transaction is single use
    assert_eq!(
        google_callback(&r, Some(&txn), &format!("code=abc&state={state}"))
            .location
            .as_deref(),
        Some("/?signin=expired")
    );
    let _ = nonce;
    // the happy path: an allowed, verified address
    let (_, state, nonce, txn) = google_start(&r);
    r.http.reply(
        200,
        &json!({"id_token": google_id_token("Owner@Example.com", &nonce, true)}).to_string(),
    );
    let ok = google_callback(&r, Some(&txn), &format!("code=abc&state={state}"));
    assert_eq!((ok.status, ok.location.as_deref()), (303, Some("/")));
    let session = ok
        .set_cookies
        .iter()
        .find(|c| c.starts_with("__Host-ozbox_session="))
        .unwrap();
    assert!(session.contains("SameSite=Strict"));
    // the secret and the verifier went to Google's token endpoint, and nowhere else
    let token_req = r
        .http
        .requests()
        .into_iter()
        .find(|q| q.url.starts_with("https://oauth2.googleapis.com/"))
        .unwrap();
    let body = String::from_utf8_lossy(token_req.body.as_deref().unwrap_or(&[])).into_owned();
    assert!(
        body.contains("client_secret=SENTINEL-GOOGLE-SECRET") && body.contains("code_verifier=")
    );
    // unverified e-mail, a stranger, a wrong nonce
    for (email, nonce_used, verified, want) in [
        ("owner@example.com", None, false, "refused"),
        ("stranger@example.com", None, true, "not_allowed"),
        ("owner@example.com", Some("WRONG"), true, "refused"),
    ] {
        let (_, state, nonce, txn) = google_start(&r);
        r.http.reply(
            200,
            &json!({"id_token": google_id_token(email, nonce_used.unwrap_or(&nonce), verified)})
                .to_string(),
        );
        let res = google_callback(&r, Some(&txn), &format!("code=abc&state={state}"));
        assert_eq!(
            res.location.as_deref(),
            Some(format!("/?signin={want}").as_str()),
            "{email}"
        );
        assert!(!res
            .set_cookies
            .iter()
            .any(|c| c.starts_with("__Host-ozbox_session=") && !c.contains("Max-Age=0")));
    }
    let _ = state;
}

#[test]
fn google_needs_a_stored_secret() {
    let r = rig();
    r.secrets.delete("google-client-secret").unwrap();
    let mut c = Client::new();
    assert_eq!(
        r.send(&mut c, "GET", "/auth/google/start", Value::Null)
            .status,
        404
    );
    let s = r.send(&mut c, "GET", "/auth/session", Value::Null);
    assert_eq!(s.body["methods"]["google"], false);
}

#[test]
fn sessions_expire_when_idle_and_after_seven_days_and_can_be_revoked() {
    let r = rig();
    let mut authn = Authenticator::new();
    r.enrol(&authn, "owner");
    let (mut a, _) = r.passkey_login(&mut authn);
    r.advance(11 * 3_600_000);
    assert_eq!(r.guard_status(&a, "GET", false), 200); // touched: idle clock restarts
    r.advance(13 * 3_600_000);
    assert_eq!(
        r.guard_status(&a, "GET", false),
        401,
        "idle for more than twelve hours"
    );
    // keep one alive past seven days
    let (b, _) = r.passkey_login(&mut authn);
    for _ in 0..16 {
        r.advance(11 * 3_600_000);
        let _ = r.guard_status(&b, "GET", false);
    }
    assert_eq!(
        r.guard_status(&b, "GET", false),
        401,
        "absolute limit of seven days"
    );
    // revoke another session from the account page, and sign out everywhere
    let (mut c1, _) = r.passkey_login(&mut authn);
    let (c2, _) = r.passkey_login(&mut authn);
    let acct = r.send(&mut c1, "GET", "/auth/account", Value::Null);
    let other = acct.body["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["current"] == false)
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        r.send(
            &mut c1,
            "DELETE",
            &format!("/auth/sessions/{other}"),
            Value::Null
        )
        .status,
        200
    );
    assert_eq!(r.guard_status(&c2, "GET", false), 401);
    let (mut d, _) = r.passkey_login(&mut authn);
    assert_eq!(
        r.send(&mut d, "POST", "/auth/signout-all", Value::Null)
            .status,
        200
    );
    assert_eq!(r.guard_status(&c1, "GET", false), 401);
    a.cookie = None;
}

#[test]
fn the_last_second_factor_cannot_be_removed_and_removing_needs_a_fresh_passkey() {
    let r = rig();
    let mut authn = Authenticator::new();
    r.enrol(&authn, "owner");
    let (mut c, _) = r.passkey_login(&mut authn);
    let acct = r.send(&mut c, "GET", "/auth/account", Value::Null);
    let id = acct.body["passkeys"][0]["id"].as_str().unwrap().to_string();
    let del = r.send(
        &mut c,
        "DELETE",
        &format!("/auth/passkeys/{id}"),
        Value::Null,
    );
    assert_eq!(
        (del.status, del.body["code"].as_str()),
        (409, Some("last_factor"))
    );
    r.advance(6 * 60_000);
    let del = r.send(
        &mut c,
        "DELETE",
        &format!("/auth/passkeys/{id}"),
        Value::Null,
    );
    assert_eq!(
        (del.status, del.body["code"].as_str()),
        (403, Some("step_up_required"))
    );
}

#[test]
fn sign_in_attempts_are_limited_per_credential() {
    let r = rig();
    let authn = Authenticator::new();
    r.enrol(&authn, "owner");
    let mut statuses = Vec::new();
    let mut other = Authenticator::new();
    other.cred_id = authn.cred_id.clone(); // wrong key, same credential id
    for _ in 0..12 {
        let mut c = Client::new();
        let o = r.send(&mut c, "POST", "/auth/passkey/login/options", Value::Null);
        let ch = decode_url(o.body["options"]["challenge"].as_str().unwrap()).unwrap();
        let (cd, ad, sig) = other.assert(&r.auth.cfg.rp, &ch);
        let v = r.send(&mut c, "POST", "/auth/passkey/login/verify", json!({"ceremony": o.body["ceremony"], "credential": {"id": encode_url(&authn.cred_id), "response": {"clientDataJSON": cd, "authenticatorData": ad, "signature": sig}}}));
        statuses.push(v.status);
    }
    assert!(statuses.contains(&429), "{statuses:?}");
    assert!(statuses[..10].iter().all(|s| *s == 401));
}

#[test]
fn cloudflare_access_is_trusted_only_after_the_token_is_verified() {
    use ring::rand::SystemRandom;
    use ring::signature::{RsaKeyPair, RSA_PKCS1_SHA256};
    let der =
        super::b64::decode_std(include_str!("testdata/access_test_key.pk8.b64").trim()).unwrap();
    let kp = RsaKeyPair::from_der(&der).unwrap();
    let r = rig_with(Some(AccessCfg {
        team_domain: "team.cloudflareaccess.com".into(),
        audience: "AUD".into(),
    }));
    let (n, e) = der_ints(kp.public().as_ref());
    let jwks = json!({"keys":[{"kid":"k1","kty":"RSA","n":encode_url(&n),"e":encode_url(&e)}]});
    let mk = |email: &str, aud: &str| {
        let h = encode_url(json!({"alg":"RS256","kid":"k1"}).to_string().as_bytes());
        let p = encode_url(json!({"aud":[aud],"iss":"https://team.cloudflareaccess.com","exp":(T0/1000)+600,"email":email}).to_string().as_bytes());
        let mut sig = vec![0u8; kp.public().modulus_len()];
        kp.sign(
            &RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            format!("{h}.{p}").as_bytes(),
            &mut sig,
        )
        .unwrap();
        format!("{h}.{p}.{}", encode_url(&sig))
    };
    let go = |token: Option<&str>| {
        let mut req = request(
            "POST",
            "/auth/access/exchange",
            "",
            &Value::Null,
            None,
            "",
            HOST,
            Some(ORIGIN),
        );
        if let Some(t) = token {
            req.headers
                .insert("cf-access-jwt-assertion".into(), t.into());
        }
        let o = r.auth.route(&req).unwrap();
        (
            o.resp.status,
            o.headers
                .iter()
                .any(|(k, v)| k == "Set-Cookie" && v.starts_with("__Host-ozbox_session=")),
        )
    };
    assert_eq!(go(None), (401, false), "the bare request is nothing");
    assert_eq!(go(Some("a.b.c")), (401, false));
    r.http.reply(200, &jwks.to_string());
    assert_eq!(go(Some(&mk("owner@example.com", "AUD"))), (200, true));
    assert_eq!(go(Some(&mk("owner@example.com", "OTHER"))), (401, false));
    assert_eq!(go(Some(&mk("stranger@example.com", "AUD"))), (403, false));
    // the keys came from the team's own address
    assert!(r
        .http
        .requests()
        .iter()
        .any(|q| q.url == "https://team.cloudflareaccess.com/cdn-cgi/access/certs"));
    // not configured: refused
    assert_eq!(
        rig()
            .auth
            .route(&request(
                "POST",
                "/auth/access/exchange",
                "",
                &Value::Null,
                None,
                "",
                HOST,
                Some(ORIGIN)
            ))
            .unwrap()
            .resp
            .status,
        404
    );
}

#[test]
fn a_destroy_needs_a_fresh_passkey_when_behind_a_sign_in() {
    use ozbox_core::{BoxName, Operation};
    let dir = tempfile::tempdir().unwrap();
    let r = rig();
    let mut authn = Authenticator::new();
    r.enrol(&authn, "owner");
    let (c, _) = r.passkey_login(&mut authn);
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 7878));
    let mut app = crate::serve::App::new(
        Box::new(ozbox_provider_fake::open(dir.path())),
        true,
        addr,
        "tok".into(),
    )
    .with_auth(r.auth.clone());
    let cookie = format!("__Host-ozbox_session={}", c.cookie.clone().unwrap());
    let call = |app: &mut crate::serve::App, method: &str, path: &str, body: Value| {
        let resp = app.handle(&request(
            method,
            path,
            "",
            &body,
            Some(&cookie),
            &c.csrf,
            HOST,
            Some(ORIGIN),
        ));
        (
            resp.status,
            serde_json::from_slice::<Value>(&resp.body).unwrap_or(Value::Null),
        )
    };
    // without a sign-in cookie the API is closed, the local token included
    let bare = app.handle(&request(
        "GET",
        "/v1/boxes",
        "",
        &Value::Null,
        None,
        "",
        HOST,
        Some(ORIGIN),
    ));
    assert_eq!(bare.status, 401);
    let mut tok = request(
        "GET",
        "/v1/boxes",
        "",
        &Value::Null,
        None,
        "",
        HOST,
        Some(ORIGIN),
    );
    tok.headers
        .insert("authorization".into(), "Bearer tok".into());
    assert_eq!(app.handle(&tok).status, 401);
    let create = json!({"operation": {"op": "create", "spec": {"name": "dev", "size": "M", "work_disk_gb": 100, "image": null, "region": null, "from_snapshot": null, "labels": {}}}});
    let (_, plan) = call(&mut app, "POST", "/v1/plans", create);
    assert_eq!(
        call(
            &mut app,
            "POST",
            "/v1/apply",
            json!({"plan_id": plan["plan_id"]})
        )
        .0,
        202
    );
    let _ = (
        BoxName::new("dev").unwrap(),
        Operation::Pause {
            name: BoxName::new("dev").unwrap(),
        },
    );
    let (_, plan) = call(
        &mut app,
        "POST",
        "/v1/plans",
        json!({"operation": {"op": "destroy", "name": "dev", "final_snapshot": true}}),
    );
    let apply = json!({"plan_id": plan["plan_id"], "confirm_name": "dev"});
    // a fresh passkey (just signed in): allowed. Six minutes later: refused, plan kept, retry after confirming.
    r.advance(6 * 60_000);
    let (st, body) = call(&mut app, "POST", "/v1/apply", apply.clone());
    assert_eq!(
        (st, body["code"].as_str()),
        (403, Some("step_up_required")),
        "{body}"
    );
    let mut cc = Client {
        cookie: c.cookie.clone(),
        csrf: c.csrf.clone(),
    };
    let o = r.send(&mut cc, "POST", "/auth/stepup/options", Value::Null);
    let ch = decode_url(o.body["options"]["challenge"].as_str().unwrap()).unwrap();
    let (cd, ad, sig) = authn.assert(&r.auth.cfg.rp, &ch);
    let v = r.send(&mut cc, "POST", "/auth/stepup/verify", json!({"ceremony": o.body["ceremony"], "credential": {"id": encode_url(&authn.cred_id), "response": {"clientDataJSON": cd, "authenticatorData": ad, "signature": sig}}}));
    assert_eq!(v.status, 200);
    // the cookie rotated with the step-up; use the new one
    let cookie2 = format!("__Host-ozbox_session={}", cc.cookie.clone().unwrap());
    let resp = app.handle(&request(
        "POST",
        "/v1/apply",
        "",
        &apply,
        Some(&cookie2),
        &cc.csrf,
        HOST,
        Some(ORIGIN),
    ));
    assert_eq!(resp.status, 202, "{}", String::from_utf8_lossy(&resp.body));
}

#[test]
fn a_local_token_server_reports_its_mode() {
    let dir = tempfile::tempdir().unwrap();
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 7878));
    let mut app = crate::serve::App::new(
        Box::new(ozbox_provider_fake::open(dir.path())),
        true,
        addr,
        "tok".into(),
    );
    let mut req = request(
        "GET",
        "/auth/session",
        "",
        &Value::Null,
        None,
        "",
        "127.0.0.1:7878",
        None,
    );
    req.headers.insert("host".into(), "127.0.0.1:7878".into());
    let resp = app.handle(&req);
    assert_eq!(
        serde_json::from_slice::<Value>(&resp.body).unwrap()["mode"],
        "token"
    );
}

/// The two integers of an `RSAPublicKey` DER (modulus, exponent), leading zero removed.
fn der_ints(der: &[u8]) -> (Vec<u8>, Vec<u8>) {
    fn len(d: &[u8], i: &mut usize) -> usize {
        let b = d[*i];
        *i += 1;
        if b < 0x80 {
            return usize::from(b);
        }
        let n = usize::from(b & 0x7f);
        let v = d[*i..*i + n]
            .iter()
            .fold(0usize, |a, x| (a << 8) | usize::from(*x));
        *i += n;
        v
    }
    let mut i = 1;
    let _ = len(der, &mut i);
    let mut out = Vec::new();
    for _ in 0..2 {
        assert_eq!(der[i], 0x02);
        i += 1;
        let l = len(der, &mut i);
        let mut v = der[i..i + l].to_vec();
        if v[0] == 0 {
            v.remove(0);
        }
        out.push(v);
        i += l;
    }
    (out.remove(0), out.remove(0))
}

#[test]
fn a_restart_does_not_sign_anyone_out_and_a_sign_out_survives_it_too() {
    let r = rig();
    let mut authn = Authenticator::new();
    r.enrol(&authn, "owner");
    let (kept, _) = r.passkey_login(&mut authn);
    let (mut ended, _) = r.passkey_login(&mut authn);
    assert_eq!(r.guard_status(&kept, "GET", false), 200);
    // sign the second one out, then start a new server process over the same state directory
    assert_eq!(
        r.send(&mut ended, "POST", "/auth/signout", Value::Null)
            .status,
        200
    );
    let c = r.clock.clone();
    let restarted = Auth::new(
        r.auth.cfg.clone(),
        r.auth.state_path.clone(),
        r.secrets.clone(),
        r.http.clone(),
        Box::new(move || c.load(Ordering::SeqCst)),
    );
    let probe = |auth: &Auth, c: &Client, method: &str, csrf: bool| {
        let cookie = c
            .cookie
            .as_ref()
            .map(|s| format!("__Host-ozbox_session={s}"));
        let req = request(
            method,
            "/v1/boxes",
            "",
            &Value::Null,
            cookie.as_deref(),
            if csrf { &c.csrf } else { "" },
            HOST,
            Some(ORIGIN),
        );
        auth.guard(&req, true).map_or(200, |r| r.status)
    };
    assert_eq!(
        probe(&restarted, &kept, "GET", false),
        200,
        "still signed in"
    );
    assert_eq!(
        probe(&restarted, &kept, "POST", true),
        200,
        "and the same CSRF token still works"
    );
    assert_eq!(
        probe(&restarted, &ended, "GET", false),
        401,
        "signed out stays out"
    );
}

#[test]
fn a_fresh_step_up_gets_an_approval_the_service_will_spend_once_and_a_stale_one_gets_nothing() {
    use crate::secrets_enc::{EncryptedSecrets, KeyProvider, LocalKekProvider};
    use crate::secrets_service::{listen, serve, Policy, SocketSecrets};

    let r = rig();
    let mut authn = Authenticator::new();
    r.enrol(&authn, "owner");
    let (c, _) = r.passkey_login(&mut authn);
    let cookie = format!("__Host-ozbox_session={}", c.cookie.clone().unwrap());

    // a real secrets service with the supervisor's socket, in a short path (socket paths are short on some systems)
    let dir = tempfile::Builder::new()
        .prefix("ozs")
        .tempdir_in("/tmp")
        .unwrap();
    let kek: Arc<dyn KeyProvider> = Arc::new(LocalKekProvider::random("local").unwrap());
    let store = Arc::new(EncryptedSecrets::new(dir.path().join("s.json"), "box-a", kek).unwrap());
    // one service with both sockets, as on a box: the approval minted on one is spent on the other
    let sup = dir.path().join("sup/s.sock");
    let import_sock = dir.path().join("imp/i.sock");
    let ls = vec![
        (listen(&sup, 0o700).unwrap(), Policy::Supervisor),
        // the opened request of the ingress route: what the dashboard's approval is spent on (an import)
        (listen(&import_sock, 0o700).unwrap(), Policy::Unsealed),
    ];
    let s2 = store.clone();
    std::thread::spawn(move || serve(s2, ls, None, None));

    let fake = tempfile::tempdir().unwrap();
    let mut app = crate::serve::App::new(
        Box::new(ozbox_provider_fake::open(fake.path())),
        true,
        "127.0.0.1:7878".parse().unwrap(),
        "tok".into(),
    )
    .with_secrets(Arc::new(SocketSecrets::supervisor(sup.clone())))
    .with_auth(r.auth.clone());

    let ask = |app: &mut crate::serve::App, body: Value| {
        let rq = request(
            "POST",
            "/v1/secrets/approvals",
            "",
            &body,
            Some(&cookie),
            &c.csrf,
            HOST,
            Some(ORIGIN),
        );
        let resp = app.secrets_approval(&rq);
        (
            resp.status,
            serde_json::from_slice::<Value>(&resp.body).unwrap_or(Value::Null),
        )
    };
    let list = |app: &crate::serve::App| {
        let resp = app.secrets_approvals_list();
        serde_json::from_slice::<Value>(&resp.body).unwrap()
    };

    // before anything is approved the service has no second factor on record; the dashboard's start-up says one exists
    app.sync_second_factor();
    assert_eq!(list(&app)["enrolled"], true);
    assert_eq!(list(&app)["available"], true);

    // a fresh step-up mints a code for one scope, project and environment
    let (st, v) = ask(
        &mut app,
        json!({"scope": "import", "project": "app", "env": "staging"}),
    );
    assert_eq!(st, 200, "{v}");
    let code = v["code"].as_str().unwrap().to_string();
    assert_eq!(
        (
            v["scope"].as_str(),
            v["project"].as_str(),
            v["env"].as_str()
        ),
        (Some("import"), Some("app"), Some("staging"))
    );
    assert!(
        v["expires_in_seconds"].as_u64().unwrap() <= 600
            && v["expires_at_ms"].as_u64().unwrap() > 0
    );
    // a scope that does not exist is refused
    assert_eq!(ask(&mut app, json!({"scope": "root"})).0, 400);

    // the import socket refuses without it and takes it with it, once
    let imp = SocketSecrets::new(import_sock.clone());
    let send = |approval: &str| {
        imp.call(
            json!({"op":"import","project":"app","env":"staging","approval":approval,
            "lines":[{"name":"API_KEY","value":"SENTINEL-approval-0123456789"}]}),
        )
    };
    assert!(send("").is_err());
    assert!(send(&code).is_ok());
    assert!(send(&code).is_err(), "single use");

    // the recent uses name scope, project, environment and how, and hold no code and no value
    let l = list(&app);
    let recent = l["recent"].as_array().unwrap();
    assert!(recent.iter().any(|e| e["outcome"] == "allowed"
        && e["scope"] == "import"
        && e["project"] == "app"
        && e["env"] == "staging"
        && e["via"] == "dashboard-stepup"));
    assert!(recent.iter().any(|e| e["outcome"] == "minted"));
    assert!(recent.iter().any(|e| e["outcome"] == "refused"));
    let text = l.to_string();
    assert!(!text.contains(&code) && !text.contains("SENTINEL"));

    // six minutes on, the passkey is stale: nothing is minted
    r.advance(6 * 60_000);
    let (st, v) = ask(
        &mut app,
        json!({"scope": "import", "project": "app", "env": "staging"}),
    );
    assert_eq!((st, v["code"].as_str()), (403, Some("step_up_required")));
}

/// Behind a sign-in, taking over a browser, resuming one and changing the browsing settings need a passkey shown a moment
/// ago (a security review, 2026-11-10); watching does not. A session id that is not one is refused before anything is
/// looked up.
#[test]
fn browser_take_over_resume_and_settings_need_a_fresh_passkey() {
    let dir = tempfile::tempdir().unwrap();
    let r = rig();
    let mut authn = Authenticator::new();
    r.enrol(&authn, "owner");
    let (c, _) = r.passkey_login(&mut authn);
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 7878));
    let mut app = crate::serve::App::new(
        Box::new(ozbox_provider_fake::open(dir.path())),
        true,
        addr,
        "tok".into(),
    )
    .with_auth(r.auth.clone());
    let cookie = format!("__Host-ozbox_session={}", c.cookie.clone().unwrap());
    let mut call = |method: &str, path: &str, body: Value| {
        let resp = app.handle(&request(
            method,
            path,
            "",
            &body,
            Some(&cookie),
            &c.csrf,
            HOST,
            Some(ORIGIN),
        ));
        (
            resp.status,
            serde_json::from_slice::<Value>(&resp.body).unwrap_or(Value::Null),
        )
    };
    r.advance(6 * 60_000);
    for (m, p) in [
        ("POST", "/v1/browser/sessions/b1-00aa11bb/takeover"),
        ("POST", "/v1/browser/sessions/b1-00aa11bb/resume"),
        ("PUT", "/v1/browser/settings"),
    ] {
        let (st, body) = call(m, p, json!({ "settings": {}, "box": "dev" }));
        assert_eq!(
            (st, body["code"].as_str()),
            (403, Some("step_up_required")),
            "{m} {p}: {body}"
        );
    }
    // watching is not a change: it is not asked for a passkey
    let (_, body) = call("GET", "/v1/browser/sessions/b1-00aa11bb/frame", Value::Null);
    assert_ne!(body["code"].as_str(), Some("step_up_required"), "{body}");
    // a session id that is not one goes no further
    let (st, _) = call(
        "GET",
        "/v1/browser/recordings/dev/..%2fx/shots/0001.jpg",
        Value::Null,
    );
    assert_eq!(st, 404);
}

// ---- roles (ADR 0039) -----------------------------------------------------------------------------------------------

use ozbox_core::roles::Role;

fn person(id: &str, role: Option<Role>) -> UserEntry {
    UserEntry {
        id: id.into(),
        role,
        ..Default::default()
    }
}

/// A dashboard over `users`, with `state_json` already on disk (what an older version wrote) when given.
fn people_rig(users: Vec<UserEntry>, state_json: Option<&str>) -> Rig {
    let dir = tempfile::tempdir().unwrap();
    if let Some(j) = state_json {
        std::fs::write(dir.path().join("auth-state.json"), j).unwrap();
    }
    reopen(users, dir)
}

/// The same dashboard started again over the state already in `dir`.
fn reopen(users: Vec<UserEntry>, dir: tempfile::TempDir) -> Rig {
    let file = AuthFile {
        public_origin: ORIGIN.into(),
        users,
        ..Default::default()
    };
    let clock = Arc::new(AtomicU64::new(T0));
    let http = Arc::new(FakeHttp::default());
    let secrets = Arc::new(MemorySecrets::default());
    let c = clock.clone();
    let auth = Arc::new(Auth::new(
        AuthConfig::new(file).unwrap(),
        Some(dir.path().join("auth-state.json")),
        secrets.clone(),
        http.clone(),
        Box::new(move || c.load(Ordering::SeqCst)),
    ));
    Rig {
        auth,
        clock,
        http,
        secrets,
        _dir: dir,
    }
}

/// What an older version wrote: nobody has a role anywhere.
const STATE_BEFORE_ROLES: &str = r#"{"users":{"owner":{"passkeys":[],"totp":true,"totp_last_step":null,"github_id":null}},"github_client_id":null,"google_client_id":null}"#;

#[test]
fn a_dashboard_made_before_roles_keeps_its_one_person_as_the_owner() {
    let r = people_rig(vec![person("owner", None)], Some(STATE_BEFORE_ROLES));
    assert_eq!(r.auth.roles()["owner"], Role::Owner);
    // signed in, the person is told they are the owner and may do everything
    let (cookie, _) = r.auth.test_session("owner", false);
    let mut c = Client {
        cookie: Some(cookie),
        csrf: String::new(),
    };
    let s = r.send(&mut c, "GET", "/auth/session", Value::Null);
    assert_eq!(s.body["state"], "signed_in");
    assert_eq!(s.body["role"], "owner");
    let can = s.body["can"].as_object().unwrap();
    assert!(
        !can.is_empty() && can.values().all(|v| v == true),
        "{can:?}"
    );
    // and the account page lists them with it
    let a = r.send(&mut c, "GET", "/auth/account", Value::Null);
    assert_eq!(a.body["people"][0]["role"], "owner");
}

#[test]
fn an_older_dashboard_with_several_people_makes_the_first_the_owner_and_the_rest_members() {
    let r = people_rig(
        vec![person("owner", None), person("friend", None)],
        Some(STATE_BEFORE_ROLES),
    );
    let roles = r.auth.roles();
    assert_eq!(
        (roles["owner"], roles["friend"]),
        (Role::Owner, Role::Member)
    );
    // the settings file may say otherwise
    let r = people_rig(
        vec![
            person("a", Some(Role::Viewer)),
            person("b", Some(Role::Owner)),
        ],
        None,
    );
    assert_eq!(
        (r.auth.role_of("a"), r.auth.role_of("b")),
        (Role::Viewer, Role::Owner)
    );
    // somebody not on the list (taken off while signed in) can do nothing
    assert_eq!(r.auth.role_of("stranger"), Role::Viewer);
}

#[test]
fn a_role_change_is_kept_across_a_restart_and_beats_the_settings_file() {
    let users = || {
        vec![
            person("owner", None),
            person("friend", None),
            person("watcher", Some(Role::Viewer)),
        ]
    };
    let r = people_rig(users(), None);
    use super::roles::RoleError;
    assert_eq!(
        r.auth.set_role("nobody", Role::Owner),
        Err(RoleError::Unknown)
    );
    assert_eq!(
        r.auth.set_role("owner", Role::Member),
        Err(RoleError::LastOwner)
    );
    assert_eq!(r.auth.set_role("watcher", Role::Member), Ok(Role::Viewer));
    assert_eq!(r.auth.set_role("friend", Role::Owner), Ok(Role::Member));
    // with a second owner the first may step down
    assert_eq!(r.auth.set_role("owner", Role::Viewer), Ok(Role::Owner));
    assert_eq!(
        r.auth.set_role("friend", Role::Viewer),
        Err(RoleError::LastOwner)
    );
    // started again over the same files: the dashboard's own record wins over the settings file's `viewer`
    let dir = r._dir;
    let r2 = reopen(users(), dir);
    let roles = r2.auth.roles();
    assert_eq!(
        (roles["owner"], roles["friend"], roles["watcher"]),
        (Role::Viewer, Role::Owner, Role::Member)
    );
}

#[test]
fn an_owner_taken_off_the_list_leaves_the_first_person_left_as_the_owner() {
    let r = people_rig(vec![person("owner", None), person("friend", None)], None);
    r.auth.set_role("friend", Role::Owner).unwrap();
    r.auth.set_role("owner", Role::Member).unwrap();
    // the settings file is edited and `friend`, the only owner, is gone
    let dir = r._dir;
    let r2 = reopen(vec![person("owner", None), person("newcomer", None)], dir);
    let roles = r2.auth.roles();
    // `owner` has a stored role of member, `newcomer` the default: nobody is an owner, so the first on the list becomes one
    assert_eq!(roles["owner"], Role::Owner, "never locked out");
    assert_eq!(roles["newcomer"], Role::Member);
}

type Session = (String, String);

fn call(
    app: &mut crate::serve::App,
    who: &Session,
    method: &str,
    path: &str,
    body: Value,
) -> (u16, Value) {
    let cookie = format!("__Host-ozbox_session={}", who.0);
    let resp = app.handle(&request(
        method,
        path,
        "",
        &body,
        Some(&cookie),
        &who.1,
        HOST,
        Some(ORIGIN),
    ));
    (
        resp.status,
        serde_json::from_slice::<Value>(&resp.body).unwrap_or(Value::Null),
    )
}

fn forbidden(r: &(u16, Value)) -> bool {
    r.0 == 403 && r.1["code"] == "role_forbidden"
}

fn app_over(r: &Rig, dir: &std::path::Path) -> crate::serve::App {
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 7878));
    crate::serve::App::new(
        Box::new(ozbox_provider_fake::open(dir)),
        true,
        addr,
        "tok".into(),
    )
    .with_auth(r.auth.clone())
    .with_task_store(Some(dir.join("tasks.json")))
}

fn three_people() -> Rig {
    people_rig(
        vec![
            person("owner", None),
            person("friend", None),
            person("watcher", Some(Role::Viewer)),
        ],
        None,
    )
}

/// A skill's files reach a box's disk and the library only for an owner or a member who may change settings: a viewer and a
/// member are refused at the HTTP layer, and the refusal comes before a large body is read (the guard the server loop runs
/// on a skill upload before it reads one byte of it).
#[test]
fn skills_are_changed_only_by_whoever_may_change_settings_and_the_refusal_comes_before_the_body() {
    let dir = tempfile::tempdir().unwrap();
    let r = three_people();
    let mut app = app_over(&r, dir.path());
    let owner = r.auth.test_session("owner", true);
    let member = r.auth.test_session("friend", true);
    let viewer = r.auth.test_session("watcher", true);
    let writes = [
        ("POST", "/v1/skills"),
        ("DELETE", "/v1/skills/demo"),
        ("POST", "/v1/skills/demo/approve"),
        ("POST", "/v1/skills/demo/restore"),
        ("PUT", "/v1/boxes/dev/skills/demo"),
        ("DELETE", "/v1/boxes/dev/skills/demo"),
    ];
    for (who, label) in [(&viewer, "viewer"), (&member, "member")] {
        for (m, p) in writes {
            let got = call(&mut app, who, m, p, json!({}));
            assert!(forbidden(&got), "{label} {m} {p}: {got:?}");
        }
        // reading what the library and the boxes hold is not refused
        for p in ["/v1/skills", "/v1/skills/holdings", "/v1/boxes/dev/skills"] {
            let got = call(&mut app, who, "GET", p, Value::Null);
            assert!(!forbidden(&got), "{label} GET {p}: {got:?}");
        }
        // the 3 MB-capable upload: the guard says no with an empty body, so a body bigger than the usual limit is never read
        let cookie = format!("__Host-ozbox_session={}", who.0);
        let req = request(
            "POST",
            "/v1/skills",
            "",
            &Value::Null,
            Some(&cookie),
            &who.1,
            HOST,
            Some(ORIGIN),
        );
        let refusal = app.guard(&req, true).unwrap();
        assert_eq!(refusal.status, 403, "{label}");
    }
    for (m, p) in writes {
        let got = call(&mut app, &owner, m, p, json!({}));
        assert!(!forbidden(&got), "owner {m} {p}: {got:?}");
    }
}

/// What each role may do, judged on every request before the route is reached.
#[test]
fn a_viewer_looks_a_member_works_and_only_an_owner_changes_what_governs_the_dashboard() {
    let dir = tempfile::tempdir().unwrap();
    let r = three_people();
    let mut app = app_over(&r, dir.path());
    let owner = r.auth.test_session("owner", true);
    let member = r.auth.test_session("friend", true);
    let viewer = r.auth.test_session("watcher", true);

    // a viewer reads
    for p in [
        "/v1/boxes",
        "/v1/runs",
        "/v1/cost",
        "/v1/audit",
        "/v1/people",
        "/v1/permissions",
    ] {
        let got = call(&mut app, &viewer, "GET", p, Value::Null);
        assert!(!forbidden(&got), "viewer GET {p}: {got:?}");
    }
    // and does nothing that acts, nor looks at a person's screen, files or terminal
    for (m, p) in [
        ("GET", "/v1/browser/sessions"),
        ("GET", "/v1/browser/sessions/b1-00aa11bb/frame"),
        (
            "GET",
            "/v1/browser/recordings/dev/b1-00aa11bb/shots/0001.jpg",
        ),
        ("POST", "/v1/browser/sessions/b1-00aa11bb/takeover"),
        ("PUT", "/v1/browser/settings"),
        ("POST", "/v1/tasks"),
        ("POST", "/v1/approval-requests/a1/approve"),
        ("POST", "/v1/apply"),
        ("POST", "/v1/plans"),
        ("PUT", "/v1/settings"),
        ("POST", "/v1/permissions/grants"),
        ("PUT", "/v1/secrets/some-key"),
        ("POST", "/v1/cost/orphans/apply"),
        ("PUT", "/v1/spend-caps"),
        ("GET", "/v1/boxes/dev/files/list"),
        ("POST", "/v1/boxes/dev/terminal"),
        ("PUT", "/v1/people/owner/role"),
    ] {
        let got = call(&mut app, &viewer, m, p, json!({}));
        assert!(forbidden(&got), "viewer {m} {p}: {got:?}");
        assert!(got.1["message"]
            .as_str()
            .unwrap()
            .contains("a viewer cannot"));
    }

    // a member does the work: it is not refused for its role (what the route then says is its own business)
    for (m, p) in [
        ("GET", "/v1/browser/sessions"),
        ("POST", "/v1/browser/sessions/b1-00aa11bb/takeover"),
        ("POST", "/v1/tasks"),
        ("POST", "/v1/approval-requests/a1/approve"),
        ("POST", "/v1/plans"),
        ("GET", "/v1/boxes/dev/files/list"),
        ("POST", "/v1/boxes/dev/terminal"),
        ("POST", "/v1/orchestrations"),
        ("POST", "/v1/schedules"),
        ("POST", "/v1/chat/messages"),
    ] {
        let got = call(&mut app, &member, m, p, json!({}));
        assert!(!forbidden(&got), "member {m} {p}: {got:?}");
    }
    // but not what governs it
    for (m, p) in [
        ("PUT", "/v1/browser/settings"),
        ("PUT", "/v1/settings"),
        ("PUT", "/v1/permissions"),
        ("POST", "/v1/permissions/grants"),
        ("PUT", "/v1/secrets/some-key"),
        ("DELETE", "/v1/secrets/some-key"),
        ("POST", "/v1/secrets/approvals"),
        ("POST", "/v1/cost/orphans/apply"),
        ("PUT", "/v1/spend-caps"),
        ("PUT", "/v1/approval-policy"),
        ("PUT", "/v1/people/friend/role"),
        ("POST", "/v1/apps/webhooks"),
        ("POST", "/v1/skills/x/approve"),
        ("PUT", "/v1/backups/settings"),
    ] {
        let got = call(&mut app, &member, m, p, json!({}));
        assert!(forbidden(&got), "member {m} {p}: {got:?}");
        assert!(got.1["message"]
            .as_str()
            .unwrap()
            .contains("a member cannot"));
    }

    // an owner is never refused for a role
    for (m, p) in [
        ("PUT", "/v1/browser/settings"),
        ("PUT", "/v1/settings"),
        ("POST", "/v1/permissions/grants"),
        ("PUT", "/v1/secrets/some-key"),
        ("POST", "/v1/browser/sessions/b1-00aa11bb/takeover"),
        ("GET", "/v1/browser/sessions"),
    ] {
        let got = call(&mut app, &owner, m, p, json!({}));
        assert!(!forbidden(&got), "owner {m} {p}: {got:?}");
    }
}

#[test]
fn a_refused_change_is_in_the_audit_chain_and_a_refused_look_is_not() {
    let dir = tempfile::tempdir().unwrap();
    let r = three_people();
    let mut app = app_over(&r, dir.path());
    let viewer = r.auth.test_session("watcher", true);
    let looked = call(
        &mut app,
        &viewer,
        "GET",
        "/v1/browser/sessions",
        Value::Null,
    );
    assert!(forbidden(&looked));
    let log = || std::fs::read_to_string(dir.path().join("tasks.audit.jsonl")).unwrap_or_default();
    assert!(
        !log().contains("permission.deny"),
        "polling must not fill the chain"
    );
    let acted = call(&mut app, &viewer, "POST", "/v1/tasks", json!({}));
    assert!(forbidden(&acted));
    let text = log();
    assert!(
        text.contains("permission.deny") && text.contains("person:watcher"),
        "{text}"
    );
    assert!(
        text.contains("role=viewer") && text.contains("rule=role-viewer"),
        "{text}"
    );
}

#[test]
fn changing_a_role_needs_an_owner_a_fresh_passkey_and_is_audited_and_takes_effect_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let r = three_people();
    let mut app = app_over(&r, dir.path());
    let owner = r.auth.test_session("owner", true);
    let stale_owner = r.auth.test_session("owner", false);
    let member = r.auth.test_session("friend", true);

    // a member cannot, whatever it shows
    assert!(forbidden(&call(
        &mut app,
        &member,
        "PUT",
        "/v1/people/friend/role",
        json!({"role": "owner"})
    )));
    // an owner without a passkey shown a moment ago is asked for one
    let (st, v) = call(
        &mut app,
        &stale_owner,
        "PUT",
        "/v1/people/friend/role",
        json!({"role": "viewer"}),
    );
    assert_eq!((st, v["code"].as_str()), (403, Some("step_up_required")));
    assert_eq!(r.auth.role_of("friend"), Role::Member, "nothing changed");
    // a role that is not one, a person who is not on the list
    let (st, _) = call(
        &mut app,
        &owner,
        "PUT",
        "/v1/people/friend/role",
        json!({"role": "admin"}),
    );
    assert_eq!(st, 400);
    let (st, _) = call(
        &mut app,
        &owner,
        "PUT",
        "/v1/people/nobody/role",
        json!({"role": "viewer"}),
    );
    assert_eq!(st, 404);
    // the dashboard keeps at least one owner
    let (st, v) = call(
        &mut app,
        &owner,
        "PUT",
        "/v1/people/owner/role",
        json!({"role": "member"}),
    );
    assert_eq!((st, v["code"].as_str()), (409, Some("last_owner")));

    // it works, and the person's next request is judged by the new role
    assert!(!forbidden(&call(
        &mut app,
        &member,
        "POST",
        "/v1/tasks",
        json!({})
    )));
    let (st, v) = call(
        &mut app,
        &owner,
        "PUT",
        "/v1/people/friend/role",
        json!({"role": "viewer"}),
    );
    assert_eq!(
        (st, v["role"].as_str(), v["was"].as_str()),
        (200, Some("viewer"), Some("member"))
    );
    assert!(forbidden(&call(
        &mut app,
        &member,
        "POST",
        "/v1/tasks",
        json!({})
    )));
    let log = std::fs::read_to_string(dir.path().join("tasks.audit.jsonl")).unwrap();
    assert!(
        log.contains("person.role")
            && log.contains("member->viewer")
            && log.contains("person:owner"),
        "{log}"
    );

    // the list says who has what
    let (st, v) = call(&mut app, &member, "GET", "/v1/people", Value::Null);
    assert_eq!(st, 200);
    assert_eq!(v["me"]["role"], "viewer");
    assert!(v["can"].as_object().unwrap().values().all(|b| b == false));
    let roles: Vec<(&str, &str)> = v["people"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| (p["id"].as_str().unwrap(), p["role"].as_str().unwrap()))
        .collect();
    assert_eq!(
        roles,
        vec![
            ("owner", "owner"),
            ("friend", "viewer"),
            ("watcher", "viewer")
        ]
    );
}

/// The dashboard learns a person's role from the sign-in status and shows only what they may do.
#[test]
fn the_sign_in_status_tells_the_page_what_the_person_may_do() {
    let r = three_people();
    for (user, role, watch, settings) in [
        ("owner", "owner", true, true),
        ("friend", "member", true, false),
        ("watcher", "viewer", false, false),
    ] {
        let (cookie, _) = r.auth.test_session(user, false);
        let mut c = Client {
            cookie: Some(cookie),
            csrf: String::new(),
        };
        let s = r.send(&mut c, "GET", "/auth/session", Value::Null);
        assert_eq!(s.body["role"], role);
        assert_eq!(s.body["can"]["watch_browser"], watch, "{user}");
        assert_eq!(s.body["can"]["change_settings"], settings, "{user}");
    }
}

#[test]
fn the_code_hosts_open_for_a_member_and_an_owner_and_not_for_a_viewer() {
    let r = three_people();
    for u in ["owner", "friend", "watcher"] {
        r.auth.test_session(u, false);
    }
    // the sessions are stored under the server's key; the code hosts ask by that key
    let keys: Vec<String> = ["owner", "friend", "watcher"]
        .iter()
        .map(|u| r.auth.lock().sessions.of_user(u)[0].0.clone())
        .collect();
    assert!(r.auth.session_may_use_boxes(&keys[0]));
    assert!(r.auth.session_may_use_boxes(&keys[1]));
    assert!(
        !r.auth.session_may_use_boxes(&keys[2]),
        "a viewer's session is alive and still does not open an IDE"
    );
    // and a role taken away stops the very next request
    r.auth.set_role("friend", Role::Viewer).unwrap();
    assert!(!r.auth.session_may_use_boxes(&keys[1]));
    assert!(!r.auth.session_may_use_boxes("no-such-session"));
}

// ---- the review's findings (2026-11-11): the paths that did not go through the request guard ---------------------

/// H1. Who signs in, and how, is set by an owner: the router for `/auth` answers before the dashboard's guard, so it
/// judges the role itself.
#[test]
fn provider_config_is_an_owners_and_a_viewer_or_member_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let r = three_people();
    let mut app = app_over(&r, dir.path());
    let owner = r.auth.test_session("owner", true);
    let member = r.auth.test_session("friend", true);
    let viewer = r.auth.test_session("watcher", true);
    let stale_owner = r.auth.test_session("owner", false);

    for (who, name) in [(&viewer, "viewer"), (&member, "member")] {
        for (path, body) in [
            ("/auth/config/github", json!({"client_id": "Iv1.attacker"})),
            (
                "/auth/config/google",
                json!({"client_id": "attacker", "client_secret": "ATTACKER-SECRET"}),
            ),
        ] {
            let got = call(&mut app, who, "PUT", path, body);
            assert!(forbidden(&got), "{name} {path}: {got:?}");
        }
    }
    // nothing changed: not the id, and not the secret
    let inner = r.auth.lock();
    assert_eq!(inner.state.github_client_id, None);
    assert_eq!(inner.state.google_client_id, None);
    drop(inner);
    assert!(
        r.secrets.get("google-client-secret").unwrap().is_none(),
        "an attacker's secret must not be stored"
    );
    // an owner still needs the passkey
    let got = call(
        &mut app,
        &stale_owner,
        "PUT",
        "/auth/config/github",
        json!({"client_id": "Iv1.mine"}),
    );
    assert_eq!(got.1["code"], "step_up_required");
    // and with it, may
    let got = call(
        &mut app,
        &owner,
        "PUT",
        "/auth/config/github",
        json!({"client_id": "Iv1.mine"}),
    );
    assert_eq!(got.0, 200, "{got:?}");
    assert_eq!(
        r.auth.lock().state.github_client_id.as_deref(),
        Some("Iv1.mine")
    );
    // the account page offers the forms to an owner only, and shows the accounts people sign in with to an owner only
    let a_owner = call(&mut app, &owner, "GET", "/auth/account", Value::Null).1;
    let a_viewer = call(&mut app, &viewer, "GET", "/auth/account", Value::Null).1;
    assert_eq!(a_owner["can_configure_providers"], true);
    assert_eq!(a_viewer["can_configure_providers"], false);
    assert!(
        a_viewer["people"][0].get("github").is_none()
            && a_viewer["people"][0].get("google").is_none()
    );
    assert!(a_owner["people"][0].get("github").is_some());
}

/// A route that the router answers without being on the table is refused, and the table and the router agree.
#[test]
fn every_auth_route_is_on_the_table_with_what_it_needs() {
    let src = include_str!("routes.rs");
    let from = src.find("let r = match (m, segs.as_slice()) {").unwrap();
    let body = &src[from..];
    let to = body.find("_ => Err(Out::err(404").unwrap();
    let mut seen = Vec::new();
    for line in body[..to].lines() {
        let t = line.trim();
        let Some(rest) = t.strip_prefix("(\"") else {
            continue;
        };
        let method = rest.split('"').next().unwrap();
        let open = rest.find('[').unwrap();
        let close = rest.find(']').unwrap();
        let segs: Vec<String> = rest[open + 1..close]
            .split(',')
            .map(|x| x.trim())
            .filter(|x| !x.is_empty())
            .map(|x| {
                x.strip_prefix('"')
                    .and_then(|y| y.strip_suffix('"'))
                    .map(str::to_string)
                    .unwrap_or_else(|| "*".to_string())
            })
            .collect();
        seen.push(format!("{method} {}", segs.join("/")));
    }
    assert!(seen.len() >= 25, "the scan found too few routes: {seen:?}");
    let mut table: Vec<String> = super::routes::AUTH_ROUTES
        .iter()
        .map(|(k, _)| k.to_string())
        .collect();
    seen.sort();
    table.sort();
    assert_eq!(
        seen, table,
        "the router and AUTH_ROUTES must name the same routes"
    );
    // one that is not on the table does not exist, whoever asks
    assert!(super::routes::auth_access("PUT", &["config", "anything-else"]).is_none());
    assert!(super::routes::auth_access("POST", &["config", "github"]).is_none());
}

/// M1. Somebody who is not on the list has no role at all: not even a look.
#[test]
fn a_person_who_is_not_on_the_list_is_signed_out_of_everything() {
    let dir = tempfile::tempdir().unwrap();
    let r = three_people();
    let mut app = app_over(&r, dir.path());
    let ghost = r.auth.test_session("ghost", true);
    assert_eq!(r.auth.role_opt("ghost"), None);
    for p in ["/v1/boxes", "/v1/runs", "/v1/audit", "/v1/cost"] {
        let got = call(&mut app, &ghost, "GET", p, Value::Null);
        assert_eq!(got.0, 401, "{p}: {got:?}");
    }
    assert_eq!(
        call(&mut app, &ghost, "POST", "/v1/tasks", json!({})).0,
        401
    );
    // and a restart over a list without them ends the session they held
    let dir = r._dir;
    let r2 = reopen(vec![person("owner", None)], dir);
    assert!(r2
        .auth
        .who_and_role(&request(
            "GET",
            "/v1/boxes",
            "",
            &Value::Null,
            None,
            "",
            HOST,
            None
        ))
        .is_none());
}

/// M2. A role that could not be written is not reported as changed, and an unreadable state file is not an empty one.
#[test]
fn a_role_that_cannot_be_saved_is_not_changed_and_a_broken_state_file_stops_the_start() {
    use super::roles::RoleError;
    let r = three_people();
    // the state file cannot be replaced: a directory with something in it sits where it goes
    let state = r._dir.path().join("auth-state.json");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::write(state.join("x"), "x").unwrap();
    assert_eq!(
        r.auth.set_role("friend", Role::Viewer),
        Err(RoleError::Save)
    );
    assert_eq!(
        r.auth.role_of("friend"),
        Role::Member,
        "nothing changed in memory either"
    );

    // a state file that exists and is not readable is refused at the start
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("auth-state.json"), "{ this is not json").unwrap();
    let cfg = AuthConfig::new(AuthFile {
        public_origin: ORIGIN.into(),
        users: vec![person("owner", None)],
        ..Default::default()
    })
    .unwrap();
    let got = Auth::try_new(
        cfg,
        Some(dir.path().join("auth-state.json")),
        Arc::new(MemorySecrets::default()),
        Arc::new(FakeHttp::default()),
        Box::new(|| T0),
    );
    let err = got.err().expect("refused");
    assert!(
        err.contains("auth-state.json") && err.contains("will not start"),
        "{err}"
    );
    // no file at all is a first start, not an error
    let cfg = AuthConfig::new(AuthFile {
        public_origin: ORIGIN.into(),
        users: vec![person("owner", None)],
        ..Default::default()
    })
    .unwrap();
    assert!(Auth::try_new(
        cfg,
        Some(tempfile::tempdir().unwrap().path().join("auth-state.json")),
        Arc::new(MemorySecrets::default()),
        Arc::new(FakeHttp::default()),
        Box::new(|| T0),
    )
    .is_ok());
}

/// M3. A role an owner chose at the dashboard belongs to somebody on the list: taken off and added again, a person gets
/// what the file says.
#[test]
fn a_person_removed_and_added_again_gets_the_files_role_not_an_old_owners() {
    let users = || vec![person("owner", None), person("friend", None)];
    let r = people_rig(users(), None);
    r.auth.set_role("friend", Role::Owner).unwrap();
    // `friend` is taken off the list and the dashboard started again
    let r2 = reopen(vec![person("owner", None)], r._dir);
    // and added again, as a viewer
    let r3 = reopen(
        vec![person("owner", None), person("friend", Some(Role::Viewer))],
        r2._dir,
    );
    assert_eq!(r3.auth.role_of("friend"), Role::Viewer);
}

/// H2. Approving a request for production makes the grant the action runs under, so it is judged as making a grant is.
#[test]
fn approving_a_production_request_is_an_owners_and_needs_a_fresh_passkey() {
    let dir = tempfile::tempdir().unwrap();
    let r = three_people();
    let mut app = app_over(&r, dir.path());
    let store = ozbox_core::run::TaskStore::new(dir.path().join("tasks.json"));
    let seed = |id: &str, production: bool| {
        store
            .update(|b| {
                b.approvals.push(ozbox_core::run::ApprovalRequest {
                    id: id.into(),
                    task_id: "t1".into(),
                    kind: ozbox_core::run::ActionKind::AskCommand,
                    action: "psql prod".into(),
                    box_name: "dev".into(),
                    asked_by: "claude-code".into(),
                    production,
                    needs_step_up: production,
                    state: ozbox_core::run::ApprovalState::Pending,
                    created_ms: T0,
                    expires_ms: T0 + 3_600_000,
                    reminders: 0,
                    decided_by: None,
                    decided_ms: None,
                    decided_with_step_up: false,
                    delivered: false,
                    used: false,
                })
            })
            .unwrap();
    };
    let state_of = |id: &str| {
        store
            .load()
            .unwrap()
            .approvals
            .iter()
            .find(|a| a.id == id)
            .map(|a| a.state)
            .unwrap()
    };
    let grants = || store.load().unwrap().perms.grants.len();
    seed("a1", true);
    seed("a2", false);
    let member = r.auth.test_session("friend", true);
    let owner = r.auth.test_session("owner", true);
    let stale_owner = r.auth.test_session("owner", false);

    // a member, with a passkey just shown, still cannot approve production: it is a grant
    let got = call(
        &mut app,
        &member,
        "POST",
        "/v1/approval-requests/a1/approve",
        json!({}),
    );
    assert!(forbidden(&got), "{got:?}");
    assert_eq!(state_of("a1"), ozbox_core::run::ApprovalState::Pending);
    assert_eq!(grants(), 0, "no grant was made");
    // an owner who has not shown a passkey is asked for one
    let got = call(
        &mut app,
        &stale_owner,
        "POST",
        "/v1/approval-requests/a1/approve",
        json!({}),
    );
    assert_eq!(got.1["code"], "step_up_required", "{got:?}");
    assert_eq!(grants(), 0);
    // a member may still deny production, and decide an ordinary request
    let got = call(
        &mut app,
        &member,
        "POST",
        "/v1/approval-requests/a2/approve",
        json!({}),
    );
    assert!(!forbidden(&got), "{got:?}");
    // an owner with a fresh passkey may approve production
    let got = call(
        &mut app,
        &owner,
        "POST",
        "/v1/approval-requests/a1/approve",
        json!({}),
    );
    assert_eq!(got.0, 200, "{got:?}");
    assert_eq!(state_of("a1"), ozbox_core::run::ApprovalState::Approved);
    seed("a3", true);
    let got = call(
        &mut app,
        &member,
        "POST",
        "/v1/approval-requests/a3/deny",
        json!({}),
    );
    assert_eq!(
        got.0, 200,
        "denying production is open to a member: {got:?}"
    );
}

/// Activity names the person who asked, even when the change finishes in somebody else's request, and the audit chain
/// agrees.
#[test]
fn activity_names_the_signed_in_person_who_asked_not_the_one_who_polled() {
    let dir = tempfile::tempdir().unwrap();
    let r = three_people();
    let mut app = app_over(&r, dir.path());
    let owner = r.auth.test_session("owner", true);
    let member = r.auth.test_session("friend", true);

    let create = json!({ "operation": { "op": "create", "spec": {
        "name": "made-by-friend", "size": "S", "work_disk_gb": 50, "image": null,
        "region": null, "from_snapshot": null, "labels": {}
    } } });
    let plan = call(&mut app, &member, "POST", "/v1/plans", create);
    assert_eq!(plan.0, 200, "{plan:?}");
    let applied = call(
        &mut app,
        &member,
        "POST",
        "/v1/apply",
        json!({ "plan_id": plan.1["plan_id"] }),
    );
    assert_eq!(applied.0, 202, "{applied:?}");
    let job = applied.1["job_id"].as_str().unwrap().to_string();
    // the OWNER is the one whose request sees the change finish
    let mut state = String::new();
    for _ in 0..100 {
        let j = call(
            &mut app,
            &owner,
            "GET",
            &format!("/v1/jobs/{job}"),
            Value::Null,
        );
        state = j.1["state"].as_str().unwrap_or("").to_string();
        if state != "running" {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert_eq!(state, "done");
    let feed = call(&mut app, &owner, "GET", "/v1/activity", Value::Null);
    let entries = feed.1["entries"].as_array().cloned().unwrap_or_default();
    let applied_entry = entries
        .iter()
        .find(|e| e["action"] == "apply create")
        .expect("the apply is in Activity");
    assert_eq!(applied_entry["actor"], "friend", "{entries:?}");
    // a person's own change is theirs too
    let current = call(&mut app, &owner, "GET", "/v1/settings", Value::Null);
    let saved = call(
        &mut app,
        &owner,
        "PUT",
        "/v1/settings",
        current.1["settings"].clone(),
    );
    assert_eq!(saved.0, 200, "{saved:?}");
    let feed = call(&mut app, &owner, "GET", "/v1/activity", Value::Null);
    let entries = feed.1["entries"].as_array().cloned().unwrap_or_default();
    let settings_entry = entries
        .iter()
        .find(|e| {
            e["box_name"] == "-" && e["action"].as_str().is_some_and(|a| a.contains("settings"))
        })
        .unwrap_or_else(|| panic!("the settings change is in Activity: {entries:?}"));
    assert_eq!(settings_entry["actor"], "owner", "{entries:?}");
    // the chain agrees: the box change is the member's, and nothing of theirs is written as the owner
    let chain = chain_of(dir.path());
    let create = chain
        .iter()
        .find(|e| e.action == "box.create")
        .unwrap_or_else(|| panic!("the apply is in the chain: {chain:?}"));
    assert_eq!(create.actor, "friend", "{chain:?}");
}

fn chain_of(dir: &std::path::Path) -> Vec<ozbox_core::audit::AuditEntry> {
    ozbox_core::audit::AuditLog::beside(&dir.join("tasks.json"))
        .entries()
        .unwrap()
}

/// R6-1: a finished background change is recorded under the person who asked (or automation), never under whoever's
/// request happened to drain it. Through the poll path, with a viewer polling, reading the chain.
#[test]
fn a_finished_background_change_is_not_credited_to_the_person_who_polled() {
    use crate::serve::worker::Done;
    let dir = tempfile::tempdir().unwrap();
    let r = three_people();
    let mut app = app_over(&r, dir.path());
    let viewer = r.auth.test_session("watcher", true);
    let asked = |who: &str| crate::serve::Actor::Person(who.to_string());
    let orphans = asked("owner");
    assert!(app.submit(Box::new(move || Done::OrphansDeleted {
        now_ms: 1,
        plan_id: "p1".into(),
        results: Vec::new(),
        rescan: crate::orphans::OrphanScan::default(),
        actor: orphans,
    })));
    assert!(app.submit(Box::new(|| Done::ToolsInstalled {
        name: "dev".into(),
        ok: true,
        actor: crate::serve::Actor::Automation,
    })));
    // the viewer's poll is what drains them
    for _ in 0..100 {
        let _ = call(&mut app, &viewer, "GET", "/v1/jobs/none", Value::Null);
        let feed = call(&mut app, &viewer, "GET", "/v1/activity", Value::Null);
        let n = feed.1["entries"].as_array().map_or(0, |e| {
            e.iter()
                .filter(|e| e["action"] == "applied delete-orphans")
                .count()
        });
        if n > 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(30));
    }
    let feed = call(&mut app, &viewer, "GET", "/v1/activity", Value::Null);
    let entries = feed.1["entries"].as_array().cloned().unwrap_or_default();
    let done = entries
        .iter()
        .find(|e| e["action"] == "applied delete-orphans")
        .unwrap_or_else(|| panic!("the delete is in Activity: {entries:?}"));
    assert_eq!(done["actor"], "owner", "{entries:?}");
    assert!(
        entries.iter().all(|e| e["actor"] != "watcher"),
        "nothing is the poller's: {entries:?}"
    );
    let chain = chain_of(dir.path());
    assert!(
        chain.iter().all(|e| e.actor != "watcher"),
        "the chain names nobody who only polled: {chain:?}"
    );
    assert!(
        chain
            .iter()
            .any(|e| e.actor == "owner" && e.action.contains("orphans")),
        "{chain:?}"
    );
}

/// R6-2: a box change is decided, audited and spent as the person making it, so a rule scoped to a member matches them
/// and not the owner, and nothing of the member's is written as the owner.
#[test]
fn a_box_change_is_decided_and_recorded_as_the_signed_in_person() {
    let dir = tempfile::tempdir().unwrap();
    let r = three_people();
    let mut app = app_over(&r, dir.path());
    let owner = r.auth.test_session("owner", true);
    let member = r.auth.test_session("friend", true);
    let rules = json!({ "default_mode": "ask", "modes": [], "browser_hosts": [], "rules": [
        { "id": "r1", "effect": "deny", "action": "*", "scope": "person", "scope_id": "friend" }
    ]});
    let put = call(&mut app, &owner, "PUT", "/v1/permissions", rules);
    assert_eq!(put.0, 200, "{put:?}");
    let create = |name: &str| {
        json!({ "operation": { "op": "create", "spec": {
            "name": name, "size": "S", "work_disk_gb": 50, "image": null,
            "region": null, "from_snapshot": null, "labels": {}
        } } })
    };
    let before = chain_of(dir.path()).len();
    let plan = call(&mut app, &member, "POST", "/v1/plans", create("by-friend"));
    assert_eq!(plan.0, 200, "{plan:?}");
    let refused = call(
        &mut app,
        &member,
        "POST",
        "/v1/apply",
        json!({ "plan_id": plan.1["plan_id"] }),
    );
    assert_eq!(
        (refused.0, refused.1["code"].as_str()),
        (403, Some("permission_denied")),
        "a deny scoped to the member matches them: {refused:?}"
    );
    let chain = chain_of(dir.path());
    let fresh = &chain[before..];
    assert!(!fresh.is_empty(), "the decision is in the chain");
    assert!(
        fresh.iter().all(|e| e.actor == "friend"),
        "the decision names the member, never the owner: {fresh:?}"
    );
    // the same rule does not touch the owner
    let plan = call(&mut app, &owner, "POST", "/v1/plans", create("by-owner"));
    let ok = call(
        &mut app,
        &owner,
        "POST",
        "/v1/apply",
        json!({ "plan_id": plan.1["plan_id"] }),
    );
    assert_eq!(ok.0, 202, "{ok:?}");
}
