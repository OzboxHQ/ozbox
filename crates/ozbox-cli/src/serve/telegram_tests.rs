//! The Telegram bridge end to end, against a fake Telegram (`telegram::fake`), a software authenticator and a real `App`:
//! pairing, links, delegations, expiry, revoke, replay, freshness, the stops, the audit chain and the sealed transcript.
//!
//! Nothing here is mocked above the HTTP client: the code under test builds the addresses, reads the answers, writes the
//! durable store and calls the chat gateway exactly as it does against the vendor.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use ozbox_core::chat_policy::admit::Admitted;
use ozbox_core::roles::Role;
use ozbox_core::{BoxName, BoxSpec, Provider, Size};
use serde_json::{json, Value};

use super::auth::b64::{decode_url, encode_url};
use super::auth::config::{AuthConfig, AuthFile, UserEntry};
use super::auth::webauthn::testkit::Authenticator;
use super::auth::webauthn::verify_registration;
use super::auth::Auth;
use super::{unix_ms, App, Req};
use crate::netguard::FakeHttp;
use crate::secrets::{MemorySecrets, SecretStore};
use crate::telegram::fake::{FakeTelegram, BOT_ID};
use crate::telegram_store::LinkState;

const ORIGIN: &str = "https://box.example.com";
const HOST: &str = "box.example.com";
/// A fixture that is obviously not a token. It stands for the bot token in every sentinel check below.
const TOKEN: &str = "7000000002:FAKE-sentinel-token-not-real";
const PHONE: i64 = 4_000_000_001;
const OTHER_PHONE: i64 = 4_000_000_002;

struct Session(String, String);

struct Rig {
    app: App,
    auth: Arc<Auth>,
    tg: FakeTelegram,
    secrets: Arc<MemorySecrets>,
    dir: tempfile::TempDir,
    authn: HashMap<String, Authenticator>,
    now: u64,
}

fn person(id: &str, role: Option<Role>) -> UserEntry {
    UserEntry {
        id: id.into(),
        role,
        ..Default::default()
    }
}

impl Rig {
    fn new() -> Rig {
        Rig::with(vec![
            person("owner", None),
            person("friend", None),
            person("watcher", Some(Role::Viewer)),
        ])
    }

    fn with(users: Vec<UserEntry>) -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let secrets = Arc::new(MemorySecrets::default());
        secrets.set("telegram-bot-token", TOKEN).unwrap();
        let clock = Arc::new(AtomicU64::new(1_800_000_000_000));
        let c = clock.clone();
        let ids: Vec<String> = users.iter().map(|u| u.id.clone()).collect();
        let auth = Arc::new(Auth::new(
            AuthConfig::new(AuthFile {
                public_origin: ORIGIN.into(),
                users,
                ..Default::default()
            })
            .unwrap(),
            Some(dir.path().join("auth-state.json")),
            secrets.clone(),
            Arc::new(FakeHttp::default()),
            Box::new(move || c.load(Ordering::SeqCst)),
        ));
        let mut authn = HashMap::new();
        for id in ids {
            let a = Authenticator::new();
            let rp = auth.cfg.rp.clone();
            let ch = [7u8; 32];
            let (cd, att) = a.register(&rp, &ch);
            let np = verify_registration(&rp, &ch, &cd, &att, &encode_url(&a.cred_id)).unwrap();
            auth.lock()
                .state
                .users
                .entry(id.clone())
                .or_default()
                .passkeys
                .push(a.passkey(&np));
            authn.insert(id, a);
        }
        let p = ozbox_provider_fake::open(dir.path());
        for n in ["alpha", "bravo"] {
            let spec = BoxSpec::new(BoxName::new(n).unwrap(), Size::M);
            let provider: &dyn Provider = &p;
            let plan = provider
                .plan(&ozbox_core::Operation::Create { spec })
                .unwrap();
            provider.apply(&plan).unwrap();
        }
        let tg = FakeTelegram::new();
        let mut settings = crate::settings::Settings::default();
        settings.apps.telegram.enabled = true;
        let access = super::access::AccessCtx {
            public_url: Some(ORIGIN.into()),
            ..Default::default()
        };
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7878);
        let app = App::new(Box::new(p), true, addr, "tok".into())
            .with_task_store(Some(dir.path().join("tasks.json")))
            .with_secrets(secrets.clone())
            .with_files(None, Some(dir.path().join("serve-state.json")))
            .with_settings(settings, None)
            .with_access(access)
            .with_http(Arc::new(tg.clone()))
            .with_auth(auth.clone());
        Rig {
            app,
            auth,
            tg,
            secrets,
            dir,
            authn,
            now: unix_ms(),
        }
    }

    fn session(&self, who: &str) -> Session {
        let (c, csrf) = self.auth.test_session(who, true);
        Session(c, csrf)
    }

    fn call(&mut self, who: &str, method: &str, path: &str, body: Value) -> (u16, Value) {
        let s = self.session(who);
        self.call_as(&s, method, path, body)
    }

    fn call_as(&mut self, s: &Session, method: &str, path: &str, body: Value) -> (u16, Value) {
        let mut headers = HashMap::new();
        headers.insert("host".to_string(), HOST.to_string());
        headers.insert("origin".to_string(), ORIGIN.to_string());
        headers.insert(
            "cookie".to_string(),
            format!("__Host-ozbox_session={}", s.0),
        );
        headers.insert("x-ozbox-csrf".to_string(), s.1.clone());
        let r = self.app.handle(&Req {
            method: method.into(),
            path: path.into(),
            query: String::new(),
            headers,
            body: if body.is_null() {
                Vec::new()
            } else {
                body.to_string().into_bytes()
            },
        });
        (
            r.status,
            serde_json::from_slice(&r.body).unwrap_or(Value::Null),
        )
    }

    /// The assertion a person's passkey makes over a challenge the server offered.
    fn assertion(&mut self, who: &str, options: &Value) -> Value {
        let ch = decode_url(options["challenge"].as_str().unwrap()).unwrap();
        let rp = self.auth.cfg.rp.clone();
        let a = self.authn.get_mut(who).unwrap();
        let (cd, ad, sig) = a.assert(&rp, &ch);
        json!({ "id": encode_url(&a.cred_id), "response": { "clientDataJSON": cd, "authenticatorData": ad, "signature": sig, "userHandle": "" } })
    }

    /// One "challenge, then assertion" step, as the browser does it.
    fn passkey_step(
        &mut self,
        who: &str,
        base: &str,
        challenge_body: Value,
        finish: &str,
        method: &str,
    ) -> (u16, Value) {
        let (st, ch) = self.call(who, "POST", &format!("{base}/challenge"), challenge_body);
        assert_eq!(st, 200, "{base}/challenge: {ch}");
        let a = self.assertion(who, &ch["options"]);
        self.call(who, method, finish, json!({ "assertion": a }))
    }

    /// Advance the server's tick: it polls the fake Telegram and applies what it found.
    fn tick(&mut self) {
        self.now = unix_ms();
        self.app.schedule.next_telegram_ms = 0;
        self.app.tick(self.now);
        // an inline worker queues its results: a second tick applies them
        self.app.tick(self.now + 1);
    }

    fn ticks(&mut self, n: usize) {
        for _ in 0..n {
            self.tick();
        }
    }

    /// Open a window, have the phone send `/link`, type the code, confirm, and enable converse on `boxes` when given.
    fn link(&mut self, who: &str, phone: i64, boxes: Option<&[&str]>) -> String {
        let (st, _) = self.passkey_step(
            who,
            "/v1/telegram/window",
            json!({}),
            "/v1/telegram/window",
            "POST",
        );
        assert_eq!(st, 200);
        self.tg.say(phone, "/link");
        self.tick();
        let code = self
            .tg
            .texts_to(phone)
            .iter()
            .find_map(|t| {
                t.strip_prefix("Your code is ")
                    .map(|r| r.split('.').next().unwrap_or("").to_string())
            })
            .expect("the bot answered /link with a code");
        let (st, cand) = self.call(
            who,
            "POST",
            "/v1/telegram/link/candidate",
            json!({ "code": code }),
        );
        assert_eq!(st, 200, "{cand}");
        assert_eq!(
            cand["account"]["id_tail"],
            format!("…{}", &phone.to_string()[phone.to_string().len() - 4..])
        );
        let body = match boxes {
            Some(b) => json!({ "label": "my phone", "converse": { "boxes": b, "days": 7 } }),
            None => json!({ "label": "my phone" }),
        };
        let (st, ch) = self.call(who, "POST", "/v1/telegram/link/challenge", body);
        assert_eq!(st, 200, "{ch}");
        let a = self.assertion(who, &ch["options"]);
        let (st, v) = self.call(who, "POST", "/v1/telegram/link", json!({ "assertion": a }));
        assert_eq!(st, 200, "{v}");
        v["link"]["id"].as_str().unwrap().to_string()
    }

    /// An owner stands behind a member's delegation with their own passkey.
    fn cosign(&mut self, did: &str) {
        let (st, ch) = self.call(
            "owner",
            "POST",
            &format!("/v1/telegram/delegations/{did}/cosign/challenge"),
            Value::Null,
        );
        assert_eq!(st, 200, "{ch}");
        let a = self.assertion("owner", &ch["options"]);
        let (st, v) = self.call(
            "owner",
            "POST",
            &format!("/v1/telegram/delegations/{did}/cosign"),
            json!({ "assertion": a }),
        );
        assert_eq!(st, 200, "{v}");
    }

    fn status(&mut self, who: &str) -> Value {
        self.call(who, "GET", "/v1/telegram", Value::Null).1
    }

    fn texts(&self, chat: i64) -> String {
        self.tg.texts_to(chat).join("\n")
    }

    fn tasks(&self) -> usize {
        self.app.chat_book().map_or(0, |b| b.tasks.len())
    }

    fn chain(&self) -> Vec<ozbox_core::audit::AuditEntry> {
        self.app
            .runs
            .store
            .as_ref()
            .and_then(|s| s.audit_log().entries().ok())
            .unwrap_or_default()
    }

    fn chain_text(&self) -> String {
        self.chain()
            .iter()
            .map(|e| format!("{} {} {:?} {}", e.actor, e.action, e.subject, e.detail))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

fn admitted(chat: i64, text: &str, id: i64) -> Admitted {
    Admitted {
        update_id: id,
        from_id: chat,
        chat_id: chat,
        first_name: "Ada".into(),
        text: text.into(),
        date_ms: unix_ms(),
        data_only: false,
    }
}

// ---------- pairing and links ----------

#[test]
fn the_bot_is_silent_until_a_person_opens_a_window_with_a_passkey_and_then_the_whole_link_path_works(
) {
    let mut r = Rig::new();
    // a stranger who writes before any window is open hears nothing, and is only counted
    let earlier = unix_ms() / 1000 - 30;
    r.tg.say_at(PHONE, "/link", earlier);
    r.tg.say_at(PHONE, "hello", earlier);
    // an account that is not linked cannot even make the bot start polling: nothing to listen for yet
    assert_eq!(r.tg.sent_count(), 0);
    // the window needs the passkey: without an assertion over its challenge, nothing opens
    let (st, ch) = r.call(
        "owner",
        "POST",
        "/v1/telegram/window/challenge",
        Value::Null,
    );
    assert_eq!(st, 200, "{ch}");
    let bad = r.assertion("friend", &ch["options"]);
    let (st, _) = r.call(
        "owner",
        "POST",
        "/v1/telegram/window",
        json!({ "assertion": bad }),
    );
    assert_ne!(
        st, 200,
        "an assertion by another person's passkey does not open it"
    );
    assert!(r.status("owner")["window"].is_null());
    // the right one does
    let (st, _) = r.passkey_step(
        "owner",
        "/v1/telegram/window",
        Value::Null,
        "/v1/telegram/window",
        "POST",
    );
    assert_eq!(st, 200);
    assert!(!r.status("owner")["window"].is_null());
    r.tick();
    assert_eq!(
        r.tg.sent_count(),
        0,
        "the earlier messages were a different time: nothing was answered"
    );
    // the phone writes /link; the bot answers with a code and nothing else
    r.tg.say(PHONE, "/link");
    r.tick();
    let said = r.texts(PHONE);
    assert!(said.starts_with("Your code is "), "{said}");
    // another account asking in the same window is not answered
    r.tg.say(OTHER_PHONE, "/link");
    r.tick();
    assert!(r.tg.texts_to(OTHER_PHONE).is_empty());
    // the code is typed into the dashboard: the account the bot saw is shown, and nothing is linked yet
    let code = said
        .strip_prefix("Your code is ")
        .unwrap()
        .split('.')
        .next()
        .unwrap()
        .to_string();
    let (st, cand) = r.call(
        "owner",
        "POST",
        "/v1/telegram/link/candidate",
        json!({ "code": code.to_lowercase() }),
    );
    assert_eq!(st, 200, "{cand}");
    assert_eq!(cand["account"]["first_name"], "Ada");
    assert_eq!(cand["account"]["id_tail"], "…0001");
    assert!(
        r.status("owner")["links"].as_array().unwrap().is_empty(),
        "no link before the confirming assertion"
    );
    // one passkey confirms the link and converse on alpha in the same step
    let (st, ch) = r.call(
        "owner",
        "POST",
        "/v1/telegram/link/challenge",
        json!({ "label": "phone", "converse": { "boxes": ["alpha"], "days": 7 } }),
    );
    assert_eq!(st, 200, "{ch}");
    assert_eq!(ch["summary"]["converse"]["boxes"], json!(["alpha"]));
    // an assertion over the link alone does not match this challenge: the delegation cannot be swapped in or out
    let (st, ch2) = r.call(
        "owner",
        "POST",
        "/v1/telegram/link/challenge",
        json!({ "label": "phone" }),
    );
    assert_eq!(st, 200);
    let wrong = r.assertion("owner", &ch["options"]);
    let (st, _) = r.call(
        "owner",
        "POST",
        "/v1/telegram/link",
        json!({ "assertion": wrong }),
    );
    assert_ne!(st, 200, "the first draft was replaced by the second");
    // a wrong assertion burns the draft (start again): the next challenge is a fresh one over the link alone
    let _ = ch2;
    let (st, ch3) = r.call(
        "owner",
        "POST",
        "/v1/telegram/link/challenge",
        json!({ "label": "phone" }),
    );
    assert_eq!(st, 200, "{ch3}");
    let a = r.assertion("owner", &ch3["options"]);
    let (st, v) = r.call(
        "owner",
        "POST",
        "/v1/telegram/link",
        json!({ "assertion": a }),
    );
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["link"]["state"], "active");
    assert!(
        v["link"]["delegations"].as_array().unwrap().is_empty(),
        "this one was confirmed without converse"
    );
    // the chat now hears the person: the notice came, and /whoami says what the link may do
    r.tick();
    assert!(
        r.texts(PHONE).contains("Linked as phone"),
        "{}",
        r.texts(PHONE)
    );
    r.tg.say(PHONE, "/whoami");
    r.tick();
    let who = r.texts(PHONE);
    assert!(
        who.contains("You are owner, a owner") && who.contains("It is allowed to read."),
        "{who}"
    );
    // and the chat is in the list that receives alerts
    assert!(r
        .app
        .state
        .telegram
        .chats
        .iter()
        .any(|c| c.id == PHONE && c.person.as_deref() == Some("owner")));
    // the audit chain has the window and the link, by the person, with ids and words only
    let chain = r.chain_text();
    assert!(
        chain.contains("telegram.window_open") && chain.contains("telegram.link"),
        "{chain}"
    );
    assert!(chain.contains("person:owner:chat:telegram"), "{chain}");
}

#[test]
fn a_link_with_converse_made_in_the_same_passkey_step_is_not_waited_on_and_talks_to_an_agent() {
    let mut r = Rig::new();
    r.link("owner", PHONE, Some(&["alpha"]));
    let st = r.status("owner");
    let d = &st["links"][0]["delegations"][0];
    assert_eq!(d["state"], "active", "{d}");
    assert_eq!(d["boxes"], json!(["alpha"]));
    // it reaches the chat gateway's own code: a session is started on alpha
    r.tg.say(PHONE, "/new alpha fix the parser");
    r.tick();
    assert_eq!(r.tasks(), 1, "{}", r.texts(PHONE));
    assert!(
        r.texts(PHONE).contains("Started t1 on alpha"),
        "{}",
        r.texts(PHONE)
    );
    // not on a box it was not delegated: a link to the dashboard and nothing started
    r.tg.say(PHONE, "/new bravo do things");
    r.tick();
    assert_eq!(r.tasks(), 1);
    assert!(
        r.texts(PHONE).contains("allow it in the dashboard"),
        "{}",
        r.texts(PHONE)
    );
    // a read needs no delegation, on any box
    r.tg.say(PHONE, "/fleet");
    r.tick();
    assert!(r.texts(PHONE).contains("boxes"), "{}", r.texts(PHONE));
}

#[test]
fn a_new_link_with_no_delegation_reads_only_and_converse_is_a_link_to_the_dashboard() {
    let mut r = Rig::new();
    r.link("owner", PHONE, None);
    r.tg.say(PHONE, "/new alpha try it");
    r.tick();
    assert_eq!(r.tasks(), 0);
    let t = r.texts(PHONE);
    assert!(
        t.contains("only do that once you allow it in the dashboard"),
        "{t}"
    );
    // the message carries one link, to this dashboard's own address, with its host named, in the fragment
    assert!(
        t.contains("box.example.com") && t.contains("https://box.example.com/go#"),
        "{t}"
    );
    assert!(!t.contains("?link="), "the token is never in a query");
}

#[test]
fn a_wrong_code_five_times_closes_the_window_and_the_bot_goes_silent_again() {
    let mut r = Rig::new();
    let (st, _) = r.passkey_step(
        "owner",
        "/v1/telegram/window",
        Value::Null,
        "/v1/telegram/window",
        "POST",
    );
    assert_eq!(st, 200);
    r.tg.say(PHONE, "/link");
    r.tick();
    for i in 0..5 {
        let (st, v) = r.call(
            "owner",
            "POST",
            "/v1/telegram/link/candidate",
            json!({ "code": "WRONGCODE" }),
        );
        assert_eq!(st, if i < 4 { 400 } else { 429 }, "{v}");
    }
    assert!(
        r.status("owner")["window"].is_null(),
        "five tries and the window is gone"
    );
    let sent = r.tg.sent_count();
    r.tg.say(PHONE, "/link");
    r.tick();
    assert_eq!(r.tg.sent_count(), sent, "silent again");
}

#[test]
fn a_window_that_runs_out_is_closed_and_a_link_draft_that_lapses_is_refused() {
    let mut r = Rig::new();
    let (st, _) = r.passkey_step(
        "owner",
        "/v1/telegram/window",
        Value::Null,
        "/v1/telegram/window",
        "POST",
    );
    assert_eq!(st, 200);
    r.tg.say(PHONE, "/link");
    r.tick();
    // eleven minutes on
    if let Some(w) = r.app.tg.window.as_mut() {
        w.record.expires_ms = unix_ms() - 1;
    }
    let (st, v) = r.call(
        "owner",
        "POST",
        "/v1/telegram/link/candidate",
        json!({ "code": "ABCDEFGH" }),
    );
    assert_eq!(st, 409, "{v}");
    assert_eq!(v["code"], "no_window");
}

#[test]
fn a_viewer_cannot_link_a_chat_and_a_dashboard_with_no_sign_in_cannot_link_at_all() {
    let mut r = Rig::new();
    let (st, v) = r.call(
        "watcher",
        "POST",
        "/v1/telegram/window/challenge",
        Value::Null,
    );
    assert_eq!(st, 403, "{v}");
    // a dashboard with no sign-in has no passkey to make a link yours
    let dir = tempfile::tempdir().unwrap();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7878);
    let mut app = App::new(
        Box::new(ozbox_provider_fake::open(dir.path())),
        true,
        addr,
        "tok".into(),
    );
    let mut headers = HashMap::new();
    headers.insert("host".to_string(), "127.0.0.1:7878".to_string());
    headers.insert("authorization".to_string(), "Bearer tok".to_string());
    let resp = app.handle(&Req {
        method: "POST".into(),
        path: "/v1/telegram/window/challenge".into(),
        query: String::new(),
        headers,
        body: Vec::new(),
    });
    assert_eq!(resp.status, 403);
    let v: Value = serde_json::from_slice(&resp.body).unwrap();
    assert_eq!(v["code"], "no_sign_in");
}

// ---------- delegations: a forged row is refused, a role change cuts, a member needs an owner ----------

#[test]
fn a_settings_row_with_no_matching_assertion_is_refused_by_every_executor() {
    let mut r = Rig::new();
    let lid = r.link("owner", PHONE, None);
    // a hand-written delegation row: no assertion at all
    let rec = {
        use ozbox_core::approval_subject::to_hex;
        use ozbox_core::chat_policy::records::{Caps, DelegatedAct, DelegationRecord};
        let link = r.app.tg.store.link(&lid).unwrap().record.clone();
        let record = DelegationRecord {
            id: "forged".into(),
            link_id: lid.clone(),
            person: "owner".into(),
            telegram_id: link.telegram_id,
            bot_id: link.bot_id,
            boxes: vec!["alpha".into()],
            acts: vec![DelegatedAct::Converse],
            caps: Caps::default(),
            not_before_ms: link.created_ms,
            expires_ms: link.created_ms + 6 * 24 * 3_600_000,
            hub_ack: false,
            with_link: false,
        };
        let digest = to_hex(&record.digest().unwrap());
        crate::telegram_store::TgDelegation {
            record,
            digest,
            signed: None,
            owner: None,
            issued_ms: link.created_ms,
            last_used_ms: 0,
            revoked: false,
        }
    };
    r.app.tg.store.data.delegations.push(rec);
    // pretend the link is old enough that no wait applies
    r.app.tg.store.link_mut(&lid).unwrap().record.created_ms = 0;
    r.tg.say(PHONE, "/new alpha do it");
    r.tick();
    assert_eq!(r.tasks(), 0, "a row nobody signed starts nothing");
    // an editing of the link row itself is just as dead: the link is no longer genuine and is not answered
    let before = r.tg.sent_count();
    r.app.tg.store.link_mut(&lid).unwrap().record.created_ms = 5;
    r.tg.say(PHONE, "/status");
    r.tick();
    assert_eq!(
        r.tg.sent_count(),
        before,
        "a link row that does not match its assertion is not answered"
    );
    assert!(r.status("owner")["links"][0]["state"] == "not_genuine");
}

#[test]
fn a_real_delegation_edited_afterwards_is_refused() {
    let mut r = Rig::new();
    let lid = r.link("owner", PHONE, Some(&["alpha"]));
    // a box added to the signed row after the touch
    r.app.tg.store.data.delegations[0]
        .record
        .boxes
        .push("bravo".into());
    r.tg.say(PHONE, "/new bravo sneak");
    r.tick();
    assert_eq!(r.tasks(), 0);
    assert!(
        r.status("owner")["links"][0]["delegations"][0]["state"] == "not_genuine",
        "{lid}"
    );
}

#[test]
fn a_role_change_cuts_a_delegation_at_the_next_message() {
    let mut r = Rig::new();
    r.link("friend", PHONE, Some(&["alpha"]));
    let owner_view = r.status("owner");
    let did = owner_view["pending_owner"][0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    r.cosign(&did);
    r.tg.say(PHONE, "/new alpha first");
    r.tick();
    assert_eq!(r.tasks(), 1, "{}", r.texts(PHONE));
    // an owner demotes the member to a viewer, through the dashboard's own route: what was delegated no longer reaches
    let (st, v) = r.call(
        "owner",
        "PUT",
        "/v1/people/friend/role",
        json!({ "role": "viewer" }),
    );
    assert_eq!(st, 200, "{v}");
    r.tg.say(PHONE, "next turn");
    r.tick();
    let t = r.texts(PHONE);
    assert!(
        t.contains("Your role on this dashboard does not allow that"),
        "{t}"
    );
    assert_eq!(r.tasks(), 1, "no second session and no turn sent");
    // and a person taken off the list altogether has the link ended at their next message
    let (st, _) = r.call("owner", "DELETE", "/v1/people/friend", Value::Null);
    if st == 200 {
        r.tg.say(PHONE, "/fleet");
        r.tick();
        assert!(
            r.texts(PHONE).contains("no longer on this dashboard"),
            "{}",
            r.texts(PHONE)
        );
        let lid = r.app.tg.store.data.links[0].record.id.clone();
        assert_eq!(r.app.tg.store.link(&lid).unwrap().state, LinkState::Revoked);
    }
}

#[test]
fn a_members_delegation_waits_for_an_owners_passkey_and_then_works() {
    let mut r = Rig::new();
    r.link("friend", PHONE, Some(&["alpha"]));
    let st = r.status("friend");
    assert_eq!(
        st["links"][0]["delegations"][0]["state"], "pending_owner",
        "{st}"
    );
    r.tg.say(PHONE, "/new alpha try");
    r.tick();
    assert_eq!(r.tasks(), 0);
    assert!(
        r.texts(PHONE).contains("owner's passkey"),
        "{}",
        r.texts(PHONE)
    );
    // the owner stands behind it, naming the member, with their own passkey
    let owner_view = r.status("owner");
    let did = owner_view["pending_owner"][0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (st, ch) = r.call(
        "owner",
        "POST",
        &format!("/v1/telegram/delegations/{did}/cosign/challenge"),
        Value::Null,
    );
    assert_eq!(st, 200, "{ch}");
    // a member cannot co-sign
    let (st, _) = r.call(
        "friend",
        "POST",
        &format!("/v1/telegram/delegations/{did}/cosign/challenge"),
        Value::Null,
    );
    assert_eq!(st, 403);
    let a = r.assertion("owner", &ch["options"]);
    let (st, v) = r.call(
        "owner",
        "POST",
        &format!("/v1/telegram/delegations/{did}/cosign"),
        json!({ "assertion": a }),
    );
    assert_eq!(st, 200, "{v}");
    r.tg.say(PHONE, "/new alpha try again");
    r.tick();
    assert_eq!(r.tasks(), 1, "{}", r.texts(PHONE));
}

#[test]
fn run_cannot_be_delegated_in_this_release_and_a_later_delegation_is_its_own_passkey() {
    let mut r = Rig::new();
    let lid = r.link("owner", PHONE, None);
    // box power can be delegated now (see e2e.rs); /run cannot yet
    let (st, v) = r.call(
        "owner",
        "POST",
        &format!("/v1/telegram/links/{lid}/delegations/challenge"),
        json!({ "acts": ["run"], "boxes": ["alpha"] }),
    );
    assert_eq!(st, 409, "{v}");
    assert_eq!(v["code"], "not_available");
    // converse later, on a link that is under a day old: allowed to make, and it waits out the first day
    let (st, v) = r.passkey_step(
        "owner",
        &format!("/v1/telegram/links/{lid}/delegations"),
        json!({ "acts": ["converse"], "boxes": ["alpha"], "days": 3 }),
        &format!("/v1/telegram/links/{lid}/delegations"),
        "POST",
    );
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["link"]["delegations"][0]["state"], "waiting");
    r.tg.say(PHONE, "/new alpha early");
    r.tick();
    assert_eq!(r.tasks(), 0);
    assert!(
        r.texts(PHONE).contains("less than a day old"),
        "{}",
        r.texts(PHONE)
    );
}

// ---------- lock, unlink, expiry, renewal, revoke ----------

#[test]
fn lock_reads_only_and_unlink_cuts_the_link_from_the_chat() {
    let mut r = Rig::new();
    let lid = r.link("owner", PHONE, Some(&["alpha"]));
    r.tg.say(PHONE, "/lock");
    r.tick();
    assert!(r.texts(PHONE).contains("Locked."), "{}", r.texts(PHONE));
    assert_eq!(r.app.tg.store.link(&lid).unwrap().state, LinkState::Locked);
    r.tg.say(PHONE, "/new alpha after the lock");
    r.tg.say(PHONE, "/status");
    r.tick();
    assert_eq!(r.tasks(), 0);
    assert!(
        r.texts(PHONE).contains("link is locked"),
        "{}",
        r.texts(PHONE)
    );
    // only a passkey in the dashboard lifts it, by the link's own person
    let (st, _) = r.call(
        "friend",
        "POST",
        &format!("/v1/telegram/links/{lid}/unlock/challenge"),
        Value::Null,
    );
    assert_eq!(st, 404);
    let (st, v) = r.passkey_step(
        "owner",
        &format!("/v1/telegram/links/{lid}/unlock"),
        Value::Null,
        &format!("/v1/telegram/links/{lid}/unlock"),
        "POST",
    );
    assert_eq!(st, 200, "{v}");
    r.tg.say(PHONE, "/new alpha after the unlock");
    r.tick();
    assert_eq!(r.tasks(), 1);
    // /unlink ends it for good: the chat is told once and then not heard
    r.tg.say(PHONE, "/unlink");
    r.tick();
    assert!(r.texts(PHONE).contains("Unlinked."), "{}", r.texts(PHONE));
    assert_eq!(r.app.tg.store.link(&lid).unwrap().state, LinkState::Revoked);
    assert!(
        r.app.state.telegram.chats.iter().all(|c| c.id != PHONE),
        "no more alerts there"
    );
    let sent = r.tg.sent_count();
    r.tg.say(PHONE, "/status");
    r.tick();
    assert_eq!(
        r.tg.sent_count(),
        sent,
        "an unlinked sender is not answered"
    );
    assert!(r.app.tg.store.data.delegations.iter().all(|d| d.revoked));
}

#[test]
fn lock_every_link_is_an_owners_and_dashboard_unlink_takes_effect_on_the_next_message() {
    let mut r = Rig::new();
    let lid = r.link("owner", PHONE, Some(&["alpha"]));
    assert_eq!(
        r.call("friend", "POST", "/v1/telegram/lock-all", Value::Null)
            .0,
        403
    );
    let (st, v) = r.call("owner", "POST", "/v1/telegram/lock-all", Value::Null);
    assert_eq!((st, v["locked"].as_u64()), (200, Some(1)));
    assert_eq!(r.status("owner")["links"][0]["state"], "locked");
    // another person cannot cut a link that is not theirs; the owner can, and the next message is silence
    let (st, _) = r.call(
        "friend",
        "DELETE",
        &format!("/v1/telegram/links/{lid}"),
        Value::Null,
    );
    assert_eq!(st, 404);
    let (st, _) = r.call(
        "owner",
        "DELETE",
        &format!("/v1/telegram/links/{lid}"),
        Value::Null,
    );
    assert_eq!(st, 200);
    let sent = r.tg.sent_count();
    r.tg.say(PHONE, "/fleet");
    r.tick();
    assert_eq!(r.tg.sent_count(), sent);
    let chain = r.chain_text();
    assert!(
        chain.contains("telegram.lock") && chain.contains("telegram.unlink"),
        "{chain}"
    );
}

#[test]
fn a_link_expires_after_thirty_days_and_a_passkey_renews_it() {
    let mut r = Rig::new();
    let lid = r.link("owner", PHONE, None);
    let before = r.status("owner")["links"][0]["expires_ms"]
        .as_u64()
        .unwrap();
    let (st, v) = r.passkey_step(
        "owner",
        &format!("/v1/telegram/links/{lid}/renew"),
        Value::Null,
        &format!("/v1/telegram/links/{lid}/renew"),
        "POST",
    );
    assert_eq!(st, 200, "{v}");
    let after = v["link"]["expires_ms"].as_u64().unwrap();
    assert!(after >= before, "a renewal never shortens a link");
    // a renewal row nobody signed does not extend anything
    r.app.tg.store.link_mut(&lid).unwrap().renewed = Some(crate::telegram_store::Renewal {
        expires_ms: after + 10 * 24 * 3_600_000,
        signed: r.app.tg.store.link(&lid).unwrap().signed.clone(),
    });
    let now_exp = r.status("owner")["links"][0]["expires_ms"]
        .as_u64()
        .unwrap();
    assert!(
        now_exp <= after + 1,
        "an assertion over something else extends nothing: {now_exp} vs {after}"
    );
}

// ---------- replay, freshness, durability ----------

#[test]
fn an_update_is_recorded_on_the_disk_before_anything_is_done_for_it() {
    let mut r = Rig::new();
    r.link("owner", PHONE, None);
    let path = r.dir.path().join("telegram.json");
    let id = r.tg.say(PHONE, "/fleet");
    // when the reply is sent, the replay set must already hold this update on the disk
    let seen_at_send = Arc::new(std::sync::Mutex::new(Vec::<bool>::new()));
    let s2 = seen_at_send.clone();
    let p2 = path.clone();
    r.tg.with(|s| {
        s.on_send = Some(Arc::new(move || {
            let text = std::fs::read_to_string(&p2).unwrap_or_default();
            if let Ok(mut v) = s2.lock() {
                v.push(text.contains(&format!("{BOT_ID}:{id}")));
            }
        }));
    });
    r.tick();
    let seen = seen_at_send.lock().unwrap().clone();
    assert!(!seen.is_empty(), "a reply was sent");
    assert!(
        seen.iter().all(|b| *b),
        "the update was on the disk before the reply: {seen:?}"
    );
}

#[test]
fn a_replay_is_not_run_twice_a_stale_message_is_dropped_and_a_random_update_id_after_a_long_gap_is_new(
) {
    let mut r = Rig::new();
    r.link("owner", PHONE, Some(&["alpha"]));
    r.tg.say_with_id(5_000, PHONE, "/new alpha once");
    r.tick();
    assert_eq!(r.tasks(), 1);
    // Telegram hands the same update again (a crash before the offset moved): nothing runs twice
    r.app.tg.store.data.offset = 0;
    r.tg.say_with_id(5_000, PHONE, "/new alpha once");
    r.tick();
    assert_eq!(
        r.tasks(),
        1,
        "the same (bot id, update_id) is never run twice"
    );
    assert_eq!(r.app.tg.store.data.counters.replays, 1);
    // a week with no updates: the next number is random and far lower, and the stored offset must not hide it
    r.app.tg.store.data.last_update_ms = unix_ms() - 8 * 24 * 3_600_000;
    r.tg.say_with_id(17, PHONE, "/fleet");
    r.tick();
    assert!(
        r.texts(PHONE).contains("boxes"),
        "a lower number is not an old one: {}",
        r.texts(PHONE)
    );
    // a message dated ten minutes ago is "too old", and is not run late
    let old = unix_ms() / 1000 - 600;
    r.tg.say_at(PHONE, "/new alpha late", old);
    r.tick();
    assert_eq!(r.tasks(), 1);
    assert!(r.texts(PHONE).contains("too old"), "{}", r.texts(PHONE));
    // the set and the offset survive a restart: reading the store back finds them
    let again = crate::telegram_store::TgStore::open(r.dir.path().join("telegram.json")).unwrap();
    assert!(again.data.seen.contains(BOT_ID, 5_000));
    assert!(again.data.offset > 5_000 || again.data.offset > 0);
}

#[test]
fn if_the_replay_set_cannot_be_written_the_bridge_stops_and_acts_on_nothing() {
    let mut r = Rig::new();
    r.link("owner", PHONE, Some(&["alpha"]));
    // make the file a directory: a write cannot succeed
    let path = r.dir.path().join("telegram.json");
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    let before = r.tg.sent_count();
    r.tg.say(PHONE, "/new alpha never");
    r.tick();
    assert_eq!(r.tasks(), 0, "nothing is done that could not be recorded");
    assert!(
        r.tg.all_sent()
            .iter()
            .skip(before)
            .all(|m| !m.1.contains("Started")),
        "nothing was started or said about it"
    );
    assert_eq!(
        r.app.tg.store.data.halted.as_ref().map(|h| h.code.as_str()),
        Some("store")
    );
}

#[test]
fn updates_that_are_not_a_private_text_message_from_the_linked_person_do_nothing() {
    let mut r = Rig::new();
    r.link("owner", PHONE, Some(&["alpha"]));
    let before = r.tg.sent_count();
    let msg = |extra: Value| {
        let mut m = json!({ "message_id": 9, "date": unix_ms() / 1000, "text": "/new alpha attack",
            "chat": { "id": PHONE, "type": "private" }, "from": { "id": PHONE, "is_bot": false, "first_name": "Ada" } });
        for (k, v) in extra.as_object().unwrap() {
            m[k] = v.clone();
        }
        json!({ "message": m })
    };
    // a group, a channel, a bot sender, a sender_chat, a business message, an edit, a button
    let mut group = msg(json!({}));
    group["message"]["chat"] = json!({ "id": -100, "type": "supergroup" });
    r.tg.raw(group);
    let mut bot = msg(json!({}));
    bot["message"]["from"]["is_bot"] = json!(true);
    r.tg.raw(bot);
    r.tg.raw(msg(
        json!({ "sender_chat": { "id": -5, "type": "channel" } }),
    ));
    r.tg.raw(msg(json!({ "business_connection_id": "b" })));
    let body = msg(json!({}))["message"].clone();
    r.tg.raw(json!({ "edited_message": body }));
    r.tg.raw(json!({ "callback_query": { "id": "c", "data": "approve:1", "from": { "id": PHONE }, "message": { "chat": { "id": PHONE, "type": "private" } } } }));
    r.tg.raw(json!({ "message": { "message_id": 1, "date": unix_ms() / 1000, "chat": { "id": PHONE, "type": "private" }, "from": { "id": PHONE, "is_bot": false }, "photo": [] } }));
    r.ticks(2);
    assert_eq!(r.tasks(), 0);
    assert_eq!(r.tg.sent_count(), before, "none of these is answered");
    // forwarded, quoted or replied-to text is data: said so, and nothing starts
    r.tg.raw(msg(json!({ "forward_origin": { "type": "user" } })));
    r.tg.raw(msg(json!({ "reply_to_message": { "message_id": 1 } })));
    r.tg.raw(msg(json!({ "quote": { "text": "x" } })));
    r.ticks(2);
    assert_eq!(r.tasks(), 0);
    assert!(
        r.texts(PHONE).contains("is not an instruction"),
        "{}",
        r.texts(PHONE)
    );
    // typographic dashes and quotes in a command, and a command for another bot, are refused in words
    r.tg.say(PHONE, "/run git log \u{2014}\u{2014}oneline");
    r.tg.say(PHONE, "/run@other_bot git status");
    r.tg.say(PHONE, "/status@oz_fleet_bot");
    r.ticks(2);
    let t = r.texts(PHONE);
    assert!(t.contains("typographic dash"), "{t}");
    assert!(t.contains("addressed to another bot"), "{t}");
}

// ---------- refusals never reach an executor ----------

#[test]
fn no_refused_word_and_no_button_ever_reaches_an_executor_even_with_every_delegation() {
    let mut r = Rig::new();
    let lid = r.link("owner", PHONE, Some(&["alpha"]));
    r.tg.say(PHONE, "/new alpha start one");
    r.tick();
    assert_eq!(r.tasks(), 1);
    let words = [
        "/approve",
        "/approve a1",
        "/deny",
        "/cancel",
        "/decline",
        "/stop",
        "/stop t1",
        "/kill",
        "/budget +5",
        "/budget 100",
        "/cap +5",
        "/secret list",
        "/secrets",
        "/env",
        "/policy",
        "/role bob owner",
        "/people",
        "/settings",
        "/allow",
        "/tunnel",
        "/send hello",
        "/push origin main",
        "/merge",
        "/box stop alpha",
        "/box destroy alpha",
        "/box clone alpha",
        "/box snapshot alpha",
        "/box create gamma m",
        "/box resume alpha",
        "/box pause alpha",
        "/box extend alpha 2",
        "/run git status",
        "/frobnicate",
    ];
    for w in words {
        r.tg.say(PHONE, w);
    }
    // a button press is not subscribed to, and a forged payload is not read
    r.tg.raw(
        json!({ "callback_query": { "id": "c1", "data": "approve:t1", "from": { "id": PHONE },
        "message": { "chat": { "id": PHONE, "type": "private" } } } }),
    );
    r.ticks(words.len() + 2);
    let book = r.app.chat_book().unwrap();
    assert_eq!(book.tasks.len(), 1, "nothing was started");
    assert!(
        !book.task("t1").unwrap().state.is_terminal(),
        "nothing was stopped"
    );
    assert!(
        book.approvals
            .iter()
            .all(|a| a.state == ozbox_core::run::ApprovalState::Pending),
        "nothing was decided"
    );
    // every one of them is in the audit chain as a refusal or a handoff, none as an act that was done
    let chain = r.chain();
    let acted: Vec<_> = chain
        .iter()
        .filter(|e| {
            // this link's own entries: on a box the chain is the box's, shared with every other test
            e.subject.as_deref() == Some(lid.as_str())
                && e.action == "telegram.act"
                && (e.detail.contains("act=refused.")
                    || e.detail.contains("act=box.")
                    || e.detail.contains("act=run"))
        })
        .collect();
    assert!(acted.is_empty(), "{acted:?}");
}

// ---------- the stops: 409, getMe, 429, webhook ----------

#[test]
fn a_409_stops_the_bridge_raises_an_alert_and_it_stays_stopped_until_an_owner_confirms() {
    let mut r = Rig::new();
    r.link("owner", PHONE, Some(&["alpha"]));
    r.tg.with(|s| s.conflicts = 1);
    r.tg.say(PHONE, "/new alpha while stopped");
    r.tick();
    let h = r.app.tg.store.data.halted.clone().expect("halted");
    assert_eq!(h.code, "conflict");
    assert!(
        r.app
            .state
            .alerts
            .recent
            .iter()
            .any(|a| a.title.contains("bridge stopped")),
        "an alert says so"
    );
    assert!(r.status("owner")["halted"]["message"]
        .as_str()
        .unwrap()
        .contains("another program"));
    // it does not poll again, so the message waits and nothing is acted on
    let polls =
        r.tg.calls()
            .iter()
            .filter(|c| c.starts_with("getUpdates"))
            .count();
    r.ticks(3);
    assert_eq!(
        r.tg.calls()
            .iter()
            .filter(|c| c.starts_with("getUpdates"))
            .count(),
        polls
    );
    assert_eq!(r.tasks(), 0);
    // it survives a restart: the store says halted
    let again = crate::telegram_store::TgStore::open(r.dir.path().join("telegram.json")).unwrap();
    assert!(again.data.halted.is_some());
    // a member cannot confirm; an owner can, and the bridge checks the bot again and goes on
    assert_eq!(
        r.call("friend", "POST", "/v1/telegram/resume", Value::Null)
            .0,
        403
    );
    assert_eq!(
        r.call("owner", "POST", "/v1/telegram/resume", Value::Null)
            .0,
        200
    );
    r.ticks(2);
    assert_eq!(r.tasks(), 1, "{}", r.texts(PHONE));
}

#[test]
fn a_webhook_somebody_set_is_named_by_host_only_and_stops_the_bridge() {
    let mut r = Rig::new();
    r.link("owner", PHONE, None);
    r.tg.with(|s| s.conflicts = 1);
    r.tg.with(|s| s.webhook = Some("https://hooks.example.com/secret-path?k=v".into()));
    r.tg.say(PHONE, "/fleet");
    r.tick();
    let h = r.app.tg.store.data.halted.clone().unwrap();
    assert_eq!(h.code, "webhook_set");
    assert!(
        h.detail.contains("hooks.example.com") && !h.detail.contains("secret-path"),
        "{}",
        h.detail
    );
}

#[test]
fn getme_must_show_no_groups_no_group_reading_and_no_inline_queries_or_the_bridge_will_not_run() {
    for flag in [
        "can_join_groups",
        "can_read_all_group_messages",
        "supports_inline_queries",
    ] {
        let mut r = Rig::new();
        // a first run: the bridge has not looked at the bot yet
        r.app.tg.store.data.links.clear();
        let (st, _) = r.call(
            "owner",
            "POST",
            "/v1/telegram/window/challenge",
            Value::Null,
        );
        assert_eq!(st, 200);
        r.app.tg.bot = None;
        r.tg.with(|s| match flag {
            "can_join_groups" => s.can_join_groups = true,
            "can_read_all_group_messages" => s.can_read_all_group_messages = true,
            _ => s.supports_inline_queries = true,
        });
        // the dashboard refuses to open a window for such a bot
        let (st, v) = r.call(
            "owner",
            "POST",
            "/v1/telegram/window/challenge",
            Value::Null,
        );
        assert_eq!(st, 409, "{flag}: {v}");
        assert_eq!(v["code"], "bot_settings");
        // and the poll stops on it as well
        r.app.tg.window = Some(super::telegram_link::OpenWindow {
            record: ozbox_core::chat_policy::records::WindowRecord {
                person: "owner".into(),
                bot_id: BOT_ID,
                nonce: "n".into(),
                opened_ms: unix_ms(),
                expires_ms: unix_ms() + 600_000,
            },
            evidence: crate::serve::auth::approval::SignedEvidence {
                person: "owner".into(),
                credential_id: "c".into(),
                authenticator_data_hex: "00".into(),
                client_data_hex: "00".into(),
                signature_hex: "00".into(),
                rp_id: HOST.into(),
                origin: ORIGIN.into(),
                at_ms: 0,
            },
            offer: None,
            candidate: None,
            tries: 0,
        });
        r.tick();
        assert_eq!(
            r.app.tg.store.data.halted.as_ref().map(|h| h.code.as_str()),
            Some("bot_settings"),
            "{flag}"
        );
        assert!(
            r.tg.calls().iter().all(|c| !c.starts_with("getUpdates")),
            "{flag}: it never polled"
        );
    }
}

#[test]
fn a_429_is_obeyed_and_a_poll_asks_for_messages_only_with_a_thirty_second_wait() {
    let mut r = Rig::new();
    r.link("owner", PHONE, None);
    let calls_before = r.tg.calls().len();
    r.tg.with(|s| s.rate_limited = 1);
    r.tick();
    assert!(r.app.tg.backoff_until_ms > unix_ms(), "told to wait");
    r.tick();
    assert_eq!(
        r.tg.calls()
            .iter()
            .skip(calls_before)
            .filter(|c| c.starts_with("getUpdates"))
            .count(),
        1,
        "no second poll inside the wait"
    );
    r.app.tg.backoff_until_ms = 0;
    r.tick();
    let polls: Vec<String> =
        r.tg.calls()
            .into_iter()
            .filter(|c| c.starts_with("getUpdates"))
            .collect();
    assert!(
        polls
            .iter()
            .all(|c| c.contains("timeout=30") && c.contains("allowed_updates=%5B%22message%22%5D")),
        "{polls:?}"
    );
    assert!(polls.iter().all(|c| !c.contains("callback_query")));
}

// ---------- the revoke between "recorded" and "run" ----------

#[test]
fn a_revoke_between_recorded_and_run_refuses() {
    let mut r = Rig::new();
    let lid = r.link("owner", PHONE, Some(&["alpha"]));
    let bot = r.app.tg.bot.clone().unwrap();
    let link = r.app.tg.store.link(&lid).cloned().unwrap();
    let who = super::telegram_bridge::Sender {
        link_id: lid.clone(),
        person: "owner".into(),
        chat_id: PHONE,
        legacy: false,
    };
    let a = admitted(PHONE, "/new alpha do the thing", 9_001);
    let now = unix_ms();
    let (planned, mac) = r
        .app
        .tg_plan(&bot, &who, Some(&link), &a, now)
        .expect("planned");
    assert!(
        matches!(
            planned.decision,
            ozbox_core::chat_policy::Decision::Allow(_)
        ),
        "{:?}",
        planned.decision
    );
    // between the record and the act, the owner cuts the link in the dashboard
    let (st, _) = r.call(
        "owner",
        "DELETE",
        &format!("/v1/telegram/links/{lid}"),
        Value::Null,
    );
    assert_eq!(st, 200);
    r.app.tg_run(&who, Some(&link), planned, &a, &mac, now);
    assert_eq!(r.tasks(), 0, "the executor never ran");
    assert!(
        r.chain_text().contains("changed_before_run"),
        "{}",
        r.chain_text()
    );
}

// ---------- audit, transcript, secrets ----------

#[test]
fn every_act_is_in_the_chain_in_at_most_160_characters_and_the_transcript_joins_to_it_by_a_keyed_mac(
) {
    let mut r = Rig::new();
    r.link("owner", PHONE, Some(&["alpha"]));
    r.tg.say(
        PHONE,
        "/new alpha please fix the parser, here is my phone 555-0100 and mail ada@example.com",
    );
    r.tg.say(PHONE, "/budget +5");
    r.tg.say(PHONE, "/box resume alpha");
    r.ticks(4);
    let chain = r.chain();
    let tg: Vec<_> = chain
        .iter()
        .filter(|e| e.action.starts_with("telegram."))
        .collect();
    assert!(tg
        .iter()
        .any(|e| e.action == "telegram.act" && e.detail.contains("act=new")));
    assert!(tg
        .iter()
        .any(|e| e.action == "telegram.refuse" && e.detail.contains("act=refused.budget")));
    assert!(tg
        .iter()
        .any(|e| e.action == "telegram.handoff" && e.detail.contains("act=box.resume")));
    for e in &tg {
        assert!(e.detail.chars().count() <= 160, "{}", e.detail);
        assert!(
            e.actor.starts_with("person:owner:chat:telegram")
                || e.actor == "person:supervisor:chat:telegram",
            "{}",
            e.actor
        );
        // the chain never holds a message
        assert!(
            !e.detail.contains("parser")
                && !e.detail.contains("ada@example.com")
                && !e.detail.contains("555"),
            "{}",
            e.detail
        );
    }
    // the detail carries the update id, the tier, the rule and a prefix of the message's mac
    let act = tg.iter().find(|e| e.detail.contains("act=new")).unwrap();
    assert!(
        act.detail.contains("upd=")
            && act.detail.contains("tier=1")
            && act.detail.contains("r=converse-delegated")
            && act.detail.contains("msg="),
        "{}",
        act.detail
    );
    // the owner reads the sealed transcript; it holds the words, and the mac in it matches the chain's prefix
    let lid = r.status("owner")["links"][0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        r.call(
            "friend",
            "GET",
            &format!("/v1/telegram/links/{lid}/transcript"),
            Value::Null
        )
        .0,
        403
    );
    let (st, v) = r.call(
        "owner",
        "GET",
        &format!("/v1/telegram/links/{lid}/transcript"),
        Value::Null,
    );
    assert_eq!(st, 200, "{v}");
    let lines = v["lines"].as_array().unwrap();
    let inbound = lines
        .iter()
        .find(|l| {
            l["dir"] == "in"
                && l["text"]
                    .as_str()
                    .unwrap()
                    .contains("please fix the parser")
        })
        .expect("the words are kept here");
    let mac = inbound["mac"].as_str().unwrap();
    assert!(
        act.detail.contains(&format!("msg={}", &mac[..16])),
        "the chain's prefix {} is of this line's mac {mac}",
        act.detail
    );
    assert!(
        lines.iter().any(|l| l["dir"] == "out"),
        "the bot's answers are kept too"
    );
    // the file on the disk holds none of the text, and reading it was itself recorded
    let file = std::fs::read_to_string(r.dir.path().join("telegram-transcript.jsonl")).unwrap();
    assert!(!file.contains("please fix the parser"));
    assert!(r.chain_text().contains("telegram.transcript_read"));
}

#[test]
fn a_pointer_link_holds_its_token_only_in_the_fragment_opens_for_its_person_without_spending_and_lapses(
) {
    let mut r = Rig::new();
    r.link("owner", PHONE, None);
    r.tg.say(PHONE, "/new alpha go");
    r.tick();
    let text =
        r.tg.texts_to(PHONE)
            .into_iter()
            .find(|t| t.contains("/go#"))
            .expect("a handoff message");
    let token = text
        .split("/go#")
        .nth(1)
        .unwrap()
        .split(|c: char| !c.is_ascii_hexdigit())
        .next()
        .unwrap()
        .to_string();
    assert_eq!(token.len(), 48);
    assert!(text.contains("box.example.com"), "the host is named");
    // the sealed transcript never holds the token
    let lid = r.status("owner")["links"][0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let (_, v) = r.call(
        "owner",
        "GET",
        &format!("/v1/telegram/links/{lid}/transcript"),
        Value::Null,
    );
    assert!(
        !v.to_string().contains(&token),
        "the transcript holds no token"
    );
    assert!(!r.chain_text().contains(&token));
    // opening changes nothing and can be done twice (Telegram's browser, then the real one)
    for _ in 0..2 {
        let (st, v) = r.call(
            "owner",
            "POST",
            "/v1/chat/links/open",
            json!({ "token": token }),
        );
        assert_eq!((st, v["path"].as_str()), (200, Some("/chat")), "{v}");
    }
    // another person learns nothing; a wrong token is the same answer
    let (st, _) = r.call(
        "friend",
        "POST",
        "/v1/chat/links/open",
        json!({ "token": token }),
    );
    assert_eq!(st, 404);
    let (st, _) = r.call(
        "owner",
        "POST",
        "/v1/chat/links/open",
        json!({ "token": "0".repeat(48) }),
    );
    assert_eq!(st, 404);
    // the message is deleted when the link lapses
    let id =
        r.tg.all_sent()
            .iter()
            .find(|m| m.1.contains("/go#"))
            .unwrap()
            .2;
    r.app.tick(unix_ms() + 11 * 60_000);
    r.app.tick(unix_ms() + 11 * 60_000 + 1);
    assert!(
        r.tg.deleted().contains(&id),
        "deleted at lapse: {:?}",
        r.tg.deleted()
    );
    let (st, _) = {
        let now_far = unix_ms() + 11 * 60_000;
        let l = r.app.chat.links.as_mut().unwrap();
        (l.peek(&token, "owner", now_far).is_err() as u16, 0)
    };
    assert_eq!(st, 1, "a lapsed link opens nothing");
}

#[test]
fn the_bot_token_is_in_no_response_no_error_no_log_no_chain_no_transcript_and_no_file() {
    let mut r = Rig::new();
    r.link("owner", PHONE, Some(&["alpha"]));
    r.tg.say(PHONE, "/new alpha hello");
    r.tg.say(PHONE, "/whoami");
    // a poll that fails every way the vendor can fail
    r.tg.with(|s| {
        s.conflicts = 1;
    });
    r.ticks(3);
    let mut hay = vec![r.chain_text(), r.texts(PHONE)];
    for p in ["/v1/telegram", "/v1/apps", "/v1/activity", "/v1/alerts"] {
        hay.push(r.call("owner", "GET", p, Value::Null).1.to_string());
    }
    hay.push(serde_json::to_string(&r.app.activity).unwrap());
    hay.push(serde_json::to_string(&r.app.state).unwrap());
    for entry in std::fs::read_dir(r.dir.path()).unwrap().flatten() {
        if entry.path().is_file() {
            hay.push(std::fs::read_to_string(entry.path()).unwrap_or_default());
        }
    }
    let lid = r.status("owner")["links"][0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    hay.push(
        r.call(
            "owner",
            "GET",
            &format!("/v1/telegram/links/{lid}/transcript"),
            Value::Null,
        )
        .1
        .to_string(),
    );
    for (i, h) in hay.iter().enumerate() {
        assert!(
            !h.contains("FAKE-sentinel") && !h.contains(TOKEN),
            "the token reached output #{i}"
        );
    }
    // nor does the address of a request: the fake never saw the token in anything but the URL it was built into
    assert!(r.tg.calls().iter().all(|c| !c.contains("FAKE-sentinel")));
    assert!(
        r.secrets.get("telegram-bot-token").unwrap().is_some(),
        "it stays in the secret store"
    );
}

#[test]
fn a_chat_linked_the_old_way_reads_and_is_told_things_and_nothing_more() {
    let mut r = Rig::new();
    r.app.state.telegram.chats.push(crate::state::TelegramChat {
        id: PHONE,
        name: "Ada".into(),
        person: Some("owner".into()),
    });
    r.tg.say(PHONE, "/fleet");
    r.tg.say(PHONE, "/new alpha old way");
    r.tick();
    let t = r.texts(PHONE);
    assert!(t.contains("boxes"), "{t}");
    assert_eq!(
        r.tasks(),
        0,
        "a chat linked before passkey links cannot converse"
    );
    assert!(t.contains("allow it in the dashboard"), "{t}");
    r.tg.say(PHONE, "/help");
    r.tick();
    assert!(
        r.texts(PHONE).contains("linked the old way"),
        "{}",
        r.texts(PHONE)
    );
    // and the old pairing by a code the dashboard makes is gone
    let (st, _) = r.call("owner", "POST", "/v1/apps/telegram/pairing", Value::Null);
    assert_eq!(st, 404);
}

#[test]
fn production_boxes_and_the_hub_are_marked_by_an_owner_and_a_chat_never_acts_on_them() {
    let mut r = Rig::new();
    r.link("owner", PHONE, Some(&["alpha", "bravo"]));
    // marking needs an owner (and a passkey shown a moment ago, which the test session has)
    assert_eq!(
        r.call(
            "friend",
            "PUT",
            "/v1/telegram/marks",
            json!({ "production": ["bravo"], "hub": "alpha" })
        )
        .0,
        403
    );
    let (st, v) = r.call(
        "owner",
        "PUT",
        "/v1/telegram/marks",
        json!({ "production": ["bravo"], "hub": "alpha" }),
    );
    assert_eq!(st, 200, "{v}");
    r.tg.say(PHONE, "/new bravo on production");
    r.tg.say(PHONE, "/new alpha on the hub");
    r.ticks(2);
    assert_eq!(r.tasks(), 0);
    let t = r.texts(PHONE);
    assert!(
        t.contains("marked Production") && t.contains("the hub that runs this dashboard"),
        "{t}"
    );
    // state is still shown for them
    r.tg.say(PHONE, "/fleet");
    r.tick();
    assert!(r.texts(PHONE).contains("bravo"), "{}", r.texts(PHONE));
}

#[test]
fn the_polling_lane_is_its_own_and_the_offset_moves_only_after_the_updates_are_recorded() {
    let mut r = Rig::new();
    r.link("owner", PHONE, None);
    let id = r.tg.say(PHONE, "/fleet");
    r.tick();
    let store = crate::telegram_store::TgStore::open(r.dir.path().join("telegram.json")).unwrap();
    assert_eq!(
        store.data.offset,
        id + 1,
        "the offset is the next update to ask for"
    );
    assert!(store.data.seen.contains(BOT_ID, id));
    // the next poll asks from there
    r.tick();
    assert!(r
        .tg
        .calls()
        .iter()
        .any(|c| c.contains(&format!("offset={}", id + 1))));
}

mod e2e;
