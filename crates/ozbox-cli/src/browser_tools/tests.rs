#![allow(clippy::unwrap_used)]
//! The browser tools through the tool host, as an agent calls them: the permission engine decides each call, approvals pause,
//! refusals hold, a challenge goes to a person, the audit chain verifies and holds no typed value. The browser is a real
//! Chromium and the site is the local test site; the box is a directory. Skips when there is no Chromium, unless
//! `OZBOX_REQUIRE_BROWSER=1` (how CI runs it).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use ozbox_browser::testsite::{self, Site};
use ozbox_core::permissions::ActorKind;
use ozbox_core::run::{ApprovalState, TaskStore};
use ozbox_core::supervisor;
use serde_json::{json, Value};

use super::*;
use crate::host_tools::{BoxFacts, HostTools};
use crate::mcp::HostScope;
use crate::orch_tools::{Role, Session};

struct ProdFacts;
impl BoxFacts for ProdFacts {
    fn exists(&self, b: &str) -> bool {
        b == "alpha"
    }
    fn production(&self, _b: &str) -> bool {
        true
    }
}

/// A session opened under standing permission on a PRODUCTION box is one a plain terminal agent could not have
/// opened. Once standing has ended (the same key now enrols as a plain terminal agent) its reads are refused too. A session
/// not opened under standing, the same agent while standing still holds, and a sandbox box are all unaffected.
#[test]
fn a_session_opened_under_standing_on_production_is_not_read_by_a_plain_terminal_agent() {
    let r = rig();
    let key = "terminal-10-1-1";
    r.host.plant_session_as("s1", "alpha", Some(key), true);
    r.host.plant_session_as("s2", "alpha", Some(key), false);
    let mut prod = HostTools::new(
        r.tools.store.clone(),
        Arc::clone(&r.tools.backend),
        Arc::new(ProdFacts),
    );
    prod.ask_wait = Duration::from_millis(30);
    prod.poll = Duration::from_millis(5);
    prod.browser = Some(Arc::clone(&r.host));
    let call = |t: &HostTools, actor: ActorKind, session: &str| {
        let h = HostScope {
            run_id: None,
            actor,
            session: Some(key.to_string()),
            ..scope()
        };
        t.call(
            &agent(),
            Some(&h),
            "browser_snapshot",
            &json!({ "session": session }),
            1_000,
        )
    };
    let e = call(&prod, ActorKind::Terminal, "s1").unwrap_err();
    assert!(
        e.message()
            .contains("opened while standing permission was on"),
        "{e:?}"
    );
    let not_that = |r: Result<Value, ToolError>, why: &str| {
        assert!(
            !matches!(&r, Err(e) if e.message().contains("opened while standing permission was on")),
            "{why}: {r:?}"
        );
    };
    not_that(
        call(&prod, ActorKind::TerminalStanding, "s1"),
        "standing still holds",
    );
    not_that(
        call(&prod, ActorKind::Terminal, "s2"),
        "not opened under standing",
    );
    not_that(call(&r.tools, ActorKind::Terminal, "s1"), "a sandbox box");
}

/// The wiring: `browser_open` called by a standing enrolment marks the session it makes, and by anyone else does not.
#[test]
fn browser_open_marks_a_session_opened_under_standing_and_only_that() {
    if !have_browser() {
        return;
    }
    let r = rig();
    r.tools
        .store
        .update(|b| b.perms.default_mode = ozbox_core::permissions::Mode::Auto)
        .unwrap();
    let key = "terminal-10-1-1";
    let open_as = |actor: ActorKind| {
        let h = HostScope {
            run_id: None,
            actor,
            session: Some(key.to_string()),
            standing_until_ms: (actor == ActorKind::TerminalStanding).then_some(u64::MAX),
            ..scope()
        };
        r.tools
            .call(&agent(), Some(&h), "browser_open", &json!({}), 1_000)
            .unwrap()["session"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let standing = open_as(ActorKind::TerminalStanding);
    let plain = open_as(ActorKind::Terminal);
    assert!(lk(&r.host.sessions)[&standing].opened_standing);
    assert!(!lk(&r.host.sessions)[&plain].opened_standing);
    r.host.close(&standing).unwrap();
    r.host.close(&plain).unwrap();
}

/// A session that finishes opening after the door changed (the opener's key is no longer the current one) is
/// closed, not left holding a browser slot that nobody can drive; one opened under a current key is kept.
#[test]
fn a_session_that_finishes_opening_after_the_door_changed_is_closed() {
    if !have_browser() {
        return;
    }
    let r = rig();
    r.host
        .set_key_current(Arc::new(|k: &str| k != "terminal-1-1-old"));
    let gone = r
        .host
        .open(
            "alpha",
            None,
            Device::Desktop,
            None,
            None,
            &[],
            Some("terminal-1-1-old"),
        )
        .unwrap_err();
    assert!(
        gone.message()
            .contains("changed while the browser was starting"),
        "{gone:?}"
    );
    assert!(r.host.sessions().is_empty(), "nothing was left open");
    let kept = r
        .host
        .open(
            "alpha",
            None,
            Device::Desktop,
            None,
            None,
            &[],
            Some("terminal-1-1-new"),
        )
        .unwrap();
    assert_eq!(r.host.sessions().len(), 1);
    r.host.close(&kept).unwrap();
}

struct Facts;
impl BoxFacts for Facts {
    fn exists(&self, b: &str) -> bool {
        b == "alpha"
    }
    fn production(&self, _b: &str) -> bool {
        false
    }
}

struct Rig {
    dir: tempfile::TempDir,
    tools: HostTools,
    host: Arc<BrowserHost>,
    site: Site,
    seen: Mutex<Vec<String>>,
}

fn have_browser() -> bool {
    if ozbox_browser::cdp::find_chromium().is_some() {
        return true;
    }
    assert!(
        std::env::var("OZBOX_REQUIRE_BROWSER").is_err(),
        "OZBOX_REQUIRE_BROWSER is set but no Chromium is installed"
    );
    eprintln!("skipped: no Chromium on this machine");
    false
}

fn rig() -> Rig {
    std::env::set_var("OZBOX_BROWSER_NO_SANDBOX", "1");
    let dir = tempfile::tempdir().unwrap();
    let store = TaskStore::new(dir.path().join("tasks.json"));
    let backend = Arc::new(InProcessBackend::new(dir.path().join("work")));
    let host = Arc::new(BrowserHost::new(
        backend,
        store.clone(),
        dir.path().join("browser-policy.json"),
    ));
    let mut tools = HostTools::new(
        store,
        Arc::new(crate::host_tools::backend::LocalBackend::new(
            dir.path().join("work"),
        )),
        Arc::new(Facts),
    );
    tools.ask_wait = Duration::from_millis(80);
    tools.poll = Duration::from_millis(10);
    tools.browser = Some(Arc::clone(&host));
    host.set_policy(
        None,
        BrowserPolicy {
            min_gap_ms: 0,
            ..BrowserPolicy::default()
        },
    )
    .unwrap();
    Rig {
        dir,
        tools,
        host,
        site: testsite::start(0).unwrap(),
        seen: Mutex::new(Vec::new()),
    }
}

fn agent() -> Session {
    Session {
        person: "ada".into(),
        role: Role::Agent,
    }
}

fn scope() -> HostScope {
    HostScope {
        box_name: Some("alpha".into()),
        run_id: Some("t1".into()),
        orchestration: None,
        actor: ActorKind::Agent,
        session: None,
        program: None,
        program_pid: None,
        code: None,
        standing_until_ms: None,
        door_gen: 0,
    }
}

impl Rig {
    fn call(&self, name: &str, a: Value) -> Result<Value, ToolError> {
        let r = self.tools.call(&agent(), Some(&scope()), name, &a, 1_000);
        self.seen.lock().unwrap().push(format!("{r:?}"));
        r
    }
    fn url(&self, host: &str, p: &str) -> String {
        format!("http://{host}:{}{p}", self.site.port)
    }
    fn ok(&self, name: &str, a: Value) -> Value {
        self.call(name, a.clone())
            .unwrap_or_else(|e| panic!("{name} {a} failed: {e:?}"))
    }
    fn open(&self, device: &str) -> String {
        self.ok("browser_open", json!({ "device": device }))["session"]
            .as_str()
            .unwrap()
            .to_string()
    }
    fn snap(&self, s: &str) -> String {
        self.ok("browser_snapshot", json!({ "session": s }))["snapshot"]
            .as_str()
            .unwrap()
            .to_string()
    }
    fn r#ref(&self, s: &str, needle: &str) -> String {
        let snap = self.snap(s);
        snap.lines()
            .find(|l| l.contains(needle))
            .and_then(|l| l.strip_prefix('[')?.split(' ').next())
            .unwrap_or_else(|| panic!("no {needle} in\n{snap}"))
            .to_string()
    }
    fn pending(&self) -> Vec<(String, String)> {
        self.tools
            .store
            .load()
            .unwrap()
            .approvals
            .iter()
            .filter(|a| a.state == ApprovalState::Pending)
            .map(|a| (a.id.clone(), a.action.clone()))
            .collect()
    }
    fn decide(&self, id: &str, approve: bool) {
        self.tools
            .store
            .update(|b| supervisor::decide(b, id, approve, "ada", false, 2_000))
            .unwrap()
            .unwrap();
    }
    fn audit(&self) -> String {
        std::fs::read_to_string(self.tools.store.audit_log().path()).unwrap()
    }
}

fn refused(e: ToolError) -> String {
    match e {
        ToolError::Refused(m) => m,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn the_tool_surface_is_this_list_and_every_tool_has_a_definition() {
    let names: Vec<&str> = BROWSER_TOOLS.iter().map(|t| t.name).collect();
    assert_eq!(
        names,
        [
            "browser_open",
            "browser_close",
            "browser_navigate",
            "browser_history",
            "browser_click",
            "browser_type",
            "browser_select",
            "browser_scroll",
            "browser_hover",
            "browser_press",
            "browser_tab",
            "browser_wait",
            "browser_upload",
            "browser_downloads",
            "browser_snapshot",
            "browser_page_screenshot",
            "browser_extract"
        ]
    );
    let defs = tool_defs(false);
    assert_eq!(defs.len(), BROWSER_TOOLS.len());
    for d in &defs {
        assert!(
            d["description"].as_str().is_some_and(|x| !x.is_empty()),
            "{d}"
        );
        assert_eq!(d["inputSchema"]["type"], "object");
    }
    // the old read-only tools are still there, and nothing here takes a key or a raw debugging address
    assert!(crate::host_tools::tool_info("browser_fetch").is_some());
    let all = serde_json::to_string(&defs).unwrap().to_ascii_lowercase();
    for banned in [
        "cdp",
        "devtools",
        "websocket",
        "remote-debugging",
        "password",
    ] {
        assert!(!all.contains(banned), "{banned}");
    }
    assert!(defs.iter().all(|d| d["inputSchema"]["required"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| !r.as_str().unwrap().is_empty())));
    assert!(tool_defs(true).iter().all(|d| d["inputSchema"]["required"]
        .as_array()
        .unwrap()
        .contains(&json!("box"))));
    assert!(is_browser_tool("browser_click") && !is_browser_tool("shell"));
}

#[test]
fn arguments_become_actions_and_a_typed_value_is_never_an_audit_word() {
    let a = to_action(
        "browser_type",
        &json!({ "session": "s", "target": "e1", "text": "SENTINEL-x", "submit": true }),
    )
    .unwrap();
    assert_eq!(a.word(), "type");
    assert!(matches!(
        a,
        Action::Type {
            submit: true,
            clear: true,
            ..
        }
    ));
    assert_eq!(
        to_action("browser_tab", &json!({ "op": "new", "url": "http://a/" }))
            .unwrap()
            .word(),
        "tab_new"
    );
    assert_eq!(
        to_action("browser_downloads", &json!({ "open": "a.pdf" }))
            .unwrap()
            .word(),
        "open_download"
    );
    assert_eq!(
        to_action("browser_downloads", &json!({})).unwrap().word(),
        "downloads"
    );
    assert!(to_action("browser_history", &json!({ "op": "sideways" })).is_err());
    assert!(to_action("browser_tab", &json!({})).is_err());
    assert!(to_action("shell", &json!({})).is_err());
    assert!(!a
        .audit_words(Some("password"))
        .join(" ")
        .contains("SENTINEL"));
}

#[test]
fn the_whole_flow_through_the_tool_host() {
    if !have_browser() {
        return;
    }
    let r = rig();
    r.tools
        .store
        .update(|b| b.perms.browser_hosts = vec!["blocked.localhost".into()])
        .unwrap();
    let local = "127.0.0.1";

    // --- an ordinary session: no approval for looking and typing, the password is never shown
    let s = r.open("desktop");
    r.ok(
        "browser_navigate",
        json!({ "session": s, "url": r.url(local, "/login") }),
    );
    let user = r.r#ref(&s, "\"Username\"");
    let pass = r.r#ref(&s, "\"Password\"");
    r.ok(
        "browser_type",
        json!({ "session": s, "target": user, "text": "ada" }),
    );
    r.ok(
        "browser_type",
        json!({ "session": s, "target": pass, "text": "SENTINEL-pw1" }),
    );
    let snap = r.snap(&s);
    assert!(
        snap.contains("[masked]") && !snap.contains("SENTINEL"),
        "{snap}"
    );

    // --- a form submit pauses for approval, showing the fields with the password masked; nothing is sent meanwhile
    let sign = r.r#ref(&s, "\"Sign in\"");
    let msg = refused(
        r.call("browser_click", json!({ "session": s, "target": sign }))
            .unwrap_err(),
    );
    assert!(msg.contains("A person has to approve this first"), "{msg}");
    let pending = r.pending();
    assert_eq!(pending.len(), 1);
    assert!(
        pending[0].1.contains("password=[hidden]") && pending[0].1.contains("username=ada"),
        "{}",
        pending[0].1
    );
    assert!(!pending[0].1.contains("SENTINEL"));
    assert!(r.site.posts.0.lock().unwrap().is_empty());
    r.decide(&pending[0].0, true);
    r.ok("browser_click", json!({ "session": s, "target": sign }));
    assert_eq!(r.site.posts.0.lock().unwrap().len(), 1);
    // one approval covers one call: the same click again asks again
    r.ok(
        "browser_navigate",
        json!({ "session": s, "url": r.url(local, "/login") }),
    );
    let sign = r.r#ref(&s, "\"Sign in\"");
    assert!(r
        .call("browser_click", json!({ "session": s, "target": sign }))
        .is_err());
    assert_eq!(r.pending().len(), 1);
    r.decide(&r.pending()[0].0, false);
    let msg = refused(
        r.call("browser_click", json!({ "session": s, "target": sign }))
            .unwrap_err(),
    );
    assert!(msg.contains("said no"), "{msg}");
    assert_eq!(r.site.posts.0.lock().unwrap().len(), 1);

    // --- a checkout is refused outright, and the refusal is in the chain
    r.ok(
        "browser_navigate",
        json!({ "session": s, "url": r.url(local, "/checkout") }),
    );
    let card = r.r#ref(&s, "\"Card number\"");
    r.ok(
        "browser_type",
        json!({ "session": s, "target": card, "text": "4111 1111 1111 1111" }),
    );
    let place = r.r#ref(&s, "\"Place order\"");
    let msg = refused(
        r.call("browser_click", json!({ "session": s, "target": place }))
            .unwrap_err(),
    );
    assert!(msg.contains("not made by an agent"), "{msg}");
    assert!(r.pending().is_empty());
    assert!(!r
        .site
        .posts
        .0
        .lock()
        .unwrap()
        .iter()
        .any(|(p, _)| p == "/pay"));
    assert!(r.audit().contains("why=browser_payment"));

    // --- a site not on the allow-list asks first; a listed one does not
    let msg = refused(
        r.call(
            "browser_navigate",
            json!({ "session": s, "url": "https://elsewhere.invalid/" }),
        )
        .unwrap_err(),
    );
    assert!(msg.contains("approve"), "{msg}");
    let id = r.pending()[0].0.clone();
    assert!(r.pending()[0].1.contains("allow-list"));
    r.decide(&id, false);
    let _ = r.call(
        "browser_navigate",
        json!({ "session": s, "url": "https://elsewhere.invalid/" }),
    );
    r.ok(
        "browser_navigate",
        json!({ "session": s, "url": r.url("blocked.localhost", "/") }),
    );
    // robots.txt is honoured on a site that is not the box's own
    let msg = refused(
        r.call(
            "browser_navigate",
            json!({ "session": s, "url": r.url("blocked.localhost", "/secret/page") }),
        )
        .unwrap_err(),
    );
    assert!(msg.contains("robots.txt"), "{msg}");

    // --- structured data, checked against the schema
    r.ok(
        "browser_navigate",
        json!({ "session": s, "url": r.url(local, "/data") }),
    );
    let schema = json!({ "type": "object", "required": ["title", "price"], "properties": {
        "title": { "type": "string", "x-selector": "h1" }, "price": { "type": "number", "x-selector": ".price" },
        "tags": { "type": "array", "x-selector": ".tag", "items": { "type": "string" } } } });
    let d = r.ok("browser_extract", json!({ "session": s, "schema": schema }));
    assert_eq!(
        d["data"],
        json!({ "title": "Blue mug", "price": 12.5, "tags": ["ceramic", "blue"] })
    );
    let bad = json!({ "type": "object", "properties": { "title": { "type": "integer", "x-selector": "h1" } } });
    assert!(matches!(
        r.call("browser_extract", json!({ "session": s, "schema": bad })),
        Err(ToolError::Invalid(_))
    ));

    // --- a picture, with secret fields blurred, comes back as an image
    let shot = r.ok("browser_page_screenshot", json!({ "session": s }));
    assert_eq!(shot["mime"], "image/jpeg");
    assert!(shot["image_base64"].as_str().unwrap().len() > 500);

    // --- a challenge is handed to a person: the agent is refused while they hold it, and cannot get round it
    let v = r.ok(
        "browser_navigate",
        json!({ "session": s, "url": r.url(local, "/captcha") }),
    );
    assert!(v["handoff"]["reason"].is_string(), "{v}");
    let msg = refused(
        r.call("browser_snapshot", json!({ "session": s }))
            .unwrap_err(),
    );
    assert!(msg.contains("A person holds this browser"), "{msg}");
    assert!(r.audit().contains("why=browser_person_holds"));
    assert!(r
        .host
        .drain_events()
        .iter()
        .any(|e| e.kind == "challenge" && e.session == s));
    // handing back while the check shows is refused; the person takes it, does it (Tab, Tab, Enter), then hands back
    let ada = PersonAct::checked("ada");
    let eve = PersonAct::checked("eve");
    assert!(matches!(
        r.host.handback(&s, &ada),
        Err(ToolError::Refused(_))
    ));
    // input goes only to a session a person has taken, and only from that person
    assert!(r
        .host
        .input(
            &s,
            &ada,
            json!({ "t": "key", "kind": "press", "key": "Tab" })
        )
        .is_err());
    r.host.takeover(&s, &ada).unwrap();
    assert!(matches!(
        r.host.input(
            &s,
            &eve,
            json!({ "t": "key", "kind": "press", "key": "Tab" })
        ),
        Err(ToolError::Refused(_))
    ));
    for k in ["Tab", "Tab", "Enter"] {
        r.host
            .input(&s, &ada, json!({ "t": "key", "kind": "press", "key": k }))
            .unwrap();
    }
    std::thread::sleep(Duration::from_millis(800));
    r.host.handback(&s, &ada).unwrap();
    assert!(r.snap(&s).contains("Test site"));

    // --- a take-over by choice blocks the agent until it is handed back
    r.host.takeover(&s, &ada).unwrap();
    assert!(r
        .call("browser_click", json!({ "session": s, "target": "e1" }))
        .is_err());
    assert!(r
        .call(
            "browser_navigate",
            json!({ "session": s, "url": r.url(local, "/") })
        )
        .is_err());
    r.host.handback(&s, &ada).unwrap();
    r.ok(
        "browser_navigate",
        json!({ "session": s, "url": r.url(local, "/") }),
    );

    // --- the replay data is there: steps with pages and names, and pictures
    let steps = r.host.backend.steps("alpha", &s).unwrap();
    assert!(steps.len() > 20, "{}", steps.len());
    assert!(steps
        .iter()
        .any(|x| x.action == "type" && x.names == ["password"]));
    assert!(
        steps.iter().any(|x| x.actor == "person") && steps.iter().any(|x| x.outcome == "handoff")
    );
    let first_shot = steps.iter().find_map(|x| x.shot.clone()).unwrap();
    assert!(r.host.backend.shot("alpha", &s, &first_shot).unwrap().len() > 100);
    assert!(r.host.backend.shot("alpha", &s, "../x.jpg").is_err());

    r.ok("browser_close", json!({ "session": s }));
    assert_eq!(
        r.host.backend.list_sessions("alpha").unwrap()[0].state,
        "closed"
    );

    // --- the chain verifies, and nothing typed or seen is in it, in a result, or in the recording
    let log = r.tools.store.audit_log();
    assert!(log.verify().unwrap().ok);
    let chain = r.audit();
    let mut everything = chain.clone() + &r.seen.lock().unwrap().join("\n");
    fn walk(d: &std::path::Path, out: &mut String) {
        for e in std::fs::read_dir(d).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if let Ok(b) = std::fs::read(&p) {
                out.push_str(&String::from_utf8_lossy(&b));
            }
        }
    }
    walk(
        &r.dir.path().join("work/alpha/.ozbox/browser/sessions"),
        &mut everything,
    );
    for leaked in ["SENTINEL", "4111 1111", "pw1"] {
        assert!(!everything.contains(leaked), "{leaked} leaked");
    }
    for word in [
        "permission.allow",
        "permission.ask",
        "permission.deny",
        "tool.completed",
        "tool=browser_click",
        "server=browser",
    ] {
        assert!(chain.contains(word), "missing {word}");
    }
}

#[test]
fn limits_pauses_and_the_wait_for_a_person() {
    if !have_browser() {
        return;
    }
    let r = rig();
    // a task limit of four actions
    r.host
        .set_policy(
            Some("small"),
            BrowserPolicy {
                min_gap_ms: 0,
                max_actions: 4,
                max_sessions: 2,
                ..BrowserPolicy::default()
            },
        )
        .unwrap();
    let s = r.ok(
        "browser_open",
        json!({ "project": "small", "device": "phone" }),
    )["session"]
        .as_str()
        .unwrap()
        .to_string();
    r.ok(
        "browser_navigate",
        json!({ "session": s, "url": r.url("127.0.0.1", "/device") }),
    );
    // a phone is a touch device with a mobile browser that says what it is
    assert!(r.snap(&s).contains("width=390 touch=true ua=true mobile"));
    r.ok("browser_snapshot", json!({ "session": s }));
    r.ok("browser_snapshot", json!({ "session": s }));
    // the limit stops the task cleanly: paused, a person told, nothing half-done
    let msg = refused(
        r.call("browser_snapshot", json!({ "session": s }))
            .unwrap_err(),
    );
    assert!(msg.contains("paused") && msg.contains("resume"), "{msg}");
    assert!(r.host.drain_events().iter().any(|e| e.kind == "paused"));
    assert_eq!(
        r.host.backend.list_sessions("alpha").unwrap()[0].state,
        "paused"
    );
    assert!(r.call("browser_snapshot", json!({ "session": s })).is_err());
    let resumed = r
        .host
        .resume("alpha", &s, &[], &PersonAct::checked("ada"))
        .unwrap();
    assert_eq!(resumed, s);
    // it is on the page it was on, with the default limits now
    assert!(r.snap(&s).contains("Device"));
    r.ok("browser_close", json!({ "session": s }));

    // a box holds a limited number of sessions
    r.host
        .set_policy(
            None,
            BrowserPolicy {
                min_gap_ms: 0,
                max_sessions: 1,
                ..BrowserPolicy::default()
            },
        )
        .unwrap();
    let a = r.open("desktop");
    let msg = refused(r.call("browser_open", json!({})).unwrap_err());
    assert!(msg.contains("limit"), "{msg}");
    r.ok("browser_close", json!({ "session": a }));

    // waiting for a person: 30 minutes by default, here shortened. Then the task pauses where it was, nothing submitted
    r.host
        .set_policy(
            None,
            BrowserPolicy {
                min_gap_ms: 0,
                ..BrowserPolicy::default()
            },
        )
        .unwrap();
    *r.host.wait_override.lock().unwrap() = Some(Duration::from_millis(250));
    let s = r.open("desktop");
    r.ok(
        "browser_navigate",
        json!({ "session": s, "url": r.url("127.0.0.1", "/login") }),
    );
    let sign = r.r#ref(&s, "\"Sign in\"");
    let first = refused(
        r.call("browser_click", json!({ "session": s, "target": sign }))
            .unwrap_err(),
    );
    assert!(first.contains("still waiting"), "{first}");
    std::thread::sleep(Duration::from_millis(300));
    let paused = refused(
        r.call("browser_click", json!({ "session": s, "target": sign }))
            .unwrap_err(),
    );
    assert!(
        paused.contains("paused") && paused.contains("nothing was submitted"),
        "{paused}"
    );
    assert!(r.site.posts.0.lock().unwrap().is_empty());
    assert_eq!(
        r.host.backend.list_sessions("alpha").unwrap()[0].state,
        "paused"
    );
    // resumed from the dashboard: the same page, and the approval can still be given
    r.host
        .resume("alpha", &s, &[], &PersonAct::checked("ada"))
        .unwrap();
    let sign = r.r#ref(&s, "\"Sign in\"");
    assert!(r
        .call("browser_click", json!({ "session": s, "target": sign }))
        .is_err());
    r.decide(&r.pending().last().unwrap().0.clone(), true);
    r.ok("browser_click", json!({ "session": s, "target": sign }));
    assert_eq!(r.site.posts.0.lock().unwrap().len(), 1);
    r.ok("browser_close", json!({ "session": s }));
    assert!(r.tools.store.audit_log().verify().unwrap().ok);
}

#[test]
fn a_site_set_for_a_local_model_is_not_read_by_a_hosted_one() {
    if !have_browser() {
        return;
    }
    let r = rig();
    r.host
        .set_policy(
            Some("private"),
            BrowserPolicy {
                min_gap_ms: 0,
                local_model_sites: vec!["127.0.0.1".into()],
                ..BrowserPolicy::default()
            },
        )
        .unwrap();
    let s = r.ok("browser_open", json!({ "project": "private" }))["session"]
        .as_str()
        .unwrap()
        .to_string();
    r.ok(
        "browser_navigate",
        json!({ "session": s, "url": r.url("127.0.0.1", "/data") }),
    );
    let msg = refused(
        r.call("browser_snapshot", json!({ "session": s }))
            .unwrap_err(),
    );
    assert!(msg.contains("local model"), "{msg}");
    assert!(r.audit().contains("why=browser_needs_local_model"));
    r.ok("browser_close", json!({ "session": s }));
}

#[test]
fn a_session_belongs_to_its_box_and_is_found_only_by_its_id() {
    let dir = tempfile::tempdir().unwrap();
    let store = TaskStore::new(dir.path().join("tasks.json"));
    let host = Arc::new(BrowserHost::new(
        Arc::new(InProcessBackend::new(dir.path().join("w"))),
        store,
        dir.path().join("p.json"),
    ));
    assert!(matches!(
        host.sess("nope", None),
        Err(ToolError::NotFound(_))
    ));
    assert!(host.takeover("nope", &PersonAct::checked("ada")).is_err());
    assert!(host.policy(None) == BrowserPolicy::default());
    assert!(host
        .set_policy(
            None,
            BrowserPolicy {
                max_actions: 0,
                ..BrowserPolicy::default()
            }
        )
        .is_err());
    assert!(host
        .set_policy(Some("../x"), BrowserPolicy::default())
        .is_err());
    host.set_policy(
        Some("p1"),
        BrowserPolicy {
            retention_days: 7,
            ..BrowserPolicy::default()
        },
    )
    .unwrap();
    assert_eq!(host.policy(Some("p1")).retention_days, 7);
    assert_eq!(host.policy(Some("other")).retention_days, 30);
}

/// An allow rule on the browser, or the engine's most permissive mode, does not let a risky step run: the tool gate asks a
/// person for it all the same, and the worker acts only on the grant a decided request becomes (a security review,
/// 2026-11-10).
#[test]
fn an_allow_rule_or_auto_mode_never_stands_in_for_a_person() {
    if !have_browser() {
        return;
    }
    let r = rig();
    r.tools
        .store
        .update(|b| {
            b.perms.default_mode = ozbox_core::permissions::Mode::Auto;
            b.perms.rules.push(ozbox_core::permissions::Rule {
                id: "allow-browser".into(),
                effect: ozbox_core::permissions::Effect::Allow,
                action: "tool.call".into(),
                scope: ozbox_core::permissions::Scope::Person,
                scope_id: None,
                path: None,
                command: None,
                env: None,
                tool: None,
                server: Some("browser".into()),
                note: String::new(),
            });
        })
        .unwrap();
    let s = r.open("desktop");
    r.ok(
        "browser_navigate",
        json!({ "session": s, "url": r.url("127.0.0.1", "/login") }),
    );
    let sign = r.r#ref(&s, "\"Sign in\"");
    let msg = refused(
        r.call("browser_click", json!({ "session": s, "target": sign }))
            .unwrap_err(),
    );
    assert!(msg.contains("A person has to approve"), "{msg}");
    assert!(r.site.posts.0.lock().unwrap().is_empty());
    assert!(r.audit().contains("why=person_required"), "{}", r.audit());
    // the approval request shows where the form goes and a check of what was shown
    let (id, text) = r.pending()[0].clone();
    assert!(
        text.contains("-> 127.0.0.1:") && text.contains("/login (check "),
        "{text}"
    );
    r.decide(&id, true);
    r.ok("browser_click", json!({ "session": s, "target": sign }));
    assert_eq!(r.site.posts.0.lock().unwrap().len(), 1);
    // the recording names the approval the step ran with
    let steps = r.host.backend.steps("alpha", &s).unwrap();
    assert!(steps
        .iter()
        .any(|x| x.approval.as_deref() == Some(id.as_str())));
    r.ok("browser_close", json!({ "session": s }));
}

/// What the worker writes is what would land in the run's log on a box: sealed lines only, so no page text, snapshot,
/// frame or extracted value is readable there.
#[test]
fn what_the_worker_writes_holds_nothing_readable() {
    if !have_browser() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let store = TaskStore::new(dir.path().join("tasks.json"));
    let backend = Arc::new(InProcessBackend::new(dir.path().join("work")));
    backend.capture();
    let host = Arc::new(BrowserHost::new(
        backend.clone(),
        store,
        dir.path().join("p.json"),
    ));
    host.set_policy(
        None,
        BrowserPolicy {
            min_gap_ms: 0,
            ..BrowserPolicy::default()
        },
    )
    .unwrap();
    let site = testsite::start(0).unwrap();
    let s = host
        .open("alpha", None, Device::Desktop, None, None, &[], None)
        .unwrap();
    let nav = host
        .call_op(
            &s,
            Op::Act {
                action: Action::Navigate {
                    url: format!("http://127.0.0.1:{}/data", site.port),
                },
                grant: None,
            },
            ACT_TIMEOUT,
        )
        .unwrap();
    assert!(nav.ok, "{nav:?}");
    let snap = host
        .call_op(
            &s,
            Op::Act {
                action: Action::Snapshot,
                grant: None,
            },
            ACT_TIMEOUT,
        )
        .unwrap();
    assert!(snap.result.to_string().contains("Blue mug"));
    let frame = host.frame(&s).unwrap();
    assert!(frame["jpeg"].as_str().unwrap().starts_with("/9j/"));
    host.close(&s).unwrap();
    let log = backend.captured().join("\n");
    assert!(!log.is_empty());
    for leak in ["Blue mug", "ceramic", "/9j/", "snapshot", "ready"] {
        assert!(
            !log.contains(leak),
            "{leak} is readable in the worker's output"
        );
    }
}

#[test]
fn a_worker_on_a_box_is_a_controlled_run_with_a_memory_cap() {
    let l = worker_launch(
        "{\"session\":\"b1\"}",
        &WorkerRun {
            max_runtime_s: 600,
            memory_bytes: 1536 << 20,
        },
    );
    assert!(l.require_capability && l.keep_stdin_open);
    assert_eq!(l.memory_max_bytes, Some(1536 << 20));
    assert_eq!(l.memory_request_bytes, 1536 << 20);
    assert_eq!(l.argv, ["ozbox", "browser-worker"]);
    // the first line, which holds the key, is standard input only: never an argument or the environment
    assert!(l.env.is_empty() && !l.argv.iter().any(|a| a.contains("session")));
    assert!(!format!("{l:?}").contains("b1"));
}

#[test]
fn a_settings_change_is_recorded_by_what_changed_and_whether_it_is_less_careful() {
    let before = BrowserPolicy::default();
    let after = BrowserPolicy {
        payments: ozbox_browser::detect::Payments::Ask,
        safe_sites: vec!["app.example".into()],
        proxy: Some("http://SENTINEL-proxy.example:3128".into()),
        max_minutes: 45,
        ..BrowserPolicy::default()
    };
    let d = settings_diff(&before, &after);
    assert!(d.contains("payments=ask"), "{d}");
    assert!(
        d.contains("safe_sites+1-0") && d.contains("max_minutes=45"),
        "{d}"
    );
    assert!(d.contains("less_careful=true"), "{d}");
    assert!(
        !d.contains("SENTINEL"),
        "a proxy address is never recorded: {d}"
    );
    assert_eq!(
        settings_diff(&before, &before),
        "changed=nothing less_careful=false"
    );
    let calmer = BrowserPolicy {
        max_minutes: 10,
        ..BrowserPolicy::default()
    };
    assert!(settings_diff(&before, &calmer).ends_with("less_careful=false"));
    // the settings file is the server's own
    let dir = tempfile::tempdir().unwrap();
    let host = BrowserHost::new(
        Arc::new(InProcessBackend::new(dir.path().join("w"))),
        TaskStore::new(dir.path().join("t.json")),
        dir.path().join("p.json"),
    );
    host.set_policy(None, after).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.path().join("p.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

#[test]
fn an_approval_reads_where_it_goes_and_its_field_names_cannot_fake_structure() {
    let r = json!({
        "reason": "this would submit a form",
        "dest": "app.example/save",
        "fingerprint": "0123456789abcdef",
        "fields": [ { "name": "a=b, c=d", "value": "x, y" }, { "name": "pw", "value": "[masked]" } ],
    });
    let t = approval_summary(&r, "app.example", "submit", "click");
    assert_eq!(
        t,
        "this would submit a form on app.example: click -> app.example/save (check 01234567) [a_b_ c_d=x,y, pw=[masked]]"
    );
}

/// An upload asks a person every time, and shows the file by its place under /work; a credential file is refused before
/// anyone is asked.
#[test]
fn an_upload_asks_and_never_takes_a_credential() {
    if !have_browser() {
        return;
    }
    let r = rig();
    let work = r.dir.path().join("work/alpha");
    for (f, body) in [
        ("uploads/report.pdf", "%PDF-1.4"),
        ("home/ozbox/.aws/credentials", "SENTINEL-aws"),
        ("project/.env", "SENTINEL-env"),
    ] {
        let p = work.join(f);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, body).unwrap();
    }
    let s = r.open("desktop");
    r.ok(
        "browser_navigate",
        json!({ "session": s, "url": r.url("127.0.0.1", "/form") }),
    );
    let input = r
        .snap(&s)
        .lines()
        .find(|l| l.contains("file-input"))
        .and_then(|l| l.strip_prefix('[')?.split(' ').next())
        .unwrap()
        .to_string();
    for bad in ["home/ozbox/.aws/credentials", "project/.env"] {
        let p = work.join(bad).to_string_lossy().into_owned();
        let msg = refused(
            r.call(
                "browser_upload",
                json!({ "session": s, "target": input, "path": p }),
            )
            .unwrap_err(),
        );
        assert!(msg.contains("upload"), "{bad}: {msg}");
    }
    assert!(r.pending().is_empty(), "a refused upload asks nobody");
    let good = work
        .join("uploads/report.pdf")
        .to_string_lossy()
        .into_owned();
    let msg = refused(
        r.call(
            "browser_upload",
            json!({ "session": s, "target": input, "path": good }),
        )
        .unwrap_err(),
    );
    assert!(msg.contains("approve"), "{msg}");
    let (id, text) = r.pending()[0].clone();
    assert!(text.contains("file=uploads/report.pdf"), "{text}");
    r.decide(&id, true);
    let v = r.ok(
        "browser_upload",
        json!({ "session": s, "target": input, "path": good }),
    );
    assert_eq!(v["file"], "uploads/report.pdf");
    assert!(!r.audit().contains("SENTINEL"));
    r.ok("browser_close", json!({ "session": s }));
}

/// ADR 0043: a session is driven only by the enrolment that opened it; a terminal agent never drives a run's or a
/// person's session, and nobody else drives a terminal's.
#[test]
fn a_terminal_enrolment_drives_only_its_own_browser_sessions() {
    let a = "terminal-10-1-1";
    let b = "terminal-20-2-2";
    assert!(may_drive(a, Some(a)));
    assert!(!may_drive(b, Some(a)), "another program on the box");
    assert!(!may_drive(a, Some("t1")), "a run's session");
    assert!(
        !may_drive(a, Some("person:ada")),
        "the person's own agent's session"
    );
    assert!(!may_drive(a, None), "a session a person resumed");
    assert!(
        !may_drive("t1", Some(a)),
        "a run does not drive a terminal's session"
    );
    assert!(!may_drive("person:ada", Some(a)));
    assert!(may_drive("t1", Some("t1")) && may_drive("t1", Some("t2")) && may_drive("t1", None));
}

/// the binding holds through the tool call itself, not only in the helper. A session a terminal enrolment opened is
/// driven by that enrolment and by nobody else, and a terminal never drives a run's. (Deleting the check in `prepare` fails
/// this; the `may_drive` test alone would not notice.)
#[test]
fn a_session_is_driven_through_the_tool_call_only_by_its_opener() {
    let r = rig();
    r.host.plant_session("s1", "alpha", Some("terminal-10-1"));
    r.host.plant_session("s2", "alpha", Some("t1"));
    let as_key = |key: &str, actor: ActorKind, session: &str| {
        let h = HostScope {
            run_id: None,
            actor,
            session: Some(key.to_string()),
            ..scope()
        };
        r.tools.call(
            &agent(),
            Some(&h),
            "browser_snapshot",
            &json!({ "session": session }),
            1_000,
        )
    };
    let msg = |e: ToolError| e.message().to_string();
    let other = as_key("terminal-20-2", ActorKind::Terminal, "s1").unwrap_err();
    assert!(msg(other).contains("no such browser session"));
    let run_session = as_key("terminal-10-1", ActorKind::Terminal, "s2").unwrap_err();
    assert!(
        msg(run_session).contains("no such browser session"),
        "a terminal never drives a run's session"
    );
    let mine = as_key("terminal-10-1", ActorKind::Terminal, "s1");
    assert!(
        !matches!(&mine, Err(e) if e.message().contains("no such browser session")),
        "{mine:?}"
    );
}
