#![allow(clippy::unwrap_used)]

use std::io::Cursor;
use std::sync::Mutex;

use super::*;
use crate::orch_tools::ToolError;

const ME: u32 = 1000;

fn me(_: &UnixStream) -> Option<Peer> {
    Some(Peer {
        uid: ME,
        pid: Some(4242),
    })
}
fn someone_else(_: &UnixStream) -> Option<Peer> {
    Some(Peer {
        uid: ME + 1,
        pid: Some(4242),
    })
}
fn unknown(_: &UnixStream) -> Option<Peer> {
    None
}
fn not_in_a_run(_: u32) -> Option<bool> {
    Some(false)
}
fn in_a_run(_: u32) -> Option<bool> {
    Some(true)
}
/// The kernel's word on a process, as the tests have it: a start time that follows the pid, and a program called `claude`.
/// Pid 77 is a pid that a new process can reuse: its start time is whatever `REUSED_START` says.
static REUSED_START: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(500);
/// The same for pid 78, so two tests that each reuse a pid never see each other's start time.
static REUSED_START_2: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(500);
/// And pid 80, for the test of a holder whose process is gone.
static REUSED_START_4: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(500);
fn who(pid: u32) -> Option<ProcIdent> {
    let start = match pid {
        77 => REUSED_START.load(Ordering::SeqCst),
        78 => REUSED_START_2.load(Ordering::SeqCst),
        80 => REUSED_START_4.load(Ordering::SeqCst),
        _ => 9000 + u64::from(pid),
    };
    Some(ProcIdent {
        start,
        program: "claude".into(),
        parent_pid: Some(pid + 1000),
    })
}
fn peer(pid: u32) -> Option<Peer> {
    Some(Peer {
        uid: ME,
        pid: Some(pid),
    })
}

/// The tool host as a coding agent meets it: every call echoes who made it and where it acts.
struct Host {
    seen: Mutex<Vec<Value>>,
    /// Browser sessions the tool host pretends to hold, by the key that opened them.
    sessions: Mutex<Vec<String>>,
    /// How long closing stranded sessions takes (a hung browser).
    close_delay: Mutex<std::time::Duration>,
    /// How many times the door asked for waiting approvals to be ended.
    ended: AtomicUsize,
    /// The generation the door asked the host to move, and the one the sweep found when it ran.
    gen: AtomicUsize,
    gen_at_sweep: AtomicUsize,
    /// What the door told the host about whether a key is still current.
    current: Mutex<Option<crate::browser_tools::KeyCurrent>>,
}

impl Host {
    fn new() -> Host {
        Host {
            seen: Mutex::new(Vec::new()),
            sessions: Mutex::new(Vec::new()),
            close_delay: Mutex::new(std::time::Duration::ZERO),
            ended: AtomicUsize::new(0),
            gen: AtomicUsize::new(0),
            gen_at_sweep: AtomicUsize::new(0),
            current: Mutex::new(None),
        }
    }
}

/// Wait for the closes the door started on their own threads to finish.
fn closes_done(r: &Rig) {
    let t = std::time::Instant::now();
    while r.door.closing() > 0 {
        assert!(
            t.elapsed() < std::time::Duration::from_secs(10),
            "a close never ended"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

impl ToolRunner for Host {
    fn run(&self, _: &Session, name: &str, _: &Value, _: u64) -> Result<Value, ToolError> {
        Err(ToolError::Refused(format!("{name} needs a box")))
    }
    fn defs(&self, s: &Session, host: Option<&HostScope>) -> Vec<Value> {
        let person = host.is_none() && matches!(s.role, Role::Person);
        let mut v = crate::host_tools::tool_defs(person);
        v.extend(crate::browser_tools::tool_defs(person));
        v
    }
    fn knows(&self, _: &Session, name: &str, _: Option<&HostScope>) -> bool {
        name.starts_with("browser_") || name == "shell"
    }
    fn bump_door_generation(&self) {
        self.gen.fetch_add(1, Ordering::SeqCst);
    }
    fn door_generation(&self) -> u64 {
        self.gen.load(Ordering::SeqCst) as u64
    }
    fn end_waiting_approvals(&self, _: u64) -> usize {
        self.gen_at_sweep
            .store(self.gen.load(Ordering::SeqCst), Ordering::SeqCst);
        self.ended.fetch_add(1, Ordering::SeqCst);
        0
    }
    fn set_key_current(&self, current: crate::browser_tools::KeyCurrent) {
        *self.current.lock().unwrap() = Some(current);
    }
    fn close_stranded_sessions(&self, stranded: &dyn Fn(&str) -> bool) -> usize {
        let delay = *self.close_delay.lock().unwrap();
        std::thread::sleep(delay);
        let mut v = self.sessions.lock().unwrap();
        let before = v.len();
        v.retain(|k| !stranded(k));
        before - v.len()
    }
    fn run_with(
        &self,
        s: &Session,
        host: Option<&HostScope>,
        name: &str,
        a: &Value,
        _: u64,
    ) -> Result<Value, ToolError> {
        let v = json!({ "tool": name, "person": s.person, "box": host.and_then(|h| h.box_name.clone()),
                        "actor": format!("{:?}", host.map(|h| h.actor)), "door_gen": host.map(|h| h.door_gen), "session": host.and_then(|h| h.session.clone()), "args": a });
        self.seen.lock().unwrap().push(v.clone());
        Ok(v)
    }
}

struct Rig {
    dir: tempfile::TempDir,
    sock: PathBuf,
    door: Arc<AgentMcp>,
    host: Arc<Host>,
}

fn rig_with(peer: fn(&UnixStream) -> Option<Peer>, in_run: fn(u32) -> Option<bool>) -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let host = Arc::new(Host::new());
    let door = AgentMcp::new_with(
        host.clone(),
        SettingStore::new(dir.path()),
        "main-box",
        ME,
        peer,
        in_run,
        who,
    );
    let sock = dir.path().join("mcp.sock");
    door.serve(AgentMcp::bind(&sock).unwrap());
    Rig {
        dir,
        sock,
        door,
        host,
    }
}

fn rig() -> Rig {
    rig_with(me, not_in_a_run)
}

fn now() -> u64 {
    crate::serve::unix_ms()
}

/// A fake Claude Code: newline-delimited JSON-RPC on the bridge's stdin, the answers read back from its stdout.
fn drive(r: &Rig, lines: &[Value]) -> Vec<Value> {
    let input: String = lines.iter().map(|l| format!("{l}\n")).collect();
    let mut out = Vec::new();
    bridge::run(&r.sock, now, Cursor::new(input), &mut out).unwrap();
    String::from_utf8(out)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

/// A fake engine that stays connected: one bridge (so one enrolment) for as long as this lives. Approvals and browser
/// sessions belong to the enrolment, so a journey that spans several calls must use one.
struct Live {
    to: UnixStream,
    from: BufReader<UnixStream>,
    run: Option<std::thread::JoinHandle<()>>,
}

fn live(r: &Rig) -> Live {
    let (to, input) = UnixStream::pair().unwrap();
    let (output, from) = UnixStream::pair().unwrap();
    let sock = r.sock.clone();
    let run = std::thread::spawn(move || {
        bridge::run(&sock, now, BufReader::new(input), output).unwrap();
    });
    Live {
        to,
        from: BufReader::new(from),
        run: Some(run),
    }
}

impl Live {
    fn ask(&mut self, line: &Value) -> Value {
        writeln!(self.to, "{line}").unwrap();
        let mut s = String::new();
        std::io::BufRead::read_line(&mut self.from, &mut s).unwrap();
        serde_json::from_str(&s).unwrap_or_else(|_| panic!("no answer: {s:?}"))
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        let _ = self.to.shutdown(std::net::Shutdown::Both);
        if let Some(t) = self.run.take() {
            let _ = t.join();
        }
    }
}

fn init() -> Value {
    json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "claude-code", "version": "x" } } })
}
fn initialized() -> Value {
    json!({ "jsonrpc": "2.0", "method": "notifications/initialized" })
}
fn list() -> Value {
    json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" })
}
fn call(name: &str, args: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": { "name": name, "arguments": args } })
}

fn raw(
    r: &Rig,
    peer: Option<Peer>,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &Value,
) -> (u16, Value) {
    let req = http::Request {
        method: method.into(),
        path: path.into(),
        headers: headers
            .iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect(),
        body: body.to_string().into_bytes(),
    };
    let (s, b) = r.door.route(peer, &req, now());
    (s, serde_json::from_slice(&b).unwrap_or(Value::Null))
}

fn the_box_user() -> Option<Peer> {
    Some(Peer {
        uid: ME,
        pid: Some(1),
    })
}

// ---- who may come in ----

#[test]
fn only_the_box_user_outside_a_run_with_the_setting_on_is_admitted() {
    let p = |uid, pid| Some(Peer { uid, pid });
    assert_eq!(admit(p(ME, Some(5)), ME, true, |_| Some(false)), Ok(()));
    // a caller the kernel did not name a process for is treated as inside a run
    assert_eq!(
        admit(p(ME, None), ME, true, |_| unreachable!()),
        Err(Refusal::InARun)
    );
    assert_eq!(admit(None, ME, true, |_| Some(false)), Err(Refusal::NotYou));
    assert_eq!(
        admit(p(0, Some(5)), ME, true, |_| Some(false)),
        Err(Refusal::NotYou)
    );
    assert_eq!(
        admit(p(ME + 1, Some(5)), ME, true, |_| Some(false)),
        Err(Refusal::NotYou)
    );
    assert_eq!(
        admit(p(ME, Some(5)), ME, true, |_| Some(true)),
        Err(Refusal::InARun)
    );
    // a process whose cgroup cannot be read is treated as inside a run: nothing is guessed in the caller's favour
    assert_eq!(
        admit(p(ME, Some(5)), ME, true, |_| None),
        Err(Refusal::InARun)
    );
    assert_eq!(
        admit(p(ME, Some(5)), ME, false, |_| Some(false)),
        Err(Refusal::Off)
    );
}

#[test]
fn a_runs_scope_is_told_from_the_cgroup_text() {
    assert!(cgroup_in_run(
        "0::/system.slice/ozboxd.service/run-ab12cd.scope\n"
    ));
    assert!(cgroup_in_run(
        "1:name=systemd:/a/b\n0::/x.slice/run-7.scope/leaf"
    ));
    assert!(!cgroup_in_run(
        "0::/user.slice/user-1000.slice/session-3.scope\n"
    ));
    assert!(!cgroup_in_run(
        "0::/user.slice/user-1000.slice/user@1000.service/tmux-spawn-1.scope\n"
    ));
    assert!(!cgroup_in_run(""));
}

#[test]
fn the_setting_defaults_on_survives_a_restart_and_an_unreadable_file_means_off() {
    let d = tempfile::tempdir().unwrap();
    let st = SettingStore::new(d.path());
    assert!(st.load().enabled);
    let off = Setting {
        enabled: false,
        by: "ada".into(),
        at_ms: 7,
        standing_until_ms: 0,
    };
    st.save(&off).unwrap();
    assert_eq!(st.load(), off);
    // a file written before standing permission existed reads as "never"
    std::fs::write(
        d.path().join("agent-mcp.json"),
        r#"{"enabled":true,"by":"ada","at_ms":7}"#,
    )
    .unwrap();
    assert_eq!(st.load().standing_until_ms, 0);
    std::fs::write(d.path().join("agent-mcp.json"), "{ nope").unwrap();
    assert!(!st.load().enabled);
}

// ---- the door's two paths, and nothing of the dashboard's ----

#[test]
fn the_socket_answers_two_paths_and_none_of_the_dashboards() {
    let r = rig();
    for path in [
        "/v1/boxes",
        "/v1/info",
        "/v1/permissions",
        "/v1/agent-mcp",
        "/",
        "/api/anything",
        "/v1/enrol/x",
        "/mcp/x",
    ] {
        let (s, _) = raw(&r, the_box_user(), "POST", path, &[], &json!({}));
        assert_eq!(s, 404, "{path}");
        let (s, _) = raw(&r, the_box_user(), "GET", path, &[], &json!({}));
        assert_eq!(s, 404, "{path}");
    }
    assert_eq!(
        raw(&r, the_box_user(), "GET", "/mcp", &[], &json!({})).0,
        405
    );
    assert_eq!(
        raw(&r, the_box_user(), "PUT", "/v1/enrol", &[], &json!({})).0,
        405
    );
}

#[test]
fn a_browser_page_is_never_a_caller() {
    let r = rig();
    let (s, _) = raw(
        &r,
        the_box_user(),
        "POST",
        "/v1/enrol",
        &[("Origin", "http://evil.example")],
        &json!({}),
    );
    assert_eq!(s, 403);
}

#[test]
fn another_user_a_caller_the_kernel_did_not_name_and_a_run_are_refused_on_both_paths() {
    let r = rig();
    for peer in [
        Some(Peer {
            uid: ME + 1,
            pid: Some(9),
        }),
        Some(Peer {
            uid: 0,
            pid: Some(9),
        }),
        None,
    ] {
        for path in ["/v1/enrol", "/mcp"] {
            let (s, v) = raw(
                &r,
                peer,
                "POST",
                path,
                &[("Authorization", "Bearer ozmt_x")],
                &list(),
            );
            assert_eq!(s, 403, "{peer:?} {path}");
            assert_eq!(v["code"], "NotYou");
        }
    }
    let r = rig_with(me, in_a_run);
    let (s, v) = raw(&r, the_box_user(), "POST", "/v1/enrol", &[], &json!({}));
    assert_eq!((s, v["code"].as_str()), (403, Some("InARun")));
}

#[test]
fn the_token_is_a_session_for_this_box_with_the_people_who_turned_it_on_named_and_nothing_else() {
    let r = rig();
    let (s, v) = raw(&r, the_box_user(), "POST", "/v1/enrol", &[], &json!({}));
    assert_eq!(s, 200);
    assert_eq!(v["box"], "main-box");
    assert_eq!(v["person"], "owner");
    let t = v["token"].as_str().unwrap().to_string();
    assert!(t.starts_with("ozmt_"));
    assert!(v.get("password").is_none());
    // used on /mcp it reaches the tool host, as this box and that person
    let (s, v) = raw(
        &r,
        the_box_user(),
        "POST",
        "/mcp",
        &[("Authorization", &format!("Bearer {t}"))],
        &call("browser_open", json!({})),
    );
    assert_eq!(s, 200);
    let seen = r.host.seen.lock().unwrap().last().cloned().unwrap();
    assert_eq!(seen["person"], "owner");
    assert_eq!(seen["box"], "main-box");
    assert_eq!(
        seen["actor"], "Some(Terminal)",
        "a coding agent in a terminal is its own kind of actor, never the person's own agent"
    );
    assert!(
        seen["session"].as_str().unwrap().starts_with("terminal-"),
        "{seen}"
    );
    assert_eq!(v["result"]["isError"], false);
}

#[test]
fn a_tool_that_the_host_does_not_know_stays_unknown_and_a_token_from_elsewhere_is_not_valid() {
    let r = rig();
    let other = AgentMcp::new_with(
        r.host.clone(),
        SettingStore::new(r.dir.path()),
        "main-box",
        ME,
        me,
        not_in_a_run,
        who,
    );
    let token = {
        let req = http::Request {
            method: "POST".into(),
            path: "/v1/enrol".into(),
            headers: vec![],
            body: vec![],
        };
        let (_, b) = other.route(the_box_user(), &req, now());
        serde_json::from_slice::<Value>(&b).unwrap()["token"]
            .as_str()
            .unwrap()
            .to_string()
    };
    // a token another door made (or one that is made up) is refused here
    for t in [token.as_str(), "ozmt_00", "nope"] {
        let (s, _) = raw(
            &r,
            the_box_user(),
            "POST",
            "/mcp",
            &[("Authorization", &format!("Bearer {t}"))],
            &list(),
        );
        assert_eq!(s, 401, "{t}");
    }
    let (s, _) = raw(&r, the_box_user(), "POST", "/mcp", &[], &list());
    assert_eq!(s, 401);
}

#[test]
fn turning_it_off_revokes_every_token_at_once_and_refuses_the_next_enrolment() {
    let r = rig();
    let t = raw(&r, the_box_user(), "POST", "/v1/enrol", &[], &json!({})).1["token"]
        .as_str()
        .unwrap()
        .to_string();
    let auth = format!("Bearer {t}");
    assert_eq!(
        raw(
            &r,
            the_box_user(),
            "POST",
            "/mcp",
            &[("Authorization", &auth)],
            &list()
        )
        .0,
        200
    );
    assert_eq!(r.door.live_tokens(now()), 1);
    r.door.set_enabled(false, "ada", now()).unwrap();
    assert_eq!(r.door.live_tokens(now()), 0);
    assert_eq!(
        raw(
            &r,
            the_box_user(),
            "POST",
            "/mcp",
            &[("Authorization", &auth)],
            &list()
        )
        .0,
        403
    );
    let (s, v) = raw(&r, the_box_user(), "POST", "/v1/enrol", &[], &json!({}));
    assert_eq!((s, v["code"].as_str()), (403, Some("Off")));
    // on again: the old token is still dead, a new one is made, and it names who turned it on
    r.door.set_enabled(true, "ada", now()).unwrap();
    assert_eq!(
        raw(
            &r,
            the_box_user(),
            "POST",
            "/mcp",
            &[("Authorization", &auth)],
            &list()
        )
        .0,
        401
    );
    let (s, v) = raw(&r, the_box_user(), "POST", "/v1/enrol", &[], &json!({}));
    assert_eq!((s, v["person"].as_str()), (200, Some("ada")));
    // and the choice is kept for the next start
    assert!(SettingStore::new(r.dir.path()).load().enabled);
}

// ---- a fake Claude Code through the bridge and the socket ----

#[test]
fn a_fake_claude_code_lists_the_tools_and_drives_a_browser_tool_through_the_socket() {
    let r = rig();
    let out = drive(
        &r,
        &[
            init(),
            initialized(),
            list(),
            call("browser_open", json!({ "device": "desktop" })),
        ],
    );
    // the notification has no answer: three answers for four lines
    assert_eq!(out.len(), 3, "{out:?}");
    assert_eq!(out[0]["result"]["serverInfo"]["name"], "ozbox");
    let names: Vec<&str> = out[1]["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"browser_open") && names.contains(&"browser_click"),
        "{names:?}"
    );
    // a person's own agent names the box in each call; this one acts on its own box and so is not asked to
    let open = out[1]["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "browser_open")
        .unwrap()
        .clone();
    assert!(
        open["inputSchema"]["required"]
            .as_array()
            .is_none_or(|r| !r.iter().any(|x| x == "box")),
        "{open}"
    );
    assert_eq!(out[2]["result"]["isError"], false);
    assert_eq!(
        out[2]["result"]["structuredContent"]["tool"],
        "browser_open"
    );
    assert_eq!(out[2]["result"]["structuredContent"]["box"], "main-box");
    assert_eq!(out[2]["result"]["structuredContent"]["person"], "owner");
}

#[test]
fn the_bridge_enrols_again_when_the_dashboard_forgot_its_token() {
    let r = rig();
    // one long-lived bridge: a call, then the setting is cycled (which revokes), then a call
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    struct Chan(std::sync::mpsc::Receiver<String>);
    impl std::io::Read for Chan {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            match self.0.recv() {
                Ok(s) => {
                    let b = s.as_bytes();
                    buf[..b.len()].copy_from_slice(b);
                    Ok(b.len())
                }
                Err(_) => Ok(0),
            }
        }
    }
    let out = Arc::new(Mutex::new(Vec::<u8>::new()));
    struct Sink(Arc<Mutex<Vec<u8>>>);
    impl Write for Sink {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let sock = r.sock.clone();
    let o = out.clone();
    let h = std::thread::spawn(move || {
        bridge::run(&sock, now, std::io::BufReader::new(Chan(rx)), Sink(o)).unwrap()
    });
    let wait = |n: usize| {
        for _ in 0..400 {
            if out.lock().unwrap().iter().filter(|b| **b == b'\n').count() >= n {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("no answer {n}");
    };
    tx.send(format!("{}\n", call("shell", json!({})))).unwrap();
    wait(1);
    r.door.set_enabled(false, "ada", now()).unwrap();
    r.door.set_enabled(true, "ada", now()).unwrap();
    tx.send(format!("{}\n", call("shell", json!({})))).unwrap();
    wait(2);
    drop(tx);
    h.join().unwrap();
    let text = String::from_utf8(out.lock().unwrap().clone()).unwrap();
    let lines: Vec<Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines[0]["result"]["isError"], false);
    assert_eq!(lines[1]["result"]["isError"], false, "{lines:?}");
    assert_eq!(lines[1]["result"]["structuredContent"]["person"], "ada");
}

#[test]
fn when_the_door_is_shut_the_handshake_works_there_are_no_tools_and_the_reason_is_given() {
    for (r, why) in [
        // another user, or a caller the kernel did not name, is dropped at accept: the bridge only sees the close
        (rig_with(someone_else, not_in_a_run), "box's own user"),
        (rig_with(unknown, not_in_a_run), "box's own user"),
        (rig_with(me, in_a_run), "a run Oz Box started"),
    ] {
        let out = drive(&r, &[init(), list(), call("browser_open", json!({}))]);
        assert_eq!(out.len(), 3);
        assert!(
            out[0]["result"]["instructions"]
                .as_str()
                .unwrap()
                .contains(why),
            "{out:?}"
        );
        assert_eq!(out[1]["result"]["tools"], json!([]));
        assert!(out[2]["error"]["message"].as_str().unwrap().contains(why));
        assert!(r.host.seen.lock().unwrap().is_empty());
    }
    let r = rig();
    r.door.set_enabled(false, "ada", now()).unwrap();
    let out = drive(&r, &[init(), list()]);
    assert!(out[0]["result"]["instructions"]
        .as_str()
        .unwrap()
        .contains("turn that on in the dashboard"));
    assert_eq!(out[1]["result"]["tools"], json!([]));
}

#[test]
fn with_no_dashboard_listening_the_bridge_still_answers_and_says_so() {
    let d = tempfile::tempdir().unwrap();
    let mut out = Vec::new();
    bridge::run(
        &d.path().join("none.sock"),
        now,
        Cursor::new(format!("{}\n{}\n", init(), list())),
        &mut out,
    )
    .unwrap();
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("is not answering"), "{text}");
}

#[test]
fn a_line_that_is_not_json_is_answered_with_a_parse_error_and_does_not_end_the_bridge() {
    let r = rig();
    let mut out = Vec::new();
    bridge::run(
        &r.sock,
        now,
        Cursor::new(format!("not json\n[1,2]\n{}\n", list())),
        &mut out,
    )
    .unwrap();
    let lines: Vec<Value> = String::from_utf8(out)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines[0]["error"]["code"], -32700);
    assert_eq!(lines[1]["error"]["code"], -32700);
    assert!(lines[2]["result"]["tools"].is_array());
}

#[test]
fn an_oversized_or_chunked_request_on_the_socket_is_refused() {
    use std::io::Read;
    let r = rig();
    let mut s = UnixStream::connect(&r.sock).unwrap();
    write!(
        s,
        "POST /mcp HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
    )
    .unwrap();
    let mut got = String::new();
    s.read_to_string(&mut got).unwrap();
    assert!(got.starts_with("HTTP/1.1 400"), "{got}");
    let mut s = UnixStream::connect(&r.sock).unwrap();
    write!(s, "POST /mcp HTTP/1.1\r\nContent-Length: 99999999\r\n\r\n").unwrap();
    let mut got = String::new();
    s.read_to_string(&mut got).unwrap();
    assert!(got.starts_with("HTTP/1.1 413"), "{got}");
}

#[test]
fn a_stale_socket_is_replaced_and_something_else_in_the_way_is_not() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("mcp.sock");
    drop(AgentMcp::bind(&p).unwrap());
    assert!(AgentMcp::bind(&p).is_ok());
    let f = d.path().join("file");
    std::fs::write(&f, "x").unwrap();
    assert!(AgentMcp::bind(&f).is_err());
    let m = std::fs::metadata(&p).unwrap();
    assert_eq!(m.permissions().mode() & 0o777, 0o666);
}

// ---- the cost of the hop (benchmark rule, 2026-11-12) ----

/// The bridge's added round trip for the cheapest call (`ping`), over the open connection, against calling the server
/// in-process. Laptop-shaped: it says how much the socket and the bridge cost, not what a call on a 4 vCPU box costs. The
/// browser tools' own latency (CDP, the page) is untouched, and this path is not on any of the benchmark's headline metrics.
#[test]
fn the_bridges_round_trip_is_small() {
    let r = rig();
    let ping = json!({ "jsonrpc": "2.0", "id": 9, "method": "ping" });
    let n = 300usize;
    let input: String = std::iter::once(init())
        .chain((0..n).map(|_| ping.clone()))
        .map(|l| format!("{l}\n"))
        .collect();
    // time the whole stream through one bridge and one connection, minus the handshake and the one enrolment
    let t0 = std::time::Instant::now();
    let mut out = Vec::new();
    bridge::run(&r.sock, now, Cursor::new(input), &mut out).unwrap();
    let per = t0.elapsed().as_micros() as f64 / (n + 1) as f64;
    // the in-process floor: the same message straight into the server
    let s = Session {
        person: "o".into(),
        role: Role::Agent,
    };
    let tok = r.door.server.issue(s, None, now(), 60_000).unwrap().token;
    let req = ProxyRequest {
        method: "POST".into(),
        path: "/mcp".into(),
        headers: vec![("Authorization".into(), format!("Bearer {tok}"))],
        body: ping.to_string().into_bytes(),
    };
    let t1 = std::time::Instant::now();
    for _ in 0..n {
        let _ = r.door.server.handle_on(Reach::Socket, &req, now());
    }
    let floor = t1.elapsed().as_micros() as f64 / n as f64;
    eprintln!("agent-mcp bridge round trip: {per:.0} us per call through the bridge, {floor:.0} us in process, {:.0} us added (laptop-shaped)", per - floor);
    assert_eq!(String::from_utf8(out).unwrap().lines().count(), n + 1);
    assert!(
        per < 50_000.0,
        "a call through the bridge took {per} us (laptop-shaped; the number is printed above)"
    );
}

// ---- the engines' settings ----

mod engine_settings {
    use super::*;
    use crate::agent_mcp::engines::{install, remove, status, Outcome};

    const PROG: &str = "/usr/local/bin/ozbox";

    fn read(p: &Path) -> Value {
        serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
    }

    fn outcome(r: &[(&str, Outcome)], id: &str) -> Outcome {
        r.iter().find(|(i, _)| *i == id).unwrap().1.clone()
    }

    #[test]
    fn install_writes_each_engine_and_a_second_run_changes_nothing() {
        let h = tempfile::tempdir().unwrap();
        let r = install(h.path(), PROG, None);
        assert!(r.iter().all(|(_, o)| *o == Outcome::Wrote), "{r:?}");
        let c = read(&h.path().join(".claude.json"));
        assert_eq!(
            c["mcpServers"]["ozbox"],
            json!({ "type": "stdio", "command": PROG, "args": ["agent-mcp", "bridge"], "env": {} })
        );
        let g = read(&h.path().join(".gemini/settings.json"));
        assert_eq!(
            g["mcpServers"]["ozbox"],
            json!({ "command": PROG, "args": ["agent-mcp", "bridge"] })
        );
        let o = read(&h.path().join(".config/opencode/opencode.json"));
        assert_eq!(
            o["mcp"]["ozbox"],
            json!({ "type": "local", "command": [PROG, "agent-mcp", "bridge"], "enabled": true })
        );
        let x = std::fs::read_to_string(h.path().join(".codex/config.toml")).unwrap();
        let t: toml::Table = x.parse().unwrap();
        assert_eq!(t["mcp_servers"]["ozbox"]["command"].as_str(), Some(PROG));
        assert_eq!(
            t["mcp_servers"]["ozbox"]["args"].as_array().unwrap().len(),
            2
        );
        let again = install(h.path(), PROG, None);
        assert!(
            again.iter().all(|(_, o)| *o == Outcome::Unchanged),
            "{again:?}"
        );
        assert!(status(h.path(), PROG).iter().all(|(_, on)| *on));
    }

    #[test]
    fn a_new_file_is_private_and_an_existing_files_mode_is_kept() {
        let h = tempfile::tempdir().unwrap();
        install(h.path(), PROG, Some("claude-code"));
        let m = std::fs::metadata(h.path().join(".claude.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(m, 0o600);
        let p = h.path().join(".gemini/settings.json");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, "{}").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        install(h.path(), PROG, Some("gemini-cli"));
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }

    #[test]
    fn the_persons_other_servers_and_settings_are_never_touched() {
        let h = tempfile::tempdir().unwrap();
        let p = h.path().join(".claude.json");
        let theirs = json!({
            "numStartups": 12, "theme": "dark",
            "projects": { "/work/app": { "allowedTools": ["Bash(ls)"] } },
            "mcpServers": { "github": { "type": "http", "url": "https://example.test/mcp", "headers": { "Authorization": "Bearer x" } },
                            "local": { "command": "node", "args": ["srv.js"] } }
        });
        std::fs::write(&p, serde_json::to_string_pretty(&theirs).unwrap()).unwrap();
        assert_eq!(
            outcome(&install(h.path(), PROG, Some("claude-code")), "claude-code"),
            Outcome::Wrote
        );
        let mut want = theirs.clone();
        want["mcpServers"]["ozbox"] =
            json!({ "type": "stdio", "command": PROG, "args": ["agent-mcp", "bridge"], "env": {} });
        assert_eq!(read(&p), want);
        assert_eq!(
            outcome(&remove(h.path(), Some("claude-code")), "claude-code"),
            Outcome::Removed
        );
        assert_eq!(read(&p), theirs);
        assert_eq!(
            outcome(&remove(h.path(), Some("claude-code")), "claude-code"),
            Outcome::Absent
        );
    }

    #[test]
    fn our_entry_with_another_program_path_is_updated_and_the_persons_own_ozbox_server_is_left() {
        let h = tempfile::tempdir().unwrap();
        install(h.path(), "/old/ozbox", Some("claude-code"));
        assert_eq!(
            outcome(&install(h.path(), PROG, Some("claude-code")), "claude-code"),
            Outcome::Wrote
        );
        assert_eq!(
            read(&h.path().join(".claude.json"))["mcpServers"]["ozbox"]["command"],
            PROG
        );
        let p = h.path().join(".gemini/settings.json");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        let mine = json!({ "mcpServers": { "ozbox": { "command": "my-own", "args": ["--x"] } } });
        std::fs::write(&p, mine.to_string()).unwrap();
        assert_eq!(
            outcome(&install(h.path(), PROG, Some("gemini-cli")), "gemini-cli"),
            Outcome::LeftYours
        );
        assert_eq!(
            outcome(&remove(h.path(), Some("gemini-cli")), "gemini-cli"),
            Outcome::LeftYours
        );
        assert_eq!(read(&p), mine);
    }

    #[test]
    fn a_file_that_is_not_understood_or_is_a_link_is_not_touched() {
        let h = tempfile::tempdir().unwrap();
        let p = h.path().join(".claude.json");
        std::fs::write(&p, "{ not json").unwrap();
        assert!(matches!(
            outcome(&install(h.path(), PROG, Some("claude-code")), "claude-code"),
            Outcome::Refused(_)
        ));
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "{ not json");
        std::fs::write(&p, "[1]").unwrap();
        assert!(matches!(
            outcome(&install(h.path(), PROG, Some("claude-code")), "claude-code"),
            Outcome::Refused(_)
        ));
        std::fs::write(&p, r#"{"mcpServers": []}"#).unwrap();
        assert!(matches!(
            outcome(&install(h.path(), PROG, Some("claude-code")), "claude-code"),
            Outcome::Refused(_)
        ));
        std::fs::remove_file(&p).unwrap();
        let target = h.path().join("elsewhere.json");
        std::fs::write(&target, "{}").unwrap();
        std::os::unix::fs::symlink(&target, &p).unwrap();
        assert!(matches!(
            outcome(&install(h.path(), PROG, Some("claude-code")), "claude-code"),
            Outcome::Refused(_)
        ));
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "{}");
        // no temp file is left behind in the folder
        assert!(std::fs::read_dir(h.path()).unwrap().all(|e| !e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")));
    }

    #[test]
    fn codex_keeps_the_persons_comments_and_servers_and_removes_only_its_block() {
        let h = tempfile::tempdir().unwrap();
        let p = h.path().join(".codex/config.toml");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        let theirs = "# my codex settings\nmodel = \"o4\"\n\n[mcp_servers.docs]\ncommand = \"docs-server\"\n";
        std::fs::write(&p, theirs).unwrap();
        assert_eq!(
            outcome(&install(h.path(), PROG, Some("codex")), "codex"),
            Outcome::Wrote
        );
        let after = std::fs::read_to_string(&p).unwrap();
        assert!(after.starts_with(theirs.trim_end()), "{after}");
        let t: toml::Table = after.parse().unwrap();
        assert!(
            t["mcp_servers"].as_table().unwrap().contains_key("docs")
                && t["mcp_servers"].as_table().unwrap().contains_key("ozbox")
        );
        assert_eq!(
            outcome(&install(h.path(), PROG, Some("codex")), "codex"),
            Outcome::Unchanged
        );
        assert_eq!(
            outcome(&remove(h.path(), Some("codex")), "codex"),
            Outcome::Removed
        );
        assert_eq!(
            std::fs::read_to_string(&p).unwrap().trim_end(),
            theirs.trim_end()
        );
        // the person's own [mcp_servers.ozbox] is theirs
        std::fs::write(&p, "[mcp_servers.ozbox]\ncommand = \"mine\"\n").unwrap();
        assert_eq!(
            outcome(&install(h.path(), PROG, Some("codex")), "codex"),
            Outcome::LeftYours
        );
        assert_eq!(
            outcome(&remove(h.path(), Some("codex")), "codex"),
            Outcome::LeftYours
        );
        assert_eq!(
            std::fs::read_to_string(&p).unwrap(),
            "[mcp_servers.ozbox]\ncommand = \"mine\"\n"
        );
    }

    #[test]
    fn one_engine_can_be_named_and_the_others_are_left_alone() {
        let h = tempfile::tempdir().unwrap();
        let r = install(h.path(), PROG, Some("opencode"));
        assert_eq!(r.len(), 1);
        assert!(!h.path().join(".claude.json").exists() && !h.path().join(".codex").exists());
        let s = status(h.path(), PROG);
        assert_eq!(
            s.iter()
                .filter(|(_, on)| *on)
                .map(|(i, _)| *i)
                .collect::<Vec<_>>(),
            ["opencode"]
        );
    }
}

// ---- the real browser tools, over the socket, with an approval (skips when there is no Chromium) ----

mod browser_over_the_socket {
    use super::*;
    use crate::browser_tools::{BrowserHost, InProcessBackend};
    use crate::host_tools::{BoxFacts, HostTools};
    use ozbox_browser::policy::BrowserPolicy;
    use ozbox_core::run::{ApprovalState, TaskStore};
    use ozbox_core::supervisor;

    struct Facts;
    impl BoxFacts for Facts {
        fn exists(&self, b: &str) -> bool {
            b == "main-box"
        }
        fn production(&self, _b: &str) -> bool {
            false
        }
    }

    /// The tool host a run would get, as the socket's runner.
    struct Real(HostTools);
    impl ToolRunner for Real {
        fn run(&self, _: &Session, name: &str, _: &Value, _: u64) -> Result<Value, ToolError> {
            Err(ToolError::Refused(format!("{name} needs a box")))
        }
        fn defs(&self, _: &Session, _: Option<&HostScope>) -> Vec<Value> {
            let mut v = crate::host_tools::tool_defs(false);
            v.extend(crate::browser_tools::tool_defs(false));
            v
        }
        fn knows(&self, _: &Session, name: &str, _: Option<&HostScope>) -> bool {
            self.0.handles(name)
        }
        fn run_with(
            &self,
            s: &Session,
            h: Option<&HostScope>,
            name: &str,
            a: &Value,
            now: u64,
        ) -> Result<Value, ToolError> {
            self.0.call(s, h, name, a, now)
        }
    }

    fn text(v: &Value) -> String {
        v["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or("")
            .to_string()
    }

    #[test]
    fn a_fake_claude_code_drives_the_browser_and_a_submit_waits_for_the_person_named() {
        if ozbox_browser::cdp::find_chromium().is_none() {
            assert!(
                std::env::var("OZBOX_REQUIRE_BROWSER").is_err(),
                "OZBOX_REQUIRE_BROWSER is set but no Chromium is installed"
            );
            eprintln!("skipped: no Chromium on this machine");
            return;
        }
        std::env::set_var("OZBOX_BROWSER_NO_SANDBOX", "1");
        let dir = tempfile::tempdir().unwrap();
        let store = TaskStore::new(dir.path().join("tasks.json"));
        let host = Arc::new(BrowserHost::new(
            Arc::new(InProcessBackend::new(dir.path().join("work"))),
            store.clone(),
            dir.path().join("browser-policy.json"),
        ));
        let mut tools = HostTools::new(
            store.clone(),
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
        let site = ozbox_browser::testsite::start(0).unwrap();
        let state = tempfile::tempdir().unwrap();
        let door = AgentMcp::new_with(
            Arc::new(Real(tools)),
            SettingStore::new(state.path()),
            "main-box",
            ME,
            me,
            not_in_a_run,
            who,
        );
        let sock = state.path().join("mcp.sock");
        door.serve(AgentMcp::bind(&sock).unwrap());
        door.set_enabled(true, "ada", now()).unwrap();
        let rig = Rig {
            dir: state,
            sock,
            door,
            host: Arc::new(Host::new()),
        };

        // one engine, one bridge, one enrolment: the approval and the browser session belong to it
        let mut engine = live(&rig);
        let mut go = |lines: &[Value]| lines.iter().map(|l| engine.ask(l)).collect::<Vec<_>>();
        let url = format!("http://127.0.0.1:{}/login", site.port);
        let open = go(&[call("browser_open", json!({ "device": "desktop" }))]);
        let s = open[0]["result"]["structuredContent"]["session"]
            .as_str()
            .unwrap_or_else(|| panic!("{open:?}"))
            .to_string();
        let nav = go(&[call(
            "browser_navigate",
            json!({ "session": s, "url": url }),
        )]);
        assert_eq!(nav[0]["result"]["isError"], false, "{nav:?}");
        let snap = go(&[call("browser_snapshot", json!({ "session": s }))]);
        let shot = snap[0]["result"]["structuredContent"]["snapshot"]
            .as_str()
            .unwrap()
            .to_string();
        let find = |needle: &str| -> String {
            shot.lines()
                .find(|l| l.contains(needle))
                .and_then(|l| l.strip_prefix('[')?.split(' ').next())
                .unwrap_or_else(|| panic!("no {needle}"))
                .to_string()
        };
        go(&[call(
            "browser_type",
            json!({ "session": s, "target": find("\"Username\""), "text": "ada" }),
        )]);
        // the submit waits for a person, and nothing is sent meanwhile
        let click = go(&[call(
            "browser_click",
            json!({ "session": s, "target": find("\"Sign in\"") }),
        )]);
        assert_eq!(click[0]["result"]["isError"], true);
        assert!(
            text(&click[0]).contains("A person has to approve this first"),
            "{click:?}"
        );
        assert!(site.posts.0.lock().unwrap().is_empty());
        let pending: Vec<_> = store
            .load()
            .unwrap()
            .approvals
            .into_iter()
            .filter(|a| a.state == ApprovalState::Pending)
            .collect();
        assert_eq!(pending.len(), 1);
        // the request names the person the agent acts for (the person who turned the setting on)
        assert!(
            pending[0].asked_by.contains("ada") && pending[0].asked_by.contains("terminal"),
            "{}",
            pending[0].asked_by
        );
        store
            .update(|b| supervisor::decide(b, &pending[0].id, true, "ada", false, 2_000))
            .unwrap()
            .unwrap();
        let again = go(&[call(
            "browser_click",
            json!({ "session": s, "target": find("\"Sign in\"") }),
        )]);
        assert_eq!(again[0]["result"]["isError"], false, "{again:?}");
        assert_eq!(site.posts.0.lock().unwrap().len(), 1);
        let audit = std::fs::read_to_string(store.audit_log().path()).unwrap();
        assert!(audit.contains("ada"), "the audit chain names the person");
        let _ = go(&[call("browser_close", json!({ "session": s }))]);
    }
}

// ---- review fixes (2026-11-12) ----

fn enrol(r: &Rig) -> (u16, Value) {
    raw(r, the_box_user(), "POST", "/v1/enrol", &[], &json!({}))
}

/// The key the door gives a process: its pid, start time and the door's epoch.
fn key_for(door: &AgentMcp, pid: u32) -> String {
    let start = who(pid).unwrap().start;
    format!(
        "terminal-{pid}-{start}-{}",
        door.epoch.load(Ordering::SeqCst)
    )
}

/// The code the door gives a process: only the door can make it.
fn code_for(door: &AgentMcp, pid: u32) -> String {
    session_code_of(&door.code_key, pid, who(pid).unwrap().start)
}

fn key_of(r: &Rig, p: Option<Peer>) -> String {
    let t = raw(r, p, "POST", "/v1/enrol", &[], &json!({})).1["token"]
        .as_str()
        .unwrap()
        .to_string();
    raw(
        r,
        p,
        "POST",
        "/mcp",
        &[("Authorization", &format!("Bearer {t}"))],
        &call("browser_open", json!({})),
    );
    r.host.seen.lock().unwrap().last().unwrap()["session"]
        .as_str()
        .unwrap()
        .to_string()
}

/// H1 + M1 + N1: a program's key is its pid and start time as the kernel says them. It is the same when the same process
/// enrols again (a renewal), and different for another process, or for a new process that reused a pid.
#[test]
fn a_programs_key_is_its_pid_and_start_time_and_survives_a_renewal() {
    let r = rig();
    let a1 = key_of(&r, peer(10));
    let a2 = key_of(&r, peer(10));
    let b = key_of(&r, peer(11));
    assert_eq!(a1, a2, "a renewal keeps the key");
    assert_ne!(a1, b, "another program has another key");
    assert_eq!(a1, key_for(&r.door, 10));
    assert!(a1.starts_with("terminal-10-9010-"), "{a1}");
    REUSED_START.store(500, Ordering::SeqCst);
    let old = key_of(&r, peer(77));
    REUSED_START.store(900, Ordering::SeqCst);
    let new = key_of(&r, peer(77));
    assert_ne!(old, new, "a new process that reuses a pid has another key");
}

/// N1: a process the kernel cannot describe is given no session.
#[test]
fn a_process_that_cannot_be_identified_gets_no_session() {
    fn nobody(_: u32) -> Option<ProcIdent> {
        None
    }
    let dir = tempfile::tempdir().unwrap();
    let host = Arc::new(Host::new());
    let door = AgentMcp::new_with(
        host,
        SettingStore::new(dir.path()),
        "main-box",
        ME,
        me,
        not_in_a_run,
        nobody,
    );
    let req = http::Request {
        method: "POST".into(),
        path: "/v1/enrol".into(),
        headers: vec![],
        body: b"{}".to_vec(),
    };
    assert_eq!(door.route(peer(10), &req, now()).0, 403);
}

#[test]
fn the_start_time_is_read_from_the_stat_line_whatever_the_programs_name_holds() {
    // field 22 counted from the last ')': the name may hold spaces, digits and brackets
    let tail = "S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 123456 20 21";
    assert_eq!(
        parse_stat_start(&format!("42 (claude) {tail}")),
        Some(123456)
    );
    assert_eq!(
        parse_stat_start(&format!("42 (a b) (c) {tail}")),
        Some(123456)
    );
    assert_eq!(parse_stat_start("42 (x) S 1"), None);
    assert_eq!(parse_stat_start("nothing"), None);
    assert_eq!(clean_program("/usr/bin/claude"), "claude");
    assert_eq!(clean_program("a b\n;rm -rf"), "abrm-rf");
    assert_eq!(clean_program(""), "unknown");
    assert!(clean_program(&"x".repeat(100)).len() <= 32);
}

/// M2: turning it off fails closed. The state folder cannot be written, the save fails, and the door is shut anyway.
#[test]
fn turning_it_off_with_an_unwritable_state_folder_still_revokes_and_refuses() {
    let r = rig();
    let t = enrol(&r).1["token"].as_str().unwrap().to_string();
    let auth = format!("Bearer {t}");
    assert_eq!(
        raw(
            &r,
            the_box_user(),
            "POST",
            "/mcp",
            &[("Authorization", &auth)],
            &list()
        )
        .0,
        200
    );
    std::fs::set_permissions(r.dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
    if std::fs::write(r.dir.path().join("probe"), "x").is_ok() {
        // running as a user the folder's mode does not bind (root): the case cannot be made here
        std::fs::set_permissions(r.dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        return;
    }
    let saved = r.door.set_enabled(false, "ada", now()).unwrap();
    assert!(!saved.persisted, "the file could not be written");
    assert_eq!(
        r.door.live_tokens(now()),
        0,
        "the tokens were revoked first"
    );
    assert_eq!(
        raw(
            &r,
            the_box_user(),
            "POST",
            "/mcp",
            &[("Authorization", &auth)],
            &list()
        )
        .0,
        403
    );
    assert_eq!(enrol(&r).1["code"], "Off");
    assert!(
        !r.door.persisted(),
        "the dashboard can say it is off only until it restarts"
    );
    // turning it ON with the folder unwritable changes nothing
    assert!(r.door.set_enabled(true, "ada", now()).is_err());
    assert!(!r.door.setting().enabled);
    std::fs::set_permissions(r.dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
}

/// H1: standing permission is off by default; it is a short, explicit opt-in that ends every token when it starts or ends,
/// and a token never outlives it.
#[test]
fn standing_permission_is_off_by_default_short_and_ends_every_token() {
    let r = rig();
    let a = enrol(&r).1;
    assert_eq!(a["standing"], false);
    let ta = a["token"].as_str().unwrap().to_string();
    assert!(r.door.set_standing(Some(10), "ada", now()).is_ok());
    assert_eq!(
        r.door.live_tokens(now()),
        0,
        "the old token did not carry its actor into the new setting"
    );
    let b = enrol(&r).1;
    assert_eq!(b["standing"], true);
    let ends = b["expires_ms"].as_u64().unwrap();
    assert!(
        ends <= now() + 10 * 60_000 + 1_000 && ends < now() + TOKEN_TTL_MS,
        "the token ends with the standing permission"
    );
    let tb = b["token"].as_str().unwrap().to_string();
    raw(
        &r,
        the_box_user(),
        "POST",
        "/mcp",
        &[("Authorization", &format!("Bearer {tb}"))],
        &call("browser_open", json!({})),
    );
    assert_eq!(
        r.host.seen.lock().unwrap().last().unwrap()["actor"],
        "Some(TerminalStanding)"
    );
    assert_eq!(
        raw(
            &r,
            the_box_user(),
            "POST",
            "/mcp",
            &[("Authorization", &format!("Bearer {ta}"))],
            &list()
        )
        .0,
        401
    );
    // it is shown on the page, and ending it ends the token and brings back the plain terminal agent
    assert!(
        view(Some(&r.door), now())["standing_until_ms"]
            .as_u64()
            .unwrap()
            > now()
    );
    r.door.set_standing(None, "ada", now()).unwrap();
    assert_eq!(
        raw(
            &r,
            the_box_user(),
            "POST",
            "/mcp",
            &[("Authorization", &format!("Bearer {tb}"))],
            &list()
        )
        .0,
        401
    );
    assert_eq!(enrol(&r).1["standing"], false);
    // bounds, and it needs the tools to be on; turning the tools off clears it
    assert!(r.door.set_standing(Some(0), "ada", now()).is_err());
    assert!(r
        .door
        .set_standing(Some(STANDING_MAX_MINUTES + 1), "ada", now())
        .is_err());
    r.door.set_standing(Some(5), "ada", now()).unwrap();
    r.door.set_enabled(false, "ada", now()).unwrap();
    assert_eq!(r.door.setting().standing_until_ms, 0);
    assert!(r.door.set_standing(Some(5), "ada", now()).is_err());
    // and an expired one is not standing, whatever the file says
    r.door.set_enabled(true, "ada", now()).unwrap();
    assert!(
        Setting {
            standing_until_ms: now() - 1,
            ..r.door.setting()
        }
        .standing_left_ms(now())
            == 0
    );
}

/// M4 + N2: each process has its own enrolment budget and token cap, so one process cannot spend another's or push its
/// token out; a caller that is not the box user is dropped at accept; slots are held per process.
#[test]
fn enrolments_are_budgeted_per_process_and_one_process_cannot_evict_anothers_token() {
    let r = rig();
    let enrol_as = |pid| raw(&r, peer(pid), "POST", "/v1/enrol", &[], &json!({}));
    let theirs = enrol_as(20).1["token"].as_str().unwrap().to_string();
    let mut codes = Vec::new();
    for _ in 0..8 {
        codes.push(enrol_as(21).0);
    }
    assert_eq!(
        &codes[..ENROLS_PER_PROCESS_PER_MINUTE],
        &[200; ENROLS_PER_PROCESS_PER_MINUTE],
        "{codes:?}"
    );
    assert!(
        codes[ENROLS_PER_PROCESS_PER_MINUTE..]
            .iter()
            .all(|c| *c == 429),
        "{codes:?}"
    );
    assert_eq!(
        enrol_as(21).1["error"],
        "this program asked for too many sessions; wait a minute"
    );
    assert!(
        r.door.live_tokens(now()) <= 1 + TOKENS_PER_PROCESS,
        "{}",
        r.door.live_tokens(now())
    );
    let auth = format!("Bearer {theirs}");
    assert_eq!(
        raw(
            &r,
            peer(20),
            "POST",
            "/mcp",
            &[("Authorization", &auth)],
            &list()
        )
        .0,
        200,
        "the other process kept its token"
    );
    assert_eq!(enrol_as(22).0, 200, "and another process can still enrol");

    // many processes: the door's own cap holds, and the one that hoards loses, not the one with a single token
    let d = rig();
    let single = raw(&d, peer(30), "POST", "/v1/enrol", &[], &json!({})).1["token"]
        .as_str()
        .unwrap()
        .to_string();
    for pid in 31..=34 {
        for _ in 0..TOKENS_PER_PROCESS {
            assert_eq!(
                raw(&d, peer(pid), "POST", "/v1/enrol", &[], &json!({})).0,
                200
            );
        }
    }
    for pid in 35..=40 {
        let _ = raw(&d, peer(pid), "POST", "/v1/enrol", &[], &json!({}));
    }
    assert!(
        d.door.live_tokens(now()) <= MAX_LIVE_TOKENS,
        "{}",
        d.door.live_tokens(now())
    );
    assert_eq!(
        raw(
            &d,
            peer(30),
            "POST",
            "/mcp",
            &[("Authorization", &format!("Bearer {single}"))],
            &list()
        )
        .0,
        200,
        "a single token is the last to go"
    );

    let e = rig();
    let p = |uid, pid| {
        Some(Peer {
            uid,
            pid: Some(pid),
        })
    };
    assert_eq!(
        e.door.take_slot(p(ME + 1, 5)),
        None,
        "another user holds no slot"
    );
    assert_eq!(e.door.take_slot(None), None);
    let held: Vec<_> = (0..MAX_PER_PEER)
        .map(|_| e.door.take_slot(p(ME, 5)).unwrap())
        .collect();
    assert_eq!(
        e.door.take_slot(p(ME, 5)),
        None,
        "one process cannot take every slot"
    );
    assert!(
        e.door.take_slot(p(ME, 6)).is_some(),
        "another process still can"
    );
    e.door.release(held[0]);
    assert!(e.door.take_slot(p(ME, 5)).is_some());
}

/// N2: a refused caller's connection is closed after the answer, so it does not keep its slot.
#[test]
fn a_refused_caller_is_answered_and_its_connection_is_closed() {
    let r = rig_with(me, in_a_run);
    let mut s = UnixStream::connect(&r.sock).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    http::write_request(&mut s, "POST", "/v1/enrol", &[], b"{}").unwrap();
    let mut rd = BufReader::new(s.try_clone().unwrap());
    let (status, _) = http::read_response(&mut rd, 4096).unwrap();
    assert_eq!(status, 403);
    assert!(
        http::read_response(&mut rd, 4096).is_err(),
        "the door closed the connection"
    );
    // a caller that is let in keeps its connection for the next request
    let ok = rig();
    let mut s = UnixStream::connect(&ok.sock).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut rd = BufReader::new(s.try_clone().unwrap());
    for _ in 0..2 {
        http::write_request(&mut s, "POST", "/v1/enrol", &[], b"{}").unwrap();
        assert_eq!(http::read_response(&mut rd, 4096).unwrap().0, 200);
    }
}

/// H2: the door names THIS box by the machine's own identity. A dashboard with a provider configured lists a fleet, and the
/// first box of a fleet is not this machine.
#[test]
fn the_door_names_this_box_and_stays_shut_on_a_dashboard_that_lists_a_fleet() {
    let fleet = vec!["aaa-first".to_string(), "main-box".to_string()];
    assert_eq!(
        door_box_name(true, false, "main-box", &fleet).as_deref(),
        Some("main-box"),
        "this box, not the first listed"
    );
    assert_eq!(
        door_box_name(false, false, "main-box", &fleet),
        None,
        "a configured provider: shut"
    );
    assert_eq!(door_box_name(false, false, "main-box", &[]), None);
    // only a debug build with the test socket named takes the first listed box (the tests and the browser specs)
    assert_eq!(
        door_box_name(false, true, "main-box", &fleet).as_deref(),
        Some("aaa-first")
    );
}

/// L7: the choice is on disk from the first start.
#[test]
fn the_first_start_writes_the_choice_down_and_never_overwrites_it() {
    let d = tempfile::tempdir().unwrap();
    let st = SettingStore::new(d.path());
    st.ensure();
    assert!(d.path().join("agent-mcp.json").exists() && st.load().enabled);
    st.save(&Setting {
        enabled: false,
        by: "ada".into(),
        at_ms: 5,
        standing_until_ms: 0,
    })
    .unwrap();
    st.ensure();
    assert!(!st.load().enabled);
}

/// A connection that sends nothing is let go by the first-request timeout (the constants are part of the contract).
#[test]
fn a_silent_connection_is_let_go_sooner_than_an_idle_one() {
    assert!(FIRST_REQUEST < IDLE && FIRST_REQUEST <= Duration::from_secs(10));
}

// ---- H1 end to end: an escaped run gains nothing through the door ----

mod escaped_run {
    use super::*;
    use crate::host_tools::{BoxFacts, HostTools};
    use ozbox_core::permissions::{Mode, NewGrant, Scope, SecondFactor};
    use ozbox_core::run::{ApprovalState, TaskStore};
    use ozbox_core::supervisor;

    struct Facts;
    impl BoxFacts for Facts {
        fn exists(&self, b: &str) -> bool {
            b == "main-box"
        }
        fn production(&self, _b: &str) -> bool {
            false
        }
    }

    struct Real(HostTools);
    impl ToolRunner for Real {
        fn run(&self, _: &Session, name: &str, _: &Value, _: u64) -> Result<Value, ToolError> {
            Err(ToolError::Refused(format!("{name} needs a box")))
        }
        fn defs(&self, _: &Session, _: Option<&HostScope>) -> Vec<Value> {
            crate::host_tools::tool_defs(false)
        }
        fn knows(&self, _: &Session, name: &str, _: Option<&HostScope>) -> bool {
            self.0.handles(name)
        }
        fn run_with(
            &self,
            s: &Session,
            h: Option<&HostScope>,
            name: &str,
            a: &Value,
            now: u64,
        ) -> Result<Value, ToolError> {
            self.0.call(s, h, name, a, now)
        }
    }

    fn text(v: &Value) -> String {
        v["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or("")
            .to_string()
    }

    /// The person set `auto` mode and made a box grant. A process that left its run's scope (the cgroup check says "not in a
    /// run" for it) enrols. It gets neither: its write asks, the card says what it is, and approvals are not shared between
    /// enrolments. With the person's explicit, short standing permission the same write goes through.
    #[test]
    fn a_process_that_escaped_its_run_and_enrols_gets_no_auto_mode_and_no_grant() {
        let dir = tempfile::tempdir().unwrap();
        let store = TaskStore::new(dir.path().join("tasks.json"));
        store
            .update(|b| {
                b.perms.default_mode = Mode::Auto;
                b.perms
                    .create_grant(
                        NewGrant {
                            granted_by: "ada".into(),
                            scope: Scope::Box,
                            scope_id: "main-box".into(),
                            actions: vec!["*".into()],
                            reason: "ship the fix".into(),
                            minutes: 60,
                            factor: SecondFactor::StepUp,
                            allow_unattended: true,
                            max_uses: None,
                        },
                        now(),
                    )
                    .unwrap();
            })
            .unwrap();
        let mut tools = HostTools::new(
            store.clone(),
            Arc::new(crate::host_tools::backend::LocalBackend::new(
                dir.path().join("work"),
            )),
            Arc::new(Facts),
        );
        tools.ask_wait = Duration::from_millis(80);
        tools.poll = Duration::from_millis(10);
        let state = tempfile::tempdir().unwrap();
        // `not_in_a_run`: the escaped process reads as an ordinary terminal one
        let door = AgentMcp::new_with(
            Arc::new(Real(tools)),
            SettingStore::new(state.path()),
            "main-box",
            ME,
            me,
            not_in_a_run,
            who,
        );
        let sock = state.path().join("mcp.sock");
        door.serve(AgentMcp::bind(&sock).unwrap());
        let rig = Rig {
            dir: state,
            sock,
            door,
            host: Arc::new(Host::new()),
        };
        // a second program on the box: another process, so another key (the same program renewing would keep its own)
        fn me_b(_: &UnixStream) -> Option<Peer> {
            Some(Peer {
                uid: ME,
                pid: Some(4343),
            })
        }
        let mut tools_b = HostTools::new(
            store.clone(),
            Arc::new(crate::host_tools::backend::LocalBackend::new(
                dir.path().join("work"),
            )),
            Arc::new(Facts),
        );
        tools_b.ask_wait = Duration::from_millis(80);
        tools_b.poll = Duration::from_millis(10);
        let state_b = tempfile::tempdir().unwrap();
        let door_b = AgentMcp::new_with(
            Arc::new(Real(tools_b)),
            SettingStore::new(state_b.path()),
            "main-box",
            ME,
            me_b,
            not_in_a_run,
            who,
        );
        let sock_b = state_b.path().join("mcp.sock");
        door_b.serve(AgentMcp::bind(&sock_b).unwrap());
        let rig_b = Rig {
            dir: state_b,
            sock: sock_b,
            door: door_b,
            host: Arc::new(Host::new()),
        };
        let write = |c: u64| {
            call(
                "files_write",
                json!({ "path": format!("a{c}.txt"), "content": "x" }),
            )
        };

        let mut a = live(&rig);
        let r = a.ask(&write(1));
        assert_eq!(
            r["result"]["isError"], true,
            "auto mode and a grant do not cover a terminal agent: {r:?}"
        );
        assert!(
            text(&r).contains("A person has to approve this first"),
            "{}",
            text(&r)
        );
        assert!(!dir.path().join("work/main-box/a1.txt").exists());
        let pending: Vec<_> = store
            .load()
            .unwrap()
            .approvals
            .into_iter()
            .filter(|x| x.state == ApprovalState::Pending)
            .collect();
        assert_eq!(pending.len(), 1);
        // N3 + R1: the card makes a claim about the ENGINE (the bridge's parent, as the kernel says, not as the caller said),
        // never names the bridge, and gives a code to match with what the engine shows
        let card = &pending[0].asked_by;
        let code = code_for(&rig.door, 4242);
        assert!(card.starts_with(&format!("a program that calls itself claude (pid 5242, session {code}), in this box's terminal")), "{card}");
        assert!(!card.contains("ozbox"), "{card}");
        // S2: the person reads the code where the engine shows them the call, not only on the card
        assert!(
            text(&r).contains(&format!("The card names this session {code}.")),
            "{}",
            text(&r)
        );

        // a second program asking for the same thing is a second request: it does not spend the first one's approval
        let mut b = live(&rig_b);
        let r = b.ask(&write(1));
        assert_eq!(r["result"]["isError"], true);
        let all = store.load().unwrap().approvals;
        assert_eq!(
            all.iter()
                .filter(|x| x.state == ApprovalState::Pending)
                .count(),
            2,
            "{all:?}"
        );
        let first = all[0].id.clone();
        store
            .update(|bk| supervisor::decide(bk, &first, true, "ada", false, 2_000))
            .unwrap()
            .unwrap();
        let again = b.ask(&write(1));
        assert_eq!(
            again["result"]["isError"], true,
            "the other enrolment did not get a's approval"
        );
        let ok = a.ask(&write(1));
        assert_eq!(
            ok["result"]["isError"], false,
            "the person's approval covers the program it was asked for: {ok:?}"
        );

        // the audit tells them apart, and names the program
        assert!(
            std::fs::read_to_string(store.audit_log().path())
                .unwrap()
                .contains("[claude:5242]"),
            "the audit names the pid the card shows"
        );
        let audit = std::fs::read_to_string(store.audit_log().path()).unwrap();
        let actors: std::collections::BTreeSet<&str> = audit
            .lines()
            .filter_map(|l| l.split("mcp:terminal-").nth(1))
            .filter_map(|r| {
                r.split(|c: char| !c.is_ascii_alphanumeric() && c != '-')
                    .next()
            })
            .collect();
        assert!(actors.len() >= 2, "{actors:?}\n{audit}");

        // the person's explicit standing permission (a short one) makes the same write go through, as auto mode and the grant say
        rig.door.set_standing(Some(5), "ada", now()).unwrap();
        let mut c = live(&rig);
        let r = c.ask(&write(2));
        assert_eq!(r["result"]["isError"], false, "{r:?}");
        assert!(dir.path().join("work/main-box/a2.txt").exists());
        // and ending it asks again
        rig.door.set_standing(None, "ada", now()).unwrap();
        let mut d = live(&rig);
        assert_eq!(d.ask(&write(3))["result"]["isError"], true);
    }

    /// N1: a renewal in the middle of a browser task. The same process enrols again (its token was about to end, or the
    /// dashboard restarted) and gets the same key: it still drives its own browser session, its pending approval is still the
    /// one request, and another program, or a new process that reused the pid, gets neither.
    #[test]
    fn a_renewal_in_the_middle_of_a_browser_task_keeps_its_session_and_its_pending_approval() {
        use crate::browser_tools::{BrowserHost, InProcessBackend};
        let dir = tempfile::tempdir().unwrap();
        let store = TaskStore::new(dir.path().join("tasks.json"));
        let browser = Arc::new(BrowserHost::new(
            Arc::new(InProcessBackend::new(dir.path().join("work"))),
            store.clone(),
            dir.path().join("browser-policy.json"),
        ));
        let mut tools = HostTools::new(
            store.clone(),
            Arc::new(crate::host_tools::backend::LocalBackend::new(
                dir.path().join("work"),
            )),
            Arc::new(Facts),
        );
        tools.ask_wait = Duration::from_millis(60);
        tools.poll = Duration::from_millis(10);
        tools.browser = Some(Arc::clone(&browser));
        let state = tempfile::tempdir().unwrap();
        let door = AgentMcp::new_with(
            Arc::new(Real(tools)),
            SettingStore::new(state.path()),
            "main-box",
            ME,
            me,
            not_in_a_run,
            who,
        );
        let sock = state.path().join("mcp.sock");
        door.serve(AgentMcp::bind(&sock).unwrap());
        let rig = Rig {
            dir: state,
            sock,
            door,
            host: Arc::new(Host::new()),
        };

        // the program's first session: it opens a browser session (planted: there is no Chromium in the test) and asks
        // for a write, which waits for a person
        browser.plant_session("s1", "main-box", Some(&key_for(&rig.door, 10)));
        let go = |p: Option<Peer>, t: &str, c: Value| {
            raw(
                &rig,
                p,
                "POST",
                "/mcp",
                &[("Authorization", &format!("Bearer {t}"))],
                &c,
            )
            .1
        };
        let text = |v: &Value| {
            v["result"]["content"][0]["text"]
                .as_str()
                .unwrap_or("")
                .to_string()
        };
        let token = |p| {
            raw(&rig, p, "POST", "/v1/enrol", &[], &json!({})).1["token"]
                .as_str()
                .unwrap()
                .to_string()
        };
        let write = call("files_write", json!({ "path": "a.txt", "content": "x" }));
        let snap = call("browser_snapshot", json!({ "session": "s1" }));
        let pending = || {
            store
                .load()
                .unwrap()
                .approvals
                .into_iter()
                .filter(|x| x.state == ApprovalState::Pending)
                .count()
        };

        let t1 = token(peer(10));
        assert!(text(&go(peer(10), &t1, write.clone())).contains("A person has to approve"));
        assert_eq!(pending(), 1);

        // the renewal: a second token for the same process
        let t2 = token(peer(10));
        assert_ne!(t1, t2);
        assert!(
            !text(&go(peer(10), &t2, snap.clone())).contains("no such browser session"),
            "its own session is still its own"
        );
        assert!(text(&go(peer(10), &t2, write.clone())).contains("A person has to approve"));
        assert_eq!(
            pending(),
            1,
            "the renewed token waits on the same request, it does not ask again"
        );
        // the person approves; the renewed token's retry goes through
        let id = store.load().unwrap().approvals[0].id.clone();
        store
            .update(|b| supervisor::decide(b, &id, true, "ada", false, 2_000))
            .unwrap()
            .unwrap();
        assert_eq!(go(peer(10), &t2, write)["result"]["isError"], false);

        // another program does not drive it, and a new process on a reused pid does not either
        let other = token(peer(11));
        assert!(text(&go(peer(11), &other, snap.clone())).contains("no such browser session"));
        REUSED_START_2.store(500, Ordering::SeqCst);
        browser.plant_session("s2", "main-box", Some(&key_for(&rig.door, 78)));
        let before = token(peer(78));
        assert!(!text(&go(
            peer(78),
            &before,
            call("browser_snapshot", json!({ "session": "s2" }))
        ))
        .contains("no such browser session"));
        REUSED_START_2.store(901, Ordering::SeqCst);
        let reused = token(peer(78));
        assert!(text(&go(
            peer(78),
            &reused,
            call("browser_snapshot", json!({ "session": "s2" }))
        ))
        .contains("no such browser session"));
    }
}

// ---- N9: a terminal enrolment is credited with what it proposes ----

mod credited {
    use super::*;
    use crate::host_tools::{BoxFacts, HostTools};
    use crate::mcp::Composite;
    use crate::memory_tools::MemoryHost;
    use crate::orch_tools::{BoxOps, Tools};
    use ozbox_core::run::TaskStore;

    struct Facts;
    impl BoxFacts for Facts {
        fn exists(&self, b: &str) -> bool {
            b == "main-box"
        }
        fn production(&self, _b: &str) -> bool {
            false
        }
    }
    struct NoFleet;
    impl BoxOps for NoFleet {
        fn list(&self) -> std::result::Result<Vec<Value>, String> {
            Err("no".into())
        }
        fn plan(&self, _: Value) -> std::result::Result<Value, String> {
            Err("no".into())
        }
        fn apply(&self, _: &str, _: &Value) -> std::result::Result<Value, String> {
            Err("no".into())
        }
    }

    #[test]
    fn a_note_a_terminal_program_proposes_names_that_program_not_the_persons_agent() {
        let dir = tempfile::tempdir().unwrap();
        let store = TaskStore::new(dir.path().join("tasks.json"));
        let mem = Arc::new(MemoryHost::open(&dir.path().join("mem")).unwrap());
        let orch = Tools::new(store.clone(), Arc::new(NoFleet)).with_memory(Some(Arc::clone(&mem)));
        let host = HostTools::new(
            store,
            Arc::new(crate::host_tools::backend::LocalBackend::new(
                dir.path().join("work"),
            )),
            Arc::new(Facts),
        );
        let state = tempfile::tempdir().unwrap();
        let door = AgentMcp::new_with(
            Arc::new(Composite { orch, host }),
            SettingStore::new(state.path()),
            "main-box",
            ME,
            me,
            not_in_a_run,
            who,
        );
        let sock = state.path().join("mcp.sock");
        door.serve(AgentMcp::bind(&sock).unwrap());
        let rig = Rig {
            dir: state,
            sock,
            door,
            host: Arc::new(Host::new()),
        };
        let t = enrol(&rig).1["token"].as_str().unwrap().to_string();
        let (status, v) = raw(
            &rig,
            the_box_user(),
            "POST",
            "/mcp",
            &[("Authorization", &format!("Bearer {t}"))],
            &call(
                "memory_write",
                json!({ "title": "how it builds", "body": "cargo build" }),
            ),
        );
        assert_eq!(status, 200);
        let id = v["result"]["structuredContent"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("{v}"))
            .to_string();
        let e = mem
            .memory
            .get(
                &ozbox_memory::memory::Caller::Person("owner".into()),
                &id,
                now(),
            )
            .unwrap();
        // S1: a note names the enrolment by its session code, never by its key, so no caller who reads the note learns the key
        let name = format!("terminal-{}", code_for(&rig.door, 1));
        assert_eq!(
            e.provenance.actor,
            format!("agent:{name}"),
            "{:?}",
            e.provenance
        );
        // R5: it is in its own field; `run` stays for runs
        assert_eq!(e.provenance.session.as_deref(), Some(name.as_str()));
        assert_eq!(e.provenance.run, None);
        // approved by the person, then read back by a terminal caller: the answer holds the code and nothing of the key
        mem.memory
            .approve(
                &ozbox_memory::memory::Caller::Person("owner".into()),
                &id,
                now(),
            )
            .unwrap();
        let (_, back) = raw(
            &rig,
            the_box_user(),
            "POST",
            "/mcp",
            &[("Authorization", &format!("Bearer {t}"))],
            &call("memory_read", json!({ "id": id })),
        );
        let answer = back.to_string();
        assert!(answer.contains(&name), "{answer}");
        assert!(
            !answer.contains(&key_for(&rig.door, 1)) && !answer.contains("terminal-1-"),
            "{answer}"
        );
    }
}

// ---- M5: the engines' writers ----

mod engine_writers {
    use crate::agent_mcp::engines::{install, retrying, write_atomic, Outcome, CHANGED};

    #[test]
    fn codex_with_an_inline_mcp_servers_table_is_refused_and_left_as_it_was() {
        let h = tempfile::tempdir().unwrap();
        let p = h.path().join(".codex/config.toml");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        let theirs = "mcp_servers = { docs = { command = \"d\" } }\n";
        std::fs::write(&p, theirs).unwrap();
        let r = install(h.path(), "/usr/local/bin/ozbox", Some("codex"));
        assert!(
            matches!(&r[0].1, Outcome::Refused(w) if w.contains("TOML")),
            "{r:?}"
        );
        assert_eq!(
            std::fs::read_to_string(&p).unwrap(),
            theirs,
            "the person's file is exactly as it was"
        );
    }

    #[test]
    fn a_file_another_program_changed_between_the_read_and_the_rename_is_not_overwritten() {
        let h = tempfile::tempdir().unwrap();
        let p = h.path().join("settings.json");
        std::fs::write(&p, "{\"theirs\":2}").unwrap();
        let stale = Some("{\"theirs\":1}".to_string());
        let r = write_atomic(&p, "{\"ours\":1}", None, Some(&stale));
        assert_eq!(r, Err(Outcome::Refused(CHANGED.into())));
        assert_eq!(
            std::fs::read_to_string(&p).unwrap(),
            "{\"theirs\":2}",
            "the other writer's change survives"
        );
        assert!(std::fs::read_dir(h.path()).unwrap().all(|e| !e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")));
        // a file that appeared when none was expected is the same
        let q = h.path().join("new.json");
        std::fs::write(&q, "{}").unwrap();
        assert!(write_atomic(&q, "{}", None, Some(&None)).is_err());
        // unchanged: it goes through
        assert!(write_atomic(
            &p,
            "{\"ours\":1}",
            None,
            Some(&Some("{\"theirs\":2}".into()))
        )
        .is_ok());
    }

    #[test]
    fn a_change_that_raced_is_read_again_and_tried_again() {
        let mut n = 0;
        let o = retrying(|| {
            n += 1;
            if n < 3 {
                Outcome::Refused(CHANGED.into())
            } else {
                Outcome::Wrote
            }
        });
        assert_eq!((o, n), (Outcome::Wrote, 3));
        let o = retrying(|| Outcome::Refused(CHANGED.into()));
        assert!(matches!(o, Outcome::Refused(w) if w.contains("kept changing")));
    }
}

// ---- review round 2 (R1 R2 R3 R8 R9) ----

static REUSED_START_3: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(500);
fn who_3(pid: u32) -> Option<ProcIdent> {
    let start = if pid == 79 {
        REUSED_START_3.load(Ordering::SeqCst)
    } else {
        9000 + u64::from(pid)
    };
    Some(ProcIdent {
        start,
        program: "claude".into(),
        parent_pid: Some(pid + 1000),
    })
}

fn req(path: &str) -> http::Request {
    http::Request {
        method: "POST".into(),
        path: path.into(),
        headers: vec![],
        body: b"{}".to_vec(),
    }
}

/// R2: a connection belongs to the process that opened it. The pid is given to a new process (so the start time changes),
/// and the connection is closed on its next request: it never gets the new process's key, nor a token on it.
#[test]
fn a_connection_whose_process_changed_is_closed_and_gets_no_key() {
    let dir = tempfile::tempdir().unwrap();
    let host = Arc::new(Host::new());
    let door = AgentMcp::new_with(
        host,
        SettingStore::new(dir.path()),
        "main-box",
        ME,
        me,
        not_in_a_run,
        who_3,
    );
    REUSED_START_3.store(500, Ordering::SeqCst);
    let bound = who_3(79).unwrap();
    let p = peer(79);
    let (s1, b1, close1) = door.route_conn(p, Some(&bound), &req("/v1/enrol"), now());
    assert_eq!((s1, close1), (200, false));
    let token = serde_json::from_slice::<Value>(&b1).unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();
    // the opener has gone and its pid belongs to the person's bridge now
    REUSED_START_3.store(901, Ordering::SeqCst);
    let (s2, b2, close2) = door.route_conn(p, Some(&bound), &req("/v1/enrol"), now());
    assert_eq!((s2, close2), (403, true), "the connection is closed");
    assert_eq!(
        serde_json::from_slice::<Value>(&b2).unwrap()["code"],
        "Changed"
    );
    assert!(serde_json::from_slice::<Value>(&b2)
        .unwrap()
        .get("token")
        .is_none());
    // the same on the tool path, and with no identity bound at all
    let mut call_req = req("/mcp");
    call_req.headers = vec![("Authorization".into(), format!("Bearer {token}"))];
    assert_eq!(door.route_conn(p, Some(&bound), &call_req, now()).0, 403);
    assert!(door.route_conn(p, None, &req("/v1/enrol"), now()).2);
    // the process that really holds the pid now connects afresh, with its own identity, and gets its own key
    let fresh = who_3(79).unwrap();
    assert_eq!(
        door.route_conn(p, Some(&fresh), &req("/v1/enrol"), now()).0,
        200
    );
}

#[test]
fn the_parent_pid_is_read_from_the_stat_line_and_the_bridge_is_never_the_name() {
    let tail = "S 4242 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 123456 20 21";
    assert_eq!(parse_stat_ppid(&format!("42 (ozbox) {tail}")), Some(4242));
    assert_eq!(parse_stat_ppid(&format!("42 (a b) (c) {tail}")), Some(4242));
    assert_eq!(parse_stat_ppid("42 (ozbox) S 0 2"), None, "pid 0 is nobody");
    assert_eq!(parse_stat_ppid("nothing"), None);
    // on a Linux box the door's reading is of the parent: the test process's own parent is a real, named process
    #[cfg(target_os = "linux")]
    {
        let me_pid = std::process::id();
        let id = proc_ident(me_pid).unwrap();
        let ppid = std::os::unix::process::parent_id();
        assert_eq!(id.parent_pid, Some(ppid));
        assert_ne!(id.program, "unknown");
    }
}

/// R1: the engine is shown the session code in the handshake and on its log; the person's card shows the same code; a script
/// that runs its own bridge has another process, so another code.
#[test]
fn the_handshake_carries_the_session_code_and_it_is_the_one_on_the_card() {
    let r = rig();
    let out = drive(&r, &[init()]);
    let said = out[0]["result"]["instructions"]
        .as_str()
        .unwrap()
        .to_string();
    let code = code_for(&r.door, 4242);
    assert!(
        said.contains(&format!("Oz Box session code {code}")),
        "{said}"
    );
    // the enrolment's own answer names it too, and another program has another code
    let mine = raw(&r, peer(4242), "POST", "/v1/enrol", &[], &json!({})).1;
    assert_eq!(mine["code"], code.as_str());
    let script = raw(&r, peer(4243), "POST", "/v1/enrol", &[], &json!({})).1;
    assert_ne!(script["code"], mine["code"]);
}

/// R3 + S3: the door-wide cap is REACHED (16 holders) and the newcomer, never a holder, is the one asked to wait, whatever its
/// pid sorts like and however many times it comes back. A holder that renews replaces its own token and is never turned away.
#[test]
fn at_the_cap_a_newcomer_waits_and_never_pushes_a_holder_out() {
    let r = rig();
    let at = now();
    let enrol_as = |pid: u32, t: u64| raw_at(&r, peer(pid), t);
    // the person's bridge first: a pid that sorts LAST as text
    let person = enrol_as(999, at).1["token"].as_str().unwrap().to_string();
    // then fifteen other processes, one token each: now 16 are live, the cap
    for (i, pid) in (100..115).enumerate() {
        assert_eq!(enrol_as(pid, at + 1 + i as u64).0, 200);
    }
    assert_eq!(r.door.live_tokens(at + 20), MAX_LIVE_TOKENS);
    // a seventeenth arrives: it waits, and nobody is evicted
    let (st, body) = enrol_as(115, at + 30);
    assert_eq!(st, 429, "{body}");
    assert_eq!(body["retry_after_s"], 60);
    assert_eq!(
        r.door.live_tokens(at + 31),
        MAX_LIVE_TOKENS,
        "nobody was pushed out"
    );
    let auth = format!("Bearer {person}");
    let mut list_req = req("/mcp");
    list_req.headers = vec![("Authorization".into(), auth)];
    list_req.body = list().to_string().into_bytes();
    assert_eq!(
        r.door.route(peer(999), &list_req, at + 32).0,
        200,
        "the long-standing token survived"
    );
    // the holder renews at the cap: it replaces its own, it is not turned away
    let renewed = enrol_as(999, at + 40);
    assert_eq!(renewed.0, 200);
    assert_eq!(r.door.live_tokens(at + 41), MAX_LIVE_TOKENS);
    assert_eq!(
        r.door.route(peer(999), &list_req, at + 42).0,
        401,
        "its own old token was replaced"
    );
}

/// S3: a squatter that enrols right after each of the person's renewals never pushes the person out, over five rounds, and
/// the 429 says when to come back. Processes that are gone do not hold a place.
#[test]
fn a_squatter_after_each_renewal_cannot_push_the_person_out_and_dead_processes_free_their_place() {
    let r = rig();
    let base = now();
    // the door is full of fifteen processes that stay alive (pid 200..) plus the person's bridge
    for pid in 200..215 {
        assert_eq!(raw_at(&r, peer(pid), base).0, 200);
    }
    let mut person = String::new();
    for round in 0..5u64 {
        let t = base + (round + 1) * 61_000; // a new minute each round, so the rate limit is not what is under test
                                             // all the other holders' tokens are still live (their ttl is 30 minutes)
        let (st, b) = raw_at(&r, peer(999), t);
        if round == 0 {
            assert_eq!(st, 200, "{b}");
        } else {
            assert_eq!(st, 200, "the person renews at the cap, round {round}: {b}");
        }
        person = b["token"].as_str().unwrap().to_string();
        // the squatter comes right after, as a new process each time
        let sq = raw_at(&r, peer(300 + round as u32), t + 1);
        assert_eq!(sq.0, 429, "round {round}: {:?}", sq.1);
        // the person still holds a working token
        let mut q = req("/mcp");
        q.headers = vec![("Authorization".into(), format!("Bearer {person}"))];
        q.body = list().to_string().into_bytes();
        assert_eq!(r.door.route(peer(999), &q, t + 2).0, 200, "round {round}");
    }
    assert!(!person.is_empty());
    // a holder whose process is gone (its pid now has another start time) frees its place for a newcomer
    let d = rig();
    REUSED_START_4.store(500, Ordering::SeqCst);
    assert_eq!(raw_at(&d, peer(80), base).0, 200);
    for pid in 400..415 {
        assert_eq!(raw_at(&d, peer(pid), base + 1).0, 200);
    }
    assert_eq!(d.door.live_tokens(base + 2), MAX_LIVE_TOKENS);
    assert_eq!(
        raw_at(&d, peer(420), base + 3).0,
        429,
        "full of live processes"
    );
    REUSED_START_4.store(901, Ordering::SeqCst); // pid 77 is somebody else now
    assert_eq!(
        raw_at(&d, peer(420), base + 4).0,
        200,
        "the gone process's place is free"
    );
    REUSED_START_4.store(500, Ordering::SeqCst);
}

fn raw_at(r: &Rig, p: Option<Peer>, t: u64) -> (u16, Value) {
    let (s, b) = r.door.route(p, &req("/v1/enrol"), t);
    (s, serde_json::from_slice(&b).unwrap_or(Value::Null))
}

/// R8: every answer to a caller the door does not let in closes the connection, including a wrong path or method, so a
/// process in a run cannot keep a slot by sending requests that are answered with a 404.
#[test]
fn a_caller_in_a_run_is_closed_whatever_it_asks() {
    let r = rig_with(me, in_a_run);
    for (m, path) in [
        ("POST", "/nope"),
        ("GET", "/mcp"),
        ("POST", "/mcp"),
        ("POST", "/v1/enrol"),
    ] {
        let mut q = req(path);
        q.method = m.into();
        let (s, _, close) = r.door.route_conn(peer(4242), who(4242).as_ref(), &q, now());
        assert_eq!((s, close), (403, true), "{m} {path}");
    }
    let mut q = req("/mcp");
    q.headers = vec![("Origin".into(), "https://evil.example".into())];
    assert!(
        r.door
            .route_conn(peer(4242), who(4242).as_ref(), &q, now())
            .2
    );
    // over the real socket: a wrong path from a run is answered once and the connection is shut
    let mut s = UnixStream::connect(&r.sock).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    http::write_request(&mut s, "POST", "/nope", &[], b"{}").unwrap();
    let mut rd = BufReader::new(s.try_clone().unwrap());
    assert_eq!(http::read_response(&mut rd, 4096).unwrap().0, 403);
    assert!(
        http::read_response(&mut rd, 4096).is_err(),
        "the door closed the connection"
    );
}

/// R9 + S5: turning the door off and on again does not give the same process its old key back, so what it was approved or opened
/// under the old one cannot be spent or driven; an ordinary renewal keeps its key. Turning standing permission ON (or extending
/// it) does NOT strand an agent in the middle of a browser task; ending it, and a change of person, do. Stranded browser
/// sessions are closed.
#[test]
fn a_turn_off_and_on_strands_the_old_key_but_a_renewal_and_standing_on_keep_it() {
    let r = rig();
    let before = key_of(&r, peer(10));
    assert_eq!(before, key_of(&r, peer(10)), "a renewal keeps the key");
    let t = raw(&r, peer(10), "POST", "/v1/enrol", &[], &json!({})).1["token"]
        .as_str()
        .unwrap()
        .to_string();
    r.door.set_enabled(false, "ada", now()).unwrap();
    r.door.set_enabled(true, "ada", now()).unwrap();
    assert_eq!(
        raw(
            &r,
            peer(10),
            "POST",
            "/mcp",
            &[("Authorization", &format!("Bearer {t}"))],
            &list()
        )
        .0,
        401,
        "the old token ended"
    );
    let after = key_of(&r, peer(10));
    assert_ne!(before, after, "the same process starts from nothing");
    // standing permission turned ON keeps the key (the agent's own browser task is not cut off), and extending it too
    r.door.set_standing(Some(5), "ada", now()).unwrap();
    let standing = key_of(&r, peer(10));
    assert_eq!(after, standing, "standing ON keeps the key");
    r.door.set_standing(Some(30), "ada", now()).unwrap();
    assert_eq!(standing, key_of(&r, peer(10)), "extending keeps it too");
    // ending it early keeps the key too, as the time running out does; a change of person strands
    r.door.set_standing(None, "ada", now()).unwrap();
    let ended = key_of(&r, peer(10));
    assert_eq!(standing, ended, "an early end keeps the key");
    r.door.set_enabled(true, "grace", now()).unwrap();
    assert_ne!(ended, key_of(&r, peer(10)), "a change of person strands");
    assert_eq!(r.door.setting().by, "grace");
}

/// S5: browser sessions a stranded key opened are closed when the key is stranded, and a session opened under the new key is not.
/// T2: ending standing permission early does not strand (it agrees with the time running out); a change of person does.
#[test]
fn sessions_that_a_stranded_key_opened_are_closed() {
    let r = rig();
    let old = key_of(&r, peer(10));
    r.host.sessions.lock().unwrap().push(old.clone());
    // turning standing ON keeps the key, so closes nothing
    r.door.set_standing(Some(5), "owner", now()).unwrap();
    closes_done(&r);
    assert_eq!(r.host.sessions.lock().unwrap().len(), 1);
    // ending it early keeps the key too, as the end of the time window does (T2): the agent's browser task goes on
    r.door.set_standing(None, "owner", now()).unwrap();
    closes_done(&r);
    assert_eq!(
        r.host.sessions.lock().unwrap().len(),
        1,
        "an early end of standing permission strands nothing"
    );
    // a change of person strands the key: the session goes
    r.door.set_enabled(true, "grace", now()).unwrap();
    closes_done(&r);
    assert!(
        r.host.sessions.lock().unwrap().is_empty(),
        "the stranded session was closed"
    );
    // a session opened under the new key survives a later change that keeps it
    let fresh = key_of(&r, peer(10));
    r.host.sessions.lock().unwrap().push(fresh);
    r.door.set_standing(Some(5), "grace", now()).unwrap();
    closes_done(&r);
    assert_eq!(r.host.sessions.lock().unwrap().len(), 1);
    // and a turn-off closes it
    r.door.set_enabled(false, "grace", now()).unwrap();
    closes_done(&r);
    assert!(r.host.sessions.lock().unwrap().is_empty());
}

/// T13: every change that ends what a waiting call asked under ends the cards the door's callers are waiting on, and one that
/// only gives a program more (turning standing on, extending it, the same person turning the door on again) does not.
#[test]
fn only_a_change_that_ends_what_a_call_asked_under_ends_its_waiting_card() {
    let r = rig();
    let ended = || r.host.ended.load(Ordering::SeqCst);
    r.door.set_enabled(true, "ada", now()).unwrap();
    let base = ended();
    r.door.set_standing(Some(5), "ada", now()).unwrap();
    r.door.set_standing(Some(30), "ada", now()).unwrap();
    assert_eq!(ended(), base, "standing on, and extended, ends nothing");
    r.door.set_standing(None, "ada", now()).unwrap();
    assert_eq!(ended(), base + 1, "an early end of standing permission");
    r.door.set_enabled(true, "grace", now()).unwrap();
    assert_eq!(ended(), base + 2, "another person takes the door");
    r.door.set_standing(Some(5), "heidi", now()).unwrap();
    assert_eq!(
        ended(),
        base + 3,
        "another person takes the standing permission"
    );
    r.door.set_enabled(false, "heidi", now()).unwrap();
    assert_eq!(ended(), base + 4, "turned off");
    r.door.set_enabled(true, "heidi", now()).unwrap();
    assert_eq!(
        ended(),
        base + 4,
        "the same person turning it on again ends nothing"
    );
}

/// T13: the generation moves inside the step that changes the setting, so it has already moved when the sweep runs, and a token
/// made after the change carries the new generation (never the new setting with the old generation, which would make every
/// waiting call on it look outdated).
#[test]
fn the_generation_moves_with_the_change_and_a_token_made_after_it_carries_the_new_one() {
    let r = rig();
    r.door.set_enabled(true, "ada", now()).unwrap();
    r.door.set_standing(Some(5), "ada", now()).unwrap();
    let g0 = r.host.gen.load(Ordering::SeqCst);
    r.door.set_standing(Some(30), "ada", now()).unwrap();
    assert_eq!(
        r.host.gen.load(Ordering::SeqCst),
        g0,
        "extending moves nothing"
    );
    r.door.set_standing(None, "ada", now()).unwrap();
    assert_eq!(r.host.gen.load(Ordering::SeqCst), g0 + 1);
    assert_eq!(
        r.host.gen_at_sweep.load(Ordering::SeqCst),
        g0 + 1,
        "the generation had already moved when the sweep ran"
    );
    drive(
        &r,
        &[init(), list(), call("shell", json!({"command": "ls"}))],
    );
    let seen = r.host.seen.lock().unwrap().clone();
    let last = seen.last().unwrap();
    assert_eq!(last["door_gen"], json!(g0 + 1), "{last}");
}

/// T14: the door tells the host how to tell whether a key is still the door's current one, and it stops being so on a change
/// that moves the epoch, which is what lets the host close a session that finished opening after the change.
#[test]
fn the_host_can_ask_whether_a_key_is_still_current() {
    let r = rig();
    let key = key_of(&r, peer(10));
    let current = r.host.current.lock().unwrap().clone().unwrap();
    assert!(current(&key));
    r.door.set_enabled(false, "ada", now()).unwrap();
    assert!(!current(&key), "a turn-off moves the epoch");
    r.door.set_enabled(true, "ada", now()).unwrap();
    assert!(
        !current(&key),
        "and it stays moved when the door is back on"
    );
    assert!(
        current(&key_for(&r.door, 10)),
        "the key a process gets now is current"
    );
}

/// T1: closing stranded sessions waits for the browser, so it must never hold the caller: the dashboard's click on the off
/// switch answers at once even when every close takes seconds.
#[test]
fn turning_the_door_off_does_not_wait_for_a_slow_browser_to_close() {
    let r = rig();
    *r.host.close_delay.lock().unwrap() = std::time::Duration::from_millis(1500);
    let old = key_of(&r, peer(10));
    r.host.sessions.lock().unwrap().push(old);
    let t = std::time::Instant::now();
    let saved = r.door.set_enabled(false, "ada", now()).unwrap();
    assert!(
        t.elapsed() < std::time::Duration::from_millis(700),
        "the off click waited for the close: {:?}",
        t.elapsed()
    );
    assert!(!saved.setting.enabled, "the off is already in force");
    assert_eq!(r.door.closing(), 1, "the close is still running");
    closes_done(&r);
    assert!(r.host.sessions.lock().unwrap().is_empty());
}

/// S5: a token is never made under a setting or an epoch that a change has already ended. While the person turns the door off
/// and on again and ends standing permission, other programs enrol; afterwards every live token's key is from the current epoch.
#[test]
fn no_token_survives_a_change_under_an_old_epoch() {
    let r = rig();
    let base = now();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let door = Arc::clone(&r.door);
    let flag = Arc::clone(&stop);
    let enroller = std::thread::spawn(move || {
        let mut i = 0u64;
        while !flag.load(Ordering::SeqCst) {
            i += 1;
            // a new minute every time, so the rate limits are not what is exercised
            let _ = door.route(
                peer(10 + (i % 5) as u32),
                &req("/v1/enrol"),
                base + i * 61_000,
            );
        }
    });
    for i in 0..300u64 {
        r.door.set_enabled(false, "ada", base).unwrap();
        r.door.set_enabled(true, "ada", base).unwrap();
        if i % 7 == 0 {
            r.door.set_standing(Some(5), "ada", base).unwrap();
            r.door.set_standing(None, "ada", base).unwrap();
        }
    }
    stop.store(true, Ordering::SeqCst);
    enroller.join().unwrap();
    // quiet now: one more change, then no live token may carry an older epoch
    r.door.set_enabled(false, "ada", base).unwrap();
    r.door.set_enabled(true, "ada", base).unwrap();
    let cur = r.door.epoch.load(Ordering::SeqCst).to_string();
    for k in r.door.server.session_keys(0) {
        assert_eq!(
            k.rsplit('-').next(),
            Some(cur.as_str()),
            "a token made under an ended epoch survived: {k}"
        );
    }
}

/// S1: the session code is a keyed hash of the process's identity, made with a secret only the door holds. A second process can
/// neither learn the person's code nor choose one: it does not follow from its own code, from another door's, or from any
/// pid or start time a program could pick.
#[test]
fn a_second_process_cannot_learn_or_force_the_persons_code() {
    let r = rig();
    let person = enrol_code(&r, 4242);
    assert_eq!(person.len(), CODE_LEN);
    assert!(
        person.bytes().all(|b| CODE_ALPHABET.contains(&b)),
        "{person}"
    );
    // the same process asks again, after a turn-off and a standing change: the same code (S2)
    r.door.set_enabled(false, "ada", now()).unwrap();
    r.door.set_enabled(true, "ada", now()).unwrap();
    r.door.set_standing(Some(5), "ada", now()).unwrap();
    r.door.set_standing(None, "ada", now()).unwrap();
    assert_eq!(
        enrol_code(&r, 4242),
        person,
        "the code lasts as long as the process does"
    );
    // a script enrols as itself and learns only its own code
    let script = enrol_code(&r, 4243);
    assert_ne!(script, person);
    // the script knows its own pid, start time and code, and the person's pid and start time (/proc is public). It cannot
    // compute the person's code without the door's key: the same pid and start under another key is another code,
    let other_door = rig();
    assert_ne!(
        code_for(&other_door.door, 4242),
        person,
        "the key decides the code, not the pid and the start"
    );
    // and no pid the script could have picked lands on the person's code (2000 tries here; the odds of one are 2000 in 2^30)
    for pid in 5000..7000 {
        assert_ne!(code_for(&r.door, pid), person, "pid {pid}");
    }
    // the code is not in the key, so nothing a caller is told of its key (and nothing it reads from a note) gives it away
    assert!(!key_for(&r.door, 4242).contains(&person));
}

fn enrol_code(r: &Rig, pid: u32) -> String {
    raw(r, peer(pid), "POST", "/v1/enrol", &[], &json!({})).1["code"]
        .as_str()
        .unwrap()
        .to_string()
}

/// S4: a caller in a run is answered and closed at once, without being let near a slot, and a caller that trickles its first
/// request is closed when the deadline for the whole of it passes, not after each read.
#[test]
fn a_run_that_says_nothing_is_closed_at_once_and_a_trickling_head_at_the_deadline() {
    let r = rig_with(me, in_a_run);
    let s = UnixStream::connect(&r.sock).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let t = std::time::Instant::now();
    let mut rd = BufReader::new(s.try_clone().unwrap());
    assert_eq!(
        http::read_response(&mut rd, 4096).unwrap().0,
        403,
        "answered without sending a byte"
    );
    assert!(http::read_response(&mut rd, 4096).is_err(), "and closed");
    assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
    assert_eq!(
        r.door.open.load(Ordering::SeqCst),
        0,
        "a refused caller held no slot"
    );
    drop(s);

    // an admitted caller that sends one byte at a time: closed at the deadline, though every read arrives in time
    let t = rig();
    t.door.set_first_request(Duration::from_millis(400));
    let mut s = UnixStream::connect(&t.sock).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let start = Instant::now();
    let mut closed = false;
    for b in b"POST /v1/enrol HTTP/1.1\r\nX: y".iter() {
        if s.write_all(&[*b]).is_err() {
            closed = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(60));
        if start.elapsed() > Duration::from_secs(4) {
            break;
        }
    }
    let mut rest = Vec::new();
    let _ = s.read_to_end(&mut rest);
    assert!(
        start.elapsed() < Duration::from_secs(4),
        "{:?} (writer saw close: {closed})",
        start.elapsed()
    );
    assert_eq!(
        t.door.open.load(Ordering::SeqCst),
        0,
        "the slot was given back"
    );
}

/// S7: the engine is the first program above the bridge that is not a shell. A wrapper shell is skipped; systemd, init, an
/// unreadable parent and a chain longer than the cap are "unknown", with no pid, never a name that is not the engine's.
#[test]
fn the_engine_is_named_through_the_bridges_real_parents() {
    use std::collections::HashMap;
    let chain = |m: &'static [(u32, &'static str, u32)]| {
        let map: HashMap<u32, (String, Option<u32>)> = m
            .iter()
            .map(|(p, c, pp)| (*p, ((*c).to_string(), Some(*pp))))
            .collect();
        move |p: u32| map.get(&p).cloned()
    };
    // claude started the bridge through `sh -c`
    let r = chain(&[(20, "sh", 21), (21, "bash", 22), (22, "claude", 1)]);
    assert_eq!(
        engine_in_chain(Some(20), &r),
        ("claude".to_string(), Some(22))
    );
    // the bridge's parent is the engine itself
    let r = chain(&[(20, "claude", 1)]);
    assert_eq!(
        engine_in_chain(Some(20), &r),
        ("claude".to_string(), Some(20))
    );
    // the engine exited and the bridge was adopted
    let r = chain(&[(1, "systemd", 0)]);
    assert_eq!(engine_in_chain(Some(1), &r), ("unknown".to_string(), None));
    let r = chain(&[(20, "systemd", 1)]);
    assert_eq!(engine_in_chain(Some(20), &r), ("unknown".to_string(), None));
    // shells all the way to init
    let r = chain(&[(20, "sh", 21), (21, "bash", 1)]);
    assert_eq!(engine_in_chain(Some(20), &r), ("unknown".to_string(), None));
    // unreadable, and no parent at all
    assert_eq!(
        engine_in_chain(Some(20), |_| None),
        ("unknown".to_string(), None)
    );
    assert_eq!(
        engine_in_chain(None, |_| None),
        ("unknown".to_string(), None)
    );
    // a long chain of shells is cut off at the cap
    let long = |p: u32| Some(("sh".to_string(), Some(p + 1)));
    assert_eq!(
        engine_in_chain(Some(100), long),
        ("unknown".to_string(), None)
    );
    // a name is cleaned as before
    let r = chain(&[(20, "cl aude!", 1)]);
    assert_eq!(engine_in_chain(Some(20), &r).0, "claude");
}

/// T4: a bridge started by hand from the web terminal or over SSH has a terminal or session host behind its shell. None of
/// those is an engine, and `ozbox`/`ozboxd` read as Oz Box itself, so the walk stops there: "unknown", never that name.
#[test]
fn a_bridge_run_from_a_terminal_or_session_host_is_not_named_after_it() {
    use std::collections::HashMap;
    for host in [
        "sshd",
        "sshd-session",
        "login",
        "su",
        "sudo",
        "runuser",
        "tmux",
        "tmux: server",
        "screen",
        "script",
        "ozboxd",
        "ozbox",
    ] {
        let map: HashMap<u32, (String, Option<u32>)> = HashMap::from([
            (20, ("bash".to_string(), Some(21))),
            (21, (host.to_string(), Some(22))),
            (22, ("claude".to_string(), Some(1))),
        ]);
        assert_eq!(
            engine_in_chain(Some(20), |p| map.get(&p).cloned()),
            ("unknown".to_string(), None),
            "{host}"
        );
    }
}
