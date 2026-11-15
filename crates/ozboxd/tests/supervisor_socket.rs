#![allow(clippy::unwrap_used)]
#![cfg(unix)]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use ozboxd::api::{bind_socket, serve, serve_supervisor, AppState, HealthInfo, SupervisorGate};
use ozboxd::checkpoint::CheckpointReport;
use ozboxd::health::IncidentLog;
use ozboxd::runs::testing::{FakeCgroup, FakeMemory, FakeSpawner};
use ozboxd::runs::{RunConfig, RunManager};
use ozboxd::selftest::{Check, Outcome, SelfTestResult};
use ozboxd::store::{Store, StoreConfig};
use ozboxd::timeutil::FakeClock;

const T0: u64 = 1_794_182_400_000;

struct Server {
    sock: PathBuf,
    sup: PathBuf,
    audit: Arc<Mutex<Vec<String>>>,
    gate: Arc<SupervisorGate>,
    shutdown: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
    handle2: Option<std::thread::JoinHandle<()>>,
    _dir: tempfile::TempDir,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        for h in [self.handle.take(), self.handle2.take()]
            .into_iter()
            .flatten()
        {
            let _ = h.join();
        }
    }
}

/// `peer` is who the kernel would say is on the other end of the supervisor socket (tests cannot change their uid).
fn server(peer: Option<u32>) -> Server {
    server_every(peer, std::time::Duration::from_secs(10))
}

fn server_every(peer: Option<u32>, every: std::time::Duration) -> Server {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(FakeClock::new(T0 + 3_600_000));
    let runs = RunManager::new(
        RunConfig::default(),
        Arc::new(FakeCgroup::default()),
        Arc::new(FakeMemory::new(16 << 30, 8 << 30)),
        Arc::new(FakeSpawner::default()),
        clock.clone(),
    );
    let state = Arc::new(AppState {
        version: "9.9.9".into(),
        started_ms: T0,
        clock: clock.clone(),
        latest: Mutex::new(None),
        store: Mutex::new(Store::open(StoreConfig::new(dir.path().join("metrics"))).unwrap()),
        runs: Arc::new(Mutex::new(runs)),
        selftest_last: Mutex::new(None),
        selftest_fn: Box::new(|| SelfTestResult {
            ts_ms: 1,
            ok: true,
            all_verified: true,
            checks: vec![Check {
                name: "x".into(),
                outcome: Outcome::Pass,
            }],
        }),
        incidents: Mutex::new(IncidentLog::in_memory()),
        checkpoint_fn: Box::new(|_| CheckpointReport {
            repos_scanned: 2,
            ..Default::default()
        }),
        checkpoint_lock: Mutex::new(()),
        health: Mutex::new(HealthInfo {
            restarts: 3,
            ..Default::default()
        }),
    });
    let sock = dir.path().join("ozboxd.sock");
    let listener = bind_socket(&sock, 0o660).unwrap();
    let shutdown = Arc::new(AtomicBool::new(false));
    let (st, sd) = (state.clone(), shutdown.clone());
    let handle = std::thread::spawn(move || {
        let _ = serve(listener, st, sd);
    });
    let sup = dir.path().join("supervisor.sock");
    let sup_listener = bind_socket(&sup, 0o666).unwrap();
    let audit = Arc::new(Mutex::new(Vec::<String>::new()));
    let (a2, st2, sd2) = (audit.clone(), state.clone(), shutdown.clone());
    let gate = Arc::new(
        SupervisorGate::new(
            move |_| peer,
            || Some(998),
            move |l| a2.lock().unwrap().push(l.to_string()),
        )
        .with_refusal_interval(every),
    );
    let gate2 = gate.clone();
    let handle2 = std::thread::spawn(move || {
        let _ = serve_supervisor(sup_listener, st2, None, sd2, gate);
    });
    Server {
        sock,
        sup,
        audit,
        gate: gate2,
        handle2: Some(handle2),
        shutdown,
        handle: Some(handle),
        _dir: dir,
    }
}

fn raw(sock: &Path, bytes: &[u8]) -> (u16, String) {
    let mut s = UnixStream::connect(sock).unwrap();
    s.write_all(bytes).unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).unwrap();
    let text = String::from_utf8_lossy(&out).into_owned();
    let status = text
        .split(' ')
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let body = text
        .split_once("\r\n\r\n")
        .map(|x| x.1.to_string())
        .unwrap_or_default();
    (status, body)
}

fn call(sock: &Path, method: &str, target: &str, body: &str) -> (u16, serde_json::Value) {
    let req = format!(
        "{method} {target} HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let (s, b) = raw(sock, req.as_bytes());
    (
        s,
        serde_json::from_str(&b).unwrap_or(serde_json::Value::Null),
    )
}

const SUPERVISOR: Option<u32> = Some(998);
const BOX_USER: Option<u32> = Some(1500);

#[test]
fn a_peer_that_is_not_the_supervisor_is_refused_before_anything_is_read() {
    for peer in [BOX_USER, Some(0), None] {
        let s = server(peer);
        let (st, v) = call(&s.sup, "GET", "/v1/health", "");
        assert_eq!(st, 403, "{peer:?} {v}");
        assert_eq!(v["code"], "peer_not_allowed");
        let a = s.audit.lock().unwrap().join("\n");
        assert!(a.contains("via=supervisor refused=peer"), "{a}");
        // the box socket still answers its own user
        assert_eq!(call(&s.sock, "GET", "/v1/health", "").0, 200);
    }
}

#[test]
fn the_supervisor_gets_the_dashboards_routes_and_each_is_audited_with_its_name() {
    let s = server(SUPERVISOR);
    for (m, p, want) in [
        ("GET", "/v1/health", 200),
        ("GET", "/v1/metrics?since=2026-01-01T00:00:00Z", 200),
        ("GET", "/v1/incidents", 200),
        ("GET", "/v1/selftest", 200),
        ("GET", "/v1/runs", 200),
        ("GET", "/v1/sessions", 200),
    ] {
        let (st, v) = call(&s.sup, m, p, "");
        assert_eq!(st, want, "{m} {p} {v}");
        assert_ne!(st, 403, "{m} {p}");
    }
    let a = s.audit.lock().unwrap().join("\n");
    for n in [
        "route=health",
        "route=runs_list",
        "route=incidents",
        "route=sessions_list",
    ] {
        assert!(a.contains(n), "{n} in {a}");
    }
    assert!(a.lines().all(|l| l.starts_with("via=supervisor")), "{a}");
}

#[test]
fn a_route_not_on_the_list_is_refused_and_audited_without_its_path() {
    let s = server(SUPERVISOR);
    for (m, p) in [
        ("GET", "/v1/backup"),
        ("POST", "/v1/backup/run"),
        ("GET", "/v1/tools"),
        ("GET", "/v1/local-ai"),
        ("POST", "/v1/agent-events"),
        ("POST", "/v1/agent-events/permission/p1"),
        ("POST", "/v1/files/trash/empty"),
        ("POST", "/v1/files/tokens"),
        ("GET", "/v1/files"),
        ("GET", "/v1/files/../backup"),
        ("DELETE", "/v1/runs"),
        ("GET", "/nope"),
    ] {
        let (st, v) = call(&s.sup, m, p, "{}");
        assert_eq!(st, 403, "{m} {p} {v}");
        assert_eq!(v["code"], "route_not_allowed");
    }
    let a = s.audit.lock().unwrap().join("\n");
    assert!(a.contains("via=supervisor refused=route"));
    assert!(!a.contains("backup") && !a.contains("tokens"), "{a}");
    // the same routes still answer on the box socket (not 403): the list narrows only the second socket
    assert_ne!(call(&s.sock, "GET", "/v1/backup", "").0, 403);
}

fn listed_run(s: &Server, id: &str) -> serde_json::Value {
    let (_, v) = call(&s.sock, "GET", "/v1/runs", "");
    let mut run = v["runs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == id)
        .unwrap_or_else(|| panic!("no run {id} in {v}"))
        .clone();
    if let Some(o) = run.as_object_mut() {
        // what legitimately differs between two runs
        for k in [
            "id",
            "started_ms",
            "created_ms",
            "started_at",
            "scope",
            "pid",
            "cgroup",
            "queued_at",
        ] {
            o.remove(k);
        }
    }
    run
}

#[test]
fn a_run_started_on_the_supervisor_socket_gets_the_same_caps_and_token_as_on_the_box_socket() {
    let s = server(SUPERVISOR);
    let body = r#"{"argv":["claude","-p"],"memory_request_bytes":1048576,"memory_max_bytes":2097152,"cpu_weight":50,"max_runtime_s":600,"keep_stdin_open":true,"require_capability":true,"stdin":"{}\n"}"#;
    let (a_st, a) = call(&s.sock, "POST", "/v1/runs", body);
    let (b_st, b) = call(&s.sup, "POST", "/v1/runs", body);
    assert_eq!((a_st, b_st), (201, 201), "{a} {b}");
    let (ida, idb) = (a["id"].as_str().unwrap(), b["id"].as_str().unwrap());
    assert_ne!(ida, idb);
    // each answer carries a per-run token, once, of the same shape and never the same value
    let (ca, cb) = (
        a["capability"].as_str().unwrap(),
        b["capability"].as_str().unwrap(),
    );
    assert_eq!(ca.len(), cb.len());
    assert_ne!(ca, cb);
    assert_eq!(listed_run(&s, ida), listed_run(&s, idb));
    // the supervisor's run is controlled by its token like the box socket's: no token, no input
    let path = format!("/v1/runs/{idb}/stdin");
    let (st, v) = call(&s.sup, "POST", &path, r#"{"text":"x"}"#);
    assert_eq!(st, 403, "{v}");
    assert_eq!(v["code"], "run_controlled");
    // and the same bad requests are refused the same way on both
    for bad in ["{not json", r#"{"argv":[]}"#] {
        assert_eq!(
            call(&s.sock, "POST", "/v1/runs", bad).0,
            call(&s.sup, "POST", "/v1/runs", bad).0
        );
    }
}

/// What decides an agent's permission request is a person, never a process on the box: the agent's hook posts the request
/// and polls for the answer, so a socket that took the answer would let the agent approve itself.
#[test]
fn no_socket_takes_the_answer_to_an_agents_permission_request() {
    let s = server(SUPERVISOR);
    let pre = r#"{"engine":"claude-code","cwd":"/work/repos/x","payload":{"hook_event_name":"PreToolUse","session_id":"s1","tool_name":"Bash","tool_input":{"command":"git push origin main"}}}"#;
    let (st, v) = call(&s.sock, "POST", "/v1/agent-events", pre);
    assert_eq!(st, 200, "{v}");
    let id = v["permission"].as_str().unwrap().to_string();
    let path = format!("/v1/agent-events/permission/{id}");
    for body in [r#"{"decision":"allow"}"#, r#"{"decision":"deny"}"#, "{}"] {
        let (st, v) = call(&s.sock, "POST", &path, body);
        assert_eq!(
            (st, v["code"].as_str()),
            (403, Some("decision_not_here")),
            "box socket {body}"
        );
        let (st, v) = call(&s.sup, "POST", &path, body);
        assert_eq!(
            (st, v["code"].as_str()),
            (403, Some("route_not_allowed")),
            "dashboard socket {body}"
        );
    }
    // the request is still pending: nothing answered it, and reading it still works on both
    assert_eq!(call(&s.sock, "GET", &path, "").1["state"], "pending");
    assert_eq!(call(&s.sup, "GET", &path, "").1["state"], "pending");
}

#[test]
fn a_flood_of_refusals_is_one_audit_line_and_the_next_real_request_is_still_logged() {
    // a peer that is not the supervisor: 100 connections, a line or two (the rest are counted into the next one)
    let s = server(BOX_USER);
    for _ in 0..100 {
        assert_eq!(call(&s.sup, "GET", "/v1/health", "").0, 403);
    }
    let lines = s.audit.lock().unwrap().clone();
    assert!(
        lines.len() <= 3 && lines.iter().all(|l| l.contains("refused=peer")),
        "{lines:?}"
    );
    // a route that is not offered: the same
    let s = server(SUPERVISOR);
    for _ in 0..100 {
        assert_eq!(call(&s.sup, "GET", "/v1/backup", "").0, 403);
    }
    let refused = s
        .audit
        .lock()
        .unwrap()
        .iter()
        .filter(|l| l.contains("refused=route"))
        .count();
    assert!((1..=3).contains(&refused), "{refused}");
    // and a real request after the flood is audited, with its outcome
    assert_eq!(call(&s.sup, "GET", "/v1/health", "").0, 200);
    let a = s.audit.lock().unwrap().join("\n");
    assert!(a.contains("route=health method=GET status=200"), "{a}");
}

/// G1 N7: the count of the last burst is written when its interval ends, even if nothing else is ever refused.
#[test]
fn the_count_of_a_refusal_burst_that_just_stops_is_still_written() {
    let s = server_every(SUPERVISOR, std::time::Duration::from_secs(4));
    for _ in 0..20 {
        assert_eq!(call(&s.sup, "GET", "/v1/backup", "").0, 403);
    }
    assert!(
        !s.audit
            .lock()
            .unwrap()
            .iter()
            .any(|l| l.contains("also_refused=")),
        "still held inside the interval"
    );
    std::thread::sleep(std::time::Duration::from_millis(4200));
    s.gate.flush_due();
    let lines = s.audit.lock().unwrap().clone();
    let total: usize = lines.iter().filter(|l| l.contains("refused=route")).count()
        + lines
            .iter()
            .filter_map(|l| l.split("also_refused=").nth(1))
            .filter_map(|n| n.parse::<usize>().ok())
            .sum::<usize>();
    assert!(
        lines.iter().any(|l| l.contains("also_refused=")),
        "{lines:?}"
    );
    // G1 F9: the held count is a line of its own that names no caller, so it can never be read as one uid's; the line before it is
    // the interval's first refusal and carries no count
    for l in lines.iter().filter(|l| l.contains("also_refused=")) {
        assert!(!l.contains("uid="), "a count with a caller attached: {l}");
        assert!(
            !l.contains("refused=route") || l.contains("callers=not_listed"),
            "{l}"
        );
    }
    for l in lines.iter().filter(|l| !l.contains("also_refused=")) {
        assert!(!l.contains("also_refused"), "{l}");
    }
    // every refusal is accounted for, and a second flush writes nothing more
    assert!(total >= 20, "{total} {lines:?}");
    let n = lines.len();
    s.gate.flush_due();
    assert_eq!(s.audit.lock().unwrap().len(), n);
}

#[test]
fn a_started_run_is_audited_with_its_id_and_status() {
    let s = server(SUPERVISOR);
    let body = r#"{"argv":["claude","-p"],"memory_request_bytes":1048576,"memory_max_bytes":2097152,"cpu_weight":50,"max_runtime_s":600}"#;
    let (st, v) = call(&s.sup, "POST", "/v1/runs", body);
    assert_eq!(st, 201, "{v}");
    let id = v["id"].as_str().unwrap();
    let (st, _) = call(&s.sup, "DELETE", &format!("/v1/runs/{id}"), "");
    assert!(st == 200 || st == 202 || st == 204, "{st}");
    let a = s.audit.lock().unwrap().join("\n");
    assert!(
        a.contains(&format!("route=run_start method=POST status=201 id={id}")),
        "{a}"
    );
    assert!(
        a.contains(&format!(
            "route=run_cancel method=DELETE status={st} id={id}"
        )),
        "{a}"
    );
    // never the path, the body or the command
    assert!(!a.contains("claude") && !a.contains("/v1/runs"), "{a}");
}

/// The checkpoint and the file writes are on the table (they add no authority that a run and the terminal do not already
/// give), each audited; the checkpoint answers like on the box socket.
#[test]
fn the_checkpoint_and_the_file_writes_are_offered_and_audited() {
    let s = server(SUPERVISOR);
    let (st, v) = call(&s.sup, "POST", "/v1/checkpoint", "");
    assert_eq!(st, 200, "{v}");
    for (m, p) in [
        ("PUT", "/v1/files/upload"),
        ("PUT", "/v1/files/write"),
        ("POST", "/v1/files/mkdir"),
        ("POST", "/v1/files/delete"),
    ] {
        let (st, v) = call(&s.sup, m, p, "{}");
        assert_ne!(st, 403, "{m} {p} {v}");
    }
    let a = s.audit.lock().unwrap().join("\n");
    for n in [
        "route=checkpoint method=POST status=200",
        "route=files_upload",
        "route=files_write",
        "route=files_mkdir",
        "route=files_delete",
    ] {
        assert!(a.contains(n), "{n} in {a}");
    }
}

/// The one line the whole gate rests on, with no injected peer: on Linux the kernel names this process as the peer.
#[cfg(target_os = "linux")]
#[test]
fn the_kernel_names_the_peer_of_a_real_connection() {
    use std::os::unix::fs::MetadataExt;
    let d = tempfile::tempdir().unwrap();
    let mine = std::fs::metadata(d.path()).unwrap().uid();
    let p = d.path().join("s.sock");
    let l = std::os::unix::net::UnixListener::bind(&p).unwrap();
    let _c = UnixStream::connect(&p).unwrap();
    let (s, _) = l.accept().unwrap();
    assert_eq!(ozboxd::api::peer_uid(&s), Some(mine));
}
