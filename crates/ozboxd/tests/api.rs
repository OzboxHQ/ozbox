#![allow(clippy::unwrap_used)]
#![cfg(unix)]

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use ozbox_core::MetricsSample;
use ozboxd::api::{bind_socket, serve, AppState, HealthInfo};
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
    state: Arc<AppState>,
    shutdown: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
    _dir: tempfile::TempDir,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn server() -> Server {
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
    Server {
        sock,
        state,
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

#[test]
fn socket_is_mode_0660_and_replaces_a_stale_one() {
    let s = server();
    let mode = std::fs::metadata(&s.sock).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o660);
    // a regular file at the path is never clobbered
    let f = s._dir.path().join("regular");
    std::fs::write(&f, "x").unwrap();
    assert!(bind_socket(&f, 0o660).is_err());
}

#[test]
fn health_metrics_and_incidents() {
    let s = server();
    let (st, v) = call(&s.sock, "GET", "/v1/health", "");
    assert_eq!(st, 200);
    assert_eq!(
        (
            v["status"].as_str(),
            v["version"].as_str(),
            v["uptime_s"].as_u64()
        ),
        (Some("ok"), Some("9.9.9"), Some(3600))
    );
    assert_eq!(v["restarts"], 3);

    assert_eq!(call(&s.sock, "GET", "/v1/metrics/now", "").0, 503);
    *s.state.latest.lock().unwrap() = Some(MetricsSample {
        ts_ms: T0,
        cpu_pct: 42.0,
        ..Default::default()
    });
    let (st, v) = call(&s.sock, "GET", "/v1/metrics/now", "");
    assert_eq!((st, v["cpu_pct"].as_f64()), (200, Some(42.0)));

    {
        let mut store = s.state.store.lock().unwrap();
        for i in 0..3 {
            store
                .push(&MetricsSample {
                    ts_ms: T0 + i * 5000,
                    cpu_pct: i as f64,
                    ..Default::default()
                })
                .unwrap();
        }
    }
    let (st, v) = call(
        &s.sock,
        "GET",
        "/v1/metrics?since=2026-11-09T00:00:00Z&step=5s",
        "",
    );
    assert_eq!(st, 200);
    assert_eq!(v["points"].as_array().map(Vec::len), Some(3));
    assert_eq!(call(&s.sock, "GET", "/v1/metrics?step=5s", "").0, 400);
    assert_eq!(
        call(
            &s.sock,
            "GET",
            "/v1/metrics?since=2026-11-09T00:00:00Z&step=7s",
            ""
        )
        .0,
        400
    );

    let (st, v) = call(
        &s.sock,
        "GET",
        "/v1/incidents?since=2026-11-09T00:00:00Z",
        "",
    );
    assert_eq!(
        (st, v["incidents"].as_array().map(Vec::len)),
        (200, Some(0))
    );
    assert_eq!(
        call(&s.sock, "GET", "/v1/incidents?since=yesterday", "").0,
        400
    );
}

#[test]
fn runs_lifecycle_never_shows_env_or_args() {
    let s = server();
    let body = r#"{"argv":["/usr/bin/tool","--password=hunter2"],"env":{"TOKEN":"s3cr3t-value"},"memory_request_bytes":1048576,"labels":{"kind":"test"}}"#;
    let (st, v) = call(&s.sock, "POST", "/v1/runs", body);
    assert_eq!(st, 201, "{v}");
    let id = v["id"].as_str().unwrap().to_string();
    let req = "GET /v1/runs HTTP/1.1\r\n\r\n";
    let (st, listing) = raw(&s.sock, req.as_bytes());
    assert_eq!(st, 200);
    assert!(listing.contains(&id) && listing.contains("\"program\":\"tool\""));
    assert!(
        !listing.contains("s3cr3t-value") && !listing.contains("hunter2"),
        "{listing}"
    );

    assert_eq!(call(&s.sock, "POST", "/v1/runs", "{not json").0, 400);
    assert_eq!(call(&s.sock, "POST", "/v1/runs", r#"{"argv":[]}"#).0, 400);
    assert_eq!(
        call(
            &s.sock,
            "POST",
            "/v1/runs",
            r#"{"argv":["x"],"memory_request_bytes":99999999999999}"#
        )
        .0,
        422
    );

    assert_eq!(
        call(&s.sock, "DELETE", &format!("/v1/runs/{id}"), "").0,
        200
    );
    assert_eq!(call(&s.sock, "DELETE", "/v1/runs/nope", "").0, 404);
    assert_eq!(call(&s.sock, "DELETE", "/v1/runs/..%2f..", "").0, 404);
}

#[test]
fn selftest_and_checkpoint() {
    let s = server();
    let (_, v) = call(&s.sock, "GET", "/v1/selftest", "");
    assert!(v["result"].is_null());
    let (st, v) = call(&s.sock, "POST", "/v1/selftest", "");
    assert_eq!((st, v["ok"].as_bool()), (200, Some(true)));
    let (_, v) = call(&s.sock, "GET", "/v1/selftest", "");
    assert_eq!(v["result"]["ok"], true);
    let (st, v) = call(&s.sock, "POST", "/v1/checkpoint", "");
    assert_eq!((st, v["repos_scanned"].as_u64()), (200, Some(2)));
}

#[test]
fn routing_errors() {
    let s = server();
    assert_eq!(call(&s.sock, "GET", "/nope", "").0, 404);
    assert_eq!(call(&s.sock, "POST", "/v1/health", "").0, 405);
    assert_eq!(call(&s.sock, "GET", "/v1/checkpoint", "").0, 405);
    assert_eq!(call(&s.sock, "GET", "/v1/health/", "").0, 200);
}

#[test]
fn hostile_requests_get_clean_errors() {
    let s = server();
    let long = format!("GET / HTTP/1.1\r\nX: {}\r\n\r\n", "a".repeat(20_000));
    assert_eq!(raw(&s.sock, long.as_bytes()).0, 431);
    assert_eq!(
        raw(
            &s.sock,
            b"POST /v1/runs HTTP/1.1\r\nContent-Length: 70000\r\n\r\n"
        )
        .0,
        413
    );
    assert_eq!(
        raw(
            &s.sock,
            b"POST /v1/runs HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
        )
        .0,
        501
    );
    assert_eq!(raw(&s.sock, b"garbage\r\n\r\n").0, 400);
    // the server is still healthy afterwards
    assert_eq!(call(&s.sock, "GET", "/v1/health", "").0, 200);
}

#[test]
fn an_agents_report_becomes_an_event_a_permission_waits_and_no_socket_answers_it() {
    let s = server();
    let pre = r#"{"engine":"claude-code","cwd":"/work/repos/api-test","payload":{"hook_event_name":"PreToolUse","session_id":"s1","tool_name":"Bash","tool_input":{"command":"git push origin main"}}}"#;
    let (st, v) = call(&s.sock, "POST", "/v1/agent-events", pre);
    assert_eq!(st, 200, "{v}");
    let id = v["permission"].as_str().unwrap().to_string();
    let (st, snap) = call(&s.sock, "GET", "/v1/agent-events?since=0", "");
    assert_eq!(st, 200);
    assert!(snap["pending"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p["id"] == id.as_str() && p["detail"] == "git push origin main"));
    let path = format!("/v1/agent-events/permission/{id}");
    assert_eq!(call(&s.sock, "GET", &path, "").1["state"], "pending");
    // a permission request is answered by a person, never through this socket (an agent could approve its own)
    for d in [
        r#"{"decision":"maybe"}"#,
        r#"{"decision":"allow"}"#,
        r#"{"decision":"deny"}"#,
    ] {
        let (st, v) = call(&s.sock, "POST", &path, d);
        assert_eq!(
            (st, v["code"].as_str()),
            (403, Some("decision_not_here")),
            "{d}"
        );
    }
    assert_eq!(call(&s.sock, "GET", &path, "").1["state"], "pending");
    assert_eq!(
        call(&s.sock, "GET", "/v1/agent-events/permission/nope", "").0,
        404
    );
    // a Stop says the agent waits for input; nonsense is refused
    let stop = r#"{"engine":"claude-code","cwd":"/work/repos/api-test","payload":{"hook_event_name":"Stop"}}"#;
    assert_eq!(call(&s.sock, "POST", "/v1/agent-events", stop).0, 200);
    let (_, snap) = call(&s.sock, "GET", "/v1/agent-events", "");
    assert!(snap["states"]
        .as_array()
        .unwrap()
        .iter()
        .any(|x| x["cwd"] == "/work/repos/api-test" && x["state"] == "waiting"));
    assert_eq!(
        call(
            &s.sock,
            "POST",
            "/v1/agent-events",
            r#"{"engine":"claude-code","payload":{"hook_event_name":"Nope"}}"#
        )
        .0,
        400
    );
    assert_eq!(call(&s.sock, "POST", "/v1/agent-events", "{x").0, 400);
    // the agent-sessions routes exist and refuse what is not a pane id
    assert_eq!(
        call(
            &s.sock,
            "POST",
            "/v1/agent-sessions/3/send",
            r#"{"text":"hi"}"#
        )
        .0,
        400
    );
    assert_eq!(call(&s.sock, "DELETE", "/v1/agent-sessions", "").0, 405);
}

#[test]
fn a_kept_open_run_takes_input_on_its_own_route_and_never_echoes_it() {
    let s = server();
    let body = r#"{"argv":["claude","-p"],"stdin":"{}\n","keep_stdin_open":true}"#;
    let (st, v) = call(&s.sock, "POST", "/v1/runs", body);
    assert_eq!(st, 201, "{v}");
    let id = v["id"].as_str().unwrap().to_string();
    let path = format!("/v1/runs/{id}/stdin");
    let (st, v) = call(&s.sock, "POST", &path, r#"{"text":"SECRET-TURN-MARKER\n"}"#);
    assert_eq!(st, 200, "{v}");
    assert!(!v.to_string().contains("SECRET-TURN-MARKER"));
    assert_eq!(call(&s.sock, "POST", &path, r#"{"close":true}"#).0, 200);
    assert_eq!(call(&s.sock, "POST", &path, r#"{"text":"late"}"#).0, 409);
    assert_eq!(call(&s.sock, "POST", &path, "{nope").0, 400);
    assert_eq!(
        call(
            &s.sock,
            "POST",
            "/v1/runs/nosuchrun/stdin",
            r#"{"text":"x"}"#
        )
        .0,
        404
    );
    assert_eq!(call(&s.sock, "GET", &path, "").0, 405);
    // a run that was not kept open refuses
    let (_, v) = call(
        &s.sock,
        "POST",
        "/v1/runs",
        r#"{"argv":["claude"],"stdin":"x"}"#,
    );
    let plain = v["id"].as_str().unwrap().to_string();
    assert_eq!(
        call(
            &s.sock,
            "POST",
            &format!("/v1/runs/{plain}/stdin"),
            r#"{"text":"x"}"#
        )
        .0,
        409
    );
}

#[test]
fn a_runs_output_is_read_from_an_offset_and_neither_the_prompt_nor_the_token_is_ever_shown() {
    let s = server();
    // the text for the run's standard input is carried in the request and is neither listed nor echoed back
    let body = r#"{"argv":["claude","-p"],"env":{"ANTHROPIC_API_KEY":"ozrt_testtoken"},"stdin":"PROMPT-TEXT-MARKER"}"#;
    let (st, v) = call(&s.sock, "POST", "/v1/runs", body);
    assert_eq!(st, 201, "{v}");
    assert!(
        !v.to_string().contains("PROMPT-TEXT-MARKER") && !v.to_string().contains("ozrt_testtoken")
    );
    let id = v["id"].as_str().unwrap().to_string();
    let (st, listing) = raw(&s.sock, b"GET /v1/runs HTTP/1.1\r\n\r\n");
    assert_eq!(st, 200);
    assert!(
        !listing.contains("PROMPT-TEXT-MARKER") && !listing.contains("ozrt_testtoken"),
        "{listing}"
    );

    // no output is kept by the fake spawner: an empty read from the start, not an error, and the state is shown
    let (st, v) = call(&s.sock, "GET", &format!("/v1/runs/{id}/log?from=0"), "");
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["log"]["text"], "");
    assert_eq!(v["log"]["next"], 0);
    assert_eq!(v["log"]["state"], "running");
    assert!(v["log"]["exit_code"].is_null());
    // from is optional, and must be a byte offset
    assert_eq!(
        call(&s.sock, "GET", &format!("/v1/runs/{id}/log"), "").0,
        200
    );
    assert_eq!(
        call(&s.sock, "GET", &format!("/v1/runs/{id}/log?from=-1"), "").0,
        400
    );
    assert_eq!(
        call(&s.sock, "GET", &format!("/v1/runs/{id}/log?from=abc"), "").0,
        400
    );
    // an unknown run, an id that is not one, and the wrong method are refused
    assert_eq!(call(&s.sock, "GET", "/v1/runs/nosuchrun/log", "").0, 404);
    assert_eq!(
        call(&s.sock, "GET", "/v1/runs/..%2f..%2fetc/log", "").0,
        404
    );
    assert_eq!(
        call(&s.sock, "POST", &format!("/v1/runs/{id}/log"), "").0,
        405
    );
    // a prompt over the limit is refused before anything starts
    let big = format!(r#"{{"argv":["x"],"stdin":"{}"}}"#, "a".repeat(49 * 1024));
    assert_eq!(call(&s.sock, "POST", "/v1/runs", &big).0, 400);
}

#[test]
fn local_models_say_so_when_the_box_has_no_runtime_service() {
    // no service is installed in this process: the route answers 503 with a message, never a crash
    let s = server();
    let (st, v) = call(&s.sock, "GET", "/v1/local-ai", "");
    assert_eq!(st, 503, "{v}");
    assert_eq!(v["code"], "local_ai_unavailable");
    assert_eq!(call(&s.sock, "POST", "/v1/local-ai/pull", "{}").0, 503);
}

fn call_with_cap(
    sock: &Path,
    method: &str,
    target: &str,
    body: &str,
    cap: &str,
) -> (u16, serde_json::Value) {
    let req = format!(
        "{method} {target} HTTP/1.1\r\nHost: x\r\nX-Ozbox-Run-Capability: {cap}\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let (s, b) = raw(sock, req.as_bytes());
    (
        s,
        serde_json::from_str(&b).unwrap_or(serde_json::Value::Null),
    )
}

/// A controlled run (a browser session, ADR 0037) answers only the caller that started it: another process on the same
/// socket (the box user's own shell) cannot write to its input, read its output or stop it.
#[test]
fn a_controlled_run_answers_only_the_caller_that_started_it() {
    let s = server();
    let body = r#"{"argv":["ozbox","browser-worker"],"stdin":"{}\n","keep_stdin_open":true,"require_capability":true,"labels":{"ozbox.browser":"1"}}"#;
    let (st, v) = call(&s.sock, "POST", "/v1/runs", body);
    assert_eq!(st, 201, "{v}");
    let id = v["id"].as_str().unwrap().to_string();
    let cap = v["capability"].as_str().unwrap().to_string();
    assert!(cap.starts_with("ozc_") && cap.len() == 68);
    // the capability is given once: the list of runs never shows it
    let (_, list) = call(&s.sock, "GET", "/v1/runs", "");
    assert!(!list.to_string().contains(&cap));
    let stdin = format!("/v1/runs/{id}/stdin");
    let log = format!("/v1/runs/{id}/log?from=0");
    let stop = format!("/v1/runs/{id}");
    let line = r#"{"text":"{\"id\":9,\"op\":\"act\",\"approved\":true}\n"}"#;
    // without it, or with a wrong one: refused, and nothing reached the run
    for c in [None, Some("ozc_0000"), Some("nonsense")] {
        let r = |m: &str, t: &str, b: &str| match c {
            None => call(&s.sock, m, t, b),
            Some(c) => call_with_cap(&s.sock, m, t, b, c),
        };
        assert_eq!(r("POST", &stdin, line).0, 403);
        assert_eq!(r("GET", &log, "").0, 403);
        assert_eq!(r("DELETE", &stop, "").0, 403);
    }
    // with it: the starter drives the run
    assert_eq!(call_with_cap(&s.sock, "POST", &stdin, line, &cap).0, 200);
    assert_eq!(call_with_cap(&s.sock, "GET", &log, "", &cap).0, 200);
    assert_eq!(call_with_cap(&s.sock, "DELETE", &stop, "", &cap).0, 200);
    // an ordinary run is unchanged
    let (_, v) = call(
        &s.sock,
        "POST",
        "/v1/runs",
        r#"{"argv":["claude"],"stdin":"x","keep_stdin_open":true}"#,
    );
    let plain = v["id"].as_str().unwrap();
    assert!(v.get("capability").is_none());
    assert_eq!(
        call(&s.sock, "GET", &format!("/v1/runs/{plain}/log?from=0"), "").0,
        200
    );
}
