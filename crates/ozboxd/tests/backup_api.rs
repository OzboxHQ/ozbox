#![allow(clippy::unwrap_used)]
#![cfg(unix)]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use ozboxd::api::{bind_socket, serve, AppState, HealthInfo};
use ozboxd::backup::BackupConfig;
use ozboxd::backup_service::{install_global, BackupService};
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
    _state: Arc<AppState>,
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
        _state: state,
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

fn env(dir: &Path) -> PathBuf {
    dir.join("restic.env")
}

#[test]
fn backups_over_the_socket_need_credentials_then_run_tagged_and_report_how_they_ended() {
    let s = server();
    let runner = Arc::new(ozbox_core::RecordingRunner::new());
    runner.reply(ozbox_core::Output {
        status: Some(0),
        stdout: String::new(),
        stderr: String::new(),
    });
    let path = env(s._dir.path());
    let svc = Arc::new(
        BackupService::new(
            BackupConfig {
                env_file: path.clone(),
                box_name: Some("main".into()),
                ..BackupConfig::default()
            },
            runner.clone(),
            Arc::new(FakeClock::new(T0)),
        )
        .inline(),
    );
    install_global(svc);

    let (st, v) = call(&s.sock, "GET", "/v1/backup/status", "");
    assert_eq!(st, 200);
    assert_eq!(v["configured"], false);
    let (st, v) = call(&s.sock, "POST", "/v1/backup/run", "{}");
    assert_eq!((st, v["code"].as_str()), (409, Some("not_configured")));
    let (st, v) = call(&s.sock, "GET", "/v1/backup/snapshots", "");
    assert_eq!((st, v["code"].as_str()), (409, Some("not_configured")));

    std::fs::write(
        &path,
        "RESTIC_REPOSITORY=s3:https://objects.example.com/b\nRESTIC_PASSWORD_FILE=/etc/ozbox/restic.pass\nAWS_SECRET_ACCESS_KEY=sekrit-key\n",
    )
    .unwrap();
    let (st, v) = call(
        &s.sock,
        "POST",
        "/v1/backup/run",
        r#"{"keep_daily":3,"keep_weekly":2,"keep_monthly":1}"#,
    );
    assert_eq!((st, v["started"].as_bool()), (202, Some(true)));
    let (_, v) = call(&s.sock, "GET", "/v1/backup/status", "");
    assert_eq!(v["configured"], true);
    assert_eq!(v["last"]["ok"], true);
    assert_eq!(v["last"]["op"], "backup");
    let calls = runner.calls();
    assert!(calls[1]
        .args
        .join(" ")
        .contains("--keep-daily 3 --keep-weekly 2 --keep-monthly 1"));
    assert!(!v.to_string().contains("sekrit") && !v.to_string().contains("objects.example.com"));

    for (body, ok) in [
        (r#"{"retention":1}"#, true),
        (
            r#"{"keep_daily":0,"keep_weekly":0,"keep_monthly":0}"#,
            false,
        ),
    ] {
        let (st, _) = call(&s.sock, "POST", "/v1/backup/run", body);
        assert_eq!(st == 202, ok, "{body}");
    }
    let (st, _) = call(
        &s.sock,
        "POST",
        "/v1/backup/forget",
        r#"{"snapshot":"--keep-last"}"#,
    );
    assert_eq!(st, 400);
    let (st, _) = call(&s.sock, "DELETE", "/v1/backup/status", "");
    assert_eq!(st, 405);
    let (st, _) = call(&s.sock, "GET", "/v1/backup/nothing", "");
    assert_eq!(st, 404);
}
