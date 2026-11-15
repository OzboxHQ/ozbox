#![allow(clippy::unwrap_used)]
#![cfg(unix)]
//! The file API over the real Unix socket: a streamed upload, a token download and the errors a client sees.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use ozboxd::api::{bind_socket, serve_with, AppState, HealthInfo};
use ozboxd::checkpoint::CheckpointReport;
use ozboxd::files::{FilesConfig, FilesService};
use ozboxd::health::IncidentLog;
use ozboxd::runs::testing::{FakeCgroup, FakeMemory, FakeSpawner};
use ozboxd::runs::{RunConfig, RunManager};
use ozboxd::selftest::{Check, Outcome, SelfTestResult};
use ozboxd::store::{Store, StoreConfig};
use ozboxd::timeutil::FakeClock;

struct Server {
    sock: PathBuf,
    root: PathBuf,
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

fn server(max_upload: u64) -> Server {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("work");
    std::fs::create_dir_all(&root).unwrap();
    let now = SystemTimeNow::ms();
    let clock = Arc::new(FakeClock::new(now));
    let runs = RunManager::new(
        RunConfig::default(),
        Arc::new(FakeCgroup::default()),
        Arc::new(FakeMemory::new(16 << 30, 8 << 30)),
        Arc::new(FakeSpawner::default()),
        clock.clone(),
    );
    let state = Arc::new(AppState {
        version: "9.9.9".into(),
        started_ms: now,
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
        checkpoint_fn: Box::new(|_| CheckpointReport::default()),
        checkpoint_lock: Mutex::new(()),
        health: Mutex::new(HealthInfo::default()),
    });
    let mut cfg = FilesConfig::new(vec![root.clone()]);
    cfg.max_upload = max_upload;
    let files = Arc::new(FilesService::new(cfg, clock).unwrap());
    let sock = dir.path().join("ozboxd.sock");
    let listener = bind_socket(&sock, 0o660).unwrap();
    let shutdown = Arc::new(AtomicBool::new(false));
    let (st, sd) = (state, shutdown.clone());
    let handle = std::thread::spawn(move || {
        let _ = serve_with(listener, st, Some(files), sd);
    });
    Server {
        sock,
        root,
        shutdown,
        handle: Some(handle),
        _dir: dir,
    }
}

struct SystemTimeNow;
impl SystemTimeNow {
    fn ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }
}

fn call(sock: &Path, head: &str, body: &[u8]) -> (u16, String, Vec<u8>) {
    let mut s = UnixStream::connect(sock).unwrap();
    s.write_all(head.as_bytes()).unwrap();
    // The server may answer (and close) before the whole body is sent: a write error is then fine.
    let _ = s.write_all(body);
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let split = out.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&out[..split]).into_owned();
    let status = head
        .split(' ')
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    (status, head, out[split + 4..].to_vec())
}

fn json(b: &[u8]) -> serde_json::Value {
    serde_json::from_slice(b).unwrap()
}

#[test]
fn upload_streams_then_a_token_downloads_it() {
    let s = server(10 * 1024 * 1024);
    let data: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
    let dir = format!("{}", s.root.display());
    let req = format!(
        "PUT /v1/files/upload?path={dir}&name=big.bin HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
        data.len()
    );
    let (st, _, body) = call(&s.sock, &req, &data);
    assert_eq!(st, 201, "{}", String::from_utf8_lossy(&body));
    assert_eq!(std::fs::read(s.root.join("big.bin")).unwrap(), data);

    let b = format!("{{\"paths\":[\"{dir}/big.bin\"],\"ttl_s\":60}}");
    let (st, _, body) = call(
        &s.sock,
        &format!(
            "POST /v1/files/tokens HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            b.len()
        ),
        b.as_bytes(),
    );
    assert_eq!(st, 201);
    let token = json(&body)["token"].as_str().unwrap().to_string();
    let (st, head, got) = call(
        &s.sock,
        &format!("GET /v1/files/download?token={token} HTTP/1.1\r\nHost: x\r\n\r\n"),
        b"",
    );
    assert_eq!(st, 200);
    assert!(head.contains(&format!("Content-Length: {}", data.len())));
    assert!(head.contains("attachment; filename=\"big.bin\""));
    assert_eq!(got, data);
}

#[test]
fn an_oversized_upload_is_refused_up_front_and_writes_nothing() {
    let s = server(1000);
    let dir = format!("{}", s.root.display());
    let req = format!("PUT /v1/files/upload?path={dir}&name=x.bin HTTP/1.1\r\nHost: x\r\nContent-Length: 5000\r\n\r\n");
    let (st, _, body) = call(&s.sock, &req, &[0u8; 5000]);
    assert_eq!(st, 413);
    assert_eq!(json(&body)["code"], "too_large");
    assert!(!s.root.join("x.bin").exists());
    // a JSON route still refuses a body over the JSON limit
    let big = vec![b' '; 70_000];
    let (st, _, _) = call(
        &s.sock,
        "POST /v1/files/mkdir HTTP/1.1\r\nHost: x\r\nContent-Length: 70000\r\n\r\n",
        &big,
    );
    assert_eq!(st, 413);
}

#[test]
fn list_and_errors_use_the_code_and_message_shape() {
    let s = server(1000);
    std::fs::write(s.root.join("a.txt"), "a").unwrap();
    let dir = format!("{}", s.root.display());
    let (st, _, body) = call(
        &s.sock,
        &format!("GET /v1/files/list?path={dir} HTTP/1.1\r\nHost: x\r\n\r\n"),
        b"",
    );
    assert_eq!(st, 200);
    assert_eq!(json(&body)["entries"][0]["name"], "a.txt");
    let (st, _, body) = call(
        &s.sock,
        "GET /v1/files/list?path=/etc HTTP/1.1\r\nHost: x\r\n\r\n",
        b"",
    );
    assert_eq!(st, 403);
    let v = json(&body);
    assert!(v["code"].is_string() && v["message"].is_string());
    // the older endpoints are untouched
    let (st, _, _) = call(&s.sock, "GET /v1/health HTTP/1.1\r\nHost: x\r\n\r\n", b"");
    assert_eq!(st, 200);
}

#[test]
fn an_empty_body_is_a_valid_save_but_a_missing_length_is_not() {
    let s = server(1000);
    let dir = format!("{}", s.root.display());
    let (st, _, _) = call(
        &s.sock,
        &format!("PUT /v1/files/write?path={dir}/e.txt&if_match=none HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n"),
        b"",
    );
    assert_eq!(st, 200);
    assert_eq!(std::fs::read(s.root.join("e.txt")).unwrap(), b"");
    let (st, _, _) = call(
        &s.sock,
        &format!("PUT /v1/files/write?path={dir}/f.txt&if_match=none HTTP/1.1\r\nHost: x\r\n\r\n"),
        b"",
    );
    assert_eq!(st, 411);
}
