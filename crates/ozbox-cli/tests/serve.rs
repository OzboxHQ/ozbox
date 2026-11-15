//! `ozbox serve` over a real loopback socket, against the fake provider in a temp state dir.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Server {
    child: Child,
    port: u16,
    token: String,
    _dir: tempfile::TempDir,
    _stdout: BufReader<std::process::ChildStdout>,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start() -> Result<Server, Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let mut child = Command::new(env!("CARGO_BIN_EXE_ozbox"))
        .args(["serve", "--port", "0"])
        .env("OZBOX_STATE_DIR", dir.path().join("state"))
        .env("OZBOX_CONFIG", dir.path().join("config.toml"))
        .env("HOME", dir.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let stdout = child.stdout.take().ok_or("no stdout")?;
    let mut line = String::new();
    let mut reader = BufReader::new(stdout);
    reader.read_line(&mut line)?;
    // "Oz Box dashboard: http://127.0.0.1:PORT/#token=TOKEN"
    let url = line.trim().rsplit(' ').next().ok_or("no url")?.to_string();
    let rest = url.strip_prefix("http://127.0.0.1:").ok_or(url.clone())?;
    let (port, token) = rest.split_once("/#token=").ok_or("no token")?;
    Ok(Server {
        child,
        port: port.parse()?,
        token: token.to_string(),
        _dir: dir,
        _stdout: reader,
    })
}

fn http(
    s: &Server,
    method: &str,
    path: &str,
    auth: bool,
    body: &str,
) -> Result<(u16, String), Box<dyn std::error::Error>> {
    let mut c = TcpStream::connect(("127.0.0.1", s.port))?;
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\nContent-Length: {}\r\n",
        s.port,
        body.len()
    );
    if auth {
        head.push_str(&format!("Authorization: Bearer {}\r\n", s.token));
    }
    head.push_str("\r\n");
    head.push_str(body);
    c.write_all(head.as_bytes())?;
    let mut raw = String::new();
    c.read_to_string(&mut raw)?;
    let status = raw
        .split(' ')
        .nth(1)
        .ok_or_else(|| format!("no status in {raw:?}"))?
        .parse()?;
    let body = raw.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    Ok((status, body))
}

#[test]
fn a_non_loopback_bind_is_refused() -> TestResult {
    let out = Command::new(env!("CARGO_BIN_EXE_ozbox"))
        .args(["serve", "--bind", "0.0.0.0", "--port", "0"])
        .stdin(Stdio::null())
        .output()?;
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("loopback"));
    Ok(())
}

#[test]
fn the_token_is_required_over_a_real_socket() -> TestResult {
    let s = start()?;
    assert_eq!(http(&s, "GET", "/v1/boxes", false, "")?.0, 401);
    let (status, body) = http(&s, "GET", "/v1/boxes", true, "")?;
    assert_eq!(status, 200);
    assert_eq!(body.trim(), "[]");
    // the page itself needs no token and carries no data
    assert_eq!(http(&s, "GET", "/", false, "")?.0, 200);
    Ok(())
}

/// A change to a box runs as a job: `POST /v1/apply` answers 202 and this waits for the job to finish.
fn apply_and_wait(s: &Server, body: &str) -> TestResult {
    let (st, answer) = http(s, "POST", "/v1/apply", true, body)?;
    assert_eq!(st, 202, "{answer}");
    let v: serde_json::Value = serde_json::from_str(&answer)?;
    let id = v["job_id"].as_str().unwrap_or("").to_string();
    for _ in 0..200 {
        let (_, j) = http(s, "GET", &format!("/v1/jobs/{id}"), true, "")?;
        let j: serde_json::Value = serde_json::from_str(&j)?;
        match j["state"].as_str() {
            Some("done") => return Ok(()),
            Some("failed") => panic!("the change failed: {j}"),
            _ => std::thread::sleep(std::time::Duration::from_millis(50)),
        }
    }
    panic!("the change did not finish");
}

#[test]
fn plan_then_apply_over_a_real_socket() -> TestResult {
    let s = start()?;
    let create = r#"{"operation":{"op":"create","spec":{"name":"dev","size":"M","work_disk_gb":100,"image":null,"region":null,"from_snapshot":null,"labels":{}}}}"#;
    let (st, body) = http(&s, "POST", "/v1/plans", true, create)?;
    assert_eq!(st, 200, "{body}");
    let plan: serde_json::Value = serde_json::from_str(&body)?;
    let apply = format!(
        r#"{{"plan_id":"{}"}}"#,
        plan["plan_id"].as_str().unwrap_or("")
    );
    apply_and_wait(&s, &apply)?;
    let (_, one) = http(&s, "GET", "/v1/boxes/dev/metrics/now", true, "")?;
    assert!(one.contains("\"source\":\"simulated\""), "{one}");
    Ok(())
}

#[test]
fn events_stream_announces_a_change_made_through_the_server() -> TestResult {
    let s = start()?;
    let mut c = TcpStream::connect(("127.0.0.1", s.port))?;
    c.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    let req = format!(
        "GET /v1/events HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer {}\r\n\r\n",
        s.port, s.token
    );
    c.write_all(req.as_bytes())?;
    // Wait for the stream to say hello before changing anything. Requests on different connections are handled in
    // whatever order they arrive, so a change made straight after sending the request could be applied before the server
    // has registered this stream, and a stream registered after a change has nothing to announce.
    let mut got = String::new();
    let mut buf = [0u8; 512];
    while !got.contains("event: hello") {
        let n = c.read(&mut buf)?;
        assert!(n > 0, "stream closed early: {got}");
        got.push_str(&String::from_utf8_lossy(&buf[..n]));
    }
    let create = r#"{"operation":{"op":"create","spec":{"name":"dev","size":"S","work_disk_gb":50,"image":null,"region":null,"from_snapshot":null,"labels":{}}}}"#;
    let (_, body) = http(&s, "POST", "/v1/plans", true, create)?;
    let plan: serde_json::Value = serde_json::from_str(&body)?;
    let apply = format!(
        r#"{{"plan_id":"{}"}}"#,
        plan["plan_id"].as_str().unwrap_or("")
    );
    apply_and_wait(&s, &apply)?;
    while !got.contains("event: changed") {
        let n = c.read(&mut buf)?;
        assert!(n > 0, "stream closed early: {got}");
        got.push_str(&String::from_utf8_lossy(&buf[..n]));
    }
    assert!(got.contains("text/event-stream") && got.contains("event: hello"));
    // and the same stream refuses a caller without the token
    assert_eq!(http(&s, "GET", "/v1/events", false, "")?.0, 401);
    Ok(())
}

/// Ctrl+C (SIGINT) and a service manager's stop (SIGTERM) take the tunnel down before the server exits. Tailscale keeps
/// forwarding in its own daemon after the program that asked for it is gone, so a missed stop leaves the dashboard
/// reachable from outside with nothing running to guard it.
#[cfg(unix)]
mod shutdown {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{Duration, Instant};

    /// A `tailscale` that records how it was called and answers like a signed-in machine with nothing forwarded.
    const FAKE_TAILSCALE: &str = r#"#!/bin/sh
echo "$@" >> "$FAKE_TAILSCALE_LOG"
case "$*" in
  "status --json") echo '{"BackendState":"Running","Self":{"DNSName":"box.tail1234.ts.net."}}' ;;
  "serve status --json") echo '{}' ;;
esac
exit 0
"#;

    fn wait_for(path: &std::path::Path, needle: &str, secs: u64) -> bool {
        let end = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < end {
            if std::fs::read_to_string(path).is_ok_and(|t| t.contains(needle)) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        false
    }

    fn stop_with(signal: &str) -> TestResult {
        let dir = tempfile::tempdir()?;
        let bin = dir.path().join("bin");
        std::fs::create_dir(&bin)?;
        let fake = bin.join("tailscale");
        std::fs::write(&fake, FAKE_TAILSCALE)?;
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755))?;
        let log = dir.path().join("tailscale.log");
        std::fs::write(
            dir.path().join("tunnel.toml"),
            "provider = \"tailscale-serve\"\npublic_url = \"https://box.tail1234.ts.net\"\n",
        )?;
        let path = format!(
            "{}:{}",
            bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let mut child = Command::new(env!("CARGO_BIN_EXE_ozbox"))
            .args(["serve", "--port", "0", "--tunnel", "tailscale-serve"])
            .env("OZBOX_STATE_DIR", dir.path().join("state"))
            .env("OZBOX_CONFIG", dir.path().join("config.toml"))
            .env("HOME", dir.path())
            .env("PATH", path)
            .env("FAKE_TAILSCALE_LOG", &log)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let mut stdout = child.stdout.take().ok_or("no stdout")?;
        assert!(
            wait_for(&log, "serve --bg --https=443", 20),
            "the tunnel never started: {:?}",
            std::fs::read_to_string(&log)
        );
        let sent = Command::new("kill")
            .args([signal, &child.id().to_string()])
            .status()?;
        assert!(sent.success());
        let end = Instant::now() + Duration::from_secs(15);
        let status = loop {
            if let Some(s) = child.try_wait()? {
                break s;
            }
            if Instant::now() > end {
                let _ = child.kill();
                return Err("the server did not stop after the signal".into());
            }
            std::thread::sleep(Duration::from_millis(100));
        };
        assert!(status.success(), "{status:?}");
        let mut out = String::new();
        stdout.read_to_string(&mut out)?;
        assert!(out.contains("Stopping"), "{out}");
        let calls = std::fs::read_to_string(&log)?;
        assert!(
            calls.lines().last() == Some("serve --https=443 off"),
            "the forward was not removed: {calls}"
        );
        Ok(())
    }

    #[test]
    fn sigterm_removes_the_tailscale_forward_and_exits_cleanly() -> TestResult {
        stop_with("-TERM")
    }

    #[test]
    fn sigint_removes_the_tailscale_forward_and_exits_cleanly() -> TestResult {
        stop_with("-INT")
    }
}

/// One answer read off a keep-alive connection: the status, once the whole body has arrived.
fn read_answer(c: &mut TcpStream) -> Result<u16, String> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        let n = c.read(&mut byte).map_err(|e| format!("no answer: {e}"))?;
        if n == 0 {
            return Err("the server closed the connection without answering".into());
        }
        head.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&head).to_string();
    let status = text
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| format!("no status in {text:?}"))?;
    let header = |name: &str| {
        text.lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case(name).then(|| v.trim().to_string())
        })
    };
    if header("transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked")) {
        // a big body comes in chunks: "<hex size>\r\n<bytes>\r\n", ended by a zero-size chunk
        loop {
            let mut size_line = Vec::new();
            while !size_line.ends_with(b"\r\n") {
                c.read_exact(&mut byte)
                    .map_err(|e| format!("a chunk size did not arrive: {e}"))?;
                size_line.push(byte[0]);
            }
            let size = usize::from_str_radix(String::from_utf8_lossy(&size_line).trim(), 16)
                .map_err(|e| format!("bad chunk size: {e}"))?;
            let mut chunk = vec![0u8; size + 2];
            c.read_exact(&mut chunk)
                .map_err(|e| format!("a chunk did not arrive: {e}"))?;
            if size == 0 {
                break;
            }
        }
    } else {
        let len: usize = header("content-length")
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| format!("no length in {text:?}"))?;
        let mut body = vec![0u8; len];
        c.read_exact(&mut body)
            .map_err(|e| format!("the body did not arrive: {e}"))?;
    }
    Ok(status)
}

/// What a dashboard does on its first load: its event stream held open, and a dozen reads sent over six reused connections at
/// the same moment, from several pages at once. Every read must be answered, once and in full.
#[test]
fn a_burst_like_a_page_load_gets_every_answer_on_reused_connections() -> TestResult {
    use std::time::Duration;
    let s = start()?;
    let paths = [
        "/v1/info",
        "/v1/boxes",
        "/v1/catalog",
        "/v1/profiles",
        "/v1/setup",
        "/v1/settings",
        "/v1/approvals",
        "/v1/cost",
    ];
    let failures: Vec<String> = std::thread::scope(|scope| {
        let mut jobs = Vec::new();
        for page in 0..10 {
            let s = &s;
            // the page's event stream: opened, and held until the page is done
            jobs.push(scope.spawn(move || -> Vec<String> {
                let mut sse = match TcpStream::connect(("127.0.0.1", s.port)) {
                    Ok(c) => c,
                    Err(e) => return vec![format!("page {page} stream: {e}")],
                };
                let _ = sse.write_all(
                    format!(
                        "GET /v1/events HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer {}\r\n\r\n",
                        s.port, s.token
                    )
                    .as_bytes(),
                );
                let mut readers = Vec::new();
                for sock in 0..6 {
                    readers.push(std::thread::spawn({
                        let (port, token) = (s.port, s.token.clone());
                        move || -> Vec<String> {
                            let mut bad = Vec::new();
                            let mut c = match TcpStream::connect(("127.0.0.1", port)) {
                                Ok(c) => c,
                                Err(e) => return vec![format!("page {page} socket {sock}: {e}")],
                            };
                            let _ = c.set_read_timeout(Some(Duration::from_secs(10)));
                            for round in 0..4 {
                                for (i, p) in paths.iter().enumerate() {
                                    if i % 6 != sock {
                                        continue;
                                    }
                                    let req = format!(
                                        "GET {p} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: keep-alive\r\nAuthorization: Bearer {token}\r\n\r\n"
                                    );
                                    if let Err(e) = c.write_all(req.as_bytes()) {
                                        bad.push(format!("page {page} {p} round {round}: {e}"));
                                        return bad;
                                    }
                                    match read_answer(&mut c) {
                                        Ok(200 | 409) => {}
                                        Ok(other) => {
                                            bad.push(format!("page {page} {p}: status {other}"))
                                        }
                                        Err(e) => {
                                            bad.push(format!("page {page} {p} round {round}: {e}"));
                                            return bad;
                                        }
                                    }
                                }
                            }
                            bad
                        }
                    }));
                }
                let mut bad = Vec::new();
                for r in readers {
                    match r.join() {
                        Ok(b) => bad.extend(b),
                        Err(_) => bad.push(format!("page {page}: a reader panicked")),
                    }
                }
                drop(sse);
                bad
            }));
        }
        jobs.into_iter()
            .flat_map(|j| j.join().unwrap_or_else(|_| vec!["a page panicked".into()]))
            .collect()
    });
    assert!(failures.is_empty(), "unanswered or wrong: {failures:#?}");
    Ok(())
}
