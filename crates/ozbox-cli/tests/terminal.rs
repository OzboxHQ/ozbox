//! The browser terminal over a real loopback socket, against the demo box (a real shell in a private folder).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

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

fn head(s: &Server, method: &str, path: &str, auth: bool, len: usize) -> String {
    let mut h = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\nContent-Length: {len}\r\n",
        s.port
    );
    if auth {
        h.push_str(&format!("Authorization: Bearer {}\r\n", s.token));
    }
    h.push_str("\r\n");
    h
}

fn http(
    s: &Server,
    method: &str,
    path: &str,
    auth: bool,
    body: &[u8],
) -> Result<(u16, String), Box<dyn std::error::Error>> {
    let mut c = TcpStream::connect(("127.0.0.1", s.port))?;
    c.write_all(head(s, method, path, auth, body.len()).as_bytes())?;
    c.write_all(body)?;
    let mut raw = Vec::new();
    c.read_to_end(&mut raw)?;
    let raw = String::from_utf8_lossy(&raw).into_owned();
    let status = raw.split(' ').nth(1).ok_or("no status")?.parse()?;
    Ok((
        status,
        raw.split("\r\n\r\n").nth(1).unwrap_or("").to_string(),
    ))
}

fn frame(ty: u8, p: &[u8]) -> Vec<u8> {
    let mut v = vec![ty];
    v.extend_from_slice(&(p.len() as u32).to_be_bytes());
    v.extend_from_slice(p);
    v
}

fn read_frame(c: &mut TcpStream) -> Result<(u8, Vec<u8>), Box<dyn std::error::Error>> {
    let mut h = [0u8; 5];
    c.read_exact(&mut h)?;
    let mut p = vec![0u8; u32::from_be_bytes([h[1], h[2], h[3], h[4]]) as usize];
    c.read_exact(&mut p)?;
    Ok((h[0], p))
}

/// A change to a box runs as a job: `POST /v1/apply` answers 202 and this waits for the job to finish.
fn apply_and_wait(s: &Server, body: &str) -> TestResult {
    let (st, answer) = http(s, "POST", "/v1/apply", true, body.as_bytes())?;
    assert_eq!(st, 202, "{answer}");
    let v: serde_json::Value = serde_json::from_str(&answer)?;
    let id = v["job_id"].as_str().unwrap_or("").to_string();
    for _ in 0..200 {
        let (_, j) = http(s, "GET", &format!("/v1/jobs/{id}"), true, b"")?;
        let j: serde_json::Value = serde_json::from_str(&j)?;
        match j["state"].as_str() {
            Some("done") => return Ok(()),
            Some("failed") => panic!("the change failed: {j}"),
            _ => std::thread::sleep(std::time::Duration::from_millis(50)),
        }
    }
    panic!("the change did not finish");
}

fn make_box(s: &Server) -> TestResult {
    let create = r#"{"operation":{"op":"create","spec":{"name":"dev","size":"M","work_disk_gb":100,"image":null,"region":null,"from_snapshot":null,"labels":{}}}}"#;
    let (_, body) = http(s, "POST", "/v1/plans", true, create.as_bytes())?;
    let plan: serde_json::Value = serde_json::from_str(&body)?;
    let apply = format!(
        r#"{{"plan_id":"{}"}}"#,
        plan["plan_id"].as_str().unwrap_or("")
    );
    apply_and_wait(s, &apply)?;
    Ok(())
}

#[test]
fn a_terminal_needs_the_token_and_a_session_is_a_real_shell() -> TestResult {
    let s = start()?;
    make_box(&s)?;
    assert_eq!(
        http(&s, "POST", "/v1/boxes/dev/terminal", false, b"{}")?.0,
        401
    );
    assert_eq!(
        http(&s, "POST", "/v1/boxes/nope/terminal", true, b"{}")?.0,
        404
    );
    let (st, body) = http(
        &s,
        "POST",
        "/v1/boxes/dev/terminal",
        true,
        br#"{"cols":100,"rows":30}"#,
    )?;
    assert_eq!(st, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body)?;
    let id = v["session"].as_str().ok_or("no session")?.to_string();

    // output needs the token as well
    let mut anon = TcpStream::connect(("127.0.0.1", s.port))?;
    anon.write_all(head(&s, "GET", &format!("/v1/terminal/{id}/output"), false, 0).as_bytes())?;
    let mut raw = String::new();
    anon.read_to_string(&mut raw)?;
    assert!(raw.contains("401"), "{raw}");

    let mut out = TcpStream::connect(("127.0.0.1", s.port))?;
    out.set_read_timeout(Some(Duration::from_secs(10)))?;
    out.write_all(head(&s, "GET", &format!("/v1/terminal/{id}/output"), true, 0).as_bytes())?;
    let mut hdr = Vec::new();
    let mut b = [0u8; 1];
    while !hdr.ends_with(b"\r\n\r\n") {
        out.read_exact(&mut b)?;
        hdr.push(b[0]);
    }
    assert!(String::from_utf8_lossy(&hdr).contains("200"));
    let mut ready = false;
    while !ready {
        let (ty, p) = read_frame(&mut out)?;
        assert_ne!(ty, 6, "{}", String::from_utf8_lossy(&p));
        ready = ty == 5;
    }
    let input = format!("/v1/terminal/{id}/input");
    assert_eq!(http(&s, "POST", &input, true, &frame(9, b"x"))?.0, 400);
    assert_eq!(
        http(
            &s,
            "POST",
            &input,
            true,
            &frame(1, b"echo ozbox-$((20+22))\n")
        )?
        .0,
        200
    );
    let mut text = String::new();
    let end = Instant::now() + Duration::from_secs(10);
    while !text.contains("ozbox-42") && Instant::now() < end {
        let (ty, p) = read_frame(&mut out)?;
        if ty == 1 {
            text.push_str(&String::from_utf8_lossy(&p));
        }
    }
    assert!(text.contains("ozbox-42"), "{text}");
    assert_eq!(
        http(&s, "DELETE", &format!("/v1/terminal/{id}"), true, b"")?.0,
        200
    );
    assert_eq!(http(&s, "POST", &input, true, &frame(1, b"x"))?.0, 404);
    // the audit trail of the server names the action, never the content
    let (_, act) = http(&s, "GET", "/v1/activity", true, b"")?;
    assert!(
        act.contains("terminal.open") && !act.contains("ozbox-42"),
        "{act}"
    );
    Ok(())
}
