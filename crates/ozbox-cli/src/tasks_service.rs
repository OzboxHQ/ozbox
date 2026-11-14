//! `ozbox tasks serve`: the channel's router as a service of its own (ADR 0044).
//!
//! On a box the key file, the task state and the mesh audit log belong to a system user, `ozbox-mesh`, that has no login. Agents run as
//! the box user, so they cannot read the key, edit the state, rewrite the audit chain or replace the program that answers the
//! laptop. They reach the router only through the sockets below, and **which socket a caller may open is decided by the permissions of
//! its directory**, not by the program (the pattern of the secrets service, ADR 0018):
//!
//! * the **agent socket** (the box user may connect): submit, reply, inbox, status, why, cancel and the public identity.
//! * the **relay socket** (the box user may connect): one operation, `exchange`, that carries the opaque envelope bytes the laptop's
//!   `ssh` command hands in and returns what this end has for it. The process that connects holds no key and sees ciphertext only, so a
//!   replaced `ozbox` on the box user's `PATH` can drop or delay an exchange and can do nothing else.
//! * the **admin socket** (root and `ozbox-mesh` only): everything, including `init`, `pin` and `restored`.
//!
//! A request is one JSON line and so is the answer.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use ozbox_core::{Error, Result};
use serde_json::{json, Value};

use crate::tasks_ops::{dispatch, init, Ends, Policy};

/// The most a request may carry: the relay's holds a whole round of sealed envelopes, JSON-escaped inside a JSON line.
const MAX_RELAY_REQUEST: u64 = 12 * 1024 * 1024;
const MAX_REQUEST: u64 = 256 * 1024;
const IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

fn limit(policy: Policy) -> u64 {
    if policy == Policy::Relay {
        MAX_RELAY_REQUEST
    } else {
        MAX_REQUEST
    }
}

/// Read one line, no longer than `max` bytes.
fn read_line(stream: &UnixStream, max: u64) -> std::io::Result<String> {
    let mut line = String::new();
    BufReader::new(stream.take(max)).read_line(&mut line)?;
    Ok(line)
}

fn handle(dir: &Path, policy: Policy, stream: UnixStream) {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    let reply = match read_line(&stream, limit(policy)) {
        Ok(l) if l.ends_with('\n') => answer(dir, policy, &l),
        Ok(_) => json!({"ok": false, "error": "request-too-large-or-unfinished"}),
        Err(_) => return,
    };
    let mut out = stream;
    let _ = writeln!(out, "{reply}");
}

fn answer(dir: &Path, policy: Policy, line: &str) -> Value {
    let Ok(req) = serde_json::from_str::<Value>(line.trim()) else {
        return json!({"ok": false, "error": "not-json"});
    };
    let outcome = if req.get("op").and_then(Value::as_str) == Some("init") {
        // the one operation that runs before there is anything to open, and only for the owner
        if policy == Policy::Admin {
            init(dir, req.get("name").and_then(Value::as_str).unwrap_or(""))
        } else {
            Err("not-allowed-here".to_string())
        }
    } else {
        Ends::open(dir).and_then(|ends| dispatch(&ends, policy, &req, false))
    };
    match outcome {
        Ok(v) => json!({"ok": true, "result": v}),
        Err(e) => json!({"ok": false, "error": e}),
    }
}

/// The three sockets and the state directory.
pub struct Paths {
    pub dir: PathBuf,
    pub agent: PathBuf,
    pub relay: PathBuf,
    pub admin: PathBuf,
}

/// Serve until the process is stopped. One thread per socket, one short-lived thread per connection.
pub fn serve(p: &Paths) -> Result<()> {
    let sockets = [
        (&p.agent, 0o750, Policy::Agent),
        (&p.relay, 0o750, Policy::Relay),
        (&p.admin, 0o700, Policy::Admin),
    ];
    let mut handles = Vec::new();
    for (path, mode, policy) in sockets {
        let l: UnixListener = crate::secrets_service::listen(path, mode).map_err(Error::Io)?;
        let dir = p.dir.clone();
        handles.push(std::thread::spawn(move || {
            for c in l.incoming().flatten() {
                let dir = dir.clone();
                std::thread::spawn(move || handle(&dir, policy, c));
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    Ok(())
}

/// Ask a socket one question.
pub fn call(sock: &Path, req: &Value, max_reply: u64) -> std::result::Result<Value, String> {
    let mut s = UnixStream::connect(sock).map_err(|e| match e.kind() {
        std::io::ErrorKind::PermissionDenied => "permission-denied".to_string(),
        std::io::ErrorKind::NotFound => "no-service".to_string(),
        k => format!("could not reach the task service: {k}"),
    })?;
    s.set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|e| e.to_string())?;
    s.set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|e| e.to_string())?;
    writeln!(s, "{req}").map_err(|e| e.to_string())?;
    let line = read_line(&s, max_reply).map_err(|e| e.to_string())?;
    let v: Value = serde_json::from_str(line.trim())
        .map_err(|_| "the task service gave no answer".to_string())?;
    if v.get("ok").and_then(Value::as_bool) == Some(true) {
        Ok(v.get("result").cloned().unwrap_or(Value::Null))
    } else {
        Err(v
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("refused")
            .to_string())
    }
}

pub const MAX_REPLY: u64 = MAX_RELAY_REQUEST;
