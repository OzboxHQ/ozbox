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
//!   replaced `ozbox` on the box user's `PATH` can drop, delay, **or record and replay** an exchange, and can do nothing else. A replay
//!   is refused by the channel (stale or already seen) and costs one audit entry a round; the socket takes one round at a time and a
//!   bounded number a minute, so replaying cannot become a flood.
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
/// (the channel's transport cap, and half as much again for the JSON escaping around it).
const MAX_RELAY_REQUEST: u64 = ozbox_core::channel::wire::TRANSPORT_CAP as u64 * 3 / 2;
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

/// How many connections a socket admits. The relay carries whole rounds and anything on the box can reach it, so it takes one at a
/// time and a bounded number a minute; the other two are the service's own callers and are not limited here.
struct Gate {
    busy: std::sync::atomic::AtomicUsize,
    max_busy: usize,
    recent: std::sync::Mutex<std::collections::VecDeque<std::time::Instant>>,
    per_minute: usize,
}

/// Held while a connection is served.
struct Permit(std::sync::Arc<Gate>);

impl Drop for Permit {
    fn drop(&mut self) {
        self.0
            .busy
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// The relay's limits: one round in flight, and a round every half second on average (a sync makes at most three exchanges and a
/// `watch` one every few seconds, so honest use never meets the limit).
const RELAY_PER_MINUTE: usize = 120;

impl Gate {
    fn new(policy: Policy) -> std::sync::Arc<Gate> {
        let (max_busy, per_minute) = if policy == Policy::Relay {
            (1, RELAY_PER_MINUTE)
        } else {
            (usize::MAX, usize::MAX)
        };
        std::sync::Arc::new(Gate {
            busy: std::sync::atomic::AtomicUsize::new(0),
            max_busy,
            recent: std::sync::Mutex::new(std::collections::VecDeque::new()),
            per_minute,
        })
    }

    fn enter(self: &std::sync::Arc<Gate>) -> Option<Permit> {
        use std::sync::atomic::Ordering::SeqCst;
        let now = std::time::Instant::now();
        {
            let mut r = self.recent.lock().ok()?;
            while r
                .front()
                .is_some_and(|t| now.duration_since(*t) >= std::time::Duration::from_secs(60))
            {
                r.pop_front();
            }
            if r.len() >= self.per_minute {
                return None;
            }
            if self.busy.fetch_add(1, SeqCst) >= self.max_busy {
                self.busy.fetch_sub(1, SeqCst);
                return None;
            }
            r.push_back(now);
        }
        Some(Permit(std::sync::Arc::clone(self)))
    }
}

/// The three sockets and the state directory.
pub struct Paths {
    pub dir: PathBuf,
    pub agent: PathBuf,
    pub relay: PathBuf,
    pub admin: PathBuf,
}

/// The router runs a program the box user must not be able to replace. When `OZBOX_TASKS_REQUIRE_ROOT_PROGRAM` is set (the box's unit
/// sets it), refuse to start unless this program and every directory above it belong to root and are writable by no one else.
fn require_root_owned_program() -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    if std::env::var_os("OZBOX_TASKS_REQUIRE_ROOT_PROGRAM").is_none() {
        return Ok(());
    }
    let exe = std::fs::canonicalize(std::env::current_exe()?)?;
    let mut at: Option<&Path> = Some(exe.as_path());
    while let Some(p) = at {
        let m = std::fs::metadata(p)?;
        if m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err(Error::Config(format!(
                "the task router will not start: {} is not owned by root or can be written by someone else, so the program could be replaced",
                p.display()
            )));
        }
        at = p.parent();
    }
    Ok(())
}

/// Serve until the process is stopped. One thread per socket, one short-lived thread per connection.
pub fn serve(p: &Paths) -> Result<()> {
    require_root_owned_program()?;
    let sockets = [
        (&p.agent, 0o750, Policy::Agent),
        (&p.relay, 0o750, Policy::Relay),
        (&p.admin, 0o700, Policy::Admin),
    ];
    let mut handles = Vec::new();
    for (path, mode, policy) in sockets {
        let l: UnixListener = crate::secrets_service::listen(path, mode).map_err(Error::Io)?;
        let dir = p.dir.clone();
        let gate = Gate::new(policy);
        handles.push(std::thread::spawn(move || {
            for c in l.incoming().flatten() {
                let dir = dir.clone();
                match gate.enter() {
                    Some(permit) => {
                        std::thread::spawn(move || {
                            handle(&dir, policy, c);
                            drop(permit);
                        });
                    }
                    None => {
                        // told at once, without reading anything: a busy relay costs the caller one line
                        let _ = c.set_write_timeout(Some(std::time::Duration::from_secs(1)));
                        let mut out = c;
                        let _ = writeln!(out, "{}", json!({"ok": false, "error": "busy"}));
                    }
                }
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

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn the_relay_takes_one_round_at_a_time_and_a_bounded_number_a_minute() {
        let g = Gate::new(Policy::Relay);
        let first = g.enter().expect("the first round is taken");
        assert!(g.enter().is_none(), "a second round at once is refused");
        drop(first);
        let mut taken = 1;
        while let Some(p) = g.enter() {
            taken += 1;
            drop(p);
            assert!(taken <= RELAY_PER_MINUTE, "the limit never applied");
        }
        assert_eq!(taken, RELAY_PER_MINUTE, "a bounded number a minute");
    }

    #[test]
    fn the_agent_and_admin_sockets_are_not_gated() {
        for p in [Policy::Agent, Policy::Admin] {
            let g = Gate::new(p);
            let held: Vec<_> = (0..500).map(|_| g.enter().expect("not gated")).collect();
            assert_eq!(held.len(), 500);
        }
    }
}
