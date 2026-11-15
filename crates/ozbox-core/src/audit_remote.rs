//! The client of a box's audit service (ADR 0028).
//!
//! On a box the audit chain is written by one process the box user cannot become: the secrets service, which owns the chain
//! file and keeps the seal key in its secret store. Everything else (the dashboard, the command line, the tool host) sends
//! its events over a socket and gets the sealed entries back; it can read the chain and ask for it to be checked, and it
//! can neither rewrite a line nor make a seal.
//!
//! The client is found, never configured per call: if one of the well-known sockets exists and can be reached, appending,
//! sealing and checking go through it. A computer that is not a box (a laptop, a test) and has no such socket keeps writing
//! its own file, as before. `OZBOX_AUDIT_SOCKET=<path>` names a socket, and `OZBOX_AUDIT_DIR` moves the directory the chain
//! is read from (tests). `OZBOX_AUDIT_SOCKET=off` forces the file, **except on a box**.
//!
//! Failing closed is deliberate: when the socket exists but the service does not answer, an append fails, and the task
//! store refuses to save a change it cannot record (ADR 0022, item 7). A restart of the service therefore pauses saves for a
//! moment rather than letting a change go unrecorded. **On a box** (it has the secrets service's run directory or its
//! settings file) the same holds when no socket exists at all: a service that has not started yet, or failed to, leaves the
//! chain's writers failing, never falling back to a file the box user could rewrite.

use std::io::{self, BufRead, Read, Write};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{json, Value};

use crate::audit::{AuditEntry, Checkpoint, NewEvent, VerifyReport};

/// Names a socket, or `off`.
pub const SOCKET_ENV: &str = "OZBOX_AUDIT_SOCKET";
/// Where the chains are read from.
pub const DIR_ENV: &str = "OZBOX_AUDIT_DIR";
/// On the persistent disk, so a system-disk replacement (an upgrade) keeps the chain.
pub const DEFAULT_DIR: &str = "/work/ozbox-audit";
/// Tried in order: the dashboard's own socket, then the box user's.
pub const DEFAULT_SOCKETS: &[&str] = &[
    "/run/ozbox-secrets/supervisor/supervisor.sock",
    "/run/ozbox-secrets/box/box.sock",
];
/// A request line is bounded by the smallest socket's limit (64 KB), so a backlog goes in pieces.
const CHUNK: usize = 40;
const MAX_ANSWER: u64 = 4 << 20;

#[derive(Debug, Clone)]
pub struct Remote {
    socket: PathBuf,
    chain: String,
    dir: PathBuf,
    /// Where this store's chain was written before a service took it over; sent so the service can take it in.
    legacy: PathBuf,
}

/// The chain's name on the service: the store's file stem, reduced to lowercase letters, digits and dashes.
pub fn chain_name(stem: &str) -> String {
    let s: String = stem
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .take(32)
        .collect();
    let s = s.trim_matches('-').to_string();
    if s.is_empty() {
        "tasks".into()
    } else {
        s
    }
}

fn is_socket(p: &Path) -> bool {
    std::fs::metadata(p).is_ok_and(|m| m.file_type().is_socket())
}

impl Remote {
    /// The service for the chain named `stem`, if this computer has one. `legacy` is where the same chain lives as a file
    /// beside the store.
    pub fn discover(stem: &str, legacy: &Path) -> Option<Remote> {
        Self::discover_on(stem, legacy, on_a_box())
    }

    /// [`Remote::discover`], told whether this computer is a box. On a box there is no way to the file: no socket means a
    /// client whose every append fails.
    pub fn discover_on(stem: &str, legacy: &Path, on_box: bool) -> Option<Remote> {
        let named = std::env::var(SOCKET_ENV).ok().filter(|v| !v.is_empty());
        let socket = match named.as_deref() {
            Some("off") if !on_box => return None,
            Some(v) if v != "off" => PathBuf::from(v),
            _ => match DEFAULT_SOCKETS
                .iter()
                .map(PathBuf::from)
                .find(|p| is_socket(p))
            {
                Some(p) => p,
                // the box socket, which every writer may use: the append fails until the service is there
                None if on_box => PathBuf::from(DEFAULT_SOCKETS[DEFAULT_SOCKETS.len() - 1]),
                None => return None,
            },
        };
        if !on_box && !is_socket(&socket) {
            return None;
        }
        let dir = std::env::var_os(DIR_ENV)
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_DIR));
        Some(Remote {
            socket,
            chain: chain_name(stem),
            dir,
            legacy: legacy.to_path_buf(),
        })
    }

    /// A client for a named socket and directory, without looking at the environment (tests, and anything that is told
    /// exactly where the service is).
    pub fn with_socket(socket: PathBuf, chain: &str, dir: PathBuf, legacy: PathBuf) -> Remote {
        Remote {
            socket,
            chain: chain_name(chain),
            dir,
            legacy,
        }
    }

    /// Where the service keeps this chain: readable by everyone on the box, writable by the service alone.
    pub fn chain_path(&self) -> PathBuf {
        self.dir.join(format!("{}.audit.jsonl", self.chain))
    }

    fn call(&self, mut req: Value) -> io::Result<Value> {
        req["chain"] = json!(self.chain);
        req["legacy"] = json!(self.legacy.to_string_lossy());
        let mut s = UnixStream::connect(&self.socket).map_err(|_| {
            io::Error::other("the audit service could not be reached, so nothing was recorded")
        })?;
        s.set_read_timeout(Some(Duration::from_secs(20)))?;
        s.set_write_timeout(Some(Duration::from_secs(20)))?;
        let mut line = serde_json::to_string(&req).map_err(io::Error::other)?;
        line.push('\n');
        s.write_all(line.as_bytes())?;
        let mut answer = String::new();
        io::BufReader::new((&s).take(MAX_ANSWER)).read_line(&mut answer)?;
        let v: Value = serde_json::from_str(answer.trim_end())
            .map_err(|_| io::Error::other("the audit service answered badly"))?;
        if v["ok"].as_bool() == Some(true) {
            Ok(v["result"].clone())
        } else {
            Err(io::Error::other(
                v["error"]
                    .as_str()
                    .unwrap_or("the audit service refused the request")
                    .to_string(),
            ))
        }
    }

    pub fn append_many(&self, events: Vec<NewEvent>) -> io::Result<Vec<AuditEntry>> {
        let mut out = Vec::new();
        for chunk in events.chunks(CHUNK) {
            let v = self.call(json!({"op": "audit_append", "events": chunk}))?;
            let got: Vec<AuditEntry> = serde_json::from_value(v["entries"].clone())
                .map_err(|_| io::Error::other("the audit service answered badly"))?;
            out.extend(got);
        }
        Ok(out)
    }

    pub fn last_src(&self) -> io::Result<Option<(String, u64)>> {
        let v = self.call(json!({"op": "audit_last_src"}))?;
        Ok(serde_json::from_value(v["src"].clone()).unwrap_or(None))
    }

    pub fn seal(&self) -> io::Result<Option<Checkpoint>> {
        let v = self.call(json!({"op": "audit_seal"}))?;
        Ok(serde_json::from_value(v["checkpoint"].clone()).unwrap_or(None))
    }

    pub fn verify(&self) -> io::Result<VerifyReport> {
        let v = self.call(json!({"op": "audit_verify"}))?;
        serde_json::from_value(v["report"].clone())
            .map_err(|_| io::Error::other("the audit service answered badly"))
    }
}

/// What tells a box from another computer: the secrets service's run directory, or its settings file, both made by root at
/// first boot.
pub const BOX_MARKERS: &[&str] = &["/run/ozbox-secrets", "/etc/ozbox/secrets.env"];

pub fn on_a_box() -> bool {
    BOX_MARKERS.iter().any(|p| Path::new(p).exists())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// The finding this closes: on a box whose secrets service had not started, the chain's writers quietly went back to a
    /// file of their own, which the box user can rewrite.
    #[test]
    fn on_a_box_with_no_socket_an_append_fails_and_no_file_is_written() {
        if std::env::var(SOCKET_ENV).is_ok()
            || DEFAULT_SOCKETS.iter().any(|p| is_socket(Path::new(p)))
        {
            return;
        }
        let d = tempfile::tempdir().unwrap();
        let r = Remote::discover_on("tasks", &d.path().join("tasks.audit.jsonl"), true).unwrap();
        let e = r
            .append_many(vec![NewEvent {
                ts_ms: 1,
                actor: "x".into(),
                action: "run.queued".into(),
                subject: None,
                detail: String::new(),
                src: None,
            }])
            .unwrap_err();
        assert!(e.to_string().contains("could not be reached"), "{e}");
        assert!(!d.path().join("tasks.audit.jsonl").exists());
        // off a box, the same computer writes its own file
        assert!(Remote::discover_on("tasks", Path::new("/tmp/x"), false).is_none());
    }

    #[test]
    fn a_chain_name_is_plain() {
        assert_eq!(chain_name("tasks"), "tasks");
        assert_eq!(chain_name("My Tasks_v2"), "my-tasks-v2");
        assert_eq!(chain_name("../.."), "tasks");
        assert_eq!(chain_name(&"a".repeat(80)).len(), 32);
    }

    #[test]
    fn a_computer_with_no_socket_writes_its_own_file() {
        // where tests run, none of the well-known sockets exists
        if DEFAULT_SOCKETS.iter().all(|p| !is_socket(Path::new(p)))
            && std::env::var(SOCKET_ENV).is_err()
        {
            assert!(Remote::discover_on("tasks", Path::new("/tmp/x"), false).is_none());
        }
    }
}
