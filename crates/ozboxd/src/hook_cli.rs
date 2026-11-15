//! `ozboxd hook <engine> [json]` and `ozboxd hooks install|status`: the box-side half of agent events.
//!
//! The agent runs `ozboxd hook <engine>` from its own hook (see [`crate::agent_events`]). It reads the agent's JSON from
//! standard input (or from its one argument, for Codex), reports it to the daemon on its Unix socket, and for a permission
//! request waits for the person's answer and prints it in the shape the agent documents.
//!
//! A hook must never get in the agent's way: whatever goes wrong (no daemon, a bad payload), it prints nothing and exits 0,
//! so the agent's own permission flow applies. While no caller can answer a permission request (see
//! [`agent_events::PERMISSION_ANSWERS_AVAILABLE`]) a risky tool is handed back to the person with "ask" (an engine with no
//! "ask" is denied at once) and the event feed is told; once one can, a request
//! nobody answers is denied by the daemon after nine minutes.
//! Nothing here prints or logs the payload.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::agent_events::{self, Decision};

pub const DEFAULT_SOCKET: &str = "/run/ozboxd/ozboxd.sock";

/// One request to the daemon's socket. `Connection: close`, so the answer ends at end-of-file.
#[cfg(unix)]
pub fn http_unix(
    socket: &Path,
    method: &str,
    path: &str,
    body: &[u8],
) -> std::io::Result<(u16, Value)> {
    use std::os::unix::net::UnixStream;
    let mut s = UnixStream::connect(socket)?;
    s.set_read_timeout(Some(Duration::from_secs(10)))?;
    s.set_write_timeout(Some(Duration::from_secs(10)))?;
    let head = format!("{method} {path} HTTP/1.1\r\nHost: ozboxd\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    s.write_all(head.as_bytes())?;
    s.write_all(body)?;
    let mut raw = Vec::new();
    s.take(256 * 1024).read_to_end(&mut raw)?;
    let text = String::from_utf8_lossy(&raw);
    let status = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let body = text.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
    Ok((status, serde_json::from_str(body).unwrap_or(Value::Null)))
}

fn ask_list() -> Vec<String> {
    match std::env::var("OZBOX_HOOK_ASK") {
        Ok(v) if !v.trim().is_empty() => v.split(',').map(|s| s.trim().to_string()).collect(),
        _ => agent_events::DEFAULT_ASK
            .iter()
            .map(|s| s.to_string())
            .collect(),
    }
}

/// The terminal this hook runs in: tmux gives every process started in a pane its id in `TMUX_PANE`, and the agent's hook is
/// one of them. It is how the daemon tells two agents in one repository apart.
fn pane_from_env() -> String {
    std::env::var("TMUX_PANE").unwrap_or_default()
}

/// Run one hook. Returns what to print on standard output (empty for nothing).
#[cfg(unix)]
pub fn run_hook(socket: &Path, engine: &str, payload: &Value, cwd: &str, ask: &[String]) -> String {
    run_hook_with(
        socket,
        engine,
        payload,
        cwd,
        ask,
        agent_events::PERMISSION_ANSWERS_AVAILABLE,
    )
}

/// [`run_hook`] with whether a person can answer in Oz Box said outright (the tests exercise both).
#[cfg(unix)]
pub fn run_hook_with(
    socket: &Path,
    engine: &str,
    payload: &Value,
    cwd: &str,
    ask: &[String],
    answers_available: bool,
) -> String {
    let event = payload
        .get("hook_event_name")
        .and_then(Value::as_str)
        .unwrap_or("");
    if matches!(event, "SessionStart" | "SessionEnd") {
        // only the session record cares (`ozboxd session-hook`); the event feed has nothing to say about it
        return String::new();
    }
    let is_pre = matches!(event, "PreToolUse" | "BeforeTool");
    if is_pre {
        let tool = payload
            .get("tool_name")
            .and_then(Value::as_str)
            .unwrap_or("");
        let input = payload.get("tool_input").cloned().unwrap_or(Value::Null);
        if !agent_events::needs_ask(tool, &input, ask) {
            // not worth a person's attention: no opinion, so the agent's own rules apply
            return String::new();
        }
        if !answers_available {
            // Nobody can answer in Oz Box yet: do not wait to be denied. Tell the daemon's event feed that a risky tool was
            // tried (best effort, no polling, and as a plain "needs input" event so no approval is left pending that nobody
            // can answer), then give the question back to the person in the agent's own terminal. An engine with no "ask" is
            // denied at once, as it was before the stopgap, because "no opinion" would let it run on its own rules (G1 F7).
            let tool = payload
                .get("tool_name")
                .and_then(Value::as_str)
                .unwrap_or("");
            let note = json!({
                "hook_event_name": "Notification",
                "session_id": payload.get("session_id").cloned().unwrap_or(Value::Null),
                "cwd": payload.get("cwd").cloned().unwrap_or(Value::Null),
                "message": format!("{tool} is waiting for your decision in the agent's own terminal"),
            });
            let body =
                json!({ "engine": engine, "payload": note, "cwd": cwd, "pane": pane_from_env() })
                    .to_string();
            let _ = http_unix(socket, "POST", "/v1/agent-events", body.as_bytes());
            return match agent_events::permission_ask(
                engine,
                "Oz Box cannot ask you yet; answer here",
            ) {
                Some(v) => v.to_string(),
                None => agent_events::permission_answer(
                    engine,
                    Decision::Deny,
                    "Oz Box cannot ask you yet; approve this in the agent's own settings",
                )
                .to_string(),
            };
        }
    }
    let body = json!({ "engine": engine, "payload": payload, "cwd": cwd, "pane": pane_from_env() })
        .to_string();
    let Ok((status, v)) = http_unix(socket, "POST", "/v1/agent-events", body.as_bytes()) else {
        return String::new();
    };
    if status != 200 && status != 201 {
        return String::new();
    }
    let Some(id) = v["permission"].as_str().filter(|_| is_pre) else {
        return String::new();
    };
    let give_up = Instant::now() + Duration::from_millis(agent_events::PERMISSION_TTL_MS + 5_000);
    while Instant::now() < give_up {
        std::thread::sleep(Duration::from_secs(1));
        let Ok((200, p)) = http_unix(
            socket,
            "GET",
            &format!("/v1/agent-events/permission/{id}"),
            b"",
        ) else {
            continue;
        };
        match p["state"].as_str() {
            Some("allow") => {
                return agent_events::permission_answer(
                    engine,
                    Decision::Allow,
                    "Approved in Oz Box",
                )
                .to_string()
            }
            Some("deny") => {
                return agent_events::permission_answer(
                    engine,
                    Decision::Deny,
                    "Not approved in Oz Box",
                )
                .to_string()
            }
            _ => {}
        }
    }
    agent_events::permission_answer(engine, Decision::Deny, "Nobody answered in Oz Box in time")
        .to_string()
}

/// `ozboxd hook <engine> [json]`. Always exit status 0.
#[cfg(unix)]
pub fn main_hook(args: &[String]) -> i32 {
    let Some(engine) = args.first() else { return 0 };
    let payload: Value = match args.get(1) {
        Some(j) => serde_json::from_str(j).unwrap_or(Value::Null),
        None => {
            let mut s = String::new();
            let _ = std::io::stdin().take(256 * 1024).read_to_string(&mut s);
            serde_json::from_str(&s).unwrap_or(Value::Null)
        }
    };
    let socket = std::env::var_os("OZBOXD_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET));
    let cwd = std::env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    // the session record first, and silently: it is what lets the session come back after the box restarts
    crate::session_resume::note_from_hook(&ozbox_core::SystemRunner, engine, &payload, &cwd);
    let out = run_hook(&socket, engine, &payload, &cwd, &ask_list());
    if !out.is_empty() {
        println!("{out}");
    }
    0
}

/// `ozboxd session-hook <engine> [json]`: what the box installs at every boot (ADR 0049). It keeps the session record and does
/// nothing else: it prints nothing, never asks and never denies a tool, and never talks to the daemon, so a person's own
/// permission settings and a supervised run are exactly as they were. Always exit status 0.
#[cfg(unix)]
pub fn main_session_hook(args: &[String]) -> i32 {
    let Some(engine) = args.first() else { return 0 };
    let payload: Value = match args.get(1) {
        Some(j) => serde_json::from_str(j).unwrap_or(Value::Null),
        None => {
            let mut s = String::new();
            let _ = std::io::stdin().take(256 * 1024).read_to_string(&mut s);
            serde_json::from_str(&s).unwrap_or(Value::Null)
        }
    };
    let cwd = std::env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    crate::session_resume::note_from_hook(&ozbox_core::SystemRunner, engine, &payload, &cwd);
    0
}

/// What an install did for one engine.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Installed,
    AlreadyThere,
    /// The person already has their own setting, left alone.
    LeftAlone(&'static str),
    /// The engine is not set up in this home folder.
    NotUsed,
}

/// What a file looked like a moment ago: enough to tell that someone else wrote it since.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Stamp {
    ino: u64,
    size: u64,
    mtime_s: i64,
    mtime_ns: i64,
}

/// The stamp of what `path` points at (through a link); `None` when there is no such file.
fn stamp(path: &Path) -> std::io::Result<Option<Stamp>> {
    use std::os::unix::fs::MetadataExt;
    match std::fs::metadata(path) {
        Ok(m) => Ok(Some(Stamp {
            ino: m.ino(),
            size: m.len(),
            mtime_s: m.mtime(),
            mtime_ns: m.mtime_nsec(),
        })),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// The error a guarded write gives when the file changed under it: nothing was written.
fn changed_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::WouldBlock,
        "the file changed while it was being edited",
    )
}

/// A temporary file of ours (`.<name>.ozbox-tmp-<pid>-<n>`) that a killed write left beside the target. Only our own name pattern,
/// only regular files, only when older than an hour, so a write in progress is never touched.
fn clean_stale_tmp(target: &Path, name: &str) {
    let (Some(dir), prefix) = (target.parent(), format!(".{name}.ozbox-tmp-")) else {
        return;
    };
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let fname = e.file_name().to_string_lossy().into_owned();
        let Some(rest) = fname.strip_prefix(&prefix) else {
            continue;
        };
        let digits = |t: &str| !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit());
        let ours = rest
            .split_once('-')
            .is_some_and(|(p, n)| digits(p) && digits(n));
        if !ours {
            continue;
        }
        let old = e
            .metadata()
            .ok()
            .filter(|m| m.is_file())
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age >= std::time::Duration::from_secs(3600));
        if old {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

/// Write a settings file in place, safely: through a link (the target is what changes; a dotfiles link stays a link), with
/// the file's own mode (and owner and group, when this process may) kept (a new file is private, 0600: a settings file can hold
/// `env` values and a key helper), through a temporary file beside the target that is flushed and renamed over it, so a reader
/// never sees half of one.
fn write_atomic(path: &Path, text: &str) -> std::io::Result<()> {
    write_atomic_guarded(path, text, None)
}

/// [`write_atomic`], and when `expect` is given (what [`stamp`] said before the file was read), the file is stamped again just
/// before the rename and nothing is renamed if it changed: the write is refused with `WouldBlock` and the temporary file removed.
fn write_atomic_guarded(
    path: &Path,
    text: &str,
    expect: Option<Option<Stamp>>,
) -> std::io::Result<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let target = match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => std::fs::canonicalize(path)?,
        _ => path.to_path_buf(),
    };
    let old = std::fs::metadata(&target).ok();
    let mode = old
        .as_ref()
        .map(|m| m.permissions().mode() & 0o7777)
        .unwrap_or(0o600);
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    clean_stale_tmp(&target, &name);
    let tmp = target.with_file_name(format!(
        ".{name}.ozbox-tmp-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let result = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)?;
        // the umask may have narrowed it; the file's own mode is what is kept
        f.set_permissions(std::fs::Permissions::from_mode(mode))?;
        // owner and group too, when this process is allowed to (the same user in practice, so this changes nothing)
        if let Some(m) = &old {
            let _ = std::os::unix::fs::fchown(&f, Some(m.uid()), Some(m.gid()));
        }
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
        if let Some(before) = expect {
            if stamp(&target)? != before {
                return Err(changed_error());
            }
        }
        std::fs::rename(&tmp, &target)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// How many times the boot install re-reads a settings file that changed under it, and how long it waits between looks.
const SETTINGS_TRIES: usize = 3;
const SETTINGS_RETRY_WAIT: std::time::Duration = std::time::Duration::from_millis(100);

/// Add the record hooks to Claude Code's settings file with care for whoever else writes it (Claude Code itself, the person's
/// editor). The file is stamped before it is read and again just before the rename; if it changed, it is read again and the work
/// redone, a few times, and then left alone. A file that exists with nothing in it is never taken to be empty settings (a writer
/// that truncates first and writes after leaves exactly that for a moment): it is left alone. `between` runs after the read and
/// before the write; it is a hook for tests and is a no-op in production.
fn edit_claude_settings(path: &Path, binary: &str, between: &mut dyn FnMut()) -> Outcome {
    for attempt in 0..SETTINGS_TRIES {
        if attempt > 0 {
            std::thread::sleep(SETTINGS_RETRY_WAIT);
        }
        let Ok(before) = stamp(path) else {
            return Outcome::LeftAlone("the settings file could not be read, so it was left alone");
        };
        if before.is_some_and(|s| s.size == 0) {
            return Outcome::LeftAlone(
                "the settings file is empty right now (it may be being written), so it was left alone",
            );
        }
        // only "not there" is an empty file: one that is there and cannot be read is never replaced
        let existing = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && before.is_none() => String::new(),
            Err(_) => {
                return Outcome::LeftAlone(
                    "the settings file could not be read, so it was left alone",
                )
            }
        };
        match agent_events::merge_record_hooks_changed(&existing, binary) {
            Ok(None) => return Outcome::AlreadyThere,
            Err(why) => return Outcome::LeftAlone(why),
            Ok(Some(new)) => {
                between();
                match write_atomic_guarded(path, &new, Some(before)) {
                    Ok(()) => return Outcome::Installed,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(_) => return Outcome::LeftAlone("the settings file could not be written"),
                }
            }
        }
    }
    Outcome::LeftAlone(
        "the settings file kept changing while it was being edited, so it was left alone",
    )
}

/// Add the hooks to the settings of every coding agent the person has set up under `home`. Claude Code's file is made
/// when its folder exists; a settings file that cannot be read is left exactly as it is. This is the explicit
/// `ozboxd hooks install`: the full set, including the asks about risky commands (ADR 0021), and the record hooks too.
pub fn install(home: &Path, binary: &str) -> Vec<(&'static str, Outcome)> {
    install_with(home, binary)
}

/// What the box runs at every boot (ADR 0049): **only the session-record hooks**, for Claude Code. Nothing here asks about or
/// denies a command, so a box's agents behave as the person set them up; the asks stay with the explicit `ozboxd hooks
/// install`. Claude Code's folder is made when it is not there yet, so the very first session on a new box is recorded too
/// (Claude Code merges into the folder and file when it starts). Idempotent. Other engines are not touched at boot (resume
/// is not supported for them), and a settings file that cannot be read is left exactly as it is.
pub fn install_at_boot(home: &Path, binary: &str) -> Vec<(&'static str, Outcome)> {
    if crate::session_resume::resume_off(home) {
        return vec![(
            "claude-code",
            Outcome::LeftAlone("turned off: ~/.config/ozbox/session-resume.off exists"),
        )];
    }
    let dir = home.join(".claude");
    if !dir.exists() {
        let _ = std::fs::create_dir_all(&dir);
    }
    let outcome = if !dir.is_dir() {
        Outcome::NotUsed
    } else {
        edit_claude_settings(&dir.join("settings.json"), binary, &mut || {})
    };
    vec![("claude-code", outcome)]
}

/// The same document, whatever its formatting or key order.
fn same_json(a: &str, b: &str) -> bool {
    a.trim() == b.trim()
        || matches!(
            (serde_json::from_str::<Value>(a), serde_json::from_str::<Value>(b)),
            (Ok(x), Ok(y)) if x == y
        )
}

fn install_with(home: &Path, binary: &str) -> Vec<(&'static str, Outcome)> {
    let mut out = Vec::new();
    for (engine, dir, file) in [
        ("claude-code", ".claude", "settings.json"),
        ("gemini", ".gemini", "settings.json"),
    ] {
        let d = home.join(dir);
        if !d.is_dir() {
            out.push((engine, Outcome::NotUsed));
            continue;
        }
        let path = d.join(file);
        let existing = std::fs::read_to_string(&path).unwrap_or_default();
        out.push((
            engine,
            match agent_events::merge_hooks(&existing, binary, engine).and_then(|full| {
                if engine == "claude-code" {
                    agent_events::merge_record_hooks(&full, binary)
                } else {
                    Ok(full)
                }
            }) {
                Ok(new) if same_json(&new, &existing) => Outcome::AlreadyThere,
                Ok(new) => match write_atomic(&path, &new) {
                    Ok(()) => Outcome::Installed,
                    Err(_) => Outcome::LeftAlone("the settings file could not be written"),
                },
                Err(why) => Outcome::LeftAlone(why),
            },
        ));
    }
    let codex = home.join(".codex");
    out.push((
        "codex",
        if !codex.is_dir() {
            Outcome::NotUsed
        } else {
            let path = codex.join("config.toml");
            let existing = std::fs::read_to_string(&path).unwrap_or_default();
            let (new, added) = agent_events::merge_codex_notify(&existing, binary);
            if added {
                match write_atomic(&path, &new) {
                    Ok(()) => Outcome::Installed,
                    Err(_) => Outcome::LeftAlone("the config file could not be written"),
                }
            } else if existing.contains("hook\", \"codex\"") {
                Outcome::AlreadyThere
            } else {
                Outcome::LeftAlone("a notify program of your own is already set")
            }
        },
    ));
    out
}

pub fn outcome_word(o: &Outcome) -> String {
    match o {
        Outcome::Installed => "installed".into(),
        Outcome::AlreadyThere => "already installed".into(),
        Outcome::LeftAlone(why) => format!("left alone: {why}"),
        Outcome::NotUsed => "not set up on this box".into(),
    }
}

#[cfg(unix)]
pub fn main_hooks(args: &[String]) -> i32 {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        eprintln!("ozboxd: HOME is not set");
        return 1;
    };
    let bin = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "ozboxd".into());
    if args.first().map(String::as_str) != Some("install") {
        eprintln!("usage: ozboxd hooks install");
        return 2;
    }
    for (engine, o) in install(&home, &bin) {
        println!("{engine}: {}", outcome_word(&o));
    }
    0
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::sync::{Arc, Mutex};

    /// One whole request: the head, then as many body bytes as its Content-Length says. A client may send the head and the
    /// body in separate writes, and a single `read` on a loaded machine then returns the head alone, so the double would
    /// answer a request whose body it never saw.
    fn read_request(c: &mut std::os::unix::net::UnixStream) -> String {
        let _ = c.set_read_timeout(Some(Duration::from_secs(10)));
        let mut raw: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            if let Some(at) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&raw[..at]).to_ascii_lowercase();
                let want = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if raw.len() >= at + 4 + want {
                    break;
                }
            }
            match c.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => raw.extend_from_slice(&chunk[..n]),
            }
        }
        String::from_utf8_lossy(&raw).to_string()
    }

    /// A daemon double on a real socket that answers like the real routes.
    fn daemon(dir: &Path, log: Arc<Mutex<Vec<String>>>, decision: &'static str) -> PathBuf {
        let sock = dir.join("d.sock");
        let l = UnixListener::bind(&sock).unwrap();
        std::thread::spawn(move || {
            for c in l.incoming() {
                let Ok(mut c) = c else { return };
                let req = read_request(&mut c);
                log.lock()
                    .unwrap()
                    .push(req.lines().next().unwrap_or("").to_string());
                let body = if req.starts_with("POST /v1/agent-events") {
                    if req.contains("PreToolUse") {
                        r#"{"seq":1,"permission":"p1"}"#
                    } else {
                        r#"{"seq":1}"#
                    }
                    .to_string()
                } else {
                    format!(r#"{{"id":"p1","state":"{decision}"}}"#)
                };
                let _ = write!(
                    c,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
            }
        });
        sock
    }

    #[test]
    fn a_risky_command_waits_for_the_answer_and_prints_it_in_the_documented_shape() {
        let d = tempfile::tempdir().unwrap();
        let log = Arc::new(Mutex::new(Vec::new()));
        let sock = daemon(d.path(), log.clone(), "allow");
        let pre = json!({ "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": { "command": "git push" } });
        let out = run_hook_with(
            &sock,
            "claude-code",
            &pre,
            "/work/repos/web",
            &["git push".to_string()],
            true,
        );
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
        assert!(log
            .lock()
            .unwrap()
            .iter()
            .any(|l| l.contains("GET /v1/agent-events/permission/p1")));
    }

    /// G1 M3: while nobody can answer in Oz Box, a risky tool is handed back to the person at once. It is never approved, never
    /// waits nine minutes to be denied, and nothing is sent to the daemon.
    #[test]
    fn while_nobody_can_answer_a_risky_tool_asks_the_person_at_once() {
        // turning the answers on is a change to this test too: it has to come with the caller
        const { assert!(!agent_events::PERMISSION_ANSWERS_AVAILABLE) };
        let d = tempfile::tempdir().unwrap();
        let log = Arc::new(Mutex::new(Vec::new()));
        let sock = daemon(d.path(), log.clone(), "allow");
        let ask = vec!["git push".to_string()];
        let risky = json!({ "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": { "command": "git push" } });
        let t = Instant::now();
        let out = run_hook(&sock, "claude-code", &risky, "/w", &ask);
        assert!(t.elapsed() < Duration::from_millis(900), "no polling");
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(
            v["hookSpecificOutput"]["permissionDecision"], "ask",
            "{out}"
        );
        // the event feed is told, once and without polling, and as a plain notification: no permission is left pending
        {
            let l = log.lock().unwrap();
            assert_eq!(l.len(), 1, "{l:?}");
            assert!(
                l[0].contains("POST /v1/agent-events") && !l[0].contains("permission/"),
                "{l:?}"
            );
        }
        // an engine with no "ask" is denied at once (as before the stopgap), never left to run on its own rules
        let g = run_hook(&sock, "gemini", &risky, "/w", &ask);
        let gv: Value = serde_json::from_str(&g).unwrap();
        assert_eq!(gv["decision"], "deny", "{g}");
        // an ordinary command is still no opinion
        let calm = json!({ "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": { "command": "ls" } });
        assert_eq!(run_hook(&sock, "claude-code", &calm, "/w", &ask), "");
    }

    #[test]
    fn an_ordinary_command_and_a_stop_say_nothing_and_a_missing_daemon_never_blocks() {
        let d = tempfile::tempdir().unwrap();
        let log = Arc::new(Mutex::new(Vec::new()));
        let sock = daemon(d.path(), log.clone(), "allow");
        let ask = vec!["git push".to_string()];
        let calm = json!({ "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": { "command": "ls" } });
        assert_eq!(run_hook(&sock, "claude-code", &calm, "/w", &ask), "");
        assert!(
            log.lock().unwrap().is_empty(),
            "an ordinary command is not even reported"
        );
        let stop = json!({ "hook_event_name": "Stop" });
        assert_eq!(run_hook(&sock, "claude-code", &stop, "/w", &ask), "");
        assert_eq!(log.lock().unwrap().len(), 1);
        let risky = json!({ "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": { "command": "git push" } });
        assert_eq!(
            run_hook_with(
                &d.path().join("none.sock"),
                "claude-code",
                &risky,
                "/w",
                &ask,
                true
            ),
            "",
            "no daemon: the agent's own rules apply"
        );
    }

    #[test]
    fn install_merges_for_the_agents_that_are_set_up_and_leaves_the_rest() {
        let h = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(h.path().join(".claude")).unwrap();
        std::fs::create_dir_all(h.path().join(".codex")).unwrap();
        std::fs::write(
            h.path().join(".claude/settings.json"),
            r#"{"model":"opus"}"#,
        )
        .unwrap();
        std::fs::write(h.path().join(".codex/config.toml"), "notify = [\"mine\"]\n").unwrap();
        let first = install(h.path(), "/usr/local/bin/ozboxd");
        assert_eq!(first[0], ("claude-code", Outcome::Installed));
        assert_eq!(first[1], ("gemini", Outcome::NotUsed));
        assert!(matches!(first[2].1, Outcome::LeftAlone(_)));
        let text = std::fs::read_to_string(h.path().join(".claude/settings.json")).unwrap();
        assert!(text.contains("opus") && text.contains("ozboxd hook"));
        assert_eq!(
            std::fs::read_to_string(h.path().join(".codex/config.toml")).unwrap(),
            "notify = [\"mine\"]\n"
        );
        assert_eq!(
            install(h.path(), "/usr/local/bin/ozboxd")[0].1,
            Outcome::AlreadyThere
        );
        // an unreadable settings file is left exactly as it is
        std::fs::write(h.path().join(".claude/settings.json"), "{broken").unwrap();
        assert!(matches!(
            install(h.path(), "/b")[0].1,
            Outcome::LeftAlone(_)
        ));
        assert_eq!(
            std::fs::read_to_string(h.path().join(".claude/settings.json")).unwrap(),
            "{broken"
        );
    }

    #[test]
    fn the_boot_install_adds_only_the_record_hooks_never_an_ask_and_leaves_other_engines_alone() {
        let h = tempfile::tempdir().unwrap();
        std::fs::create_dir(h.path().join(".gemini")).unwrap();
        std::fs::create_dir(h.path().join(".codex")).unwrap();
        // a brand-new box: nothing set up yet, and the first session must still be recorded
        let first = install_at_boot(h.path(), "/usr/local/bin/ozboxd");
        assert_eq!(first, vec![("claude-code", Outcome::Installed)]);
        let path = h.path().join(".claude/settings.json");
        let text = std::fs::read_to_string(&path).unwrap();
        let v: Value = serde_json::from_str(&text).unwrap();
        let events: Vec<&String> = v["hooks"].as_object().unwrap().keys().collect();
        assert_eq!(events.len(), 4, "{events:?}");
        for ev in ["SessionStart", "SessionEnd", "UserPromptSubmit", "Stop"] {
            assert!(v["hooks"][ev].is_array(), "{ev}");
        }
        // no PreToolUse (the git push / sudo / rm -rf asks), no Notification, no feed hook
        assert!(
            !text.contains("PreToolUse") && !text.contains("\"hook\""),
            "{text}"
        );
        assert!(!text.contains(agent_events::MARKER));
        // Gemini (whose hook can only deny) and Codex are not touched at boot
        assert!(!h.path().join(".gemini/settings.json").exists());
        assert!(!h.path().join(".codex/config.toml").exists());
        // every later boot changes nothing, byte for byte
        assert_eq!(
            install_at_boot(h.path(), "/usr/local/bin/ozboxd")[0].1,
            Outcome::AlreadyThere
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
        // an upgrade from an install made before SessionEnd existed gains it, and keeps the person's own hooks
        let mut v: Value = serde_json::from_str(&text).unwrap();
        v["hooks"].as_object_mut().unwrap().remove("SessionEnd");
        v["hooks"]["Stop"]
            .as_array_mut()
            .unwrap()
            .push(json!({"hooks":[{"type":"command","command":"echo mine"}]}));
        std::fs::write(&path, v.to_string()).unwrap();
        assert_eq!(
            install_at_boot(h.path(), "/usr/local/bin/ozboxd")[0].1,
            Outcome::Installed
        );
        let after = std::fs::read_to_string(&path).unwrap();
        assert!(after.contains("SessionEnd") && after.contains("echo mine"));
        // a settings file that cannot be read is still left exactly as it is
        std::fs::write(&path, "{broken").unwrap();
        assert!(matches!(
            install_at_boot(h.path(), "/b")[0].1,
            Outcome::LeftAlone(_)
        ));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{broken");
    }

    #[test]
    fn the_explicit_install_still_adds_the_asks_and_the_record_hooks_and_the_boot_install_does_not_undo_it(
    ) {
        let h = tempfile::tempdir().unwrap();
        std::fs::create_dir(h.path().join(".claude")).unwrap();
        assert_eq!(install(h.path(), "/b")[0].1, Outcome::Installed);
        let path = h.path().join(".claude/settings.json");
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("PreToolUse") && text.contains("SessionEnd"));
        assert_eq!(install(h.path(), "/b")[0].1, Outcome::AlreadyThere);
        assert_eq!(install_at_boot(h.path(), "/b")[0].1, Outcome::AlreadyThere);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
    }

    #[test]
    fn a_session_start_or_end_is_for_the_record_only_and_never_reaches_the_daemon() {
        let d = tempfile::tempdir().unwrap();
        let log = Arc::new(Mutex::new(Vec::new()));
        let sock = daemon(d.path(), log.clone(), "allow");
        for ev in ["SessionStart", "SessionEnd"] {
            let p = json!({ "hook_event_name": ev, "session_id": "s1", "reason": "other" });
            assert_eq!(run_hook(&sock, "claude-code", &p, "/w", &[]), "");
        }
        assert!(log.lock().unwrap().is_empty());
    }

    // ---- the settings file is written with care (S17) ----

    fn mode_of(p: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).unwrap().permissions().mode() & 0o7777
    }

    #[test]
    fn a_settings_file_that_is_a_link_is_edited_through_and_stays_a_link() {
        let h = tempfile::tempdir().unwrap();
        std::fs::create_dir(h.path().join(".claude")).unwrap();
        let dots = h.path().join("dotfiles");
        std::fs::create_dir(&dots).unwrap();
        let real = dots.join("claude-settings.json");
        std::fs::write(&real, r#"{"theme":"dark"}"#).unwrap();
        let link = h.path().join(".claude/settings.json");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert_eq!(install_at_boot(h.path(), "/b")[0].1, Outcome::Installed);
        assert!(std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read_link(&link).unwrap(), real);
        let text = std::fs::read_to_string(&real).unwrap();
        assert!(text.contains("theme") && text.contains("SessionEnd"));
        // no temporary file is left beside either
        for d in [&dots, &h.path().join(".claude")] {
            let names: Vec<String> = std::fs::read_dir(d)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            assert!(!names.iter().any(|n| n.contains("ozbox-tmp")), "{names:?}");
        }
        assert_eq!(install_at_boot(h.path(), "/b")[0].1, Outcome::AlreadyThere);
        // a link that points nowhere is left alone, not replaced by a file
        let h2 = tempfile::tempdir().unwrap();
        std::fs::create_dir(h2.path().join(".claude")).unwrap();
        let l2 = h2.path().join(".claude/settings.json");
        std::os::unix::fs::symlink(h2.path().join("missing.json"), &l2).unwrap();
        assert!(matches!(
            install_at_boot(h2.path(), "/b")[0].1,
            Outcome::LeftAlone(_)
        ));
        assert!(std::fs::symlink_metadata(&l2)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn the_files_own_mode_is_kept_and_a_new_one_is_private() {
        for mode in [0o600, 0o640, 0o644] {
            let h = tempfile::tempdir().unwrap();
            std::fs::create_dir(h.path().join(".claude")).unwrap();
            let path = h.path().join(".claude/settings.json");
            std::fs::write(&path, r#"{"env":{"X":"y"}}"#).unwrap();
            std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(mode))
                .unwrap();
            assert_eq!(install_at_boot(h.path(), "/b")[0].1, Outcome::Installed);
            assert_eq!(mode_of(&path), mode, "{mode:o}");
        }
        let h = tempfile::tempdir().unwrap();
        assert_eq!(install_at_boot(h.path(), "/b")[0].1, Outcome::Installed);
        assert_eq!(mode_of(&h.path().join(".claude/settings.json")), 0o600);
    }

    #[test]
    fn the_order_of_the_keys_is_kept_and_a_second_run_changes_nothing_not_even_the_formatting() {
        let h = tempfile::tempdir().unwrap();
        std::fs::create_dir(h.path().join(".claude")).unwrap();
        let path = h.path().join(".claude/settings.json");
        std::fs::write(
            &path,
            r#"{"zeta":1,"env":{"b":"1","a":"2"},"alpha":2,"hooks":{"Stop":[{"hooks":[{"type":"command","command":"echo mine"}]}]},"model":"m"}"#,
        )
        .unwrap();
        assert_eq!(install_at_boot(h.path(), "/b")[0].1, Outcome::Installed);
        let text = std::fs::read_to_string(&path).unwrap();
        let at = |k: &str| text.find(&format!("\"{k}\"")).unwrap();
        assert!(
            at("zeta") < at("env")
                && at("env") < at("alpha")
                && at("alpha") < at("hooks")
                && at("hooks") < at("model"),
            "{text}"
        );
        assert!(
            text.find("\"b\"").unwrap() < text.find("\"a\"").unwrap(),
            "nested order too: {text}"
        );
        assert!(text.contains("echo mine"));
        assert_eq!(install_at_boot(h.path(), "/b")[0].1, Outcome::AlreadyThere);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
        // Claude Code rewrote the file its own way (compact, and without the fields it does not know): still ours, never written again
        let v: Value = serde_json::from_str(&text).unwrap();
        let compact = serde_json::to_string(&v).unwrap();
        std::fs::write(&path, &compact).unwrap();
        assert_eq!(install_at_boot(h.path(), "/b")[0].1, Outcome::AlreadyThere);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), compact);
    }

    #[test]
    fn a_settings_file_that_is_broken_or_unreadable_is_never_overwritten() {
        let h = tempfile::tempdir().unwrap();
        std::fs::create_dir(h.path().join(".claude")).unwrap();
        let path = h.path().join(".claude/settings.json");
        for bad in [
            &b"{broken"[..],
            &b"[1,2]"[..],
            &[0xff, 0xfe, 0x00][..],
            &b""[..],
        ] {
            std::fs::write(&path, bad).unwrap();
            let out = outcome_word(&install_at_boot(h.path(), "/b")[0].1);
            if bad.is_empty() {
                // S22: an existing empty file is never taken for no settings (a writer may be between truncate and write)
                assert!(out.contains("empty"), "{out}");
                assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
                continue;
            }
            assert!(out.starts_with("left alone"), "{bad:?}: {out}");
            assert_eq!(std::fs::read(&path).unwrap(), bad);
        }
    }

    #[test]
    fn a_settings_file_that_changes_during_the_edit_is_read_again_and_never_overwritten() {
        let h = tempfile::tempdir().unwrap();
        let dir = h.path().join(".claude");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("settings.json");
        std::fs::write(&path, "{\"model\": \"opus\"}").unwrap();
        // someone else writes once between our read and our rename: we redo the work on what they wrote
        let mut n = 0;
        let out = edit_claude_settings(&path, "/b", &mut || {
            n += 1;
            if n == 1 {
                std::fs::write(&path, "{\"model\": \"opus\", \"theme\": \"dark\"}").unwrap();
            }
        });
        assert_eq!(out, Outcome::Installed);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.contains("\"theme\"") && text.contains("session-hook"),
            "{text}"
        );
        assert_eq!(n, 2);
        // someone else writes every time: bounded, and then left alone with their last write intact
        let mut k = 0;
        std::fs::write(&path, "{\"a\": 0}").unwrap();
        let out = edit_claude_settings(&path, "/b", &mut || {
            k += 1;
            std::fs::write(&path, format!("{{\"a\": {k}{}}}", " ".repeat(k))).unwrap();
        });
        assert!(
            matches!(out, Outcome::LeftAlone(w) if w.contains("kept changing")),
            "{out:?}"
        );
        assert_eq!(k, SETTINGS_TRIES);
        assert!(!std::fs::read_to_string(&path)
            .unwrap()
            .contains("session-hook"));
        // no temporary file is left behind
        let strays: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains("ozbox-tmp"))
            .collect();
        assert!(strays.is_empty(), "{strays:?}");
    }

    #[test]
    fn an_existing_empty_settings_file_is_left_alone_never_taken_for_no_settings() {
        let h = tempfile::tempdir().unwrap();
        let dir = h.path().join(".claude");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("settings.json");
        std::fs::write(&path, "").unwrap();
        let out = install_at_boot(h.path(), "/b");
        assert!(
            matches!(out[0].1, Outcome::LeftAlone(w) if w.contains("empty")),
            "{:?}",
            out[0].1
        );
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
        // a file that is not there at all is still made
        std::fs::remove_file(&path).unwrap();
        assert_eq!(install_at_boot(h.path(), "/b")[0].1, Outcome::Installed);
    }

    #[test]
    fn the_guarded_write_refuses_when_the_stamp_no_longer_matches() {
        let h = tempfile::tempdir().unwrap();
        let p = h.path().join("s.json");
        std::fs::write(&p, "{}").unwrap();
        let before = stamp(&p).unwrap();
        std::fs::write(&p, "{\"x\":1}").unwrap();
        let e = write_atomic_guarded(&p, "{\"y\":2}", Some(before)).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::WouldBlock);
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "{\"x\":1}");
        // a file that appeared after we saw none is also a change
        let q = h.path().join("new.json");
        let none = stamp(&q).unwrap();
        std::fs::write(&q, "{}").unwrap();
        assert!(write_atomic_guarded(&q, "{\"y\":2}", Some(none)).is_err());
        // and an unchanged one goes through
        let ok = stamp(&p).unwrap();
        write_atomic_guarded(&p, "{\"y\":2}", Some(ok)).unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "{\"y\":2}");
    }

    #[test]
    fn stale_temporary_files_of_ours_are_removed_and_nothing_else_is() {
        let h = tempfile::tempdir().unwrap();
        let p = h.path().join("settings.json");
        std::fs::write(&p, "{}").unwrap();
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(7200);
        let set_old = |f: &Path| {
            std::fs::File::options()
                .write(true)
                .open(f)
                .unwrap()
                .set_modified(old)
                .unwrap();
        };
        let mk = |name: &str, aged: bool| {
            let f = h.path().join(name);
            std::fs::write(&f, "x").unwrap();
            if aged {
                set_old(&f);
            }
            f
        };
        let stale = mk(".settings.json.ozbox-tmp-123-4", true);
        let fresh = mk(".settings.json.ozbox-tmp-124-0", false);
        let other_name = mk(".settings.json.ozbox-tmp-abc-1", true);
        let theirs = mk(".settings.json.bak", true);
        let other_file = mk(".other.json.ozbox-tmp-1-1", true);
        write_atomic(&p, "{\"a\":1}").unwrap();
        assert!(!stale.exists());
        assert!(fresh.exists() && other_name.exists() && theirs.exists() && other_file.exists());
    }

    #[test]
    fn owner_and_mode_are_kept_and_a_duplicate_hooks_key_leaves_the_file_alone() {
        use std::os::unix::fs::MetadataExt;
        let h = tempfile::tempdir().unwrap();
        let dir = h.path().join(".claude");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("settings.json");
        std::fs::write(&path, "{\"model\":\"x\"}").unwrap();
        let (u, g) = {
            let m = std::fs::metadata(&path).unwrap();
            (m.uid(), m.gid())
        };
        assert_eq!(install_at_boot(h.path(), "/b")[0].1, Outcome::Installed);
        let m = std::fs::metadata(&path).unwrap();
        assert_eq!((m.uid(), m.gid()), (u, g));
        // two "hooks" keys: a JSON reader keeps the last one, our editor would have edited the first: untouched
        let dup = "{\"hooks\":{},\"model\":\"x\",\"hooks\":{\"Stop\":[]}}";
        std::fs::write(&path, dup).unwrap();
        let out = install_at_boot(h.path(), "/b");
        assert!(
            matches!(out[0].1, Outcome::LeftAlone(w) if w.contains("twice")),
            "{:?}",
            out[0].1
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), dup);
    }

    #[test]
    fn the_off_switch_stops_the_boot_install_and_the_explicit_install_still_works() {
        let h = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(h.path().join(".config/ozbox")).unwrap();
        std::fs::write(crate::session_resume::off_switch(h.path()), "").unwrap();
        assert!(matches!(
            install_at_boot(h.path(), "/b")[0].1,
            Outcome::LeftAlone(_)
        ));
        assert!(!h.path().join(".claude").exists(), "nothing was made");
        std::fs::create_dir(h.path().join(".claude")).unwrap();
        assert_eq!(install(h.path(), "/b")[0].1, Outcome::Installed);
    }
}
