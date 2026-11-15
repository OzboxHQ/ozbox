//! The browser terminal: a shell on a pseudo-terminal, reached over the daemon's Unix socket.
//!
//! The daemon keeps its "no upgrades" HTTP reader; this endpoint is the one deliberate exception. `GET /v1/terminal`
//! answers `101 Switching Protocols` (`Upgrade: ozbox-pty/1`) and the connection then carries frames:
//! `[type: u8][length: u32 big-endian][payload]`, at most [`MAX_FRAME`] bytes of payload.
//!
//! | type | direction | payload |
//! |------|-----------|---------|
//! | 1 data | both | raw terminal bytes |
//! | 2 resize | to the box | columns u16, rows u16 (big-endian) |
//! | 3 close | to the box | none: detach (a tmux session keeps running) |
//! | 4 exit | from the box | exit status i32 (big-endian), then the connection ends |
//!
//! By default a session attaches to one shared tmux session (`ozbox`), so it survives a dropped connection and is the
//! same shell an SSH or editor terminal shows. Without tmux it is the box user's login shell.
//!
//! The audit trail records that a session started and ended, how long, and how many bytes moved each way. It never
//! records keystrokes or output. The shell starts with a clean environment: nothing the daemon was configured with
//! (backup passwords, tokens) is inherited.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use serde::Serialize;

use crate::config::TerminalSection;
use crate::http::{self, Head, Response};

pub const MAX_FRAME: usize = 64 * 1024;
pub const T_DATA: u8 = 1;
pub const T_RESIZE: u8 = 2;
pub const T_CLOSE: u8 = 3;
pub const T_EXIT: u8 = 4;
const MIN_COLS: u16 = 10;
const MAX_COLS: u16 = 500;
const MIN_ROWS: u16 = 3;
const MAX_ROWS: u16 = 200;
const MAX_AUDIT_BYTES: u64 = 512 * 1024;
const KEEP_AUDIT_LINES: usize = 500;

pub fn write_frame<W: Write>(w: &mut W, ty: u8, payload: &[u8]) -> std::io::Result<()> {
    if payload.len() > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "frame too large",
        ));
    }
    let mut head = [0u8; 5];
    head[0] = ty;
    head[1..].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    w.write_all(&head)?;
    w.write_all(payload)?;
    w.flush()
}

/// The next frame, or `None` at a clean end of stream.
pub fn read_frame<R: Read>(r: &mut R) -> std::io::Result<Option<(u8, Vec<u8>)>> {
    let mut head = [0u8; 5];
    match r.read_exact(&mut head) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes([head[1], head[2], head[3], head[4]]) as usize;
    if len > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload)?;
    Ok(Some((head[0], payload)))
}

pub fn resize_payload(cols: u16, rows: u16) -> [u8; 4] {
    let c = cols.to_be_bytes();
    let r = rows.to_be_bytes();
    [c[0], c[1], r[0], r[1]]
}

fn clamp_size(cols: u16, rows: u16) -> PtySize {
    PtySize {
        rows: rows.clamp(MIN_ROWS, MAX_ROWS),
        cols: cols.clamp(MIN_COLS, MAX_COLS),
        pixel_width: 0,
        pixel_height: 0,
    }
}

/// A tmux session name is plain: letters, digits, `_` and `-`.
pub fn valid_session_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// What to run, as an argv array (never a shell string).
pub fn plan_command(cfg: &TerminalSection, tmux: Option<&Path>, shell: &str) -> Vec<String> {
    if !cfg.command.is_empty() {
        return cfg.command.clone();
    }
    match tmux {
        Some(t) if cfg.tmux && valid_session_name(&cfg.tmux_session) => vec![
            t.to_string_lossy().into_owned(),
            "start-server".into(),
            ";".into(),
            "set-option".into(),
            "-g".into(),
            "history-limit".into(),
            cfg.history_lines.clamp(100, 200_000).to_string(),
            ";".into(),
            "set-option".into(),
            "-g".into(),
            "default-shell".into(),
            shell.to_string(),
            ";".into(),
            "new-session".into(),
            "-A".into(),
            "-s".into(),
            cfg.tmux_session.clone(),
        ],
        _ => vec![shell.to_string(), "-l".into()],
    }
}

/// Attach to one existing tmux session of the box user's, by name (the Code panel's Open): an argv array, the name exact
/// (`=name`, never a prefix). `None` when there is no tmux, tmux is off, the shell is overridden or the name is not plain.
pub fn plan_attach(cfg: &TerminalSection, tmux: Option<&Path>, name: &str) -> Option<Vec<String>> {
    if !cfg.command.is_empty() || !cfg.tmux || !ozbox_core::procs::valid_session_name(name) {
        return None;
    }
    Some(vec![
        tmux?.to_string_lossy().into_owned(),
        "attach-session".into(),
        "-t".into(),
        format!("={name}"),
    ])
}

/// The command a terminal runs: the plan, behind a one-line wrapper that takes the session's own OOM score up. Pure.
pub fn terminal_argv(plan: &[String]) -> Vec<String> {
    let raise = ozbox_core::memory_plan::raise_score_snippet(
        ozbox_core::memory_plan::TERMINAL_OOM_SCORE_ADJ,
    );
    let mut v = vec![
        "/bin/sh".to_string(),
        "-c".into(),
        format!("{raise}; exec \"$@\""),
        "ozbox-terminal".into(),
    ];
    v.extend(plan.iter().cloned());
    v
}

fn find_in_path(name: &str, path: &str) -> Option<PathBuf> {
    std::env::split_paths(path)
        .map(|d| d.join(name))
        .find(|p| p.is_file())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub ts_ms: u64,
    /// `terminal.start` or `terminal.end`.
    pub event: &'static str,
    pub session: String,
    pub cols: u16,
    pub rows: u16,
    pub tmux: bool,
    /// Set on `terminal.end`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_s: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_in: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_out: Option<u64>,
    /// `client_closed`, `shell_exited` or `idle_timeout`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
}

/// An append-only JSON-lines record of sessions. Counts and ids only.
pub struct AuditLog {
    path: Option<PathBuf>,
    lock: Mutex<()>,
}

impl AuditLog {
    pub fn new(path: Option<PathBuf>) -> Self {
        Self {
            path,
            lock: Mutex::new(()),
        }
    }

    pub fn record(&self, ev: &AuditEvent) {
        let Some(p) = &self.path else { return };
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let line = serde_json::to_string(ev).unwrap_or_default();
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
        {
            let _ = writeln!(f, "{line}");
        }
        if std::fs::metadata(p).map(|m| m.len()).unwrap_or(0) > MAX_AUDIT_BYTES {
            let lines = self.read_lines(KEEP_AUDIT_LINES);
            let _ = std::fs::write(p, lines.join("\n") + "\n");
        }
    }

    fn read_lines(&self, n: usize) -> Vec<String> {
        let Some(p) = &self.path else {
            return Vec::new();
        };
        let text = std::fs::read_to_string(p).unwrap_or_default();
        let all: Vec<&str> = text.lines().filter(|l| !l.is_empty()).collect();
        all[all.len().saturating_sub(n)..]
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    /// The newest `n` events, oldest first.
    pub fn recent(&self, n: usize) -> Vec<serde_json::Value> {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        self.read_lines(n)
            .iter()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }
}

pub struct TerminalService {
    cfg: TerminalSection,
    cwd: PathBuf,
    env: Vec<(String, String)>,
    path_env: String,
    active: AtomicUsize,
    audit: AuditLog,
}

fn random_id() -> String {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut b = [0u8; 8];
    if SystemRandom::new().fill(&mut b).is_err() {
        b = now_ms().to_be_bytes();
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl TerminalService {
    /// `cwd` is where a new shell starts (usually the work disk).
    pub fn new(cfg: TerminalSection, cwd: PathBuf, audit_path: Option<PathBuf>) -> Self {
        let get = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        let path_env =
            get("PATH").unwrap_or_else(|| "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin".into());
        // A clean environment: only what a login shell needs. Never the daemon's own.
        let mut env = vec![
            ("TERM".to_string(), "xterm-256color".to_string()),
            ("COLORTERM".to_string(), "truecolor".to_string()),
            ("PATH".to_string(), path_env.clone()),
        ];
        for k in ["HOME", "USER", "LOGNAME", "SHELL", "LANG", "LC_ALL"] {
            if let Some(v) = get(k) {
                env.push((k.to_string(), v));
            }
        }
        Self {
            cfg,
            cwd,
            env,
            path_env,
            active: AtomicUsize::new(0),
            audit: AuditLog::new(audit_path),
        }
    }

    pub fn audit(&self) -> &AuditLog {
        &self.audit
    }

    pub fn active(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }

    fn argv(&self, attach: Option<&str>) -> Option<Vec<String>> {
        if let Some(name) = attach {
            return plan_attach(
                &self.cfg,
                find_in_path("tmux", &self.path_env).as_deref(),
                name,
            );
        }
        Some(self.default_argv())
    }

    fn default_argv(&self) -> Vec<String> {
        // bash by default (owner decision); the box user's own $SHELL, then sh, only when bash is absent.
        let own = self
            .env
            .iter()
            .find(|(k, _)| k == "SHELL")
            .map(|(_, v)| v.clone());
        let shell = ["/bin/bash", "/usr/bin/bash"]
            .iter()
            .map(|s| s.to_string())
            .chain(own)
            .find(|s| Path::new(s).is_file())
            .unwrap_or_else(|| "/bin/sh".into());
        plan_command(
            &self.cfg,
            find_in_path("tmux", &self.path_env).as_deref(),
            &shell,
        )
    }

    /// Serve one connection whose request head is already read. Always answers the socket, upgraded or not.
    pub fn handle(&self, mut stream: UnixStream, head: &Head) {
        let _ = stream.set_nonblocking(false);
        let refuse = |stream: &mut UnixStream, resp: Response| {
            let _ = http::write_response(stream, &resp);
        };
        if head.method != "GET" {
            return refuse(&mut stream, Response::error(405, "method not allowed"));
        }
        if !self.cfg.enabled {
            return refuse(
                &mut stream,
                Response::error(404, "the terminal is turned off on this box"),
            );
        }
        if self.active.fetch_add(1, Ordering::SeqCst) >= self.cfg.max_sessions {
            self.active.fetch_sub(1, Ordering::SeqCst);
            return refuse(
                &mut stream,
                Response::json(
                    503,
                    &serde_json::json!({
                        "code": "terminal_busy",
                        "message": "too many terminal sessions are open on this box",
                        "error": "too many terminal sessions are open on this box"
                    }),
                ),
            );
        }
        let guard = ActiveGuard(&self.active);
        let num = |k: &str, d: u16| {
            head.query
                .get(k)
                .and_then(|v| v.parse::<u16>().ok())
                .unwrap_or(d)
        };
        let size = clamp_size(num("cols", 80), num("rows", 24));
        let attach = head.query.get("session").map(String::as_str);
        let Some(argv) = self.argv(attach) else {
            return refuse(
                &mut stream,
                Response::json(
                    400,
                    &serde_json::json!({
                        "code": "bad_session",
                        "message": "that session cannot be attached here",
                        "error": "that session cannot be attached here"
                    }),
                ),
            );
        };
        let session = random_id();
        let started = match self.spawn(&argv, size) {
            Ok(s) => s,
            Err(_) => {
                return refuse(
                    &mut stream,
                    Response::json(
                        500,
                        &serde_json::json!({
                            "code": "terminal_failed",
                            "message": "the shell could not be started",
                            "error": "the shell could not be started"
                        }),
                    ),
                )
            }
        };
        let upgrade = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: ozbox-pty/1\r\nConnection: Upgrade\r\nCache-Control: no-store\r\n\r\n";
        if stream.write_all(upgrade.as_bytes()).is_err() {
            let mut child = started.child;
            let _ = child.kill();
            return;
        }
        let tmux = self.cfg.command.is_empty()
            && argv
                .first()
                .is_some_and(|a| a.rsplit('/').next() == Some("tmux"));
        self.audit.record(&AuditEvent {
            ts_ms: now_ms(),
            event: "terminal.start",
            session: session.clone(),
            cols: size.cols,
            rows: size.rows,
            tmux,
            duration_s: None,
            bytes_in: None,
            bytes_out: None,
            reason: None,
        });
        let t0 = Instant::now();
        let (bytes_in, bytes_out, reason) = self.pump(stream, started, self.cfg.idle_timeout_s);
        self.audit.record(&AuditEvent {
            ts_ms: now_ms(),
            event: "terminal.end",
            session,
            cols: size.cols,
            rows: size.rows,
            tmux,
            duration_s: Some(t0.elapsed().as_secs()),
            bytes_in: Some(bytes_in),
            bytes_out: Some(bytes_out),
            reason: Some(reason),
        });
        drop(guard);
    }

    fn spawn(&self, argv: &[String], size: PtySize) -> Result<Started, String> {
        argv.first().ok_or("no command")?;
        let pair = native_pty_system()
            .openpty(size)
            .map_err(|e| e.to_string())?;
        // The daemon is protected from the OOM killer (ADR 0045) and a child inherits its score; a terminal is where a person
        // runs a build, so it puts its own score back up first (a process may raise its score, never lower it). The tmux
        // server this may start, and everything in it, inherits that.
        let wrapped = terminal_argv(argv);
        let (first, rest) = wrapped.split_first().ok_or("no command")?;
        let mut cmd = CommandBuilder::new(first);
        cmd.args(rest);
        cmd.env_clear();
        for (k, v) in &self.env {
            cmd.env(k, v);
        }
        if self.cwd.is_dir() {
            cmd.cwd(&self.cwd);
        }
        let child = pair.slave.spawn_command(cmd).map_err(|e| e.to_string())?;
        drop(pair.slave);
        let reader = pair.master.try_clone_reader().map_err(|e| e.to_string())?;
        let writer = pair.master.take_writer().map_err(|e| e.to_string())?;
        Ok(Started {
            master: pair.master,
            child,
            reader,
            writer,
        })
    }

    /// Move bytes both ways until the client leaves, the shell exits or the session is idle.
    fn pump(&self, stream: UnixStream, s: Started, idle_s: u64) -> (u64, u64, &'static str) {
        let Started {
            master,
            mut child,
            mut reader,
            mut writer,
        } = s;
        let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));
        let _ = stream.set_read_timeout(None);
        let (Ok(mut rd_stream), Ok(wr_stream)) = (stream.try_clone(), stream.try_clone()) else {
            let _ = child.kill();
            return (0, 0, "client_closed");
        };
        let out_stream = Arc::new(Mutex::new(wr_stream));
        let bytes_in = Arc::new(AtomicU64::new(0));
        let bytes_out = Arc::new(AtomicU64::new(0));
        let last = Arc::new(AtomicU64::new(0));
        let t0 = Instant::now();
        let shell_done = Arc::new(AtomicBool::new(false));
        let client_done = Arc::new(AtomicBool::new(false));

        // shell -> client. A slow client blocks this write, which stops reading the shell: that is the back-pressure
        // (the memory this holds is one buffer).
        let out_thread = {
            let (st, bo, last, done) = (
                out_stream.clone(),
                bytes_out.clone(),
                last.clone(),
                shell_done.clone(),
            );
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 16 * 1024];
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            bo.fetch_add(n as u64, Ordering::SeqCst);
                            last.store(t0.elapsed().as_secs(), Ordering::SeqCst);
                            let mut w = st.lock().unwrap_or_else(|e| e.into_inner());
                            if write_frame(&mut *w, T_DATA, &buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
                done.store(true, Ordering::SeqCst);
            })
        };
        // client -> shell
        let in_thread = {
            let (bi, last, done) = (bytes_in.clone(), last.clone(), client_done.clone());
            std::thread::spawn(move || {
                loop {
                    match read_frame(&mut rd_stream) {
                        Ok(Some((T_DATA, data))) => {
                            bi.fetch_add(data.len() as u64, Ordering::SeqCst);
                            last.store(t0.elapsed().as_secs(), Ordering::SeqCst);
                            if writer.write_all(&data).is_err() || writer.flush().is_err() {
                                break;
                            }
                        }
                        Ok(Some((T_RESIZE, p))) if p.len() == 4 => {
                            let size = clamp_size(
                                u16::from_be_bytes([p[0], p[1]]),
                                u16::from_be_bytes([p[2], p[3]]),
                            );
                            let _ = master.resize(size);
                        }
                        Ok(Some((T_CLOSE, _))) | Ok(None) | Err(_) => break,
                        Ok(Some(_)) => {}
                    }
                }
                done.store(true, Ordering::SeqCst);
            })
        };

        let reason = loop {
            std::thread::sleep(Duration::from_millis(50));
            if shell_done.load(Ordering::SeqCst) {
                break "shell_exited";
            }
            if client_done.load(Ordering::SeqCst) {
                break "client_closed";
            }
            if idle_s > 0
                && t0
                    .elapsed()
                    .as_secs()
                    .saturating_sub(last.load(Ordering::SeqCst))
                    >= idle_s
            {
                break "idle_timeout";
            }
        };
        // Stop the shell side. For a tmux client this detaches; the tmux session lives on.
        let status = if reason == "shell_exited" {
            // Give the shell a moment to be reaped so the real status is reported.
            let end = Instant::now() + Duration::from_secs(2);
            loop {
                match child.try_wait() {
                    Ok(Some(st)) => break st.exit_code() as i32,
                    Ok(None) if Instant::now() < end => {
                        std::thread::sleep(Duration::from_millis(20))
                    }
                    _ => {
                        let _ = child.kill();
                        break -1;
                    }
                }
            }
        } else {
            let _ = child.kill();
            let _ = child.wait();
            0
        };
        if reason != "client_closed" {
            let mut w = out_stream.lock().unwrap_or_else(|e| e.into_inner());
            let _ = write_frame(&mut *w, T_EXIT, &status.to_be_bytes());
        }
        let _ = stream.shutdown(std::net::Shutdown::Both);
        let _ = in_thread.join();
        let _ = out_thread.join();
        (
            bytes_in.load(Ordering::SeqCst),
            bytes_out.load(Ordering::SeqCst),
            reason,
        )
    }
}

struct Started {
    master: Box<dyn portable_pty::MasterPty + Send>,
    child: Box<dyn portable_pty::Child + Send + Sync>,
    reader: Box<dyn Read + Send>,
    writer: Box<dyn Write + Send>,
}

struct ActiveGuard<'a>(&'a AtomicUsize);

impl Drop for ActiveGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

static GLOBAL: OnceLock<Arc<TerminalService>> = OnceLock::new();

/// Install the service the socket server hands `/v1/terminal` to. First call wins.
pub fn install_global(svc: Arc<TerminalService>) {
    let _ = GLOBAL.set(svc);
}

pub fn global() -> Option<Arc<TerminalService>> {
    GLOBAL.get().cloned()
}

pub fn is_terminal_path(path: &str) -> bool {
    path == "/v1/terminal"
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn a_terminal_puts_its_own_oom_score_up_before_the_plan_runs_and_never_changes_the_plan() {
        let plan = vec![
            "/usr/bin/tmux".to_string(),
            "new-session".into(),
            "-A".into(),
        ];
        let v = terminal_argv(&plan);
        assert_eq!(&v[..2], ["/bin/sh", "-c"]);
        assert_eq!(
            v[2],
            "{ echo 200 >/proc/self/oom_score_adj; } 2>/dev/null; exec \"$@\""
        );
        // the plan follows as separate words: nothing the person's session names is read by a shell
        assert_eq!(&v[4..], plan.as_slice());
        let weird = vec!["bash".to_string(), "-c".into(), "echo $(id); x".into()];
        assert_eq!(terminal_argv(&weird)[4..], weird[..]);
    }

    fn cfg(cmd: &[&str]) -> TerminalSection {
        TerminalSection {
            command: cmd.iter().map(|s| s.to_string()).collect(),
            ..TerminalSection::default()
        }
    }

    fn head(cols: u16, rows: u16) -> Head {
        let mut query = BTreeMap::new();
        query.insert("cols".to_string(), cols.to_string());
        query.insert("rows".to_string(), rows.to_string());
        Head {
            method: "GET".into(),
            path: "/v1/terminal".into(),
            query,
            content_length: 0,
            length_given: false,
            early: Vec::new(),
            capability: None,
        }
    }

    struct Client {
        s: UnixStream,
        status: String,
    }

    /// Connect to a service through a socket pair, run `handle` on a thread, read the HTTP head.
    fn connect(svc: &Arc<TerminalService>, h: Head) -> Result<Client, Box<dyn std::error::Error>> {
        let (a, b) = UnixStream::pair()?;
        let svc = svc.clone();
        std::thread::spawn(move || svc.handle(b, &h));
        let mut s = a;
        s.set_read_timeout(Some(Duration::from_secs(10)))?;
        let mut raw = Vec::new();
        let mut byte = [0u8; 1];
        while !raw.ends_with(b"\r\n\r\n") {
            s.read_exact(&mut byte)?;
            raw.push(byte[0]);
        }
        let status = String::from_utf8_lossy(&raw)
            .lines()
            .next()
            .unwrap_or("")
            .to_string();
        if status.contains("503") || status.contains("404") {
            // a refusal carries a body; leave it unread
        }
        Ok(Client { s, status })
    }

    fn read_until(c: &mut Client, needle: &str) -> Result<String, Box<dyn std::error::Error>> {
        let mut text = String::new();
        let end = Instant::now() + Duration::from_secs(10);
        while Instant::now() < end {
            match read_frame(&mut c.s)? {
                Some((T_DATA, d)) => {
                    text.push_str(&String::from_utf8_lossy(&d));
                    if text.contains(needle) {
                        return Ok(text);
                    }
                }
                Some((T_EXIT, _)) | None => break,
                Some(_) => {}
            }
        }
        Err(format!("never saw {needle:?}; got {text:?}").into())
    }

    fn svc(cfg: TerminalSection, dir: &Path) -> Arc<TerminalService> {
        Arc::new(TerminalService::new(
            cfg,
            dir.to_path_buf(),
            Some(dir.join("audit.jsonl")),
        ))
    }

    #[test]
    fn frames_round_trip_and_refuse_oversize() -> TestResult {
        let mut buf = Vec::new();
        write_frame(&mut buf, T_DATA, b"hi")?;
        write_frame(&mut buf, T_RESIZE, &resize_payload(100, 30))?;
        let mut r = std::io::Cursor::new(buf);
        assert_eq!(read_frame(&mut r)?, Some((T_DATA, b"hi".to_vec())));
        assert_eq!(read_frame(&mut r)?, Some((T_RESIZE, vec![0, 100, 0, 30])));
        assert_eq!(read_frame(&mut r)?, None);
        assert!(write_frame(&mut Vec::new(), T_DATA, &vec![0; MAX_FRAME + 1]).is_err());
        let mut bad = vec![T_DATA];
        bad.extend_from_slice(&((MAX_FRAME as u32) + 1).to_be_bytes());
        assert!(read_frame(&mut std::io::Cursor::new(bad)).is_err());
        Ok(())
    }

    #[test]
    fn attaching_a_named_session_is_one_exact_argv_and_refuses_odd_names_and_no_tmux() {
        let c = cfg(&[]);
        let t = Some(Path::new("/usr/bin/tmux"));
        assert_eq!(
            plan_attach(&c, t, "term-2").unwrap(),
            ["/usr/bin/tmux", "attach-session", "-t", "=term-2"]
        );
        for bad in ["", "a b", "x;y", "../x", "a'b"] {
            assert!(plan_attach(&c, t, bad).is_none(), "{bad}");
        }
        assert!(plan_attach(&c, None, "term-2").is_none());
        assert!(plan_attach(&cfg(&["cat"]), t, "term-2").is_none());
    }

    #[test]
    fn the_default_command_attaches_to_tmux_with_bounded_history() {
        let c = TerminalSection::default();
        let argv = plan_command(&c, Some(Path::new("/usr/bin/tmux")), "/bin/bash");
        assert_eq!(argv[0], "/usr/bin/tmux");
        assert!(argv.windows(3).any(|w| w == ["new-session", "-A", "-s"]));
        assert!(argv.contains(&"ozbox".to_string()));
        assert!(argv.contains(&"20000".to_string()));
        assert!(argv.windows(2).any(|w| w == ["default-shell", "/bin/bash"]));
        // no tmux: the login shell
        assert_eq!(plan_command(&c, None, "/bin/bash"), ["/bin/bash", "-l"]);
        // an odd session name is never passed to tmux
        let mut odd = c.clone();
        odd.tmux_session = "a;b".into();
        assert_eq!(
            plan_command(&odd, Some(Path::new("/usr/bin/tmux")), "/bin/sh")[0],
            "/bin/sh"
        );
        // an explicit command wins
        assert_eq!(
            plan_command(&cfg(&["cat"]), Some(Path::new("/usr/bin/tmux")), "/bin/sh"),
            ["cat"]
        );
    }

    #[test]
    fn a_session_echoes_input_resizes_and_is_audited_without_content() -> TestResult {
        let d = tempfile::tempdir()?;
        let svc = svc(
            cfg(&["sh", "-c", "read l; stty size; read m; echo got-$m"]),
            d.path(),
        );
        let mut c = connect(&svc, head(80, 24))?;
        assert!(c.status.contains("101"), "{}", c.status);
        write_frame(&mut c.s, T_RESIZE, &resize_payload(120, 40))?;
        std::thread::sleep(Duration::from_millis(150));
        write_frame(&mut c.s, T_DATA, b"go\n")?;
        let out = read_until(&mut c, "40 120")?;
        assert!(out.contains("40 120"), "{out}");
        write_frame(&mut c.s, T_DATA, b"SECRETWORD\n")?;
        read_until(&mut c, "got-SECRETWORD")?;
        // the shell ends: an exit frame follows
        let mut exited = false;
        while let Some((ty, p)) = read_frame(&mut c.s)? {
            if ty == T_EXIT {
                assert_eq!(p, 0i32.to_be_bytes());
                exited = true;
                break;
            }
        }
        assert!(exited);
        std::thread::sleep(Duration::from_millis(300));
        let log = std::fs::read_to_string(d.path().join("audit.jsonl"))?;
        assert!(
            log.contains("terminal.start") && log.contains("terminal.end"),
            "{log}"
        );
        assert!(log.contains("shell_exited"));
        assert!(
            !log.contains("SECRETWORD") && !log.contains("40 120"),
            "{log}"
        );
        assert_eq!(svc.active(), 0);
        Ok(())
    }

    #[test]
    fn at_most_max_sessions_and_a_closed_session_frees_its_place() -> TestResult {
        let d = tempfile::tempdir()?;
        let mut c1 = cfg(&["cat"]);
        c1.max_sessions = 1;
        let svc = svc(c1, d.path());
        let mut first = connect(&svc, head(80, 24))?;
        assert!(first.status.contains("101"));
        let second = connect(&svc, head(80, 24))?;
        assert!(second.status.contains("503"), "{}", second.status);
        write_frame(&mut first.s, T_CLOSE, &[])?;
        let end = Instant::now() + Duration::from_secs(5);
        while svc.active() != 0 && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(svc.active(), 0);
        let third = connect(&svc, head(80, 24))?;
        assert!(third.status.contains("101"));
        Ok(())
    }

    #[test]
    fn an_idle_session_is_closed() -> TestResult {
        let d = tempfile::tempdir()?;
        let mut c = cfg(&["cat"]);
        c.idle_timeout_s = 1;
        let svc = svc(c, d.path());
        let mut cl = connect(&svc, head(80, 24))?;
        let end = Instant::now() + Duration::from_secs(8);
        let mut exited = false;
        while Instant::now() < end {
            match read_frame(&mut cl.s)? {
                Some((T_EXIT, _)) | None => {
                    exited = true;
                    break;
                }
                Some(_) => {}
            }
        }
        assert!(exited);
        std::thread::sleep(Duration::from_millis(300));
        assert!(std::fs::read_to_string(d.path().join("audit.jsonl"))?.contains("idle_timeout"));
        Ok(())
    }

    #[test]
    fn the_shell_does_not_inherit_the_daemons_environment() -> TestResult {
        std::env::set_var("OZBOX_TEST_SENTINEL_SECRET", "leaky-value");
        let d = tempfile::tempdir()?;
        let svc = svc(
            cfg(&[
                "sh",
                "-c",
                "echo SENT=${OZBOX_TEST_SENTINEL_SECRET-unset}; echo TERM=$TERM",
            ]),
            d.path(),
        );
        let mut c = connect(&svc, head(80, 24))?;
        let out = read_until(&mut c, "TERM=xterm-256color")?;
        assert!(
            out.contains("SENT=unset") && !out.contains("leaky-value"),
            "{out}"
        );
        Ok(())
    }

    #[test]
    fn a_turned_off_terminal_and_non_get_are_refused() -> TestResult {
        let d = tempfile::tempdir()?;
        let mut off = cfg(&["cat"]);
        off.enabled = false;
        let s = svc(off, d.path());
        assert!(connect(&s, head(80, 24))?.status.contains("404"));
        let s2 = svc(cfg(&["cat"]), d.path());
        let mut h = head(80, 24);
        h.method = "POST".into();
        assert!(connect(&s2, h)?.status.contains("405"));
        Ok(())
    }

    #[test]
    fn sizes_are_clamped() {
        let s = clamp_size(0, 0);
        assert_eq!((s.cols, s.rows), (MIN_COLS, MIN_ROWS));
        let s = clamp_size(60000, 60000);
        assert_eq!((s.cols, s.rows), (MAX_COLS, MAX_ROWS));
    }
}
