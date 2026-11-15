//! The browser terminal, as `ozbox serve` offers it.
//!
//! A terminal is three plain HTTP calls, all behind the same sign-in as the rest of the API, so it works through any
//! proxy or tunnel and never needs a token in a URL:
//!
//! 1. `POST /v1/boxes/<name>/terminal` `{cols, rows}` makes a session and returns its id.
//! 2. `GET /v1/terminal/<id>/output` is a long response of frames (`[type][u32 length][payload]`, the same frames the
//!    box daemon speaks). The first frame is `ready` (or `error`); then terminal output; `exit` at the end; a `noop`
//!    keep-alive every 5 s (which is also how a closed browser tab is noticed).
//! 3. `POST /v1/terminal/<id>/input` carries frames to the shell (data, resize, close); `DELETE /v1/terminal/<id>` ends
//!    the session.
//!
//! The browser sends one input call at a time and batches keystrokes while one is in flight, so order is kept.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ozbox_core::BoxRecord;
use ozboxd::terminal::{read_frame, write_frame, T_CLOSE, T_DATA, T_RESIZE};

use super::agent::{AgentError, BoxAgent};

/// Frames this server adds to the daemon's.
pub const F_NOOP: u8 = 0;
pub const F_READY: u8 = 5;
pub const F_ERROR: u8 = 6;
const KEEPALIVE: Duration = Duration::from_secs(5);
const ATTACH_WAIT: Duration = Duration::from_secs(30);
pub const MAX_SESSIONS: usize = 8;

/// A connection to a box's terminal endpoint, past the upgrade. `hold` keeps the forward from being closed as idle.
pub struct Conn {
    pub stream: UnixStream,
    pub hold: Option<Box<dyn Send>>,
}

struct Pending {
    agent: Arc<dyn BoxAgent>,
    rec: BoxRecord,
    cols: u16,
    rows: u16,
    /// An existing tmux session to attach (the Code panel's Open); none opens the shared one.
    session: Option<String>,
}

struct Session {
    box_name: String,
    created: Instant,
    pending: Option<Pending>,
    writer: Option<Arc<Mutex<UnixStream>>>,
}

#[derive(Clone, Default)]
pub struct Sessions {
    map: Arc<Mutex<HashMap<String, Session>>>,
}

pub enum InputError {
    Unknown,
    NotReady,
    Bad,
    Gone,
}

/// What an output call needs to run on its own thread.
pub struct OutputJob {
    pub id: String,
    pub sessions: Sessions,
    agent: Arc<dyn BoxAgent>,
    rec: BoxRecord,
    cols: u16,
    rows: u16,
    session: Option<String>,
}

impl Sessions {
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        &self,
        id: String,
        box_name: &str,
        agent: Arc<dyn BoxAgent>,
        rec: BoxRecord,
        cols: u16,
        rows: u16,
        session: Option<String>,
    ) -> Result<(), ()> {
        let mut m = self.map.lock().map_err(|_| ())?;
        if m.len() >= MAX_SESSIONS {
            return Err(());
        }
        m.insert(
            id,
            Session {
                box_name: box_name.to_string(),
                created: Instant::now(),
                pending: Some(Pending {
                    agent,
                    rec,
                    cols,
                    rows,
                    session,
                }),
                writer: None,
            },
        );
        Ok(())
    }

    pub fn box_of(&self, id: &str) -> Option<String> {
        self.map.lock().ok()?.get(id).map(|s| s.box_name.clone())
    }

    pub fn take_output(&self, id: &str) -> Option<OutputJob> {
        let mut m = self.map.lock().ok()?;
        let p = m.get_mut(id)?.pending.take()?;
        Some(OutputJob {
            id: id.to_string(),
            sessions: self.clone(),
            agent: p.agent,
            rec: p.rec,
            cols: p.cols,
            rows: p.rows,
            session: p.session,
        })
    }

    pub fn input(&self, id: &str, body: &[u8]) -> Result<(), InputError> {
        let writer = {
            let m = self.map.lock().map_err(|_| InputError::Gone)?;
            let s = m.get(id).ok_or(InputError::Unknown)?;
            s.writer.clone().ok_or(InputError::NotReady)?
        };
        // Validate every frame before forwarding any.
        let mut frames = Vec::new();
        let mut cur = std::io::Cursor::new(body);
        loop {
            match read_frame(&mut cur) {
                Ok(Some((ty, p))) => {
                    let ok = match ty {
                        T_DATA | T_CLOSE => true,
                        T_RESIZE => p.len() == 4,
                        _ => false,
                    };
                    if !ok {
                        return Err(InputError::Bad);
                    }
                    frames.push((ty, p));
                }
                Ok(None) => break,
                Err(_) => return Err(InputError::Bad),
            }
        }
        let mut w = writer.lock().map_err(|_| InputError::Gone)?;
        let _ = w.set_write_timeout(Some(Duration::from_secs(2)));
        for (ty, p) in frames {
            write_frame(&mut *w, ty, &p).map_err(|_| InputError::Gone)?;
        }
        Ok(())
    }

    /// End a session: the shell side is told to detach and the connection is closed.
    pub fn close(&self, id: &str) -> bool {
        let removed = self.map.lock().ok().and_then(|mut m| m.remove(id));
        match removed {
            Some(s) => {
                if let Some(w) = s.writer {
                    if let Ok(mut w) = w.lock() {
                        let _ = write_frame(&mut *w, T_CLOSE, &[]);
                        let _ = w.shutdown(std::net::Shutdown::Both);
                    }
                }
                true
            }
            None => false,
        }
    }

    /// Drop sessions whose output was never opened.
    pub fn sweep(&self) {
        if let Ok(mut m) = self.map.lock() {
            m.retain(|_, s| s.pending.is_none() || s.created.elapsed() < ATTACH_WAIT);
        }
    }
}

fn frame_bytes(ty: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(payload.len() + 5);
    v.push(ty);
    v.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    v.extend_from_slice(payload);
    v
}

/// Read the daemon's answer to the terminal request. `Ok` only for `101`; any other status becomes an error carrying
/// the daemon's message.
pub fn handshake(stream: &mut UnixStream) -> Result<(), AgentError> {
    let bad = |m: &str| AgentError::Unreachable(m.to_string());
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 4096 {
            return Err(bad(
                "the box's agent answered with something that is not HTTP",
            ));
        }
        match stream.read(&mut b) {
            Ok(1) => head.push(b[0]),
            _ => return Err(bad("the box's agent did not answer the terminal request")),
        }
    }
    let text = String::from_utf8_lossy(&head).into_owned();
    let status: u16 = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| bad("the box's agent answered with something that is not HTTP"))?;
    if status == 101 {
        let _ = stream.set_read_timeout(None);
        return Ok(());
    }
    let len = text
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .and_then(|v| v.trim().parse::<usize>().ok())
        })
        .unwrap_or(0)
        .min(4096);
    let mut body = vec![0u8; len];
    let _ = stream.read_exact(&mut body);
    let msg = serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v.get("message").and_then(|m| m.as_str()).map(String::from))
        .unwrap_or_else(|| "the box could not open a terminal".into());
    Err(match status {
        503 => AgentError::Unreachable(msg),
        404 => AgentError::Unsupported(msg),
        _ => AgentError::Unreachable(msg),
    })
}

/// The request line the daemon expects.
pub fn request_line(cols: u16, rows: u16, session: Option<&str>) -> String {
    // The name is plain (checked before it gets here); anything else is left out rather than sent.
    let attach = session
        .filter(|n| ozbox_core::procs::valid_session_name(n))
        .map(|n| format!("&session={n}"))
        .unwrap_or_default();
    format!(
        "GET /v1/terminal?cols={cols}&rows={rows}{attach} HTTP/1.1\r\nHost: ozboxd\r\nConnection: Upgrade\r\nUpgrade: ozbox-pty/1\r\n\r\n"
    )
}

/// Run one output call to its end: connect to the box, then copy frames to the browser. Called on its own thread with
/// the response writer.
pub fn run_output(job: OutputJob, mut out: Box<dyn Write + Send>) {
    let head = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nCache-Control: no-store\r\nConnection: close\r\n\
X-Content-Type-Options: nosniff\r\nCross-Origin-Resource-Policy: same-origin\r\n\r\n";
    if out.write_all(head.as_bytes()).is_err() {
        job.sessions.close(&job.id);
        return;
    }
    let conn = match job
        .agent
        .terminal(&job.rec, job.cols, job.rows, job.session.as_deref())
    {
        Ok(c) => c,
        Err(e) => {
            let msg = serde_json::json!({
                "code": match e { AgentError::Unsupported(_) => "unsupported", AgentError::Unreachable(_) => "agent_unreachable" },
                "message": e.to_string(),
            });
            let _ = out.write_all(&frame_bytes(F_ERROR, msg.to_string().as_bytes()));
            let _ = out.flush();
            job.sessions.close(&job.id);
            return;
        }
    };
    let Conn { stream, hold } = conn;
    let (Ok(mut reader), Ok(writer)) = (stream.try_clone(), stream.try_clone()) else {
        job.sessions.close(&job.id);
        return;
    };
    let writer = Arc::new(Mutex::new(writer));
    {
        let Ok(mut m) = job.sessions.map.lock() else {
            return;
        };
        match m.get_mut(&job.id) {
            Some(s) => s.writer = Some(writer.clone()),
            None => {
                let _ = stream.shutdown(std::net::Shutdown::Both);
                return;
            }
        }
    }
    let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(32);
    std::thread::spawn(move || {
        while let Ok(Some((ty, p))) = read_frame(&mut reader) {
            if tx.send(frame_bytes(ty, &p)).is_err() {
                break;
            }
        }
    });
    let mut ok = out.write_all(&frame_bytes(F_READY, &[])).is_ok() && out.flush().is_ok();
    while ok {
        match rx.recv_timeout(KEEPALIVE) {
            Ok(bytes) => ok = out.write_all(&bytes).is_ok() && out.flush().is_ok(),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                ok = out.write_all(&frame_bytes(F_NOOP, &[])).is_ok() && out.flush().is_ok()
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    // The browser went away or the shell ended: detach, close, forget.
    if let Ok(mut w) = writer.lock() {
        let _ = write_frame(&mut *w, T_CLOSE, &[]);
        let _ = w.shutdown(std::net::Shutdown::Both);
    }
    drop(hold);
    job.sessions.close(&job.id);
}

/// `/v1/terminal/<id>/output` -> the id.
pub fn output_id(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("/v1/terminal/")?;
    let id = rest.strip_suffix("/output")?;
    (!id.is_empty() && !id.contains('/')).then_some(id)
}

pub fn valid_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

use super::{random_hex, App, Req, Resp};

impl App {
    pub(super) fn terminal_open(&mut self, name: &str, body: &[u8]) -> Resp {
        #[derive(serde::Deserialize)]
        struct Open {
            cols: Option<u16>,
            rows: Option<u16>,
            /// Attach this existing tmux session instead of the shared one.
            session: Option<String>,
        }
        let o: Open = if body.is_empty() {
            Open {
                cols: None,
                rows: None,
                session: None,
            }
        } else {
            match serde_json::from_slice(body) {
                Ok(o) => o,
                Err(_) => return Resp::error(400, "bad_request", "the request body is not valid"),
            }
        };
        if let Some(sn) = &o.session {
            if !ozbox_core::procs::valid_session_name(sn) {
                return Resp::error(400, "bad_request", "that is not a session name");
            }
        }
        let rec = match self.running_box(name) {
            Ok(r) => r,
            Err(r) => return r,
        };
        let id = match random_hex(16) {
            Ok(i) => i,
            Err(_) => return Resp::error(500, "internal", "could not make a session id"),
        };
        self.terminals.sweep();
        if self
            .terminals
            .open(
                id.clone(),
                name,
                Arc::clone(&self.agent),
                rec,
                o.cols.unwrap_or(80),
                o.rows.unwrap_or(24),
                o.session,
            )
            .is_err()
        {
            return Resp::error(429, "too_many_terminals", "too many terminals are open");
        }
        self.log_activity("terminal.open", name, None, "ok");
        // Who this terminal is for, before any output arrives (G7 R3): the box, whether the shell is real or a demo's, and what
        // it runs as. A real box's shell is started by the box's own agent as the box user; `ozbox serve` (the supervisor's
        // user) never starts one. A demo's is a made-up shell on this computer.
        let simulated = self.simulated_metrics;
        Resp::json(
            200,
            &serde_json::json!({
                "session": id,
                "target": {
                    "box": name,
                    "source": if simulated { "simulated" } else { "live" },
                    "runs_as": if simulated { "demo" } else { "box_user" },
                },
            }),
        )
    }

    pub(super) fn terminal_input(&mut self, id: &str, body: &[u8]) -> Resp {
        if !valid_id(id) {
            return Resp::error(404, "not_found", "no such terminal");
        }
        match self.terminals.input(id, body) {
            Ok(()) => Resp::json(200, &serde_json::json!({ "ok": true })),
            Err(InputError::Unknown) => Resp::error(404, "not_found", "no such terminal"),
            Err(InputError::NotReady) => {
                Resp::error(409, "not_ready", "the terminal is still connecting")
            }
            Err(InputError::Bad) => Resp::error(400, "bad_request", "the input is not valid"),
            Err(InputError::Gone) => Resp::error(410, "gone", "the terminal has ended"),
        }
    }

    pub(super) fn terminal_close(&mut self, id: &str) -> Resp {
        if !valid_id(id) {
            return Resp::error(404, "not_found", "no such terminal");
        }
        let name = self.terminals.box_of(id);
        if !self.terminals.close(id) {
            return Resp::error(404, "not_found", "no such terminal");
        }
        self.log_activity("terminal.close", name.as_deref().unwrap_or(""), None, "ok");
        Resp::json(200, &serde_json::json!({ "ok": true }))
    }

    pub(super) fn prepare_terminal_output(
        &mut self,
        req: &Req,
        id: &str,
    ) -> Result<OutputJob, Resp> {
        if let Some(r) = self.guard(req, true) {
            return Err(r);
        }
        if req.method != "GET" {
            return Err(Resp::error(405, "method_not_allowed", "method not allowed"));
        }
        if !valid_id(id) {
            return Err(Resp::error(404, "not_found", "no such terminal"));
        }
        self.terminals
            .take_output(id)
            .ok_or_else(|| Resp::error(404, "not_found", "no such terminal"))
    }
}

#[cfg(test)]
mod attach_tests {
    use super::request_line;

    #[test]
    fn a_session_is_asked_for_by_a_plain_name_only() {
        let plain = request_line(80, 24, None);
        assert!(
            plain.starts_with("GET /v1/terminal?cols=80&rows=24 HTTP/1.1")
                && !plain.contains("session")
        );
        assert!(request_line(80, 24, Some("term-2")).contains("rows=24&session=term-2 HTTP/1.1"));
        // a name that is not plain never reaches the request line
        for bad in ["a b", "x&y=1", "x\r\nHost: evil"] {
            assert!(
                !request_line(80, 24, Some(bad)).contains("session"),
                "{bad}"
            );
        }
    }
}
