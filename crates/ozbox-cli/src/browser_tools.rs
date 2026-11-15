//! The browser on the box as MCP tools (ADR 0037): the tool host's browser tools, the backends that reach a session's worker,
//! and [`BrowserHost`], which owns the sessions.
//!
//! A session is a worker process on the box (`ozbox browser-worker`) with a Chromium behind it, reached over one sealed
//! channel only this server holds the key to. Each tool call is two steps the worker answers: *preview* (what would this
//! do, how risky is it, where would it go?), then, once the permission engine has decided, *act*. A risky act carries a
//! person's grant, which only an approval request a person decided can produce. The engine sees one call per action, with the domain as its path and the action word and field *name* as its
//! command. A typed value, a page's text and an address never reach the audit chain.

use std::collections::HashMap;
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ozbox_browser::channel::{Channel, SessionKey};
use ozbox_browser::detect::host_in;
use ozbox_browser::policy::{BrowserPolicy, Device};
use ozbox_browser::protocol::{Action, Grant, Op, Reply, Request, Start};
use ozbox_browser::record::{self, Meta, Step};
use ozbox_core::claude_code::{Launch, RunTransport};
use ozbox_core::permissions::{ActorKind, PermConfig};
use ozbox_core::run::TaskStore;
use serde_json::{json, Value};
use zeroize::Zeroize;

use crate::host_tools::backend::HostBackend;
use crate::host_tools::{Extra, Prepared, ToolInfo, Writes};
use crate::orch_tools::ToolError;

pub const OPEN_TIMEOUT: Duration = Duration::from_secs(60);
pub const ACT_TIMEOUT: Duration = Duration::from_secs(120);
const SCREENSHOT_MAX: usize = 400 * 1024;

// ---- the tools -----------------------------------------------------------------------------------------------------------

/// The browser tools. A test holds this list: an agent can call nothing else here.
pub const BROWSER_TOOLS: [ToolInfo; 17] = [
    ToolInfo { name: "browser_open", server: "browser", writes: Writes::Write, summary: "Open an isolated browser session (Chromium) and get its id. Pick a device: desktop, tablet or phone." },
    ToolInfo { name: "browser_close", server: "browser", writes: Writes::Write, summary: "Close a browser session. Its recording stays for the retention period." },
    ToolInfo { name: "browser_navigate", server: "browser", writes: Writes::Depends, summary: "Open an address in the session. A site that is not on the allow-list asks a person first." },
    ToolInfo { name: "browser_history", server: "browser", writes: Writes::Depends, summary: "Go back, go forward or reload." },
    ToolInfo { name: "browser_click", server: "browser", writes: Writes::Depends, summary: "Click an element named in the last snapshot. A click that submits a form, sends something or pays is approved by a person first." },
    ToolInfo { name: "browser_type", server: "browser", writes: Writes::Depends, summary: "Type text into a field named in the last snapshot. Typed values are never recorded." },
    ToolInfo { name: "browser_select", server: "browser", writes: Writes::Depends, summary: "Choose an option in a drop-down list." },
    ToolInfo { name: "browser_scroll", server: "browser", writes: Writes::Read, summary: "Scroll the page, or bring an element into view." },
    ToolInfo { name: "browser_hover", server: "browser", writes: Writes::Read, summary: "Move the pointer over an element." },
    ToolInfo { name: "browser_press", server: "browser", writes: Writes::Depends, summary: "Press a key, such as Enter, Tab or Control+a." },
    ToolInfo { name: "browser_tab", server: "browser", writes: Writes::Depends, summary: "List, open, switch to or close tabs." },
    ToolInfo { name: "browser_wait", server: "browser", writes: Writes::Read, summary: "Wait some time, for some text, or for an element." },
    ToolInfo { name: "browser_upload", server: "browser", writes: Writes::Write, summary: "Put a file from an upload folder (default /work/uploads) into a file input. A person approves every upload." },
    ToolInfo { name: "browser_downloads", server: "browser", writes: Writes::Depends, summary: "List what the session downloaded; documents can be opened, programs and scripts are held back." },
    ToolInfo { name: "browser_snapshot", server: "browser", writes: Writes::Read, summary: "The page as text: headings, text and numbered elements, with secret fields and sensitive numbers masked." },
    ToolInfo { name: "browser_page_screenshot", server: "browser", writes: Writes::Read, summary: "A picture of the page, with secret fields blurred. Use the snapshot first; a picture is for layout." },
    ToolInfo { name: "browser_extract", server: "browser", writes: Writes::Read, summary: "Read data from the page into a JSON schema (x-selector says where each value is). The result is checked against the schema." },
];

pub fn is_browser_tool(name: &str) -> bool {
    BROWSER_TOOLS.iter().any(|t| t.name == name)
}

pub fn tool_info(name: &str) -> Option<&'static ToolInfo> {
    BROWSER_TOOLS.iter().find(|t| t.name == name)
}

fn prop(kind: &str, desc: &str) -> Value {
    json!({ "type": kind, "description": desc })
}

fn schema(name: &str, person_session: bool) -> Value {
    let mut p = serde_json::Map::new();
    let mut required: Vec<&str> = Vec::new();
    if name != "browser_open" {
        p.insert(
            "session".into(),
            prop("string", "The session id from browser_open."),
        );
        required.push("session");
    }
    let mut add = |k: &str, v: Value, req: bool| {
        p.insert(k.into(), v);
        if req {
            required.push(match k {
                "url" => "url",
                "target" => "target",
                "text" => "text",
                "value" => "value",
                "key" => "key",
                "path" => "path",
                "schema" => "schema",
                "op" => "op",
                _ => "",
            });
        }
    };
    let target = || prop("string", "An element from the last snapshot, such as e12.");
    match name {
        "browser_open" => {
            add("device", json!({ "type": "string", "enum": ["desktop", "tablet", "phone"], "description": "The screen to emulate (default desktop). Phone and tablet are touch devices." }), false);
            add("project", prop("string", "The project whose browsing settings apply."), false);
            add("run", prop("string", "A name for this task in the recording."), false);
        }
        "browser_navigate" => add("url", prop("string", "http or https address."), true),
        "browser_history" => add("op", json!({ "type": "string", "enum": ["back", "forward", "reload"] }), true),
        "browser_click" | "browser_hover" => add("target", target(), true),
        "browser_type" => {
            add("target", target(), true);
            add("text", prop("string", "What to type (up to 8000 characters)."), true);
            add("submit", prop("boolean", "Press Enter after typing. A submit is approved by a person first."), false);
            add("clear", prop("boolean", "Clear the field first (default true)."), false);
        }
        "browser_select" => {
            add("target", target(), true);
            add("value", prop("string", "The option's value or its visible text."), true);
        }
        "browser_scroll" => {
            add("target", prop("string", "Bring this element into view."), false);
            add("dy", prop("integer", "Pixels to scroll down (negative is up)."), false);
        }
        "browser_press" => add("key", prop("string", "A key name: Enter, Tab, Escape, ArrowDown, Control+a, ..."), true),
        "browser_tab" => {
            add("op", json!({ "type": "string", "enum": ["list", "new", "switch", "close"] }), true);
            add("url", prop("string", "For new: the address to open."), false);
            add("index", prop("integer", "For switch and close: the tab number from list."), false);
        }
        "browser_wait" => {
            add("ms", prop("integer", "Milliseconds to wait (up to 30000)."), false);
            add("text", prop("string", "Wait until this text is on the page."), false);
            add("selector", prop("string", "Wait until an element matching this CSS selector exists."), false);
            add("timeout_ms", prop("integer", "Longest wait for a condition (up to 60000)."), false);
        }
        "browser_upload" => {
            add("target", target(), true);
            add("path", prop("string", "A file in an upload folder the person chose (default /work/uploads) or in this session's downloads."), true);
        }
        "browser_downloads" => add("open", prop("string", "A file name from the list: where to find a document, or ask to open a held-back file."), false),
        "browser_page_screenshot" => add("full_page", prop("boolean", "The whole page, not just what shows."), false),
        "browser_extract" => add("schema", json!({ "type": "object", "description": "A JSON schema. Give each value an x-selector (CSS); an array's x-selector is its rows, and its items' selectors are read inside each row. x-attr reads an attribute." }), true),
        _ => {}
    }
    required.retain(|r| !r.is_empty());
    if person_session {
        p.insert("box".into(), prop("string", "The box the browser runs on."));
        required.push("box");
    }
    json!({
        "name": name,
        "description": tool_info(name).map(|i| i.summary).unwrap_or(""),
        "inputSchema": { "type": "object", "properties": p, "required": required },
    })
}

pub fn tool_defs(person_session: bool) -> Vec<Value> {
    BROWSER_TOOLS
        .iter()
        .map(|t| schema(t.name, person_session))
        .collect()
}

// ---- reaching a worker -----------------------------------------------------------------------------------------------------

/// What the box is asked for when a worker starts: how long it may run and how much memory it may use. The box admits it only
/// when that much memory is free (ADR 0019), so the sessions on one box are bounded together, not only counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerRun {
    pub max_runtime_s: u64,
    pub memory_bytes: u64,
}

/// Where sessions run and where their recordings are read from. A backend carries lines and nothing else: it cannot read
/// them (every line after the first is sealed, see `ozbox_browser::channel`), and the first line, which holds the
/// session's key, is the worker's standard input and is never logged.
pub trait BrowserBackend: Send + Sync {
    /// Start a worker with its first line (its settings and key). Returns a handle; does not wait for it to be ready.
    fn start(&self, box_name: &str, first_line: &str, run: &WorkerRun) -> Result<String, String>;
    /// Send one sealed line.
    fn send(&self, box_name: &str, handle: &str, line: &str) -> Result<(), String>;
    /// The next line the worker wrote, or `None` when none came before `deadline`. An error means the session ended.
    fn next_line(
        &self,
        box_name: &str,
        handle: &str,
        deadline: Instant,
    ) -> Result<Option<String>, String>;
    fn stop(&self, box_name: &str, handle: &str);
    /// The browser folder and `/work`, as the worker sees them.
    fn roots(&self, box_name: &str) -> (String, String);
    /// Where the worker keeps what only it may see (profiles, held-back downloads, a saved place), when it runs as a user of
    /// its own on that box. `None`: it keeps them under the recording root.
    fn private_root(&self, _box_name: &str) -> Option<String> {
        None
    }
    fn list_sessions(&self, box_name: &str) -> Result<Vec<Meta>, String>;
    fn steps(&self, box_name: &str, session: &str) -> Result<Vec<Step>, String>;
    fn shot(&self, box_name: &str, session: &str, name: &str) -> Result<Vec<u8>, String>;
}

pub(crate) fn valid_shot(n: &str) -> bool {
    n.len() <= 20
        && n.ends_with(".jpg")
        && n.len() > 4
        && n[..n.len() - 4].chars().all(|c| c.is_ascii_digit())
}

/// Workers as threads of this process, with a directory per box: the demo provider and the tests. The browser is still a
/// real Chromium; only the box is pretend. The lines are sealed all the same.
pub struct InProcessBackend {
    base: PathBuf,
    workers: Mutex<HashMap<String, Arc<InProc>>>,
    next: Mutex<u64>,
    /// When a test asks: every line a worker wrote, as it would land in a run's log on a
    /// box, to prove it holds nothing readable. Off otherwise, so a long-running demo server keeps nothing.
    log: Mutex<Option<Vec<String>>>,
}

struct InProc {
    to_worker: Sender<Vec<u8>>,
    from_worker: Mutex<Receiver<String>>,
}

struct ChanReader {
    rx: Receiver<Vec<u8>>,
    buf: Vec<u8>,
    at: usize,
}

impl Read for ChanReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        while self.at >= self.buf.len() {
            match self.rx.recv() {
                Ok(b) => {
                    self.buf = b;
                    self.at = 0;
                }
                Err(_) => return Ok(0),
            }
        }
        let n = out.len().min(self.buf.len() - self.at);
        out[..n].copy_from_slice(&self.buf[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }
}

struct ChanWriter {
    tx: Sender<String>,
    line: Vec<u8>,
}

impl Write for ChanWriter {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.line.extend_from_slice(b);
        while let Some(i) = self.line.iter().position(|c| *c == b'\n') {
            let l: Vec<u8> = self.line.drain(..=i).collect();
            let _ = self
                .tx
                .send(String::from_utf8_lossy(&l).trim_end().to_string());
        }
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl InProcessBackend {
    pub fn new(base: impl Into<PathBuf>) -> Self {
        Self {
            base: base.into(),
            workers: Mutex::new(HashMap::new()),
            next: Mutex::new(0),
            log: Mutex::new(None),
        }
    }
    /// Keep every line the workers write from now on (tests only).
    #[cfg(test)]
    pub fn capture(&self) {
        *Self::lock(&self.log) = Some(Vec::new());
    }
    /// The lines kept since `capture`.
    #[cfg(test)]
    pub fn captured(&self) -> Vec<String> {
        Self::lock(&self.log).clone().unwrap_or_default()
    }
    fn work(&self, box_name: &str) -> PathBuf {
        self.base.join(box_name)
    }
    fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
        m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl BrowserBackend for InProcessBackend {
    fn start(&self, box_name: &str, first_line: &str, _run: &WorkerRun) -> Result<String, String> {
        let (to_worker, rx_in) = mpsc::channel::<Vec<u8>>();
        let (tx_out, from_worker) = mpsc::channel::<String>();
        let mut first = first_line.trim().to_string();
        let start: Start = serde_json::from_str(&first).map_err(|e| e.to_string())?;
        first.zeroize();
        std::thread::spawn(move || {
            let input = BufReader::new(ChanReader {
                rx: rx_in,
                buf: Vec::new(),
                at: 0,
            });
            let mut out = ChanWriter {
                tx: tx_out,
                line: Vec::new(),
            };
            // a failure to start is itself a sealed line the worker wrote
            let _ = ozbox_browser::worker::run(start, input, &mut out);
        });
        let mut n = Self::lock(&self.next);
        *n += 1;
        let h = format!("inproc-{box_name}-{n}");
        Self::lock(&self.workers).insert(
            h.clone(),
            Arc::new(InProc {
                to_worker,
                from_worker: Mutex::new(from_worker),
            }),
        );
        Ok(h)
    }

    fn send(&self, _b: &str, handle: &str, line: &str) -> Result<(), String> {
        let w = Self::lock(&self.workers)
            .get(handle)
            .cloned()
            .ok_or("that session is not running")?;
        let mut l = line.to_string();
        l.push('\n');
        w.to_worker
            .send(l.into_bytes())
            .map_err(|_| "the browser session has ended".to_string())
    }

    fn next_line(
        &self,
        _b: &str,
        handle: &str,
        deadline: Instant,
    ) -> Result<Option<String>, String> {
        let w = Self::lock(&self.workers)
            .get(handle)
            .cloned()
            .ok_or("that session is not running")?;
        let rx = Self::lock(&w.from_worker);
        match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(l) => {
                if let Some(log) = Self::lock(&self.log).as_mut() {
                    log.push(l.clone());
                }
                Ok(Some(l))
            }
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => Err("the browser session has ended".into()),
        }
    }

    fn stop(&self, _b: &str, handle: &str) {
        Self::lock(&self.workers).remove(handle);
    }

    fn roots(&self, box_name: &str) -> (String, String) {
        let w = self.work(box_name);
        (
            w.join(".ozbox/browser").to_string_lossy().into_owned(),
            w.to_string_lossy().into_owned(),
        )
    }

    fn list_sessions(&self, box_name: &str) -> Result<Vec<Meta>, String> {
        Ok(record::list_sessions(Path::new(&self.roots(box_name).0)))
    }

    fn steps(&self, box_name: &str, session: &str) -> Result<Vec<Step>, String> {
        record::load_steps(Path::new(&self.roots(box_name).0), session)
    }

    fn shot(&self, box_name: &str, session: &str, name: &str) -> Result<Vec<u8>, String> {
        if !record::valid_session_id(session) || !valid_shot(name) {
            return Err("no such picture".into());
        }
        std::fs::read(
            record::session_dir(Path::new(&self.roots(box_name).0), session)
                .join("shots")
                .join(name),
        )
        .map_err(|_| "no such picture".into())
    }
}

/// Workers as runs on the box, through its daemon (ADR 0019): the worker is `ozbox browser-worker` with its standard input
/// kept open, a request is a line sent to it and a reply is a line in the run's log. The run is a *controlled* run: the
/// daemon answers its input, its log and its stop only to the caller that started it (this server, holding the run's
/// capability), so another process on the box cannot drive it or read it. Nothing new listens on the box.
pub struct DaemonBrowserBackend {
    transport: Mutex<Box<dyn RunTransport>>,
    files: Arc<dyn HostBackend>,
    reads: Mutex<HashMap<String, Cursor>>,
    poll: Duration,
}

#[derive(Default)]
struct Cursor {
    run: String,
    from: u64,
    partial: Vec<u8>,
    exited: bool,
}

/// A door enrolment's key (`terminal-<pid>-<start time>`, see `crate::agent_mcp`), as against a run's id or `person:<name>`.
pub fn is_terminal_key(key: &str) -> bool {
    key.starts_with("terminal-")
}

/// May a caller with this key drive a session its opener (a key, or none for one a person resumed) opened? A terminal
/// enrolment drives only its own; everyone else never drives a terminal enrolment's.
pub fn may_drive(caller: &str, opener: Option<&str>) -> bool {
    if is_terminal_key(caller) {
        opener == Some(caller)
    } else {
        !opener.is_some_and(is_terminal_key)
    }
}

pub const BOX_ROOT: &str = "/work/.ozbox/browser";

impl DaemonBrowserBackend {
    pub fn new(transport: Box<dyn RunTransport>, files: Arc<dyn HostBackend>) -> Self {
        Self {
            transport: Mutex::new(transport),
            files,
            reads: Mutex::new(HashMap::new()),
            poll: Duration::from_millis(120),
        }
    }

    fn t(&self) -> std::sync::MutexGuard<'_, Box<dyn RunTransport>> {
        self.transport
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn cursors(&self) -> std::sync::MutexGuard<'_, HashMap<String, Cursor>> {
        self.reads
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn exec_text(
        &self,
        box_name: &str,
        script: &str,
        arg: &str,
        cap: usize,
    ) -> Result<String, String> {
        let cwd = self.files.resolve(box_name, "/work")?;
        let o = self.files.exec(
            box_name,
            &crate::host_tools::backend::ExecReq {
                argv: vec![
                    "sh".into(),
                    "-c".into(),
                    script.into(),
                    "sh".into(),
                    arg.into(),
                ],
                cwd: cwd.abs,
                timeout: Duration::from_secs(30),
                cap,
                stdin: None,
            },
        )?;
        if o.code == Some(0) {
            Ok(o.output)
        } else {
            Err("that could not be read".into())
        }
    }
}

/// The run a browsing session is on the box: its first line on standard input, a memory cap the box enforces and
/// admits by, and the daemon's capability so nothing else on the box can drive it.
pub fn worker_launch(first_line: &str, run: &WorkerRun) -> Launch {
    let mut stdin = first_line.to_string();
    if !stdin.ends_with('\n') {
        stdin.push('\n');
    }
    Launch {
        argv: vec!["ozbox".into(), "browser-worker".into()],
        cwd: Some("/work".into()),
        env: Default::default(),
        labels: [("ozbox.browser".to_string(), "1".to_string())].into(),
        max_runtime_s: Some(run.max_runtime_s),
        memory_request_bytes: run.memory_bytes,
        memory_max_bytes: Some(run.memory_bytes),
        stdin: Some(stdin),
        keep_stdin_open: true,
        require_capability: true,
    }
}

impl BrowserBackend for DaemonBrowserBackend {
    fn start(&self, box_name: &str, first_line: &str, run: &WorkerRun) -> Result<String, String> {
        let mut launch = worker_launch(first_line, run);
        let started = self.t().launch(box_name, &launch);
        if let Some(s) = launch.stdin.as_mut() {
            s.zeroize();
        }
        let run_id = started?;
        let handle = format!("run-{run_id}");
        self.cursors().insert(
            handle.clone(),
            Cursor {
                run: run_id,
                ..Cursor::default()
            },
        );
        Ok(handle)
    }

    fn send(&self, box_name: &str, handle: &str, line: &str) -> Result<(), String> {
        let run = self
            .cursors()
            .get(handle)
            .map(|c| c.run.clone())
            .ok_or("that session is not running")?;
        let mut l = line.to_string();
        l.push('\n');
        self.t().send(box_name, &run, &l, false)
    }

    fn next_line(
        &self,
        box_name: &str,
        handle: &str,
        deadline: Instant,
    ) -> Result<Option<String>, String> {
        loop {
            let (run, from) = {
                let mut g = self.cursors();
                let c = g.get_mut(handle).ok_or("that session is not running")?;
                if let Some(i) = c.partial.iter().position(|b| *b == b'\n') {
                    let line: Vec<u8> = c.partial.drain(..=i).collect();
                    return Ok(Some(String::from_utf8_lossy(&line).trim_end().to_string()));
                }
                if c.exited {
                    return Err("the browser session has ended".into());
                }
                (c.run.clone(), c.from)
            };
            let chunk = self.t().read_log(box_name, &run, from)?;
            let got = !chunk.bytes.is_empty();
            if let Some(c) = self.cursors().get_mut(handle) {
                c.from = chunk.next;
                c.partial.extend_from_slice(&chunk.bytes);
                if chunk.exited.is_some() && chunk.bytes.is_empty() {
                    c.exited = true;
                }
            }
            if !got {
                if Instant::now() >= deadline {
                    return Ok(None);
                }
                std::thread::sleep(self.poll);
            }
        }
    }

    fn stop(&self, box_name: &str, handle: &str) {
        let c = self.cursors().remove(handle);
        if let Some(c) = c {
            let _ = self.t().stop(box_name, &c.run);
        }
    }

    fn roots(&self, _box_name: &str) -> (String, String) {
        (BOX_ROOT.into(), "/work".into())
    }

    fn list_sessions(&self, box_name: &str) -> Result<Vec<Meta>, String> {
        let out = self.exec_text(box_name, r#"for f in "$1"/sessions/*/meta.json; do [ -f "$f" ] && { cat "$f" | tr -d '\n'; echo; }; done; true"#, BOX_ROOT, 512 * 1024)?;
        let mut v: Vec<Meta> = out
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();
        v.sort_by_key(|m| std::cmp::Reverse(m.started_ms));
        Ok(v)
    }

    fn steps(&self, box_name: &str, session: &str) -> Result<Vec<Step>, String> {
        if !record::valid_session_id(session) {
            return Err("that is not a session".into());
        }
        let out = self.exec_text(
            box_name,
            r#"cat "$1" 2>/dev/null; true"#,
            &format!("{BOX_ROOT}/sessions/{session}/steps.jsonl"),
            2 * 1024 * 1024,
        )?;
        Ok(out
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect())
    }

    fn shot(&self, box_name: &str, session: &str, name: &str) -> Result<Vec<u8>, String> {
        if !record::valid_session_id(session) || !valid_shot(name) {
            return Err("no such picture".into());
        }
        let out = self.exec_text(
            box_name,
            r#"base64 < "$1" | tr -d '\n'"#,
            &format!("{BOX_ROOT}/sessions/{session}/shots/{name}"),
            2 * 1024 * 1024,
        )?;
        ozbox_browser::b64::decode(out.trim())
    }
}

// ---- the host ------------------------------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct BrowserEvent {
    /// `challenge`, `paused`, `limit`, `limit_warning`, `takeover`.
    pub kind: &'static str,
    pub session: String,
    pub box_name: String,
    pub text: String,
}

/// One session's end of the sealed channel, and the replies that arrived for calls still waiting.
struct Lane {
    chan: Mutex<Channel>,
    /// Only one caller reads the worker's lines at a time, in order (each must open after the last).
    reader: Mutex<()>,
    mail: Mutex<HashMap<u64, Reply>>,
    /// The person holding the session, when one has taken over.
    holder: Mutex<Option<String>>,
}

#[derive(Clone)]
struct Sess {
    box_name: String,
    /// The key of the caller that opened it (a run's id, `person:<name>`, or a door enrolment's own key); None when a person
    /// resumed it from the dashboard.
    opener: Option<String>,
    /// It was opened by a door enrolment while the person's standing permission was in force. On a production box
    /// a plain terminal agent could never have opened it, so once the standing permission has ended it is not driven by one.
    opened_standing: bool,
    handle: String,
    policy: BrowserPolicy,
    warned: bool,
    lane: Arc<Lane>,
}

/// Who is calling a browser tool through the tool host, and where: what `prepare` needs besides the caller's key.
#[derive(Debug, Clone, Copy)]
pub struct Caller<'a> {
    /// The caller's key: a run's id, `person:<name>`, or a door enrolment's own key.
    pub key: &'a str,
    pub actor: ActorKind,
    /// The box the call is on is tagged production.
    pub production: bool,
}

/// A person, as the dashboard knows them after it checked their sign-in (and, where the act needs it, a fresh second
/// factor). Taking over, handing back and a person's input take one of these; the agent's tools have no way to make one.
pub struct PersonAct {
    who: String,
}

impl PersonAct {
    /// Only the dashboard's routes make one, after their checks (see `serve::browser_routes`).
    pub(crate) fn checked(who: &str) -> Self {
        Self {
            who: who.chars().take(60).collect(),
        }
    }
    pub fn who(&self) -> &str {
        &self.who
    }
}

/// The browsing settings: a default and per-project overrides, in a file beside the task store (on the server, not the box).
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PolicyFile {
    #[serde(default)]
    pub default: BrowserPolicy,
    #[serde(default)]
    pub projects: std::collections::BTreeMap<String, BrowserPolicy>,
}

/// Whether a run (by its key) uses a local model.
pub type LocalModelCheck = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// Whether a door enrolment's key is still the door's current one (see [`BrowserHost::set_key_current`]).
pub type KeyCurrent = Arc<dyn Fn(&str) -> bool + Send + Sync>;

pub struct BrowserHost {
    pub backend: Arc<dyn BrowserBackend>,
    store: TaskStore,
    policy_path: PathBuf,
    sessions: Mutex<HashMap<String, Sess>>,
    waits: Mutex<HashMap<String, Instant>>,
    events: Mutex<Vec<BrowserEvent>>,
    next_id: Mutex<u64>,
    /// Tests shorten the wait for a person.
    pub wait_override: Mutex<Option<Duration>>,
    /// Whether the run asking is on a local model, for sites that need one. Absent: such sites are refused.
    pub local_model: Option<LocalModelCheck>,
    /// Whether a door enrolment's key is still the door's current one (set by the door), so a session that finishes opening
    /// after the door changed is not orphaned. Absent: every key counts as current.
    key_current: Mutex<Option<KeyCurrent>>,
}

fn lk<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn now_ms() -> u64 {
    ozbox_browser::worker::now_ms()
}

/// The most replies kept for callers that stopped waiting.
const MAIL_MAX: usize = 64;

impl BrowserHost {
    pub fn new(backend: Arc<dyn BrowserBackend>, store: TaskStore, policy_path: PathBuf) -> Self {
        Self {
            backend,
            store,
            policy_path,
            sessions: Mutex::new(HashMap::new()),
            waits: Mutex::new(HashMap::new()),
            events: Mutex::new(Vec::new()),
            next_id: Mutex::new(0),
            wait_override: Mutex::new(None),
            local_model: None,
            key_current: Mutex::new(None),
        }
    }

    // ---- settings

    pub fn policy_file(&self) -> PolicyFile {
        std::fs::read_to_string(&self.policy_path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    pub fn policy(&self, project: Option<&str>) -> BrowserPolicy {
        let f = self.policy_file();
        project
            .and_then(|p| f.projects.get(p).cloned())
            .unwrap_or(f.default)
    }

    /// Change the settings. Returns what changed, as the audit chain records it (see [`settings_diff`]).
    pub fn set_policy(&self, project: Option<&str>, p: BrowserPolicy) -> Result<String, String> {
        p.validate()?;
        let mut f = self.policy_file();
        let before = match project {
            Some(name) if ozbox_browser::policy::valid_name(name) => {
                f.projects.insert(name.to_string(), p.clone())
            }
            Some(_) => {
                return Err("a project name is letters, digits, dashes and underscores".into())
            }
            None => Some(std::mem::replace(&mut f.default, p.clone())),
        };
        let text = serde_json::to_string_pretty(&f).map_err(|e| e.to_string())?;
        let tmp = self.policy_path.with_extension("json.tmp");
        write_private(&tmp, &text).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, &self.policy_path).map_err(|e| e.to_string())?;
        Ok(settings_diff(&before.unwrap_or_default(), &p))
    }

    // ---- events and the audit chain

    pub fn drain_events(&self) -> Vec<BrowserEvent> {
        std::mem::take(&mut *lk(&self.events))
    }

    fn event(&self, kind: &'static str, s: &Sess, id: &str, text: &str) {
        lk(&self.events).push(BrowserEvent {
            kind,
            session: id.to_string(),
            box_name: s.box_name.clone(),
            text: text.to_string(),
        });
    }

    /// A person's act or a lifecycle step, as an action word and the session id. Never an input, a page or a value.
    pub fn audit(&self, actor: &str, word: &str, session: &str) {
        self.audit_detail(actor, word, &format!("session={session}"));
    }

    pub fn audit_detail(&self, actor: &str, word: &str, detail: &str) {
        let now = now_ms();
        let _ = self
            .store
            .update(|b| b.record(now, actor, word, None, detail));
    }

    // ---- sessions

    fn sess(&self, id: &str, box_name: Option<&str>) -> Result<Sess, ToolError> {
        let s = lk(&self.sessions).get(id).cloned().ok_or_else(|| {
            ToolError::NotFound(
                "there is no such browser session (open one with browser_open)".into(),
            )
        })?;
        if box_name.is_some_and(|b| b != s.box_name) {
            return Err(ToolError::NotFound(
                "there is no such browser session".into(),
            ));
        }
        Ok(s)
    }

    /// A session that is there without a browser behind it, opened by `opener`: how a test proves who may drive what.
    #[cfg(test)]
    #[allow(clippy::unwrap_used)]
    pub(crate) fn plant_session(&self, id: &str, box_name: &str, opener: Option<&str>) {
        self.plant_session_as(id, box_name, opener, false);
    }

    /// As [`BrowserHost::plant_session`], saying whether the opener held standing permission when it opened it.
    #[cfg(test)]
    #[allow(clippy::unwrap_used)]
    pub(crate) fn plant_session_as(
        &self,
        id: &str,
        box_name: &str,
        opener: Option<&str>,
        opened_standing: bool,
    ) {
        let key = SessionKey::generate().unwrap();
        let s = Sess {
            box_name: box_name.to_string(),
            opener: opener.map(str::to_string),
            opened_standing,
            handle: "none".into(),
            policy: BrowserPolicy::default(),
            warned: false,
            lane: Arc::new(Lane {
                chan: Mutex::new(Channel::host(&key, id).unwrap()),
                reader: Mutex::new(()),
                mail: Mutex::new(HashMap::new()),
                holder: Mutex::new(None),
            }),
        };
        lk(&self.sessions).insert(id.to_string(), s);
    }

    pub fn sessions(&self) -> Vec<(String, String)> {
        let mut v: Vec<_> = lk(&self.sessions)
            .iter()
            .map(|(k, s)| (k.clone(), s.box_name.clone()))
            .collect();
        v.sort();
        v
    }

    fn fresh_id(&self) -> String {
        let mut n = lk(&self.next_id);
        *n += 1;
        let mut rnd = [0u8; 4];
        let _ = getrandom::getrandom(&mut rnd);
        format!(
            "b{}-{:02x}{:02x}{:02x}{:02x}",
            *n, rnd[0], rnd[1], rnd[2], rnd[3]
        )
    }

    /// Open (or, with an existing id whose recording is paused, resume) a session. `opener` is the key of the caller that
    /// opened it (see `may_drive`).
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        &self,
        box_name: &str,
        id: Option<String>,
        device: Device,
        project: Option<&str>,
        run: Option<String>,
        allowed: &[String],
        opener: Option<&str>,
    ) -> Result<String, ToolError> {
        self.open_as(box_name, id, device, project, run, allowed, opener, false)
    }

    /// Set how the host asks whether a door enrolment's key is still current.
    pub fn set_key_current(&self, current: KeyCurrent) {
        *lk(&self.key_current) = Some(current);
    }

    /// As [`BrowserHost::open`], saying whether the opener was a standing enrolment.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn open_as(
        &self,
        box_name: &str,
        id: Option<String>,
        device: Device,
        project: Option<&str>,
        run: Option<String>,
        allowed: &[String],
        opener: Option<&str>,
        opened_standing: bool,
    ) -> Result<String, ToolError> {
        let policy = self.policy(project);
        let count = lk(&self.sessions)
            .values()
            .filter(|s| s.box_name == box_name)
            .count() as u32;
        if count >= policy.max_sessions {
            return Err(ToolError::Refused(format!(
                "this box already has {count} browser sessions open, which is the limit ({}). Close one first, or raise the limit in the browsing settings.",
                policy.max_sessions
            )));
        }
        let id = id.unwrap_or_else(|| self.fresh_id());
        let (root, work) = self.backend.roots(box_name);
        let key = SessionKey::generate().map_err(ToolError::Failed)?;
        let chan = Channel::host(&key, &id).map_err(ToolError::Failed)?;
        let wr = WorkerRun {
            max_runtime_s: (u64::from(policy.max_minutes) + u64::from(policy.wait_minutes)) * 60
                + 300,
            memory_bytes: u64::from(policy.memory_mb) * 1024 * 1024,
        };
        let start = Start {
            session: id.clone(),
            key,
            root,
            work,
            device,
            policy: policy.clone(),
            allowed_hosts: allowed.to_vec(),
            run,
            private_root: self.backend.private_root(box_name),
            memory_max_bytes: Some(wr.memory_bytes),
            max_runtime_s: Some(wr.max_runtime_s),
        };
        let mut first =
            serde_json::to_string(&start).map_err(|e| ToolError::Failed(e.to_string()))?;
        drop(start);
        let started = self.backend.start(box_name, &first, &wr);
        first.zeroize();
        let handle = started.map_err(ToolError::Failed)?;
        let s = Sess {
            box_name: box_name.to_string(),
            opener: opener.map(str::to_string),
            opened_standing,
            handle,
            policy,
            warned: false,
            lane: Arc::new(Lane {
                chan: Mutex::new(chan),
                reader: Mutex::new(()),
                mail: Mutex::new(HashMap::new()),
                holder: Mutex::new(None),
            }),
        };
        // the first line out is the worker's, sealed with this session's key: proof it is the worker this server started
        match self.wait_reply(&s, 0, Instant::now() + OPEN_TIMEOUT) {
            Ok(r) if r.ok => {}
            Ok(r) => {
                self.backend.stop(box_name, &s.handle);
                return Err(ToolError::Failed(
                    r.error
                        .unwrap_or_else(|| "the browser could not be started".into()),
                ));
            }
            Err(e) => {
                self.backend.stop(box_name, &s.handle);
                return Err(ToolError::Failed(match e {
                    ToolError::Failed(m) if m.contains("in time") => {
                        "the browser did not start in time (the box may not have the memory free that a session needs)"
                            .into()
                    }
                    other => other.message().to_string(),
                }));
            }
        }
        lk(&self.sessions).insert(id.clone(), s);
        // The sweep that ends a door's old sessions runs once, when the door changes, and a browser takes seconds to start. A
        // session whose opener's key stopped being current while it was starting would never be swept and nobody can drive it,
        // so it is looked at again now it is in the table: either the sweep saw it, or this check sees the door has moved
        // (the door moves its epoch BEFORE it sweeps).
        if let Some(key) = opener.filter(|k| is_terminal_key(k)) {
            let current = lk(&self.key_current).clone();
            if current.is_some_and(|c| !c(key)) {
                let _ = self.close(&id);
                return Err(ToolError::Refused(
                    "the door for coding agents changed while the browser was starting, so this session was closed. Ask again".into(),
                ));
            }
        }
        Ok(id)
    }

    fn next_req_id(&self) -> u64 {
        let mut n = lk(&self.next_id);
        *n += 1;
        *n
    }

    /// Seal and send one request; then wait for its reply.
    fn req(&self, s: &Sess, op: Op, timeout: Duration) -> Result<Reply, ToolError> {
        let pause = matches!(op, Op::Pause { .. });
        let id = self.next_req_id();
        let plain = serde_json::to_vec(&Request { id, op })
            .map_err(|e| ToolError::Failed(e.to_string()))?;
        {
            // sealed and sent under one lock, so the numbering on the wire is the order the worker reads
            let mut c = lk(&s.lane.chan);
            let line = c.seal(id, &plain);
            self.backend
                .send(&s.box_name, &s.handle, &line)
                .map_err(ToolError::Failed)?;
        }
        let deadline = Instant::now() + timeout;
        if pause {
            // a pause may be answered by the worker's own pause, which has no request id
            return self.wait_either(s, id, deadline);
        }
        self.wait_reply(s, id, deadline)
    }

    fn wait_either(&self, s: &Sess, id: u64, deadline: Instant) -> Result<Reply, ToolError> {
        loop {
            {
                let mut mail = lk(&s.lane.mail);
                if let Some(r) = mail.remove(&id).or_else(|| mail.remove(&0)) {
                    return Ok(r);
                }
            }
            self.pull(s, deadline)?;
            if Instant::now() >= deadline {
                return Err(ToolError::Failed(
                    "the browser did not answer in time".into(),
                ));
            }
        }
    }

    /// Wait for the reply to `id`, reading the worker's lines in turn with any other caller waiting on the same session.
    fn wait_reply(&self, s: &Sess, id: u64, deadline: Instant) -> Result<Reply, ToolError> {
        loop {
            if let Some(r) = lk(&s.lane.mail).remove(&id) {
                return Ok(r);
            }
            self.pull(s, deadline)?;
            if Instant::now() >= deadline {
                if let Some(r) = lk(&s.lane.mail).remove(&id) {
                    return Ok(r);
                }
                return Err(ToolError::Failed(
                    "the browser did not answer in time".into(),
                ));
            }
        }
    }

    /// Read and open the next line, if this caller gets the turn; file the reply by its id. A line that does not open with
    /// the session's key (written into the run's log by something other than the worker) is dropped.
    fn pull(&self, s: &Sess, deadline: Instant) -> Result<(), ToolError> {
        let Ok(_turn) = s.lane.reader.try_lock() else {
            std::thread::sleep(Duration::from_millis(10));
            return Ok(());
        };
        let slice = (Instant::now() + Duration::from_millis(300)).min(deadline);
        let Some(line) = self
            .backend
            .next_line(&s.box_name, &s.handle, slice)
            .map_err(ToolError::Failed)?
        else {
            return Ok(());
        };
        let opened = lk(&s.lane.chan).open(&line);
        if let Ok((_, plain)) = opened {
            if let Ok(r) = serde_json::from_slice::<Reply>(&plain) {
                let mut mail = lk(&s.lane.mail);
                if mail.len() >= MAIL_MAX {
                    if let Some(oldest) = mail.keys().min().copied() {
                        mail.remove(&oldest);
                    }
                }
                mail.insert(r.id, r);
            }
        }
        Ok(())
    }

    pub fn call_op(&self, id: &str, op: Op, timeout: Duration) -> Result<Reply, ToolError> {
        let s = self.sess(id, None)?;
        self.req(&s, op, timeout)
    }

    pub fn close(&self, id: &str) -> Result<(), ToolError> {
        let s = self.sess(id, None)?;
        let _ = self.req(&s, Op::Close, Duration::from_secs(15));
        self.backend.stop(&s.box_name, &s.handle);
        lk(&self.sessions).remove(id);
        lk(&self.waits).remove(id);
        Ok(())
    }

    /// Close every session a terminal enrolment opened whose key `stranded` says can never come back (the door's key changed).
    /// Nobody can drive such a session, so leaving it would hold a browser until the dashboard restarts. Returns how
    /// many were closed.
    pub fn close_stranded(&self, stranded: &dyn Fn(&str) -> bool) -> usize {
        let ids: Vec<String> = lk(&self.sessions)
            .iter()
            .filter(|(_, s)| {
                s.opener
                    .as_deref()
                    .is_some_and(|k| is_terminal_key(k) && stranded(k))
            })
            .map(|(id, _)| id.clone())
            .collect();
        ids.iter().filter(|id| self.close(id).is_ok()).count()
    }

    /// Who holds a session now, if a person does.
    pub fn holder(&self, id: &str) -> Option<String> {
        lk(&self.sessions)
            .get(id)
            .and_then(|s| lk(&s.lane.holder).clone())
    }

    pub fn takeover(&self, id: &str, person: &PersonAct) -> Result<Value, ToolError> {
        let s = self.sess(id, None)?;
        let r = self.req(
            &s,
            Op::Takeover {
                who: person.who().to_string(),
            },
            Duration::from_secs(30),
        )?;
        if r.ok {
            *lk(&s.lane.holder) = Some(person.who().to_string());
        }
        self.audit(&format!("person:{}", person.who()), "browser.takeover", id);
        reply_value(r)
    }

    pub fn handback(&self, id: &str, person: &PersonAct) -> Result<Value, ToolError> {
        let s = self.sess(id, None)?;
        let r = self.req(&s, Op::Handback, Duration::from_secs(30))?;
        if r.ok {
            *lk(&s.lane.holder) = None;
            self.audit(&format!("person:{}", person.who()), "browser.handback", id);
        }
        reply_value(r)
    }

    /// A person's pointer or keys, relayed only for the person who holds the session.
    pub fn input(&self, id: &str, person: &PersonAct, event: Value) -> Result<(), ToolError> {
        let s = self.sess(id, None)?;
        let holder = lk(&s.lane.holder).clone();
        if holder.as_deref() != Some(person.who()) {
            return Err(ToolError::Refused(
                "only the person who took over this browser can send it input".into(),
            ));
        }
        reply_value(self.req(&s, Op::Input { event }, Duration::from_secs(15))?).map(|_| ())
    }

    pub fn frame(&self, id: &str) -> Result<Value, ToolError> {
        reply_value(self.call_op(id, Op::Frame, Duration::from_secs(20))?)
    }

    pub fn status(&self, id: &str) -> Result<Value, ToolError> {
        let mut v = reply_value(self.call_op(id, Op::Status, Duration::from_secs(15))?)?;
        if let Some(h) = self.holder(id) {
            v["holder"] = json!(h);
        }
        Ok(v)
    }

    pub fn pause(&self, id: &str, reason: &str) -> Result<(), ToolError> {
        let s = self.sess(id, None)?;
        let r = self.req(
            &s,
            Op::Pause {
                reason: reason.to_string(),
            },
            Duration::from_secs(30),
        )?;
        self.backend.stop(&s.box_name, &s.handle);
        lk(&self.sessions).remove(id);
        self.audit("browser", "browser.pause", id);
        self.event("paused", &s, id, reason);
        reply_value(r).map(|_| ())
    }

    /// Start a paused session again where it was.
    pub fn resume(
        &self,
        box_name: &str,
        id: &str,
        allowed: &[String],
        person: &PersonAct,
    ) -> Result<String, ToolError> {
        if lk(&self.sessions).contains_key(id) {
            return Err(ToolError::Refused("that session is already running".into()));
        }
        let metas = self
            .backend
            .list_sessions(box_name)
            .map_err(ToolError::Failed)?;
        let m = metas
            .into_iter()
            .find(|m| m.session == id)
            .ok_or_else(|| ToolError::NotFound("there is no such recording".into()))?;
        if m.state != "paused" {
            return Err(ToolError::Refused(
                "only a paused session can be resumed".into(),
            ));
        }
        let device = Device::parse(&m.device).unwrap_or_default();
        let id = self.open(
            box_name,
            Some(id.to_string()),
            device,
            None,
            m.run.clone(),
            allowed,
            None,
        )?;
        self.audit(&format!("person:{}", person.who()), "browser.resume", &id);
        Ok(id)
    }

    /// How long this session has waited for a person; at the limit the task pauses between actions and says how to resume.
    pub fn waited_too_long(&self, id: &str, box_name: &str) -> Option<String> {
        let started = *lk(&self.waits)
            .entry(id.to_string())
            .or_insert_with(Instant::now);
        let limit = lk(&self.wait_override).unwrap_or_else(|| {
            let m = lk(&self.sessions)
                .get(id)
                .map_or(30, |s| s.policy.wait_minutes);
            Duration::from_secs(u64::from(m) * 60)
        });
        if started.elapsed() < limit {
            return None;
        }
        lk(&self.waits).remove(id);
        let _ = self.pause(id, "waited too long for a person");
        let _ = box_name;
        Some(format!(
            "Nobody answered for {} minutes, so the browser task is paused where it was: nothing was submitted. A person can resume it from the dashboard (Browser, Resume). Stop here until then.",
            limit.as_secs() / 60
        ))
    }

    pub fn clear_waiting(&self, id: &str) {
        lk(&self.waits).remove(id);
    }

    // ---- preparing a tool call

    pub(crate) fn prepare(
        self: &Arc<Self>,
        name: &str,
        a: &Value,
        box_name: &str,
        caller: Caller<'_>,
        perms: &PermConfig,
        _now: u64,
    ) -> Result<(Prepared, Extra), ToolError> {
        let me = Arc::clone(self);
        let bx = box_name.to_string();
        let run_key = caller.key;
        if name == "browser_open" {
            let device = match a.get("device").and_then(Value::as_str) {
                None => Device::Desktop,
                Some(d) => Device::parse(d).ok_or_else(|| {
                    ToolError::Invalid("device is desktop, tablet or phone".into())
                })?,
            };
            let project = a.get("project").and_then(Value::as_str).map(str::to_string);
            let run = a
                .get("run")
                .and_then(Value::as_str)
                .map(|r| r.chars().take(80).collect::<String>());
            let allowed = perms.browser_hosts.clone();
            let b2 = bx.clone();
            let opener = run_key.to_string();
            let standing = caller.actor == ActorKind::TerminalStanding;
            return Ok((
                Prepared {
                    writes: Some(true),
                    path: Some(bx),
                    command: Some(vec!["browser".into(), "open".into()]),
                    sensitive: false,
                    summary: format!("open a {device:?} browser session").to_ascii_lowercase(),
                    env: None,
                    job: Box::new(move |_be, _bx| {
                        let id = me.open_as(
                            &b2,
                            None,
                            device,
                            project.as_deref(),
                            run,
                            &allowed,
                            Some(&opener),
                            standing,
                        )?;
                        Ok(
                            json!({ "session": id, "device": format!("{device:?}").to_ascii_lowercase(), "next": "Call browser_navigate, then browser_snapshot." }),
                        )
                    }),
                },
                Extra {
                    baseline: true,
                    ..Extra::default()
                },
            ));
        }
        let sid = a
            .get("session")
            .and_then(Value::as_str)
            .ok_or_else(|| ToolError::Invalid("session is required".into()))?
            .to_string();
        let s = self.sess(&sid, Some(box_name))?;
        // ADR 0043: a coding agent that came through the terminal door drives only the sessions its own
        // enrolment opened, and nobody else's session is driven by one. Session ids are folder names the box user can read.
        if !may_drive(run_key, s.opener.as_deref()) {
            return Err(ToolError::NotFound(
                "there is no such browser session (open one with browser_open)".into(),
            ));
        }
        // A session opened under standing permission on a production box is one a plain terminal agent could never
        // have opened (production refuses it any changing call, and opening is one). When the standing permission has ended, its
        // reads (snapshot, extract, screenshot) are refused as well, so a page a person's approval signed in cannot go on being
        // read. A person's own agent and a run are unaffected; so is a session on a sandbox box.
        if s.opened_standing && caller.production && caller.actor == ActorKind::Terminal {
            return Err(ToolError::Refused(
                "this browser session was opened while standing permission was on, on a production box, and that has ended, so this agent can no longer use it. A person can close it from the dashboard; it also ends by itself when its time is up".into(),
            ));
        }
        if name == "browser_close" {
            return Ok((
                Prepared {
                    writes: Some(true),
                    path: Some(bx),
                    command: Some(vec!["browser".into(), "close".into()]),
                    sensitive: false,
                    summary: "close the browser session".into(),
                    env: None,
                    job: Box::new(move |_be, _bx| {
                        me.close(&sid)?;
                        Ok(json!({ "closed": true }))
                    }),
                },
                Extra {
                    baseline: true,
                    ..Extra::default()
                },
            ));
        }
        let action = to_action(name, a)?;
        action.validate().map_err(ToolError::Invalid)?;
        // the worker's preview: what is this, how risky, which field, where would it go, and a fingerprint of it
        let pv = self.req(
            &s,
            Op::Preview {
                action: action.clone(),
            },
            ACT_TIMEOUT,
        )?;
        let extra_session = Some(sid.clone());
        let refuse = |why: &'static str, msg: String| -> Result<(Prepared, Extra), ToolError> {
            Ok((
                Prepared {
                    writes: Some(true),
                    path: Some(bx.clone()),
                    command: Some(action.audit_words(None)),
                    sensitive: false,
                    summary: "refused".into(),
                    env: None,
                    job: Box::new(|_be, _bx| Err(ToolError::Refused("refused".into()))),
                },
                Extra {
                    refuse: Some((why, msg)),
                    baseline: true,
                    session: extra_session.clone(),
                    ..Extra::default()
                },
            ))
        };
        if !pv.ok {
            let msg = pv.error.clone().unwrap_or_default();
            return match pv.code.as_deref() {
                Some("person_holds") => refuse("browser_person_holds", msg),
                Some("refused") => refuse("browser_refused", msg),
                Some("limit") => {
                    let _ = self.pause(&sid, &msg);
                    refuse("browser_limit", format!("{msg}. The task is paused where it was and nothing is half-done; a person can resume it from the dashboard."))
                }
                Some("invalid") => Err(ToolError::Invalid(msg)),
                _ => Err(ToolError::Failed(msg)),
            };
        }
        let r = &pv.result;
        let host = r["host"].as_str().unwrap_or("").to_string();
        let gate = r["gate"].as_str().unwrap_or("allow");
        let risk = r["risk"].as_str().unwrap_or("none").to_string();
        let fingerprint = r["fingerprint"].as_str().unwrap_or("").to_string();
        let name_field = r["names"]
            .as_array()
            .and_then(|n| n.first())
            .and_then(Value::as_str)
            .map(str::to_string);
        if r["warn"] == json!(true) && !s.warned {
            if let Some(x) = lk(&self.sessions).get_mut(&sid) {
                x.warned = true;
            }
            self.event(
                "limit_warning",
                &s,
                &sid,
                "80% of this browsing task's actions or time is used",
            );
        }
        match gate {
            "refuse" => {
                return refuse(
                    if risk == "internal" {
                        "browser_internal"
                    } else {
                        "browser_payment"
                    },
                    r["message"].as_str().unwrap_or("refused").to_string(),
                )
            }
            "handoff" => {
                self.event(
                    "challenge",
                    &s,
                    &sid,
                    r["reason"].as_str().unwrap_or("a check"),
                );
                return refuse(
                    "browser_challenge",
                    r["message"]
                        .as_str()
                        .unwrap_or("a person must take over")
                        .to_string(),
                );
            }
            _ => {}
        }
        // a site that needs a local model is not read by a hosted one
        if matches!(
            action,
            Action::Snapshot | Action::Screenshot { .. } | Action::Extract { .. }
        ) && host_in(&s.policy.local_model_sites, &host)
        {
            let local = self.local_model.as_ref().is_some_and(|f| f(run_key));
            if !local {
                return refuse("browser_needs_local_model", "this site is set to be read only by a local model, and this run is not using one".into());
            }
        }
        let asks = gate == "ask";
        let writes = !action.reads() || asks;
        let summary = if asks {
            approval_summary(r, &host, &risk, action.word())
        } else {
            format!("{} {host}", action.word())
        };
        let command = action.audit_words(name_field.as_deref());
        let act2 = action.clone();
        let sid2 = sid.clone();
        let me2 = Arc::clone(&me);
        let slot: ApprovalSlot = Arc::new(Mutex::new(None));
        let slot2 = Arc::clone(&slot);
        Ok((
            Prepared {
                writes: Some(writes),
                path: Some(if host.is_empty() { bx.clone() } else { host }),
                command: Some(command),
                sensitive: asks,
                summary,
                env: None,
                job: Box::new(move |_be, _bx| {
                    let s = me2.sess(&sid2, None)?;
                    // a grant exists only when a person decided this call's approval request: the engine allowing a call
                    // is never one (the tool gate asks for every risky call, whatever a rule or the mode says)
                    let grant = if asks {
                        lk(&slot2).take().map(|approval| {
                            let mac = lk(&s.lane.chan).grant(
                                &approval,
                                &fingerprint,
                                &risk,
                                &act2.grant_bytes(),
                            );
                            Grant {
                                approval,
                                fingerprint: fingerprint.clone(),
                                risk: risk.clone(),
                                mac,
                            }
                        })
                    } else {
                        None
                    };
                    let reply = me2.req(
                        &s,
                        Op::Act {
                            action: act2.clone(),
                            grant,
                        },
                        ACT_TIMEOUT,
                    )?;
                    me2.finish(&sid2, &s, &act2, reply)
                }),
            },
            // the risky kinds ask a person, always: the baseline (a click is not a decision) applies only to a call that
            // does not, and a call that does is marked so no allow rule or mode lets it through without a person
            Extra {
                baseline: !asks,
                session: extra_session,
                person_required: asks,
                approval: asks.then_some(slot),
                ..Extra::default()
            },
        ))
    }

    fn finish(&self, sid: &str, s: &Sess, action: &Action, r: Reply) -> Result<Value, ToolError> {
        if r.ok {
            let mut v = r.result;
            if let Some(h) = v.get("handoff") {
                self.event(
                    "challenge",
                    s,
                    sid,
                    h["reason"].as_str().unwrap_or("a check"),
                );
            }
            if matches!(action, Action::Screenshot { .. }) {
                // the picture itself, for a model that needs the layout
                return self.screenshot_value(sid, s, &mut v);
            }
            return Ok(v);
        }
        let msg = r.error.unwrap_or_default();
        match r.code.as_deref() {
            Some("limit") => {
                let _ = self.pause(sid, &msg);
                self.event("limit", s, sid, &msg);
                Err(ToolError::Refused(format!("{msg}. The task is paused where it was and nothing is half-done; a person can resume it from the dashboard.")))
            }
            Some("person_holds" | "risk" | "robots" | "refused" | "changed") => {
                Err(ToolError::Refused(msg))
            }
            Some("invalid" | "schema") => Err(ToolError::Invalid(msg)),
            _ => Err(ToolError::Failed(msg)),
        }
    }

    fn screenshot_value(&self, sid: &str, s: &Sess, v: &mut Value) -> Result<Value, ToolError> {
        // the worker kept the picture as the last step's shot
        let steps = self
            .backend
            .steps(&s.box_name, sid)
            .map_err(ToolError::Failed)?;
        let name = steps
            .iter()
            .rev()
            .find_map(|st| st.shot.clone())
            .ok_or_else(|| ToolError::Failed("no picture was kept".into()))?;
        let bytes = self
            .backend
            .shot(&s.box_name, sid, &name)
            .map_err(ToolError::Failed)?;
        if bytes.len() > SCREENSHOT_MAX {
            return Err(ToolError::Failed(
                "the picture is too large to return: take a snapshot instead".into(),
            ));
        }
        v["mime"] = json!("image/jpeg");
        v["image_base64"] = json!(ozbox_browser::b64::encode(&bytes));
        Ok(v.clone())
    }
}

/// Where the tool gate puts the id of the approval request a person decided for a call, for the call's job to turn into
/// a grant. Only the gate fills it, and only with a request a person approved.
pub(crate) type ApprovalSlot = Arc<Mutex<Option<String>>>;

/// The approval as a person reads it: `<reason> on <host>: <word> -> <destination> (check <fingerprint>) [field=value, ...]`.
/// The destination and the fingerprint are part of it, so a page that changes what the action is aimed at, or where it
/// sends, makes a different approval request.
pub fn approval_summary(r: &Value, host: &str, risk: &str, word: &str) -> String {
    let fields: Vec<String> = r["fields"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|f| {
            format!(
                "{}={}",
                ozbox_browser::detect::clean_name(f["name"].as_str().unwrap_or("")),
                f["value"]
                    .as_str()
                    .unwrap_or("")
                    .replace(", ", ",")
                    .chars()
                    .take(120)
                    .collect::<String>()
            )
        })
        .collect();
    let mut t = format!("{} on {host}: {word}", r["reason"].as_str().unwrap_or(risk));
    let dest = r["dest"].as_str().unwrap_or("");
    if !dest.is_empty() {
        t.push_str(&format!(" -> {}", dest.replace(' ', "_")));
    }
    let fp = r["fingerprint"].as_str().unwrap_or("");
    if !fp.is_empty() {
        t.push_str(&format!(" (check {})", &fp[..fp.len().min(8)]));
    }
    if !fields.is_empty() {
        t.push_str(&format!(" [{}]", fields.join(", ")));
    }
    t
}

/// What changed in the settings, for the audit chain: the names of the fields that changed, and for the ones that make
/// browsing less careful, which way they went (`payments=ask`, `safe_sites+2`). Never a proxy address.
pub fn settings_diff(before: &BrowserPolicy, after: &BrowserPolicy) -> String {
    let b = serde_json::to_value(before).unwrap_or(Value::Null);
    let a = serde_json::to_value(after).unwrap_or(Value::Null);
    let mut changed: Vec<String> = Vec::new();
    if let (Some(bo), Some(ao)) = (b.as_object(), a.as_object()) {
        for (k, av) in ao {
            let bv = bo.get(k).unwrap_or(&Value::Null);
            if bv == av {
                continue;
            }
            let word = match (k.as_str(), av) {
                ("proxy", _) => "proxy".to_string(),
                (_, Value::Array(new)) => {
                    let old = bv.as_array().cloned().unwrap_or_default();
                    let added = new.iter().filter(|x| !old.contains(x)).count();
                    let removed = old.iter().filter(|x| !new.contains(x)).count();
                    format!("{k}+{added}-{removed}")
                }
                (_, Value::String(s)) => format!("{k}={}", s.chars().take(24).collect::<String>()),
                (_, Value::Bool(v)) => format!("{k}={v}"),
                (_, Value::Number(n)) => format!("{k}={n}"),
                _ => k.clone(),
            };
            changed.push(word);
        }
    }
    let weaker = before.payments != after.payments
        && after.payments == ozbox_browser::detect::Payments::Ask
        || (!after.respect_robots && before.respect_robots)
        || after
            .safe_sites
            .iter()
            .chain(&after.exempt_sites)
            .chain(&after.upload_dirs)
            .any(|x| {
                !before.safe_sites.contains(x)
                    && !before.exempt_sites.contains(x)
                    && !before.upload_dirs.contains(x)
            })
        || after.max_download_bytes > before.max_download_bytes;
    format!(
        "changed={} less_careful={weaker}",
        if changed.is_empty() {
            "nothing".to_string()
        } else {
            changed.join(",")
        }
    )
}

/// The settings file: only the server's own user may read it.
fn write_private(path: &Path, text: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(text.as_bytes())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, text)
    }
}

fn reply_value(r: Reply) -> Result<Value, ToolError> {
    if r.ok {
        return Ok(r.result);
    }
    let m = r.error.unwrap_or_default();
    Err(match r.code.as_deref() {
        Some("person_holds" | "risk" | "challenge" | "not_taken_over" | "changed" | "refused") => {
            ToolError::Refused(m)
        }
        Some("invalid") => ToolError::Invalid(m),
        _ => ToolError::Failed(m),
    })
}

/// A tool call as the action it stands for.
pub fn to_action(name: &str, a: &Value) -> Result<Action, ToolError> {
    let mut m = serde_json::Map::new();
    let tag = match name {
        "browser_navigate" => "navigate",
        "browser_history" => match a.get("op").and_then(Value::as_str) {
            Some("back") => "back",
            Some("forward") => "forward",
            Some("reload") => "reload",
            _ => return Err(ToolError::Invalid("op is back, forward or reload".into())),
        },
        "browser_click" => "click",
        "browser_type" => "type",
        "browser_select" => "select",
        "browser_scroll" => "scroll",
        "browser_hover" => "hover",
        "browser_press" => "press",
        "browser_tab" => match a.get("op").and_then(Value::as_str) {
            Some("list") => "tab_list",
            Some("new") => "tab_new",
            Some("switch") => "tab_switch",
            Some("close") => "tab_close",
            _ => {
                return Err(ToolError::Invalid(
                    "op is list, new, switch or close".into(),
                ))
            }
        },
        "browser_wait" => "wait",
        "browser_upload" => "upload",
        "browser_downloads" => {
            if a.get("open").and_then(Value::as_str).is_some() {
                "open_download"
            } else {
                "downloads"
            }
        }
        "browser_snapshot" => "snapshot",
        "browser_page_screenshot" => "screenshot",
        "browser_extract" => "extract",
        _ => return Err(ToolError::NotFound(format!("there is no tool {name}"))),
    };
    m.insert("action".into(), json!(tag));
    if let Some(o) = a.as_object() {
        for (k, v) in o {
            if matches!(k.as_str(), "session" | "box" | "op") {
                continue;
            }
            let key = if tag == "open_download" && k == "open" {
                "name"
            } else {
                k.as_str()
            };
            m.insert(key.to_string(), v.clone());
        }
    }
    serde_json::from_value(Value::Object(m))
        .map_err(|e| ToolError::Invalid(format!("those arguments do not fit {name}: {e}")))
}

#[cfg(test)]
mod tests;
