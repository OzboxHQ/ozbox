//! How an agent run reaches a real box: the box daemon's run API, over the same outbound route as every other call.
//!
//! [`BoxRunTransport`] is what the Claude Code adapter (`ozbox_core::claude_code`) talks to. It turns "launch this", "read
//! the output from byte N" and "stop it" into calls on [`BoxAgent::runs`] (the daemon's `/v1/runs`, forwarded over the
//! provider's SSH route), and nothing else.
//!
//! What a run is handed, and what it is not:
//!
//! - **The prompt is the run's standard input.** It travels in the request body and the daemon feeds it to the program
//!   through a pipe. It is never an argument (arguments are listed by `ps`) and never a file.
//! - **The run's environment holds a per-run token and the broker's address, never a provider key** (ADR 0017). The
//!   broker runs inside this server, on this computer, so a run on the box cannot reach it directly. When the
//!   environment names the broker's port, a reverse forward over the connection that is already open to the box makes
//!   that same port answer on the box's own loopback address. No port is opened on the box to anything else.
//! - **Nothing here logs or keeps a request body.** Errors are plain sentences chosen here or by the daemon; the daemon's
//!   answers never carry a run's environment.

use std::collections::BTreeMap;
use std::sync::Arc;

use ozbox_core::claude_code::{Launch, LogChunk, RunTransport};
use ozbox_core::BoxRecord;
use serde_json::{json, Value};

use super::agent::BoxAgent;

#[derive(Default)]
struct LinkState {
    boxes: BTreeMap<String, BoxRecord>,
    /// The credential broker's port on this computer, when it is running.
    broker_port: Option<u16>,
    /// The Oz Box tools' port on this computer, when it is running (reached the same way).
    mcp_port: Option<u16>,
}

/// What every engine's transport shares: the boxes this server knows and the broker's port. One link, any number of
/// engines: an engine adapter (Claude Code, Codex, ...) is given a [`BoxRunTransport`] made from it and nothing here knows
/// which engine it serves.
#[derive(Clone, Default)]
pub struct RunLink(Arc<std::sync::Mutex<LinkState>>);

impl RunLink {
    /// The boxes this server knows, as of this tick.
    pub fn set_boxes(&self, recs: impl IntoIterator<Item = BoxRecord>) {
        if let Ok(mut l) = self.0.lock() {
            l.boxes = recs
                .into_iter()
                .map(|r| (r.spec.name.as_str().to_string(), r))
                .collect();
        }
    }

    pub fn set_mcp_port(&self, port: Option<u16>) {
        if let Ok(mut l) = self.0.lock() {
            l.mcp_port = port;
        }
    }

    fn mcp_port(&self) -> Option<u16> {
        self.0.lock().ok().and_then(|l| l.mcp_port)
    }

    pub fn set_broker_port(&self, port: Option<u16>) {
        if let Ok(mut l) = self.0.lock() {
            l.broker_port = port;
        }
    }

    fn rec(&self, box_name: &str) -> Result<BoxRecord, String> {
        self.0
            .lock()
            .ok()
            .and_then(|l| l.boxes.get(box_name).cloned())
            .ok_or_else(|| "that box is not known to this server".to_string())
    }

    fn broker_port(&self) -> Option<u16> {
        self.0.lock().ok().and_then(|l| l.broker_port)
    }
}

pub struct BoxRunTransport {
    agent: Arc<dyn BoxAgent>,
    link: RunLink,
    /// Controlled runs' capabilities, by run id: held here only, shown to the daemon on each call, wiped when the run stops.
    caps: BTreeMap<String, zeroize::Zeroizing<String>>,
}

const TOO_OLD: &str = "this box's agent is too old to run agents; run `ozbox upgrade` on the box";

impl BoxRunTransport {
    pub fn new(agent: Arc<dyn BoxAgent>, link: RunLink) -> Self {
        Self {
            agent,
            link,
            caps: BTreeMap::new(),
        }
    }

    /// One call to the daemon's run API, with the run's capability when it is a controlled run.
    fn call(
        &self,
        rec: &BoxRecord,
        run_id: &str,
        method: &str,
        sub: &str,
        body: &[u8],
    ) -> Result<(u16, Value), String> {
        match self.caps.get(run_id) {
            Some(c) => self.agent.runs_controlled(rec, method, sub, body, c),
            None => self.agent.runs(rec, method, sub, body),
        }
        .map_err(|e| e.to_string())
    }
}

/// What a run that brings its own files is told when the box's daemon predates them (ADR 0055).
const TOO_OLD_FILES: &str =
    "this box's agent is too old to hand a run its sign-in; run `ozbox upgrade` on the box";
const TOO_OLD_CONTROLLED: &str =
    "this box's agent is too old to keep a browser session to this server alone; run `ozbox upgrade` on the box";

/// A short sentence from the daemon's error answer.
fn why(v: &Value) -> String {
    v["error"]
        .as_str()
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_control())
        .take(160)
        .collect()
}

impl RunTransport for BoxRunTransport {
    fn launch(&mut self, box_name: &str, launch: &Launch) -> Result<String, String> {
        let rec = self.link.rec(box_name)?;
        for port in [self.link.broker_port(), self.link.mcp_port()]
            .into_iter()
            .flatten()
        {
            let needle = format!("127.0.0.1:{port}");
            if launch.env.values().any(|v| v.contains(&needle)) {
                self.agent
                    .reverse_forward(&rec, port)
                    .map_err(|e| e.to_string())?;
            }
        }
        // The body holds the run's environment and prompt: it lives only for this call.
        let mut body = json!({
            "argv": launch.argv,
            "cwd": launch.cwd,
            "env": launch.env,
            "labels": launch.labels,
            "max_runtime_s": launch.max_runtime_s,
            "memory_request_bytes": launch.memory_request_bytes,
            "memory_max_bytes": launch.memory_max_bytes,
            "stdin": launch.stdin,
            "keep_stdin_open": launch.keep_stdin_open,
            "require_capability": launch.require_capability,
        });
        // a run's own files (ADR 0055), only when it has any, so an older box daemon is never sent a field it would drop
        if !launch.files.is_empty() {
            body["files"] = Value::Array(
                launch
                    .files
                    .iter()
                    .map(|f| json!({"dir_env": f.dir_env, "path": f.path, "contents": f.contents}))
                    .collect(),
            );
        }
        let mut body = zeroize::Zeroizing::new(body.to_string());
        let (status, v) = self
            .agent
            .runs(&rec, "POST", "", body.as_bytes())
            .map_err(|e| e.to_string())?;
        body.clear();
        match status {
            200 | 201 => {
                let id = v["id"]
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| "the box did not say which run it started".to_string())?;
                // a daemon that did not write the run's files would start the engine without them: stop it and say why
                if !launch.files.is_empty()
                    && v["files"].as_u64() != Some(launch.files.len() as u64)
                {
                    let _ = self.agent.runs(&rec, "DELETE", &format!("/{id}"), &[]);
                    return Err(TOO_OLD_FILES.into());
                }
                if launch.require_capability {
                    match v["capability"].as_str() {
                        Some(c) => {
                            self.caps
                                .insert(id.clone(), zeroize::Zeroizing::new(c.to_string()));
                        }
                        // an older daemon ignored the request: the run is not controlled, so it is not used
                        None => {
                            let _ = self.agent.runs(&rec, "DELETE", &format!("/{id}"), &[]);
                            return Err(TOO_OLD_CONTROLLED.into());
                        }
                    }
                }
                Ok(id)
            }
            404 | 405 => Err(TOO_OLD.into()),
            429 => Err("the box has too many runs waiting; try again shortly".into()),
            422 => Err("the run needs more memory than the box has".into()),
            400 => Err(format!("the box refused the run: {}", why(&v))),
            s => Err(format!("the box could not start the run (HTTP {s})")),
        }
    }

    fn read_log(&mut self, box_name: &str, run_id: &str, from: u64) -> Result<LogChunk, String> {
        let rec = self.link.rec(box_name)?;
        let (status, v) = self.call(
            &rec,
            run_id,
            "GET",
            &format!("/{run_id}/log?from={from}"),
            &[],
        )?;
        match status {
            200 => {
                let l = &v["log"];
                Ok(LogChunk {
                    bytes: l["text"].as_str().unwrap_or("").as_bytes().to_vec(),
                    next: l["next"].as_u64().unwrap_or(from),
                    exited: l["exit_code"].as_i64().map(|c| c as i32),
                })
            }
            404 => Err("the run is no longer on the box (it may have restarted)".into()),
            s => Err(format!(
                "the box would not give the run's output (HTTP {s})"
            )),
        }
    }

    fn send(
        &mut self,
        box_name: &str,
        run_id: &str,
        text: &str,
        close: bool,
    ) -> Result<(), String> {
        let rec = self.link.rec(box_name)?;
        // the text is a person's message: it lives in this body only
        let body = json!({ "text": text, "close": close }).to_string();
        let (status, v) = self.call(
            &rec,
            run_id,
            "POST",
            &format!("/{run_id}/stdin"),
            body.as_bytes(),
        )?;
        match status {
            200 => Ok(()),
            404 | 405 => Err(
                "the box's agent is too old for conversations; run `ozbox upgrade` on the box"
                    .into(),
            ),
            409 => Err(format!("the agent would not take the message: {}", why(&v))),
            s => Err(format!("the box would not take the message (HTTP {s})")),
        }
    }

    fn stop(&mut self, box_name: &str, run_id: &str) -> Result<(), String> {
        let rec = self.link.rec(box_name)?;
        let (status, v) = self.call(&rec, run_id, "DELETE", &format!("/{run_id}"), &[])?;
        self.caps.remove(run_id);
        match status {
            200 | 404 => Ok(()),
            s => Err(format!(
                "the box could not stop the run (HTTP {s}) {}",
                why(&v)
            )),
        }
    }
}
