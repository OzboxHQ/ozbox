//! A headless engine that runs **one process per turn**: the shape of Codex CLI (`codex exec`) and Gemini CLI (`gemini -p`).
//!
//! Each turn is one run on the box, through the box daemon ([`RunTransport`]), exactly like the Claude Code adapter:
//!
//! - **The task text is the process's standard input, never argv.** A long one is sent in pieces over a kept-open input,
//!   which is closed after the last piece so the program starts.
//! - **Credentials only in the process environment**: the per-run token and the broker's address (ADR 0017), and the run's
//!   token for the Oz Box tools (ADR 0043). Another vendor family's variables are dropped at this edge
//!   ([`crate::engine_turn::strip_foreign`]). The environment is kept in this adapter's memory only while the run lasts, so
//!   the next turn can be started; it is never logged, serialized or put in an error.
//! - **A conversation is a chain of processes.** The engine reports its own session id in its output; the next message
//!   starts a new process that resumes that session. Between turns nothing runs on the box.
//!
//! What differs per program (the argv, the output format, the exit codes) is a [`Dialect`].

use std::collections::BTreeMap;
use std::fmt;

use crate::agent_engine::{AgentEngine, EngineError, EngineEvent, EngineStart};
use crate::claude_code::{
    build_prompt, pieces, Launch, RunTransport, MAX_LONG_PROMPT_BYTES, MAX_POLL_FAILURES,
    MAX_PROMPT_BYTES, PROMPT_PIECE_BYTES, WRAPPER,
};
use crate::engine_turn::strip_foreign;

/// What one line of a program's output said, besides the events.
#[derive(Debug, Default)]
pub struct LineState {
    /// The program's own session id, once it said it.
    pub session: Option<String>,
    /// The turn ended: its final text, or why it failed.
    pub end: Option<Result<String, String>>,
    /// The last thing the agent said, for a turn that ends without a final text.
    pub last_message: String,
    /// A message being streamed in pieces.
    pub partial_message: String,
    /// The model the run was started with, for usage the program reports without naming one.
    pub model: Option<String>,
}

/// One headless program.
pub trait Dialect: Send {
    /// The engine id (Models routing, `RunSpec::engine`).
    fn id(&self) -> &'static str;
    /// The program and its arguments for one turn, after the fixed wrapper. Never the task text, never a secret.
    /// `resume` is the program's own session id from the turn before.
    fn argv(&self, req: &EngineStart, resume: Option<&str>) -> Result<Vec<String>, EngineError>;
    /// The process environment for the run, from what the run was handed (another family's credentials already dropped).
    fn env(&self, env: BTreeMap<String, String>) -> BTreeMap<String, String> {
        env
    }
    fn parse_line(&self, line: &str, st: &mut LineState) -> Vec<EngineEvent>;
    /// The program ended without saying how its turn went.
    fn exit_failure(&self, code: i32) -> String {
        format!("the agent exited with code {code}")
    }
}

struct Turn {
    run_id: String,
    offset: u64,
    partial: Vec<u8>,
    failures: u32,
}

struct Run {
    /// The request the run was started with, kept to start the next turn. Its environment is secret.
    req: EngineStart,
    turn: Option<Turn>,
    st: LineState,
    session_reported: bool,
    finished: bool,
}

/// A one-process-per-turn engine for a [`Dialect`].
pub struct HeadlessEngine<T: RunTransport, D: Dialect> {
    transport: T,
    dialect: D,
    runs: BTreeMap<String, Run>,
    seq: u64,
}

impl<T: RunTransport, D: Dialect> fmt::Debug for HeadlessEngine<T, D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HeadlessEngine")
            .field("engine", &self.dialect.id())
            .field("runs", &self.runs.len())
            .finish()
    }
}

impl<T: RunTransport, D: Dialect> HeadlessEngine<T, D> {
    pub fn new(transport: T, dialect: D) -> Self {
        Self {
            transport,
            dialect,
            runs: BTreeMap::new(),
            seq: 0,
        }
    }
    pub fn transport(&self) -> &T {
        &self.transport
    }
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Launch one turn: the argv, the environment, the text on standard input.
    fn launch_turn(
        &mut self,
        req: &EngineStart,
        resume: Option<&str>,
        text: &str,
    ) -> Result<Turn, EngineError> {
        if text.len() > MAX_LONG_PROMPT_BYTES {
            return Err(EngineError::Failed(
                "the task text is too long to send to a box; shorten it".into(),
            ));
        }
        let mut argv: Vec<String> = ["sh", "-c", WRAPPER, "sh"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        argv.extend(self.dialect.argv(req, resume)?);
        let long = text.len() > MAX_PROMPT_BYTES;
        let all = pieces(text, PROMPT_PIECE_BYTES);
        let (head, tail): (String, Vec<&str>) = if long {
            (
                all.first().copied().unwrap_or("").to_string(),
                all[1..].to_vec(),
            )
        } else {
            (text.to_string(), Vec::new())
        };
        let mut labels = BTreeMap::new();
        labels.insert("kind".to_string(), "agent".to_string());
        labels.insert("task".to_string(), req.task_id.clone());
        labels.insert("engine".to_string(), self.dialect.id().to_string());
        let launch = Launch {
            argv,
            cwd: req.repo.as_ref().map(|r| format!("/work/repos/{r}")),
            env: self
                .dialect
                .env(strip_foreign(self.dialect.id(), &req.secret_env)),
            labels,
            max_runtime_s: req.max_runtime_s,
            memory_request_bytes: 2 * 1024 * 1024 * 1024,
            memory_max_bytes: None,
            require_capability: false,
            stdin: Some(head),
            keep_stdin_open: long,
        };
        let run_id = self
            .transport
            .launch(&req.box_name, &launch)
            .map_err(EngineError::Failed)?;
        let last = tail.len().saturating_sub(1);
        for (i, piece) in tail.iter().enumerate() {
            if let Err(e) = self
                .transport
                .send(&req.box_name, &run_id, piece, i == last)
            {
                let _ = self.transport.stop(&req.box_name, &run_id);
                return Err(EngineError::Failed(e));
            }
        }
        Ok(Turn {
            run_id,
            offset: 0,
            partial: Vec::new(),
            failures: 0,
        })
    }
}

impl<T: RunTransport, D: Dialect> AgentEngine for HeadlessEngine<T, D> {
    fn id(&self) -> &str {
        self.dialect.id()
    }

    fn start(&mut self, req: &EngineStart) -> Result<String, EngineError> {
        let resume = req
            .resume_session
            .as_deref()
            .filter(|s| crate::claude_code::is_resume_id(s));
        let text = if resume.is_some() && req.interactive {
            "Continue where you left off.".to_string()
        } else {
            build_prompt(req)
        };
        let turn = self.launch_turn(req, resume, &text)?;
        self.seq += 1;
        let handle = format!("{}-{}", self.dialect.id(), self.seq);
        self.runs.insert(
            handle.clone(),
            Run {
                req: req.clone(),
                turn: Some(turn),
                st: LineState {
                    session: resume.map(str::to_string),
                    model: req.model.clone(),
                    ..LineState::default()
                },
                session_reported: resume.is_some(),
                finished: false,
            },
        );
        Ok(handle)
    }

    fn poll(&mut self, handle: &str) -> Result<Vec<EngineEvent>, EngineError> {
        let r = self.runs.get_mut(handle).ok_or(EngineError::Unavailable)?;
        if r.finished {
            return Ok(Vec::new());
        }
        let Some(turn) = r.turn.as_mut() else {
            return Ok(Vec::new()); // between turns of a conversation
        };
        let chunk = match self
            .transport
            .read_log(&r.req.box_name, &turn.run_id, turn.offset)
        {
            Ok(c) => {
                turn.failures = 0;
                c
            }
            Err(e) => {
                turn.failures += 1;
                if turn.failures >= MAX_POLL_FAILURES {
                    return Err(EngineError::Failed(e));
                }
                return Ok(Vec::new());
            }
        };
        turn.offset = chunk.next;
        turn.partial.extend_from_slice(&chunk.bytes);
        let mut events = Vec::new();
        while let Some(pos) = turn.partial.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = turn.partial.drain(..=pos).collect();
            events.extend(
                self.dialect
                    .parse_line(&String::from_utf8_lossy(&line), &mut r.st),
            );
        }
        if chunk.exited.is_some() && !turn.partial.is_empty() {
            let rest = std::mem::take(&mut turn.partial);
            events.extend(
                self.dialect
                    .parse_line(&String::from_utf8_lossy(&rest), &mut r.st),
            );
        }
        if !r.session_reported {
            if let Some(s) = r.st.session.clone() {
                r.session_reported = true;
                events.insert(0, EngineEvent::Session(s));
            }
        }
        // the turn is over once the program said so, or once it exited
        let end = match (r.st.end.take(), chunk.exited) {
            (Some(e), _) => Some(e),
            (None, Some(0)) => Some(Ok(std::mem::take(&mut r.st.last_message))),
            (None, Some(code)) => Some(Err(self.dialect.exit_failure(code))),
            (None, None) => None,
        };
        let Some(end) = end else {
            return Ok(events);
        };
        if chunk.exited.is_none() {
            // the program said the turn is over but is still writing; read it to the end on the next poll first
            r.st.end = Some(end);
            return Ok(events);
        }
        r.turn = None;
        r.st.last_message.clear();
        match end {
            Err(why) => {
                r.finished = true;
                events.push(if crate::claude_code::looks_like_refusal(&why) {
                    EngineEvent::ProviderRefused(why)
                } else {
                    EngineEvent::Failed(why)
                });
            }
            Ok(text) if r.req.interactive => {
                events.push(EngineEvent::TurnDone(
                    text.chars().take(crate::run::MAX_REPLY_CHARS).collect(),
                ));
            }
            Ok(text) => {
                r.finished = true;
                events.push(EngineEvent::Finished {
                    summary: if text.trim().is_empty() {
                        "finished".into()
                    } else {
                        text.chars().take(500).collect()
                    },
                    links: Vec::new(),
                });
            }
        }
        Ok(events)
    }

    fn resolve(&mut self, _handle: &str, _approved: bool) -> Result<(), EngineError> {
        // a headless program never stops to ask (see `engine_turn::capabilities`); nothing waits for this answer
        Ok(())
    }

    fn send(&mut self, handle: &str, text: &str) -> Result<(), EngineError> {
        let (req, resume) = {
            let r = self.runs.get(handle).ok_or(EngineError::Unavailable)?;
            if !r.req.interactive || r.finished {
                return Err(EngineError::Failed("this run is not a conversation".into()));
            }
            if r.turn.is_some() {
                return Err(EngineError::Failed(
                    "the agent is still answering the last message".into(),
                ));
            }
            let Some(s) = r.st.session.clone() else {
                return Err(EngineError::Failed(
                    "the agent did not say which session to continue".into(),
                ));
            };
            (r.req.clone(), s)
        };
        let turn = self.launch_turn(&req, Some(&resume), text)?;
        if let Some(r) = self.runs.get_mut(handle) {
            r.turn = Some(turn);
        }
        Ok(())
    }

    fn stop(&mut self, handle: &str) -> Result<(), EngineError> {
        if let Some(r) = self.runs.remove(handle) {
            if let Some(t) = r.turn {
                let _ = self.transport.stop(&r.req.box_name, &t.run_id);
            }
        }
        Ok(())
    }
}

/// Is this a URL the adapter may put in a program's settings on the command line: `http(s)://`, no quote, no space, no
/// control character, nothing that could end a TOML string. A loopback address or the broker's is what is expected.
pub fn safe_url(u: &str) -> bool {
    (u.starts_with("http://") || u.starts_with("https://"))
        && u.len() <= 300
        && u.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    ':' | '/' | '.' | '-' | '_' | '~' | '%' | '?' | '=' | '&' | '[' | ']'
                )
        })
}

/// Is this a model name the adapter may pass: letters, digits and `-._:/@`, starting with a letter or digit.
pub fn safe_model(m: &str) -> bool {
    m.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && m.len() <= 100
        && m.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | ':' | '/' | '@'))
}
