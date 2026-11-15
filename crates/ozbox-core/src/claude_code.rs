//! The Claude Code adapter: `claude -p ... --output-format stream-json`, run headless as the box user inside the run's
//! cgroup through the box daemon.
//!
//! - **The prompt never goes through argv.** It is the run's standard input: the box daemon feeds it to the program
//!   through a pipe and keeps no copy of it, so it is neither an argument (`ps` lists those) nor a file. A fixed one-line
//!   wrapper only puts the box user's own program folder on `PATH` before it runs the program.
//! - **Credentials.** Either the box user's own Claude login (nothing is passed), or what [`EngineStart::secret_env`]
//!   carries for this run, passed in the process environment only. A host that runs a credential broker puts a per-run
//!   token and the broker's address there instead of a provider key (ADR 0017). Nothing here logs, serializes or puts
//!   it in an error.
//! - **The ask list.** Commands the policy asks about are passed as `--disallowedTools`, so the agent cannot run them on its
//!   own. (Approving one and then letting it run needs a permission prompt hook; that is not built yet.)
//! - **Usage.** Tokens are counted per message; the cost arrives with the final result.
//!
//! The transport is a trait ([`RunTransport`]) so the adapter is tested with a fake and works over whatever reaches the
//! box daemon's run API.

use std::collections::BTreeMap;
use std::fmt;

use serde_json::Value;

use crate::agent_engine::{AgentEngine, EngineError, EngineEvent, EngineStart};

/// What to ask the box daemon to run.
#[derive(Clone)]
pub struct Launch {
    pub argv: Vec<String>,
    pub cwd: Option<String>,
    /// Secret values: never logged or serialized.
    pub env: BTreeMap<String, String>,
    pub labels: BTreeMap<String, String>,
    pub max_runtime_s: Option<u64>,
    pub memory_request_bytes: u64,
    /// A hard memory cap the box enforces (`memory.max`), when the run should have one.
    pub memory_max_bytes: Option<u64>,
    /// A controlled run: the box gives a capability to whoever started it, and the run's input, output and stop then need
    /// it. The transport keeps the capability; nothing else sees it.
    pub require_capability: bool,
    /// Text fed to the program's standard input (the prompt). Secret: never logged or serialized.
    pub stdin: Option<String>,
    /// Keep standard input open after `stdin`, so [`RunTransport::send`] can add to it (a conversation, or a prompt that
    /// is longer than one request holds).
    pub keep_stdin_open: bool,
}

/// The most prompt text one request to a box's daemon carries, in bytes. A longer prompt is sent in pieces.
pub const MAX_PROMPT_BYTES: usize = 40_000;
/// The longest whole prompt, sent in pieces over a kept-open input.
pub const MAX_LONG_PROMPT_BYTES: usize = 400_000;
/// The size of one piece: small enough that even a worst-case JSON escaping stays inside a request.
pub const PROMPT_PIECE_BYTES: usize = 8_000;

impl fmt::Debug for Launch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Launch")
            .field("program", &self.argv.first())
            .field("args", &self.argv.len().saturating_sub(1))
            .field("env_keys", &self.env.len())
            .field("stdin_bytes", &self.stdin.as_ref().map(String::len))
            .finish()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogChunk {
    pub bytes: Vec<u8>,
    /// Where to read from next.
    pub next: u64,
    /// The exit code once the run has ended.
    pub exited: Option<i32>,
}

/// How the adapter reaches a box's daemon. Errors are plain text without secrets.
pub trait RunTransport: Send {
    fn launch(&mut self, box_name: &str, launch: &Launch) -> Result<String, String>;
    fn read_log(&mut self, box_name: &str, run_id: &str, from: u64) -> Result<LogChunk, String>;
    fn stop(&mut self, box_name: &str, run_id: &str) -> Result<(), String>;
    /// Append text to a kept-open run's standard input, and end the input when `close`. The text is secret: never logged.
    fn send(&mut self, box_name: &str, run_id: &str, text: &str, close: bool)
        -> Result<(), String>;
}

/// Cut text into pieces of at most `max` bytes, only at character boundaries.
pub fn pieces(text: &str, max: usize) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = text;
    while !rest.is_empty() {
        let mut end = rest.len().min(max);
        while !rest.is_char_boundary(end) {
            end -= 1;
        }
        let (a, b) = rest.split_at(end);
        out.push(a);
        rest = b;
    }
    out
}

/// One person message as the line the agent reads in conversation mode.
pub fn user_turn_line(text: &str) -> String {
    let mut s = serde_json::json!({
        "type": "user",
        "message": { "role": "user", "content": [{ "type": "text", "text": text }] },
    })
    .to_string();
    s.push('\n');
    s
}

struct Run {
    box_name: String,
    run_id: String,
    offset: u64,
    partial: Vec<u8>,
    last_cents: u64,
    counted: std::collections::BTreeSet<String>,
    finished: bool,
    /// Reads of the output that failed one after another.
    failures: u32,
    interactive: bool,
    session_seen: bool,
}

/// How many reads in a row may fail before the run is given up on. A dropped connection to a box comes back by itself; a
/// run that has been gone this long is not coming back.
pub const MAX_POLL_FAILURES: u32 = 30;

pub struct ClaudeCodeEngine<T: RunTransport> {
    transport: T,
    runs: BTreeMap<String, Run>,
    seq: u64,
}

/// The fixed wrapper: the box user's own program folder is searched first (a service's `PATH` does not include it), then
/// the program runs with its arguments as they are. No variable data is in the script itself.
const WRAPPER: &str = r#"PATH="$HOME/.local/bin:$PATH"; export PATH; exec "$@""#;

fn tool_pattern(cmd: &str) -> String {
    format!("Bash({}:*)", cmd.trim())
}

/// The argv for one run (without the prompt, which is the run's standard input). `model` is the model chosen for this run.
pub fn build_argv(deny_commands: &[String], model: Option<&str>) -> Vec<String> {
    build_argv_for(deny_commands, model, false, None, false)
}

/// Is this something that can follow `--resume`? Claude Code's session ids are UUIDs; what is accepted is plain words that
/// start with a letter or digit, so an id can never be read as a flag (`--dangerously-skip-permissions` is a valid-looking
/// "word" otherwise). Shared with the session resume at boot (`ozboxd::session_resume`).
pub fn is_resume_id(id: &str) -> bool {
    id.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && id.len() <= 100
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// As [`build_argv`]; in conversation mode the agent reads one JSON line per message from standard input and keeps its own
/// session, which `resume` continues after a pause. `ask_for_edits` is a run a chat app started: the agent is launched in
/// its `default` permission mode, not `acceptEdits`, so an edit is not made on the strength of a message from a chat.
pub fn build_argv_for(
    deny_commands: &[String],
    model: Option<&str>,
    interactive: bool,
    resume: Option<&str>,
    ask_for_edits: bool,
) -> Vec<String> {
    let mut v: Vec<String> = ["sh", "-c", WRAPPER, "sh"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    v.extend(
        [
            "claude",
            "-p",
            "--output-format",
            "stream-json",
            "--verbose",
            "--permission-mode",
        ]
        .iter()
        .map(|s| s.to_string()),
    );
    v.push(
        if ask_for_edits {
            "default"
        } else {
            "acceptEdits"
        }
        .to_string(),
    );
    if interactive {
        v.push("--input-format".into());
        v.push("stream-json".into());
    }
    if let Some(r) = resume.filter(|r| is_resume_id(r)) {
        v.push("--resume".into());
        v.push(r.to_string());
    }
    for c in deny_commands.iter().filter(|c| !c.trim().is_empty()) {
        v.push("--disallowedTools".into());
        v.push(tool_pattern(c));
    }
    if let Some(m) = model.filter(|m| !m.trim().is_empty()) {
        v.push("--model".into());
        v.push(m.trim().to_string());
    }
    v
}

/// The text the agent is given: the task, and where its work lives.
pub fn build_prompt(req: &EngineStart) -> String {
    let mut p = String::new();
    if let Some(skill) = &req.skill {
        p.push_str(&format!("Use the skill `{skill}`.\n\n"));
    }
    if let Some(b) = &req.resume_from {
        p.push_str(&format!(
            "You are continuing earlier work saved on the branch `{b}`. Check it out and carry on from where it stopped.\n\n"
        ));
    } else if let Some(b) = &req.branch {
        p.push_str(&format!("Work on the branch `{b}` (create it if it does not exist). Never push to a protected branch.\n\n"));
    }
    p.push_str(&req.prompt);
    p
}

/// What one line of `stream-json` output means.
#[derive(Debug, Default)]
pub struct StreamState {
    pub last_cents: u64,
    pub result_seen: bool,
    /// Message ids already counted: one message is printed once per content block, with the same usage each time.
    pub counted: std::collections::BTreeSet<String>,
    /// A conversation: a `result` ends one turn, not the run.
    pub interactive: bool,
    /// The session id has been reported.
    pub session_seen: bool,
}

/// Whether an error from the agent is the provider refusing the call (a rate limit, an overloaded or unavailable
/// service) rather than the agent failing at its task. Only these switch a run to its fallback model.
pub fn looks_like_refusal(text: &str) -> bool {
    let t = text.to_ascii_lowercase();
    [
        "rate limit",
        "rate_limit",
        "overloaded",
        "429",
        "529",
        "503",
        "service unavailable",
        "usage limit",
        "quota",
    ]
    .iter()
    .any(|n| t.contains(n))
}

pub fn parse_line(line: &str, st: &mut StreamState) -> Vec<EngineEvent> {
    let line = line.trim();
    if line.is_empty() {
        return Vec::new();
    }
    let Ok(v) = serde_json::from_str::<Value>(line) else {
        return vec![EngineEvent::Log(line.chars().take(300).collect())];
    };
    let mut out = Vec::new();
    if !st.session_seen {
        if let Some(id) = v
            .get("session_id")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        {
            st.session_seen = true;
            out.push(EngineEvent::Session(id.chars().take(100).collect()));
        }
    }
    match v.get("type").and_then(Value::as_str) {
        Some("assistant") => {
            let msg = &v["message"];
            for block in msg["content"].as_array().into_iter().flatten() {
                match block.get("type").and_then(Value::as_str) {
                    Some("text") => {
                        if let Some(t) = block["text"].as_str() {
                            for l in t.lines().filter(|l| !l.trim().is_empty()).take(3) {
                                out.push(EngineEvent::Log(l.chars().take(300).collect()));
                            }
                        }
                    }
                    Some("tool_use") => {
                        // only the tool's name: its input may hold anything
                        let name = block["name"].as_str().unwrap_or("tool");
                        out.push(EngineEvent::Log(format!("using {name}")));
                    }
                    _ => {}
                }
            }
            let u = &msg["usage"];
            let n = |k: &str| u[k].as_u64().unwrap_or(0);
            let (input, output) = (
                n("input_tokens") + n("cache_creation_input_tokens"),
                n("output_tokens"),
            );
            let fresh = msg["id"]
                .as_str()
                .map(|id| st.counted.insert(id.to_string()))
                .unwrap_or(true);
            if fresh && input + output + n("cache_read_input_tokens") > 0 {
                out.push(EngineEvent::TokenUsage {
                    input_tokens: input,
                    output_tokens: output,
                    cached_input_tokens: n("cache_read_input_tokens"),
                    model: msg["model"].as_str().map(|m| m.chars().take(100).collect()),
                });
            }
        }
        Some("result") => {
            st.result_seen = true;
            let total = (v["total_cost_usd"].as_f64().unwrap_or(0.0) * 100.0)
                .round()
                .max(0.0) as u64;
            if total > st.last_cents {
                out.push(EngineEvent::ReportedCost {
                    cents: total - st.last_cents,
                });
                st.last_cents = total;
            }
            let text: String = v["result"]
                .as_str()
                .unwrap_or("")
                .chars()
                .take(500)
                .collect();
            if v["is_error"].as_bool().unwrap_or(false)
                || v["subtype"]
                    .as_str()
                    .is_some_and(|s| s.starts_with("error"))
            {
                out.push(if looks_like_refusal(&text) {
                    EngineEvent::ProviderRefused(text)
                } else {
                    EngineEvent::Failed(if text.is_empty() {
                        "the agent reported an error".into()
                    } else {
                        text
                    })
                });
            } else if st.interactive {
                // the whole reply, not the 500-character summary: a chat shows it
                let full: String = v["result"]
                    .as_str()
                    .unwrap_or("")
                    .chars()
                    .take(crate::run::MAX_REPLY_CHARS)
                    .collect();
                out.push(EngineEvent::TurnDone(full));
            } else {
                out.push(EngineEvent::Finished {
                    summary: if text.is_empty() {
                        "finished".into()
                    } else {
                        text
                    },
                    links: Vec::new(),
                });
            }
        }
        _ => {}
    }
    out
}

impl<T: RunTransport> ClaudeCodeEngine<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
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
}

impl<T: RunTransport> AgentEngine for ClaudeCodeEngine<T> {
    fn id(&self) -> &str {
        "claude-code"
    }

    fn start(&mut self, req: &EngineStart) -> Result<String, EngineError> {
        let mut prompt = build_prompt(req);
        if req.interactive && req.resume_session.is_some() {
            prompt = "Continue where you left off.".to_string();
        }
        if prompt.len() > MAX_LONG_PROMPT_BYTES {
            return Err(EngineError::Failed(
                "the task text is too long to send to a box; shorten it".into(),
            ));
        }
        // The first message goes in the launch; what does not fit one request follows in pieces, over an input that is
        // kept open until the last piece (and for good in a conversation).
        let first_line = if req.interactive {
            user_turn_line(&prompt)
        } else {
            prompt.clone()
        };
        let long = first_line.len() > MAX_PROMPT_BYTES;
        let (head, tail): (String, Vec<String>) = if long {
            let mut it = pieces(&first_line, PROMPT_PIECE_BYTES).into_iter();
            let h = it.next().unwrap_or("").to_string();
            (h, it.map(str::to_string).collect())
        } else {
            (first_line, Vec::new())
        };
        let mut labels = BTreeMap::new();
        labels.insert("kind".to_string(), "agent".to_string());
        labels.insert("task".to_string(), req.task_id.clone());
        let launch = Launch {
            argv: build_argv_for(
                &req.deny_commands,
                req.model.as_deref(),
                req.interactive,
                req.resume_session.as_deref(),
                req.ask_for_edits,
            ),
            cwd: req.repo.as_ref().map(|r| format!("/work/repos/{r}")),
            env: req.secret_env.clone(),
            labels,
            max_runtime_s: req.max_runtime_s,
            memory_request_bytes: 2 * 1024 * 1024 * 1024,
            memory_max_bytes: None,
            require_capability: false,
            stdin: Some(head),
            keep_stdin_open: req.interactive || long,
        };
        let run_id = self
            .transport
            .launch(&req.box_name, &launch)
            .map_err(EngineError::Failed)?;
        let last = tail.len().saturating_sub(1);
        for (i, piece) in tail.iter().enumerate() {
            let close = !req.interactive && i == last;
            if let Err(e) = self.transport.send(&req.box_name, &run_id, piece, close) {
                let _ = self.transport.stop(&req.box_name, &run_id);
                return Err(EngineError::Failed(e));
            }
        }
        self.seq += 1;
        let handle = format!("cc-{}", self.seq);
        self.runs.insert(
            handle.clone(),
            Run {
                box_name: req.box_name.clone(),
                run_id,
                offset: 0,
                partial: Vec::new(),
                last_cents: 0,
                counted: Default::default(),
                finished: false,
                failures: 0,
                interactive: req.interactive,
                session_seen: req.resume_session.is_some(),
            },
        );
        Ok(handle)
    }

    fn poll(&mut self, handle: &str) -> Result<Vec<EngineEvent>, EngineError> {
        let r = self.runs.get_mut(handle).ok_or(EngineError::Unavailable)?;
        if r.finished {
            return Ok(Vec::new());
        }
        let chunk = match self.transport.read_log(&r.box_name, &r.run_id, r.offset) {
            Ok(c) => {
                r.failures = 0;
                c
            }
            Err(e) => {
                // a connection that dropped for a moment must not end a long run: say nothing new and try again
                r.failures += 1;
                if r.failures >= MAX_POLL_FAILURES {
                    return Err(EngineError::Failed(e));
                }
                return Ok(Vec::new());
            }
        };
        r.offset = chunk.next;
        r.partial.extend_from_slice(&chunk.bytes);
        let mut st = StreamState {
            last_cents: r.last_cents,
            result_seen: false,
            counted: std::mem::take(&mut r.counted),
            interactive: r.interactive,
            session_seen: r.session_seen,
        };
        let mut events = Vec::new();
        while let Some(pos) = r.partial.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = r.partial.drain(..=pos).collect();
            events.extend(parse_line(&String::from_utf8_lossy(&line), &mut st));
        }
        r.last_cents = st.last_cents;
        r.session_seen = st.session_seen;
        r.counted = std::mem::take(&mut st.counted);
        if let Some(code) = chunk.exited {
            if !r.partial.is_empty() {
                let rest = std::mem::take(&mut r.partial);
                events.extend(parse_line(&String::from_utf8_lossy(&rest), &mut st));
            }
            if !st.result_seen
                && !events
                    .iter()
                    .any(|e| matches!(e, EngineEvent::Finished { .. } | EngineEvent::Failed(_)))
            {
                events.push(if code == 0 {
                    EngineEvent::Finished {
                        summary: "finished".into(),
                        links: Vec::new(),
                    }
                } else {
                    EngineEvent::Failed(format!("the agent exited with code {code}"))
                });
            }
        }
        if events
            .iter()
            .any(|e| matches!(e, EngineEvent::Finished { .. } | EngineEvent::Failed(_)))
        {
            r.finished = true;
        }
        Ok(events)
    }

    fn resolve(&mut self, _handle: &str, _approved: bool) -> Result<(), EngineError> {
        // Claude Code runs headless without asking; the ask list is enforced by refusing those commands up front.
        Ok(())
    }

    fn send(&mut self, handle: &str, text: &str) -> Result<(), EngineError> {
        let r = self.runs.get(handle).ok_or(EngineError::Unavailable)?;
        if !r.interactive || r.finished {
            return Err(EngineError::Failed("this run is not a conversation".into()));
        }
        let line = user_turn_line(text);
        for piece in pieces(&line, PROMPT_PIECE_BYTES) {
            self.transport
                .send(&r.box_name, &r.run_id, piece, false)
                .map_err(EngineError::Failed)?;
        }
        Ok(())
    }

    fn stop(&mut self, handle: &str) -> Result<(), EngineError> {
        if let Some(r) = self.runs.remove(handle) {
            let _ = self.transport.stop(&r.box_name, &r.run_id);
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeTransport {
        launches: Vec<Launch>,
        log: Vec<u8>,
        exit: Option<i32>,
        stopped: bool,
        sent: Vec<(String, bool)>,
    }

    impl RunTransport for FakeTransport {
        fn launch(&mut self, _: &str, l: &Launch) -> Result<String, String> {
            self.launches.push(l.clone());
            Ok("run-1".into())
        }
        fn read_log(&mut self, _: &str, _: &str, from: u64) -> Result<LogChunk, String> {
            let bytes = self.log[(from as usize).min(self.log.len())..].to_vec();
            Ok(LogChunk {
                next: self.log.len() as u64,
                bytes,
                exited: self.exit,
            })
        }
        fn stop(&mut self, _: &str, _: &str) -> Result<(), String> {
            self.stopped = true;
            Ok(())
        }
        fn send(&mut self, _: &str, _: &str, text: &str, close: bool) -> Result<(), String> {
            self.sent.push((text.to_string(), close));
            Ok(())
        }
    }

    fn start(secret: Option<&str>) -> EngineStart {
        EngineStart {
            task_id: "t1".into(),
            box_name: "alpha".into(),
            prompt: "Fix the parser. Do not print secrets.".into(),
            skill: None,
            repo: Some("web".into()),
            branch: Some("fix/p".into()),
            resume_from: None,
            secret_env: secret
                .map(|s| [("ANTHROPIC_API_KEY".to_string(), s.to_string())].into())
                .unwrap_or_default(),
            deny_commands: vec!["rm -rf".into(), "sudo".into()],
            max_runtime_s: Some(600),
            model: None,
            on_fallback: false,
            interactive: false,
            resume_session: None,
            ask_for_edits: false,
        }
    }

    #[test]
    fn the_prompt_is_standard_input_never_argv_and_the_key_only_in_the_environment() {
        let mut e = ClaudeCodeEngine::new(FakeTransport::default());
        let h = e.start(&start(Some("sk-ant-SECRETVALUE123"))).unwrap();
        let t = e.transport();
        let l = &t.launches[0];
        let argv = l.argv.join("\u{1}");
        assert!(
            !argv.contains("Fix the parser"),
            "the prompt is not an argument"
        );
        assert!(!argv.contains("SECRETVALUE"));
        assert_eq!(
            l.env.get("ANTHROPIC_API_KEY").map(String::as_str),
            Some("sk-ant-SECRETVALUE123")
        );
        assert!(
            !format!("{l:?}").contains("SECRETVALUE"),
            "Debug hides the environment"
        );
        assert_eq!(l.argv[0..4], ["sh", "-c", WRAPPER, "sh"]);
        assert_eq!(l.argv[4], "claude");
        assert!(l.argv.contains(&"stream-json".to_string()));
        assert!(l
            .argv
            .windows(2)
            .any(|w| w[0] == "--disallowedTools" && w[1] == "Bash(rm -rf:*)"));
        assert_eq!(l.cwd.as_deref(), Some("/work/repos/web"));
        assert_eq!(l.labels.get("kind").map(String::as_str), Some("agent"));
        assert!(l.stdin.as_deref().unwrap().contains("Fix the parser"));
        assert!(
            !format!("{l:?}").contains("Fix the parser"),
            "Debug hides the prompt"
        );
        e.stop(&h).unwrap();
        assert!(e.transport().stopped);
    }

    #[test]
    fn the_model_chosen_for_the_run_is_passed_and_a_prompt_over_the_long_limit_is_refused() {
        let mut e = ClaudeCodeEngine::new(FakeTransport::default());
        let mut req = start(None);
        req.model = Some("claude-sonnet-4-5".into());
        e.start(&req).unwrap();
        let argv = &e.transport().launches[0].argv;
        assert!(argv
            .windows(2)
            .any(|w| w[0] == "--model" && w[1] == "claude-sonnet-4-5"));
        let mut e2 = ClaudeCodeEngine::new(FakeTransport::default());
        req.prompt = "x".repeat(MAX_LONG_PROMPT_BYTES + 1);
        assert!(matches!(e2.start(&req), Err(EngineError::Failed(m)) if m.contains("too long")));
        assert!(e2.transport().launches.is_empty());
    }

    #[test]
    fn a_rate_limit_error_is_the_provider_refusing_and_other_errors_are_failures() {
        let mut st = StreamState::default();
        let rate = r#"{"type":"result","subtype":"error_during_execution","is_error":true,"result":"API Error: 429 rate limit exceeded"}"#;
        assert!(parse_line(rate, &mut st)
            .iter()
            .any(|e| matches!(e, EngineEvent::ProviderRefused(t) if t.contains("429"))));
        let other = r#"{"type":"result","subtype":"error_during_execution","is_error":true,"result":"tests still fail"}"#;
        assert!(parse_line(other, &mut st)
            .iter()
            .any(|e| matches!(e, EngineEvent::Failed(_))));
        assert!(looks_like_refusal("The API is Overloaded"));
        assert!(!looks_like_refusal("the build failed"));
    }

    #[test]
    fn stream_json_becomes_log_usage_and_a_finish_and_cost_is_counted_once() {
        let mut e = ClaudeCodeEngine::new(FakeTransport::default());
        let h = e.start(&start(None)).unwrap();
        let log = concat!(
            "{\"type\":\"system\",\"subtype\":\"init\"}\n",
            "{\"type\":\"assistant\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"Reading the parser\"},{\"type\":\"tool_use\",\"name\":\"Read\",\"input\":{\"file\":\"x\"}}],\"id\":\"msg_1\",\"model\":\"claude-sonnet-4-5\",\"usage\":{\"input_tokens\":100,\"output_tokens\":20,\"cache_read_input_tokens\":50}}}\n",
            "{\"type\":\"assistant\",\"message\":{\"id\":\"msg_1\",\"content\":[],\"usage\":{\"input_tokens\":100,\"output_tokens\":20,\"cache_read_input_tokens\":50}}}\n",
            "{\"type\":\"result\",\"subtype\":\"success\",\"is_error\":false,\"result\":\"Fixed it\",\"total_cost_usd\":0.1234}\n"
        );
        // delivered in two pieces, the second cutting a line in half
        let cut = log.len() - 40;
        e.transport.log = log.as_bytes()[..cut].to_vec();
        let first = e.poll(&h).unwrap();
        assert!(first.contains(&EngineEvent::Log("Reading the parser".into())));
        assert!(first.contains(&EngineEvent::Log("using Read".into())));
        let usage = EngineEvent::TokenUsage {
            input_tokens: 100,
            output_tokens: 20,
            cached_input_tokens: 50,
            model: Some("claude-sonnet-4-5".into()),
        };
        assert!(first.contains(&usage));
        assert_eq!(
            first.iter().filter(|x| **x == usage).count(),
            1,
            "a message printed twice is counted once"
        );
        assert!(!first
            .iter()
            .any(|x| matches!(x, EngineEvent::Finished { .. })));
        e.transport.log = log.as_bytes().to_vec();
        let second = e.poll(&h).unwrap();
        assert!(second.contains(&EngineEvent::ReportedCost { cents: 12 }));
        assert!(
            matches!(second.last(), Some(EngineEvent::Finished { summary, .. }) if summary == "Fixed it")
        );
        assert!(e.poll(&h).unwrap().is_empty());
    }

    #[test]
    fn an_error_result_or_an_exit_without_a_result_is_a_failure() {
        let mut st = StreamState::default();
        let ev = parse_line("{\"type\":\"result\",\"subtype\":\"error_max_turns\",\"is_error\":true,\"result\":\"too many turns\"}", &mut st);
        assert!(matches!(ev.last(), Some(EngineEvent::Failed(m)) if m == "too many turns"));
        let mut e = ClaudeCodeEngine::new(FakeTransport::default());
        let h = e.start(&start(None)).unwrap();
        e.transport.exit = Some(137);
        let ev = e.poll(&h).unwrap();
        assert_eq!(
            ev,
            vec![EngineEvent::Failed("the agent exited with code 137".into())]
        );
    }

    #[test]
    fn a_dropped_connection_is_tolerated_for_a_while_and_then_the_run_is_given_up_on() {
        struct Flaky {
            fail: bool,
        }
        impl RunTransport for Flaky {
            fn launch(&mut self, _: &str, _: &Launch) -> Result<String, String> {
                Ok("run-1".into())
            }
            fn read_log(&mut self, _: &str, _: &str, from: u64) -> Result<LogChunk, String> {
                if self.fail {
                    Err("the box could not be reached".into())
                } else {
                    Ok(LogChunk {
                        bytes: Vec::new(),
                        next: from,
                        exited: None,
                    })
                }
            }
            fn stop(&mut self, _: &str, _: &str) -> Result<(), String> {
                Ok(())
            }
            fn send(&mut self, _: &str, _: &str, _: &str, _: bool) -> Result<(), String> {
                Ok(())
            }
        }
        let mut e = ClaudeCodeEngine::new(Flaky { fail: false });
        let h = e.start(&start(None)).unwrap();
        e.transport_mut().fail = true;
        for _ in 0..MAX_POLL_FAILURES - 1 {
            assert!(e.poll(&h).unwrap().is_empty());
        }
        // it comes back: the count starts again
        e.transport_mut().fail = false;
        assert!(e.poll(&h).unwrap().is_empty());
        e.transport_mut().fail = true;
        for _ in 0..MAX_POLL_FAILURES - 1 {
            assert!(e.poll(&h).is_ok());
        }
        assert!(matches!(e.poll(&h), Err(EngineError::Failed(m)) if m.contains("reached")));
    }

    #[test]
    fn a_resumed_run_is_told_where_its_work_is() {
        let mut req = start(None);
        req.resume_from = Some("wip/alpha/20261109".into());
        let p = build_prompt(&req);
        assert!(p.contains("wip/alpha/20261109") && p.contains("Fix the parser"));
    }

    #[test]
    fn a_conversation_reads_json_lines_keeps_its_input_open_and_a_result_ends_a_turn_not_the_run() {
        let mut st = start(None);
        st.interactive = true;
        let mut e = ClaudeCodeEngine::new(FakeTransport::default());
        let h = e.start(&st).unwrap();
        let l = &e.transport().launches[0];
        assert!(l.keep_stdin_open);
        assert!(l
            .argv
            .windows(2)
            .any(|w| w == ["--input-format", "stream-json"]));
        let first: Value = serde_json::from_str(l.stdin.as_deref().unwrap().trim()).unwrap();
        assert_eq!(first["type"], "user");
        assert_eq!(first["message"]["content"][0]["text"], build_prompt(&st));
        // a later message is another line on the same input, never an argument
        e.send(&h, "now the tests").unwrap();
        let (line, close) = e.transport().sent[0].clone();
        assert!(!close && line.ends_with('\n') && line.contains("now the tests"));
        // the stream: session id, a reply, a result = the turn is done, the run is not
        e.transport_mut().log = concat!(
            "{\"type\":\"system\",\"subtype\":\"init\",\"session_id\":\"sess-1\"}\n",
            "{\"type\":\"result\",\"subtype\":\"success\",\"session_id\":\"sess-1\",\"is_error\":false,\"result\":\"All done here\",\"total_cost_usd\":0.02}\n"
        )
        .as_bytes()
        .to_vec();
        let ev = e.poll(&h).unwrap();
        assert!(ev.contains(&EngineEvent::Session("sess-1".into())));
        assert!(ev.contains(&EngineEvent::TurnDone("All done here".into())));
        assert!(!ev.iter().any(|x| matches!(x, EngineEvent::Finished { .. })));
        // a run that is not a conversation refuses messages
        let mut e2 = ClaudeCodeEngine::new(FakeTransport::default());
        let h2 = e2.start(&start(None)).unwrap();
        assert!(e2.send(&h2, "x").is_err());
    }

    #[test]
    fn a_run_a_chat_app_started_is_launched_in_the_default_permission_mode() {
        let mode = |v: &[String]| {
            let i = v.iter().position(|a| a == "--permission-mode").unwrap();
            v[i + 1].clone()
        };
        assert_eq!(
            mode(&build_argv_for(&[], None, false, None, false)),
            "acceptEdits"
        );
        assert_eq!(
            mode(&build_argv_for(&[], None, true, None, true)),
            "default"
        );
        assert_eq!(mode(&build_argv(&[], None)), "acceptEdits");
        // and the engine passes the choice on from the start request
        let mut req = start(None);
        req.ask_for_edits = true;
        let mut e = ClaudeCodeEngine::new(FakeTransport::default());
        e.start(&req).unwrap();
        let argv = &e.transport.launches.last().unwrap().argv;
        assert_eq!(mode(argv), "default");
        assert!(!argv.iter().any(|a| a == "acceptEdits"));
    }

    #[test]
    fn a_continued_conversation_names_its_session_and_a_bad_id_is_never_passed() {
        let v = build_argv_for(&[], None, true, Some("abc-123_X"), false);
        assert!(v.windows(2).any(|w| w == ["--resume", "abc-123_X"]));
        let bad = build_argv_for(&[], None, true, Some("x; rm -rf /"), false);
        assert!(!bad.iter().any(|a| a == "--resume"));
        // a leading dash would be read by claude as a flag
        let flag = build_argv_for(
            &[],
            None,
            true,
            Some("--dangerously-skip-permissions"),
            false,
        );
        assert!(!flag
            .iter()
            .any(|a| a == "--resume" || a.starts_with("--dangerously")));
        assert!(!is_resume_id("-x") && !is_resume_id("_x") && is_resume_id("0a-b_c"));
    }

    #[test]
    fn a_prompt_longer_than_one_request_goes_in_pieces_over_an_input_kept_open_then_closed() {
        let mut st = start(None);
        st.prompt = "é".repeat(60_000); // 120 KB
        let mut e = ClaudeCodeEngine::new(FakeTransport::default());
        e.start(&st).unwrap();
        let t = e.transport();
        assert!(t.launches[0].keep_stdin_open);
        let head = t.launches[0].stdin.as_ref().unwrap();
        assert!(head.len() <= PROMPT_PIECE_BYTES);
        let joined: String =
            head.clone() + &t.sent.iter().map(|(s, _)| s.as_str()).collect::<String>();
        assert!(joined.contains(&"é".repeat(1000)) && joined.len() > 120_000);
        assert!(t.sent.last().unwrap().1, "the last piece closes the input");
        assert!(t.sent[..t.sent.len() - 1].iter().all(|(_, c)| !c));
        // too long altogether
        st.prompt = "x".repeat(MAX_LONG_PROMPT_BYTES + 1);
        assert!(ClaudeCodeEngine::new(FakeTransport::default())
            .start(&st)
            .is_err());
        // pieces never split a character
        assert!(pieces(&"é".repeat(10), 3)
            .iter()
            .all(|p| p.chars().all(|c| c == 'é')));
    }
}
