//! What coding agents on this box say about themselves: "needs input", "finished", "asks permission".
//!
//! Any coding agent in a repo can report here, whichever program it is, by the best mechanism it offers. The agent's own
//! hook runs `ozboxd hook <engine>`, which posts what it was given to this daemon's socket:
//!
//! * `POST /v1/agent-events` with `{ "engine": "claude-code", "payload": { ... } }` records one event and, for a permission
//!   request, opens a pending decision and returns its id.
//! * `GET /v1/agent-events?since=<seq>` returns the events after `seq`, the pending permission requests and the state of
//!   every session (waiting for input, or busy).
//! * `GET /v1/agent-events/permission/<id>` reads a request. No socket of the daemon takes its answer: a process on the box
//!   that could post one could approve its own request, so the answer is made by a person through a path that carries
//!   the signed-in person (none is built yet). A request nobody answers is denied when it lapses, never approved.
//!
//! The levels of integration, per engine, and where each comes from (checked in the engine's own documentation):
//!
//! * Claude Code: hooks in `~/.claude/settings.json` (`Notification`, `Stop`, `PreToolUse`, `UserPromptSubmit`; and `SessionStart`/`SessionEnd` for the session record), exec form
//!   with `args`, a `PreToolUse` answer of `permissionDecision` allow, deny or ask. <https://code.claude.com/docs/en/hooks>
//! * Gemini CLI: the same hook shape in `~/.gemini/settings.json` (`Notification`, `BeforeAgent`, `AfterAgent`, `BeforeTool`; times in
//!   milliseconds). <https://github.com/google-gemini/gemini-cli/blob/main/docs/hooks/index.md> Its input schema is not on
//!   that page, so the fields read here are read defensively and an unreadable payload is still a "needs input".
//! * Codex: `notify = ["program", "args"]` in `~/.codex/config.toml`, called with one JSON argument; the only event is
//!   `agent-turn-complete`, so there is no permission routing. <https://learn.chatgpt.com/docs/config-file/config-advanced>
//!   A `notify` the person already set is left alone (it holds one program), and the engine stays at the basic level.
//! * Aider: `--notifications-command` fires when it waits for input
//!   (<https://aider.chat/docs/usage/notifications.html>). It is a flag or setting of the person's, so nothing is written.
//! * OpenCode and anything else: no documented hook was confirmed, so they use the terminal fallback (basic level).
//!
//! Event text is bounded and has secret-looking words removed. The log lives in memory: a restart of the daemon forgets it,
//! and an agent that is still waiting reports again at its next event.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use serde_json::{json, Value};

/// The most events kept, and how long one detail may be.
pub const MAX_EVENTS: usize = 500;
pub const MAX_DETAIL: usize = 300;
/// A permission request nobody answers is denied after this long. Shorter than a hook's default timeout (600 s), so the
/// agent gets an answer instead of timing out into its own prompt.
pub const PERMISSION_TTL_MS: u64 = 9 * 60_000;
pub const MAX_PENDING: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    NeedsInput,
    /// The agent's own terminal is asking whether it may do something (Claude Code's permission notification). Kept apart from
    /// `NeedsInput`: a line typed now would answer that question, so nothing but the person at the terminal may type.
    PermissionPrompt,
    Finished,
    Permission,
    Busy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AgentEvent {
    pub seq: u64,
    pub ts_ms: u64,
    pub engine: String,
    pub kind: Kind,
    /// The agent's own session id (opaque), and the folder it works in.
    pub session: String,
    pub cwd: String,
    /// The terminal (tmux pane id) the agent runs in, as its hook saw it. Empty when the hook did not run in tmux.
    pub pane: String,
    /// The tool, for a permission request.
    pub tool: Option<String>,
    /// A bounded, cleaned line: the command or file for a permission request, the message otherwise.
    pub detail: String,
    /// The pending decision, for a permission request.
    pub permission: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Pending,
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize)]
pub struct Permission {
    pub id: String,
    pub seq: u64,
    pub engine: String,
    pub cwd: String,
    pub tool: String,
    pub detail: String,
    pub created_ms: u64,
    pub state: Decision,
}

/// Whether a session is at its prompt (messages may be typed to it) or working.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Waiting,
    Busy,
    /// At a permission prompt: not a place to type a message (a typed line would answer the prompt).
    Asking,
}

/// What one terminal's agent last said. Kept per terminal (per agent process), never per folder: two agents in one repository
/// are two answers, and one finishing says nothing about the other's open question.
#[derive(Debug, Clone)]
struct PaneState {
    engine: String,
    state: SessionState,
    ts_ms: u64,
    /// A per-turn hook (`UserPromptSubmit`, `BeforeAgent`) has fired for this terminal: the proof that "finished" is followed
    /// by "busy" again, so a stale "waiting" cannot outlive the next turn.
    turn_hook_seen: bool,
    /// The permission mode Claude Code last reported from this terminal (`permission_mode` in its hook input: `default`,
    /// `plan`, `acceptEdits`, `auto`, `dontAsk` or `bypassPermissions`; <https://code.claude.com/docs/en/hooks>). Kept as heard,
    /// bounded to letters; not every event carries it, so an event without one leaves the last one standing. What a chat
    /// app may do depends on it (see [`crate::agent_sessions::Authority`]).
    mode: Option<String>,
}

#[derive(Debug, Default)]
pub struct EventLog {
    next_seq: u64,
    next_perm: u64,
    events: VecDeque<AgentEvent>,
    perms: BTreeMap<String, Permission>,
    /// The latest state by working folder (what the feed shows; never what decides whether typing is safe).
    states: BTreeMap<String, (SessionState, u64)>,
    /// The latest state by terminal: the only thing a typed line is checked against.
    panes: BTreeMap<String, PaneState>,
}

/// Engines whose own hooks prove a turn started. For these, "waiting" counts only after such a hook has fired in that
/// terminal (see [`PaneState::turn_hook_seen`]).
fn needs_turn_hook(engine: &str) -> bool {
    matches!(engine, "claude-code" | "gemini")
}

/// Remove control characters and secret-looking words, and bound the length.
pub fn clean(text: &str) -> String {
    let mut words = Vec::new();
    let mut hide_next = false;
    for w in text.split_whitespace() {
        let lower = w.to_ascii_lowercase();
        let trimmed = w.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_');
        let keyish = [
            "sk-",
            "ghp_",
            "gho_",
            "github_pat_",
            "xoxb-",
            "xapp-",
            "AKIA",
            "ozrt_",
        ]
        .iter()
        .any(|p| trimmed.starts_with(p))
            && w.len() >= 12;
        if hide_next {
            words.push("[hidden]".to_string());
            hide_next = false;
        } else if lower == "bearer" {
            words.push(w.to_string());
            hide_next = true;
        } else if keyish {
            words.push("[hidden]".to_string());
        } else if let Some((name, _)) = w.split_once('=') {
            let n = name.to_ascii_uppercase();
            if ["KEY", "TOKEN", "SECRET", "PASSWORD"]
                .iter()
                .any(|k| n.contains(k))
            {
                words.push(format!("{name}=[hidden]"));
            } else {
                words.push(w.to_string());
            }
        } else {
            words.push(w.to_string());
        }
    }
    words
        .join(" ")
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_DETAIL)
        .collect()
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

/// What a tool call is, in one cleaned line: the command for a shell tool, else the file or URL it names.
pub fn tool_detail(input: &Value) -> String {
    for k in ["command", "file_path", "path", "url", "pattern"] {
        if let Some(t) = input.get(k).and_then(Value::as_str) {
            return clean(t);
        }
    }
    String::new()
}

/// Which tool calls are worth asking a person about: a shell command that starts with, or contains, one of `ask`.
pub fn needs_ask(tool: &str, input: &Value, ask: &[String]) -> bool {
    let is_shell = matches!(tool, "Bash" | "run_shell_command" | "shell");
    if !is_shell {
        return false;
    }
    let cmd = input.get("command").and_then(Value::as_str).unwrap_or("");
    ask.iter().filter(|a| !a.trim().is_empty()).any(|a| {
        cmd.trim_start().starts_with(a.trim())
            || cmd.contains(&format!(" {}", a.trim()))
            || cmd.contains(&format!("&& {}", a.trim()))
    })
}

/// The default commands a hook asks about.
pub const DEFAULT_ASK: [&str; 3] = ["git push", "sudo", "rm -rf"];

/// What one agent payload means, per engine. `None` for a payload that says nothing worth reporting.
pub fn normalize(
    engine: &str,
    payload: &Value,
    cwd_default: &str,
) -> Option<(Kind, String, String, Option<String>, String)> {
    // (kind, session, cwd, tool, detail)
    let cwd = payload
        .get("cwd")
        .and_then(Value::as_str)
        .filter(|c| c.starts_with('/'))
        .unwrap_or(cwd_default)
        .to_string();
    match engine {
        "claude-code" | "gemini" => {
            let session = clean(s(payload, "session_id"))
                .chars()
                .take(100)
                .collect::<String>();
            match s(payload, "hook_event_name") {
                "Stop" | "AfterAgent" => Some((
                    Kind::Finished,
                    session,
                    cwd,
                    None,
                    clean(s(payload, "message")),
                )),
                // a helper agent finishing says nothing about the main one, which is still working
                "UserPromptSubmit" | "BeforeAgent" | "SubagentStop" => {
                    Some((Kind::Busy, session, cwd, None, String::new()))
                }
                "Notification" => {
                    let message = s(payload, "message");
                    // Fail closed: only a notification that positively says "idle, waiting at the prompt" is
                    // `NeedsInput`. A permission prompt, an MCP question (`elicitation_dialog`), a type this code has
                    // never heard of and one with no type at all are all "the terminal is asking", so that no line
                    // typed from outside can answer it.
                    let kind = if s(payload, "notification_type") == "idle_prompt" {
                        Kind::NeedsInput
                    } else {
                        Kind::PermissionPrompt
                    };
                    Some((kind, session, cwd, None, clean(message)))
                }
                "PreToolUse" | "BeforeTool" => {
                    let tool = clean(s(payload, "tool_name"));
                    let input = payload.get("tool_input").cloned().unwrap_or(Value::Null);
                    Some((
                        Kind::Permission,
                        session,
                        cwd,
                        Some(tool),
                        tool_detail(&input),
                    ))
                }
                _ => None,
            }
        }
        "codex" => {
            if s(payload, "type") != "agent-turn-complete" {
                return None;
            }
            Some((
                Kind::Finished,
                clean(s(payload, "thread-id")).chars().take(100).collect(),
                cwd,
                None,
                clean(s(payload, "last-assistant-message")),
            ))
        }
        // Aider calls its command when it waits for input, with nothing to read.
        "aider" => Some((Kind::NeedsInput, String::new(), cwd, None, String::new())),
        _ => None,
    }
}

impl EventLog {
    pub fn new() -> Self {
        Self::default()
    }

    fn push(&mut self, mut e: AgentEvent) -> u64 {
        self.next_seq += 1;
        e.seq = self.next_seq;
        let state = match e.kind {
            Kind::NeedsInput | Kind::Finished => Some(SessionState::Waiting),
            Kind::PermissionPrompt => Some(SessionState::Asking),
            Kind::Busy | Kind::Permission => Some(SessionState::Busy),
        };
        if let Some(st) = state {
            if !e.pane.is_empty() {
                let prev = self.panes.get(&e.pane).filter(|p| p.engine == e.engine);
                let was_asking = prev.is_some_and(|p| p.state == SessionState::Asking);
                let turn_hook_seen = e.kind == Kind::Busy || prev.is_some_and(|p| p.turn_hook_seen);
                // An "idle" notice does not lift a question: whether Claude Code can send one while a dialog is still open is
                // not established, so only the agent's next real step (a prompt, a tool call, `Stop`) ends "asking".
                let st = if e.kind == Kind::NeedsInput && was_asking {
                    SessionState::Asking
                } else {
                    st
                };
                self.panes.insert(
                    e.pane.clone(),
                    PaneState {
                        engine: e.engine.clone(),
                        state: st,
                        ts_ms: e.ts_ms,
                        turn_hook_seen,
                        // the last mode stands until another is heard (another program in the pane drops it with the rest)
                        mode: prev.and_then(|p| p.mode.clone()),
                    },
                );
                while self.panes.len() > 200 {
                    let oldest = self
                        .panes
                        .iter()
                        .min_by_key(|(_, p)| p.ts_ms)
                        .map(|(k, _)| k.clone());
                    match oldest {
                        Some(k) => self.panes.remove(&k),
                        None => break,
                    };
                }
            }
            self.states.insert(e.cwd.clone(), (st, e.ts_ms));
            while self.states.len() > 200 {
                let Some(k) = self.states.keys().next().cloned() else {
                    break;
                };
                self.states.remove(&k);
            }
        }
        let seq = e.seq;
        self.events.push_back(e);
        while self.events.len() > MAX_EVENTS {
            self.events.pop_front();
        }
        seq
    }

    /// Record a report from an agent whose terminal is not known.
    pub fn report(
        &mut self,
        engine: &str,
        payload: &Value,
        cwd_default: &str,
        now_ms: u64,
    ) -> Result<(u64, Option<String>), &'static str> {
        self.report_in_pane(engine, payload, cwd_default, "", now_ms)
    }

    /// Record a report. `pane` is the tmux pane the agent's hook ran in (`TMUX_PANE`), or empty; anything that is not a pane
    /// id is taken as empty. Returns the event's sequence number and, for a permission request, its id.
    pub fn report_in_pane(
        &mut self,
        engine: &str,
        payload: &Value,
        cwd_default: &str,
        pane: &str,
        now_ms: u64,
    ) -> Result<(u64, Option<String>), &'static str> {
        let pane = if crate::agent_sessions::valid_pane_id(pane) {
            pane.to_string()
        } else {
            String::new()
        };
        let engine: String = engine
            .chars()
            .filter(|c| c.is_ascii_lowercase() || *c == '-')
            .take(24)
            .collect();
        if engine.is_empty() {
            return Err("name the agent program");
        }
        let Some((kind, session, cwd, tool, detail)) = normalize(&engine, payload, cwd_default)
        else {
            return Err("that is not an event this daemon records");
        };
        let mut permission = None;
        if kind == Kind::Permission {
            self.expire(now_ms);
            if self
                .perms
                .values()
                .filter(|p| p.state == Decision::Pending)
                .count()
                >= MAX_PENDING
            {
                return Err("too many requests are waiting for an answer");
            }
            self.next_perm += 1;
            let id = format!("p{}", self.next_perm);
            permission = Some(id.clone());
            self.perms.insert(
                id.clone(),
                Permission {
                    id,
                    seq: self.next_seq + 1,
                    engine: engine.clone(),
                    cwd: cwd.clone(),
                    tool: tool.clone().unwrap_or_default(),
                    detail: detail.clone(),
                    created_ms: now_ms,
                    state: Decision::Pending,
                },
            );
        }
        let heard_mode = (engine == "claude-code")
            .then(|| s(payload, "permission_mode"))
            .filter(|m| {
                !m.is_empty() && m.len() <= 24 && m.chars().all(|c| c.is_ascii_alphabetic())
            })
            .map(str::to_string);
        let (engine_key, pane_key) = (engine.clone(), pane.clone());
        let seq = self.push(AgentEvent {
            seq: 0,
            ts_ms: now_ms,
            engine,
            kind,
            session,
            cwd,
            pane,
            tool,
            detail,
            permission: permission.clone(),
        });
        if !pane_key.is_empty() {
            if let Some(m) = heard_mode {
                if let Some(p) = self
                    .panes
                    .get_mut(&pane_key)
                    .filter(|p| p.engine == engine_key)
                {
                    p.mode = Some(m);
                }
            }
        }
        Ok((seq, permission))
    }

    /// The permission mode Claude Code last reported from this terminal, or `None` when none has been heard (or the pane
    /// holds another program).
    pub fn permission_mode(&self, pane: &str, engine: &str) -> Option<&str> {
        self.panes
            .get(pane)
            .filter(|p| p.engine == engine)
            .and_then(|p| p.mode.as_deref())
    }

    /// Requests nobody answered in time are denied.
    pub fn expire(&mut self, now_ms: u64) {
        for p in self.perms.values_mut() {
            if p.state == Decision::Pending
                && now_ms.saturating_sub(p.created_ms) >= PERMISSION_TTL_MS
            {
                p.state = Decision::Deny;
            }
        }
        while self.perms.len() > 100 {
            let Some(k) = self
                .perms
                .iter()
                .find(|(_, p)| p.state != Decision::Pending)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            self.perms.remove(&k);
        }
    }

    pub fn permission(&mut self, id: &str, now_ms: u64) -> Option<Permission> {
        self.expire(now_ms);
        self.perms.get(id).cloned()
    }

    /// Answer a request once. A second answer, or one for a request that lapsed, changes nothing.
    pub fn decide(&mut self, id: &str, allow: bool, now_ms: u64) -> Result<Decision, &'static str> {
        self.expire(now_ms);
        let p = self.perms.get_mut(id).ok_or("no such request")?;
        if p.state != Decision::Pending {
            return Err("that request was already answered or has lapsed");
        }
        p.state = if allow {
            Decision::Allow
        } else {
            Decision::Deny
        };
        Ok(p.state)
    }

    /// What the agent in this terminal last said, or `None` when nothing is known: no event from a hook in that terminal, an
    /// event from another program (the pane id was reused), or a "waiting" that nothing proves is current (see
    /// [`PaneState::turn_hook_seen`]). Never a guess from a neighbouring folder or another agent's report.
    pub fn state_of_pane(&self, pane: &str, engine: &str) -> Option<SessionState> {
        let p = self.panes.get(pane).filter(|p| p.engine == engine)?;
        if p.state == SessionState::Waiting && needs_turn_hook(engine) && !p.turn_hook_seen {
            return None;
        }
        Some(p.state)
    }

    /// Has a hook of this engine reported from this terminal? That is what "hooks level" means, not the program's name.
    pub fn hook_seen(&self, pane: &str, engine: &str) -> bool {
        self.panes.get(pane).is_some_and(|p| p.engine == engine)
    }

    pub fn snapshot(&mut self, since: u64, now_ms: u64) -> Value {
        self.expire(now_ms);
        let events: Vec<&AgentEvent> = self.events.iter().filter(|e| e.seq > since).collect();
        let pending: Vec<&Permission> = self
            .perms
            .values()
            .filter(|p| p.state == Decision::Pending)
            .collect();
        let states: Vec<Value> = self
            .states
            .iter()
            .map(|(cwd, (st, ts))| json!({ "cwd": cwd, "state": st, "ts_ms": ts }))
            .collect();
        json!({ "last_seq": self.next_seq, "events": events, "pending": pending, "states": states })
    }
}

static GLOBAL: OnceLock<Mutex<EventLog>> = OnceLock::new();

pub fn global() -> &'static Mutex<EventLog> {
    GLOBAL.get_or_init(|| Mutex::new(EventLog::new()))
}

// ---- the hook: what the agent runs ------------------------------------------------------------------------------

/// The answer a Claude Code or Gemini `PreToolUse` hook prints for a decision.
pub fn permission_answer(engine: &str, decision: Decision, why: &str) -> Value {
    let verdict = if decision == Decision::Allow {
        "allow"
    } else {
        "deny"
    };
    if engine == "gemini" {
        return json!({ "decision": verdict, "reason": why });
    }
    json!({ "hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": verdict,
        "permissionDecisionReason": why,
    }})
}

/// Does any caller answer a permission request yet? Not today: no socket of this daemon takes the answer, and
/// the dashboard has no caller for it. Until one exists the hook does not wait nine minutes to be denied: it hands the
/// question back to the person in their own terminal ([`permission_ask`]). Turn this on only together with that caller
/// (the signed-in person, a step-up for risky tools, the decision on the audit chain).
pub const PERMISSION_ANSWERS_AVAILABLE: bool = false;

/// "Ask the person" in the shape the agent documents, or `None` for an engine with no such answer (it gets no opinion from
/// the hook, so its own rules apply). Claude Code's `permissionDecision: "ask"` makes the agent prompt in its own terminal.
pub fn permission_ask(engine: &str, why: &str) -> Option<Value> {
    (engine == "claude-code").then(|| {
        json!({ "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": why,
        }})
    })
}

/// The marker every hook this daemon installs carries, so an install is recognised and never doubled.
pub const MARKER: &str = "ozboxd hook";

fn handler(binary: &str, engine: &str, timeout: Value) -> Value {
    json!({ "type": "command", "command": binary, "args": ["hook", engine], "timeout": timeout, "name": MARKER })
}

/// Add this daemon's hooks to a settings document (Claude Code or Gemini). Everything the person already has is kept,
/// in order; a hook that is already ours is not added again; a settings value that is not an object is refused rather than
/// replaced.
pub fn merge_hooks(existing: &str, binary: &str, engine: &str) -> Result<String, &'static str> {
    let events: &[(&str, &str)] = if engine == "gemini" {
        &[
            ("Notification", ""),
            ("BeforeAgent", ""),
            ("AfterAgent", ""),
            ("BeforeTool", "run_shell_command"),
        ]
    } else {
        &[
            ("Notification", ""),
            ("Stop", ""),
            ("UserPromptSubmit", ""),
            ("PreToolUse", "Bash"),
        ]
    };
    // Claude's timeout is seconds, Gemini's is milliseconds. A permission waits up to nine minutes.
    let timeout = |ev: &str| match (engine, ev) {
        ("gemini", "BeforeTool") => json!(570_000),
        ("gemini", _) => json!(10_000),
        (_, "PreToolUse") => json!(570),
        _ => json!(10),
    };
    merge_events(existing, events, MARKER, &|ev| {
        handler(binary, engine, timeout(ev))
    })
}

/// The events the session record needs, for Claude Code. `SessionStart` and `UserPromptSubmit` and `Stop` keep the record
/// current; `SessionEnd` removes it when the person ended the session.
pub const RECORD_EVENTS: [&str; 4] = ["SessionStart", "SessionEnd", "UserPromptSubmit", "Stop"];

/// Is this hook handler ours: the exact `ozboxd session-hook claude-code` command, wherever the binary lives. Recognised by
/// what it runs, never by a field Claude Code does not document (`name`), so a settings file that Claude Code has rewritten
/// is still seen as ours and is not added to again.
fn is_record_handler(h: &Value, binary: &str) -> bool {
    let args_ok = h.get("args").and_then(Value::as_array).is_some_and(|a| {
        a.len() == 2
            && a[0].as_str() == Some("session-hook")
            && a[1].as_str() == Some("claude-code")
    });
    let cmd_ok = h
        .get("command")
        .and_then(Value::as_str)
        .is_some_and(|c| c == binary || c.rsplit('/').next() == Some("ozboxd"));
    args_ok && cmd_ok
}

/// A JSON object as its entries in file order, each value kept as the text it was written as. Parsing a settings file into
/// `serde_json::Value` sorts every object's keys (the crate is not built with `preserve_order`, which would change the size and
/// output of every `Value` in the workspace), so a file Claude Code wrote in its own order would be re-sorted by every edit.
struct Entries(Vec<(String, Box<RawValue>)>);

impl<'de> Deserialize<'de> for Entries {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Entries;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("an object")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut m: A,
            ) -> Result<Entries, A::Error> {
                let mut v = Vec::new();
                while let Some(kv) = m.next_entry::<String, Box<RawValue>>()? {
                    v.push(kv);
                }
                Ok(Entries(v))
            }
        }
        d.deserialize_map(V)
    }
}

impl Serialize for Entries {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut m = s.serialize_map(Some(self.0.len()))?;
        for (k, v) in &self.0 {
            m.serialize_entry(k, v)?;
        }
        m.end()
    }
}

impl Entries {
    fn parse(text: &str) -> Result<Entries, serde_json::Error> {
        serde_json::from_str(text)
    }
    fn index(&self, key: &str) -> Option<usize> {
        self.0.iter().position(|(k, _)| k == key)
    }
    fn count(&self, key: &str) -> usize {
        self.0.iter().filter(|(k, _)| k == key).count()
    }
    fn set(&mut self, key: &str, text: String) -> Result<(), &'static str> {
        let raw = RawValue::from_string(text).map_err(|_| "the settings could not be written")?;
        match self.index(key) {
            Some(i) => self.0[i].1 = raw,
            None => self.0.push((key.to_string(), raw)),
        }
        Ok(())
    }
}

/// Add the session-record hooks, and only those, to a Claude Code settings document. They run `ozboxd session-hook`, which
/// writes or removes the record and nothing else: it prints nothing, never asks, never denies and never talks to the event
/// feed, so a person's permission settings and a supervised run (`claude -p`) are exactly as they were. Nothing else in
/// the document is touched: every key keeps its place, and everything that is not ours is kept as the text it was written as.
/// `Ok(None)` means nothing needs to change: the hooks are all there, so the file is not written (and is not even
/// re-formatted). A hook that is ours but points at another path of the binary is pointed at `binary` (that one group is
/// re-written, with its keys sorted).
pub fn merge_record_hooks_changed(
    existing: &str,
    binary: &str,
) -> Result<Option<String>, &'static str> {
    let mut root = if existing.trim().is_empty() {
        Entries(Vec::new())
    } else {
        Entries::parse(existing).map_err(|e| {
            if e.is_syntax() || e.is_eof() {
                "the settings file is not valid JSON, so it was left alone"
            } else {
                "the settings file is not an object, so it was left alone"
            }
        })?
    };
    if root.count("hooks") > 1 {
        return Err("the settings file has the hooks setting twice, so it was left alone");
    }
    let mut hooks = match root.index("hooks") {
        Some(i) => Entries::parse(root.0[i].1.get())
            .map_err(|_| "the hooks setting is not an object, so it was left alone")?,
        None => Entries(Vec::new()),
    };
    let mut changed = root.index("hooks").is_none();
    if RECORD_EVENTS.iter().any(|ev| hooks.count(ev) > 1) {
        return Err("a hooks entry appears twice, so the settings file was left alone");
    }
    for ev in RECORD_EVENTS {
        let mut groups: Vec<Box<RawValue>> = match hooks.index(ev) {
            Some(i) => serde_json::from_str(hooks.0[i].1.get())
                .map_err(|_| "a hooks entry is not a list, so it was left alone")?,
            None => {
                changed = true;
                Vec::new()
            }
        };
        let mut found = false;
        let mut edited = false;
        for g in groups.iter_mut() {
            let Ok(mut v) = serde_json::from_str::<Value>(g.get()) else {
                continue;
            };
            let Some(hs) = v.get_mut("hooks").and_then(Value::as_array_mut) else {
                continue;
            };
            let mut group_changed = false;
            for h in hs.iter_mut().filter(|h| is_record_handler(h, binary)) {
                found = true;
                if h.get("command").and_then(Value::as_str) != Some(binary) {
                    h["command"] = json!(binary);
                    group_changed = true;
                }
            }
            if group_changed {
                *g = RawValue::from_string(v.to_string())
                    .map_err(|_| "the settings could not be written")?;
                edited = true;
            }
        }
        if !found {
            let new = json!({ "hooks": [{ "type": "command", "command": binary, "args": ["session-hook", "claude-code"], "timeout": 10 }] });
            groups.push(
                RawValue::from_string(new.to_string())
                    .map_err(|_| "the settings could not be written")?,
            );
            edited = true;
        }
        if edited {
            changed = true;
            let text = serde_json::to_string_pretty(&groups)
                .map_err(|_| "the settings could not be written")?;
            hooks.set(ev, text)?;
        }
    }
    if !changed {
        return Ok(None);
    }
    let hooks_text =
        serde_json::to_string_pretty(&hooks).map_err(|_| "the settings could not be written")?;
    root.set("hooks", hooks_text)?;
    serde_json::to_string_pretty(&root)
        .map(Some)
        .map_err(|_| "the settings could not be written")
}

/// [`merge_record_hooks_changed`], as the whole document: the existing text when nothing changes.
pub fn merge_record_hooks(existing: &str, binary: &str) -> Result<String, &'static str> {
    merge_record_hooks_changed(existing, binary).map(|n| n.unwrap_or_else(|| existing.to_string()))
}

fn merge_events(
    existing: &str,
    events: &[(&str, &str)],
    marker: &str,
    make: &dyn Fn(&str) -> Value,
) -> Result<String, &'static str> {
    let mut doc: Value = if existing.trim().is_empty() {
        json!({})
    } else {
        serde_json::from_str(existing)
            .map_err(|_| "the settings file is not valid JSON, so it was left alone")?
    };
    let Some(root) = doc.as_object_mut() else {
        return Err("the settings file is not an object, so it was left alone");
    };
    let hooks = root.entry("hooks").or_insert_with(|| json!({}));
    let Some(hooks) = hooks.as_object_mut() else {
        return Err("the hooks setting is not an object, so it was left alone");
    };
    for (ev, matcher) in events {
        let list = hooks.entry((*ev).to_string()).or_insert_with(|| json!([]));
        let Some(list) = list.as_array_mut() else {
            return Err("a hooks entry is not a list, so it was left alone");
        };
        let ours = list.iter().any(|g| {
            g.get("hooks").and_then(Value::as_array).is_some_and(|hs| {
                hs.iter()
                    .any(|h| h.get("name").and_then(Value::as_str) == Some(marker))
            })
        });
        if !ours {
            let mut group = json!({ "hooks": [make(ev)] });
            if !matcher.is_empty() {
                group["matcher"] = json!(matcher);
            }
            list.push(group);
        }
    }
    serde_json::to_string_pretty(&doc).map_err(|_| "the settings could not be written")
}

/// Whether the Codex config already sets its own `notify`, and the config with ours added when it does not.
pub fn merge_codex_notify(existing: &str, binary: &str) -> (String, bool) {
    let has = existing.lines().map(str::trim_start).any(|l| {
        l.starts_with("notify") && l.trim_start_matches("notify").trim_start().starts_with('=')
    });
    if has {
        return (existing.to_string(), false);
    }
    // a top-level key must come before any table
    let line = format!(
        "notify = [\"{}\", \"hook\", \"codex\"]\n",
        binary.replace('\\', "\\\\").replace('"', "\\\"")
    );
    (format!("{line}{existing}"), true)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_claude_permission_notification_is_kept_as_asking_and_an_idle_one_is_not() {
        let mut log = EventLog::new();
        let note = |msg: &str, kind: &str| json!({ "hook_event_name": "Notification", "cwd": "/work/repos/web", "message": msg, "notification_type": kind });
        log.report_in_pane(
            "claude-code",
            &note(
                "Claude needs your permission to use Bash",
                "permission_prompt",
            ),
            "/x",
            "%3",
            1,
        )
        .unwrap();
        assert_eq!(
            log.state_of_pane("%3", "claude-code"),
            Some(SessionState::Asking)
        );
        assert_eq!(
            log.snapshot(0, 2)["events"][0]["kind"],
            "permission_prompt",
            "the fact is in the event, not flattened to needs_input"
        );
        log.report_in_pane(
            "claude-code",
            &note("Claude is waiting for your input", "idle_prompt"),
            "/x",
            "%3",
            3,
        )
        .unwrap();
        // an idle notice alone does not lift a question; the next real step (here `Stop`) does, and it counts as waiting only
        // because a turn hook has fired in this terminal
        assert_eq!(
            log.state_of_pane("%3", "claude-code"),
            Some(SessionState::Asking)
        );
    }

    #[test]
    fn claude_events_become_needs_input_finished_busy_and_permission() {
        let mut log = EventLog::new();
        let stop =
            json!({ "hook_event_name": "Stop", "session_id": "s1", "cwd": "/work/repos/web" });
        let (seq, perm) = log
            .report_in_pane("claude-code", &stop, "/x", "%3", 1)
            .unwrap();
        assert_eq!((seq, perm), (1, None));
        assert_eq!(
            log.state_of_pane("%3", "claude-code"),
            None,
            "a Stop with no turn start ever heard in this terminal proves nothing"
        );
        log.report_in_pane(
            "claude-code",
            &json!({ "hook_event_name": "UserPromptSubmit", "cwd": "/work/repos/web" }),
            "/x",
            "%3",
            2,
        )
        .unwrap();
        assert_eq!(
            log.state_of_pane("%3", "claude-code"),
            Some(SessionState::Busy)
        );
        let pre = json!({ "hook_event_name": "PreToolUse", "session_id": "s1", "cwd": "/work/repos/web",
            "tool_name": "Bash", "tool_input": { "command": "git push origin main" } });
        let (_, perm) = log.report("claude-code", &pre, "/x", 3).unwrap();
        let id = perm.unwrap();
        let p = log.permission(&id, 4).unwrap();
        assert_eq!(
            (p.tool.as_str(), p.detail.as_str(), p.state),
            ("Bash", "git push origin main", Decision::Pending)
        );
        assert!(log.snapshot(0, 5)["pending"].as_array().unwrap().len() == 1);
        assert!(log
            .report(
                "claude-code",
                &json!({ "hook_event_name": "SomethingNew" }),
                "/x",
                5
            )
            .is_err());
    }

    #[test]
    fn a_permission_is_answered_once_and_a_lapsed_one_is_denied_never_approved() {
        let mut log = EventLog::new();
        let pre = json!({ "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": { "command": "sudo ls" } });
        let (_, id) = log
            .report("claude-code", &pre, "/work/repos/a", 100)
            .unwrap();
        let id = id.unwrap();
        assert_eq!(log.decide(&id, true, 200), Ok(Decision::Allow));
        assert!(log.decide(&id, false, 300).is_err(), "an answer is final");
        let (_, id2) = log
            .report("claude-code", &pre, "/work/repos/a", 1_000)
            .unwrap();
        let id2 = id2.unwrap();
        assert_eq!(
            log.permission(&id2, 1_000 + PERMISSION_TTL_MS)
                .unwrap()
                .state,
            Decision::Deny
        );
        assert!(
            log.decide(&id2, true, 1_000 + PERMISSION_TTL_MS + 1)
                .is_err(),
            "a lapsed request cannot be approved late"
        );
        assert!(log.decide("nope", true, 1).is_err());
    }

    #[test]
    fn codex_aider_and_unknown_engines_are_read_at_their_own_level() {
        let mut log = EventLog::new();
        let c = json!({ "type": "agent-turn-complete", "thread-id": "t9", "cwd": "/work/repos/api", "last-assistant-message": "done" });
        assert!(log.report("codex", &c, "/x", 1).is_ok());
        assert!(log
            .report("codex", &json!({ "type": "other" }), "/x", 1)
            .is_err());
        let (_, p) = log
            .report_in_pane("aider", &Value::Null, "/work/repos/lib", "%2", 2)
            .unwrap();
        assert!(p.is_none() && log.state_of_pane("%2", "aider") == Some(SessionState::Waiting));
        assert!(log.report("opencode", &json!({}), "/x", 3).is_err());
        assert!(log.report("", &json!({}), "/x", 3).is_err());
    }

    #[test]
    fn only_risky_shell_commands_are_asked_about_and_secrets_never_reach_an_event() {
        let ask: Vec<String> = DEFAULT_ASK.iter().map(|s| s.to_string()).collect();
        let b = |c: &str| json!({ "command": c });
        assert!(needs_ask("Bash", &b("git push"), &ask));
        assert!(needs_ask("Bash", &b("cd x && git push -f"), &ask));
        assert!(needs_ask("Bash", &b("sudo apt update"), &ask));
        assert!(!needs_ask("Bash", &b("git status"), &ask));
        assert!(
            !needs_ask("Edit", &b("git push"), &ask),
            "only shell commands are asked about"
        );
        let t = clean("curl -H Authorization: Bearer sk-ant-api03-SECRETSECRETSECRET https://x API_TOKEN=abc123 ok");
        assert!(
            !t.contains("SECRETSECRET") && !t.contains("abc123") && t.contains("ok"),
            "{t}"
        );
        assert!(clean(&"a".repeat(1000)).len() <= MAX_DETAIL);
    }

    #[test]
    fn merging_hooks_keeps_what_the_person_has_adds_ours_once_and_refuses_what_it_cannot_read() {
        let mine = r#"{"model":"opus","hooks":{"Stop":[{"hooks":[{"type":"command","command":"echo hi"}]}]}}"#;
        let once = merge_hooks(mine, "/usr/local/bin/ozboxd", "claude-code").unwrap();
        let v: Value = serde_json::from_str(&once).unwrap();
        assert_eq!(v["model"], "opus");
        assert_eq!(
            v["hooks"]["Stop"][0]["hooks"][0]["command"], "echo hi",
            "theirs first"
        );
        assert_eq!(v["hooks"]["Stop"].as_array().unwrap().len(), 2);
        for ev in ["Notification", "Stop", "UserPromptSubmit", "PreToolUse"] {
            assert!(v["hooks"][ev].is_array(), "{ev}");
        }
        assert_eq!(v["hooks"]["PreToolUse"][0]["matcher"], "Bash");
        assert_eq!(
            v["hooks"]["PreToolUse"][0]["hooks"][0]["args"],
            json!(["hook", "claude-code"]),
            "exec form, no shell"
        );
        // again: nothing doubles
        assert_eq!(
            merge_hooks(&once, "/usr/local/bin/ozboxd", "claude-code").unwrap(),
            once
        );
        assert!(merge_hooks("{not json", "x", "claude-code").is_err());
        assert!(merge_hooks("[]", "x", "claude-code").is_err());
        assert!(merge_hooks(r#"{"hooks":{"Stop":"nope"}}"#, "x", "claude-code").is_err());
        let fresh: Value = serde_json::from_str(&merge_hooks("", "x", "gemini").unwrap()).unwrap();
        assert!(
            fresh["hooks"]["AfterAgent"].is_array()
                && fresh["hooks"]["BeforeAgent"].is_array()
                && fresh["hooks"]["BeforeTool"][0]["hooks"][0]["timeout"] == 570_000
        );
    }

    #[test]
    fn a_codex_notify_the_person_already_set_is_left_alone() {
        let (out, added) = merge_codex_notify("model = \"x\"\n", "/usr/local/bin/ozboxd");
        assert!(
            added && out.starts_with("notify = [\"/usr/local/bin/ozboxd\", \"hook\", \"codex\"]\n")
        );
        let (same, added) = merge_codex_notify("notify = [\"mine\"]\n", "/b");
        assert!(!added && same == "notify = [\"mine\"]\n");
        let (_, again) = merge_codex_notify(&out, "/usr/local/bin/ozboxd");
        assert!(!again);
    }

    #[test]
    fn the_answer_a_hook_prints_follows_each_engines_documented_shape() {
        let a = permission_answer("claude-code", Decision::Deny, "no");
        assert_eq!(a["hookSpecificOutput"]["permissionDecision"], "deny");
        assert_eq!(
            permission_answer("gemini", Decision::Allow, "ok")["decision"],
            "allow"
        );
    }

    #[test]
    fn the_record_hooks_are_only_the_record_events_with_their_own_marker_and_never_a_permission() {
        let mine = r#"{"permissions":{"allow":["Bash(git push:*)"]},"hooks":{"Stop":[{"hooks":[{"type":"command","command":"echo hi"}]}]}}"#;
        let out = merge_record_hooks(mine, "/usr/local/bin/ozboxd").unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["permissions"]["allow"][0], "Bash(git push:*)");
        let events: Vec<&str> = v["hooks"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        for ev in RECORD_EVENTS {
            assert!(events.contains(&ev), "{ev}");
        }
        assert_eq!(events.len(), RECORD_EVENTS.len(), "{events:?}");
        for ev in ["PreToolUse", "BeforeTool", "Notification"] {
            assert!(
                v["hooks"].get(ev).is_none(),
                "{ev} must not be installed at boot"
            );
        }
        assert_eq!(v["hooks"]["Stop"][0]["hooks"][0]["command"], "echo hi");
        let ours = &v["hooks"]["SessionEnd"][0]["hooks"][0];
        assert!(ours.get("name").is_none(), "no undocumented field");
        assert_eq!(ours["args"], json!(["session-hook", "claude-code"]));
        // again: nothing doubles; and the full install's marker is a different one
        assert_eq!(
            merge_record_hooks(&out, "/usr/local/bin/ozboxd").unwrap(),
            out
        );
        // recognised by what it runs: Claude Code stripping unknown fields, or compact formatting, adds nothing and rewrites nothing
        assert_eq!(
            merge_record_hooks_changed(&out, "/usr/local/bin/ozboxd").unwrap(),
            None
        );
        let compact = serde_json::to_string(&serde_json::from_str::<Value>(&out).unwrap()).unwrap();
        assert_eq!(
            merge_record_hooks_changed(&compact, "/usr/local/bin/ozboxd").unwrap(),
            None,
            "a differently formatted file with all the hooks is not rewritten"
        );
        // the same hooks at another path of the binary are pointed at the new one, and nothing else changes
        let moved = merge_record_hooks_changed(&out, "/opt/ozboxd")
            .unwrap()
            .unwrap();
        assert!(moved.contains("/opt/ozboxd") && !moved.contains("/usr/local/bin/ozboxd"));
        assert_eq!(moved.matches("session-hook").count(), 4);
        // a person's own hook that merely looks alike is not ours
        let alike = r#"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"/x/other","args":["session-hook","claude-code"]}]}]}}"#;
        let a = merge_record_hooks(alike, "/usr/local/bin/ozboxd").unwrap();
        assert!(a.contains("/x/other") && a.contains("/usr/local/bin/ozboxd"));
        // unreadable settings are refused, not replaced
        assert!(merge_record_hooks("{broken", "/b").is_err());
        assert!(merge_record_hooks("[]", "/b").is_err());
    }
}
