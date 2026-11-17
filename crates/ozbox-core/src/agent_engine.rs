//! The engine layer: how a coding agent is started, watched and stopped.
//!
//! An [`AgentEngine`] is an adapter for one agent program (Claude Code, Codex, an OpenAI-compatible loop, ...). The
//! supervisor knows only this trait, so changing the engine never changes what is allowed: admission, caps, approvals and
//! the audit trail live above it.
//!
//! To add an engine, implement the trait:
//!
//! - `start` launches the agent for a task and returns an opaque handle. `EngineStart::resume_from` names the WIP branch
//!   a paused run saved, so the agent continues from its own work. Credentials arrive in `EngineStart::secret_env`
//!   (a key handed for this run) or are the box user's own login; never put one in a prompt, argument, log or error.
//! - `poll` returns what happened since the last call as [`EngineEvent`]s: log lines, usage (the change since the last
//!   event, in US cents and tokens), a proposed action that may need a person's yes, and the end.
//! - `resolve` tells the engine a person's answer to a proposed action.
//! - `stop` ends it (and leaves the working tree alone; the supervisor checkpoints around it).
//!
//! [`FakeEngine`] is the scripted engine the tests and the demo provider use. The real adapter for Claude Code headless is
//! in `crate::claude_code`.

use std::collections::BTreeMap;
use std::fmt;

use crate::approvals::AgentAction;
use crate::run::ResultLink;

/// A file for one run only (ADR 0055): a sign-in the engine must read itself, which the box writes into a private folder of
/// that run, sets `dir_env` to, and removes when the run ends. Its text is secret: never logged, serialized for anything but
/// the start request, or put in an error.
#[derive(Clone, PartialEq, Eq)]
pub struct RunFile {
    /// The engine's own documented variable for its home folder (`CODEX_HOME`).
    pub dir_env: String,
    /// Where in that folder (`auth.json`).
    pub path: String,
    pub contents: String,
}

impl fmt::Debug for RunFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunFile")
            .field("dir_env", &self.dir_env)
            .field("path", &self.path)
            .field("bytes", &self.contents.len())
            .finish()
    }
}

/// Everything an engine needs to start one run.
#[derive(Clone)]
pub struct EngineStart {
    pub task_id: String,
    pub box_name: String,
    pub prompt: String,
    pub skill: Option<String>,
    pub repo: Option<String>,
    pub branch: Option<String>,
    /// The WIP branch a paused run saved; continue from it.
    pub resume_from: Option<String>,
    /// Secrets for this run only. Never logged, serialized or put in an error.
    pub secret_env: BTreeMap<String, String>,
    /// Commands the agent must not run on its own (the policy's ask list), for engines that can be told.
    pub deny_commands: Vec<String>,
    pub max_runtime_s: Option<u64>,
    /// The model chosen for this run (a name, never a key); the credentials for it are in `secret_env`.
    pub model: Option<String>,
    /// The run is on its fallback model because the first provider refused it.
    pub on_fallback: bool,
    /// A conversation: the agent keeps running between messages (see [`AgentEngine::send`]).
    pub interactive: bool,
    /// The agent's own session id from an earlier segment of this run, to continue the same conversation.
    pub resume_session: Option<String>,
    /// The run was started from a chat app. An engine that can be told asks for an edit instead of making it (Claude Code is
    /// launched in its `default` permission mode, not `acceptEdits`).
    pub ask_for_edits: bool,
    /// Files for this run only (ADR 0055), handed over only when the person opted this engine in. Secret.
    pub run_files: Vec<RunFile>,
}

impl fmt::Debug for EngineStart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EngineStart")
            .field("task_id", &self.task_id)
            .field("box_name", &self.box_name)
            .field("secret_env_keys", &self.secret_env.len())
            .field("run_files", &self.run_files.len())
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum EngineEvent {
    /// A line of the agent's own output.
    Log(String),
    /// More was used since the last usage event. The cents are an estimate the engine made itself.
    Usage {
        cents: u64,
        tokens: u64,
    },
    /// Tokens one model call used, as the provider counted them. The supervisor records them against the run's provider
    /// and model (`model` is what the engine says it called, when it says) and prices them as an estimate.
    TokenUsage {
        input_tokens: u64,
        output_tokens: u64,
        cached_input_tokens: u64,
        model: Option<String>,
    },
    /// The engine reported what the run cost, in cents more than it had reported before. A reported cost replaces the
    /// estimate for the run.
    ReportedCost {
        cents: u64,
    },
    /// The provider refused the run (a rate limit, an outage, an overloaded service). The supervisor switches to the
    /// run's fallback model when it has one; the text is for a person and holds no secret.
    ProviderRefused(String),
    /// The agent wants to do something the policy may ask about; it waits for [`AgentEngine::resolve`].
    Propose(AgentAction),
    Finished {
        summary: String,
        links: Vec<ResultLink>,
    },
    Failed(String),
    /// An interactive session finished answering one message and waits for the next. Not the end of the run.
    TurnDone(String),
    /// The agent's own id for this conversation, so it can be continued after a pause.
    Session(String),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EngineError {
    #[error("{0}")]
    Failed(String),
    #[error("that engine is not available")]
    Unavailable,
}

pub trait AgentEngine: Send {
    fn id(&self) -> &str;
    fn start(&mut self, req: &EngineStart) -> Result<String, EngineError>;
    fn poll(&mut self, handle: &str) -> Result<Vec<EngineEvent>, EngineError>;
    /// Answer the last proposed action. A denied action must not be done.
    fn resolve(&mut self, handle: &str, approved: bool) -> Result<(), EngineError>;
    fn stop(&mut self, handle: &str) -> Result<(), EngineError>;
    /// Hand a person's message to an interactive session as its next turn. Engines without a conversation mode keep the
    /// default.
    fn send(&mut self, _handle: &str, _text: &str) -> Result<(), EngineError> {
        Err(EngineError::Unavailable)
    }
}

/// Replace what looks like a secret in one line of output: the exact secret values given, and the usual key shapes.
pub fn redact_line(line: &str, secrets: &[String]) -> String {
    let mut out = line.to_string();
    for s in secrets.iter().filter(|s| s.len() >= 6) {
        out = out.replace(s.as_str(), "[hidden]");
    }
    let mut words: Vec<String> = Vec::new();
    let mut hide_next = false;
    for w in out.split(' ') {
        let lower = w.to_ascii_lowercase();
        if hide_next && !w.is_empty() {
            words.push("[hidden]".into());
            hide_next = false;
            continue;
        }
        if lower == "bearer" {
            hide_next = true;
        }
        let key_shaped = ["sk-", "ghp_", "gho_", "github_pat_", "xoxb-", "AKIA"]
            .iter()
            .any(|p| {
                w.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_')
                    .starts_with(p)
            })
            && w.len() >= 16;
        if key_shaped {
            words.push("[hidden]".into());
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
    words.join(" ")
}

/// A scripted engine for tests and the demo provider. The prompt steers it with markers:
///
/// - `sim:steps=N` finish after N polls (default 4);
/// - `sim:cents=N` and `sim:tokens=N` usage added per poll (default 3 cents, 1000 tokens);
/// - `sim:push=<branch>` propose pushing that branch at the second poll;
/// - `sim:command=<word>` propose running that one-word command at the second poll;
/// - `sim:in=N` and `sim:out=N` token usage reported per poll through `TokenUsage` (instead of `Usage`), with
///   `sim:cached=N` cached input tokens;
/// - `sim:reported=N` the engine reports a total cost of N cents when it finishes;
/// - `sim:refuse` the first provider the run starts on refuses it at the first poll (a run on its fallback is fine);
/// - `sim:fail` end with a failure;
/// - in a conversation (`EngineStart::interactive`) it never finishes: it answers the first message and every later one
///   with `TurnDone`, and a message holding `sim:push=<branch>` proposes that push first.
#[derive(Debug, Default)]
pub struct FakeEngine {
    runs: BTreeMap<String, FakeRun>,
    seq: u64,
    /// Every answer given through `resolve`, newest last: (handle, approved).
    pub resolutions: Vec<(String, bool)>,
    /// The handles stopped.
    pub stopped: Vec<String>,
    /// The `resume_from` of every start.
    pub resumes: Vec<Option<String>>,
    /// The names (never the values) of the secret environment of every start, in order.
    pub env_names: Vec<Vec<String>>,
    /// How many runs were refused by their provider (the marker `sim:refuse`).
    pub refused: u64,
    /// The model of every start, in order.
    pub models: Vec<Option<String>>,
    /// The secret environment of every start, values included, for tests that act as the agent would (a run token to
    /// present to the credential broker). A test double only: a real engine never keeps it.
    pub envs: Vec<BTreeMap<String, String>>,
    /// The `resume_session` of every start, in order.
    pub sessions: Vec<Option<String>>,
    /// The `ask_for_edits` of every start, in order.
    pub ask_for_edits: Vec<bool>,
    /// The run files of every start, in order (ADR 0055), for tests that check which run was handed a sign-in.
    pub files: Vec<Vec<RunFile>>,
}

#[derive(Debug)]
struct FakeRun {
    polls: u64,
    steps: u64,
    cents: u64,
    tokens: u64,
    push: Option<String>,
    command: Option<String>,
    fail: bool,
    waiting: bool,
    resumed: bool,
    done: bool,
    task: String,
    secret_count: usize,
    tokens_in: Option<u64>,
    tokens_out: u64,
    cached: u64,
    reported: Option<u64>,
    refuse: bool,
    /// A conversation: the messages waiting to be answered (the first is the prompt), and the session id still to report.
    convo: Option<std::collections::VecDeque<String>>,
    session: Option<String>,
    /// A proposed push the conversation waits on, and the text it answers afterwards.
    after_approval: Option<String>,
}

fn marker(prompt: &str, name: &str) -> Option<String> {
    let needle = format!("sim:{name}=");
    prompt
        .split_whitespace()
        .find_map(|w| w.strip_prefix(needle.as_str()).map(str::to_string))
}

impl AgentEngine for FakeEngine {
    fn id(&self) -> &str {
        "fake"
    }

    fn start(&mut self, req: &EngineStart) -> Result<String, EngineError> {
        self.seq += 1;
        let handle = format!("fake-{}", self.seq);
        let num = |n: &str, d: u64| {
            marker(&req.prompt, n)
                .and_then(|v| v.parse().ok())
                .unwrap_or(d)
        };
        self.resumes.push(req.resume_from.clone());
        self.env_names
            .push(req.secret_env.keys().cloned().collect());
        self.models.push(req.model.clone());
        self.envs.push(req.secret_env.clone());
        self.files.push(req.run_files.clone());
        self.sessions.push(req.resume_session.clone());
        self.ask_for_edits.push(req.ask_for_edits);
        let on_fallback = req.on_fallback;
        self.runs.insert(
            handle.clone(),
            FakeRun {
                polls: 0,
                steps: num("steps", 4),
                cents: num("cents", 3),
                tokens: num("tokens", 1000),
                push: marker(&req.prompt, "push"),
                command: marker(&req.prompt, "command"),
                fail: req.prompt.contains("sim:fail"),
                waiting: false,
                resumed: req.resume_from.is_some(),
                done: false,
                task: req.task_id.clone(),
                secret_count: req.secret_env.len(),
                tokens_in: marker(&req.prompt, "in").and_then(|v| v.parse().ok()),
                tokens_out: num("out", 0),
                cached: num("cached", 0),
                reported: marker(&req.prompt, "reported").and_then(|v| v.parse().ok()),
                refuse: req.prompt.contains("sim:refuse") && !on_fallback,
                convo: req
                    .interactive
                    .then(|| std::collections::VecDeque::from([req.prompt.clone()])),
                session: req.interactive.then(|| {
                    req.resume_session
                        .clone()
                        .unwrap_or_else(|| format!("sim-session-{}", self.seq))
                }),
                after_approval: None,
            },
        );
        Ok(handle)
    }

    fn poll(&mut self, handle: &str) -> Result<Vec<EngineEvent>, EngineError> {
        let r = self.runs.get_mut(handle).ok_or(EngineError::Unavailable)?;
        if r.done || r.waiting {
            return Ok(Vec::new());
        }
        r.polls += 1;
        let mut ev = Vec::new();
        if r.convo.is_some() {
            if let Some(s) = r.session.take() {
                ev.push(EngineEvent::Session(s));
            }
            if r.polls == 1 {
                ev.push(EngineEvent::Log(format!("starting {}", r.task)));
            }
            let Some(text) = r.convo.as_mut().and_then(|q| q.pop_front()) else {
                return Ok(ev);
            };
            ev.push(EngineEvent::Usage {
                cents: r.cents,
                tokens: r.tokens,
            });
            if let Some(b) = marker(&text, "push") {
                r.waiting = true;
                r.after_approval = Some(text.chars().take(200).collect());
                ev.push(EngineEvent::Propose(AgentAction::GitPush { branch: b }));
                return Ok(ev);
            }
            if let Some(c) = marker(&text, "command") {
                r.waiting = true;
                r.after_approval = Some(text.chars().take(200).collect());
                ev.push(EngineEvent::Propose(AgentAction::Command { argv: vec![c] }));
                return Ok(ev);
            }
            let said: String = text.chars().take(200).collect();
            ev.push(EngineEvent::TurnDone(format!("Done: {said}")));
            return Ok(ev);
        }
        if r.polls == 1 {
            ev.push(EngineEvent::Log(if r.resumed {
                format!("resuming {} from its saved work", r.task)
            } else {
                format!("starting {}", r.task)
            }));
            if r.secret_count > 0 {
                ev.push(EngineEvent::Log(format!(
                    "using {} key(s) handed to this run",
                    r.secret_count
                )));
            }
        }
        ev.push(EngineEvent::Log(format!("step {} of {}", r.polls, r.steps)));
        if r.refuse {
            r.done = true;
            self.refused += 1;
            ev.push(EngineEvent::ProviderRefused(
                "the provider answered 429: rate limit".into(),
            ));
            return Ok(ev);
        }
        if let Some(i) = r.tokens_in {
            ev.push(EngineEvent::TokenUsage {
                input_tokens: i,
                output_tokens: r.tokens_out,
                cached_input_tokens: r.cached,
                model: None,
            });
        } else {
            ev.push(EngineEvent::Usage {
                cents: r.cents,
                tokens: r.tokens,
            });
        }
        if r.polls == 2 {
            if let Some(b) = r.push.take() {
                r.waiting = true;
                ev.push(EngineEvent::Propose(AgentAction::GitPush { branch: b }));
                return Ok(ev);
            }
            if let Some(c) = r.command.take() {
                r.waiting = true;
                ev.push(EngineEvent::Propose(AgentAction::Command { argv: vec![c] }));
                return Ok(ev);
            }
        }
        if r.polls >= r.steps {
            r.done = true;
            if let (Some(c), false) = (r.reported, r.fail) {
                ev.push(EngineEvent::ReportedCost { cents: c });
            }
            ev.push(if r.fail {
                EngineEvent::Failed("the agent gave up".into())
            } else {
                EngineEvent::Finished {
                    summary: format!("{} finished", r.task),
                    links: vec![ResultLink {
                        kind: "pull_request".into(),
                        label: "Pull request".into(),
                        url: format!("https://example.com/pull/{}", r.task),
                    }],
                }
            });
        }
        Ok(ev)
    }

    fn send(&mut self, handle: &str, text: &str) -> Result<(), EngineError> {
        let r = self.runs.get_mut(handle).ok_or(EngineError::Unavailable)?;
        match r.convo.as_mut() {
            Some(q) => {
                q.push_back(text.to_string());
                Ok(())
            }
            None => Err(EngineError::Failed("this run is not a conversation".into())),
        }
    }

    fn resolve(&mut self, handle: &str, approved: bool) -> Result<(), EngineError> {
        let r = self.runs.get_mut(handle).ok_or(EngineError::Unavailable)?;
        r.waiting = false;
        if let (Some(q), Some(t)) = (r.convo.as_mut(), r.after_approval.take()) {
            // the conversation goes on: the answer to the message that asked
            q.push_front(format!(
                "{} ({})",
                t.replace("sim:push", "push")
                    .replace("sim:command", "command"),
                if approved { "approved" } else { "denied" }
            ));
        }
        self.resolutions.push((handle.to_string(), approved));
        Ok(())
    }

    fn stop(&mut self, handle: &str) -> Result<(), EngineError> {
        self.runs.remove(handle);
        self.stopped.push(handle.to_string());
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn redaction_hides_known_values_and_key_shapes() {
        let secrets = vec!["hunter2hunter2".to_string()];
        let line = "using hunter2hunter2 and sk-abcdefghijklmnop1234 with API_KEY=abc Authorization: Bearer tok123 ok";
        let r = redact_line(line, &secrets);
        for s in [
            "hunter2hunter2",
            "sk-abcdefghijklmnop1234",
            "=abc",
            "tok123",
        ] {
            assert!(!r.contains(s), "{r}");
        }
        assert!(r.ends_with("ok"));
        assert_eq!(redact_line("plain words here", &[]), "plain words here");
    }
}
