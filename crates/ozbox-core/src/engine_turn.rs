//! The engine-neutral task and turn model: what a task, an instruction, an ask, a reply, a tool use, a result, usage and a
//! run's state **mean**, defined once, at the engine boundary (ADR 0056).
//!
//! Every engine adapter (Claude Code, Codex CLI, Gemini CLI, and the scripted ones the tests use) speaks its own program's
//! format: prompts, tool calls, approvals and hooks, transcripts, cost and usage. The adapter turns that into
//! [`EngineEvent`]s at its edge, and this module turns those into [`Turn`]s. Nothing engine-specific leaves an adapter:
//!
//! - **no engine or provider field in a turn.** A turn never names the program, the vendor, the model's session id, a resume
//!   token or a key. Usage names the model the engine said it called (a name, never a key), because the spend cap prices it;
//!   the provider it is billed to comes from the Models routing (ADR 0015), not from the engine.
//! - **text is redacted before it is a turn.** Every text a turn carries has passed [`redact_line`] with the run's own
//!   secret values, and the key-shape screen ([`crate::secret_shape::find_secret`]) on the way to the hub: a turn that still
//!   holds a key shape is refused, not sent.
//! - **a turn can ask and never grant** (ADR 0044). An [`Ask`] of kind approval is handed to the ADR 0041 request flow of the
//!   box it happened on; a reply over the hub is data for the agent, never a decision.
//!
//! The hub carries turns in its own frozen kinds ([`crate::hub::wire::Kind`]): a task is `task.assign` ([`Assign`]), a
//! question is `question`, a reply is `answer`, the state is `status` ([`StatusBody`]), a result is `result` ([`ResultBody`]),
//! being stuck is `blocked`. [`to_hub`] and [`from_hub`] are the only places that map between the two, so the envelope stays
//! engine-neutral: the same bytes whether Claude Code, Codex or Gemini did the work.
//!
//! [`EngineSession`] drives one adapter through this model; it is the API the hub's harness uses to put any engine on a box.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::agent_engine::{redact_line, AgentEngine, EngineError, EngineEvent, EngineStart};
use crate::approvals::AgentAction;
use crate::hub::engine::{Assign, ResultBody, StatusBody};
use crate::hub::refusal::KeyDeclaration;
use crate::hub::wire::Kind;
use crate::run::ResultLink;

/// The longest text one turn carries. A longer reply is cut; a whole transcript never crosses.
pub const MAX_TURN_TEXT: usize = 4_000;

/// A piece of work for an agent, whoever runs it. The hub's `task.assign` carries it as an [`Assign`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Task {
    /// `<orchestration>/<feature>` on the hub; any stable id on one box.
    pub id: String,
    pub title: String,
    /// What to do, in a person's words. Data to the agent, never a permission.
    pub instruction: String,
    pub repo: Option<String>,
    pub branch: Option<String>,
}

/// Why an agent waits on someone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AskKind {
    /// A question for a person or another agent. Answered with a [`Reply`].
    Question,
    /// An action the policy may ask about. Decided only through ADR 0041 on the box where it happened: a reply over the hub
    /// is never a decision.
    Approval { action: AgentAction },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ask {
    /// Unique within the task, made by the side that asks; empty for a question that came over the hub.
    pub id: String,
    #[serde(flatten)]
    pub kind: AskKind,
    pub text: String,
}

/// An answer to an [`Ask`] of kind question, or a new instruction in a conversation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reply {
    /// The ask it answers, on the box where it was asked. Over the hub a reply is matched by its task, so this is empty there.
    pub ask_id: String,
    pub text: String,
}

/// What a finished run produced: its words, and where its work is (a branch, a commit, links). A diff travels as an artifact
/// the hub pulls by name and hash, never inline.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outcome {
    pub summary: String,
    pub branch: Option<String>,
    pub commit: Option<String>,
    pub links: Vec<ResultLink>,
}

/// Tokens and cost, as the engine reported them. Priced and capped by the supervisor under the one spend cap; the provider
/// comes from the run's Models routing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cached_input_tokens: u64,
    /// Cents the engine itself reported (replaces the estimate), when it reports cost.
    pub reported_cents: u64,
    /// An estimate the engine made itself (the scripted engines), in cents.
    pub estimated_cents: u64,
    /// The model the engine said it called: a name, never a key.
    pub model: Option<String>,
}

/// Where a run stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    Running,
    /// Waiting for a reply, a decision, or the next message of a conversation.
    Waiting,
    /// The provider refused it (a rate limit, an outage), or it cannot go on without help.
    Blocked,
    Done,
    Failed,
}

/// One thing that happened in a run, or one thing handed to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Turn {
    /// The agent said something (a line of its own output).
    Say(String),
    /// The agent used a tool: its name only.
    ToolUse(String),
    Ask(Ask),
    /// An answer, or the next message, handed to the agent.
    Reply(Reply),
    Usage(Usage),
    /// The run moved to a state, with a reason for a person when it has one.
    State(RunState, Option<String>),
    /// The run finished (its state is [`RunState::Done`]).
    Result(Outcome),
}

/// Whether an engine can do something, said honestly. `Unsupported` is never faked by an adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "support", content = "why", rename_all = "snake_case")]
pub enum Support {
    Yes,
    Partly(&'static str),
    Unsupported(&'static str),
}

impl Support {
    pub fn is_yes(self) -> bool {
        matches!(self, Support::Yes)
    }
}

/// What an engine's adapter can do. One row per engine id; [`capabilities`] is the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Capabilities {
    pub engine: &'static str,
    /// Whether Oz Box can start it headless at all. `Unsupported` means the engine has no adapter (Planned).
    pub headless: Support,
    /// The page the adapter follows for the headless invocation.
    pub docs: &'static str,
    /// A conversation: the next message continues the same session.
    pub conversation: Support,
    /// The run's own Oz Box tools (ADR 0043) reachable from inside the run.
    pub mcp_in_runs: Support,
    /// The policy's ask list refused command by command.
    pub per_command_ask_list: Support,
    /// The agent stops and asks before a risky act, so ADR 0041 can decide it (rather than the act being refused up front).
    pub asks_before_acting: Support,
    /// Tokens per call as the provider counted them.
    pub token_usage: Support,
    /// A cost the engine reports itself.
    pub reported_cost: Support,
}

/// The adapters, and what each can do. Engines the Models routing knows but with no adapter are listed as Planned, with the
/// reason.
pub fn capabilities() -> Vec<Capabilities> {
    use Support::*;
    vec![
        Capabilities {
            engine: "claude-code",
            headless: Yes,
            docs: "https://code.claude.com/docs/en/headless",
            conversation: Yes,
            mcp_in_runs: Partly("orchestration runs, through the repository's MCP settings and the run's token"),
            per_command_ask_list: Yes,
            asks_before_acting: Unsupported(
                "headless runs refuse the ask list up front; asking needs a permission hook in the run, not built",
            ),
            token_usage: Yes,
            reported_cost: Yes,
        },
        Capabilities {
            engine: "codex",
            headless: Yes,
            docs: "https://learn.chatgpt.com/docs/non-interactive-mode",
            conversation: Yes,
            mcp_in_runs: Yes,
            per_command_ask_list: Partly(
                "Codex takes no per-command list: runs are sandboxed to the workspace with no network, which refuses pushes, downloads and remote shells; local commands in the workspace are not refused one by one",
            ),
            asks_before_acting: Unsupported("codex exec never stops to ask; acts the sandbox refuses fail"),
            token_usage: Yes,
            reported_cost: Unsupported("codex exec reports tokens, not cost; the supervisor prices them"),
        },
        Capabilities {
            engine: "gemini-cli",
            headless: Yes,
            docs: "https://geminicli.com/docs/cli/headless/",
            conversation: Yes,
            mcp_in_runs: Unsupported(
                "Gemini CLI reads MCP servers from a settings file only; a file for one run is not built (it needs the run files of ADR 0055)",
            ),
            per_command_ask_list: Partly(
                "in headless mode every shell command needs a confirmation nobody can give, so all are refused, not only the ask list",
            ),
            asks_before_acting: Unsupported("headless mode never stops to ask"),
            token_usage: Yes,
            reported_cost: Unsupported("Gemini CLI reports tokens, not cost; the supervisor prices them"),
        },
        Capabilities {
            engine: "opencode",
            headless: Unsupported(
                "`opencode run` is documented, but not its machine-readable output, reading the task from standard input, or a settings file for one run; Planned until it is",
            ),
            docs: "https://opencode.ai/docs/cli/",
            conversation: Unsupported("no adapter"),
            mcp_in_runs: Unsupported("no adapter"),
            per_command_ask_list: Unsupported("no adapter"),
            asks_before_acting: Unsupported("no adapter"),
            token_usage: Unsupported("no adapter"),
            reported_cost: Unsupported("no adapter"),
        },
        Capabilities {
            engine: "aider",
            headless: Unsupported("not planned in this release"),
            docs: "https://aider.chat/docs/scripting.html",
            conversation: Unsupported("no adapter"),
            mcp_in_runs: Unsupported("no adapter"),
            per_command_ask_list: Unsupported("no adapter"),
            asks_before_acting: Unsupported("no adapter"),
            token_usage: Unsupported("no adapter"),
            reported_cost: Unsupported("no adapter"),
        },
    ]
}

/// The row for one engine.
pub fn capabilities_of(engine: &str) -> Option<Capabilities> {
    capabilities().into_iter().find(|c| c.engine == engine)
}

/// The credential variables of each vendor family. A run of one engine is handed **none of another family's**: whatever
/// reached an adapter by mistake is dropped at its edge, so a Codex run can never read the token a Claude Code run was
/// given, and the reverse (the sentinel test pins it).
const FAMILIES: &[(&str, &[&str])] = &[
    (
        "anthropic",
        &[
            "ANTHROPIC_",
            "CLAUDE_CODE_",
            "AWS_BEARER_TOKEN_BEDROCK",
            "CLOUD_ML_REGION",
        ],
    ),
    (
        "openai",
        &[
            "OPENAI_",
            "CODEX_API_KEY",
            "CODEX_HOME",
            "OPENROUTER_API_KEY",
            "MISTRAL_API_KEY",
            "GROQ_API_KEY",
            "TOGETHER_API_KEY",
            "AZURE_OPENAI_",
        ],
    ),
    (
        "google",
        &[
            "GEMINI_",
            "GOOGLE_API_KEY",
            "GOOGLE_GEMINI_BASE_URL",
            "GOOGLE_GENAI_",
            "GOOGLE_CLOUD_",
            "GOOGLE_APPLICATION_CREDENTIALS",
        ],
    ),
];

/// The vendor family an engine speaks for. The scripted engine speaks for all (it is only ever a test).
fn family_of(engine: &str) -> Option<&'static str> {
    match engine {
        "claude-code" => Some("anthropic"),
        "codex" => Some("openai"),
        "gemini-cli" => Some("google"),
        _ => None,
    }
}

/// The run's environment without another vendor family's credentials.
pub fn strip_foreign(engine: &str, env: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let Some(own) = family_of(engine) else {
        return env.clone();
    };
    env.iter()
        .filter(|(k, _)| {
            !FAMILIES
                .iter()
                .filter(|(f, _)| *f != own)
                .any(|(_, names)| names.iter().any(|n| k.starts_with(n)))
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// The text a turn carries: the run's secrets replaced, cut to [`MAX_TURN_TEXT`].
pub fn clean(text: &str, secrets: &[String]) -> String {
    redact_line(text, secrets)
        .chars()
        .take(MAX_TURN_TEXT)
        .collect()
}

/// Translate what an adapter reported into turns. `secrets` are the run's own secret values; every text is redacted with them.
pub fn turns_of(ev: EngineEvent, secrets: &[String], next_ask: &mut u64) -> Vec<Turn> {
    match ev {
        EngineEvent::Log(l) => vec![Turn::Say(clean(&l, secrets))],
        EngineEvent::ToolUse { name } => vec![Turn::ToolUse(clean(&name, secrets))],
        EngineEvent::Usage { cents, tokens } => vec![Turn::Usage(Usage {
            output_tokens: tokens,
            estimated_cents: cents,
            ..Usage::default()
        })],
        EngineEvent::TokenUsage {
            input_tokens,
            output_tokens,
            cached_input_tokens,
            model,
        } => vec![Turn::Usage(Usage {
            input_tokens,
            output_tokens,
            cached_input_tokens,
            model,
            ..Usage::default()
        })],
        EngineEvent::ReportedCost { cents } => vec![Turn::Usage(Usage {
            reported_cents: cents,
            ..Usage::default()
        })],
        EngineEvent::ProviderRefused(why) => {
            vec![Turn::State(RunState::Blocked, Some(clean(&why, secrets)))]
        }
        EngineEvent::Propose(action) => {
            *next_ask += 1;
            vec![
                Turn::Ask(Ask {
                    id: format!("a{next_ask}"),
                    text: clean(&describe(&action), secrets),
                    kind: AskKind::Approval { action },
                }),
                Turn::State(RunState::Waiting, None),
            ]
        }
        EngineEvent::Finished { summary, links } => vec![
            Turn::Result(Outcome {
                summary: clean(&summary, secrets),
                links,
                ..Outcome::default()
            }),
            Turn::State(RunState::Done, None),
        ],
        EngineEvent::Failed(e) => vec![Turn::State(RunState::Failed, Some(clean(&e, secrets)))],
        EngineEvent::TurnDone(text) => vec![
            Turn::Say(clean(&text, secrets)),
            Turn::State(RunState::Waiting, None),
        ],
        // the engine's own session id is how the adapter resumes; it is engine-specific and never leaves the session
        EngineEvent::Session(_) => Vec::new(),
    }
}

fn describe(a: &AgentAction) -> String {
    match a {
        AgentAction::GitPush { branch } => format!("push the branch {branch}"),
        AgentAction::OpenPr { base } => format!("open a pull request into {base}"),
        AgentAction::Command { argv } => format!("run {}", argv.first().map_or("", String::as_str)),
        AgentAction::Message { channel } => format!("send a message on {channel}"),
        AgentAction::Spend { cents, what } => format!("spend {cents} cents on {what}"),
        AgentAction::Touch {
            resource,
            production,
        } => format!(
            "change {resource}{}",
            if *production { " (production)" } else { "" }
        ),
    }
}

// ---- the hub -----------------------------------------------------------------------------------------------------------

/// The body of a `question`, an `answer` or a `blocked` on the hub: which task, what kind of message, and what is said. Fixed
/// fields only, no engine field, unknown fields refused. It is the same shape as the hub's own answer about a feature (the merge
/// queue's `conflict`, `tests-failed`, `merged` ...), so one body means one thing whoever sends it. A reply is matched to its
/// question by the task: one agent holds one task on a worker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageBody {
    pub orchestration: String,
    pub feature: String,
    /// `question`, `answer` or `blocked` from this module; the hub's merge queue sends other kinds of answer.
    pub kind: String,
    pub text: String,
}

/// What a turn becomes on the hub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HubOut {
    /// Send this kind with this body.
    Send(Kind, Vec<u8>),
    /// An approval: the box's own ADR 0041 request flow decides it, and its request goes to `main` through that path
    /// (`approval.request`, built by the approval path, not here). Never a body this module invents.
    Approval(AgentAction),
    /// Nothing crosses the hub for this turn (a line of output, a tool use, usage: they stay on the box's run record).
    Local,
}

/// Why a turn was not sent.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HubMapError {
    #[error("the text looks like it holds {0}; it was not sent")]
    SecretShape(&'static str),
    #[error("the body could not be encoded")]
    Encode,
}

/// Split `<orchestration>/<feature>`.
pub fn split_task_id(id: &str) -> (String, String) {
    match id.split_once('/') {
        Some((o, f)) => (o.to_string(), f.to_string()),
        None => ("-".to_string(), id.to_string()),
    }
}

fn screened(text: &str) -> Result<(), HubMapError> {
    match crate::secret_shape::find_secret(text) {
        Some(what) => Err(HubMapError::SecretShape(what)),
        None => Ok(()),
    }
}

fn json<T: Serialize>(v: &T) -> Result<Vec<u8>, HubMapError> {
    serde_json::to_vec(v).map_err(|_| HubMapError::Encode)
}

/// The hub message for one turn of the task `task_id` (`<orchestration>/<feature>`).
pub fn to_hub(task_id: &str, turn: &Turn) -> Result<HubOut, HubMapError> {
    let (orchestration, feature) = split_task_id(task_id);
    let message = |kind: Kind, text: &str| -> Result<HubOut, HubMapError> {
        screened(text)?;
        Ok(HubOut::Send(
            kind,
            json(&MessageBody {
                orchestration: orchestration.clone(),
                feature: feature.clone(),
                kind: kind.name().to_string(),
                text: text.to_string(),
            })?,
        ))
    };
    let status = |state: &str, text: &str| -> Result<HubOut, HubMapError> {
        screened(text)?;
        Ok(HubOut::Send(
            Kind::Status,
            json(&StatusBody {
                orchestration: orchestration.clone(),
                feature: feature.clone(),
                state: state.to_string(),
                text: text.to_string(),
            })?,
        ))
    };
    match turn {
        Turn::Ask(a) => match &a.kind {
            AskKind::Question => message(Kind::Question, &a.text),
            AskKind::Approval { action } => Ok(HubOut::Approval(action.clone())),
        },
        Turn::Reply(r) => message(Kind::Answer, &r.text),
        Turn::Result(o) => {
            screened(&o.summary)?;
            match &o.commit {
                Some(c) => Ok(HubOut::Send(
                    Kind::Result,
                    json(&ResultBody {
                        orchestration,
                        feature,
                        commit: c.clone(),
                        summary: o.summary.clone(),
                    })?,
                )),
                // a run that answered rather than committed reports it as its state
                None => status("done", &o.summary),
            }
        }
        Turn::State(RunState::Running, _) => status("working", ""),
        Turn::State(RunState::Failed, why) => status("failed", why.as_deref().unwrap_or("")),
        Turn::State(RunState::Blocked, why) => message(Kind::Blocked, why.as_deref().unwrap_or("")),
        // waiting is said by the ask itself; done by the result
        Turn::State(RunState::Waiting | RunState::Done, _) => Ok(HubOut::Local),
        Turn::Say(_) | Turn::ToolUse(_) | Turn::Usage(_) => Ok(HubOut::Local),
    }
}

/// What a hub message means to the agent that receives it. `None` for a kind that carries no turn, or a body that is not one.
/// A question that is plain text (a worker that asks without naming its task) is a question about no task (`-/-`).
pub fn from_hub(kind: Kind, body: &[u8]) -> Option<(String, Turn)> {
    let mb = || {
        serde_json::from_slice::<MessageBody>(body)
            .ok()
            .map(|b| (format!("{}/{}", b.orchestration, b.feature), b))
    };
    match kind {
        Kind::Question => {
            let (task, text) = match mb() {
                Some((t, b)) if b.kind == "question" => (t, b.text),
                Some(_) => return None,
                None => {
                    let t = std::str::from_utf8(body).ok()?;
                    if t.trim_start().starts_with('{') {
                        return None;
                    }
                    ("-/-".to_string(), t.chars().take(MAX_TURN_TEXT).collect())
                }
            };
            Some((
                task,
                Turn::Ask(Ask {
                    id: String::new(),
                    kind: AskKind::Question,
                    text,
                }),
            ))
        }
        // the merge queue's answers (a conflict, failing tests, merged) are words for the agent too, said with their kind
        Kind::Answer => mb().map(|(t, b)| {
            let text = if b.kind == "answer" {
                b.text
            } else {
                format!("{}: {}", b.kind, b.text)
            };
            (
                t,
                Turn::Reply(Reply {
                    ask_id: String::new(),
                    text,
                }),
            )
        }),
        Kind::Blocked => mb()
            .filter(|(_, b)| b.kind == "blocked")
            .map(|(t, b)| (t, Turn::State(RunState::Blocked, Some(b.text)))),
        Kind::Result => serde_json::from_slice::<ResultBody>(body).ok().map(|r| {
            (
                format!("{}/{}", r.orchestration, r.feature),
                Turn::Result(Outcome {
                    summary: r.summary,
                    commit: Some(r.commit),
                    ..Outcome::default()
                }),
            )
        }),
        Kind::Status => serde_json::from_slice::<StatusBody>(body)
            .ok()
            .and_then(|s| {
                let id = format!("{}/{}", s.orchestration, s.feature);
                let text = (!s.text.is_empty()).then(|| s.text.clone());
                let state = match s.state.as_str() {
                    "accepted" | "working" => RunState::Running,
                    "done" => {
                        return Some((
                            id,
                            Turn::Result(Outcome {
                                summary: s.text,
                                ..Outcome::default()
                            }),
                        ))
                    }
                    "refused" | "unsupported" | "failed" => RunState::Failed,
                    _ => return None,
                };
                Some((id, Turn::State(state, text)))
            }),
        _ => None,
    }
}

/// The task an assignment carries.
pub fn task_of(a: &Assign) -> Task {
    Task {
        id: format!("{}/{}", a.orchestration, a.feature),
        title: a.title.clone(),
        instruction: a.brief.clone(),
        repo: a.repo.clone(),
        branch: Some(a.branch.clone()),
    }
}

/// The assignment for a task (names only; the keys are a declaration by name, Production refused by the hub and the worker).
pub fn assign_of(task: &Task, keys: KeyDeclaration, lease_expiry_ms: u64) -> Assign {
    let (orchestration, feature) = split_task_id(&task.id);
    Assign {
        orchestration,
        feature: feature.clone(),
        title: task.title.clone(),
        brief: task.instruction.clone(),
        branch: task
            .branch
            .clone()
            .unwrap_or_else(|| format!("feat/{feature}")),
        repo: task.repo.clone(),
        claims: Vec::new(),
        contracts: Vec::new(),
        keys,
        lease_expiry_ms,
        engine: None,
        model: None,
    }
}

// ---- driving one engine through the model ------------------------------------------------------------------------------

/// How a session starts: the task, the box, and what the Models routing and the broker chose for this run.
#[derive(Clone)]
pub struct SessionStart {
    pub task: Task,
    pub box_name: String,
    /// The model chosen for the run (a name), from the Models routing (ADR 0015).
    pub model: Option<String>,
    /// The run's per-run token and the broker's address (ADR 0017), and the Oz Box tools' address and token (ADR 0043).
    /// Secret: never logged; handed to the engine only.
    pub secret_env: BTreeMap<String, String>,
    /// The policy's ask list (ADR 0014).
    pub deny_commands: Vec<String>,
    /// Keep the session open for replies.
    pub conversation: bool,
}

impl std::fmt::Debug for SessionStart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionStart")
            .field("task", &self.task.id)
            .field("box_name", &self.box_name)
            .field("secret_env_keys", &self.secret_env.len())
            .finish()
    }
}

/// One engine running one task, seen only through [`Turn`]s. The engine's own session id stays in here.
pub struct EngineSession {
    engine: Box<dyn AgentEngine>,
    handle: String,
    secrets: Vec<String>,
    next_ask: u64,
    pending_approval: bool,
    /// A conversation: a turn that ends waiting for the next message is the agent asking whoever gave it the task.
    conversation: bool,
    pub state: RunState,
}

impl EngineSession {
    /// Start `engine` on the task. The prompt is the task's title and instruction; the engine's adapter frames it.
    pub fn start(mut engine: Box<dyn AgentEngine>, s: &SessionStart) -> Result<Self, EngineError> {
        let mut prompt = String::new();
        if !s.task.title.trim().is_empty() {
            prompt.push_str(s.task.title.trim());
            prompt.push_str("\n\n");
        }
        prompt.push_str(&s.task.instruction);
        let req = EngineStart {
            task_id: s.task.id.clone(),
            box_name: s.box_name.clone(),
            prompt,
            skill: None,
            repo: s.task.repo.clone(),
            branch: s.task.branch.clone(),
            resume_from: None,
            secret_env: s.secret_env.clone(),
            deny_commands: s.deny_commands.clone(),
            max_runtime_s: None,
            model: s.model.clone(),
            on_fallback: false,
            interactive: s.conversation,
            resume_session: None,
            ask_for_edits: false,
        };
        let handle = engine.start(&req)?;
        Ok(EngineSession {
            engine,
            handle,
            secrets: s.secret_env.values().cloned().collect(),
            next_ask: 0,
            pending_approval: false,
            conversation: s.conversation,
            state: RunState::Running,
        })
    }

    pub fn engine_id(&self) -> &str {
        self.engine.id()
    }

    /// What happened since the last call, as turns.
    pub fn step(&mut self) -> Result<Vec<Turn>, EngineError> {
        if matches!(self.state, RunState::Done | RunState::Failed) {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for ev in self.engine.poll(&self.handle)? {
            if matches!(ev, EngineEvent::Propose(_)) {
                self.pending_approval = true;
            }
            if let (true, EngineEvent::TurnDone(text)) = (self.conversation, &ev) {
                // in a conversation the agent's last words before it waits are its question to whoever gave it the task
                self.next_ask += 1;
                out.push(Turn::Ask(Ask {
                    id: format!("q{}", self.next_ask),
                    kind: AskKind::Question,
                    text: clean(text, &self.secrets),
                }));
                self.state = RunState::Waiting;
                out.push(Turn::State(RunState::Waiting, None));
                continue;
            }
            for t in turns_of(ev, &self.secrets, &mut self.next_ask) {
                if let Turn::State(s, _) = &t {
                    self.state = *s;
                }
                out.push(t);
            }
        }
        Ok(out)
    }

    /// Hand the agent a reply (or the next message of a conversation).
    pub fn reply(&mut self, r: &Reply) -> Result<(), EngineError> {
        self.engine.send(&self.handle, &r.text)?;
        self.state = RunState::Running;
        Ok(())
    }

    /// The decision on the pending approval, which ADR 0041 made on this box. Refused when nothing is pending, so a message
    /// can never turn into a decision by arriving here.
    pub fn decide(&mut self, approved: bool) -> Result<(), EngineError> {
        if !self.pending_approval {
            return Err(EngineError::Failed(
                "nothing is waiting for a decision".into(),
            ));
        }
        self.pending_approval = false;
        self.engine.resolve(&self.handle, approved)?;
        self.state = RunState::Running;
        Ok(())
    }

    pub fn stop(&mut self) -> Result<(), EngineError> {
        self.engine.stop(&self.handle)
    }
}

#[cfg(test)]
mod tests;
