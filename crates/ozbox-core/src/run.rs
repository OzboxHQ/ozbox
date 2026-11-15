//! Supervised agent runs: the contract everything that starts an agent uses.
//!
//! A **run** is one agent doing one job on one box: an engine (`claude-code`, `codex`, ...), a prompt or a skill, the
//! box, optionally a repository and branch, **caps** (time, spend, tokens) and where the result goes. Whoever wants a
//! run - a person at the dashboard, `ozbox run start`, a schedule, a trigger - builds a [`RunSpec`] and calls
//! [`RunStarter::start_run`]. That is the whole interface:
//!
//! ```
//! use ozbox_core::run::{RunCaps, RunOrigin, RunSpec, RunStarter, TaskStore, TaskState};
//!
//! let dir = std::env::temp_dir().join(format!("ozbox-doc-{}", std::process::id()));
//! let store = TaskStore::new(dir.join("tasks.json"));
//! let spec = RunSpec {
//!     engine: "fake".into(),
//!     prompt: "Fix the failing test in the parser.".into(),
//!     skill: None,
//!     box_name: "alpha".into(),
//!     repo: Some("web".into()),
//!     branch: Some("fix/parser".into()),
//!     caps: RunCaps { max_runtime_s: Some(1800), max_spend_cents: Some(500), max_tokens: None },
//!     deliver_to: Vec::new(),
//!     requested_by: "ada".into(),
//!     origin: RunOrigin::Schedule { id: "nightly".into() },
//!     idempotency_key: Some("nightly:2026-11-10T03:00Z".into()),
//!     model: None,
//!     interactive: false,
//! };
//! let started = store.start_run(spec).unwrap();
//! assert_eq!(started.state, TaskState::Queued);
//! # let _ = std::fs::remove_dir_all(dir);
//! ```
//!
//! `start_run` only **enqueues**: it validates the spec, writes a queued task to the task store and returns its id.
//! The supervisor, which `ozbox serve` runs, admits it when the box has room (a size cap and
//! free memory), runs it, pauses it at a cap and asks a person, and finishes it. Starting the same
//! `idempotency_key` twice returns the first task, so a retried schedule firing never makes two runs.
//!
//! The task store is one JSON file, written atomically and changed under a lock file, so the CLI and the server see the
//! same state. It holds no secret: an engine's key is in the secret store and reaches the engine through its
//! environment, never through a [`RunSpec`] or a log line.
//!
//! These shapes are part of the stable `/v1` and `--json` surface: add fields (with a default), never rename or remove.

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::name::BoxName;

/// The most tasks (of any state) kept; finished ones are forgotten oldest first.
pub const MAX_TASKS: usize = 500;
/// The most tasks waiting at once.
pub const MAX_QUEUED: usize = 200;
/// The most log lines kept per task, and the longest line.
pub const LOG_LINES: usize = 400;
pub const LOG_LINE_CHARS: usize = 400;
/// The longest prompt.
pub const MAX_PROMPT_CHARS: usize = 20_000;
/// The most audit records kept.
pub const MAX_AUDIT: usize = 2000;

/// Time, spend and token limits for one run. A missing limit is no limit of that kind.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RunCaps {
    /// Seconds of the run being active (time spent waiting for a person does not count).
    pub max_runtime_s: Option<u64>,
    /// Spend in US cents.
    pub max_spend_cents: Option<u64>,
    pub max_tokens: Option<u64>,
}

/// Where a finished run's result goes. The board always has it; the others add a delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliverTo {
    /// Open a pull request with the work (asks first when it targets a protected branch).
    PullRequest,
    /// Send an alert (under the routing rules) when the run finishes.
    Alert,
}

/// Who asked for the run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RunOrigin {
    #[default]
    Manual,
    /// Started from a chat app (Telegram, Slack, WhatsApp). It runs under the chat's authority: never `auto` or `accept
    /// edits`, and no standing permission applies to it.
    Chat,
    Schedule {
        id: String,
    },
    Trigger {
        id: String,
    },
    /// A conductor or a worker of an orchestration (`ozbox_core::orch`). `feature` is empty for the conductor.
    Orchestration {
        id: String,
        #[serde(default)]
        feature: String,
    },
}

/// Everything needed to start a run. Build one and call [`RunStarter::start_run`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunSpec {
    /// The engine's id: lowercase letters, digits, `-` and `.`.
    pub engine: String,
    /// What to do. Text from people; never an instruction from an outside source.
    pub prompt: String,
    /// A skill to run instead of (or with) the prompt.
    #[serde(default)]
    pub skill: Option<String>,
    /// The box it runs on.
    pub box_name: String,
    /// A repository under `/work/repos`, like `web` or `org/web`.
    #[serde(default)]
    pub repo: Option<String>,
    /// The branch it works on (never a protected branch; the run gets its own).
    #[serde(default)]
    pub branch: Option<String>,
    #[serde(default)]
    pub caps: RunCaps,
    #[serde(default)]
    pub deliver_to: Vec<DeliverTo>,
    /// The person (or `schedule:<id>`) the cost is counted against.
    pub requested_by: String,
    #[serde(default = "manual")]
    pub origin: RunOrigin,
    /// Starting the same key again returns the first run.
    #[serde(default)]
    pub idempotency_key: Option<String>,
    /// A provider and model for this run only. Without it the box's choice for the engine applies, then the fleet's.
    #[serde(default)]
    pub model: Option<ModelRef>,
    /// A conversation: the agent stays running between messages and each one is the next turn (a chat session). When
    /// false the run does one job and finishes.
    #[serde(default)]
    pub interactive: bool,
}

/// A provider (by its id in Settings -> Models) and one of its models.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelRef {
    pub provider_id: String,
    pub model: String,
}

/// The model a run uses, as the card and the run detail show it. Names only: never a key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunModel {
    pub provider_id: String,
    pub model: String,
    /// What the run switches to when the provider refuses it (a rate limit or an outage).
    #[serde(default)]
    pub fallback: Option<ModelRef>,
    /// Set once the run has switched: the model it started on.
    #[serde(default)]
    pub fell_back_from: Option<ModelRef>,
    /// Why it switched, in words.
    #[serde(default)]
    pub fallback_reason: Option<String>,
}

/// Where a run's cost figure comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CostSource {
    /// Counted from tokens and the price table: an estimate.
    Estimated,
    /// The engine said what the run cost. A reported cost replaces the estimate.
    Reported,
}

fn manual() -> RunOrigin {
    RunOrigin::Manual
}

/// Why a run could not be started. The text is for a person and holds no secret.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RunStartError {
    #[error("{field}: {reason}")]
    Invalid {
        field: &'static str,
        reason: &'static str,
    },
    #[error("too many runs are waiting; wait for some to finish")]
    QueueFull,
    #[error("the task store could not be used: {0}")]
    Store(String),
}

fn simple(s: &str, max: usize, extra: &[char]) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || extra.contains(&c))
}

fn bad(field: &'static str, reason: &'static str) -> RunStartError {
    RunStartError::Invalid { field, reason }
}

impl RunSpec {
    /// Refuse anything that could not be run safely. Called by `start_run`.
    pub fn validate(&self) -> Result<(), RunStartError> {
        if !simple(&self.engine, 40, &['-', '.', '_'])
            || self.engine.chars().any(|c| c.is_ascii_uppercase())
        {
            return Err(bad(
                "engine",
                "use lowercase letters, digits, - . and _ (up to 40)",
            ));
        }
        let p = self.prompt.trim();
        if p.is_empty() && self.skill.is_none() {
            return Err(bad("prompt", "say what to do, or name a skill"));
        }
        if self.prompt.chars().count() > MAX_PROMPT_CHARS {
            return Err(bad("prompt", "too long"));
        }
        if let Some(s) = &self.skill {
            if !simple(s, 60, &['-', '.', '_', '/']) || s.contains("..") {
                return Err(bad("skill", "not a valid skill name"));
            }
        }
        if BoxName::new(self.box_name.clone()).is_err() {
            return Err(bad("box", "not a valid box name"));
        }
        if let Some(r) = &self.repo {
            if !simple(r, 200, &['-', '.', '_', '/'])
                || r.contains("..")
                || r.starts_with('/')
                || r.starts_with('-')
            {
                return Err(bad("repo", "not a valid repository path"));
            }
        }
        if let Some(b) = &self.branch {
            if !simple(b, 100, &['-', '.', '_', '/'])
                || b.contains("..")
                || b.starts_with('-')
                || b.starts_with('/')
                || b.ends_with('/')
                || b.ends_with(".lock")
            {
                return Err(bad("branch", "not a valid branch name"));
            }
        }
        for (v, field) in [
            (self.caps.max_runtime_s, "max_runtime_s"),
            (self.caps.max_spend_cents, "max_spend_cents"),
            (self.caps.max_tokens, "max_tokens"),
        ] {
            if v == Some(0) {
                return Err(bad(field, "must be more than zero, or left out"));
            }
        }
        if self.caps.max_spend_cents.is_some_and(|c| c > 10_000_000) {
            return Err(bad("max_spend_cents", "more than $100,000"));
        }
        if self.requested_by.is_empty()
            || self.requested_by.len() > 64
            || self.requested_by.chars().any(char::is_control)
        {
            return Err(bad("requested_by", "1 to 64 characters"));
        }
        match &self.origin {
            RunOrigin::Manual | RunOrigin::Chat => {}
            RunOrigin::Orchestration { id, feature } => {
                if !simple(id, 40, &['-', '.', '_'])
                    || !(feature.is_empty() || simple(feature, 40, &['-', '.', '_']))
                {
                    return Err(bad("origin", "not a valid orchestration id"));
                }
            }
            RunOrigin::Schedule { id } | RunOrigin::Trigger { id } => {
                if !simple(id, 80, &['-', '.', '_', ':']) {
                    return Err(bad("origin", "not a valid schedule or trigger id"));
                }
            }
        }
        if let Some(k) = &self.idempotency_key {
            if !simple(k, 120, &['-', '.', '_', ':', '/']) {
                return Err(bad("idempotency_key", "not a valid key"));
            }
        }
        if let Some(m) = &self.model {
            if !simple(&m.provider_id, 24, &['-'])
                || m.model.is_empty()
                || m.model.len() > 100
                || m.model.chars().any(char::is_control)
            {
                return Err(bad("model", "not a valid provider and model"));
            }
        }
        Ok(())
    }
}

/// Where a task is on the board.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskState {
    /// Waiting for the box to have room (a size cap, free memory) or for a monthly cap.
    Queued,
    Running,
    /// Paused for a person: a cap was reached or an action needs approval. Nothing is lost.
    NeedsYou,
    /// Finished its work; a person looks at it.
    Review,
    Done,
    Failed,
    Cancelled,
}

impl TaskState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            TaskState::Done | TaskState::Failed | TaskState::Cancelled
        )
    }
    /// Holds a place on the box (counts against its size cap).
    pub fn is_active(self) -> bool {
        matches!(self, TaskState::Running | TaskState::NeedsYou)
    }
}

/// Why a task needs a person.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Needs {
    SpendCap,
    TimeCap,
    TokenCap,
    /// The fleet's or the person's monthly cap.
    MonthlyCap {
        scope: String,
    },
    /// A person paused the session (chat `/pause`); resuming continues the same conversation.
    Paused,
    Approval {
        approval_id: String,
    },
}

/// A link to something the run produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultLink {
    /// `pull_request`, `diff`, `branch` or `file`.
    pub kind: String,
    pub label: String,
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Task {
    pub id: String,
    pub spec: RunSpec,
    pub state: TaskState,
    pub created_ms: u64,
    #[serde(default)]
    pub started_ms: Option<u64>,
    #[serde(default)]
    pub finished_ms: Option<u64>,
    /// Seconds spent active, across pauses.
    #[serde(default)]
    pub active_s: u64,
    #[serde(default)]
    pub spend_cents: u64,
    #[serde(default)]
    pub tokens: u64,
    #[serde(default)]
    pub needs: Option<Needs>,
    #[serde(default)]
    pub log: Vec<String>,
    /// The branch the work was saved to when the run paused or stopped.
    #[serde(default)]
    pub wip_branch: Option<String>,
    #[serde(default)]
    pub links: Vec<ResultLink>,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    /// Why it is still queued, in words.
    #[serde(default)]
    pub queue_reason: Option<String>,
    /// This run is a retry of that one.
    #[serde(default)]
    pub retry_of: Option<String>,
    /// The engine's own handle. Opaque; never shown.
    #[serde(default)]
    pub handle: Option<String>,
    /// Caps added by a person after a pause (on top of the spec's).
    #[serde(default)]
    pub extra_spend_cents: u64,
    #[serde(default)]
    pub extra_runtime_s: u64,
    #[serde(default)]
    pub extra_tokens: u64,
    /// A person asked for it to stop; the supervisor does it at the next tick.
    #[serde(default)]
    pub cancel_requested: bool,
    /// The provider and model the run was started on, once it has been. Names only.
    #[serde(default)]
    pub model: Option<RunModel>,
    /// What the engine said the run cost, in cents, added up over its segments. It replaces the estimate.
    #[serde(default)]
    pub reported_cents: u64,
    /// The estimate from tokens and the price table, in millionths of a dollar (so tiny calls are not rounded away).
    #[serde(default)]
    pub est_micros: u64,
    /// An interactive session has answered and waits for the person's next message (it still holds its place).
    #[serde(default)]
    pub awaiting_input: bool,
    /// The agent's own session id, so a paused session continues the conversation. Opaque; never shown.
    #[serde(default)]
    pub session_id: Option<String>,
    /// Messages from people waiting to be handed to the agent at the next tick (each is delivered once, then removed).
    #[serde(default)]
    pub inbox: Vec<String>,
    /// How many turns the agent has finished, and what it said last (clean, bounded; no secrets).
    /// A person asked to pause the session; the supervisor saves the work and stops the agent at the next tick.
    #[serde(default)]
    pub pause_requested: bool,
    #[serde(default)]
    pub turns: u32,
    #[serde(default)]
    pub last_reply: Option<String>,
}

/// The longest message a person can hand to a running session, and how many may wait.
pub const MAX_INBOX_CHARS: usize = 16_000;
pub const MAX_INBOX: usize = 20;
/// The longest reply kept from one turn.
pub const MAX_REPLY_CHARS: usize = 4_000;

impl Task {
    /// Work out `spend_cents` again: what the engine reported if it reported anything, else the estimate (rounded to the
    /// nearest cent). Returns how much the figure moved, for the monthly ledger.
    pub fn recompute_spend(&mut self) -> i64 {
        let before = self.spend_cents;
        self.spend_cents = if self.reported_cents > 0 {
            self.reported_cents
        } else {
            (self.est_micros + 5_000) / 10_000
        };
        self.spend_cents as i64 - before as i64
    }

    /// Where the figure in `spend_cents` comes from; none while nothing has been counted.
    pub fn cost_source(&self) -> Option<CostSource> {
        if self.reported_cents > 0 {
            Some(CostSource::Reported)
        } else if self.est_micros > 0 || self.spend_cents > 0 {
            Some(CostSource::Estimated)
        } else {
            None
        }
    }

    pub fn spend_cap(&self) -> Option<u64> {
        self.spec
            .caps
            .max_spend_cents
            .map(|c| c + self.extra_spend_cents)
    }
    pub fn runtime_cap(&self) -> Option<u64> {
        self.spec
            .caps
            .max_runtime_s
            .map(|c| c + self.extra_runtime_s)
    }
    pub fn token_cap(&self) -> Option<u64> {
        self.spec.caps.max_tokens.map(|c| c + self.extra_tokens)
    }

    /// Add a line to the log, trimmed and bounded.
    pub fn push_log(&mut self, line: &str) {
        let clean: String = line
            .chars()
            .filter(|c| !c.is_control() || *c == '\t')
            .take(LOG_LINE_CHARS)
            .collect();
        self.log.push(clean);
        if self.log.len() > LOG_LINES {
            let drop = self.log.len() - LOG_LINES;
            self.log.drain(..drop);
        }
    }
}

/// What an approval is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    PushProtectedBranch,
    OpenPrToMain,
    AskCommand,
    OutboundMessage,
    SpendAboveThreshold,
    ProductionResource,
    /// A call to a tool over MCP (shell, git, files, ...) the permission engine said to ask about.
    ToolCall,
}

impl ActionKind {
    pub const ALL: [ActionKind; 7] = [
        ActionKind::PushProtectedBranch,
        ActionKind::OpenPrToMain,
        ActionKind::AskCommand,
        ActionKind::OutboundMessage,
        ActionKind::SpendAboveThreshold,
        ActionKind::ProductionResource,
        ActionKind::ToolCall,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalState {
    Pending,
    Approved,
    Denied,
    Expired,
}

/// An action an agent wants to take that needs a person's yes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub id: String,
    pub task_id: String,
    pub kind: ActionKind,
    /// The exact action, as the agent will run it (secrets removed).
    pub action: String,
    pub box_name: String,
    /// Who or what asked: the engine and the person behind the run.
    pub asked_by: String,
    /// The action touches something tagged production.
    pub production: bool,
    /// The decision needs a fresh second factor (in sign-in mode).
    pub needs_step_up: bool,
    pub state: ApprovalState,
    pub created_ms: u64,
    pub expires_ms: u64,
    #[serde(default)]
    pub reminders: u8,
    #[serde(default)]
    pub decided_by: Option<String>,
    #[serde(default)]
    pub decided_ms: Option<u64>,
    #[serde(default)]
    pub decided_with_step_up: bool,
    /// The decision has been passed to the engine.
    #[serde(default)]
    pub delivered: bool,
    /// An approved request for a tool call was used by the call it was asked for (it covers that one call). Spent or
    /// refused requests are also marked so a repeat of the call asks again.
    #[serde(default)]
    pub used: bool,
}

/// One line of the audit trail: who did what to which task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Counts up for ever; lets a reader see what is new.
    #[serde(default)]
    pub seq: u64,
    pub ts_ms: u64,
    /// A person, `supervisor` or `engine:<id>`.
    pub actor: String,
    pub action: String,
    pub task_id: Option<String>,
    pub detail: String,
}

/// The fleet's and each person's monthly spend limits, in cents. A missing limit is no limit.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SpendCaps {
    pub fleet_monthly_cents: Option<u64>,
    pub person_monthly_cents: Option<u64>,
    /// A person's own limit, instead of the default one above.
    pub per_person: BTreeMap<String, u64>,
}

impl SpendCaps {
    /// What limit applies to `person`: their own, else the default one, else none.
    fn limit_of(&self, person: &str) -> Option<u64> {
        self.per_person
            .get(person)
            .copied()
            .or(self.person_monthly_cents)
    }

    /// Whether replacing `self` with `new` allows MORE spend: a limit removed or raised, for the fleet, for the default
    /// person or for anyone named in either list (a person's own limit dropped falls back to the default, and a new own
    /// limit above the default raises it). Lowering or adding a limit is not loosening.
    #[must_use]
    pub fn loosens(&self, new: &SpendCaps) -> bool {
        let wider = |old: Option<u64>, now: Option<u64>| match (old, now) {
            (Some(_), None) => true,
            (Some(a), Some(b)) => b > a,
            _ => false,
        };
        wider(self.fleet_monthly_cents, new.fleet_monthly_cents)
            || wider(self.person_monthly_cents, new.person_monthly_cents)
            || self
                .per_person
                .keys()
                .chain(new.per_person.keys())
                .any(|k| wider(self.limit_of(k), new.limit_of(k)))
    }
}

/// Spend counted this month.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Ledger {
    /// `YYYY-MM` (UTC). A new month starts from zero.
    pub month: String,
    pub fleet_cents: u64,
    pub by_person: BTreeMap<String, u64>,
}

/// The whole task store.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Book {
    /// Bumped on every write.
    pub rev: u64,
    pub next_seq: u64,
    pub tasks: Vec<Task>,
    pub approvals: Vec<ApprovalRequest>,
    pub policy: crate::approvals::ApprovalPolicy,
    pub caps: SpendCaps,
    pub ledger: Ledger,
    pub audit: Vec<AuditRecord>,
    pub audit_seq: u64,
    /// Names this store in the audit chain (a store that is reset gets a new one), so a record is chained once.
    pub audit_epoch: String,
    /// The highest audit record number already handed to the chain.
    pub audit_chained: u64,
    /// Permission modes, rules and Production grants (`crate::permissions`).
    pub perms: crate::permissions::PermConfig,
    /// Orchestrations: one conductor agent handing features to worker boxes (`crate::orch`).
    pub orchestrations: Vec<crate::orch::Orchestration>,
    /// The person's limits for orchestrations; a rules file or a request can only tighten them.
    pub orch_settings: crate::orch::OrchSettings,
}

impl Book {
    pub fn task(&self, id: &str) -> Option<&Task> {
        self.tasks.iter().find(|t| t.id == id)
    }
    pub fn task_mut(&mut self, id: &str) -> Option<&mut Task> {
        self.tasks.iter_mut().find(|t| t.id == id)
    }
    pub fn approval(&self, id: &str) -> Option<&ApprovalRequest> {
        self.approvals.iter().find(|a| a.id == id)
    }
    /// Tasks started by one schedule or trigger that have not finished (for an overlap rule).
    pub fn unfinished_for(&self, origin: &RunOrigin) -> Vec<&Task> {
        self.tasks
            .iter()
            .filter(|t| {
                &t.spec.origin == origin && !t.state.is_terminal() && t.state != TaskState::Review
            })
            .collect()
    }

    pub fn record(
        &mut self,
        ts_ms: u64,
        actor: &str,
        action: &str,
        task: Option<&str>,
        detail: &str,
    ) {
        self.audit_seq += 1;
        self.audit.push(AuditRecord {
            seq: self.audit_seq,
            ts_ms,
            actor: actor.to_string(),
            action: action.to_string(),
            task_id: task.map(str::to_string),
            detail: detail
                .chars()
                .filter(|c| !c.is_control())
                .take(300)
                .collect(),
        });
        if self.audit.len() > MAX_AUDIT {
            let drop = self.audit.len() - MAX_AUDIT;
            self.audit.drain(..drop);
        }
    }

    /// Add a queued task for a validated spec. Returns the existing one for a repeated idempotency key.
    pub fn enqueue(
        &mut self,
        spec: RunSpec,
        now_ms: u64,
        retry_of: Option<String>,
    ) -> Result<(String, bool), RunStartError> {
        spec.validate()?;
        if let Some(k) = &spec.idempotency_key {
            if let Some(t) = self
                .tasks
                .iter()
                .find(|t| t.spec.idempotency_key.as_deref() == Some(k) && retry_of.is_none())
            {
                return Ok((t.id.clone(), false));
            }
        }
        if self
            .tasks
            .iter()
            .filter(|t| t.state == TaskState::Queued)
            .count()
            >= MAX_QUEUED
        {
            return Err(RunStartError::QueueFull);
        }
        self.next_seq += 1;
        let id = format!("t{}", self.next_seq);
        let who = spec.requested_by.clone();
        let line = format!("{} on {}", spec.engine, spec.box_name);
        self.tasks.push(Task {
            id: id.clone(),
            spec,
            state: TaskState::Queued,
            created_ms: now_ms,
            started_ms: None,
            finished_ms: None,
            active_s: 0,
            spend_cents: 0,
            tokens: 0,
            needs: None,
            log: Vec::new(),
            wip_branch: None,
            links: Vec::new(),
            summary: None,
            error: None,
            queue_reason: None,
            retry_of,
            handle: None,
            extra_spend_cents: 0,
            extra_runtime_s: 0,
            extra_tokens: 0,
            cancel_requested: false,
            model: None,
            reported_cents: 0,
            est_micros: 0,
            awaiting_input: false,
            session_id: None,
            inbox: Vec::new(),
            turns: 0,
            pause_requested: false,
            last_reply: None,
        });
        self.record(now_ms, &who, "run.queued", Some(&id), &line);
        self.forget_old();
        Ok((id, true))
    }

    /// Keep the store bounded: forget the oldest finished tasks (and their approvals) past [`MAX_TASKS`].
    pub fn forget_old(&mut self) {
        while self.tasks.len() > MAX_TASKS {
            let Some(pos) = self.tasks.iter().position(|t| t.state.is_terminal()) else {
                break;
            };
            let gone = self.tasks.remove(pos);
            self.approvals.retain(|a| a.task_id != gone.id);
        }
    }
}

/// What a successful `start_run` returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunStarted {
    pub id: String,
    pub state: TaskState,
    /// False when the idempotency key had already started this run.
    pub created: bool,
}

/// The one way to start a run.
pub trait RunStarter {
    fn start_run(&self, spec: RunSpec) -> Result<RunStarted, RunStartError>;
}

/// The task store: one JSON file, written atomically, changed under a lock file.
#[derive(Debug, Clone)]
pub struct TaskStore {
    path: PathBuf,
}

struct Lock(PathBuf);

impl Drop for Lock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

impl fmt::Display for TaskStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.path.display())
    }
}

/// What of a task-store audit record goes in the chain: ids and words, and never the text of an approval's action
/// (the approval itself carries it, for the person who decides).
fn chain_event(epoch: &str, r: &AuditRecord) -> crate::audit::NewEvent {
    let detail = if r.action.starts_with("approval.") {
        String::new()
    } else {
        r.detail.clone()
    };
    crate::audit::NewEvent {
        ts_ms: r.ts_ms,
        actor: r.actor.clone(),
        action: r.action.clone(),
        subject: r.task_id.clone(),
        detail,
        src: Some((epoch.to_string(), r.seq)),
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl TaskStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read the store. A missing file is an empty store; a damaged one is an error (never silently emptied).
    pub fn load(&self) -> io::Result<Book> {
        match std::fs::read(&self.path) {
            Ok(b) => serde_json::from_slice(&b).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, format!("tasks file: {e}"))
            }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Book::default()),
            Err(e) => Err(e),
        }
    }

    fn lock(&self) -> io::Result<Lock> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let lock_path = self.path.with_extension("lock");
        let start = Instant::now();
        loop {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock_path)
            {
                Ok(_) => return Ok(Lock(lock_path)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    // A lock older than half a minute belongs to a process that died.
                    let stale = std::fs::metadata(&lock_path)
                        .and_then(|m| m.modified())
                        .ok()
                        .and_then(|t| t.elapsed().ok())
                        .is_some_and(|age| age > Duration::from_secs(30));
                    if stale {
                        let _ = std::fs::remove_file(&lock_path);
                        continue;
                    }
                    if start.elapsed() > Duration::from_secs(5) {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "the task store is busy",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// The tamper-evident chain that goes with this store (`crate::audit`).
    pub fn audit_log(&self) -> crate::audit::AuditLog {
        crate::audit::AuditLog::beside(&self.path)
    }

    /// Copy every audit record the chain has not seen into it, under the lock the caller holds. The chain is written
    /// first: if it cannot be, nothing is saved, so a change is never kept without its record.
    fn chain_new_records(&self, book: &mut Book) -> io::Result<()> {
        if book.audit_seq <= book.audit_chained && !book.audit_epoch.is_empty() {
            return Ok(());
        }
        if book.audit_epoch.is_empty() {
            let mut raw = [0u8; 6];
            ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut raw)
                .map_err(|_| io::Error::other("no random numbers are available"))?;
            book.audit_epoch = crate::audit::hex(&raw);
        }
        let epoch = book.audit_epoch.clone();
        let events: Vec<crate::audit::NewEvent> = book
            .audit
            .iter()
            .filter(|r| r.seq > book.audit_chained)
            .map(|r| chain_event(&epoch, r))
            .collect();
        self.audit_log().append_many(events)?;
        book.audit_chained = book.audit_seq;
        Ok(())
    }

    /// Read, change and write the store as one step no other process can interleave with.
    pub fn update<R>(&self, f: impl FnOnce(&mut Book) -> R) -> io::Result<R> {
        let _lock = self.lock()?;
        let mut book = self.load()?;
        let out = f(&mut book);
        book.rev += 1;
        self.chain_new_records(&mut book)?;
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec(&book).map_err(io::Error::other)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(&tmp, &self.path)?;
        Ok(out)
    }
}

impl RunStarter for TaskStore {
    fn start_run(&self, spec: RunSpec) -> Result<RunStarted, RunStartError> {
        spec.validate()?;
        let ts = now_ms();
        let r = self
            .update(|b| b.enqueue(spec, ts, None))
            .map_err(|e| RunStartError::Store(e.to_string()))??;
        Ok(RunStarted {
            id: r.0,
            state: TaskState::Queued,
            created: r.1,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn spend_caps_loosen_by_a_raised_removed_or_newly_generous_limit() {
        let caps = |fleet: Option<u64>, person: Option<u64>, own: &[(&str, u64)]| SpendCaps {
            fleet_monthly_cents: fleet,
            person_monthly_cents: person,
            per_person: own.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
        };
        let base = caps(Some(5000), Some(100), &[("ada", 1000)]);
        assert!(!base.loosens(&base));
        // lower, or a first limit where there was none: not loosening
        assert!(!base.loosens(&caps(Some(4000), Some(50), &[("ada", 500)])));
        assert!(!caps(None, None, &[]).loosens(&caps(Some(9000), Some(9000), &[("bob", 1)])));
        // raised or removed
        assert!(base.loosens(&caps(Some(9000), Some(100), &[("ada", 1000)])));
        assert!(base.loosens(&caps(None, Some(100), &[("ada", 1000)])));
        assert!(base.loosens(&caps(Some(5000), None, &[("ada", 1000)])));
        assert!(base.loosens(&caps(Some(5000), Some(100), &[("ada", 2000)])));
        // a person's own limit dropped falls back to a default that is lower (fine) or higher (a loosening)
        assert!(!base.loosens(&caps(Some(5000), Some(100), &[])));
        assert!(base.loosens(&caps(Some(5000), Some(5000), &[])));
        // a NEW own limit above the default is a raise for that person, even though nobody's old entry changed
        assert!(base.loosens(&caps(
            Some(5000),
            Some(100),
            &[("ada", 1000), ("bob", 9000)]
        )));
        assert!(!base.loosens(&caps(Some(5000), Some(100), &[("ada", 1000), ("bob", 50)])));
    }

    pub(crate) fn spec(box_name: &str) -> RunSpec {
        RunSpec {
            engine: "fake".into(),
            prompt: "do the thing".into(),
            skill: None,
            box_name: box_name.into(),
            repo: Some("web".into()),
            branch: Some("fix/x".into()),
            caps: RunCaps::default(),
            deliver_to: Vec::new(),
            requested_by: "ada".into(),
            origin: RunOrigin::Manual,
            idempotency_key: None,
            model: None,
            interactive: false,
        }
    }

    #[test]
    fn a_spec_is_checked_before_anything_is_queued() {
        let mut s = spec("alpha");
        assert!(s.validate().is_ok());
        for (mutate, field) in [
            (
                Box::new(|s: &mut RunSpec| s.engine = "Bad Engine".into())
                    as Box<dyn Fn(&mut RunSpec)>,
                "engine",
            ),
            (Box::new(|s| s.prompt = "  ".into()), "prompt"),
            (Box::new(|s| s.box_name = "Not A Box".into()), "box"),
            (Box::new(|s| s.repo = Some("../etc".into())), "repo"),
            (Box::new(|s| s.branch = Some("-rf".into())), "branch"),
            (
                Box::new(|s| s.caps.max_spend_cents = Some(0)),
                "max_spend_cents",
            ),
            (Box::new(|s| s.requested_by = String::new()), "requested_by"),
        ] {
            s = spec("alpha");
            mutate(&mut s);
            match s.validate() {
                Err(RunStartError::Invalid { field: f, .. }) => assert_eq!(f, field),
                other => panic!("{field}: {other:?}"),
            }
        }
    }

    #[test]
    fn start_run_enqueues_and_a_repeated_key_returns_the_first_run() {
        let dir = tempfile::tempdir().unwrap();
        let store = TaskStore::new(dir.path().join("tasks.json"));
        let mut s = spec("alpha");
        s.idempotency_key = Some("nightly:1".into());
        let a = store.start_run(s.clone()).unwrap();
        assert_eq!((a.state, a.created), (TaskState::Queued, true));
        let b = store.start_run(s).unwrap();
        assert_eq!((b.id.as_str(), b.created), (a.id.as_str(), false));
        let book = store.load().unwrap();
        assert_eq!(book.tasks.len(), 1);
        assert_eq!(book.audit[0].action, "run.queued");
        // the file is private to the owner
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(store.path())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0);
        }
    }

    #[test]
    fn the_queue_is_bounded_and_the_store_forgets_old_finished_tasks() {
        let mut book = Book::default();
        for _ in 0..MAX_QUEUED {
            book.enqueue(spec("alpha"), 1, None).unwrap();
        }
        assert_eq!(
            book.enqueue(spec("alpha"), 1, None).unwrap_err(),
            RunStartError::QueueFull
        );
        for t in &mut book.tasks {
            t.state = TaskState::Done;
        }
        for _ in 0..(MAX_TASKS - MAX_QUEUED + 5) {
            let (id, _) = book.enqueue(spec("alpha"), 2, None).unwrap();
            book.task_mut(&id).unwrap().state = TaskState::Done;
        }
        assert!(book.tasks.len() <= MAX_TASKS);
    }

    #[test]
    fn a_damaged_store_is_an_error_not_an_empty_one() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("tasks.json");
        std::fs::write(&p, b"{not json").unwrap();
        let store = TaskStore::new(&p);
        assert!(store.load().is_err());
        assert!(store.start_run(spec("alpha")).is_err());
        assert_eq!(std::fs::read(&p).unwrap(), b"{not json");
    }

    #[test]
    fn the_log_is_bounded_and_clean() {
        let mut b = Book::default();
        let (id, _) = b.enqueue(spec("alpha"), 1, None).unwrap();
        let t = b.task_mut(&id).unwrap();
        for i in 0..(LOG_LINES + 10) {
            t.push_log(&format!("line {i}\u{7}"));
        }
        assert_eq!(t.log.len(), LOG_LINES);
        assert!(!t.log[0].contains('\u{7}'));
        t.push_log(&"x".repeat(10_000));
        assert_eq!(t.log.last().unwrap().len(), LOG_LINE_CHARS);
    }

    #[test]
    fn every_record_a_store_change_makes_lands_in_the_audit_chain_once() {
        let dir = tempfile::tempdir().unwrap();
        let store = TaskStore::new(dir.path().join("tasks.json"));
        store.start_run(spec("alpha")).unwrap();
        store
            .update(|b| b.record(5, "ada", "approval.policy_changed", None, ""))
            .unwrap();
        store.update(|_| ()).unwrap();
        let log = store.audit_log();
        let words: Vec<String> = log
            .entries()
            .unwrap()
            .into_iter()
            .map(|e| e.action)
            .collect();
        assert_eq!(words, vec!["run.queued", "approval.policy_changed"]);
        let v = log.verify().unwrap();
        assert!(v.ok, "{v:?}");
        // the chain outlives the store's own bounded list
        let book = store.load().unwrap();
        assert_eq!(book.audit_chained, book.audit_seq);
    }

    #[test]
    fn a_store_reset_does_not_lose_or_repeat_chain_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tasks.json");
        let store = TaskStore::new(&path);
        store.start_run(spec("alpha")).unwrap();
        std::fs::remove_file(&path).unwrap();
        store.start_run(spec("alpha")).unwrap();
        let log = store.audit_log();
        assert_eq!(log.entries().unwrap().len(), 2);
        assert!(log.verify().unwrap().ok);
    }

    #[test]
    fn an_edit_to_the_chain_file_is_found_by_verify() {
        let dir = tempfile::tempdir().unwrap();
        let store = TaskStore::new(dir.path().join("tasks.json"));
        store.start_run(spec("alpha")).unwrap();
        store
            .update(|b| b.record(5, "ada", "approval.policy_changed", None, ""))
            .unwrap();
        let log = store.audit_log();
        let text = std::fs::read_to_string(log.path()).unwrap();
        std::fs::write(log.path(), text.replace("ada", "eve")).unwrap();
        assert!(!log.verify().unwrap().ok);
    }

    #[test]
    fn an_approvals_command_line_never_reaches_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let store = TaskStore::new(dir.path().join("tasks.json"));
        store
            .update(|b| {
                b.record(
                    5,
                    "engine:x",
                    "approval.requested",
                    Some("t1"),
                    "rm -rf /work/customers",
                )
            })
            .unwrap();
        let text = std::fs::read_to_string(store.audit_log().path()).unwrap();
        assert!(!text.contains("customers"));
        assert!(text.contains("approval.requested"));
    }
}
