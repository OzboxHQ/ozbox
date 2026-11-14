//! Orchestration: one agent (the conductor) hands features to worker boxes and keeps them from colliding.
//!
//! This module is the pure part: the durable model and every decision, with no I/O, so it is tested with fake boxes
//! and a fake clock exactly like the supervisor. It lives on [`Book`] (the task store) so a feature's state and its
//! worker task change in one locked update, and so everything resumes after a restart from what the file holds: the
//! feature's branch, its `wip/` branch and its session id.
//!
//! - **Policy** ([`OrchPolicy`], in `orch_rules`) is what the server enforces: worker and sub-agent limits, one
//!   spend cap, what the conductor may decide, whether a merge needs a person. A rules file or a request can only
//!   *tighten* the person's settings, never loosen them.
//! - **Claims** say which files or areas one feature owns. [`check_path`] is the one function every pre-edit or
//!   pre-commit check calls; an overlap is refused or sequenced.
//! - **Contracts** are shared interfaces agreed before workers start. They are versioned; a change is broadcast to
//!   every feature that refers to it.
//! - **Mailbox**: conductor and workers talk through persisted messages. A worker that asks a question is `Blocked`
//!   until it is answered by the conductor (inside policy) or, for a question marked for a person, by the person.
//! - **Merge queue** (`orch_merge`): each ready feature is rebased in order, tested, approved as the policy requires and
//!   merged; a conflict goes back to the owning worker.
//!
//! The shapes here are part of the stable `/v1` and `--json` surface: add fields with a default, never rename.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

pub use crate::orch_rules::{
    effective, parse_rules, MergeApproval, OrchPolicy, OrchSettings, OverlapRule, Overrides,
    WorkerKind, WorkerPref,
};
use crate::run::{Book, RunCaps, TaskState};

/// Orchestrations kept (finished ones are forgotten oldest first).
pub const MAX_ORCHESTRATIONS: usize = 30;
pub const MAX_FEATURES: usize = 16;
pub const MAX_MESSAGES: usize = 500;
pub const MAX_TEXT: usize = 4000;
pub const MAX_CONTRACT_BYTES: usize = 32 * 1024;
pub const MAX_CLAIMS: usize = 40;
pub const MAX_CONTRACTS: usize = 40;

/// Why an orchestration request was refused. The text is for a person and holds no secret.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OrchError {
    #[error("there is no such orchestration")]
    NoOrchestration,
    #[error("there is no such feature")]
    NoFeature,
    #[error("{0}")]
    Invalid(String),
    /// The request is inside what the settings allow but over what this orchestration's policy allows.
    #[error("{0}")]
    Limit(String),
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    NotAllowed(String),
}

impl OrchError {
    /// A stable word for `--json` and the REST error code.
    pub fn code(&self) -> &'static str {
        match self {
            OrchError::NoOrchestration | OrchError::NoFeature => "not_found",
            OrchError::Invalid(_) => "invalid",
            OrchError::Limit(_) => "over_limit",
            OrchError::Conflict(_) => "conflict",
            OrchError::NotAllowed(_) => "not_allowed",
        }
    }
}

fn invalid(s: impl Into<String>) -> OrchError {
    OrchError::Invalid(s.into())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrchState {
    Active,
    /// Stopped for a person: the spend cap, or asked to pause.
    Paused,
    Done,
    Stopped,
}

/// How a feature was handed to its worker. Persisted, because state alone cannot tell a hub-route `Starting` (the task is
/// already on the worker channel) from a laptop-route `Starting`: the server's tick, `claims_declare` and `reassign` must never
/// send a hub-route feature down the laptop route (ADR 0042 section 12, review H-1). An older Book has no field and loads as `Ssh`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    #[default]
    Ssh,
    Hub,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeatureState {
    /// Declared; waiting for its contracts, or for a feature it must follow.
    Planned,
    /// Its box is being made or its task queued.
    Starting,
    Working,
    /// Waiting for an answer to a question.
    Blocked,
    /// Finished its work; not yet in the merge queue.
    ReadyToMerge,
    InQueue,
    Merged,
    /// The merge hit a conflict (or failing tests) and the work went back to this worker.
    ConflictReturned,
    Paused,
    Stopped,
    Failed,
}

impl FeatureState {
    /// Holds a worker box.
    pub fn is_open(self) -> bool {
        !matches!(
            self,
            FeatureState::Merged | FeatureState::Stopped | FeatureState::Failed
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    /// A file, a directory, or a glob (`*`, `**`, `?`), relative to the repository.
    pub pattern: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractRef {
    pub id: String,
    /// The version the feature was started against.
    pub version: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Feature {
    pub id: String,
    pub title: String,
    /// What to build, in the conductor's words (text from the conductor; a worker treats it as the job).
    pub brief: String,
    pub box_name: String,
    /// The route the feature was handed over by. Never changed after the hand-over.
    #[serde(default)]
    pub transport: Transport,
    pub worker: WorkerPref,
    /// Whether this server made the box for the feature (so it may pause and later destroy it).
    #[serde(default)]
    pub box_made: bool,
    pub repo: Option<String>,
    pub branch: String,
    #[serde(default)]
    pub claims: Vec<Claim>,
    #[serde(default)]
    pub contracts: Vec<ContractRef>,
    /// Features this one waits for (an overlap that was sequenced instead of refused).
    #[serde(default)]
    pub after: Vec<String>,
    pub engine: String,
    #[serde(default)]
    pub model: Option<String>,
    pub sub_agents: u8,
    #[serde(default)]
    pub caps: RunCaps,
    pub state: FeatureState,
    #[serde(default)]
    pub task_id: Option<String>,
    /// The engine's own session id, when it reported one (so a resumed worker continues the conversation).
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub wip_branch: Option<String>,
    /// The message the feature is blocked on.
    #[serde(default)]
    pub blocked_on: Option<u64>,
    pub created_ms: u64,
    #[serde(default)]
    pub merged_ms: Option<u64>,
    /// Keep the worker box after the merge (it is paused, never destroyed).
    #[serde(default)]
    pub keep: bool,
    /// The worker box was paused after the merge.
    #[serde(default)]
    pub box_paused: bool,
    /// The worker box was destroyed.
    #[serde(default)]
    pub box_destroyed: bool,
    /// An answer or a changed contract has not yet reached the worker's engine.
    #[serde(default)]
    pub resume_pending: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractRev {
    pub version: u32,
    pub ts_ms: u64,
    pub by: String,
    pub hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contract {
    pub id: String,
    pub name: String,
    /// `api`, `types`, `schema` or `doc`.
    pub kind: String,
    pub body: String,
    pub version: u32,
    /// Files this contract describes; workers may read them but claim none of them.
    #[serde(default)]
    pub paths: Vec<String>,
    /// A draft is not agreed: a feature may not start against it.
    pub agreed: bool,
    pub updated_ms: u64,
    #[serde(default)]
    pub history: Vec<ContractRev>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MsgKind {
    Question,
    Answer,
    Status,
    ContractChanged,
    Blocked,
    Approval,
    Instruction,
    Note,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    pub seq: u64,
    pub ts_ms: u64,
    /// `conductor`, `feature:<id>`, `person` or `system`.
    pub from: String,
    pub to: String,
    pub kind: MsgKind,
    #[serde(default)]
    pub feature: Option<String>,
    pub text: String,
    #[serde(default)]
    pub reply_to: Option<u64>,
    /// A question that has been answered.
    #[serde(default)]
    pub resolved: bool,
    /// Only the person may answer (a risky decision, or the conductor passed it up).
    #[serde(default)]
    pub needs_person: bool,
    #[serde(default)]
    pub approval_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MergeState {
    Waiting,
    Rebasing,
    Testing,
    AwaitingApproval,
    Merging,
    Merged,
    Conflict,
    TestsFailed,
    Failed,
}

impl MergeState {
    pub fn is_finished(self) -> bool {
        matches!(
            self,
            MergeState::Merged
                | MergeState::Conflict
                | MergeState::TestsFailed
                | MergeState::Failed
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeEntry {
    pub feature_id: String,
    pub queued_ms: u64,
    pub state: MergeState,
    #[serde(default)]
    pub detail: String,
    #[serde(default)]
    pub approval_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Orchestration {
    pub id: String,
    pub goal: String,
    pub requested_by: String,
    /// The box the conductor works on (usually the one holding `main`).
    pub conductor_box: String,
    #[serde(default)]
    pub conductor_task: Option<String>,
    #[serde(default)]
    pub conductor_session: Option<String>,
    pub state: OrchState,
    #[serde(default)]
    pub paused_reason: Option<String>,
    pub created_ms: u64,
    pub updated_ms: u64,
    pub policy: OrchPolicy,
    #[serde(default)]
    pub features: Vec<Feature>,
    #[serde(default)]
    pub contracts: Vec<Contract>,
    #[serde(default)]
    pub messages: Vec<Message>,
    #[serde(default)]
    pub merge_queue: Vec<MergeEntry>,
    #[serde(default)]
    pub next_feature: u64,
    #[serde(default)]
    pub next_msg: u64,
    /// Boxes this orchestration made for workers that no feature uses yet. They count against the worker limit.
    #[serde(default)]
    pub spare_boxes: Vec<String>,
}

/// What a request to add a feature says. Anything left out takes the policy's default.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FeatureReq {
    pub title: String,
    pub brief: String,
    pub box_name: Option<String>,
    pub worker: Option<WorkerPref>,
    pub repo: Option<String>,
    pub branch: Option<String>,
    pub claims: Vec<String>,
    pub contracts: Vec<String>,
    pub engine: Option<String>,
    pub model: Option<String>,
    pub sub_agents: Option<u8>,
    pub caps: RunCaps,
    pub keep: bool,
}

// ---- small helpers ----------------------------------------------------------------------------------------------

fn clean_text(s: &str, max: usize) -> String {
    s.chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .take(max)
        .collect()
}

pub fn slug(s: &str, max: usize) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if !out.ends_with('-') && !out.is_empty() {
            out.push('-');
        }
        if out.len() >= max {
            break;
        }
    }
    out.trim_end_matches('-').to_string()
}

/// A stable 64-bit fingerprint (FNV-1a) of a contract body, to tell a change from a re-publish.
fn fingerprint(s: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{h:016x}")
}

// ---- claims -----------------------------------------------------------------------------------------------------

/// A claim pattern in its one form: no leading `./` or `/`, no `..`, no doubled or trailing slash.
pub fn normalize_pattern(p: &str) -> Result<String, OrchError> {
    let p = p.trim();
    if p.is_empty() || p.len() > 200 || p.chars().any(char::is_control) {
        return Err(invalid(
            "a claim is a path or pattern of up to 200 characters",
        ));
    }
    let mut parts = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => return Err(invalid("a claim cannot contain `..`")),
            s => parts.push(s),
        }
    }
    Ok(parts.join("/"))
}

fn is_glob(p: &str) -> bool {
    p.contains(['*', '?'])
}

/// The fixed part a claim begins with, cut at a whole path segment.
fn literal_prefix(p: &str) -> String {
    match p.find(['*', '?']) {
        None => p.to_string(),
        Some(i) => match p[..i].rfind('/') {
            Some(j) => p[..j].to_string(),
            None => String::new(),
        },
    }
}

fn contains_path(outer: &str, inner: &str) -> bool {
    outer.is_empty() || inner == outer || inner.starts_with(&format!("{outer}/"))
}

/// Whether two claims could name the same file. Deliberately generous: a doubt is an overlap.
pub fn claims_overlap(a: &str, b: &str) -> bool {
    let (pa, pb) = (literal_prefix(a), literal_prefix(b));
    contains_path(&pa, &pb) || contains_path(&pb, &pa)
}

fn glob_match(pat: &[u8], s: &[u8]) -> bool {
    match pat.first() {
        None => s.is_empty(),
        Some(b'*') => {
            if pat.get(1) == Some(&b'*') {
                let rest = pat.get(2..).unwrap_or(&[]);
                let rest = rest.strip_prefix(b"/").unwrap_or(rest);
                (0..=s.len()).any(|i| glob_match(rest, &s[i..]))
            } else {
                let rest = &pat[1..];
                let mut i = 0;
                loop {
                    if glob_match(rest, &s[i..]) {
                        return true;
                    }
                    if i >= s.len() || s[i] == b'/' {
                        return false;
                    }
                    i += 1;
                }
            }
        }
        Some(b'?') => !s.is_empty() && s[0] != b'/' && glob_match(&pat[1..], &s[1..]),
        Some(c) => s.first() == Some(c) && glob_match(&pat[1..], &s[1..]),
    }
}

/// Whether a claim covers a file (a plain claim covers a directory's whole subtree).
pub fn claim_covers(claim: &str, path: &str) -> bool {
    if is_glob(claim) {
        glob_match(claim.as_bytes(), path.as_bytes())
            || contains_path(&literal_prefix(claim), path) && claim.ends_with("/**")
    } else {
        contains_path(claim, path)
    }
}

/// What [`declare_claims`] did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum ClaimOutcome {
    Granted,
    /// The overlap was sequenced: the feature waits for these to merge.
    Sequenced {
        after: Vec<String>,
    },
}

impl Orchestration {
    pub fn feature(&self, id: &str) -> Option<&Feature> {
        self.features.iter().find(|f| f.id == id)
    }
    pub fn feature_mut(&mut self, id: &str) -> Option<&mut Feature> {
        self.features.iter_mut().find(|f| f.id == id)
    }
    pub fn contract(&self, id: &str) -> Option<&Contract> {
        self.contracts.iter().find(|c| c.id == id)
    }

    /// Worker boxes in use: the distinct boxes of features that have not finished.
    pub fn open_workers(&self) -> usize {
        self.features
            .iter()
            .filter(|f| f.state.is_open())
            .map(|f| f.box_name.as_str())
            .chain(self.spare_boxes.iter().map(String::as_str))
            .collect::<BTreeSet<_>>()
            .len()
    }

    /// Declare (replace) the files and areas a feature owns. Another open feature already holding an overlapping claim
    /// refuses it, or sequences it, as the policy says. A contract's own files are never claimable by a worker.
    pub fn declare_claims(
        &mut self,
        feature_id: &str,
        patterns: &[String],
        now_ms: u64,
    ) -> Result<ClaimOutcome, OrchError> {
        if patterns.len() > MAX_CLAIMS {
            return Err(invalid(format!("at most {MAX_CLAIMS} claims per feature")));
        }
        let mut norm = Vec::new();
        for p in patterns {
            let n = normalize_pattern(p)?;
            if !norm.contains(&n) {
                norm.push(n);
            }
        }
        if self.feature(feature_id).is_none() {
            return Err(OrchError::NoFeature);
        }
        for n in &norm {
            for c in &self.contracts {
                if c.paths.iter().any(|cp| claims_overlap(cp, n)) {
                    return Err(OrchError::Conflict(format!(
                        "{n} is described by the contract {}: change the contract through the conductor, do not claim its files",
                        c.name
                    )));
                }
            }
        }
        let mut after: Vec<String> = Vec::new();
        for n in &norm {
            for other in self
                .features
                .iter()
                .filter(|f| f.id != feature_id && f.state.is_open())
            {
                if let Some(c) = other.claims.iter().find(|c| claims_overlap(&c.pattern, n)) {
                    if self.policy.on_overlap == OverlapRule::Refuse {
                        return Err(OrchError::Conflict(format!(
                            "{n} overlaps {} claimed by {} ({}): choose a different area or sequence the features",
                            c.pattern, other.id, other.title
                        )));
                    }
                    if !after.contains(&other.id) {
                        after.push(other.id.clone());
                    }
                }
            }
        }
        self.updated_ms = now_ms;
        let f = self.feature_mut(feature_id).ok_or(OrchError::NoFeature)?;
        f.claims = norm.into_iter().map(|pattern| Claim { pattern }).collect();
        if after.is_empty() {
            f.after.clear();
            Ok(ClaimOutcome::Granted)
        } else {
            f.after = after.clone();
            if f.transport == Transport::Hub {
                // already on the worker channel: waiting would put it back in the tick's hands and start it a second time by
                // the laptop route. It is failed with a reason instead (the conductor restarts it after the other merges).
                if matches!(f.state, FeatureState::Planned | FeatureState::Starting) {
                    f.state = FeatureState::Failed;
                }
                return Err(OrchError::Conflict(
                    "that feature went over the worker channel and cannot wait for another: it was stopped. Start it again after the other merges.".into(),
                ));
            }
            if f.state == FeatureState::Planned || f.state == FeatureState::Starting {
                f.state = FeatureState::Planned;
            }
            Ok(ClaimOutcome::Sequenced { after })
        }
    }

    /// The one pre-edit / pre-commit check. `Ok(())` means this feature owns the path; the error says who does, or that
    /// nobody has claimed it yet. With `strict_claims` off an unclaimed path is allowed.
    pub fn check_path(&self, feature_id: &str, path: &str) -> Result<(), OrchError> {
        let path = normalize_pattern(path)?;
        let me = self.feature(feature_id).ok_or(OrchError::NoFeature)?;
        if me.claims.iter().any(|c| claim_covers(&c.pattern, &path)) {
            return Ok(());
        }
        if let Some(owner) = self.features.iter().find(|f| {
            f.id != feature_id
                && f.state.is_open()
                && f.claims.iter().any(|c| claim_covers(&c.pattern, &path))
        }) {
            return Err(OrchError::Conflict(format!(
                "{path} belongs to {} ({}): ask the conductor, do not edit it",
                owner.id, owner.title
            )));
        }
        if let Some(c) = self
            .contracts
            .iter()
            .find(|c| c.paths.iter().any(|cp| claim_covers(cp, &path)))
        {
            return Err(OrchError::Conflict(format!(
                "{path} is part of the contract {}: ask the conductor to change it",
                c.name
            )));
        }
        if self.policy.strict_claims {
            Err(OrchError::Conflict(format!(
                "{path} is not claimed by any feature: declare a claim for it first"
            )))
        } else {
            Ok(())
        }
    }

    // ---- contracts ----------------------------------------------------------------------------------------------

    /// Publish a contract (or a new version of one). The same text again changes nothing. A new version is broadcast to
    /// every feature that refers to the contract. Returns the id and the version.
    #[allow(clippy::too_many_arguments)]
    pub fn publish_contract(
        &mut self,
        by: &str,
        name: &str,
        kind: &str,
        body: &str,
        paths: &[String],
        agreed: bool,
        now_ms: u64,
    ) -> Result<(String, u32), OrchError> {
        let id = slug(name, 40);
        if id.is_empty() {
            return Err(invalid("a contract needs a name"));
        }
        if !["api", "types", "schema", "doc"].contains(&kind) {
            return Err(invalid("a contract's kind is api, types, schema or doc"));
        }
        if body.len() > MAX_CONTRACT_BYTES {
            return Err(invalid("a contract is at most 32 KB"));
        }
        let mut np = Vec::new();
        for p in paths.iter().take(MAX_CLAIMS) {
            np.push(normalize_pattern(p)?);
        }
        let hash = fingerprint(body);
        self.updated_ms = now_ms;
        let existing = self.contracts.iter().position(|c| c.id == id);
        let version = match existing {
            Some(i) => {
                let c = &mut self.contracts[i];
                if fingerprint(&c.body) == hash && c.agreed == agreed && c.paths == np {
                    return Ok((id, c.version));
                }
                let changed = fingerprint(&c.body) != hash;
                if changed {
                    c.version += 1;
                }
                c.body = body.to_string();
                c.kind = kind.to_string();
                c.paths = np;
                c.agreed = agreed;
                c.updated_ms = now_ms;
                c.history.push(ContractRev {
                    version: c.version,
                    ts_ms: now_ms,
                    by: by.to_string(),
                    hash,
                });
                (c.version, changed)
            }
            None => {
                if self.contracts.len() >= MAX_CONTRACTS {
                    return Err(OrchError::Limit(format!(
                        "at most {MAX_CONTRACTS} contracts"
                    )));
                }
                self.contracts.push(Contract {
                    id: id.clone(),
                    name: clean_text(name, 80),
                    kind: kind.to_string(),
                    body: body.to_string(),
                    version: 1,
                    paths: np,
                    agreed,
                    updated_ms: now_ms,
                    history: vec![ContractRev {
                        version: 1,
                        ts_ms: now_ms,
                        by: by.to_string(),
                        hash,
                    }],
                });
                (1, false)
            }
        };
        let (version, changed) = version;
        if changed {
            // every feature that refers to it hears, once, and its pinned version moves only when it acknowledges
            let targets: Vec<String> = self
                .features
                .iter()
                .filter(|f| f.state.is_open() && f.contracts.iter().any(|r| r.id == id))
                .map(|f| f.id.clone())
                .collect();
            for t in targets {
                let text = format!(
                    "Contract {id} is now version {version}. Read it again before you continue."
                );
                self.push_message(
                    now_ms,
                    "conductor",
                    &format!("feature:{t}"),
                    MsgKind::ContractChanged,
                    Some(&t),
                    &text,
                    None,
                    false,
                );
                if let Some(f) = self.feature_mut(&t) {
                    f.resume_pending = true;
                }
            }
        }
        Ok((id, version))
    }

    /// A feature acknowledges the version it has now read.
    pub fn ack_contract(&mut self, feature_id: &str, contract_id: &str) -> Result<u32, OrchError> {
        let v = self
            .contract(contract_id)
            .ok_or_else(|| invalid("there is no such contract"))?
            .version;
        let f = self.feature_mut(feature_id).ok_or(OrchError::NoFeature)?;
        match f.contracts.iter_mut().find(|r| r.id == contract_id) {
            Some(r) => r.version = v,
            None => f.contracts.push(ContractRef {
                id: contract_id.to_string(),
                version: v,
            }),
        }
        Ok(v)
    }

    // ---- mailbox ------------------------------------------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    fn push_message(
        &mut self,
        now_ms: u64,
        from: &str,
        to: &str,
        kind: MsgKind,
        feature: Option<&str>,
        text: &str,
        reply_to: Option<u64>,
        needs_person: bool,
    ) -> u64 {
        self.next_msg += 1;
        let seq = self.next_msg;
        self.messages.push(Message {
            seq,
            ts_ms: now_ms,
            from: from.to_string(),
            to: to.to_string(),
            kind,
            feature: feature.map(str::to_string),
            text: clean_text(text, MAX_TEXT),
            reply_to,
            resolved: false,
            needs_person,
            approval_id: None,
        });
        if self.messages.len() > MAX_MESSAGES {
            // forget the oldest answered or informational ones first; an open question is never forgotten
            if let Some(pos) = self
                .messages
                .iter()
                .position(|m| m.resolved || !matches!(m.kind, MsgKind::Question | MsgKind::Blocked))
            {
                self.messages.remove(pos);
            }
        }
        seq
    }

    fn party_ok(&self, p: &str) -> bool {
        match p {
            "conductor" | "person" | "system" => true,
            _ => p
                .strip_prefix("feature:")
                .is_some_and(|f| self.feature(f).is_some()),
        }
    }

    /// Add a message. A question or a "blocked" from a worker stops it at a safe point: the feature is `Blocked` until
    /// the question is answered. `from` is checked against the caller's role by the layer above; here it must exist.
    #[allow(clippy::too_many_arguments)]
    pub fn post(
        &mut self,
        now_ms: u64,
        from: &str,
        to: &str,
        kind: MsgKind,
        text: &str,
        reply_to: Option<u64>,
        needs_person: bool,
    ) -> Result<u64, OrchError> {
        if text.trim().is_empty() {
            return Err(invalid("a message needs some text"));
        }
        if !self.party_ok(from) || !self.party_ok(to) {
            return Err(invalid(
                "a message goes between the conductor, a feature, the person and the system",
            ));
        }
        let feature = [from, to]
            .iter()
            .find_map(|p| p.strip_prefix("feature:"))
            .map(str::to_string);
        self.updated_ms = now_ms;
        let seq = self.push_message(
            now_ms,
            from,
            to,
            kind,
            feature.as_deref(),
            text,
            reply_to,
            needs_person,
        );
        if from.starts_with("feature:") && matches!(kind, MsgKind::Question | MsgKind::Blocked) {
            if let Some(fid) = &feature {
                if let Some(f) = self.feature_mut(fid) {
                    if matches!(f.state, FeatureState::Working | FeatureState::Starting) {
                        f.state = FeatureState::Blocked;
                    }
                    f.blocked_on = Some(seq);
                }
            }
        }
        Ok(seq)
    }

    /// Answer a question. The conductor may answer unless the question needs the person; the person always may. The
    /// worker is unblocked and marked to be told (`resume_pending`).
    pub fn answer(
        &mut self,
        now_ms: u64,
        question: u64,
        by_person: bool,
        text: &str,
    ) -> Result<u64, OrchError> {
        let q = self
            .messages
            .iter()
            .find(|m| m.seq == question)
            .cloned()
            .ok_or_else(|| invalid("there is no such message"))?;
        if !matches!(
            q.kind,
            MsgKind::Question | MsgKind::Blocked | MsgKind::Approval
        ) {
            return Err(invalid("only a question can be answered"));
        }
        if q.resolved {
            return Err(OrchError::Conflict(
                "that question is already answered".into(),
            ));
        }
        if q.needs_person && !by_person {
            return Err(OrchError::NotAllowed(
                "this one is for the person: it is waiting for their answer".into(),
            ));
        }
        let to = q.from.clone();
        let from = if by_person { "person" } else { "conductor" };
        let seq = self.post(
            now_ms,
            from,
            &to,
            MsgKind::Answer,
            text,
            Some(question),
            false,
        )?;
        if let Some(m) = self.messages.iter_mut().find(|m| m.seq == question) {
            m.resolved = true;
        }
        if let Some(fid) = q.feature {
            if let Some(f) = self.feature_mut(&fid) {
                if f.blocked_on == Some(question) {
                    f.blocked_on = None;
                    if f.state == FeatureState::Blocked {
                        f.state = FeatureState::Working;
                    }
                    f.resume_pending = true;
                }
            }
        }
        Ok(seq)
    }

    /// Mark a question as one only the person can answer (the conductor passes it up).
    pub fn escalate(&mut self, question: u64, now_ms: u64) -> Result<(), OrchError> {
        let m = self
            .messages
            .iter_mut()
            .find(|m| m.seq == question && !m.resolved)
            .ok_or_else(|| invalid("there is no such open question"))?;
        m.needs_person = true;
        self.updated_ms = now_ms;
        Ok(())
    }

    /// Messages for a party after `since`, oldest first.
    pub fn inbox(&self, party: &str, since: u64) -> Vec<&Message> {
        self.messages
            .iter()
            .filter(|m| m.seq > since && m.to == party)
            .collect()
    }

    /// Questions waiting for an answer, and who may give it.
    pub fn open_questions(&self) -> Vec<&Message> {
        self.messages
            .iter()
            .filter(|m| !m.resolved && matches!(m.kind, MsgKind::Question | MsgKind::Blocked))
            .collect()
    }

    // ---- features -----------------------------------------------------------------------------------------------

    /// Add a feature: the worker box, the branch, the claims and contracts it starts against. Refuses what the policy
    /// does not allow (worker count, sub-agents, a protected branch) and what would collide (claims).
    pub fn add_feature(&mut self, req: &FeatureReq, now_ms: u64) -> Result<String, OrchError> {
        if self.state != OrchState::Active {
            return Err(OrchError::Conflict(
                "this orchestration is not active".into(),
            ));
        }
        if self.features.len() >= MAX_FEATURES {
            return Err(OrchError::Limit(format!("at most {MAX_FEATURES} features")));
        }
        let title = clean_text(req.title.trim(), 80);
        if title.is_empty() {
            return Err(invalid("a feature needs a title"));
        }
        let brief = clean_text(req.brief.trim(), 6000);
        if brief.is_empty() {
            return Err(invalid("a feature needs a brief: what to build"));
        }
        let sub = req.sub_agents.unwrap_or(self.policy.max_sub_agents);
        if sub > self.policy.max_sub_agents {
            return Err(OrchError::Limit(format!(
                "at most {} sub-agents per worker here",
                self.policy.max_sub_agents
            )));
        }
        let worker = req
            .worker
            .clone()
            .unwrap_or_else(|| self.policy.worker.clone());
        if worker.kind != WorkerKind::Clone && !self.policy.may_create_boxes {
            return Err(OrchError::NotAllowed(
                "this orchestration may only use clones of the conductor's box".into(),
            ));
        }
        self.next_feature += 1;
        let id = format!("f{}", self.next_feature);
        let box_name = req
            .box_name
            .clone()
            .unwrap_or_else(|| format!("{}-{}", slug(&self.id, 12), id));
        crate::name::BoxName::new(box_name.clone()).map_err(|e| invalid(e.to_string()))?;
        if box_name == self.conductor_box {
            return Err(invalid("a worker needs its own box, not the conductor's"));
        }
        let new_box = !self
            .features
            .iter()
            .any(|f| f.state.is_open() && f.box_name == box_name);
        let from_spare = self.spare_boxes.contains(&box_name);
        if new_box && !from_spare && self.open_workers() >= usize::from(self.policy.max_workers) {
            self.next_feature -= 1;
            return Err(OrchError::Limit(format!(
                "at most {} worker boxes at once here",
                self.policy.max_workers
            )));
        }
        let branch = match &req.branch {
            Some(b) => b.clone(),
            None => format!(
                "{}{}/{}",
                self.policy.branch_prefix,
                self.id,
                slug(&title, 30)
            ),
        };
        if branch == self.policy.base_branch || branch.ends_with('/') {
            self.next_feature -= 1;
            return Err(invalid(
                "a feature works on its own branch, never the base branch",
            ));
        }
        if self
            .features
            .iter()
            .any(|f| f.state.is_open() && f.branch == branch)
        {
            self.next_feature -= 1;
            return Err(OrchError::Conflict(
                "another feature already uses that branch".into(),
            ));
        }
        for c in &req.contracts {
            let cid = slug(c, 40);
            match self.contract(&cid) {
                None => {
                    self.next_feature -= 1;
                    return Err(invalid(format!(
                        "there is no contract {c}: publish it first"
                    )));
                }
                Some(x) if !x.agreed => {
                    self.next_feature -= 1;
                    return Err(OrchError::Conflict(format!(
                        "the contract {c} is still a draft: agree it before work starts against it"
                    )));
                }
                Some(_) => {}
            }
        }
        let contracts: Vec<ContractRef> = req
            .contracts
            .iter()
            .filter_map(|c| {
                let id = slug(c, 40);
                self.contract(&id).map(|x| ContractRef {
                    id,
                    version: x.version,
                })
            })
            .collect();
        self.features.push(Feature {
            id: id.clone(),
            title,
            brief,
            box_name: box_name.clone(),
            transport: Transport::default(),
            worker,
            box_made: from_spare,
            repo: req.repo.clone().or_else(|| self.policy.repo.clone()),
            branch,
            claims: Vec::new(),
            contracts,
            after: Vec::new(),
            engine: req
                .engine
                .clone()
                .unwrap_or_else(|| self.policy.engine.clone()),
            model: req.model.clone(),
            sub_agents: sub,
            caps: req.caps,
            state: FeatureState::Planned,
            task_id: None,
            session_id: None,
            wip_branch: None,
            blocked_on: None,
            created_ms: now_ms,
            merged_ms: None,
            keep: req.keep,
            box_paused: false,
            box_destroyed: false,
            resume_pending: false,
        });
        self.spare_boxes.retain(|b| b != &box_name);
        if !req.claims.is_empty() {
            if let Err(e) = self.declare_claims(&id, &req.claims, now_ms) {
                self.features.retain(|f| f.id != id);
                self.next_feature -= 1;
                return Err(e);
            }
        }
        self.updated_ms = now_ms;
        Ok(id)
    }

    /// Features that may start now: planned, every feature they follow merged, every contract they use still agreed.
    pub fn startable(&self) -> Vec<String> {
        if self.state != OrchState::Active {
            return Vec::new();
        }
        self.features
            .iter()
            .filter(|f| f.state == FeatureState::Planned && f.transport == Transport::Ssh)
            .filter(|f| {
                f.after.iter().all(|a| {
                    self.feature(a)
                        .is_some_and(|x| x.state == FeatureState::Merged)
                })
            })
            .map(|f| f.id.clone())
            .collect()
    }

    /// The task for a feature has been queued.
    pub fn mark_started(
        &mut self,
        feature_id: &str,
        task_id: &str,
        now_ms: u64,
    ) -> Result<(), OrchError> {
        let f = self.feature_mut(feature_id).ok_or(OrchError::NoFeature)?;
        f.task_id = Some(task_id.to_string());
        f.state = FeatureState::Starting;
        f.resume_pending = false;
        self.updated_ms = now_ms;
        Ok(())
    }

    /// Stop, pause or hand back a feature. The caller acts on the task and box; this records the decision.
    pub fn set_feature_state(
        &mut self,
        feature_id: &str,
        state: FeatureState,
        now_ms: u64,
    ) -> Result<(), OrchError> {
        let f = self.feature_mut(feature_id).ok_or(OrchError::NoFeature)?;
        if matches!(f.state, FeatureState::Merged) {
            return Err(OrchError::Conflict("that feature is already merged".into()));
        }
        f.state = state;
        self.updated_ms = now_ms;
        if matches!(state, FeatureState::Stopped | FeatureState::Failed) {
            self.merge_queue
                .retain(|e| e.feature_id != feature_id || e.state.is_finished());
        }
        Ok(())
    }

    /// Give a feature to another box (for example when its box was lost). Its branch and claims stay.
    pub fn reassign(
        &mut self,
        feature_id: &str,
        box_name: &str,
        now_ms: u64,
    ) -> Result<(), OrchError> {
        crate::name::BoxName::new(box_name.to_string()).map_err(|e| invalid(e.to_string()))?;
        if box_name == self.conductor_box {
            return Err(invalid("a worker needs its own box, not the conductor's"));
        }
        let taken = self
            .features
            .iter()
            .any(|f| f.id != feature_id && f.state.is_open() && f.box_name == box_name);
        let f = self.feature_mut(feature_id).ok_or(OrchError::NoFeature)?;
        if matches!(f.state, FeatureState::Merged) {
            return Err(OrchError::Conflict("that feature is already merged".into()));
        }
        if f.transport == Transport::Hub {
            return Err(OrchError::Conflict(
                "that feature went over the worker channel and cannot be reassigned until a task can be stopped over it (task.stop is not built yet)".into(),
            ));
        }
        f.box_name = box_name.to_string();
        f.box_made = false;
        f.box_paused = false;
        f.task_id = None;
        f.state = FeatureState::Planned;
        let _ = taken; // sharing a box is allowed: the daemon's admission still caps its runs
        self.updated_ms = now_ms;
        Ok(())
    }

    // ---- lifecycle of worker boxes ------------------------------------------------------------------------------

    /// What to do with worker boxes of merged features: pause the box when the feature merges, destroy it after the
    /// policy's days unless it is kept. Never touches a box another open feature still uses.
    pub fn sweep_boxes(&self, now_ms: u64) -> Vec<BoxAction> {
        let mut out = Vec::new();
        for f in self
            .features
            .iter()
            .filter(|f| f.state == FeatureState::Merged)
        {
            let shared = self
                .features
                .iter()
                .any(|o| o.id != f.id && o.state.is_open() && o.box_name == f.box_name);
            // only a box this orchestration made is ours to pause or destroy
            if shared || f.box_destroyed || !f.box_made {
                continue;
            }
            if !f.box_paused {
                out.push(BoxAction::Pause {
                    feature: f.id.clone(),
                    box_name: f.box_name.clone(),
                });
                continue;
            }
            let keep = f.keep || self.policy.keep_workers;
            let due = f.merged_ms.is_some_and(|m| {
                now_ms.saturating_sub(m) >= u64::from(self.policy.destroy_after_days) * 86_400_000
            });
            if !keep && due {
                out.push(BoxAction::Destroy {
                    feature: f.id.clone(),
                    box_name: f.box_name.clone(),
                });
            }
        }
        out
    }

    pub fn box_done(&mut self, feature_id: &str, action: &BoxAction) {
        if let Some(f) = self.feature_mut(feature_id) {
            match action {
                BoxAction::Pause { .. } => f.box_paused = true,
                BoxAction::Destroy { .. } => f.box_destroyed = true,
            }
        }
    }

    // ---- prompts ------------------------------------------------------------------------------------------------

    /// What a worker is told. Everything here comes from the conductor or the person; the worker treats text from
    /// anywhere else (issues, web pages, files) as data.
    pub fn worker_prompt(&self, feature_id: &str) -> Result<String, OrchError> {
        let f = self.feature(feature_id).ok_or(OrchError::NoFeature)?;
        let mut s = String::new();
        s.push_str(&format!(
            "You are a worker on feature {} (\"{}\") of a larger job: {}\n\n",
            f.id,
            f.title,
            clean_text(&self.goal, 600)
        ));
        s.push_str(&format!("What to build:\n{}\n\n", f.brief));
        s.push_str(&format!(
            "Work on the branch `{}`{}. Commit often, and push the branch to `origin` when it is ready (the merge queue fetches it from there). Never touch `{}`, never push to a protected branch, and never merge: the conductor's merge queue does that.\n\n",
            f.branch,
            f.repo.as_ref().map(|r| format!(" in the repository `{r}`")).unwrap_or_default(),
            self.policy.base_branch
        ));
        if f.claims.is_empty() {
            s.push_str("You have no file claims yet. Before you edit anything, ask for claims with the `claims_declare` tool.\n\n");
        } else {
            s.push_str("The files and areas you own (edit only these):\n");
            for c in &f.claims {
                s.push_str(&format!("- {}\n", c.pattern));
            }
            s.push_str("Before editing anything else, call `claims_check`. If a file belongs to someone else, ask the conductor with `worker_ask` instead of editing it.\n\n");
        }
        if !f.contracts.is_empty() {
            s.push_str("Shared contracts you build against (read each with `contract_read`; do not change them):\n");
            for r in &f.contracts {
                if let Some(c) = self.contract(&r.id) {
                    s.push_str(&format!(
                        "- {} (version {}): {} \n",
                        c.name, c.version, c.kind
                    ));
                }
            }
            s.push('\n');
        }
        s.push_str(&format!(
            "You may use at most {} sub-agents at the same time.\n",
            f.sub_agents
        ));
        s.push_str("If you need a decision, call `worker_ask`, write down where you stopped, and end your turn: you will be resumed with the answer. Report progress with `worker_status`. When the feature is complete and its tests pass, call `worker_done`.\n");
        if !self.policy.guidance.trim().is_empty() {
            s.push_str(&format!(
                "\nHouse rules from the person:\n{}\n",
                clean_text(&self.policy.guidance, 3000)
            ));
        }
        Ok(s)
    }

    /// What the conductor is told when this server starts it.
    pub fn conductor_prompt(&self) -> String {
        let mut s = format!(
            "You are the conductor of an orchestration. The goal: {}\n\nYou have the Oz Box tools. Plan the features, publish the shared contracts first, then start one feature per worker box with `task_start` (at most {} worker boxes, at most {} sub-agents each). Check `claims_check` before overlapping work, answer workers' questions with `approvals_decide` and the mailbox, and put finished features in the `merge_queue`. Anything risky (a protected branch, production, a message to someone outside, spend above the cap) goes to the person; you cannot decide it.\n",
            clean_text(&self.goal, 1500), self.policy.max_workers, self.policy.max_sub_agents
        );
        if !self.policy.guidance.trim().is_empty() {
            s.push_str(&format!(
                "\nHouse rules from the person:\n{}\n",
                clean_text(&self.policy.guidance, 3000)
            ));
        }
        s
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum BoxAction {
    Pause { feature: String, box_name: String },
    Destroy { feature: String, box_name: String },
}

// ---- Book-level operations ---------------------------------------------------------------------------------------

impl Book {
    pub fn orchestration(&self, id: &str) -> Option<&Orchestration> {
        self.orchestrations.iter().find(|o| o.id == id)
    }
    pub fn orchestration_mut(&mut self, id: &str) -> Option<&mut Orchestration> {
        self.orchestrations.iter_mut().find(|o| o.id == id)
    }

    /// Start an orchestration. `layers` are the rules file and the request: each can only tighten the settings.
    pub fn start_orchestration(
        &mut self,
        goal: &str,
        person: &str,
        conductor_box: &str,
        layers: &[&Overrides],
        now_ms: u64,
    ) -> Result<String, OrchError> {
        let goal = clean_text(goal.trim(), 2000);
        if goal.is_empty() {
            return Err(invalid("say what the orchestration is for"));
        }
        crate::name::BoxName::new(conductor_box.to_string()).map_err(|e| invalid(e.to_string()))?;
        if self
            .orchestrations
            .iter()
            .filter(|o| matches!(o.state, OrchState::Active | OrchState::Paused))
            .count()
            >= MAX_ORCHESTRATIONS
        {
            return Err(OrchError::Limit("too many orchestrations are open".into()));
        }
        let policy = effective(&self.orch_settings, layers);
        self.next_seq += 1;
        let id = format!("o{}", self.next_seq);
        self.orchestrations.push(Orchestration {
            id: id.clone(),
            goal,
            requested_by: person.to_string(),
            conductor_box: conductor_box.to_string(),
            conductor_task: None,
            conductor_session: None,
            state: OrchState::Active,
            paused_reason: None,
            created_ms: now_ms,
            updated_ms: now_ms,
            policy,
            features: Vec::new(),
            contracts: Vec::new(),
            messages: Vec::new(),
            merge_queue: Vec::new(),
            next_feature: 0,
            next_msg: 0,
            spare_boxes: Vec::new(),
        });
        self.record(now_ms, person, "orchestration.started", None, &id);
        while self.orchestrations.len() > MAX_ORCHESTRATIONS {
            match self
                .orchestrations
                .iter()
                .position(|o| matches!(o.state, OrchState::Done | OrchState::Stopped))
            {
                Some(p) => {
                    self.orchestrations.remove(p);
                }
                None => break,
            }
        }
        Ok(id)
    }

    /// What the feature tasks of an orchestration have spent, in US cents.
    pub fn orchestration_spend(&self, id: &str) -> u64 {
        let Some(o) = self.orchestration(id) else {
            return 0;
        };
        o.features
            .iter()
            .filter_map(|f| f.task_id.as_deref().and_then(|t| self.task(t)))
            .map(|t| t.spend_cents)
            .sum()
    }

    /// Keep an orchestration inside its one spend cap. At the cap it pauses and every active worker task is capped at
    /// what it has spent, so the supervisor's own cap logic checkpoints it to its `wip/` branch and asks; nothing is
    /// killed unsaved. Returns whether it paused now.
    pub fn enforce_budget(&mut self, id: &str, now_ms: u64) -> bool {
        let spent = self.orchestration_spend(id);
        let Some(o) = self.orchestration(id) else {
            return false;
        };
        let Some(cap) = o.policy.spend_cap_cents else {
            return false;
        };
        if spent < cap || o.state != OrchState::Active {
            return false;
        }
        let tasks: Vec<String> = o
            .features
            .iter()
            .filter(|f| f.state.is_open())
            .filter_map(|f| f.task_id.clone())
            .collect();
        for tid in &tasks {
            if let Some(t) = self.task_mut(tid) {
                if !t.state.is_terminal() {
                    t.spec.caps.max_spend_cents = Some(t.spend_cents.max(1));
                }
            }
        }
        if let Some(o) = self.orchestration_mut(id) {
            o.state = OrchState::Paused;
            o.paused_reason = Some("spend cap".into());
            o.updated_ms = now_ms;
            let text = format!(
                "The orchestration reached its spend cap ({} cents). Workers are saving their work. Add budget to continue.",
                cap
            );
            o.push_message(
                now_ms,
                "system",
                "person",
                MsgKind::Note,
                None,
                &text,
                None,
                true,
            );
        }
        self.record(now_ms, "supervisor", "orchestration.cap", None, id);
        true
    }

    /// Raise the cap and let a paused orchestration continue (its capped tasks are given room by the caller through the
    /// ordinary "add budget" on each task).
    pub fn add_orch_budget(
        &mut self,
        id: &str,
        add_cents: u64,
        who: &str,
        now_ms: u64,
    ) -> Result<u64, OrchError> {
        let o = self
            .orchestration_mut(id)
            .ok_or(OrchError::NoOrchestration)?;
        let cap = o
            .policy
            .spend_cap_cents
            .unwrap_or(0)
            .saturating_add(add_cents);
        o.policy.spend_cap_cents = Some(cap);
        if o.state == OrchState::Paused && o.paused_reason.as_deref() == Some("spend cap") {
            o.state = OrchState::Active;
            o.paused_reason = None;
        }
        o.updated_ms = now_ms;
        self.record(now_ms, who, "orchestration.budget", None, id);
        Ok(cap)
    }

    /// Feature states follow their tasks: a finished task means the work is ready to merge, a failed one is failed.
    pub fn follow_tasks(&mut self, now_ms: u64) {
        #[allow(clippy::type_complexity)]
        let updates: Vec<(String, String, TaskState, Option<String>, Option<String>)> = self
            .orchestrations
            .iter()
            .flat_map(|o| {
                o.features.iter().filter_map(|f| {
                    let t = self.task(f.task_id.as_deref()?)?;
                    Some((
                        o.id.clone(),
                        f.id.clone(),
                        t.state,
                        t.wip_branch.clone(),
                        t.handle.clone(),
                    ))
                })
            })
            .collect();
        for (oid, fid, ts, wip, _) in updates {
            let Some(o) = self.orchestration_mut(&oid) else {
                continue;
            };
            let Some(f) = o.feature_mut(&fid) else {
                continue;
            };
            if wip.is_some() {
                f.wip_branch = wip;
            }
            let next = match (f.state, ts) {
                (FeatureState::Starting, TaskState::Running) => Some(FeatureState::Working),
                (
                    FeatureState::Starting | FeatureState::Working,
                    TaskState::Review | TaskState::Done,
                ) if f.blocked_on.is_none() => Some(FeatureState::ReadyToMerge),
                (
                    FeatureState::Starting | FeatureState::Working | FeatureState::Blocked,
                    TaskState::Failed,
                ) => Some(FeatureState::Failed),
                (FeatureState::Starting | FeatureState::Working, TaskState::Cancelled) => {
                    Some(FeatureState::Stopped)
                }
                _ => None,
            };
            if let Some(n) = next {
                f.state = n;
                o.updated_ms = now_ms;
            }
        }
    }
}

/// How a message reaches a worker whose engine is still running. The default says it cannot, and the answer waits
/// until the worker ends its turn, when the feature is resumed from its branch with the answer in its prompt.
pub trait WorkerChannel {
    fn send(&mut self, task_id: &str, text: &str) -> Result<(), String>;
}

pub struct NoChannel;

impl WorkerChannel for NoChannel {
    fn send(&mut self, _: &str, _: &str) -> Result<(), String> {
        Err("this engine cannot take a message while it works".into())
    }
}

fn model_ref(m: &str) -> Option<crate::run::ModelRef> {
    let (p, model) = m.split_once('/')?;
    Some(crate::run::ModelRef {
        provider_id: p.to_string(),
        model: model.to_string(),
    })
}

impl Book {
    fn feature_spec(
        &self,
        oid: &str,
        fid: &str,
        prompt: String,
        key: String,
    ) -> Result<crate::run::RunSpec, OrchError> {
        let o = self.orchestration(oid).ok_or(OrchError::NoOrchestration)?;
        let f = o.feature(fid).ok_or(OrchError::NoFeature)?;
        let mut caps = f.caps;
        if let Some(cap) = o.policy.spend_cap_cents {
            let left = cap.saturating_sub(self.orchestration_spend(oid)).max(1);
            caps.max_spend_cents = Some(caps.max_spend_cents.map_or(left, |c| c.min(left)));
        }
        Ok(crate::run::RunSpec {
            engine: f.engine.clone(),
            prompt,
            skill: None,
            box_name: f.box_name.clone(),
            repo: f.repo.clone(),
            branch: Some(f.branch.clone()),
            caps,
            deliver_to: Vec::new(),
            requested_by: o.requested_by.clone(),
            origin: crate::run::RunOrigin::Orchestration {
                id: oid.to_string(),
                feature: fid.to_string(),
            },
            idempotency_key: Some(key),
            model: f.model.as_deref().and_then(model_ref),
            interactive: false,
        })
    }

    /// Queue the worker task of a feature that may start. The supervisor admits it when its box has room.
    pub fn start_feature(
        &mut self,
        oid: &str,
        fid: &str,
        now_ms: u64,
    ) -> Result<String, OrchError> {
        let o = self.orchestration(oid).ok_or(OrchError::NoOrchestration)?;
        if o.state != OrchState::Active {
            return Err(OrchError::Conflict("this orchestration is paused".into()));
        }
        let prompt = o.worker_prompt(fid)?;
        let key = format!("orch:{oid}:{fid}:start");
        let spec = self.feature_spec(oid, fid, prompt, key)?;
        let (tid, _) = self
            .enqueue(spec, now_ms, None)
            .map_err(|e| OrchError::Limit(e.to_string()))?;
        let o = self
            .orchestration_mut(oid)
            .ok_or(OrchError::NoOrchestration)?;
        o.mark_started(fid, &tid, now_ms)?;
        Ok(tid)
    }

    /// Continue a feature after an answer, a changed contract or a conflict: a new task on the same branch, from the
    /// saved work, with what the worker missed in its prompt.
    pub fn resume_feature(
        &mut self,
        oid: &str,
        fid: &str,
        now_ms: u64,
    ) -> Result<String, OrchError> {
        let o = self.orchestration(oid).ok_or(OrchError::NoOrchestration)?;
        if o.state != OrchState::Active {
            return Err(OrchError::Conflict("this orchestration is paused".into()));
        }
        let mut prompt = o.worker_prompt(fid)?;
        let party = format!("feature:{fid}");
        let missed: Vec<String> = o
            .inbox(&party, 0)
            .iter()
            .rev()
            .take(10)
            .map(|m| format!("- ({}) {}", m.from, m.text))
            .collect();
        if !missed.is_empty() {
            prompt.push_str(
                "\nYou stopped and are being resumed from your saved work. Messages for you, newest first:\n",
            );
            prompt.push_str(&missed.join("\n"));
            prompt.push('\n');
        }
        self.next_seq += 1;
        let key = format!("orch:{oid}:{fid}:resume{}", self.next_seq);
        let spec = self.feature_spec(oid, fid, prompt, key)?;
        let (tid, _) = self
            .enqueue(spec, now_ms, None)
            .map_err(|e| OrchError::Limit(e.to_string()))?;
        let o = self
            .orchestration_mut(oid)
            .ok_or(OrchError::NoOrchestration)?;
        o.mark_started(fid, &tid, now_ms)?;
        Ok(tid)
    }

    /// Queue the conductor's own run on its box, with the orchestration's goal and rules in the prompt.
    pub fn start_conductor(
        &mut self,
        oid: &str,
        extra: &str,
        now_ms: u64,
    ) -> Result<String, OrchError> {
        let o = self.orchestration(oid).ok_or(OrchError::NoOrchestration)?;
        let mut prompt = o.conductor_prompt();
        if !extra.trim().is_empty() {
            prompt.push_str(&format!(
                "\nThe person adds:\n{}\n",
                clean_text(extra, 4000)
            ));
        }
        let spec = crate::run::RunSpec {
            engine: o.policy.engine.clone(),
            prompt,
            skill: None,
            box_name: o.conductor_box.clone(),
            repo: o.policy.repo.clone(),
            branch: None,
            caps: RunCaps {
                max_spend_cents: o.policy.spend_cap_cents,
                ..Default::default()
            },
            deliver_to: Vec::new(),
            requested_by: o.requested_by.clone(),
            origin: crate::run::RunOrigin::Orchestration {
                id: oid.to_string(),
                feature: String::new(),
            },
            idempotency_key: Some(format!("orch:{oid}:conductor")),
            model: None,
            interactive: false,
        };
        let (tid, _) = self
            .enqueue(spec, now_ms, None)
            .map_err(|e| OrchError::Limit(e.to_string()))?;
        if let Some(o) = self.orchestration_mut(oid) {
            o.conductor_task = Some(tid.clone());
        }
        Ok(tid)
    }

    /// One pass of the orchestrations, called with the supervisor's tick: features follow their tasks, the spend cap
    /// is enforced, features that may start are queued, features with something to hear are told (or resumed), and
    /// worker boxes due to be paused or destroyed are returned for the host to act on. A feature is queued only when
    /// its box is ready (`box_ready`), which the host answers.
    pub fn tick_orchestrations(
        &mut self,
        chan: &mut dyn WorkerChannel,
        box_ready: &mut dyn FnMut(&Feature) -> bool,
        now_ms: u64,
    ) -> Vec<(String, BoxAction)> {
        self.follow_tasks(now_ms);
        let ids: Vec<String> = self
            .orchestrations
            .iter()
            .filter(|o| o.state != OrchState::Stopped)
            .map(|o| o.id.clone())
            .collect();
        let mut acts = Vec::new();
        for id in ids {
            self.enforce_budget(&id, now_ms);
            let Some(o) = self.orchestration(&id) else {
                continue;
            };
            if o.state == OrchState::Active {
                let go: Vec<String> = o
                    .startable()
                    .into_iter()
                    .filter(|f| {
                        o.feature(f)
                            .is_some_and(|x| x.task_id.is_none() && box_ready(x))
                    })
                    .collect();
                for f in go {
                    let _ = self.start_feature(&id, &f, now_ms);
                }
                let Some(o) = self.orchestration(&id) else {
                    continue;
                };
                #[allow(clippy::type_complexity)]
                let pending: Vec<(String, Option<String>, bool, String)> = o
                    .features
                    .iter()
                    .filter(|f| f.resume_pending)
                    .map(|f| {
                        let live =
                            f.task_id
                                .as_deref()
                                .and_then(|t| self.task(t))
                                .is_some_and(|t| {
                                    !t.state.is_terminal() && t.state != TaskState::Review
                                });
                        let text = o
                            .inbox(&format!("feature:{}", f.id), 0)
                            .iter()
                            .rev()
                            .take(3)
                            .map(|m| m.text.clone())
                            .collect::<Vec<_>>()
                            .join("\n");
                        (f.id.clone(), f.task_id.clone(), live, text)
                    })
                    .collect();
                for (fid, tid, live, text) in pending {
                    if live {
                        if let Some(t) = tid {
                            if chan.send(&t, &text).is_ok() {
                                if let Some(f) = self
                                    .orchestration_mut(&id)
                                    .and_then(|o| o.feature_mut(&fid))
                                {
                                    f.resume_pending = false;
                                }
                            }
                        }
                    } else {
                        let _ = self.resume_feature(&id, &fid, now_ms);
                    }
                }
            }
            if let Some(o) = self.orchestration(&id) {
                for a in o.sweep_boxes(now_ms) {
                    acts.push((id.clone(), a));
                }
            }
        }
        acts
    }
}

impl Book {
    /// Stop or pause one feature: its task is asked to stop (the supervisor saves its work to its `wip/` branch first).
    pub fn halt_feature(
        &mut self,
        oid: &str,
        fid: &str,
        pause: bool,
        now_ms: u64,
    ) -> Result<(), OrchError> {
        let tid = {
            let o = self
                .orchestration_mut(oid)
                .ok_or(OrchError::NoOrchestration)?;
            o.set_feature_state(
                fid,
                if pause {
                    FeatureState::Paused
                } else {
                    FeatureState::Stopped
                },
                now_ms,
            )?;
            o.feature(fid).and_then(|f| f.task_id.clone())
        };
        if let Some(t) = tid.and_then(|t| self.task_mut(&t)) {
            if !t.state.is_terminal() {
                t.cancel_requested = true;
            }
        }
        Ok(())
    }

    /// Pause (or stop for good) a whole orchestration: every open feature and the conductor's own run are halted.
    pub fn halt_orchestration(
        &mut self,
        oid: &str,
        stop: bool,
        who: &str,
        now_ms: u64,
    ) -> Result<(), OrchError> {
        let (open, ctask): (Vec<String>, Option<String>) = {
            let o = self.orchestration(oid).ok_or(OrchError::NoOrchestration)?;
            (
                o.features
                    .iter()
                    .filter(|f| f.state.is_open())
                    .map(|f| f.id.clone())
                    .collect(),
                o.conductor_task.clone(),
            )
        };
        for f in open {
            let _ = self.halt_feature(oid, &f, !stop, now_ms);
        }
        if let Some(t) = ctask.and_then(|t| self.task_mut(&t)) {
            if !t.state.is_terminal() {
                t.cancel_requested = true;
            }
        }
        if let Some(o) = self.orchestration_mut(oid) {
            o.state = if stop {
                OrchState::Stopped
            } else {
                OrchState::Paused
            };
            o.paused_reason = (!stop).then(|| "paused by a person".to_string());
            o.updated_ms = now_ms;
        }
        self.record(
            now_ms,
            who,
            if stop {
                "orchestration.stopped"
            } else {
                "orchestration.paused"
            },
            None,
            oid,
        );
        Ok(())
    }

    /// Let a paused orchestration go on: paused features are resumed from their saved branches.
    pub fn resume_orchestration(
        &mut self,
        oid: &str,
        who: &str,
        now_ms: u64,
    ) -> Result<(), OrchError> {
        let paused: Vec<String> = {
            let o = self
                .orchestration_mut(oid)
                .ok_or(OrchError::NoOrchestration)?;
            if o.state == OrchState::Stopped || o.state == OrchState::Done {
                return Err(OrchError::Conflict("that orchestration is finished".into()));
            }
            o.state = OrchState::Active;
            o.paused_reason = None;
            o.updated_ms = now_ms;
            o.features
                .iter()
                .filter(|f| f.state == FeatureState::Paused)
                .map(|f| f.id.clone())
                .collect()
        };
        for f in paused {
            let _ = self.resume_feature(oid, &f, now_ms);
        }
        self.record(now_ms, who, "orchestration.resumed", None, oid);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
