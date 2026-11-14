//! Tasks, messages, artifacts and the state table (ADR 0044 section 3). The shapes are A2A-shaped (task, status, messages made of
//! parts, artifacts); this release does not claim conformance with the specification.

use serde::{Deserialize, Serialize};

use crate::approval_subject::{is_production_environment, Encoder};

/// The closed list of task kinds in this release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TaskKind {
    /// Ask the other side something. Ungated.
    Question,
    /// Tell the other side something, with nothing to do. Ungated.
    Note,
    /// Ask the receiver to do one typed act. Gated: refused by name until the approval path exists.
    LaptopAct,
}

impl TaskKind {
    pub fn name(self) -> &'static str {
        match self {
            TaskKind::Question => "question",
            TaskKind::Note => "note",
            TaskKind::LaptopAct => "laptop-act",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum State {
    Held,
    Submitted,
    Working,
    InputRequired,
    ApprovalRequired,
    Completed,
    Failed,
    Canceled,
    Rejected,
}

impl State {
    pub fn name(self) -> &'static str {
        match self {
            State::Held => "held",
            State::Submitted => "submitted",
            State::Working => "working",
            State::InputRequired => "input-required",
            State::ApprovalRequired => "approval-required",
            State::Completed => "completed",
            State::Failed => "failed",
            State::Canceled => "canceled",
            State::Rejected => "rejected",
        }
    }

    pub fn parse(s: &str) -> Option<State> {
        [
            State::Held,
            State::Submitted,
            State::Working,
            State::InputRequired,
            State::ApprovalRequired,
            State::Completed,
            State::Failed,
            State::Canceled,
            State::Rejected,
        ]
        .into_iter()
        .find(|x| x.name() == s)
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            State::Completed | State::Failed | State::Canceled | State::Rejected
        )
    }
}

/// Whose authority moves a state. The sender never writes a receiver's state and the receiver never writes a sender's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Sender,
    Receiver,
}

/// ADR 0044 section 3.1, as a function. `Held` is the sender's own (unsent); everything after delivery is the receiver's.
pub fn may_move(from: State, to: State, side: Side) -> bool {
    use State::*;
    if from.terminal() {
        return false;
    }
    match side {
        Side::Sender => matches!((from, to), (Held, Submitted | Canceled | Failed)),
        Side::Receiver => matches!(
            (from, to),
            (
                Submitted,
                Rejected | Working | Canceled | Completed | Failed | InputRequired
            ) | (
                Working,
                InputRequired | ApprovalRequired | Completed | Failed | Canceled
            ) | (InputRequired, Working | Failed | Canceled | Completed)
                | (ApprovalRequired, Working | Failed | Canceled)
        ),
    }
}

/// A claim the sender makes about where a message's words came from. For display only: no rule depends on it. **An end never claims
/// `Person`**: whether a person wrote something is not a thing a sender can say about itself (an agent in a terminal looks like a
/// person to a check of the terminal), so every message an end sends says `Fleet`. A receiver treats text from a peer as untrusted
/// whatever it claims, and keeps the claim only as what the sender said.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Label {
    Person,
    Fleet,
    Untrusted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Part {
    Text {
        text: String,
    },
    Data {
        schema: String,
        json: serde_json::Value,
    },
}

impl Part {
    /// Every string in the part, for the screen and the size check.
    pub fn strings(&self) -> Vec<String> {
        match self {
            Part::Text { text } => vec![text.clone()],
            Part::Data { schema, json } => vec![schema.clone(), json.to_string()],
        }
    }

    pub fn size(&self) -> usize {
        self.strings().iter().map(String::len).sum()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    pub id: String,
    pub from: String,
    pub ts_ms: u64,
    /// What the sender **claimed**. Never trusted.
    pub label: Label,
    pub parts: Vec<Part>,
    /// Stamped by the end that stores the message, never taken from the wire: `self`, or `peer:<name>`.
    #[serde(default)]
    pub provenance: String,
    /// True for every message that came from a peer. Text from a peer reaches a model only inside a fenced untrusted block.
    #[serde(default)]
    pub untrusted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Artifact {
    pub id: String,
    pub name: String,
    pub parts: Vec<Part>,
    /// SHA-256 of the artifact's canonical bytes, hex: what a later reference names it by.
    pub hash: String,
}

impl Artifact {
    pub fn new(id: &str, name: &str, parts: Vec<Part>) -> Artifact {
        let mut e = Encoder::new("ozbox-mesh-artifact");
        e.text(name).count(parts.len());
        for p in &parts {
            e.text(&serde_json::to_string(p).unwrap_or_default());
        }
        Artifact {
            id: id.to_string(),
            name: name.to_string(),
            parts,
            hash: crate::approval_subject::to_hex(&e.digest()),
        }
    }
}

/// The typed acts. One in this release. Never a free-form command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "act", rename_all = "kebab-case")]
pub enum Act {
    /// Push one commit to one branch, without force.
    PushRef {
        repo: String,
        remote: String,
        r#ref: String,
        sha: String,
        env: String,
    },
}

/// A name: letters, digits, `.`, `_` and `-`, not starting with `-` or `.`.
fn plain_name(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && !s.starts_with(['-', '.'])
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// A branch name that `git check-ref-format --branch` would accept, in the plain subset an act allows: no `+` (a force push), no
/// `:` (a refspec), no `..`, `//`, `@{`, `.lock` or leading and trailing separators.
pub fn branch_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 200
        && !s.starts_with(['-', '/', '.'])
        && !s.ends_with(['/', '.'])
        && !s.ends_with(".lock")
        && !s.contains("..")
        && !s.contains("//")
        && !s.contains("/.")
        && !s.contains(".lock/")
        && s != "@"
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-'))
}

impl Act {
    pub fn env(&self) -> &str {
        match self {
            Act::PushRef { env, .. } => env,
        }
    }

    /// Whether the act is shaped right. This is the shape a future approval digest signs and the laptop parses, so it is strict:
    /// `ref` is a plain branch name (never `+main`, never `HEAD:refs/...`), `remote` and `repo` are the **names** of a remote and a
    /// repository pinned on the receiving computer (never a URL, a path or a `transport::` form), and `sha` is a full object id.
    pub fn valid(&self) -> Result<(), &'static str> {
        match self {
            Act::PushRef {
                repo,
                remote,
                r#ref,
                sha,
                env,
            } => {
                if !(plain_name(repo, 64)
                    && plain_name(remote, 64)
                    && branch_ok(r#ref)
                    && plain_name(env, 64))
                {
                    return Err("act-field-invalid");
                }
                if !matches!(sha.len(), 40 | 64) || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err("act-sha-invalid");
                }
                Ok(())
            }
        }
    }

    pub fn is_production(&self) -> bool {
        is_production_environment(self.env())
    }
}

/// The codes a refusal is named by (they are audit words and `why` words).
pub mod code {
    pub const PRODUCTION: &str = "production-act-refused";
    pub const NO_APPROVAL_PATH: &str = "approval-path-not-built";
    pub const KEY_SHAPED: &str = "key-shaped-content";
    pub const TOO_BIG: &str = "too-big";
    pub const RATE: &str = "resource-exhausted";
    pub const NOT_ALLOWED: &str = "kind-not-allowed";
    pub const CONFLICT: &str = "task-id-conflict";
    pub const JOURNAL_FULL: &str = "journal-full";
    pub const EXPIRED: &str = "expired";
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Task {
    pub id: String,
    pub from: String,
    pub to: String,
    pub kind: TaskKind,
    pub title: String,
    pub state: State,
    pub reason: Option<String>,
    pub context_id: Option<String>,
    pub parent: Option<String>,
    pub deadline_ms: u64,
    pub created_ms: u64,
    pub updated_ms: u64,
    pub messages: Vec<Message>,
    pub artifacts: Vec<Artifact>,
    pub act: Option<Act>,
    /// Always `None` on a task this release acts on: no approval text or id grants anything.
    pub approval_ref: Option<String>,
    /// The sequence number of the envelope that carried the task, while it is unacknowledged (sender side).
    pub sent_seq: Option<u64>,
    pub unread: bool,
    /// The hash of the body that created the task: what a replay or a reused id is compared with, and what a tombstone keeps.
    #[serde(default)]
    pub hash: String,
    /// The other end asked this one to stop. A cancel is a request: the task ends only when the receiver moves it.
    #[serde(default)]
    pub cancel_requested: bool,
}

/// The longest title and the most inline bytes in one message (starting values, tuned later).
pub const MAX_TITLE: usize = 200;
pub const MAX_INLINE: usize = 64 * 1024;

/// The sealed bodies of the sequenced and control kinds.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "body", rename_all = "kebab-case")]
pub enum Body {
    Task {
        kind: TaskKind,
        title: String,
        context_id: Option<String>,
        parent: Option<String>,
        deadline_ms: u64,
        act: Option<Act>,
        approval_ref: Option<String>,
        message: Message,
    },
    Message {
        message: Message,
    },
    Status {
        state: State,
        reason: Option<String>,
    },
    Artifact {
        artifact: Artifact,
    },
    Cancel,
}

impl Body {
    /// The envelope kind that carries this body.
    pub fn kind_name(&self) -> &'static str {
        match self {
            Body::Task { .. } => "task",
            Body::Message { .. } => "message",
            Body::Status { .. } => "status",
            Body::Artifact { .. } => "artifact",
            Body::Cancel => "cancel",
        }
    }

    /// Every string in the body, for the screen. Ids, names, parent and reasons are in it, not only the text parts.
    pub fn strings(&self) -> Vec<String> {
        let mut out = Vec::new();
        let msg = |m: &Message, out: &mut Vec<String>| {
            out.push(m.id.clone());
            out.push(m.from.clone());
            out.extend(m.parts.iter().flat_map(Part::strings));
        };
        match self {
            Body::Task {
                title,
                context_id,
                parent,
                act,
                approval_ref,
                message,
                ..
            } => {
                out.push(title.clone());
                out.extend(context_id.iter().cloned());
                out.extend(parent.iter().cloned());
                out.extend(approval_ref.iter().cloned());
                // the act's fields are checked for shape (`Act::valid`), not for key shapes: a full object id looks like a token
                let _ = act;
                msg(message, &mut out);
            }
            Body::Message { message } => msg(message, &mut out),
            Body::Status { reason, .. } => out.extend(reason.iter().cloned()),
            Body::Artifact { artifact } => {
                out.push(artifact.id.clone());
                out.push(artifact.name.clone());
                out.extend(artifact.parts.iter().flat_map(Part::strings));
            }
            Body::Cancel => {}
        }
        out
    }
}

/// A short, stable id: 10 characters of time then 16 random ones (Crockford base32), so ids sort by creation.
pub fn new_id(now_ms: u64) -> String {
    const A: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut out = String::new();
    for i in (0..10).rev() {
        out.push(char::from(A[((now_ms >> (5 * i)) & 31) as usize]));
    }
    let mut r = [0u8; 16];
    let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut r);
    for b in &r {
        out.push(char::from(A[usize::from(b & 31)]));
    }
    out
}
