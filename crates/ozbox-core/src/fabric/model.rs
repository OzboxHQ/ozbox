//! Messages, their delivery states and the limits every surface shares.

use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

use super::addr::{Address, Participant, ParticipantKind};

/// The longest message text, in bytes, after cleaning. Long output stays where it was made; a message points at it.
pub const MAX_TEXT: usize = 8 * 1024;
/// The most recipients one post reaches, after groups and fleets are expanded.
pub const MAX_FANOUT: usize = 20;
/// Posts per sender per minute, and per day.
pub const PER_MINUTE: u32 = 30;
pub const PER_DAY: u32 = 600;
/// The most messages one mailbox keeps; read ones go first.
pub const MAX_MAILBOX: usize = 5_000;
/// Retention: a read message is kept 30 days, an unread one 90 (then it expires and its sender sees `expired`).
pub const KEEP_READ_MS: u64 = 30 * 86_400_000;
pub const KEEP_UNREAD_MS: u64 = 90 * 86_400_000;
/// The longest a fetch waits for a message.
pub const MAX_WAIT_MS: u64 = 25_000;
/// The most messages one fetch returns.
pub const MAX_GET: usize = 50;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeliveryState {
    /// On the sender's box; not yet taken by the hub.
    Queued,
    /// Stored on the hub, in the recipient's mailbox.
    Accepted,
    /// Fetched by the recipient (or in its box's replica).
    Delivered,
    /// The recipient acknowledged it.
    Read,
    /// Retention ended before it was read.
    Expired,
    /// Queued on a worker, then refused by the hub (the sender's receipt says why).
    Refused,
}

impl DeliveryState {
    pub fn name(self) -> &'static str {
        match self {
            DeliveryState::Queued => "queued",
            DeliveryState::Accepted => "accepted",
            DeliveryState::Delivered => "delivered",
            DeliveryState::Read => "read",
            DeliveryState::Expired => "expired",
            DeliveryState::Refused => "refused",
        }
    }
}

/// Who wrote a message, as the hub's registry says (never as the message claims).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attribution {
    pub display: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub box_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
}

impl Attribution {
    pub fn of(p: &Participant) -> Attribution {
        Attribution {
            display: p.display.clone(),
            box_name: p.box_name.clone(),
            engine: p.engine.clone(),
            provider: p.provider.clone(),
        }
    }

    /// One line: `alpha on box-a (codex · openai)`.
    pub fn line(&self) -> String {
        let mut s = self.display.clone();
        if let Some(b) = &self.box_name {
            s.push_str(" on ");
            s.push_str(b);
        }
        let tech: Vec<&str> = [self.engine.as_deref(), self.provider.as_deref()]
            .into_iter()
            .flatten()
            .collect();
        if !tech.is_empty() {
            s.push_str(&format!(" ({})", tech.join(" · ")));
        }
        s
    }
}

/// One copy of a message, in one recipient's mailbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    pub id: String,
    pub thread: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
    pub from: Address,
    /// As addressed: a group or fleet stays the group here.
    pub to: Address,
    /// Whose mailbox this copy is in.
    pub recipient: Address,
    pub text: String,
    pub sent_ms: u64,
    /// The position in the recipient's mailbox, from 1: the cursor.
    pub seq: u64,
    pub attribution: Attribution,
    pub state: DeliveryState,
}

/// What a caller asks to send.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Post {
    pub to: Vec<Address>,
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostReceipt {
    pub id: String,
    pub thread: String,
    pub recipients: Vec<(Address, DeliveryState)>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Batch {
    pub messages: Vec<Message>,
    /// The cursor to pass as `after` next time.
    pub next: u64,
    pub more: bool,
}

/// A participant as a caller sees it: no members, no home.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParticipantView {
    pub address: Address,
    pub kind: ParticipantKind,
    pub display: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub box_name: Option<String>,
    #[serde(default)]
    pub projects: Vec<String>,
}

impl ParticipantView {
    pub fn of(p: &Participant) -> ParticipantView {
        ParticipantView {
            address: p.address.clone(),
            kind: p.address.kind(),
            display: p.display.clone(),
            engine: p.engine.clone(),
            provider: p.provider.clone(),
            box_name: p.box_name.clone(),
            projects: p.projects.clone(),
        }
    }
}

/// A fresh message id: 16 random hex digits.
pub fn new_id() -> String {
    let mut b = [0u8; 8];
    let _ = SystemRandom::new().fill(&mut b);
    crate::approval_subject::to_hex(&b)
}

/// A thread id or a message id as given by a caller.
pub fn id_ok(s: &str) -> bool {
    crate::channel::wire::word_ok(s)
}
