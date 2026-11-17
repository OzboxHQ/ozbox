//! One model for every message Oz Box sends to a person, and one design for how it reads on every channel.
//!
//! A [`Notice`] says, in this order: **what** (a title that starts with the verb a person must act on), **what is asked**
//! in plain words, **where** (box, project, environment, with a Production badge), **who or what asked and why**, the
//! **risk**, **when it expires**, the **primary action** (one link to exactly that item in the dashboard) and a short,
//! stable **reference**. It follows the shape mature systems use for actionable notifications (a verb-led title, the
//! context as a few labelled facts, one primary action as a link button, a reference id), rendered with each channel's
//! own conventions and escaping by [`render`].
//!
//! The link is resolved per recipient at the moment of sending ([`Notice::action_for`]): a one-time pointer link for a
//! person (24 random bytes, a keyed hash held, ten minutes, that person only; see `chat::links`), the item's plain
//! address for a shared place (a channel, a list, a webhook) where no one person is the recipient, or words that name the
//! page when the dashboard has no public address. **Nothing in a notice decides anything**: a button only opens the
//! dashboard, which asks for a passkey there.
//!
//! What a notice never carries: a secret, a token other than its own one-time link, a value, or long agent output. Every
//! text field is cleaned and bounded when it is rendered ([`clean`]), and the resolved link is never serialised.

use serde::{Deserialize, Serialize};

use crate::messages::t;

pub mod render;
#[cfg(test)]
mod tests;

/// How long a one-time link lasts, in minutes (the same number as `chat::links::TTL_MS`).
pub const LINK_MINUTES: u64 = crate::chat::links::TTL_MS / 60_000;

/// The longest the plain-words summary may be: long agent output stays in the dashboard.
pub const SUMMARY_MAX: usize = 400;
/// The longest any one fact's value may be.
pub const VALUE_MAX: usize = 160;
/// The most request details a notice lists; the rest is counted.
pub const DETAILS_MAX: usize = 6;

/// What a notice is about. Additive: a new kind is a new variant.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoticeKind {
    /// An ADR 0041 change request (guard override, import, policy, tunnel token...) waiting for a person.
    ApprovalRequest,
    /// A coding agent stopped to ask before a step.
    AgentAsks,
    /// Something about a box, a schedule or the fleet.
    #[default]
    Alert,
    /// The monthly budget.
    Budget,
    /// The daily summary.
    Digest,
    /// A test from Settings.
    Test,
    /// A conversational reply in a chat (an agent's answer, a command's result). Rendered as plain text.
    Reply,
}

/// One labelled fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fact {
    pub label: String,
    pub value: String,
}

/// What to open in the dashboard: a path the server chose (never text from an agent or a filer) and the page's name in
/// words, for when no link can be made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Open {
    pub path: String,
    pub place: String,
}

/// The primary action, resolved for one recipient. Never serialised: a one-time link exists only in the message sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// A pointer link made for this person: `https://<host>/go#<token>`.
    OneTime { url: String, host: String },
    /// The item's own address, for a shared place: the dashboard asks the reader to sign in.
    Page { url: String, host: String },
    /// No public address is known: the page, named in words.
    Words,
}

impl Action {
    pub fn url(&self) -> Option<&str> {
        match self {
            Action::OneTime { url, .. } | Action::Page { url, .. } => Some(url),
            Action::Words => None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Notice {
    pub kind: NoticeKind,
    pub urgent: bool,
    /// Starts with the verb: "Approve or deny: skip the pre-commit guard".
    pub title: String,
    /// What is asked, in plain words.
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub box_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    pub production: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asked_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    /// The request's own details (label and value), at most [`DETAILS_MAX`] shown.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub details: Vec<Fact>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_ms: Option<u64>,
    pub created_ms: u64,
    /// A short, stable id a person can quote: the same in every channel and on the dashboard card.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    /// Say that the message only tells and decides nothing (every approval).
    pub only_tells: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open: Option<Open>,
    /// The action resolved for the recipient this copy is for.
    #[serde(skip)]
    pub action: Option<Action>,
    /// The message this one answers, in the channel's own terms (a Telegram message id, a Slack `ts`): a reply to a message
    /// sent to several boxes is threaded under it. Delivery routing, not content.
    #[serde(skip)]
    pub thread: Option<String>,
}

impl Notice {
    pub fn new(kind: NoticeKind, title: impl Into<String>, summary: impl Into<String>) -> Self {
        Notice {
            kind,
            title: title.into(),
            summary: summary.into(),
            ..Default::default()
        }
    }

    /// A chat reply: words only, sent as plain text.
    pub fn reply(text: impl Into<String>) -> Self {
        Notice::new(NoticeKind::Reply, String::new(), text)
    }

    /// Thread this message under the one it answers.
    pub fn in_thread(mut self, thread: Option<String>) -> Self {
        self.thread = thread;
        self
    }

    /// The dashboard page to open.
    pub fn opens(mut self, path: impl Into<String>, place: impl Into<String>) -> Self {
        self.open = Some(Open {
            path: path.into(),
            place: place.into(),
        });
        self
    }

    /// This copy, with its action resolved for one recipient (see [`Notice::action_for`]).
    pub fn with_action(&self, action: Option<Action>) -> Notice {
        let mut n = self.clone();
        n.action = action;
        n
    }

    /// The action for one recipient: a one-time link when a token was made for them, the item's address when there is a
    /// public address but no one person, words when there is no public address. `None` when there is nothing to open.
    pub fn action_for(&self, base: Option<&str>, token: Option<&str>) -> Option<Action> {
        let open = self.open.as_ref()?;
        let Some(base) = base
            .map(|b| b.trim().trim_end_matches('/'))
            .filter(|b| !b.is_empty())
        else {
            return Some(Action::Words);
        };
        let host = host_of(base);
        Some(match token {
            Some(tok) => Action::OneTime {
                url: format!("{base}/go#{tok}"),
                host,
            },
            None => Action::Page {
                url: format!("{base}{}", open.path),
                host,
            },
        })
    }

    /// The page's name in words, for the sentences that name it.
    pub fn place(&self) -> String {
        self.open
            .as_ref()
            .map_or_else(|| t("notice.place_activity", &[]), |o| o.place.clone())
    }
}

/// The host of an `https://host/...` base, for "open it on <host>" (a lookalike host is then recognisable).
pub fn host_of(base: &str) -> String {
    base.split("://")
        .nth(1)
        .unwrap_or(base)
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .to_string()
}

/// A short reference for an id: what a person quotes, the same in every channel.
pub fn reference(id: &str) -> String {
    let clean: String = id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(12)
        .collect();
    clean
}

/// An id as a path segment: only the characters an id is made of pass, so a path is never built from anything else.
pub fn path_id(id: &str) -> String {
    id.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(128)
        .collect()
}

/// Any text leaving in a notice: key-shaped words removed, control characters taken out, and at most `max` characters.
pub fn clean(text: &str, max: usize) -> String {
    let s = crate::chat::text::outgoing(text, &[], usize::MAX);
    let one: String = s
        .chars()
        .map(|c| if c == '\n' || c == '\t' { ' ' } else { c })
        .collect();
    let one = one.split_whitespace().collect::<Vec<_>>().join(" ");
    crate::channels::clip(&one, max)
}

/// A span of time in words: "5 min", "2 h 5 min", "3 d".
pub fn span(ms: u64) -> String {
    let min = ms / 60_000;
    if min == 0 {
        t("notice.span_now", &[])
    } else if min < 60 {
        t("notice.span_min", &[("n", &min.to_string())])
    } else if min < 48 * 60 {
        t(
            "notice.span_hours",
            &[
                ("h", &(min / 60).to_string()),
                ("m", &(min % 60).to_string()),
            ],
        )
    } else {
        t("notice.span_days", &[("n", &(min / (24 * 60)).to_string())])
    }
}
