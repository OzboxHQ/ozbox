//! Chat is just another participant: the function a chat gateway calls to post a person's message into the fabric, and the one
//! that collects the replies for the person's linked chats (ADR 0050, ADR 0056).
//!
//! The gateway owns who a chat belongs to and how `@agent`, `@box`, `@group` and `@fleet` expand under the person's delegation; it
//! hands this module the person and the resolved addresses. This module adds nothing to what the person may do: the fabric's own
//! rule (a person reaches only their own participants) still applies, and a message posted from a chat is data like any other.
//! A reply comes back as a [`ChatReply`], with the agent named by the fabric's registry (never by its own words), which the
//! gateway renders through its notice model: `Notice::reply(text)` with `asked_by` = [`ChatReply::attribution`], `box_name`,
//! `project`, `reference` and `created_ms`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::addr::Address;
use super::model::{DeliveryState, Post, MAX_GET};
use super::policy::Reach;
use super::{FabricApi, FabricError};

/// The chats each person hears replies in.
pub const MAX_CHATS_PER_PERSON: usize = 16;

/// A person's message from a chat, after the gateway resolved who it is for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatInbound {
    pub person: String,
    /// `telegram`, `whatsapp`, `slack` or `dashboard`.
    pub channel: String,
    /// The gateway's own key for the conversation. Opaque here.
    pub chat_ref: String,
    pub targets: Vec<Address>,
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatPosted {
    pub id: String,
    pub thread: String,
    pub recipients: Vec<(Address, DeliveryState)>,
}

/// One reply for a person's chats, ready for the notice model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatReply {
    /// Every chat of the person that hears replies: `(channel, chat_ref)`.
    pub to_chats: Vec<(String, String)>,
    pub message_id: String,
    pub thread: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_reply_to: Option<String>,
    pub from: Address,
    /// `alpha on box-a (codex · openai)`, from the registry.
    pub attribution: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub box_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    pub text: String,
    /// A short id a person can quote: the first eight characters of the message id.
    pub reference: String,
    pub sent_ms: u64,
}

/// Which chats each person hears in. Plain data: the gateway keeps it with its own state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subscriptions {
    pub chats: BTreeMap<String, Vec<(String, String)>>,
}

fn channel_ok(c: &str) -> bool {
    matches!(c, "telegram" | "whatsapp" | "slack" | "dashboard")
}

pub fn subscribe(subs: &mut Subscriptions, person: &str, channel: &str, chat_ref: &str) {
    if !channel_ok(channel) || chat_ref.is_empty() || chat_ref.len() > 128 {
        return;
    }
    let v = subs.chats.entry(person.to_string()).or_default();
    let c = (channel.to_string(), chat_ref.to_string());
    if !v.contains(&c) {
        if v.len() >= MAX_CHATS_PER_PERSON {
            v.remove(0);
        }
        v.push(c);
    }
}

pub fn unsubscribe(subs: &mut Subscriptions, person: &str, channel: &str, chat_ref: &str) {
    if let Some(v) = subs.chats.get_mut(person) {
        v.retain(|(c, r)| !(c == channel && r == chat_ref));
    }
}

/// Post a person's chat message into the fabric, and subscribe the chat it came from to replies.
pub fn post_from_chat(
    f: &dyn FabricApi,
    subs: &mut Subscriptions,
    m: ChatInbound,
    now: u64,
) -> Result<ChatPosted, FabricError> {
    if !channel_ok(&m.channel) {
        return Err(FabricError::Invalid(
            "that chat channel is not known".into(),
        ));
    }
    let by = Reach::person(&m.person);
    let r = f.post(
        &by,
        Post {
            to: m.targets,
            text: m.text,
            thread: m.thread,
            reply_to: m.reply_to,
        },
        now,
    )?;
    subscribe(subs, &m.person, &m.channel, &m.chat_ref);
    Ok(ChatPosted {
        id: r.id,
        thread: r.thread,
        recipients: r.recipients,
    })
}

/// The replies in the person's mailbox after `after`, one per message, addressed to every chat the person hears in. What it
/// returns is acknowledged, so a reply is shown once. Returns the replies and the next cursor.
pub fn pull_replies(
    f: &dyn FabricApi,
    subs: &Subscriptions,
    person: &str,
    after: u64,
    now: u64,
) -> Result<(Vec<ChatReply>, u64), FabricError> {
    let by = Reach::person(person);
    let batch = f.get(&by, after, MAX_GET, 0, now)?;
    let chats = subs.chats.get(person).cloned().unwrap_or_default();
    // the registry names each sender's projects; one project is shown when it is unambiguous
    let views = f.participants(&by, now).unwrap_or_default();
    let project_of = |a: &Address| {
        views
            .iter()
            .find(|v| &v.address == a)
            .and_then(|v| (v.projects.len() == 1).then(|| v.projects[0].clone()))
    };
    let ids: Vec<String> = batch.messages.iter().map(|m| m.id.clone()).collect();
    let replies = batch
        .messages
        .into_iter()
        .map(|m| ChatReply {
            to_chats: chats.clone(),
            reference: m.id.chars().take(8).collect(),
            project: project_of(&m.from),
            message_id: m.id,
            thread: m.thread,
            in_reply_to: m.reply_to,
            attribution: m.attribution.line(),
            box_name: m.attribution.box_name.clone(),
            from: m.from,
            text: m.text,
            sent_ms: m.sent_ms,
        })
        .collect();
    if !ids.is_empty() {
        f.ack(&by, &ids, now)?;
    }
    Ok((replies, batch.next))
}
