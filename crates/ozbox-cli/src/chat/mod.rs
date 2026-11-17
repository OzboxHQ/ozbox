//! The chat gateway: talking to coding agents from Telegram, Slack, WhatsApp and the dashboard.
//!
//! One conversation model for every channel. A chat is bound to one thing at a time: a supervised session (a run of a
//! coding agent that stays open between messages, on the board like any run) or a live terminal session
//! (experimental). The pieces:
//!
//! * [`command`]: what a message means, the same in every channel.
//! * [`gateway`]: the state (who is linked, what each chat is bound to) and the pure rules for what a command does.
//! * [`text`]: everything that leaves for a chat (secrets removed, shortened, spaced) and the per-person rate limit.
//! * [`links`]: one-time, expiring links from a chat to the dashboard for approvals that need a passkey.
//! * [`ws`] and [`slack`]: Slack's Socket Mode over an outbound websocket (no inbound endpoint).
//! * [`whatsapp`]: WhatsApp Cloud API messages through the signed webhook, with the 24-hour window.
//! * [`remote`]: the delivery of a message to an agent on a worker box of a hub (interface built; the mesh adapter is Planned).
//!
//! Only linked people are heard. Text a person writes is their instruction; a forwarded or quoted message and anything an
//! agent printed is data and is never acted on.

use serde::{Deserialize, Serialize};

/// Which chat channels beyond Telegram and the dashboard are switched on. The keys and tokens they need are in the secret
/// store, never here.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ChatConfig {
    pub slack: bool,
    pub whatsapp: bool,
}

pub mod code;
pub mod command;
pub mod gateway;
pub mod links;
pub mod mesh_agents;
pub mod remote;
pub mod slack;
pub mod text;
pub mod whatsapp;
pub mod ws;
