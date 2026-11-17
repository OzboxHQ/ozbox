//! The fabric's profile of the shared channel ([`crate::channel`]) and the frames it carries between a worker and the hub.
//!
//! A profile of its own: its domain tag means a fabric envelope never verifies as a worker-channel or mesh one, and the reverse,
//! and its closed list of kinds has nothing that approves, delivers a key or sets a pin. The worker channel's kinds and golden
//! vectors are untouched. The envelope, sealing, signing, order, replay and acknowledgement are the channel's.
//!
//! The fabric rides the hub's [`crate::hub::wire::Transport`] under endpoint names of its own: `<box>.fabric`. A box name never
//! has a dot, so these never collide with the worker channel's `<box>`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::addr::{Address, Participant};
use super::model::{DeliveryState, Message, Post};
use super::walls::{Proposal, Wall};
use crate::channel::wire::Profile;

pub const ENVELOPE_TAG: &str = "ozbox-fabric-envelope-v1";
/// Every fabric frame signs this as its `ext`.
pub const EXT: &[u8] = b"fabric-v1";
pub const MAX_BODY: usize = 256 * 1024;

pub const K_REGISTER: &str = "fabric.register";
pub const K_POST: &str = "fabric.post";
pub const K_DELIVER: &str = "fabric.deliver";
pub const K_READ: &str = "fabric.read";
pub const K_STATE: &str = "fabric.state";
pub const K_DIRECTORY: &str = "fabric.directory";
pub const K_WALLS: &str = "fabric.walls";
pub const K_PROPOSE: &str = "fabric.propose";

/// The kinds a worker sends; the rest only the hub sends.
pub const TO_HUB: [&str; 4] = [K_REGISTER, K_POST, K_READ, K_PROPOSE];

pub static PROFILE: Profile = Profile {
    tag: ENVELOPE_TAG,
    audit: "fabric",
    kinds: &[
        K_REGISTER,
        K_POST,
        K_DELIVER,
        K_READ,
        K_STATE,
        K_DIRECTORY,
        K_WALLS,
        K_PROPOSE,
    ],
    max_body: MAX_BODY,
    check_ext: |_, ext| ext == EXT,
};

/// A box's fabric endpoint on the transport.
pub fn endpoint(box_name: &str) -> String {
    format!("{box_name}.fabric")
}

/// The box an endpoint names, when it is one.
pub fn box_of(endpoint: &str) -> Option<&str> {
    endpoint
        .strip_suffix(".fabric")
        .filter(|b| super::addr::box_ok(b))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Register {
    pub participants: Vec<Participant>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostFrame {
    pub id: String,
    pub by: Address,
    pub post: Post,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deliver {
    pub messages: Vec<Message>,
}

/// A worker's receipts: copies its agents fetched, and copies they acknowledged.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Read {
    pub delivered: Vec<(Address, String)>,
    pub read: Vec<(Address, String)>,
}

/// What changed about messages the worker's agents sent: each recipient's state, or the hub's refusal.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateFrame {
    pub states: Vec<(String, BTreeMap<Address, DeliveryState>)>,
    pub refused: Vec<(String, String)>,
}

/// The participants the worker's agents may see.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Directory {
    pub participants: Vec<Participant>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WallFrame {
    pub scope: String,
    pub wall: Wall,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposeFrame {
    pub proposal: Proposal,
}
