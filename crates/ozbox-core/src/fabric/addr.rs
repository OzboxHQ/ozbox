//! Who can be written to: a stable address and the participant record behind it.
//!
//! | Address | Means |
//! |---|---|
//! | `agent:<box>/<session>` | one agent session on one box, whatever its engine and provider |
//! | `person:<id>` | a person, reached through any chat they linked or the dashboard |
//! | `group:<name>` | a named set of participants, listed explicitly |
//! | `fleet:<name>` | the agents on a person's boxes, listed explicitly |
//!
//! An address names a target, never authority: whether the caller may write to it is [`crate::fabric::policy`]'s question.

use serde::{Deserialize, Serialize};

use super::FabricError;
use crate::agent_mesh::printable_line;

/// The most members a group or fleet lists.
pub const MAX_MEMBERS: usize = 50;
/// The longest display name, engine or provider kept.
const MAX_ATTR: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum Address {
    Agent { box_name: String, session: String },
    Person { id: String },
    Group { name: String },
    Fleet { name: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ParticipantKind {
    Agent,
    Person,
    Group,
    Fleet,
}

impl ParticipantKind {
    pub fn name(self) -> &'static str {
        match self {
            ParticipantKind::Agent => "agent",
            ParticipantKind::Person => "person",
            ParticipantKind::Group => "group",
            ParticipantKind::Fleet => "fleet",
        }
    }
}

/// A box name: what [`crate::BoxName`] accepts (lower case, digits and dashes, starting with a letter).
pub fn box_ok(s: &str) -> bool {
    crate::BoxName::new(s).is_ok()
}

/// A session as the chat gateway and the tool host name them: a task id, a run id, `t-<code>`, or a terminal (`%3`, `main:%3`).
pub fn session_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'%' | b':'))
}

/// A person id, a group or a fleet name: the memory scope grammar (letters, digits, dot, dash, underscore, 1 to 64).
pub fn name_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

impl Address {
    pub fn agent(box_name: &str, session: &str) -> Address {
        Address::Agent {
            box_name: box_name.into(),
            session: session.into(),
        }
    }

    pub fn person(id: &str) -> Address {
        Address::Person { id: id.into() }
    }

    /// Strict: the text form and nothing else.
    pub fn parse(s: &str) -> Option<Address> {
        let (kind, rest) = s.trim().split_once(':')?;
        match kind {
            "agent" => {
                let (b, sess) = rest.split_once('/')?;
                (box_ok(b) && session_ok(sess)).then(|| Address::agent(b, sess))
            }
            "person" => name_ok(rest).then(|| Address::person(rest)),
            "group" => name_ok(rest).then(|| Address::Group { name: rest.into() }),
            "fleet" => name_ok(rest).then(|| Address::Fleet { name: rest.into() }),
            _ => None,
        }
    }

    pub fn kind(&self) -> ParticipantKind {
        match self {
            Address::Agent { .. } => ParticipantKind::Agent,
            Address::Person { .. } => ParticipantKind::Person,
            Address::Group { .. } => ParticipantKind::Group,
            Address::Fleet { .. } => ParticipantKind::Fleet,
        }
    }

    /// A group or a fleet: an address that fans out to its members.
    pub fn is_many(&self) -> bool {
        matches!(self, Address::Group { .. } | Address::Fleet { .. })
    }

    /// The box an agent lives on.
    pub fn box_name(&self) -> Option<&str> {
        match self {
            Address::Agent { box_name, .. } => Some(box_name),
            _ => None,
        }
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Address::Agent { box_name, session } => write!(f, "agent:{box_name}/{session}"),
            Address::Person { id } => write!(f, "person:{id}"),
            Address::Group { name } => write!(f, "group:{name}"),
            Address::Fleet { name } => write!(f, "fleet:{name}"),
        }
    }
}

impl TryFrom<String> for Address {
    type Error = String;
    fn try_from(s: String) -> Result<Self, String> {
        Address::parse(&s).ok_or_else(|| "not a fabric address".to_string())
    }
}

impl From<Address> for String {
    fn from(a: Address) -> String {
        a.to_string()
    }
}

/// One participant. Registered by the box it is homed on (an agent) or by the hub (a person, a group, a fleet).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Participant {
    pub address: Address,
    /// The person it acts for (a person: itself). The wall nothing crosses.
    pub person: String,
    #[serde(default)]
    pub display: String,
    /// An agent's engine (`claude-code`, `codex`, `gemini`, `opencode`) and model provider: attributes, never the address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default)]
    pub projects: Vec<String>,
    /// The box an agent runs on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub box_name: Option<String>,
    /// A group's or fleet's members (agents or people; never another group).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<Address>,
    /// The box whose fabric holds this participant's mailbox replica (the hub's own name for people, groups and fleets).
    pub home: String,
}

fn clean_attr(s: &str) -> String {
    printable_line(s).trim().chars().take(MAX_ATTR).collect()
}

impl Participant {
    /// An agent on `box_name`, homed there.
    pub fn agent(box_name: &str, session: &str, person: &str) -> Participant {
        Participant {
            address: Address::agent(box_name, session),
            person: person.into(),
            display: session.into(),
            engine: None,
            provider: None,
            projects: Vec::new(),
            box_name: Some(box_name.into()),
            members: Vec::new(),
            home: box_name.into(),
        }
    }

    pub fn person(id: &str, hub: &str) -> Participant {
        Participant {
            address: Address::person(id),
            person: id.into(),
            display: id.into(),
            engine: None,
            provider: None,
            projects: Vec::new(),
            box_name: None,
            members: Vec::new(),
            home: hub.into(),
        }
    }

    /// The record checked and cleaned: what is stored is this, never what was sent.
    pub fn checked(mut self) -> Result<Participant, FabricError> {
        let bad = |m: &str| Err(FabricError::Invalid(m.into()));
        if !name_ok(&self.person) || !box_ok(&self.home) {
            return bad("a participant needs a person and a home box");
        }
        match &self.address {
            Address::Agent { box_name, .. } => {
                if self.box_name.as_deref() != Some(box_name.as_str()) || self.home != *box_name {
                    return bad("an agent is homed on the box it runs on");
                }
                if !self.members.is_empty() {
                    return bad("an agent has no members");
                }
            }
            Address::Person { id } => {
                if *id != self.person || !self.members.is_empty() || self.box_name.is_some() {
                    return bad("a person is its own person and has no members or box");
                }
            }
            Address::Group { .. } | Address::Fleet { .. } => {
                if self.members.len() > MAX_MEMBERS {
                    return Err(FabricError::Limit(format!(
                        "a group lists at most {MAX_MEMBERS} members"
                    )));
                }
                if self.members.iter().any(Address::is_many) {
                    return bad("a group's members are agents or people, never another group");
                }
                if self.box_name.is_some() {
                    return bad("a group has no box");
                }
            }
        }
        if self.projects.len() > 16 || self.projects.iter().any(|p| !name_ok(p)) {
            return bad("projects are names (letters, digits, dot, dash, underscore), at most 16");
        }
        self.display = clean_attr(&self.display);
        if self.display.is_empty() {
            self.display = match &self.address {
                Address::Agent { session, .. } => session.clone(),
                Address::Person { id } => id.clone(),
                Address::Group { name } | Address::Fleet { name } => name.clone(),
            };
        }
        self.engine = self
            .engine
            .as_deref()
            .map(clean_attr)
            .filter(|s| !s.is_empty());
        self.provider = self
            .provider
            .as_deref()
            .map(clean_attr)
            .filter(|s| !s.is_empty());
        self.members.sort();
        self.members.dedup();
        self.projects.sort();
        self.projects.dedup();
        Ok(self)
    }
}
