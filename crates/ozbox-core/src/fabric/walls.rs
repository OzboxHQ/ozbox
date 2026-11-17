//! Memory walls and reviewed skills as the fabric carries them to a worker (ADR 0024, 0025, 0056).
//!
//! The hub's memory and skills stores stay the authority. The hub sends a worker only **approved** notes and **approved** skills,
//! and only of the walls that worker's own agents may read (`person:` of their person, `box:` of that box, `project:` of their
//! projects). A worker keeps them as a replica and reads them with the same rule an agent caller has on the hub, so the scoping is
//! unchanged. An agent on a worker only proposes: the proposal travels to the hub and waits there for a person, as on the hub.

use std::collections::BTreeMap;

use ring::digest::{digest, SHA256};
use serde::{Deserialize, Serialize};

use super::addr::Address;
use super::policy::Reach;
use super::FabricError;

/// The most notes, and skills, one wall carries to a worker.
pub const MAX_NOTES_PER_WALL: usize = 200;
pub const MAX_SKILLS_PER_WALL: usize = 50;
/// The longest `SKILL.md` carried.
pub const MAX_SKILL_TEXT: usize = 32 * 1024;

/// An approved note, with who wrote it, on which box, and who reviewed it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedNote {
    pub id: String,
    pub scope: String,
    pub title: String,
    pub body: String,
    #[serde(default)]
    pub tags: Vec<String>,
    pub written_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub written_box: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewed_ms: Option<u64>,
    pub revision: u32,
    pub updated_ms: u64,
}

/// An approved skill installed on a wall: its approved hash, and its `SKILL.md` with that text's own digest, which the worker checks
/// before it serves the text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedSkill {
    pub scope: String,
    pub name: String,
    pub description: String,
    pub version: String,
    pub hash: String,
    pub text: String,
    pub text_sha256: String,
}

impl SharedSkill {
    pub fn text_digest(text: &str) -> String {
        crate::approval_subject::to_hex(digest(&SHA256, text.as_bytes()).as_ref())
    }

    pub fn intact(&self) -> bool {
        Self::text_digest(&self.text) == self.text_sha256
    }
}

/// A note an agent proposes, as the tool takes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewProposal {
    pub scope: String,
    pub title: String,
    pub body: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_ms: Option<u64>,
}

/// A proposal on its way to the hub: who proposed it and from which box (the hub fills both from the channel and the registry).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proposal {
    pub id: String,
    pub by: Address,
    pub person: String,
    pub from_box: String,
    pub note: NewProposal,
}

/// What the hub's memory and skills look like to the fabric. Implemented over `ozbox_memory` by that crate; a fake in tests.
pub trait WallSource: Send + Sync {
    /// The approved, unexpired notes of one wall.
    fn approved(&self, scope: &str, now: u64) -> Vec<SharedNote>;
    /// The approved skills installed on one wall (`box:` or `project:`).
    fn skills(&self, scope: &str) -> Vec<SharedSkill>;
    /// File a proposal as PENDING for a person to review; returns its id.
    fn propose(&self, p: &Proposal, now: u64) -> Result<String, FabricError>;
}

/// One wall as carried: its notes and its skills.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Wall {
    pub notes: Vec<SharedNote>,
    pub skills: Vec<SharedSkill>,
}

impl Wall {
    pub fn digest(&self) -> String {
        let bytes = serde_json::to_vec(self).unwrap_or_default();
        crate::approval_subject::to_hex(digest(&SHA256, &bytes).as_ref())
    }

    /// Bounded, and only what a wall of that name may hold.
    pub fn bounded(mut self, scope: &str) -> Wall {
        self.notes.retain(|n| n.scope == scope);
        self.notes.truncate(MAX_NOTES_PER_WALL);
        self.skills
            .retain(|s| s.scope == scope && s.text.len() <= MAX_SKILL_TEXT && s.intact());
        self.skills.truncate(MAX_SKILLS_PER_WALL);
        self
    }
}

/// The replica a worker holds: walls by scope.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Walls {
    pub walls: BTreeMap<String, Wall>,
}

impl Walls {
    fn readable<'a>(&'a self, r: &'a Reach) -> impl Iterator<Item = &'a Wall> + 'a {
        self.walls
            .iter()
            .filter(|(s, _)| r.reads_wall(s))
            .map(|(_, w)| w)
    }

    /// Notes the caller may read whose title, body or tags contain every word of the query (all of them for an empty query).
    pub fn search(&self, r: &Reach, query: &str, limit: usize) -> Vec<SharedNote> {
        let words: Vec<String> = query.split_whitespace().map(str::to_lowercase).collect();
        let mut out: Vec<SharedNote> = self
            .readable(r)
            .flat_map(|w| w.notes.iter())
            .filter(|n| {
                let hay = format!("{} {} {}", n.title, n.body, n.tags.join(" ")).to_lowercase();
                words.iter().all(|w| hay.contains(w))
            })
            .cloned()
            .collect();
        out.sort_by_key(|n| std::cmp::Reverse(n.updated_ms));
        out.truncate(limit);
        out
    }

    pub fn note(&self, r: &Reach, id: &str) -> Option<SharedNote> {
        self.readable(r)
            .flat_map(|w| w.notes.iter())
            .find(|n| n.id == id)
            .cloned()
    }

    /// The skills the caller may use, one per name (a box's own first, then its projects').
    pub fn skills(&self, r: &Reach) -> Vec<SharedSkill> {
        let mut seen = std::collections::BTreeSet::new();
        let mut order = Vec::new();
        if let Some(b) = &r.box_name {
            order.push(format!("box:{b}"));
        }
        order.extend(r.projects.iter().map(|p| format!("project:{p}")));
        let mut out = Vec::new();
        for s in order {
            for k in self
                .walls
                .get(&s)
                .map(|w| w.skills.as_slice())
                .unwrap_or(&[])
            {
                if k.intact() && seen.insert(k.name.clone()) {
                    out.push(k.clone());
                }
            }
        }
        out
    }
}
