//! Who sees whom. Built by the tool host (or the chat bridge) from the session, never from anything the caller says.
//!
//! An agent sees: itself; its person; the agents of the **same person** that share its box or one of its projects; the groups and
//! fleets of its person that list it as a member; and what its person delegated to it (a conductor's workers). A person sees every
//! participant that acts for them. Posting needs sight. Reading is one's own mailbox only. Nothing crosses from one person's
//! participants to another's, delegation included.

use serde::{Deserialize, Serialize};

use super::addr::{Address, Participant};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reach {
    pub me: Address,
    pub person: String,
    #[serde(default)]
    pub projects: Vec<String>,
    #[serde(default)]
    pub box_name: Option<String>,
    /// Participants the person put in this agent's reach beyond the rule (still the person's own).
    #[serde(default)]
    pub delegated: Vec<Address>,
}

impl Reach {
    /// A person, as the chat bridge and the dashboard act for them.
    pub fn person(id: &str) -> Reach {
        Reach {
            me: Address::person(id),
            person: id.into(),
            projects: Vec::new(),
            box_name: None,
            delegated: Vec::new(),
        }
    }

    /// The reach a registered agent has: what its record says, nothing more.
    pub fn of(p: &Participant) -> Reach {
        Reach {
            me: p.address.clone(),
            person: p.person.clone(),
            projects: p.projects.clone(),
            box_name: p.box_name.clone(),
            delegated: Vec::new(),
        }
    }

    /// Whether this caller may see (and so write to) `p`.
    pub fn sees(&self, p: &Participant) -> bool {
        if p.person != self.person {
            return false;
        }
        if p.address == self.me || self.delegated.contains(&p.address) {
            return true;
        }
        match &self.me {
            Address::Person { .. } => true,
            Address::Agent { .. } => match &p.address {
                Address::Person { id } => *id == self.person,
                Address::Agent { .. } => {
                    (self.box_name.is_some() && p.box_name == self.box_name)
                        || p.projects.iter().any(|x| self.projects.contains(x))
                }
                Address::Group { .. } | Address::Fleet { .. } => p.members.contains(&self.me),
            },
            // a group never acts
            Address::Group { .. } | Address::Fleet { .. } => false,
        }
    }

    /// Whether this caller may read a memory wall (`person:`, `project:`, `box:`): the rule of `ozbox_memory`'s agent caller.
    pub fn reads_wall(&self, scope: &str) -> bool {
        match scope.split_once(':') {
            Some(("person", n)) => n == self.person,
            Some(("project", n)) => self.projects.iter().any(|p| p == n),
            Some(("box", n)) => self.box_name.as_deref() == Some(n),
            _ => false,
        }
    }

    /// The walls this caller reads.
    pub fn walls(&self) -> Vec<String> {
        let mut v = vec![format!("person:{}", self.person)];
        if let Some(b) = &self.box_name {
            v.push(format!("box:{b}"));
        }
        v.extend(self.projects.iter().map(|p| format!("project:{p}")));
        v
    }
}
