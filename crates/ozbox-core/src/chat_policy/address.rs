//! Who a chat message is for (ADR 0050, "End-to-end path"): one address grammar for every chat app and the dashboard, the
//! expansion of an address into the boxes a person may reach, and the delivery state of each target.
//!
//! | Address | Means |
//! |---|---|
//! | `@<box>/<session>` | one session on one box |
//! | `@<box>` | the box's agent: the session this chat follows there, or a new one |
//! | `@<group>` | every box in a named group of boxes (fan-out) |
//! | `@fleet` | every box the person may reach (fan-out) |
//!
//! A name is a box first; a group may not share a box's name (the dashboard refuses that), and `fleet` is reserved. An
//! address names targets, never authority: each target is still put to `decide` with that box's own facts, and a fan-out
//! reaches only the boxes the person's delegation covers, saying how many were left out and why.
//!
//! Pure: no clock, store or network.

use std::collections::BTreeMap;

use super::acts::box_name_ok;

/// The most boxes one message fans out to.
pub const MAX_FANOUT: usize = 20;
/// The reserved name for every box the person may reach.
pub const FLEET: &str = "fleet";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Address {
    Session {
        box_name: String,
        session: String,
    },
    /// A box or a group: which one is settled by [`expand`].
    Name(String),
    Fleet,
}

impl Address {
    /// Parse `@box`, `@box/session`, `@group` or `@fleet` (the `@` is optional).
    pub fn parse(s: &str) -> Option<Address> {
        let s = s.strip_prefix('@').unwrap_or(s);
        if s.eq_ignore_ascii_case(FLEET) {
            return Some(Address::Fleet);
        }
        match s.split_once('/') {
            Some((b, sess)) => (box_name_ok(b) && session_ok(sess)).then(|| Address::Session {
                box_name: b.to_string(),
                session: sess.to_string(),
            }),
            None => box_name_ok(s).then(|| Address::Name(s.to_string())),
        }
    }

    /// The address as a person writes it.
    pub fn render(&self) -> String {
        match self {
            Address::Session { box_name, session } => format!("@{box_name}/{session}"),
            Address::Name(n) => format!("@{n}"),
            Address::Fleet => format!("@{FLEET}"),
        }
    }

    pub fn fans_out(&self, groups: &BTreeMap<String, Vec<String>>, boxes: &[BoxReach]) -> bool {
        match self {
            Address::Fleet => true,
            Address::Name(n) => !boxes.iter().any(|b| &b.name == n) && groups.contains_key(n),
            Address::Session { .. } => false,
        }
    }
}

/// A session id as the gateway names them: a task id (`t1a2b`) or a terminal (`%3`, `main:%3`).
fn session_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'%' | b':' | b'.'))
}

/// What the fleet record and the person's delegations say about one box, read just now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoxReach {
    pub name: String,
    pub production: bool,
    /// The person holds a live converse delegation that names this box.
    pub delegated: bool,
    /// The box is running and its agent answered; `false` is an honest "unreachable", never silence.
    pub online: bool,
    /// Reached over the hub's channel rather than this dashboard's own agent (a worker box of a hub).
    pub remote: bool,
}

/// Why a box an address named is not a target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Skip {
    /// Production boxes are never reached from chat.
    Production,
    /// The person's delegation does not name it.
    NotDelegated,
    /// No such box in this fleet.
    Unknown,
    /// More than [`MAX_FANOUT`] boxes.
    TooMany,
}

impl Skip {
    pub const fn code(self) -> &'static str {
        match self {
            Skip::Production => "production",
            Skip::NotDelegated => "not_delegated",
            Skip::Unknown => "unknown",
            Skip::TooMany => "too_many",
        }
    }
}

/// One box (and, for a session address, one session) a message goes to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub box_name: String,
    pub session: Option<String>,
    pub online: bool,
    pub remote: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Expansion {
    pub targets: Vec<Target>,
    pub skipped: Vec<(String, Skip)>,
    pub fanout: bool,
}

/// The boxes an address reaches for this person. `boxes` is every box the dashboard knows, `groups` the named groups.
pub fn expand(
    addr: &Address,
    boxes: &[BoxReach],
    groups: &BTreeMap<String, Vec<String>>,
) -> Expansion {
    let find = |n: &str| boxes.iter().find(|b| b.name == n);
    let (names, session, fanout): (Vec<String>, Option<String>, bool) = match addr {
        Address::Session { box_name, session } => {
            (vec![box_name.clone()], Some(session.clone()), false)
        }
        Address::Name(n) if find(n).is_some() => (vec![n.clone()], None, false),
        Address::Name(n) => match groups.get(n) {
            Some(g) => (g.clone(), None, true),
            None => (vec![n.clone()], None, false),
        },
        Address::Fleet => (boxes.iter().map(|b| b.name.clone()).collect(), None, true),
    };
    let mut names = names;
    names.sort();
    names.dedup();
    let mut e = Expansion {
        fanout,
        ..Expansion::default()
    };
    for n in names {
        let Some(b) = find(&n) else {
            e.skipped.push((n, Skip::Unknown));
            continue;
        };
        if b.production {
            e.skipped.push((n, Skip::Production));
        } else if !b.delegated {
            e.skipped.push((n, Skip::NotDelegated));
        } else if e.targets.len() >= MAX_FANOUT {
            e.skipped.push((n, Skip::TooMany));
        } else {
            e.targets.push(Target {
                box_name: n,
                session: session.clone(),
                online: b.online,
                remote: b.remote,
            });
        }
    }
    e
}

/// The conversation fabric's address for one expanded target (the hub contract's mapping): a session is
/// `agent:<box>/<session>`; a box with no session yet has no fabric address (the gateway resolves it to a session first).
pub fn fabric_target(t: &Target) -> Option<String> {
    t.session
        .as_ref()
        .map(|s| format!("agent:{}/{}", t.box_name, s))
}

/// The fabric's address for a whole address, when it names a group or the fleet: `group:<name>`, `fleet:<person>`.
pub fn fabric_group(
    a: &Address,
    person: &str,
    groups: &BTreeMap<String, Vec<String>>,
) -> Option<String> {
    match a {
        Address::Fleet => Some(format!("fleet:{person}")),
        Address::Name(n) if groups.contains_key(n) => Some(format!("group:{n}")),
        _ => None,
    }
}

/// The boxes a person may see in `/boxes`: every non-Production box the delegation names. A Production box is listed as
/// metadata by `/fleet`, never here.
pub fn reachable(boxes: &[BoxReach]) -> Vec<&BoxReach> {
    boxes
        .iter()
        .filter(|b| !b.production && b.delegated)
        .collect()
}

/// The groups a person may use in `/fleets`, with how many of their boxes the person may reach.
pub fn reachable_groups<'a>(
    boxes: &[BoxReach],
    groups: &'a BTreeMap<String, Vec<String>>,
) -> Vec<(&'a str, usize, usize)> {
    groups
        .iter()
        .map(|(g, members)| {
            let reach = members
                .iter()
                .filter(|m| {
                    boxes
                        .iter()
                        .any(|b| &&b.name == m && !b.production && b.delegated)
                })
                .count();
            (g.as_str(), reach, members.len())
        })
        .filter(|(_, reach, _)| *reach > 0)
        .collect()
}

/// Where one target's copy of a message stands. Reported back in the chat, compactly.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DeliveryState {
    /// Accepted by the gateway, not yet handed to the box.
    Queued,
    /// The box's agent took it (a session was started or the line was typed).
    Delivered,
    /// The agent began a turn on it.
    PickedUp,
    /// The agent answered.
    Replied,
    /// The box could not be reached: why, as a code.
    Unreachable(&'static str),
    /// The box refused it or it failed: why, as a code.
    Failed(&'static str),
}

impl DeliveryState {
    pub const fn code(&self) -> &'static str {
        match self {
            DeliveryState::Queued => "queued",
            DeliveryState::Delivered => "delivered",
            DeliveryState::PickedUp => "picked_up",
            DeliveryState::Replied => "replied",
            DeliveryState::Unreachable(_) => "unreachable",
            DeliveryState::Failed(_) => "failed",
        }
    }

    pub const fn is_final(&self) -> bool {
        matches!(
            self,
            DeliveryState::Replied | DeliveryState::Unreachable(_) | DeliveryState::Failed(_)
        )
    }

    /// The order a state may only move forward in.
    const fn rank(&self) -> u8 {
        match self {
            DeliveryState::Queued => 0,
            DeliveryState::Delivered => 1,
            DeliveryState::PickedUp => 2,
            _ => 3,
        }
    }
}

/// One target of one message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetDelivery {
    pub box_name: String,
    /// The session the copy went to, once it is known.
    pub session: Option<String>,
    pub state: DeliveryState,
}

/// One message to one or more targets, with an id the chat and the audit chain both use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivery {
    pub msg_id: String,
    pub address: Address,
    pub targets: Vec<TargetDelivery>,
    pub skipped: Vec<(String, Skip)>,
}

impl Delivery {
    pub fn new(msg_id: &str, address: Address, e: &Expansion) -> Delivery {
        Delivery {
            msg_id: msg_id.to_string(),
            address,
            targets: e
                .targets
                .iter()
                .map(|t| TargetDelivery {
                    box_name: t.box_name.clone(),
                    session: t.session.clone(),
                    state: DeliveryState::Queued,
                })
                .collect(),
            skipped: e.skipped.clone(),
        }
    }

    /// Move one target forward. A state never moves back, and a final state never changes.
    pub fn advance(&mut self, box_name: &str, state: DeliveryState) -> bool {
        let Some(t) = self.targets.iter_mut().find(|t| t.box_name == box_name) else {
            return false;
        };
        if t.state.is_final() || state.rank() < t.state.rank() {
            return false;
        }
        t.state = state;
        true
    }

    pub fn done(&self) -> bool {
        self.targets.iter().all(|t| t.state.is_final())
    }

    /// The compact summary: how many targets are in each state, and the skipped boxes by reason.
    pub fn summary(&self) -> Summary {
        let mut s = Summary {
            msg_id: self.msg_id.clone(),
            address: self.address.render(),
            ..Summary::default()
        };
        for t in &self.targets {
            *s.states.entry(t.state.code()).or_default() += 1;
        }
        for (_, why) in &self.skipped {
            *s.skipped.entry(why.code()).or_default() += 1;
        }
        s
    }
}

/// A structured summary of one delivery, so a renderer can change its words without changing what is reported.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Summary {
    pub msg_id: String,
    pub address: String,
    pub states: BTreeMap<&'static str, usize>,
    pub skipped: BTreeMap<&'static str, usize>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn b(name: &str, production: bool, delegated: bool, online: bool) -> BoxReach {
        BoxReach {
            name: name.into(),
            production,
            delegated,
            online,
            remote: false,
        }
    }

    fn fleet() -> Vec<BoxReach> {
        vec![
            b("alpha", false, true, true),
            b("bravo", false, true, false),
            b("charlie", false, false, true),
            b("prod", true, true, true),
        ]
    }

    fn groups() -> BTreeMap<String, Vec<String>> {
        let mut g = BTreeMap::new();
        g.insert(
            "web".to_string(),
            vec!["alpha".into(), "bravo".into(), "charlie".into()],
        );
        g.insert("ops".to_string(), vec!["prod".into()]);
        g
    }

    #[test]
    fn the_grammar_reads_a_session_a_box_a_group_and_the_fleet_and_nothing_else() {
        assert_eq!(
            Address::parse("@alpha/t1a2"),
            Some(Address::Session {
                box_name: "alpha".into(),
                session: "t1a2".into()
            })
        );
        assert_eq!(
            Address::parse("@alpha"),
            Some(Address::Name("alpha".into()))
        );
        assert_eq!(Address::parse("@FLEET"), Some(Address::Fleet));
        for bad in ["@", "@Alpha!", "@a/b c", "@a/", "@/x", "@alpha/$(id)"] {
            assert_eq!(Address::parse(bad), None, "{bad}");
        }
        assert_eq!(Address::parse("@alpha/%3").unwrap().render(), "@alpha/%3");
    }

    #[test]
    fn a_fleet_reaches_only_delegated_non_production_boxes_and_says_what_it_left_out() {
        let e = expand(&Address::Fleet, &fleet(), &groups());
        assert!(e.fanout);
        let names: Vec<_> = e.targets.iter().map(|t| t.box_name.as_str()).collect();
        assert_eq!(names, ["alpha", "bravo"]);
        assert!(
            !e.targets[1].online,
            "an offline box is a target with an honest state"
        );
        assert!(e.skipped.contains(&("charlie".into(), Skip::NotDelegated)));
        assert!(e.skipped.contains(&("prod".into(), Skip::Production)));
    }

    #[test]
    fn a_group_expands_a_box_name_wins_and_an_unknown_name_is_skipped() {
        let e = expand(&Address::Name("web".into()), &fleet(), &groups());
        assert!(e.fanout);
        assert_eq!(e.targets.len(), 2);
        let e = expand(&Address::Name("alpha".into()), &fleet(), &groups());
        assert!(!e.fanout);
        assert_eq!(e.targets.len(), 1);
        let e = expand(&Address::Name("ops".into()), &fleet(), &groups());
        assert!(e.targets.is_empty());
        assert_eq!(e.skipped, vec![("prod".into(), Skip::Production)]);
        let e = expand(&Address::Name("nope".into()), &fleet(), &groups());
        assert_eq!(e.skipped, vec![("nope".into(), Skip::Unknown)]);
    }

    #[test]
    fn targets_map_to_the_fabrics_addresses() {
        let t = Target {
            box_name: "alpha".into(),
            session: Some("t3".into()),
            online: true,
            remote: false,
        };
        assert_eq!(fabric_target(&t).as_deref(), Some("agent:alpha/t3"));
        let t = Target { session: None, ..t };
        assert_eq!(fabric_target(&t), None);
        assert_eq!(
            fabric_group(&Address::Fleet, "ada", &groups()).as_deref(),
            Some("fleet:ada")
        );
        assert_eq!(
            fabric_group(&Address::Name("web".into()), "ada", &groups()).as_deref(),
            Some("group:web")
        );
        assert_eq!(
            fabric_group(&Address::Name("alpha".into()), "ada", &groups()),
            None
        );
    }

    #[test]
    fn a_fan_out_is_bounded() {
        let many: Vec<BoxReach> = (0..30)
            .map(|i| b(&format!("b{i:02}"), false, true, true))
            .collect();
        let e = expand(&Address::Fleet, &many, &BTreeMap::new());
        assert_eq!(e.targets.len(), MAX_FANOUT);
        assert_eq!(e.skipped.len(), 10);
        assert!(e.skipped.iter().all(|(_, s)| *s == Skip::TooMany));
    }

    #[test]
    fn discovery_lists_only_what_the_person_may_reach() {
        let r: Vec<_> = reachable(&fleet()).iter().map(|b| b.name.clone()).collect();
        assert_eq!(r, ["alpha", "bravo"]);
        assert_eq!(reachable_groups(&fleet(), &groups()), vec![("web", 2, 3)]);
    }

    #[test]
    fn delivery_states_move_forward_only_and_the_summary_counts_them() {
        let e = expand(&Address::Fleet, &fleet(), &groups());
        let mut d = Delivery::new("m1", Address::Fleet, &e);
        assert!(d.advance("alpha", DeliveryState::Delivered));
        assert!(d.advance("alpha", DeliveryState::Replied));
        assert!(!d.advance("alpha", DeliveryState::Queued), "never back");
        assert!(d.advance("bravo", DeliveryState::Unreachable("offline")));
        assert!(
            !d.advance("bravo", DeliveryState::Replied),
            "a final state stays"
        );
        assert!(d.done());
        let s = d.summary();
        assert_eq!(s.states.get("replied"), Some(&1));
        assert_eq!(s.states.get("unreachable"), Some(&1));
        assert_eq!(s.skipped.get("production"), Some(&1));
        assert_eq!(s.skipped.get("not_delegated"), Some(&1));
        assert_eq!(s.address, "@fleet");
    }
}
