//! Who may do what at the dashboard: three roles, decided by the permission engine.
//!
//! A person who can sign in to the dashboard has one role. Each role is a small set of **deny rules** handed to
//! [`permissions::decide`], the same function every other actor goes through, so "may this person do this?" has one
//! answer shape (allow, ask or deny, with the rule that decided) and one place a deny rule wins. There is no second
//! mechanism: a role is a [`PermConfig`] made of rules.
//!
//! | Role | May |
//! |---|---|
//! | **owner** | everything, including the settings, permissions, secrets policy, costs and who has which role |
//! | **member** | work: start and stop runs, approve what agents ask, watch and take over a browser, use a terminal, the IDE and files, change a box. Not the settings, permissions, secrets policy, costs or people |
//! | **viewer** | look: the fleet, runs, costs and the audit log. Nothing that acts, and not the pictures of a browser or the files and terminal of a box |
//!
//! The first person on a dashboard's list is its owner. There is always at least one owner: [`resolve`] makes one when
//! a list holds none, and a role change that would leave none is refused by the caller.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::permissions::{self, Action, ActorKind, Ctx, Decision, Effect, PermConfig, Rule, Scope};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Owner,
    Member,
    Viewer,
}

impl Role {
    pub const ALL: [Role; 3] = [Role::Owner, Role::Member, Role::Viewer];

    pub fn name(self) -> &'static str {
        match self {
            Role::Owner => "owner",
            Role::Member => "member",
            Role::Viewer => "viewer",
        }
    }

    pub fn parse(s: &str) -> Option<Role> {
        Role::ALL.into_iter().find(|r| r.name() == s.trim())
    }

    /// The actions a member or an owner may **not** do, one rule each. An owner has none.
    fn denied(self) -> &'static [Action] {
        match self {
            Role::Owner => &[],
            Role::Member => &[
                // the settings, in every part of the dashboard (the browser's settings among them)
                Action::SettingsChange,
                // permissions: granting access to production
                Action::GrantCreate,
                // the secrets policy: writing a secret, minting the approval that lets one be used
                Action::SecretWrite,
                Action::SecretUse,
                // costs: spend caps, and deleting what the bill says is forgotten
                Action::Spend,
                Action::ResourceTouch,
                // who has which role
                Action::PeopleManage,
            ],
            // a viewer's rule is one deny of every action (see `rules`), so there is no list to keep in step
            Role::Viewer => &[],
        }
    }
}

/// The deny rules of a role, with ids that name it (`role-viewer`, `role-member-settings.change`).
pub fn rules(role: Role) -> Vec<Rule> {
    let rule = |id: String, action: &str, note: &str| Rule {
        id,
        effect: Effect::Deny,
        action: action.to_string(),
        scope: Scope::Person,
        scope_id: None,
        path: None,
        command: None,
        env: None,
        tool: None,
        server: None,
        note: note.to_string(),
    };
    match role {
        Role::Owner => Vec::new(),
        Role::Viewer => vec![rule(
            "role-viewer".into(),
            "*",
            "a viewer can look but not act",
        )],
        Role::Member => role
            .denied()
            .iter()
            .map(|a| {
                rule(
                    format!("role-member-{}", a.name()),
                    a.name(),
                    "only an owner can do this",
                )
            })
            .collect(),
    }
}

/// A role as a permission configuration: only its deny rules, no grants, the default mode.
pub fn config(role: Role) -> PermConfig {
    PermConfig {
        rules: rules(role),
        ..PermConfig::default()
    }
}

/// May a person with this role do this? Asks [`permissions::decide`]; only a deny refuses (an `ask` is for agents, and a
/// person at the dashboard is the one being asked).
pub fn decide(role: Role, person: &str, action: Action, now_ms: u64) -> Decision {
    let ctx = Ctx {
        person: person.to_string(),
        actor: ActorKind::Person,
        ..Ctx::default()
    };
    permissions::decide(&config(role), &ctx, action, now_ms)
}

pub fn allowed(role: Role, action: Action) -> bool {
    decide(role, "", action, 0).effect != Effect::Deny
}

/// What every role may do, as the dashboard shows it. Each is an action a route needs.
pub const CAPABILITIES: [(&str, Action); 8] = [
    ("watch_browser", Action::BrowserWatch),
    ("control_browser", Action::BrowserControl),
    ("approve", Action::ApprovalDecide),
    ("start_runs", Action::RunStart),
    ("use_boxes", Action::CommandRun),
    ("change_settings", Action::SettingsChange),
    ("manage_costs", Action::Spend),
    ("manage_people", Action::PeopleManage),
];

/// The capabilities a role has, by name, for the dashboard to degrade to.
pub fn capabilities(role: Role) -> BTreeMap<&'static str, bool> {
    CAPABILITIES
        .iter()
        .map(|(name, action)| (*name, allowed(role, *action)))
        .collect()
}

/// The role each person on a list has: an explicit one (kept by the dashboard, or written in its settings) wins; the
/// first person with none is the owner, the rest are members. If the result has no owner (the owner was taken off the
/// list, or every role was set below owner) the first person on the list becomes one, so nobody is ever locked out.
///
/// `people` are ids in list order; `explicit` holds the roles somebody chose.
pub fn resolve(people: &[String], explicit: &BTreeMap<String, Role>) -> BTreeMap<String, Role> {
    let mut out = BTreeMap::new();
    for (i, id) in people.iter().enumerate() {
        let role =
            explicit
                .get(id)
                .copied()
                .unwrap_or(if i == 0 { Role::Owner } else { Role::Member });
        out.insert(id.clone(), role);
    }
    if !out.values().any(|r| *r == Role::Owner) {
        if let Some(first) = people.first() {
            out.insert(first.clone(), Role::Owner);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn people(ids: &[&str]) -> Vec<String> {
        ids.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn every_action_name_is_unique_across_the_agent_and_dashboard_sets() {
        let mut names: Vec<&str> = Action::ALL.iter().map(|a| a.name()).collect();
        names.extend(Action::DASHBOARD.iter().map(|a| a.name()));
        let n = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), n);
    }

    #[test]
    fn an_owner_may_do_everything_and_a_viewer_nothing_that_acts() {
        for a in Action::ALL.iter().chain(Action::DASHBOARD.iter()) {
            assert!(allowed(Role::Owner, *a), "owner {}", a.name());
            let d = decide(Role::Viewer, "v", *a, 0);
            assert_eq!(d.effect, Effect::Deny, "viewer {}", a.name());
            assert_eq!(d.rule.as_deref(), Some("role-viewer"));
        }
    }

    #[test]
    fn a_member_works_but_does_not_change_settings_permissions_secrets_costs_or_people() {
        for a in [
            Action::RunStart,
            Action::RunStop,
            Action::ApprovalDecide,
            Action::BrowserWatch,
            Action::BrowserControl,
            Action::CommandRun,
            Action::FileRead,
            Action::FileWrite,
            Action::BoxChange,
            Action::BoxCreate,
            Action::BoxDestroy,
            Action::MessageSend,
            Action::ToolCall,
        ] {
            assert!(allowed(Role::Member, a), "member {}", a.name());
        }
        for a in [
            Action::SettingsChange,
            Action::GrantCreate,
            Action::SecretWrite,
            Action::SecretUse,
            Action::Spend,
            Action::ResourceTouch,
            Action::PeopleManage,
        ] {
            let d = decide(Role::Member, "m", a, 0);
            assert_eq!(d.effect, Effect::Deny, "member {}", a.name());
            assert_eq!(d.reason, permissions::Reason::RuleDeny);
            assert!(d.rule.unwrap_or_default().starts_with("role-member-"));
        }
    }

    #[test]
    fn the_capability_list_follows_the_roles() {
        let o = capabilities(Role::Owner);
        let m = capabilities(Role::Member);
        let v = capabilities(Role::Viewer);
        assert!(o.values().all(|b| *b));
        assert!(v.values().all(|b| !*b));
        assert!(
            m["watch_browser"]
                && m["control_browser"]
                && m["approve"]
                && m["start_runs"]
                && m["use_boxes"]
        );
        assert!(!m["change_settings"] && !m["manage_costs"] && !m["manage_people"]);
    }

    #[test]
    fn the_first_person_is_the_owner_and_the_rest_are_members() {
        let r = resolve(&people(&["ann", "bo", "cy"]), &BTreeMap::new());
        assert_eq!(r["ann"], Role::Owner);
        assert_eq!(r["bo"], Role::Member);
        assert_eq!(r["cy"], Role::Member);
    }

    #[test]
    fn an_explicit_role_wins_and_a_list_with_no_owner_gets_one() {
        let explicit = BTreeMap::from([
            ("ann".to_string(), Role::Viewer),
            ("bo".to_string(), Role::Member),
        ]);
        let r = resolve(&people(&["ann", "bo"]), &explicit);
        assert_eq!(r["ann"], Role::Owner, "never locked out");
        assert_eq!(r["bo"], Role::Member);
        // an owner who was taken off the list: the first person left becomes the owner
        let explicit = BTreeMap::from([("gone".to_string(), Role::Owner)]);
        let r = resolve(&people(&["bo", "cy"]), &explicit);
        assert_eq!(r["bo"], Role::Owner);
        assert_eq!(r.len(), 2, "a role for somebody not on the list is dropped");
        // an explicit second owner is kept
        let explicit = BTreeMap::from([("bo".to_string(), Role::Owner)]);
        let r = resolve(&people(&["ann", "bo"]), &explicit);
        assert_eq!((r["ann"], r["bo"]), (Role::Owner, Role::Owner));
    }

    #[test]
    fn names_round_trip() {
        for r in Role::ALL {
            assert_eq!(Role::parse(r.name()), Some(r));
        }
        assert_eq!(Role::parse("admin"), None);
        assert_eq!(
            serde_json::to_string(&Role::Viewer).unwrap_or_default(),
            "\"viewer\""
        );
    }
}
