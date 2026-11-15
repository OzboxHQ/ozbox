//! Which actions an agent must ask about, and the words of the question.
//!
//! The policy is data (edited in Settings, saved with the task store); [`classify`] is a pure function from an action
//! to "ask, and why" or "go ahead". It never decides to allow something the policy asks about, and an unknown action is
//! never silently allowed: callers hand it one of the [`AgentAction`] shapes, and anything an engine cannot name as one
//! of them is a command, which is checked against the ask list.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::run::ActionKind;

/// The longest an approval may wait, and the shortest.
pub const MIN_EXPIRY_S: u64 = 60;
pub const MAX_EXPIRY_S: u64 = 7 * 24 * 3600;
/// An expiry longer than this (the default, 8 hours) is a loosening when it is a raise: a stale request, filed before the context
/// changed, stays approvable for longer (owner decision D16, 2026-11-15). Keep `policyLoosens` in the dashboard in step.
pub const LOOSENING_EXPIRY_S: u64 = 8 * 3600;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ApprovalPolicy {
    /// The kinds of action that ask. A kind left out never asks.
    pub ask: BTreeSet<ActionKind>,
    /// Branch names (or `prefix/*`) that count as protected.
    pub protected_branches: Vec<String>,
    /// Commands that ask: the words each must start with (`rm -rf`, `git push --force`).
    pub ask_commands: Vec<String>,
    /// An action that would spend more than this many US cents asks.
    pub spend_threshold_cents: Option<u64>,
    /// Seconds before an unanswered request is denied.
    pub expiry_s: u64,
    /// People who may decide; empty means anyone who can sign in to the dashboard.
    pub approvers: Vec<String>,
    /// May the person who asked for the run also approve its requests.
    pub allow_requester: bool,
    /// The kinds that need a fresh second factor to decide (in sign-in mode).
    pub step_up: BTreeSet<ActionKind>,
}

impl Default for ApprovalPolicy {
    fn default() -> Self {
        Self {
            // a tool call asks because the permission engine says so, not because the policy lists it
            ask: ActionKind::ALL
                .into_iter()
                .filter(|k| *k != ActionKind::ToolCall)
                .collect(),
            protected_branches: ["main", "master", "staging", "production", "release/*"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            ask_commands: [
                "sudo",
                "rm -rf",
                "rm -fr",
                "git push --force",
                "git push -f",
                "git reset --hard",
                "curl",
                "wget",
                "ssh",
                "scp",
                "tofu apply",
                "tofu destroy",
                "terraform apply",
                "terraform destroy",
                "kubectl delete",
                "docker push",
                "npm publish",
                "cargo publish",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            spend_threshold_cents: Some(2000),
            expiry_s: 8 * 3600,
            approvers: Vec::new(),
            allow_requester: true,
            step_up: [
                ActionKind::ProductionResource,
                ActionKind::PushProtectedBranch,
            ]
            .into_iter()
            .collect(),
        }
    }
}

impl ApprovalPolicy {
    /// Whether replacing `self` with `new` asks LESS than before: a kind of action no longer asks, a protected branch or a
    /// command is dropped, the spend threshold goes away or rises, the people who may decide widen, the requester may now
    /// approve their own run, a kind loses its second factor, or an unanswered request stays approvable for longer than
    /// [`LOOSENING_EXPIRY_S`] (8 hours) AND longer than it did. A change that only tightens, or moves the expiry within
    /// 8 hours (or lowers it), is not loosening. Such a change needs a fresh second factor (ADR 0041, owner decision D16).
    #[must_use]
    pub fn loosens(&self, new: &ApprovalPolicy) -> bool {
        let dropped = |old: &[String], now: &[String]| old.iter().any(|x| !now.contains(x));
        let threshold = match (self.spend_threshold_cents, new.spend_threshold_cents) {
            (Some(_), None) => true,
            (Some(a), Some(b)) => b > a,
            _ => false,
        };
        // an empty list means anyone who can sign in, so it is the widest
        let approvers = match (self.approvers.is_empty(), new.approvers.is_empty()) {
            (false, true) => true,
            (false, false) => new.approvers.iter().any(|p| !self.approvers.contains(p)),
            _ => false,
        };
        !self.ask.is_subset(&new.ask)
            || dropped(&self.protected_branches, &new.protected_branches)
            || dropped(&self.ask_commands, &new.ask_commands)
            || threshold
            || approvers
            || (!self.allow_requester && new.allow_requester)
            || !self.step_up.is_subset(&new.step_up)
            || (new.expiry_s > LOOSENING_EXPIRY_S && new.expiry_s > self.expiry_s)
    }

    /// Refuse a policy that could not work. The message is for a person.
    pub fn validate(&self) -> Result<(), String> {
        if !(MIN_EXPIRY_S..=MAX_EXPIRY_S).contains(&self.expiry_s) {
            return Err("expiry: between 1 minute and 7 days".into());
        }
        if self.protected_branches.len() > 50
            || self.ask_commands.len() > 100
            || self.approvers.len() > 100
        {
            return Err("too many entries".into());
        }
        let word = |s: &str| {
            !s.is_empty() && s.len() <= 100 && s.chars().all(|c| c.is_ascii_graphic() || c == ' ')
        };
        if !self
            .protected_branches
            .iter()
            .all(|b| word(b) && !b.contains(' '))
        {
            return Err("protected branches: letters, digits and / . _ - * only".into());
        }
        if !self.ask_commands.iter().all(|c| word(c)) {
            return Err("commands: plain words only".into());
        }
        if !self.approvers.iter().all(|p| word(p) && !p.contains(' ')) {
            return Err("approvers: a person's id each".into());
        }
        if self.spend_threshold_cents.is_some_and(|c| c > 10_000_000) {
            return Err("spend threshold: more than $100,000".into());
        }
        Ok(())
    }

    pub fn is_protected(&self, branch: &str) -> bool {
        self.protected_branches
            .iter()
            .any(|p| match p.strip_suffix("/*") {
                Some(prefix) => branch.starts_with(&format!("{prefix}/")),
                None => p == branch,
            })
    }

    /// May this person decide a request.
    pub fn may_decide(&self, person: &str, requested_by: &str) -> bool {
        if !self.allow_requester && person == requested_by {
            return false;
        }
        self.approvers.is_empty() || self.approvers.iter().any(|a| a == person)
    }
}

/// Something an agent wants to do that the supervisor may need to ask about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum AgentAction {
    GitPush {
        branch: String,
    },
    OpenPr {
        base: String,
    },
    Command {
        argv: Vec<String>,
    },
    /// Any message to someone outside: email, chat, a webhook.
    Message {
        channel: String,
    },
    Spend {
        cents: u64,
        what: String,
    },
    Touch {
        resource: String,
        production: bool,
    },
}

/// The question to put to a person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ask {
    pub kind: ActionKind,
    /// The exact action, secrets removed.
    pub action: String,
    pub production: bool,
}

/// Remove what looks like a secret from a command line before it is shown or stored.
pub fn scrub_secrets(text: &str) -> String {
    let secretish = |name: &str| {
        let n = name.to_ascii_uppercase();
        [
            "KEY",
            "TOKEN",
            "SECRET",
            "PASSWORD",
            "PASSWD",
            "CREDENTIAL",
            "AUTH",
        ]
        .iter()
        .any(|w| n.contains(w))
    };
    let mut out: Vec<String> = Vec::new();
    let mut hide_next = false;
    for word in text.split_whitespace() {
        if hide_next {
            out.push("[hidden]".into());
            hide_next = false;
            continue;
        }
        if let Some((name, _)) = word.split_once('=') {
            if secretish(name.trim_start_matches('-')) {
                out.push(format!("{name}=[hidden]"));
                continue;
            }
        }
        if word.starts_with('-') && secretish(word) && !word.contains('=') {
            out.push(word.to_string());
            hide_next = true;
            continue;
        }
        if word.eq_ignore_ascii_case("bearer") {
            out.push(word.to_string());
            hide_next = true;
            continue;
        }
        out.push(word.to_string());
    }
    out.join(" ")
}

pub fn starts_with_words(argv: &[String], pattern: &str) -> bool {
    let words: Vec<&str> = pattern.split_whitespace().collect();
    if words.is_empty() || argv.len() < words.len() {
        return false;
    }
    let base = |s: &str| s.rsplit('/').next().unwrap_or(s).to_string();
    words.iter().enumerate().all(|(i, w)| {
        if i == 0 {
            base(&argv[0]) == *w
        } else {
            // a flag may be written in any order after the program: `git push origin main --force`
            argv[i] == *w
        }
    }) || (words.len() > 1
        && base(&argv[0]) == words[0]
        && words[1..]
            .iter()
            .all(|w| argv.iter().skip(1).any(|a| a == w)))
}

/// The words that describe an action to a person, with secrets removed.
pub fn describe(action: &AgentAction) -> String {
    match action {
        AgentAction::GitPush { branch } => format!("git push origin {branch}"),
        AgentAction::OpenPr { base } => format!("open a pull request into {base}"),
        AgentAction::Command { argv } => scrub_secrets(&argv.join(" ")),
        AgentAction::Message { channel } => format!("send a message through {channel}"),
        AgentAction::Spend { cents, what } => {
            format!("spend ${}.{:02} on {what}", cents / 100, cents % 100)
        }
        AgentAction::Touch { resource, .. } => format!("use {resource}"),
    }
}

/// Decide whether an action needs a person's yes. `box_production` is whether the run's box is tagged production.
pub fn classify(
    policy: &ApprovalPolicy,
    action: &AgentAction,
    box_production: bool,
) -> Option<Ask> {
    let asks = |k: ActionKind| policy.ask.contains(&k);
    // Anything touching something tagged production asks first, whatever else it is.
    let production = box_production
        || matches!(
            action,
            AgentAction::Touch {
                production: true,
                ..
            }
        );
    let text = describe(action);
    if production
        && asks(ActionKind::ProductionResource)
        && !matches!(
            action,
            AgentAction::Message { .. } | AgentAction::Spend { .. }
        )
    {
        return Some(Ask {
            kind: ActionKind::ProductionResource,
            action: text,
            production: true,
        });
    }
    let kind = match action {
        AgentAction::GitPush { branch } if policy.is_protected(branch) => {
            Some(ActionKind::PushProtectedBranch)
        }
        AgentAction::OpenPr { base } if policy.is_protected(base) => Some(ActionKind::OpenPrToMain),
        AgentAction::Command { argv }
            if policy
                .ask_commands
                .iter()
                .any(|p| starts_with_words(argv, p)) =>
        {
            Some(ActionKind::AskCommand)
        }
        AgentAction::Message { .. } => Some(ActionKind::OutboundMessage),
        AgentAction::Spend { cents, .. }
            if policy.spend_threshold_cents.is_some_and(|t| *cents > t) =>
        {
            Some(ActionKind::SpendAboveThreshold)
        }
        _ => None,
    }?;
    asks(kind).then_some(Ask {
        kind,
        action: text,
        production,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn cmd(s: &str) -> AgentAction {
        AgentAction::Command {
            argv: s.split_whitespace().map(str::to_string).collect(),
        }
    }

    #[test]
    fn loosening_is_told_from_tightening() {
        let base = ApprovalPolicy::default();
        assert!(!base.loosens(&base));
        let mut l = base.clone();
        l.ask.remove(&ActionKind::ALL[0]);
        assert!(base.loosens(&l) && !l.loosens(&base));
        let mut l = base.clone();
        l.protected_branches.pop();
        assert!(base.loosens(&l));
        let mut l = base.clone();
        l.ask_commands.clear();
        assert!(base.loosens(&l));
        let mut t = base.clone();
        t.allow_requester = false;
        assert!(t.loosens(&base) && !base.loosens(&t));
        let mut l = base.clone();
        l.expiry_s = base.expiry_s + 60;
        // D16: 8 hours is the line. A raise to just past it loosens; at it, or any lowering, does not
        assert!(base.loosens(&l) && !l.loosens(&base));
        l.expiry_s = LOOSENING_EXPIRY_S;
        assert!(!base.loosens(&l));
        let mut shorter = base.clone();
        shorter.expiry_s = 3600;
        assert!(
            !shorter.loosens(&base),
            "1 hour to the 8-hour default is not past the line"
        );
        let mut ten = base.clone();
        ten.expiry_s = 10 * 3600;
        let mut twelve = base.clone();
        twelve.expiry_s = 12 * 3600;
        assert!(
            ten.loosens(&twelve) && !twelve.loosens(&ten),
            "past the line only a further raise loosens"
        );
        assert!(
            !ten.loosens(&ten),
            "an unchanged long expiry is not a change"
        );
        assert!(shorter.loosens(&twelve));
        let mut a = base.clone();
        a.spend_threshold_cents = Some(500);
        let mut b = a.clone();
        b.spend_threshold_cents = Some(900);
        assert!(a.loosens(&b) && !b.loosens(&a));
        b.spend_threshold_cents = None;
        assert!(a.loosens(&b) && !b.loosens(&a));
        let mut a = base.clone();
        a.approvers = vec!["ada".into()];
        let mut b = a.clone();
        b.approvers.push("bob".into());
        assert!(a.loosens(&b) && !b.loosens(&a));
        b.approvers.clear();
        assert!(a.loosens(&b) && !b.loosens(&a));
        let mut l = base.clone();
        l.step_up.remove(&ActionKind::ProductionResource);
        assert!(base.loosens(&l) && !l.loosens(&base));
    }

    #[test]
    fn the_default_policy_asks_about_the_risky_actions_and_lets_the_rest_go() {
        let p = ApprovalPolicy::default();
        assert!(p.validate().is_ok());
        let k = |a: &AgentAction| classify(&p, a, false).map(|x| x.kind);
        assert_eq!(
            k(&AgentAction::GitPush {
                branch: "main".into()
            }),
            Some(ActionKind::PushProtectedBranch)
        );
        assert_eq!(
            k(&AgentAction::GitPush {
                branch: "release/1.2".into()
            }),
            Some(ActionKind::PushProtectedBranch)
        );
        assert_eq!(
            k(&AgentAction::GitPush {
                branch: "wip/alpha/1".into()
            }),
            None
        );
        assert_eq!(
            k(&AgentAction::OpenPr {
                base: "main".into()
            }),
            Some(ActionKind::OpenPrToMain)
        );
        assert_eq!(
            k(&AgentAction::OpenPr {
                base: "feature".into()
            }),
            None
        );
        assert_eq!(k(&cmd("rm -rf /work/x")), Some(ActionKind::AskCommand));
        assert_eq!(
            k(&cmd("git push origin main --force")),
            Some(ActionKind::AskCommand)
        );
        assert_eq!(k(&cmd("/usr/bin/sudo ls")), Some(ActionKind::AskCommand));
        assert_eq!(k(&cmd("cargo test")), None);
        assert_eq!(k(&cmd("rm file")), None);
        assert_eq!(
            k(&AgentAction::Message {
                channel: "email".into()
            }),
            Some(ActionKind::OutboundMessage)
        );
        assert_eq!(
            k(&AgentAction::Spend {
                cents: 5000,
                what: "gpu".into()
            }),
            Some(ActionKind::SpendAboveThreshold)
        );
        assert_eq!(
            k(&AgentAction::Spend {
                cents: 100,
                what: "gpu".into()
            }),
            None
        );
    }

    #[test]
    fn production_asks_first_and_a_kind_left_out_never_asks() {
        let p = ApprovalPolicy::default();
        let a = classify(
            &p,
            &AgentAction::Touch {
                resource: "db".into(),
                production: true,
            },
            false,
        )
        .unwrap();
        assert_eq!(
            (a.kind, a.production),
            (ActionKind::ProductionResource, true)
        );
        // a plain command on a production-tagged box asks as production
        let a = classify(&p, &cmd("cargo test"), true).unwrap();
        assert_eq!(a.kind, ActionKind::ProductionResource);
        let mut q = p.clone();
        q.ask.remove(&ActionKind::PushProtectedBranch);
        assert!(classify(
            &q,
            &AgentAction::GitPush {
                branch: "main".into()
            },
            false
        )
        .is_none());
    }

    #[test]
    fn secrets_are_removed_from_the_action_shown() {
        let p = ApprovalPolicy::default();
        let a = classify(&p, &cmd("curl --token abc123 https://example.com API_KEY=sk-live-1 -H Authorization: Bearer xyz"), false).unwrap();
        for s in ["abc123", "sk-live-1", "xyz"] {
            assert!(!a.action.contains(s), "{}", a.action);
        }
        assert!(a.action.contains("[hidden]"));
    }

    #[test]
    fn who_may_decide_follows_the_policy() {
        let mut p = ApprovalPolicy::default();
        assert!(p.may_decide("ada", "ada"));
        p.allow_requester = false;
        assert!(!p.may_decide("ada", "ada"));
        assert!(p.may_decide("bo", "ada"));
        p.approvers = vec!["cy".into()];
        assert!(!p.may_decide("bo", "ada"));
        assert!(p.may_decide("cy", "ada"));
    }

    #[test]
    fn a_policy_that_cannot_work_is_refused() {
        let p = ApprovalPolicy {
            expiry_s: 5,
            ..ApprovalPolicy::default()
        };
        assert!(p.validate().is_err());
        let mut p = ApprovalPolicy::default();
        p.protected_branches.push("bad branch".into());
        assert!(p.validate().is_err());
    }
}
