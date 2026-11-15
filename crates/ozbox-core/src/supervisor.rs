//! The supervisor: admits queued runs, watches them, pauses them at a cap, asks people about risky actions, and writes the
//! audit trail. It is pure logic over a [`Book`] and an [`AgentHost`], so every rule is tested with a fake engine and a
//! fake clock. `ozbox serve` calls [`Supervisor::tick`] about once a second and delivers the alerts it returns.

use std::collections::BTreeMap;

use crate::agent_engine::{redact_line, AgentEngine, EngineEvent, EngineStart};
use crate::approvals::{classify, describe, AgentAction, ApprovalPolicy, Ask};
use crate::model_usage::ModelUsage;
use crate::permissions::{
    self, Action as PermAction, ActorKind, Ctx, Effect, Environment, NewGrant, Reason, Scope,
    SecondFactor,
};
use crate::run::{
    ActionKind, ApprovalRequest, ApprovalState, Book, ModelRef, Needs, RunModel, RunSpec, Task,
    TaskState,
};
use crate::size::{GpuKind, Size};

/// How many agent runs a box of this size runs at once; the rest queue.
pub fn size_cap(size: Size) -> usize {
    match size {
        Size::XS => 1,
        Size::S => 2,
        Size::M => 4,
        Size::L => 6,
        Size::XL => 8,
        Size::XXL => 16,
        Size::Gpu(GpuKind::Small) => 4,
        Size::Gpu(GpuKind::Large) => 8,
    }
}

/// What the supervisor needs to know about a box.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoxInfo {
    pub size: Size,
    pub running: bool,
    /// The box carries the label `env=production` (or `production=true`).
    pub production: bool,
}

/// The provider and model chosen for a run, and the environment that lets the engine reach it. The environment is
/// secret: it goes to the engine at start and nowhere else (not the task store, not a log, not an error).
pub struct ModelAssignment {
    pub provider_id: String,
    pub model: String,
    /// What the run switches to when the provider refuses it, if anything.
    pub fallback: Option<ModelRef>,
    pub env: BTreeMap<String, String>,
}

impl std::fmt::Debug for ModelAssignment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModelAssignment")
            .field("provider_id", &self.provider_id)
            .field("model", &self.model)
            .field("env_names", &self.env.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

/// What a run may still spend through its model credentials.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ModelGrant {
    /// In millionths of a dollar; none = no limit.
    pub cap_micros: Option<u64>,
    pub now_ms: u64,
}

/// One model call a broker counted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokeredUsage {
    pub provider_id: String,
    pub model: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cached_input_tokens: u64,
}

/// Everything outside the supervisor: the boxes and the engines on them.
pub trait AgentHost {
    fn box_info(&self, box_name: &str) -> Option<BoxInfo>;
    /// The box has memory for one more run (the daemon's own admission, seen from here).
    fn has_room(&mut self, box_name: &str) -> bool;
    /// Why a running box cannot take a run right now (its agent cannot be reached), or none. The run then waits in the
    /// queue and says so, instead of failing: the box usually comes back.
    fn box_unavailable(&mut self, _box_name: &str) -> Option<String> {
        None
    }
    fn engine(&mut self, id: &str) -> Option<&mut dyn AgentEngine>;
    /// Save uncommitted work on the box to a `wip/` branch; the branch name, or none when there was nothing to save.
    fn checkpoint(&mut self, box_name: &str, repo: Option<&str>) -> Result<Option<String>, String>;
    /// Secret values to remove from any line of output.
    fn secrets(&self, _task: &Task) -> Vec<String> {
        Vec::new()
    }
    /// A key handed to this run, if the person set one.
    fn secret_env(&self, _spec: &RunSpec) -> BTreeMap<String, String> {
        BTreeMap::new()
    }
    /// Environment for a run that is not a secret key: where it reaches the Oz Box tools, and its token for them. A
    /// token is worth one run and is dropped in [`AgentHost::end_run`].
    fn run_env(&mut self, _task_id: &str, _spec: &RunSpec) -> BTreeMap<String, String> {
        BTreeMap::new()
    }
    /// The provider and model for this run: the run's own choice, else the box's, else the fleet's for the engine.
    /// `Ok(None)` means nothing is chosen and the engine uses its own login. `Err` says what to fix (the run then waits
    /// in the queue with that reason). With `use_fallback` it is the fallback's turn, after the first choice was refused.
    ///
    /// `grant` says what the run may still spend, so a credential broker can bind its token to it. The assignment's
    /// environment must never hold a long-lived vendor key: a host hands the run a short-lived scoped token instead.
    fn resolve_model(
        &mut self,
        _task_id: &str,
        _spec: &RunSpec,
        _use_fallback: bool,
        _grant: ModelGrant,
    ) -> Result<Option<ModelAssignment>, String> {
        Ok(None)
    }
    /// The run is over for now (finished, paused, stopped, failed or switching model): whatever token it held stops
    /// working.
    fn end_run(&mut self, _task_id: &str) {}
    /// What a credential broker counted for this run since the last call. The broker sees every provider reply, so its
    /// figures are the ones to trust.
    fn drain_usage(&mut self, _task_id: &str) -> Vec<BrokeredUsage> {
        Vec::new()
    }
    /// Whether usage for this run is counted by the broker, in which case the engine's own token events are ignored
    /// (counting both would double the cost).
    fn usage_via_broker(&self, _task_id: &str) -> bool {
        false
    }
    /// Whether this month's cap on a model provider has been reached: the scope in words, or none.
    fn model_cap_scope(&mut self, _provider_id: &str, _now_ms: u64) -> Option<String> {
        None
    }
    /// Record what one model call used (names and counts only).
    fn record_usage(&mut self, _usage: &ModelUsage) {}
    /// What those tokens cost at the price table, in millionths of a dollar; none when the model has no price.
    fn estimate_micros(&mut self, _usage: &ModelUsage) -> Option<u64> {
        None
    }
}

/// Something to tell people about, under the alert routing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertEffect {
    pub key: String,
    pub kind: &'static str,
    pub urgent: bool,
    pub box_name: String,
    pub title: String,
    pub body: String,
}

/// Why a person's request on a task was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ActionError {
    #[error("there is no such run")]
    NoSuchTask,
    #[error("there is no such request")]
    NoSuchApproval,
    #[error("that run is {0:?} and cannot be changed that way")]
    WrongState(TaskState),
    #[error("that request was already decided or has expired")]
    AlreadyDecided,
    #[error("you are not allowed to decide that request")]
    NotAllowed,
    #[error("this decision needs a fresh second factor")]
    StepUpRequired,
    #[error("that run is not a conversation")]
    NotInteractive,
    #[error("that message is empty, too long or the run already has too many waiting")]
    BadMessage,
}

/// Budget a person adds when a run is paused at a cap.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AddBudget {
    pub cents: u64,
    pub seconds: u64,
    pub tokens: u64,
}

const REMINDERS_S: [u64; 2] = [15 * 60, 3600];

#[derive(Debug, Default)]
pub struct Supervisor {
    last_tick_ms: Option<u64>,
}

fn alert(
    task: &Task,
    kind: &'static str,
    urgent: bool,
    title: String,
    body: String,
) -> AlertEffect {
    AlertEffect {
        key: format!("run:{}:{kind}", task.id),
        kind,
        urgent,
        box_name: task.spec.box_name.clone(),
        title,
        body,
    }
}

fn money(cents: u64) -> String {
    format!("${}.{:02}", cents / 100, cents % 100)
}

impl Supervisor {
    pub fn new() -> Self {
        Self::default()
    }

    /// One pass. `month` is `YYYY-MM` (UTC) of `now_ms`.
    pub fn tick(
        &mut self,
        book: &mut Book,
        host: &mut dyn AgentHost,
        now_ms: u64,
        month: &str,
    ) -> Vec<AlertEffect> {
        let dt_s = self
            .last_tick_ms
            .map(|l| (now_ms.saturating_sub(l) / 1000).min(60))
            .unwrap_or(0);
        self.last_tick_ms = Some(now_ms);
        let mut fx = Vec::new();
        if book.ledger.month != month {
            book.ledger = crate::run::Ledger {
                month: month.to_string(),
                ..Default::default()
            };
        }
        deliver_decisions(book, host, now_ms);
        deliver_inbox(book, host, now_ms);
        expire_and_remind(book, now_ms, &mut fx);
        cancel_requested(book, host, now_ms);
        pause_requested(book, host, now_ms);
        poll_active(book, host, now_ms, dt_s, &mut fx);
        check_caps(book, host, now_ms, &mut fx);
        resume_monthly(book, host, now_ms);
        admit(book, host, now_ms, &mut fx);
        fx
    }
}

fn engine_of<'a>(host: &'a mut dyn AgentHost, id: &str) -> Option<&'a mut dyn AgentEngine> {
    host.engine(id)
}

/// Hand waiting messages to the sessions that are running, in order, one tick at a time. A message the engine cannot take
/// stays in the inbox for the next tick; a session that has stopped drops it with a line in the run's log.
fn deliver_inbox(book: &mut Book, host: &mut dyn AgentHost, now_ms: u64) {
    let ids: Vec<String> = book
        .tasks
        .iter()
        .filter(|t| t.state == TaskState::Running && t.handle.is_some() && !t.inbox.is_empty())
        .map(|t| t.id.clone())
        .collect();
    for id in ids {
        let Some(t) = book.task(&id) else { continue };
        let (engine, handle) = (t.spec.engine.clone(), t.handle.clone().unwrap_or_default());
        let texts = t.inbox.clone();
        let mut sent = 0;
        let mut failed: Option<String> = None;
        for text in &texts {
            match engine_of(host, &engine).map(|e| e.send(&handle, text)) {
                Some(Ok(())) => sent += 1,
                Some(Err(e)) => {
                    failed = Some(e.to_string());
                    break;
                }
                None => break,
            }
        }
        if let Some(t) = book.task_mut(&id) {
            t.inbox.drain(..sent);
            if sent > 0 {
                t.awaiting_input = false;
            }
            if let Some(f) = failed {
                // not secret: the engine's own sentence about why a message could not be handed over
                t.push_log(&format!(
                    "a message could not be handed to the agent: {}",
                    f.chars().take(120).collect::<String>()
                ));
                t.inbox.clear();
            }
        }
        if sent > 0 {
            book.record(
                now_ms,
                "supervisor",
                "run.message",
                Some(&id),
                "a message was handed to the agent",
            );
        }
    }
}

/// Add a person's message to a running interactive session. The text is kept only until it is handed over.
pub fn send_message(
    book: &mut Book,
    id: &str,
    text: &str,
    actor: &str,
    now_ms: u64,
) -> Result<(), ActionError> {
    let t = book.task_mut(id).ok_or(ActionError::NoSuchTask)?;
    if !t.spec.interactive {
        return Err(ActionError::NotInteractive);
    }
    if !matches!(t.state, TaskState::Running | TaskState::Queued) {
        return Err(ActionError::WrongState(t.state));
    }
    let text = text.trim();
    if text.is_empty() || text.chars().count() > crate::run::MAX_INBOX_CHARS || text.contains('\0')
    {
        return Err(ActionError::BadMessage);
    }
    if t.inbox.len() >= crate::run::MAX_INBOX {
        return Err(ActionError::BadMessage);
    }
    t.inbox.push(text.to_string());
    book.record(now_ms, actor, "run.message_queued", Some(id), "");
    Ok(())
}

/// Ask for a running session to be paused: at the next tick its work is saved, the agent stops, and it waits under
/// "Needs you" until it is resumed (the same conversation continues).
pub fn request_pause(
    book: &mut Book,
    id: &str,
    actor: &str,
    now_ms: u64,
) -> Result<(), ActionError> {
    let t = book.task_mut(id).ok_or(ActionError::NoSuchTask)?;
    if t.state != TaskState::Running {
        return Err(ActionError::WrongState(t.state));
    }
    t.pause_requested = true;
    book.record(now_ms, actor, "run.pause_requested", Some(id), "");
    Ok(())
}

fn pause_requested(book: &mut Book, host: &mut dyn AgentHost, now_ms: u64) {
    let ids: Vec<String> = book
        .tasks
        .iter()
        .filter(|t| t.pause_requested && t.state == TaskState::Running)
        .map(|t| t.id.clone())
        .collect();
    for id in ids {
        checkpoint(book, host, &id, now_ms);
        stop_engine(book, host, &id);
        if let Some(t) = book.task_mut(&id) {
            t.pause_requested = false;
            t.state = TaskState::NeedsYou;
            t.needs = Some(Needs::Paused);
            t.handle = None;
            t.awaiting_input = false;
            t.push_log("paused");
        }
        book.record(now_ms, "supervisor", "run.paused", Some(&id), "");
    }
}

fn deliver_decisions(book: &mut Book, host: &mut dyn AgentHost, now_ms: u64) {
    let pending: Vec<(String, String, bool)> = book
        .approvals
        .iter()
        .filter(|a| !a.delivered && a.state != ApprovalState::Pending)
        .map(|a| {
            (
                a.id.clone(),
                a.task_id.clone(),
                a.state == ApprovalState::Approved,
            )
        })
        .collect();
    for (aid, tid, approved) in pending {
        if let Some(a) = book.approvals.iter_mut().find(|a| a.id == aid) {
            a.delivered = true;
        }
        let Some(t) = book.task_mut(&tid) else {
            continue;
        };
        if t.state.is_terminal() {
            continue;
        }
        let (engine, handle) = (t.spec.engine.clone(), t.handle.clone());
        if let (Some(h), Some(e)) = (handle, engine_of(host, &engine)) {
            let _ = e.resolve(&h, approved);
        }
        if let Some(t) = book.task_mut(&tid) {
            if matches!(t.needs, Some(Needs::Approval { .. })) {
                t.needs = None;
                t.state = TaskState::Running;
            }
            t.push_log(if approved {
                "a person approved the action"
            } else {
                "the action was not approved"
            });
        }
        let _ = now_ms;
    }
}

fn expire_and_remind(book: &mut Book, now_ms: u64, fx: &mut Vec<AlertEffect>) {
    let mut events: Vec<(String, String)> = Vec::new();
    for a in book
        .approvals
        .iter_mut()
        .filter(|a| a.state == ApprovalState::Pending)
    {
        if now_ms >= a.expires_ms {
            a.state = ApprovalState::Expired;
            a.decided_ms = Some(now_ms);
            a.decided_by = Some("supervisor".into());
            events.push((a.id.clone(), a.task_id.clone()));
            continue;
        }
        let waited = now_ms.saturating_sub(a.created_ms) / 1000;
        if (a.reminders as usize) < REMINDERS_S.len() && waited >= REMINDERS_S[a.reminders as usize]
        {
            a.reminders += 1;
            fx.push(AlertEffect {
                key: format!("run-approval:{}:remind{}", a.id, a.reminders),
                kind: "approval_waiting",
                urgent: true,
                box_name: a.box_name.clone(),
                title: "An agent is still waiting for your answer".into(),
                body: format!("Waiting {} minutes: {}", waited / 60, a.action),
            });
        }
    }
    for (aid, tid) in events {
        book.record(now_ms, "supervisor", "approval.expired", Some(&tid), &aid);
        if let Some(t) = book.task_mut(&tid) {
            t.push_log("the request expired and was denied");
        }
    }
}

fn stop_engine(book: &mut Book, host: &mut dyn AgentHost, id: &str) {
    host.end_run(id);
    let Some(t) = book.task_mut(id) else { return };
    if let Some(h) = t.handle.take() {
        let engine = t.spec.engine.clone();
        if let Some(e) = engine_of(host, &engine) {
            let _ = e.stop(&h);
        }
    }
}

fn checkpoint(book: &mut Book, host: &mut dyn AgentHost, id: &str, now_ms: u64) {
    let Some(t) = book.task(id) else { return };
    let (b, r) = (t.spec.box_name.clone(), t.spec.repo.clone());
    let res = host.checkpoint(&b, r.as_deref());
    match res {
        Ok(Some(branch)) => {
            if let Some(t) = book.task_mut(id) {
                t.wip_branch = Some(branch.clone());
            }
            book.record(now_ms, "supervisor", "run.checkpoint", Some(id), &branch);
        }
        Ok(None) => {}
        Err(e) => {
            book.record(now_ms, "supervisor", "run.checkpoint_failed", Some(id), &e);
            if let Some(t) = book.task_mut(id) {
                t.push_log("saving the work failed; the run stays paused so nothing is lost");
            }
        }
    }
}

fn cancel_requested(book: &mut Book, host: &mut dyn AgentHost, now_ms: u64) {
    let ids: Vec<String> = book
        .tasks
        .iter()
        .filter(|t| t.cancel_requested && !t.state.is_terminal())
        .map(|t| t.id.clone())
        .collect();
    for id in ids {
        let was_active = book.task(&id).is_some_and(|t| t.handle.is_some());
        if was_active {
            checkpoint(book, host, &id, now_ms);
        }
        stop_engine(book, host, &id);
        finish(book, &id, TaskState::Cancelled, now_ms);
        // an open request for a stopped run is withdrawn
        for a in book
            .approvals
            .iter_mut()
            .filter(|a| a.task_id == id && a.state == ApprovalState::Pending)
        {
            a.state = ApprovalState::Denied;
            a.decided_by = Some("supervisor".into());
            a.decided_ms = Some(now_ms);
            a.delivered = true;
        }
        book.record(now_ms, "supervisor", "run.cancelled", Some(&id), "");
    }
}

fn finish(book: &mut Book, id: &str, state: TaskState, now_ms: u64) {
    if let Some(t) = book.task_mut(id) {
        t.state = state;
        t.needs = None;
        t.handle = None;
        t.finished_ms = Some(now_ms);
        t.queue_reason = None;
    }
}

/// Change a run's cost figures and keep the monthly ledger equal to the sum of the runs' costs.
fn change_spend(book: &mut Book, task: &str, f: impl FnOnce(&mut Task)) {
    let who = book
        .task(task)
        .map(|t| t.spec.requested_by.clone())
        .unwrap_or_default();
    let mut delta = 0i64;
    if let Some(t) = book.task_mut(task) {
        f(t);
        delta = t.recompute_spend();
    }
    let apply = |v: &mut u64| *v = (*v as i64 + delta).max(0) as u64;
    apply(&mut book.ledger.fleet_cents);
    apply(book.ledger.by_person.entry(who).or_default());
}

fn add_spend(book: &mut Book, task: &str, cents: u64, tokens: u64) {
    change_spend(book, task, |t| {
        t.est_micros += cents * 10_000;
        t.tokens += tokens;
    });
}

/// Record one model call against the run's provider and model, and add its estimated cost to the run.
fn add_token_usage(
    book: &mut Book,
    host: &mut dyn AgentHost,
    id: &str,
    now_ms: u64,
    (input_tokens, output_tokens, cached_input_tokens): (u64, u64, u64),
    reported: Option<(String, String)>,
) {
    let Some(t) = book.task(id) else { return };
    let (provider_id, model) = match (&t.model, reported) {
        (_, Some((p, m))) if !p.is_empty() => (p, m),
        (Some(m), r) => (
            m.provider_id.clone(),
            r.map(|(_, m)| m).unwrap_or_else(|| m.model.clone()),
        ),
        // No model chosen: the engine's own login. There is nothing to price it against, but tokens still count.
        (None, _) => (String::new(), String::new()),
    };
    let usage = ModelUsage {
        ts_ms: now_ms,
        box_name: Some(t.spec.box_name.clone()),
        engine: Some(t.spec.engine.clone()),
        provider_id,
        model,
        input_tokens,
        output_tokens,
        cached_input_tokens,
    };
    let micros = if usage.is_valid() {
        host.record_usage(&usage);
        host.estimate_micros(&usage).unwrap_or(0)
    } else {
        0
    };
    change_spend(book, id, |t| {
        t.est_micros += micros;
        t.tokens += input_tokens + output_tokens;
    });
}

fn poll_active(
    book: &mut Book,
    host: &mut dyn AgentHost,
    now_ms: u64,
    dt_s: u64,
    fx: &mut Vec<AlertEffect>,
) {
    let ids: Vec<String> = book
        .tasks
        .iter()
        .filter(|t| t.state == TaskState::Running && t.handle.is_some())
        .map(|t| t.id.clone())
        .collect();
    for id in ids {
        let Some(t) = book.task_mut(&id) else {
            continue;
        };
        if !t.awaiting_input {
            t.active_s += dt_s;
        }
        let (engine, handle) = (t.spec.engine.clone(), t.handle.clone().unwrap_or_default());
        let secrets = book.task(&id).map(|t| host.secrets(t)).unwrap_or_default();
        for u in host.drain_usage(&id) {
            add_token_usage(
                book,
                host,
                &id,
                now_ms,
                (u.input_tokens, u.output_tokens, u.cached_input_tokens),
                Some((u.provider_id, u.model)),
            );
        }
        let via_broker = host.usage_via_broker(&id);
        let events = match engine_of(host, &engine).map(|e| e.poll(&handle)) {
            Some(Ok(ev)) => ev,
            Some(Err(e)) => {
                if let Some(t) = book.task_mut(&id) {
                    t.error = Some(redact_line(&e.to_string(), &secrets));
                }
                checkpoint(book, host, &id, now_ms);
                stop_engine(book, host, &id);
                finish(book, &id, TaskState::Failed, now_ms);
                book.record(
                    now_ms,
                    "supervisor",
                    "run.failed",
                    Some(&id),
                    "the engine stopped answering",
                );
                continue;
            }
            None => continue,
        };
        for ev in events {
            let Some(state) = book.task(&id).map(|t| t.state) else {
                break;
            };
            if state != TaskState::Running {
                break;
            }
            match ev {
                EngineEvent::Log(l) => {
                    if let Some(t) = book.task_mut(&id) {
                        t.push_log(&redact_line(&l, &secrets));
                    }
                }
                EngineEvent::Usage { cents, tokens } => {
                    // a broker's count is the one to trust, so the engine's own figures are left out
                    if !via_broker {
                        add_spend(book, &id, cents, tokens);
                    }
                }
                EngineEvent::TokenUsage {
                    input_tokens,
                    output_tokens,
                    cached_input_tokens,
                    model,
                } => {
                    if !via_broker {
                        add_token_usage(
                            book,
                            host,
                            &id,
                            now_ms,
                            (input_tokens, output_tokens, cached_input_tokens),
                            model.map(|m| (String::new(), m)),
                        );
                    }
                }
                EngineEvent::ReportedCost { cents } => {
                    change_spend(book, &id, |t| t.reported_cents += cents);
                }
                EngineEvent::ProviderRefused(why) => {
                    switch_to_fallback(book, host, &id, &redact_line(&why, &secrets), now_ms);
                    break;
                }
                EngineEvent::Propose(action) => {
                    propose(book, host, &id, &action, now_ms, fx);
                }
                EngineEvent::Finished { summary, links } => {
                    if let Some(t) = book.task_mut(&id) {
                        t.summary = Some(redact_line(&summary, &secrets));
                        t.links = links;
                    }
                    stop_engine(book, host, &id);
                    finish(book, &id, TaskState::Review, now_ms);
                    book.record(now_ms, "supervisor", "run.finished", Some(&id), "");
                    if let Some(t) = book.task(&id) {
                        if t.spec.deliver_to.contains(&crate::run::DeliverTo::Alert) {
                            fx.push(alert(
                                t,
                                "run_finished",
                                false,
                                "An agent run finished".into(),
                                format!(
                                    "{} on {} is ready to review.",
                                    t.spec.engine, t.spec.box_name
                                ),
                            ));
                        }
                    }
                }
                EngineEvent::Session(s) => {
                    if let Some(t) = book.task_mut(&id) {
                        t.session_id = Some(s.chars().take(100).collect());
                    }
                }
                EngineEvent::TurnDone(text) => {
                    if let Some(t) = book.task_mut(&id) {
                        let clean = redact_line(&text, &secrets);
                        t.last_reply =
                            Some(clean.chars().take(crate::run::MAX_REPLY_CHARS).collect());
                        t.turns += 1;
                        // a message that arrived while the agent was still answering is the next turn already
                        t.awaiting_input = t.inbox.is_empty();
                        t.push_log("waiting for your next message");
                    }
                }
                EngineEvent::Failed(e) => {
                    if let Some(t) = book.task_mut(&id) {
                        t.error = Some(redact_line(&e, &secrets));
                    }
                    checkpoint(book, host, &id, now_ms);
                    stop_engine(book, host, &id);
                    finish(book, &id, TaskState::Failed, now_ms);
                    book.record(now_ms, "supervisor", "run.failed", Some(&id), "");
                    if let Some(t) = book.task(&id) {
                        fx.push(alert(
                            t,
                            "run_failed",
                            false,
                            "An agent run failed".into(),
                            format!(
                                "{} on {} stopped with an error.",
                                t.spec.engine, t.spec.box_name
                            ),
                        ));
                    }
                }
            }
        }
    }
}

/// The provider refused the run. With a fallback the work is saved, the engine stopped and the run queued again on the
/// fallback model (it continues from its saved work); without one the run fails and says why. The switch is recorded on
/// the run and in the audit trail.
fn switch_to_fallback(book: &mut Book, host: &mut dyn AgentHost, id: &str, why: &str, now_ms: u64) {
    let fallback = book
        .task(id)
        .and_then(|t| t.model.as_ref())
        .and_then(|m| m.fallback.clone());
    checkpoint(book, host, id, now_ms);
    stop_engine(book, host, id);
    let reason: String = why.chars().take(200).collect();
    let Some(fb) = fallback else {
        if let Some(t) = book.task_mut(id) {
            t.error = Some(format!("the provider refused the run: {reason}"));
        }
        finish(book, id, TaskState::Failed, now_ms);
        book.record(
            now_ms,
            "supervisor",
            "run.failed",
            Some(id),
            "the provider refused the run and no fallback is set",
        );
        return;
    };
    if let Some(t) = book.task_mut(id) {
        if let Some(m) = t.model.as_mut() {
            m.fell_back_from = Some(ModelRef {
                provider_id: m.provider_id.clone(),
                model: m.model.clone(),
            });
            m.provider_id = fb.provider_id.clone();
            m.model = fb.model.clone();
            m.fallback = None;
            m.fallback_reason = Some(reason.clone());
        }
        t.state = TaskState::Queued;
        t.queue_reason = Some("switching to the fallback model".into());
        t.push_log(&format!(
            "the provider refused the run ({reason}); switching to {}",
            fb.model
        ));
    }
    book.record(
        now_ms,
        "supervisor",
        "run.model_fallback",
        Some(id),
        &format!("{}/{}", fb.provider_id, fb.model),
    );
}

/// Who a run's actions count as, and the orchestration it belongs to, for the permission engine.
fn actor_and_orchestration(origin: &crate::run::RunOrigin) -> (ActorKind, Option<String>) {
    use crate::run::RunOrigin;
    match origin {
        RunOrigin::Schedule { .. } => (ActorKind::Schedule, None),
        RunOrigin::Trigger { .. } => (ActorKind::Trigger, None),
        RunOrigin::Chat => (ActorKind::Chat, None),
        RunOrigin::Orchestration { id, .. } => (ActorKind::Agent, Some(id.clone())),
        RunOrigin::Manual => (ActorKind::Agent, None),
    }
}

/// Would a message a chat app adds to this run run under more authority than a chat app may use: the mode in force for it is
/// `auto` or `accept edits`, or a standing permission (an active grant) reaches its box, run or orchestration? The agent
/// acts on what it is sent, so a chat app is refused there (G7 R4, T-2). A run a chat app started is held to `ask` and never
/// covered by a grant, so it is fine.
pub fn broader_than_chat(book: &Book, id: &str, now_ms: u64) -> Result<bool, ActionError> {
    let t = book.task(id).ok_or(ActionError::NoSuchTask)?;
    let (actor, orchestration) = actor_and_orchestration(&t.spec.origin);
    let ctx = Ctx {
        person: t.spec.requested_by.clone(),
        actor,
        box_name: Some(t.spec.box_name.clone()),
        run_id: Some(t.id.clone()),
        orchestration,
        ..Ctx::default()
    };
    Ok(book.perms.broader_than_chat(&ctx, now_ms))
}

/// The permission engine's view of an action an agent proposes.
fn perm_request(t: &Task, action: &AgentAction, production: bool) -> (Ctx, PermAction) {
    let (actor, orchestration) = actor_and_orchestration(&t.spec.origin);
    let (perm, command) = match action {
        AgentAction::GitPush { .. } => (PermAction::GitPush, None),
        AgentAction::OpenPr { .. } => (PermAction::PrOpen, None),
        AgentAction::Command { argv } => (PermAction::CommandRun, Some(argv.clone())),
        AgentAction::Message { .. } => (PermAction::MessageSend, None),
        AgentAction::Spend { .. } => (PermAction::Spend, None),
        AgentAction::Touch { .. } => (PermAction::ResourceTouch, None),
    };
    let production = production
        || matches!(
            action,
            AgentAction::Touch {
                production: true,
                ..
            }
        );
    let branch = match action {
        AgentAction::GitPush { branch } => Some(branch.clone()),
        AgentAction::OpenPr { base } => Some(base.clone()),
        _ => None,
    };
    (
        Ctx {
            person: t.spec.requested_by.clone(),
            actor,
            box_name: Some(t.spec.box_name.clone()),
            project: None,
            run_id: Some(t.id.clone()),
            orchestration,
            env: if production {
                Environment::Production
            } else {
                Environment::Sandbox
            },
            path: branch,
            command,
            tool: None,
            server: None,
            writes: None,
            sensitive: false,
        },
        perm,
    )
}

/// What to ask when the engine says ask but the approval policy did not single the action out.
fn synthesized_ask(action: &AgentAction, production: bool) -> Ask {
    let kind = match action {
        AgentAction::GitPush { .. } => ActionKind::PushProtectedBranch,
        AgentAction::OpenPr { .. } => ActionKind::OpenPrToMain,
        AgentAction::Command { .. } => ActionKind::AskCommand,
        AgentAction::Message { .. } => ActionKind::OutboundMessage,
        AgentAction::Spend { .. } => ActionKind::SpendAboveThreshold,
        AgentAction::Touch { .. } => ActionKind::ProductionResource,
    };
    Ask {
        kind,
        action: describe(action),
        production,
    }
}

/// A rule or the mode refused an action outright: the engine is told no, the run goes on, and it is in the audit chain.
fn refuse_action(book: &mut Book, host: &mut dyn AgentHost, id: &str, reason: Reason, now_ms: u64) {
    let Some(t) = book.task(id) else { return };
    let (engine, handle) = (t.spec.engine.clone(), t.handle.clone().unwrap_or_default());
    if let Some(e) = engine_of(host, &engine) {
        let _ = e.resolve(&handle, false);
    }
    if let Some(t) = book.task_mut(id) {
        t.push_log(&format!("an action was refused: {}", reason.sentence()));
    }
    let _ = now_ms;
}

fn propose(
    book: &mut Book,
    host: &mut dyn AgentHost,
    id: &str,
    action: &AgentAction,
    now_ms: u64,
    fx: &mut Vec<AlertEffect>,
) {
    let Some(t) = book.task(id) else { return };
    let production = host
        .box_info(&t.spec.box_name)
        .is_some_and(|b| b.production);
    let policy_ask = classify(&book.policy, action, production);
    // The permission engine decides. The approval policy tells it what it singles out; production is the engine's own
    // gate, so it does not count as "singled out" here.
    let (mut ctx, perm_action) = perm_request(t, action, production);
    ctx.sensitive = policy_ask
        .as_ref()
        .is_some_and(|a| a.kind != ActionKind::ProductionResource);
    let decision = permissions::decide(&book.perms, &ctx, perm_action, now_ms);
    let actor = format!("engine:{}", t.spec.engine);
    let ev = permissions::audit_event(&decision, &ctx, perm_action, &actor, now_ms);
    book.record(now_ms, &actor, &ev.action, Some(id), &ev.detail);
    if let Some(g) = decision.grant.as_deref().filter(|_| decision.allowed()) {
        book.perms.use_grant(g);
        book.record(now_ms, &actor, "grant.used", Some(id), g);
    }
    let in_production = ctx.env == Environment::Production;
    let ask = match decision.effect {
        // No grant: the person can still answer this one request in the moment, which makes a one-use grant.
        Effect::Deny if decision.reason == Reason::ProductionNoGrant => {
            Some(policy_ask.unwrap_or_else(|| synthesized_ask(action, true)))
        }
        Effect::Deny => {
            refuse_action(book, host, id, decision.reason, now_ms);
            return;
        }
        Effect::Ask => Some(policy_ask.unwrap_or_else(|| synthesized_ask(action, in_production))),
        Effect::Allow => None,
    };
    let Some(t) = book.task(id) else { return };
    let (engine, handle) = (t.spec.engine.clone(), t.handle.clone().unwrap_or_default());
    let Some(ask) = ask else {
        if let Some(e) = engine_of(host, &engine) {
            let _ = e.resolve(&handle, true);
        }
        return;
    };
    book.next_seq += 1;
    let aid = format!("a{}", book.next_seq);
    let needs_step_up = ask.production || book.policy.step_up.contains(&ask.kind);
    let t = match book.task(id) {
        Some(t) => t.clone(),
        None => return,
    };
    book.approvals.push(ApprovalRequest {
        id: aid.clone(),
        task_id: id.to_string(),
        kind: ask.kind,
        action: ask.action.clone(),
        box_name: t.spec.box_name.clone(),
        asked_by: format!("{} for {}", t.spec.engine, t.spec.requested_by),
        production: ask.production,
        needs_step_up,
        state: ApprovalState::Pending,
        created_ms: now_ms,
        expires_ms: now_ms + book.policy.expiry_s * 1000,
        reminders: 0,
        decided_by: None,
        decided_ms: None,
        decided_with_step_up: false,
        delivered: false,
        used: false,
    });
    if let Some(t) = book.task_mut(id) {
        t.state = TaskState::NeedsYou;
        t.needs = Some(Needs::Approval {
            approval_id: aid.clone(),
        });
        t.push_log("waiting for a person to approve an action");
    }
    book.record(
        now_ms,
        &format!("engine:{}", t.spec.engine),
        "approval.requested",
        Some(id),
        &ask.action,
    );
    fx.push(alert(
        &t,
        "approval_needed",
        true,
        "An agent needs your approval".into(),
        format!(
            "{} on {} wants to: {}",
            t.spec.engine, t.spec.box_name, ask.action
        ),
    ));
}

fn pause_for(
    book: &mut Book,
    host: &mut dyn AgentHost,
    id: &str,
    needs: Needs,
    now_ms: u64,
    fx: &mut Vec<AlertEffect>,
) {
    checkpoint(book, host, id, now_ms);
    stop_engine(book, host, id);
    let Some(t) = book.task_mut(id) else { return };
    t.state = TaskState::NeedsYou;
    t.needs = Some(needs.clone());
    t.push_log("paused at a limit; the work is saved");
    let t = t.clone();
    let (title, body, action) = match &needs {
        Needs::SpendCap => (
            "An agent reached its spend limit",
            format!(
                "{} on {} used {} and is paused. Add budget or stop it.",
                t.spec.engine,
                t.spec.box_name,
                money(t.spend_cents)
            ),
            "run.paused_spend",
        ),
        Needs::TimeCap => (
            "An agent reached its time limit",
            format!(
                "{} on {} ran {} minutes and is paused. Add time or stop it.",
                t.spec.engine,
                t.spec.box_name,
                t.active_s / 60
            ),
            "run.paused_time",
        ),
        Needs::TokenCap => (
            "An agent reached its token limit",
            format!(
                "{} on {} is paused at its token limit. Add tokens or stop it.",
                t.spec.engine, t.spec.box_name
            ),
            "run.paused_tokens",
        ),
        Needs::MonthlyCap { scope } => (
            "A monthly spend limit was reached",
            format!(
                "The {scope} limit was reached, so {} on {} is paused. Raise the limit or stop it.",
                t.spec.engine, t.spec.box_name
            ),
            "run.paused_monthly",
        ),
        Needs::Approval { .. } | Needs::Paused => return,
    };
    book.record(now_ms, "supervisor", action, Some(id), "");
    fx.push(alert(&t, "run_needs_you", true, title.into(), body));
}

fn person_cap(book: &Book, person: &str) -> Option<u64> {
    book.caps
        .per_person
        .get(person)
        .copied()
        .or(book.caps.person_monthly_cents)
}

/// The one monthly-cap check, for every source: the fleet's and the person's spend limits (Settings -> Approvals) and
/// the model provider's own monthly cap (Settings -> Models). The first that holds names its scope in words.
fn monthly_block(
    book: &Book,
    host: &mut dyn AgentHost,
    task: &Task,
    now_ms: u64,
) -> Option<String> {
    if let Some(s) = scope_over(book, &task.spec.requested_by) {
        return Some(s);
    }
    task.model
        .as_ref()
        .and_then(|m| host.model_cap_scope(&m.provider_id, now_ms))
}

fn scope_over(book: &Book, person: &str) -> Option<String> {
    if book
        .caps
        .fleet_monthly_cents
        .is_some_and(|c| book.ledger.fleet_cents >= c)
    {
        return Some("fleet monthly".into());
    }
    let spent = book.ledger.by_person.get(person).copied().unwrap_or(0);
    if person_cap(book, person).is_some_and(|c| spent >= c) {
        return Some(format!("monthly limit for {person}"));
    }
    None
}

fn check_caps(book: &mut Book, host: &mut dyn AgentHost, now_ms: u64, fx: &mut Vec<AlertEffect>) {
    let running: Vec<String> = book
        .tasks
        .iter()
        .filter(|t| t.state == TaskState::Running)
        .map(|t| t.id.clone())
        .collect();
    for id in running {
        let Some(t) = book.task(&id) else { continue };
        let needs = if t.spend_cap().is_some_and(|c| t.spend_cents >= c) {
            Some(Needs::SpendCap)
        } else if t.runtime_cap().is_some_and(|c| t.active_s >= c) {
            Some(Needs::TimeCap)
        } else if t.token_cap().is_some_and(|c| t.tokens >= c) {
            Some(Needs::TokenCap)
        } else {
            monthly_block(book, host, t, now_ms).map(|scope| Needs::MonthlyCap { scope })
        };
        if let Some(n) = needs {
            pause_for(book, host, &id, n, now_ms, fx);
        }
    }
}

/// A run paused by a monthly cap goes back in the queue once the cap no longer holds (raised, or a new month).
fn resume_monthly(book: &mut Book, host: &mut dyn AgentHost, now_ms: u64) {
    let ids: Vec<String> = book
        .tasks
        .iter()
        .filter(|t| {
            t.state == TaskState::NeedsYou && matches!(t.needs, Some(Needs::MonthlyCap { .. }))
        })
        .filter(|t| monthly_block(book, &mut *host, t, now_ms).is_none())
        .map(|t| t.id.clone())
        .collect();
    for id in ids {
        if let Some(t) = book.task_mut(&id) {
            t.state = TaskState::Queued;
            t.needs = None;
        }
        book.record(now_ms, "supervisor", "run.resumed_monthly", Some(&id), "");
    }
}

/// A queued run that would break a monthly limit waits under "Needs you", with the limit named, instead of starting. It
/// goes back in the queue by itself when the limit is raised or the month turns.
fn hold_for_cap(book: &mut Book, id: &str, scope: String, now_ms: u64, fx: &mut Vec<AlertEffect>) {
    let Some(t) = book.task_mut(id) else { return };
    t.state = TaskState::NeedsYou;
    t.needs = Some(Needs::MonthlyCap {
        scope: scope.clone(),
    });
    t.queue_reason = None;
    t.push_log(&format!("not started: the {scope} limit was reached"));
    let t = t.clone();
    book.record(now_ms, "supervisor", "run.held_monthly", Some(id), &scope);
    fx.push(alert(
        &t,
        "run_needs_you",
        true,
        "A monthly spend limit was reached".into(),
        format!(
            "The {scope} limit was reached, so {} on {} has not started. Raise the limit or stop it.",
            t.spec.engine, t.spec.box_name
        ),
    ));
}

fn admit(book: &mut Book, host: &mut dyn AgentHost, now_ms: u64, fx: &mut Vec<AlertEffect>) {
    let mut queued: Vec<(bool, u64, String)> = book
        .tasks
        .iter()
        .filter(|t| t.state == TaskState::Queued && !t.cancel_requested)
        .map(|t| (t.wip_branch.is_none(), t.created_ms, t.id.clone()))
        .collect();
    queued.sort();
    for (_, _, id) in queued {
        let Some(t) = book.task(&id) else { continue };
        let (box_name, who, engine) = (
            t.spec.box_name.clone(),
            t.spec.requested_by.clone(),
            t.spec.engine.clone(),
        );
        let on_fallback = t.model.as_ref().is_some_and(|m| m.fell_back_from.is_some());
        // the fleet's and the person's spend limits are cheap to read, so they come first
        if let Some(scope) = scope_over(book, &who) {
            hold_for_cap(book, &id, scope, now_ms, fx);
            continue;
        }
        let reason = (|| -> Option<String> {
            let Some(info) = host.box_info(&box_name) else {
                return Some("this box has no agent to run on yet".into());
            };
            if !info.running {
                return Some("the box is paused".into());
            }
            let active = book
                .tasks
                .iter()
                .filter(|o| o.spec.box_name == box_name && holds_slot(o))
                .count();
            if active >= size_cap(info.size) {
                return Some(format!(
                    "the box is running {active} runs, the most for its size"
                ));
            }
            if let Some(why) = host.box_unavailable(&box_name) {
                return Some(why);
            }
            if !host.has_room(&box_name) {
                return Some("waiting for free memory on the box".into());
            }
            None
        })();
        if let Some(r) = reason {
            if let Some(t) = book.task_mut(&id) {
                t.queue_reason = Some(r);
            }
            continue;
        }
        // the provider and model; the credentials are read now and go to the engine at start only
        let Some(spec) = book.task(&id).map(|t| t.spec.clone()) else {
            continue;
        };
        let grant = ModelGrant {
            cap_micros: book.task(&id).and_then(|t| {
                t.spend_cap()
                    .map(|c| c.saturating_sub(t.spend_cents) * 10_000)
            }),
            now_ms,
        };
        let assignment = match host.resolve_model(&id, &spec, on_fallback, grant) {
            Ok(a) => a,
            Err(why) => {
                if let Some(t) = book.task_mut(&id) {
                    t.queue_reason = Some(format!("the model is not ready: {why}"));
                }
                continue;
            }
        };
        if let Some(a) = &assignment {
            if let Some(scope) = host.model_cap_scope(&a.provider_id, now_ms) {
                host.end_run(&id);
                hold_for_cap(book, &id, scope, now_ms, fx);
                continue;
            }
        }
        let Some(t) = book.task(&id) else { continue };
        let mut secret_env = host.secret_env(&t.spec);
        let (tid, tspec) = (t.id.clone(), t.spec.clone());
        secret_env.extend(host.run_env(&tid, &tspec));
        if let Some(a) = &assignment {
            secret_env.extend(a.env.iter().map(|(k, v)| (k.clone(), v.clone())));
        }
        let req = EngineStart {
            task_id: t.id.clone(),
            box_name: box_name.clone(),
            prompt: t.spec.prompt.clone(),
            skill: t.spec.skill.clone(),
            repo: t.spec.repo.clone(),
            branch: t.spec.branch.clone(),
            resume_from: t.wip_branch.clone(),
            secret_env,
            deny_commands: book.policy.ask_commands.clone(),
            max_runtime_s: t.runtime_cap().map(|c| c.saturating_sub(t.active_s).max(1)),
            model: assignment.as_ref().map(|a| a.model.clone()),
            on_fallback,
            interactive: t.spec.interactive,
            resume_session: t.session_id.clone(),
            ask_for_edits: t.spec.origin == crate::run::RunOrigin::Chat,
        };
        let started = match engine_of(host, &engine) {
            Some(e) => e.start(&req).map_err(|e| e.to_string()),
            None => Err("that engine is not set up".to_string()),
        };
        match started {
            Ok(h) => {
                if let Some(t) = book.task_mut(&id) {
                    t.handle = Some(h);
                    t.state = TaskState::Running;
                    t.queue_reason = None;
                    t.started_ms.get_or_insert(now_ms);
                    if let Some(a) = assignment {
                        // names only; a fallback already used stays on the record
                        let (from, reason) = t
                            .model
                            .take()
                            .map(|m| (m.fell_back_from, m.fallback_reason))
                            .unwrap_or_default();
                        t.model = Some(RunModel {
                            provider_id: a.provider_id,
                            model: a.model,
                            fallback: a.fallback,
                            fell_back_from: from,
                            fallback_reason: reason,
                        });
                    }
                    t.push_log("started");
                }
                book.record(now_ms, "supervisor", "run.started", Some(&id), &box_name);
            }
            Err(e) => {
                host.end_run(&id);
                if let Some(t) = book.task_mut(&id) {
                    t.error = Some(e.chars().take(200).collect());
                }
                finish(book, &id, TaskState::Failed, now_ms);
                book.record(
                    now_ms,
                    "supervisor",
                    "run.failed",
                    Some(&id),
                    "could not start",
                );
            }
        }
    }
}

/// A run that holds a place on its box: running, or waiting for an answer with its engine still up.
fn holds_slot(t: &Task) -> bool {
    t.handle.is_some() && t.state.is_active()
}

// ---- what a person can do to a run ------------------------------------------------------------------------------

/// Stop a run. A queued one is cancelled at once; a running one is checkpointed and stopped at the next tick.
pub fn cancel(book: &mut Book, id: &str, actor: &str, now_ms: u64) -> Result<(), ActionError> {
    let t = book.task_mut(id).ok_or(ActionError::NoSuchTask)?;
    if t.state.is_terminal() || t.state == TaskState::Review {
        return Err(ActionError::WrongState(t.state));
    }
    if t.state == TaskState::Queued || (t.state == TaskState::NeedsYou && t.handle.is_none()) {
        t.state = TaskState::Cancelled;
        t.needs = None;
        t.finished_ms = Some(now_ms);
    } else {
        t.cancel_requested = true;
    }
    book.record(now_ms, actor, "run.cancel", Some(id), "");
    Ok(())
}

/// Start a failed or cancelled run again as a new run (its saved work is picked up through its branch).
pub fn retry(book: &mut Book, id: &str, actor: &str, now_ms: u64) -> Result<String, ActionError> {
    let t = book.task(id).ok_or(ActionError::NoSuchTask)?.clone();
    if !matches!(t.state, TaskState::Failed | TaskState::Cancelled) {
        return Err(ActionError::WrongState(t.state));
    }
    let mut spec = t.spec.clone();
    spec.idempotency_key = None;
    let (new_id, _) = book
        .enqueue(spec, now_ms, Some(id.to_string()))
        .map_err(|_| ActionError::WrongState(t.state))?;
    if let Some(n) = book.task_mut(&new_id) {
        n.wip_branch = t.wip_branch.clone();
    }
    book.record(now_ms, actor, "run.retry", Some(&new_id), id);
    Ok(new_id)
}

/// Move a finished run to Review ("look at this"), or accept a reviewed one as Done.
pub fn set_review(
    book: &mut Book,
    id: &str,
    review: bool,
    actor: &str,
    now_ms: u64,
) -> Result<(), ActionError> {
    let t = book.task_mut(id).ok_or(ActionError::NoSuchTask)?;
    let ok = if review {
        matches!(
            t.state,
            TaskState::Done | TaskState::Failed | TaskState::Cancelled
        )
    } else {
        t.state == TaskState::Review
    };
    if !ok {
        return Err(ActionError::WrongState(t.state));
    }
    t.state = if review {
        TaskState::Review
    } else {
        TaskState::Done
    };
    book.record(
        now_ms,
        actor,
        if review { "run.review" } else { "run.accept" },
        Some(id),
        "",
    );
    Ok(())
}

/// Add budget to a run paused at a cap and put it back in the queue; it continues from its saved work.
pub fn resume(
    book: &mut Book,
    id: &str,
    add: AddBudget,
    actor: &str,
    now_ms: u64,
) -> Result<(), ActionError> {
    let t = book.task_mut(id).ok_or(ActionError::NoSuchTask)?;
    match (&t.state, &t.needs) {
        (
            TaskState::NeedsYou,
            Some(
                Needs::SpendCap
                | Needs::TimeCap
                | Needs::TokenCap
                | Needs::MonthlyCap { .. }
                | Needs::Paused,
            ),
        ) => {}
        _ => return Err(ActionError::WrongState(t.state)),
    }
    let monthly = matches!(t.needs, Some(Needs::MonthlyCap { .. }));
    t.extra_spend_cents += add.cents;
    t.extra_runtime_s += add.seconds;
    t.extra_tokens += add.tokens;
    t.needs = None;
    t.state = TaskState::Queued;
    book.record(
        now_ms,
        actor,
        "run.resume",
        Some(id),
        &format!(
            "added {} cents, {} s, {} tokens",
            add.cents, add.seconds, add.tokens
        ),
    );
    let _ = monthly;
    Ok(())
}

/// A person's answer to an approval request. `step_up_fresh` is whether they passed a second factor just now (true
/// outside sign-in mode, where there is no second factor to ask for).
pub fn decide(
    book: &mut Book,
    approval_id: &str,
    approve: bool,
    person: &str,
    step_up_fresh: bool,
    now_ms: u64,
) -> Result<(), ActionError> {
    let factor = step_up_fresh.then_some(SecondFactor::StepUp);
    decide_with(book, approval_id, approve, person, factor, now_ms)
}

/// As [`decide`], saying how the person confirmed (`None`: they did not). Approving a request on production makes a
/// one-use grant for it, so the record of what was let through is the same as for a time-boxed grant, and it names the
/// factor honestly: a typed confirmation or a signed-out session is recorded as exactly that.
pub fn decide_with(
    book: &mut Book,
    approval_id: &str,
    approve: bool,
    person: &str,
    factor: Option<SecondFactor>,
    now_ms: u64,
) -> Result<(), ActionError> {
    let a = book
        .approval(approval_id)
        .ok_or(ActionError::NoSuchApproval)?
        .clone();
    if a.state != ApprovalState::Pending {
        return Err(ActionError::AlreadyDecided);
    }
    let requested_by = book
        .task(&a.task_id)
        .map(|t| t.spec.requested_by.clone())
        .unwrap_or_default();
    if !book.policy.may_decide(person, &requested_by) {
        book.record(
            now_ms,
            person,
            "approval.refused",
            Some(&a.task_id),
            "not an approver",
        );
        return Err(ActionError::NotAllowed);
    }
    // Approving needs the second factor where the request asks for it; denying never does.
    if approve && a.needs_step_up && factor.is_none() {
        return Err(ActionError::StepUpRequired);
    }
    if let Some(x) = book.approvals.iter_mut().find(|x| x.id == approval_id) {
        x.state = if approve {
            ApprovalState::Approved
        } else {
            ApprovalState::Denied
        };
        x.decided_by = Some(person.to_string());
        x.decided_ms = Some(now_ms);
        x.decided_with_step_up = factor.is_some() && a.needs_step_up;
    }
    book.record(
        now_ms,
        person,
        if approve {
            "approval.approved"
        } else {
            "approval.denied"
        },
        Some(&a.task_id),
        &a.action,
    );
    if approve && a.production {
        let f = factor.unwrap_or(SecondFactor::NoSignIn);
        let made = book.perms.create_grant(
            NewGrant {
                granted_by: person.to_string(),
                scope: Scope::Run,
                scope_id: a.task_id.clone(),
                actions: vec!["*".into()],
                reason: format!("approved request {}", a.id),
                minutes: 1,
                factor: f,
                allow_unattended: false,
                max_uses: Some(1),
            },
            now_ms,
        );
        if let Ok(g) = made {
            // It covers exactly the action approved, which the engine is handed next; it is spent at once.
            book.perms.use_grant(&g.id);
            book.record(
                now_ms,
                person,
                "grant.created",
                Some(&a.task_id),
                &format!("{} one use, via {:?}", g.id, f),
            );
        }
    }
    Ok(())
}

/// Counts of tasks by state, for the board's headings.
pub fn counts(book: &Book) -> BTreeMap<TaskState, usize> {
    let mut m = BTreeMap::new();
    for t in &book.tasks {
        *m.entry(t.state).or_insert(0) += 1;
    }
    m
}

/// Used by tests and the demo provider: a host with a fixed set of boxes and a fake engine.
pub struct SimHost {
    pub boxes: BTreeMap<String, BoxInfo>,
    pub engine: crate::agent_engine::FakeEngine,
    pub memory_ok: bool,
    pub checkpoints: Vec<String>,
    pub checkpoint_fails: bool,
    pub key: Option<String>,
    /// The provider and model every run gets (when set), and its fallback.
    pub model: Option<(String, String)>,
    pub fallback: Option<(String, String)>,
    /// Why the model cannot be resolved (a key missing), when set.
    pub model_error: Option<String>,
    /// Providers whose monthly cap is reached.
    pub capped: Vec<String>,
    /// Every usage record, in order.
    pub usage: Vec<ModelUsage>,
    /// What one token costs, in millionths of a dollar (the same for input and output).
    pub micros_per_token: u64,
    /// The runs whose credentials were ended, in order.
    pub ended: Vec<String>,
    /// Usage a broker would report, drained once per run.
    pub broker_usage: Vec<BrokeredUsage>,
    pub via_broker: bool,
}

impl SimHost {
    pub fn new() -> Self {
        Self {
            boxes: BTreeMap::new(),
            engine: crate::agent_engine::FakeEngine::default(),
            memory_ok: true,
            checkpoints: Vec::new(),
            checkpoint_fails: false,
            key: None,
            model: None,
            fallback: None,
            model_error: None,
            capped: Vec::new(),
            usage: Vec::new(),
            micros_per_token: 0,
            ended: Vec::new(),
            broker_usage: Vec::new(),
            via_broker: false,
        }
    }
    pub fn with_box(mut self, name: &str, size: Size, production: bool) -> Self {
        self.boxes.insert(
            name.to_string(),
            BoxInfo {
                size,
                running: true,
                production,
            },
        );
        self
    }
}

impl Default for SimHost {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentHost for SimHost {
    fn box_info(&self, box_name: &str) -> Option<BoxInfo> {
        self.boxes.get(box_name).copied()
    }
    fn has_room(&mut self, _: &str) -> bool {
        self.memory_ok
    }
    fn engine(&mut self, id: &str) -> Option<&mut dyn AgentEngine> {
        (id == "fake").then_some(&mut self.engine as &mut dyn AgentEngine)
    }
    fn checkpoint(&mut self, box_name: &str, _: Option<&str>) -> Result<Option<String>, String> {
        if self.checkpoint_fails {
            return Err("the box did not answer".into());
        }
        let b = format!("wip/{box_name}/{}", self.checkpoints.len() + 1);
        self.checkpoints.push(b.clone());
        Ok(Some(b))
    }
    fn secrets(&self, _: &Task) -> Vec<String> {
        self.key.iter().cloned().collect()
    }
    fn secret_env(&self, _: &RunSpec) -> BTreeMap<String, String> {
        self.key
            .iter()
            .map(|k| ("ENGINE_KEY".to_string(), k.clone()))
            .collect()
    }
    fn resolve_model(
        &mut self,
        _: &str,
        spec: &RunSpec,
        use_fallback: bool,
        _: ModelGrant,
    ) -> Result<Option<ModelAssignment>, String> {
        if let Some(e) = &self.model_error {
            return Err(e.clone());
        }
        let primary = spec
            .model
            .as_ref()
            .map(|m| (m.provider_id.clone(), m.model.clone()))
            .or_else(|| self.model.clone());
        let pick = if use_fallback {
            self.fallback.clone()
        } else {
            primary
        };
        Ok(pick.map(|(provider_id, model)| ModelAssignment {
            env: [("MODEL_KEY".to_string(), format!("key-for-{provider_id}"))].into(),
            fallback: (!use_fallback)
                .then(|| self.fallback.clone())
                .flatten()
                .map(|(provider_id, model)| ModelRef { provider_id, model }),
            provider_id,
            model,
        }))
    }
    fn end_run(&mut self, task_id: &str) {
        self.ended.push(task_id.to_string());
    }
    fn drain_usage(&mut self, _: &str) -> Vec<BrokeredUsage> {
        std::mem::take(&mut self.broker_usage)
    }
    fn usage_via_broker(&self, _: &str) -> bool {
        self.via_broker
    }
    fn model_cap_scope(&mut self, provider_id: &str, _: u64) -> Option<String> {
        self.capped
            .iter()
            .any(|p| p == provider_id)
            .then(|| format!("monthly limit of the {provider_id} model provider"))
    }
    fn record_usage(&mut self, usage: &ModelUsage) {
        self.usage.push(usage.clone());
    }
    fn estimate_micros(&mut self, u: &ModelUsage) -> Option<u64> {
        (self.micros_per_token > 0)
            .then(|| (u.input_tokens + u.output_tokens) * self.micros_per_token)
    }
}

/// Policy kinds as the board shows them (for the filter).
pub fn kind_name(k: ActionKind) -> &'static str {
    match k {
        ActionKind::PushProtectedBranch => "push_protected_branch",
        ActionKind::OpenPrToMain => "open_pr_to_main",
        ActionKind::AskCommand => "ask_command",
        ActionKind::OutboundMessage => "outbound_message",
        ActionKind::SpendAboveThreshold => "spend_above_threshold",
        ActionKind::ProductionResource => "production_resource",
        ActionKind::ToolCall => "tool_call",
    }
}

#[allow(dead_code)]
fn _policy_is_used(_: &ApprovalPolicy) {}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::run::{RunCaps, RunOrigin};

    fn spec(prompt: &str, box_name: &str) -> RunSpec {
        RunSpec {
            engine: "fake".into(),
            prompt: prompt.into(),
            skill: None,
            box_name: box_name.into(),
            repo: Some("web".into()),
            branch: None,
            caps: RunCaps::default(),
            deliver_to: Vec::new(),
            requested_by: "ada".into(),
            origin: RunOrigin::Manual,
            idempotency_key: None,
            model: None,
            interactive: false,
        }
    }

    fn add(book: &mut Book, prompt: &str, box_name: &str) -> String {
        book.enqueue(spec(prompt, box_name), 1000, None).unwrap().0
    }

    fn run_ticks(
        sup: &mut Supervisor,
        book: &mut Book,
        host: &mut SimHost,
        from: u64,
        n: u64,
    ) -> Vec<AlertEffect> {
        let mut all = Vec::new();
        for i in 0..n {
            all.extend(sup.tick(book, host, from + i * 1000, "2026-11"));
        }
        all
    }

    fn state(book: &Book, id: &str) -> TaskState {
        book.task(id).unwrap().state
    }

    #[test]
    fn a_box_runs_as_many_as_its_size_allows_and_the_rest_wait() {
        let mut book = Book::default();
        let mut host = SimHost::new().with_box("alpha", Size::S, false);
        let ids: Vec<String> = (0..4)
            .map(|_| add(&mut book, "sim:steps=1000", "alpha"))
            .collect();
        let mut sup = Supervisor::new();
        run_ticks(&mut sup, &mut book, &mut host, 2000, 3);
        let running = ids
            .iter()
            .filter(|i| state(&book, i) == TaskState::Running)
            .count();
        assert_eq!(running, size_cap(Size::S));
        assert_eq!(running, 2);
        let waiting = book.task(&ids[3]).unwrap();
        assert_eq!(waiting.state, TaskState::Queued);
        assert!(waiting
            .queue_reason
            .as_deref()
            .unwrap()
            .contains("most for its size"));
        // a slot frees when one is cancelled, and the oldest waiting run takes it
        cancel(&mut book, &ids[0], "ada", 6000).unwrap();
        run_ticks(&mut sup, &mut book, &mut host, 7000, 2);
        assert_eq!(state(&book, &ids[0]), TaskState::Cancelled);
        assert_eq!(state(&book, &ids[2]), TaskState::Running);
        assert_eq!(state(&book, &ids[3]), TaskState::Queued);
    }

    #[test]
    fn the_size_caps_are_the_documented_ones() {
        let v: Vec<usize> = Size::STANDARD.iter().map(|s| size_cap(*s)).collect();
        assert_eq!(v, vec![1, 2, 4, 6, 8, 16]);
    }

    #[test]
    fn a_run_waits_when_the_box_is_short_of_memory_or_paused() {
        let mut book = Book::default();
        let mut host = SimHost::new().with_box("alpha", Size::M, false);
        host.memory_ok = false;
        let a = add(&mut book, "x", "alpha");
        let mut sup = Supervisor::new();
        run_ticks(&mut sup, &mut book, &mut host, 2000, 2);
        assert_eq!(
            book.task(&a).unwrap().queue_reason.as_deref(),
            Some("waiting for free memory on the box")
        );
        host.memory_ok = true;
        host.boxes.get_mut("alpha").unwrap().running = false;
        run_ticks(&mut sup, &mut book, &mut host, 5000, 1);
        assert_eq!(
            book.task(&a).unwrap().queue_reason.as_deref(),
            Some("the box is paused")
        );
        host.boxes.get_mut("alpha").unwrap().running = true;
        run_ticks(&mut sup, &mut book, &mut host, 7000, 1);
        assert_eq!(state(&book, &a), TaskState::Running);
    }

    #[test]
    fn only_a_run_a_chat_app_started_is_asked_to_ask_for_edits() {
        let mut book = Book::default();
        let mut host = SimHost::new().with_box("alpha", Size::M, false);
        let mut sup = Supervisor::new();
        let mut chat = spec("from chat", "alpha");
        chat.origin = RunOrigin::Chat;
        book.enqueue(chat, 1000, None).unwrap();
        book.enqueue(spec("from the dashboard", "alpha"), 1000, None)
            .unwrap();
        run_ticks(&mut sup, &mut book, &mut host, 2000, 3);
        let mut seen = host.engine.ask_for_edits.clone();
        seen.sort();
        assert_eq!(seen, vec![false, true]);
    }

    #[test]
    fn a_run_that_reaches_its_spend_cap_pauses_saves_its_work_and_asks_then_resumes() {
        let mut book = Book::default();
        let mut host = SimHost::new().with_box("alpha", Size::M, false);
        let mut s = spec("sim:steps=100 sim:cents=10", "alpha");
        s.caps.max_spend_cents = Some(25);
        let id = book.enqueue(s, 1000, None).unwrap().0;
        let mut sup = Supervisor::new();
        let fx = run_ticks(&mut sup, &mut book, &mut host, 2000, 6);
        let t = book.task(&id).unwrap();
        assert_eq!(t.state, TaskState::NeedsYou);
        assert_eq!(t.needs, Some(Needs::SpendCap));
        assert_eq!(t.wip_branch.as_deref(), Some("wip/alpha/1"));
        assert!(
            t.handle.is_none(),
            "the engine was stopped, nothing is running up cost"
        );
        assert_eq!(host.engine.stopped.len(), 1);
        let a = fx.iter().find(|a| a.kind == "run_needs_you").unwrap();
        assert!(a.urgent && a.body.contains("$0.30"), "{a:?}");
        let spent = t.spend_cents;
        // nothing more is spent while it waits
        run_ticks(&mut sup, &mut book, &mut host, 9000, 3);
        assert_eq!(book.task(&id).unwrap().spend_cents, spent);
        // more budget: it continues from the saved branch
        resume(
            &mut book,
            &id,
            AddBudget {
                cents: 1000,
                ..Default::default()
            },
            "ada",
            12_000,
        )
        .unwrap();
        run_ticks(&mut sup, &mut book, &mut host, 13_000, 2);
        assert_eq!(state(&book, &id), TaskState::Running);
        assert_eq!(
            host.engine.resumes.last().unwrap().as_deref(),
            Some("wip/alpha/1")
        );
        assert!(book.audit.iter().any(|r| r.action == "run.paused_spend"));
        assert!(book
            .audit
            .iter()
            .any(|r| r.action == "run.resume" && r.actor == "ada"));
    }

    #[test]
    fn a_paused_run_can_be_stopped_and_loses_nothing() {
        let mut book = Book::default();
        let mut host = SimHost::new().with_box("alpha", Size::M, false);
        let mut s = spec("sim:steps=100 sim:cents=50", "alpha");
        s.caps.max_spend_cents = Some(60);
        let id = book.enqueue(s, 1000, None).unwrap().0;
        let mut sup = Supervisor::new();
        run_ticks(&mut sup, &mut book, &mut host, 2000, 4);
        assert_eq!(state(&book, &id), TaskState::NeedsYou);
        cancel(&mut book, &id, "ada", 9000).unwrap();
        assert_eq!(state(&book, &id), TaskState::Cancelled);
        assert!(
            book.task(&id).unwrap().wip_branch.is_some(),
            "the saved branch is kept"
        );
    }

    #[test]
    fn the_time_and_token_caps_pause_too_and_active_time_excludes_waiting() {
        let mut book = Book::default();
        let mut host = SimHost::new().with_box("alpha", Size::M, false);
        let mut s = spec("sim:steps=100", "alpha");
        s.caps.max_runtime_s = Some(3);
        let t1 = book.enqueue(s, 1000, None).unwrap().0;
        let mut s = spec("sim:steps=100 sim:tokens=400", "alpha");
        s.caps.max_tokens = Some(1000);
        let t2 = book.enqueue(s, 1000, None).unwrap().0;
        let mut sup = Supervisor::new();
        run_ticks(&mut sup, &mut book, &mut host, 2000, 8);
        assert_eq!(book.task(&t1).unwrap().needs, Some(Needs::TimeCap));
        assert_eq!(book.task(&t2).unwrap().needs, Some(Needs::TokenCap));
        let active = book.task(&t1).unwrap().active_s;
        run_ticks(&mut sup, &mut book, &mut host, 20_000, 5);
        assert_eq!(book.task(&t1).unwrap().active_s, active);
    }

    #[test]
    fn if_saving_the_work_fails_the_run_is_still_stopped_and_says_so() {
        let mut book = Book::default();
        let mut host = SimHost::new().with_box("alpha", Size::M, false);
        host.checkpoint_fails = true;
        let mut s = spec("sim:steps=100 sim:cents=50", "alpha");
        s.caps.max_spend_cents = Some(60);
        let id = book.enqueue(s, 1000, None).unwrap().0;
        let mut sup = Supervisor::new();
        run_ticks(&mut sup, &mut book, &mut host, 2000, 4);
        let t = book.task(&id).unwrap();
        assert_eq!(t.state, TaskState::NeedsYou);
        assert!(t.log.iter().any(|l| l.contains("saving the work failed")));
        assert!(book
            .audit
            .iter()
            .any(|r| r.action == "run.checkpoint_failed"));
    }

    #[test]
    fn monthly_caps_stop_new_runs_and_pause_running_ones_until_raised() {
        let mut book = Book::default();
        book.caps.person_monthly_cents = Some(20);
        let mut host = SimHost::new().with_box("alpha", Size::M, false);
        let a = add(&mut book, "sim:steps=100 sim:cents=10", "alpha");
        let mut sup = Supervisor::new();
        run_ticks(&mut sup, &mut book, &mut host, 2000, 5);
        assert!(matches!(
            book.task(&a).unwrap().needs,
            Some(Needs::MonthlyCap { .. })
        ));
        // a run that would start over the limit waits under "Needs you", with the limit named
        let b = add(&mut book, "sim:steps=100", "alpha");
        run_ticks(&mut sup, &mut book, &mut host, 9000, 2);
        assert_eq!(state(&book, &b), TaskState::NeedsYou);
        assert!(matches!(
            &book.task(&b).unwrap().needs,
            Some(Needs::MonthlyCap { scope }) if scope.contains("limit")
        ));
        // someone else is unaffected, and a raised cap lets both continue
        book.caps.person_monthly_cents = Some(100_000);
        run_ticks(&mut sup, &mut book, &mut host, 12_000, 3);
        assert_eq!(state(&book, &a), TaskState::Running);
        assert_eq!(state(&book, &b), TaskState::Running);
        // a new month starts from zero
        book.caps.person_monthly_cents = Some(15);
        sup.tick(&mut book, &mut host, 20_000, "2026-12");
        assert_eq!(book.ledger.month, "2026-12");
    }

    #[test]
    fn the_fleet_cap_counts_everyone() {
        let mut book = Book::default();
        book.caps.fleet_monthly_cents = Some(15);
        let mut host = SimHost::new().with_box("alpha", Size::M, false);
        let a = add(&mut book, "sim:steps=100 sim:cents=10", "alpha");
        let mut other = spec("sim:steps=100 sim:cents=10", "alpha");
        other.requested_by = "bo".into();
        let b = book.enqueue(other, 1000, None).unwrap().0;
        let mut sup = Supervisor::new();
        run_ticks(&mut sup, &mut book, &mut host, 2000, 4);
        for id in [&a, &b] {
            assert!(
                matches!(book.task(id).unwrap().needs, Some(Needs::MonthlyCap { .. })),
                "{id}"
            );
        }
    }

    #[test]
    fn a_risky_action_waits_for_a_person_and_the_decision_reaches_the_engine() {
        let mut book = Book::default();
        let mut host = SimHost::new().with_box("alpha", Size::M, false);
        let id = add(&mut book, "sim:steps=100 sim:push=main", "alpha");
        let mut sup = Supervisor::new();
        let fx = run_ticks(&mut sup, &mut book, &mut host, 2000, 4);
        let t = book.task(&id).unwrap();
        assert_eq!(t.state, TaskState::NeedsYou);
        let aid = match &t.needs {
            Some(Needs::Approval { approval_id }) => approval_id.clone(),
            other => panic!("{other:?}"),
        };
        let a = book.approval(&aid).unwrap();
        assert_eq!(a.action, "git push origin main");
        assert_eq!(a.kind, ActionKind::PushProtectedBranch);
        assert!(a.needs_step_up && a.asked_by.contains("ada"));
        assert!(fx.iter().any(|f| f.kind == "approval_needed" && f.urgent));
        // approving without the second factor is refused and changes nothing
        assert_eq!(
            decide(&mut book, &aid, true, "ada", false, 7000),
            Err(ActionError::StepUpRequired)
        );
        assert_eq!(book.approval(&aid).unwrap().state, ApprovalState::Pending);
        decide(&mut book, &aid, true, "ada", true, 8000).unwrap();
        assert_eq!(
            decide(&mut book, &aid, false, "ada", true, 8100),
            Err(ActionError::AlreadyDecided)
        );
        run_ticks(&mut sup, &mut book, &mut host, 9000, 2);
        assert_eq!(host.engine.resolutions.last().map(|r| r.1), Some(true));
        assert_eq!(state(&book, &id), TaskState::Running);
        let a = book.approval(&aid).unwrap();
        assert!(a.decided_with_step_up && a.decided_by.as_deref() == Some("ada"));
        let actions: Vec<&str> = book.audit.iter().map(|r| r.action.as_str()).collect();
        assert!(actions.contains(&"approval.requested") && actions.contains(&"approval.approved"));
    }

    fn actions(book: &Book) -> Vec<String> {
        book.audit.iter().map(|r| r.action.clone()).collect()
    }

    #[test]
    fn a_deny_rule_refuses_the_action_with_no_approval_and_leaves_a_record() {
        use crate::permissions::{Effect, PermSettings, Rule, Scope};
        let mut book = Book::default();
        let mut host = SimHost::new().with_box("alpha", Size::M, false);
        book.perms
            .apply_settings(PermSettings {
                default_mode: crate::permissions::Mode::Ask,
                modes: vec![],
                rules: vec![Rule {
                    id: String::new(),
                    effect: Effect::Deny,
                    action: "git.push".into(),
                    scope: Scope::Box,
                    scope_id: Some("alpha".into()),
                    path: None,
                    command: None,
                    env: None,
                    tool: None,
                    server: None,
                    note: String::new(),
                }],
                browser_hosts: vec![],
            })
            .unwrap();
        let id = add(&mut book, "sim:steps=100 sim:push=wip-x", "alpha");
        let mut sup = Supervisor::new();
        run_ticks(&mut sup, &mut book, &mut host, 2000, 4);
        assert!(book.approvals.is_empty(), "a refusal is not a question");
        assert_eq!(state(&book, &id), TaskState::Running);
        assert_eq!(host.engine.resolutions.last().map(|r| r.1), Some(false));
        let a = actions(&book);
        assert!(a.contains(&"permission.deny".to_string()), "{a:?}");
    }

    #[test]
    fn plan_only_refuses_a_push_that_would_otherwise_go_ahead() {
        let mut book = Book::default();
        let mut host = SimHost::new().with_box("alpha", Size::M, false);
        book.perms.default_mode = crate::permissions::Mode::PlanOnly;
        let id = add(&mut book, "sim:steps=100 sim:push=wip-x", "alpha");
        let mut sup = Supervisor::new();
        run_ticks(&mut sup, &mut book, &mut host, 2000, 4);
        assert_eq!(state(&book, &id), TaskState::Running);
        assert_eq!(host.engine.resolutions.last().map(|r| r.1), Some(false));
    }

    #[test]
    fn a_production_action_with_no_grant_asks_and_is_recorded_as_refused_by_the_engine() {
        let mut book = Book::default();
        let mut host = SimHost::new().with_box("prod", Size::M, true);
        let id = add(&mut book, "sim:steps=100 sim:push=wip-x", "prod");
        let mut sup = Supervisor::new();
        run_ticks(&mut sup, &mut book, &mut host, 2000, 4);
        assert_eq!(state(&book, &id), TaskState::NeedsYou);
        assert!(actions(&book).contains(&"permission.deny".to_string()));
    }

    #[test]
    fn an_active_grant_lets_a_production_action_through_and_is_counted() {
        use crate::permissions::{NewGrant, Scope, SecondFactor};
        let mut book = Book::default();
        let mut host = SimHost::new().with_box("prod", Size::M, true);
        let id = add(&mut book, "sim:steps=100 sim:push=wip-x", "prod");
        let g = book
            .perms
            .create_grant(
                NewGrant {
                    granted_by: "ada".into(),
                    scope: Scope::Box,
                    scope_id: "prod".into(),
                    actions: vec!["git.*".into()],
                    reason: "deploy the fix".into(),
                    minutes: 30,
                    factor: SecondFactor::StepUp,
                    allow_unattended: false,
                    max_uses: None,
                },
                1000,
            )
            .unwrap();
        let mut sup = Supervisor::new();
        run_ticks(&mut sup, &mut book, &mut host, 2000, 4);
        assert!(book.approvals.is_empty());
        assert_eq!(state(&book, &id), TaskState::Running);
        assert_eq!(host.engine.resolutions.last().map(|r| r.1), Some(true));
        assert_eq!(book.perms.grants[0].uses, 1);
        let a = actions(&book);
        assert!(
            a.contains(&"permission.allow".to_string()) && a.contains(&"grant.used".to_string())
        );
        assert!(book.audit.iter().any(|r| r.detail.contains(&g.id)));
    }

    #[test]
    fn once_the_grant_has_lapsed_the_next_production_action_asks_again() {
        use crate::permissions::{NewGrant, Scope, SecondFactor};
        let mut book = Book::default();
        let mut host = SimHost::new().with_box("prod", Size::M, true);
        let id = add(&mut book, "sim:steps=100 sim:push=wip-x", "prod");
        book.perms
            .create_grant(
                NewGrant {
                    granted_by: "ada".into(),
                    scope: Scope::Box,
                    scope_id: "prod".into(),
                    actions: vec!["*".into()],
                    reason: "a short window".into(),
                    minutes: 1,
                    factor: SecondFactor::StepUp,
                    allow_unattended: false,
                    max_uses: None,
                },
                0,
            )
            .unwrap();
        let mut sup = Supervisor::new();
        // the clock starts after the minute is up
        run_ticks(&mut sup, &mut book, &mut host, 70_000, 4);
        assert_eq!(state(&book, &id), TaskState::NeedsYou);
    }

    #[test]
    fn approving_a_production_request_makes_a_spent_one_use_grant_naming_the_factor() {
        use crate::permissions::SecondFactor;
        let mut book = Book::default();
        let mut host = SimHost::new().with_box("prod", Size::M, true);
        let id = add(&mut book, "sim:steps=100 sim:push=wip-x", "prod");
        let mut sup = Supervisor::new();
        run_ticks(&mut sup, &mut book, &mut host, 2000, 4);
        let aid = book.approvals[0].id.clone();
        // nothing confirmed: refused
        assert_eq!(
            decide_with(&mut book, &aid, true, "ada", None, 7000),
            Err(ActionError::StepUpRequired)
        );
        assert!(book.perms.grants.is_empty());
        decide_with(
            &mut book,
            &aid,
            true,
            "ada",
            Some(SecondFactor::TypedConfirmation),
            8000,
        )
        .unwrap();
        let g = &book.perms.grants[0];
        assert_eq!(g.factor, SecondFactor::TypedConfirmation);
        assert!(!g.factor.is_real(), "a typed word is recorded as not 2FA");
        assert_eq!((g.max_uses, g.uses), (Some(1), 1));
        assert!(!g.is_active(8001));
        run_ticks(&mut sup, &mut book, &mut host, 9000, 2);
        assert_eq!(state(&book, &id), TaskState::Running);
        assert!(actions(&book).contains(&"grant.created".to_string()));
    }

    #[test]
    fn denying_a_production_request_makes_no_grant() {
        let mut book = Book::default();
        let mut host = SimHost::new().with_box("prod", Size::M, true);
        add(&mut book, "sim:steps=100 sim:push=wip-x", "prod");
        let mut sup = Supervisor::new();
        run_ticks(&mut sup, &mut book, &mut host, 2000, 4);
        let aid = book.approvals[0].id.clone();
        decide(&mut book, &aid, false, "ada", false, 7000).unwrap();
        assert!(book.perms.grants.is_empty());
    }

    #[test]
    fn a_denied_action_is_not_done_and_denying_needs_no_second_factor() {
        let mut book = Book::default();
        let mut host = SimHost::new().with_box("alpha", Size::M, false);
        let id = add(&mut book, "sim:steps=100 sim:command=sudo", "alpha");
        let mut sup = Supervisor::new();
        run_ticks(&mut sup, &mut book, &mut host, 2000, 4);
        let aid = book.approvals[0].id.clone();
        decide(&mut book, &aid, false, "ada", false, 7000).unwrap();
        run_ticks(&mut sup, &mut book, &mut host, 8000, 2);
        assert_eq!(host.engine.resolutions.last().map(|r| r.1), Some(false));
        assert_eq!(state(&book, &id), TaskState::Running);
    }

    #[test]
    fn who_may_decide_is_enforced_and_a_refusal_is_audited() {
        let mut book = Book::default();
        book.policy.approvers = vec!["cy".into()];
        let mut host = SimHost::new().with_box("alpha", Size::M, false);
        add(&mut book, "sim:steps=100 sim:command=sudo", "alpha");
        let mut sup = Supervisor::new();
        run_ticks(&mut sup, &mut book, &mut host, 2000, 4);
        let aid = book.approvals[0].id.clone();
        assert_eq!(
            decide(&mut book, &aid, false, "ada", true, 7000),
            Err(ActionError::NotAllowed)
        );
        assert!(book
            .audit
            .iter()
            .any(|r| r.action == "approval.refused" && r.actor == "ada"));
        decide(&mut book, &aid, false, "cy", true, 7100).unwrap();
    }

    #[test]
    fn an_unanswered_request_is_reminded_then_denied_and_never_approved() {
        let mut book = Book::default();
        book.policy.expiry_s = 2 * 3600;
        let mut host = SimHost::new().with_box("alpha", Size::M, false);
        let id = add(&mut book, "sim:steps=100 sim:push=main", "alpha");
        let mut sup = Supervisor::new();
        run_ticks(&mut sup, &mut book, &mut host, 2000, 4);
        let aid = book.approvals[0].id.clone();
        let created = book.approvals[0].created_ms;
        let fx = sup.tick(&mut book, &mut host, created + 16 * 60_000, "2026-11");
        assert_eq!(
            fx.iter().filter(|f| f.kind == "approval_waiting").count(),
            1
        );
        let fx = sup.tick(&mut book, &mut host, created + 61 * 60_000, "2026-11");
        assert_eq!(
            fx.iter().filter(|f| f.kind == "approval_waiting").count(),
            1
        );
        sup.tick(&mut book, &mut host, created + 3 * 3600 * 1000, "2026-11");
        sup.tick(
            &mut book,
            &mut host,
            created + 3 * 3600 * 1000 + 1000,
            "2026-11",
        );
        let a = book.approval(&aid).unwrap();
        assert_eq!(a.state, ApprovalState::Expired);
        assert_eq!(host.engine.resolutions.last().map(|r| r.1), Some(false));
        assert_eq!(
            decide(
                &mut book,
                &aid,
                true,
                "ada",
                true,
                created + 4 * 3600 * 1000
            ),
            Err(ActionError::AlreadyDecided)
        );
        assert!(book.audit.iter().any(|r| r.action == "approval.expired"));
        assert_eq!(state(&book, &id), TaskState::Running);
    }

    #[test]
    fn an_action_the_policy_allows_goes_ahead_and_a_production_box_always_asks() {
        let mut book = Book::default();
        let mut host =
            SimHost::new()
                .with_box("alpha", Size::M, false)
                .with_box("prod", Size::M, true);
        let a = add(&mut book, "sim:steps=100 sim:push=wip-x", "alpha");
        let p = add(&mut book, "sim:steps=100 sim:push=wip-x", "prod");
        let mut sup = Supervisor::new();
        run_ticks(&mut sup, &mut book, &mut host, 2000, 4);
        assert_eq!(state(&book, &a), TaskState::Running);
        assert_eq!(state(&book, &p), TaskState::NeedsYou);
        let ap = book.approvals.iter().find(|x| x.task_id == p).unwrap();
        assert!(ap.production && ap.needs_step_up);
    }

    #[test]
    fn finishing_goes_to_review_and_a_failure_saves_the_work() {
        let mut book = Book::default();
        let mut host = SimHost::new().with_box("alpha", Size::M, false);
        let ok = add(&mut book, "sim:steps=2", "alpha");
        let bad = add(&mut book, "sim:steps=2 sim:fail", "alpha");
        let mut sup = Supervisor::new();
        let fx = run_ticks(&mut sup, &mut book, &mut host, 2000, 5);
        let t = book.task(&ok).unwrap();
        assert_eq!(t.state, TaskState::Review);
        assert_eq!(t.links[0].kind, "pull_request");
        assert_eq!(state(&book, &bad), TaskState::Failed);
        assert!(book.task(&bad).unwrap().wip_branch.is_some());
        assert!(fx.iter().any(|f| f.kind == "run_failed"));
        set_review(&mut book, &ok, false, "ada", 9000).unwrap();
        assert_eq!(state(&book, &ok), TaskState::Done);
        let n = retry(&mut book, &bad, "ada", 9500).unwrap();
        assert_eq!(
            book.task(&n).unwrap().retry_of.as_deref(),
            Some(bad.as_str())
        );
        assert_eq!(
            retry(&mut book, &ok, "ada", 9600),
            Err(ActionError::WrongState(TaskState::Done))
        );
    }

    #[test]
    fn no_secret_reaches_the_log_the_summary_the_audit_or_an_alert() {
        let mut book = Book::default();
        let mut host = SimHost::new().with_box("alpha", Size::M, false);
        host.key = Some("sk-live-SECRETSECRET123456".into());
        let id = add(&mut book, "sim:steps=2 sim:push=main", "alpha");
        book.task_mut(&id).unwrap().spec.prompt = "sim:steps=3".into();
        let mut sup = Supervisor::new();
        let fx = run_ticks(&mut sup, &mut book, &mut host, 2000, 6);
        let dump = format!("{:?}{:?}{:?}", book.task(&id).unwrap(), book.audit, fx);
        assert!(!dump.contains("SECRETSECRET"), "{dump}");
        assert!(!serde_json::to_string(&book)
            .unwrap()
            .contains("SECRETSECRET"));
        assert!(book
            .task(&id)
            .unwrap()
            .log
            .iter()
            .any(|l| l.contains("1 key(s)")));
    }

    #[test]
    fn an_unknown_engine_fails_the_run_with_a_clear_reason() {
        let mut book = Book::default();
        let mut host = SimHost::new().with_box("alpha", Size::M, false);
        let id = add(&mut book, "x", "alpha");
        book.task_mut(&id).unwrap().spec.engine = "nope".into();
        let mut sup = Supervisor::new();
        run_ticks(&mut sup, &mut book, &mut host, 2000, 2);
        let t = book.task(&id).unwrap();
        assert_eq!(t.state, TaskState::Failed);
        assert_eq!(t.error.as_deref(), Some("that engine is not set up"));
    }

    fn model_host() -> SimHost {
        let mut h = SimHost::new().with_box("alpha", Size::M, false);
        h.model = Some(("anth".into(), "claude-sonnet".into()));
        h.fallback = Some(("oa".into(), "gpt-5".into()));
        h
    }

    #[test]
    fn a_run_starts_on_its_models_provider_with_its_credentials_handed_to_the_engine_only() {
        let mut book = Book::default();
        let mut host = model_host();
        let id = add(&mut book, "sim:steps=100", "alpha");
        let mut sup = Supervisor::new();
        run_ticks(&mut sup, &mut book, &mut host, 2000, 2);
        let t = book.task(&id).unwrap();
        let m = t.model.as_ref().unwrap();
        assert_eq!(
            (m.provider_id.as_str(), m.model.as_str()),
            ("anth", "claude-sonnet")
        );
        assert_eq!(m.fallback.as_ref().unwrap().model, "gpt-5");
        assert_eq!(host.engine.env_names, vec![vec!["MODEL_KEY".to_string()]]);
        assert_eq!(host.engine.models, vec![Some("claude-sonnet".to_string())]);
        // the key is nowhere in the stored task
        let stored = serde_json::to_string(&book).unwrap();
        assert!(!stored.contains("key-for-anth"), "{stored}");
    }

    #[test]
    fn a_runs_own_model_wins_and_a_model_that_cannot_be_resolved_keeps_it_queued_with_the_reason() {
        let mut book = Book::default();
        let mut host = model_host();
        let mut s = spec("sim:steps=100", "alpha");
        s.model = Some(ModelRef {
            provider_id: "mist".into(),
            model: "large".into(),
        });
        let a = book.enqueue(s, 1000, None).unwrap().0;
        let mut sup = Supervisor::new();
        run_ticks(&mut sup, &mut book, &mut host, 2000, 2);
        assert_eq!(
            book.task(&a).unwrap().model.as_ref().unwrap().provider_id,
            "mist"
        );
        host.model_error = Some("no key is saved for Anthropic".into());
        let b = add(&mut book, "sim:steps=100", "alpha");
        run_ticks(&mut sup, &mut book, &mut host, 9000, 2);
        let t = book.task(&b).unwrap();
        assert_eq!(t.state, TaskState::Queued);
        assert!(t
            .queue_reason
            .as_deref()
            .unwrap()
            .contains("no key is saved"));
        host.model_error = None;
        run_ticks(&mut sup, &mut book, &mut host, 12_000, 2);
        assert_eq!(state(&book, &b), TaskState::Running);
    }

    #[test]
    fn reported_tokens_are_recorded_priced_and_a_reported_cost_replaces_the_estimate() {
        let mut book = Book::default();
        let mut host = model_host();
        host.micros_per_token = 100; // $0.0001 per token
        let id = add(
            &mut book,
            "sim:steps=3 sim:in=10000 sim:out=5000 sim:cached=7 sim:reported=9",
            "alpha",
        );
        let mut sup = Supervisor::new();
        run_ticks(&mut sup, &mut book, &mut host, 2000, 3);
        let t = book.task(&id).unwrap();
        assert_eq!(host.usage.len(), 2);
        let u = &host.usage[0];
        assert_eq!(
            (
                u.provider_id.as_str(),
                u.model.as_str(),
                u.box_name.as_deref(),
                u.engine.as_deref()
            ),
            ("anth", "claude-sonnet", Some("alpha"), Some("fake"))
        );
        assert_eq!(
            (u.input_tokens, u.output_tokens, u.cached_input_tokens),
            (10_000, 5_000, 7)
        );
        // 2 polls x 15,000 tokens x $0.0001 = $3.00, an estimate
        assert_eq!(t.spend_cents, 300);
        assert_eq!(t.cost_source(), Some(crate::run::CostSource::Estimated));
        assert_eq!(book.ledger.fleet_cents, 300);
        run_ticks(&mut sup, &mut book, &mut host, 4000, 3);
        let t = book.task(&id).unwrap();
        assert_eq!(t.state, TaskState::Review);
        // the engine said 9 cents: that replaces the estimate, in the card and in the monthly ledger
        assert_eq!(t.spend_cents, 9);
        assert_eq!(t.cost_source(), Some(crate::run::CostSource::Reported));
        assert_eq!(book.ledger.fleet_cents, 9);
    }

    #[test]
    fn a_provider_that_refuses_switches_the_run_to_its_fallback_and_says_so() {
        let mut book = Book::default();
        let mut host = model_host();
        let id = add(&mut book, "sim:steps=100 sim:refuse", "alpha");
        let mut sup = Supervisor::new();
        run_ticks(&mut sup, &mut book, &mut host, 2000, 4);
        let t = book.task(&id).unwrap();
        assert_eq!(t.state, TaskState::Running, "{:?}", t.log);
        let m = t.model.as_ref().unwrap();
        assert_eq!((m.provider_id.as_str(), m.model.as_str()), ("oa", "gpt-5"));
        assert_eq!(m.fell_back_from.as_ref().unwrap().model, "claude-sonnet");
        assert!(m.fallback_reason.as_deref().unwrap().contains("429"));
        assert!(m.fallback.is_none(), "it switches once");
        assert!(book.audit.iter().any(|a| a.action == "run.model_fallback"));
        assert_eq!(host.engine.refused, 1);
        assert_eq!(
            host.engine.models,
            vec![Some("claude-sonnet".to_string()), Some("gpt-5".to_string())]
        );
    }

    #[test]
    fn a_refusal_with_no_fallback_fails_the_run_with_the_reason() {
        let mut book = Book::default();
        let mut host = model_host();
        host.fallback = None;
        let id = add(&mut book, "sim:steps=100 sim:refuse", "alpha");
        let mut sup = Supervisor::new();
        run_ticks(&mut sup, &mut book, &mut host, 2000, 3);
        let t = book.task(&id).unwrap();
        assert_eq!(t.state, TaskState::Failed);
        assert!(t.error.as_deref().unwrap().contains("refused"));
    }

    #[test]
    fn a_providers_monthly_cap_holds_a_new_run_and_pauses_a_running_one_in_needs_you() {
        let mut book = Book::default();
        let mut host = model_host();
        let a = add(&mut book, "sim:steps=1000", "alpha");
        let mut sup = Supervisor::new();
        run_ticks(&mut sup, &mut book, &mut host, 2000, 3);
        assert_eq!(state(&book, &a), TaskState::Running);
        host.capped.push("anth".into());
        let b = add(&mut book, "sim:steps=1000", "alpha");
        let fx = run_ticks(&mut sup, &mut book, &mut host, 6000, 2);
        for id in [&a, &b] {
            let t = book.task(id).unwrap();
            assert_eq!(t.state, TaskState::NeedsYou, "{id}");
            assert!(
                matches!(&t.needs, Some(Needs::MonthlyCap { scope }) if scope.contains("anth")),
                "{id}"
            );
        }
        assert!(fx
            .iter()
            .any(|f| f.kind == "run_needs_you" && f.urgent && f.body.contains("anth")));
        // lifting the cap sends both back to run, with no second cap system involved
        host.capped.clear();
        run_ticks(&mut sup, &mut book, &mut host, 9000, 3);
        assert_eq!(state(&book, &a), TaskState::Running);
        assert_eq!(state(&book, &b), TaskState::Running);
    }

    #[test]
    fn the_fleet_cap_and_a_providers_cap_are_one_check() {
        let mut book = Book::default();
        book.caps.fleet_monthly_cents = Some(10);
        let mut host = model_host();
        let a = add(&mut book, "sim:steps=1000 sim:cents=20", "alpha");
        let mut sup = Supervisor::new();
        run_ticks(&mut sup, &mut book, &mut host, 2000, 4);
        assert!(
            matches!(&book.task(&a).unwrap().needs, Some(Needs::MonthlyCap { scope }) if scope.contains("fleet"))
        );
        let b = add(&mut book, "sim:steps=1000", "alpha");
        run_ticks(&mut sup, &mut book, &mut host, 9000, 2);
        assert!(matches!(
            &book.task(&b).unwrap().needs,
            Some(Needs::MonthlyCap { .. })
        ));
    }

    #[test]
    fn brokered_usage_is_what_counts_the_engines_own_figures_are_ignored_and_credentials_end_with_the_run(
    ) {
        let mut book = Book::default();
        let mut host = model_host();
        host.via_broker = true;
        host.micros_per_token = 100;
        let id = add(
            &mut book,
            "sim:steps=3 sim:in=999999 sim:out=999999",
            "alpha",
        );
        let mut sup = Supervisor::new();
        run_ticks(&mut sup, &mut book, &mut host, 2000, 2);
        host.broker_usage.push(BrokeredUsage {
            provider_id: "anth".into(),
            model: "claude-sonnet".into(),
            input_tokens: 1000,
            output_tokens: 500,
            cached_input_tokens: 0,
        });
        run_ticks(&mut sup, &mut book, &mut host, 4000, 1);
        let t = book.task(&id).unwrap();
        // 1,500 tokens at $0.0001: the engine's 2,000,000-token claim was not counted
        assert_eq!(t.spend_cents, 15);
        assert_eq!(t.tokens, 1500);
        assert_eq!(host.usage.len(), 1);
        assert!(host.ended.is_empty(), "the run is still going");
        run_ticks(&mut sup, &mut book, &mut host, 5000, 4);
        assert_eq!(state(&book, &id), TaskState::Review);
        assert!(
            host.ended.contains(&id),
            "its token is revoked when it finishes"
        );
    }

    #[test]
    fn a_conversation_answers_turn_by_turn_pauses_resumes_its_session_and_never_finishes_on_its_own(
    ) {
        let mut book = Book::default();
        let mut host = SimHost::new().with_box("alpha", Size::M, false);
        let mut sup = Supervisor::new();
        let mut spec = spec("hello there", "alpha");
        spec.interactive = true;
        let (id, _) = book.enqueue(spec, 1_000, None).unwrap();
        let mut now = 1_000;
        let tick = |book: &mut Book, host: &mut SimHost, sup: &mut Supervisor, now: &mut u64| {
            *now += 1_000;
            sup.tick(book, host, *now, "2026-11");
        };
        for _ in 0..3 {
            tick(&mut book, &mut host, &mut sup, &mut now);
        }
        let t = book.task(&id).unwrap();
        assert_eq!(
            t.state,
            TaskState::Running,
            "a turn is not the end of the run"
        );
        assert!(t.awaiting_input && t.turns == 1);
        assert_eq!(t.last_reply.as_deref(), Some("Done: hello there"));
        assert!(t.session_id.is_some());
        // a message is queued, handed over once, and answered
        send_message(&mut book, &id, "and the tests", "ada", now).unwrap();
        assert!(book.task(&id).unwrap().inbox.len() == 1);
        for _ in 0..3 {
            tick(&mut book, &mut host, &mut sup, &mut now);
        }
        let t = book.task(&id).unwrap();
        assert!(t.inbox.is_empty() && t.turns == 2 && t.awaiting_input);
        assert_eq!(t.last_reply.as_deref(), Some("Done: and the tests"));
        // a run that is not a conversation refuses a message; an empty one is refused
        assert_eq!(
            send_message(&mut book, &id, "  ", "ada", now),
            Err(ActionError::BadMessage)
        );
        // pause saves, stops and waits; resume continues the SAME session
        request_pause(&mut book, &id, "ada", now).unwrap();
        tick(&mut book, &mut host, &mut sup, &mut now);
        let t = book.task(&id).unwrap();
        assert_eq!(
            (t.state, t.needs.clone()),
            (TaskState::NeedsYou, Some(Needs::Paused))
        );
        let session = t.session_id.clone();
        resume(&mut book, &id, AddBudget::default(), "ada", now).unwrap();
        for _ in 0..2 {
            tick(&mut book, &mut host, &mut sup, &mut now);
        }
        assert_eq!(host.engine.sessions.last().cloned().flatten(), session);
        assert_eq!(book.task(&id).unwrap().state, TaskState::Running);
    }

    #[test]
    fn a_plain_run_refuses_a_message() {
        let mut book = Book::default();
        let (id, _) = book.enqueue(spec("x", "alpha"), 1, None).unwrap();
        assert_eq!(
            send_message(&mut book, &id, "hi", "ada", 2),
            Err(ActionError::NotInteractive)
        );
    }
}
