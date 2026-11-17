//! The worker's real run path: a task from the hub is a **supervised run** of the box (ADR 0014), not a second way to start a program.
//!
//! The hub agent never launches an agent program itself. [`SupervisedEngine`] is an [`AgentEngine`] whose `start` queues a
//! [`RunSpec`] in the box's own task store through [`RunStarter::start_run`], the one door every run uses, and whose `poll` reads that
//! run's record back as engine events. The box's supervisor (`ozbox serve`, the same one that runs a person's or a schedule's runs)
//! does everything else, so everything it decides still applies to a task from the hub:
//!
//! * **the engine and provider** are the box's own Models routing (ADR 0015). The hub names an engine and, at most, a model; the
//!   provider and the credentials come from the box, and a name that is not `provider:model` is left to the routing;
//! * **credentials** reach the run only as the broker's per-run token (ADR 0017). This module holds no key, builds no environment
//!   and never sees a response; a subscription sign-in (B4-25) is the supervisor's opt-in, honoured because the run is the
//!   supervisor's;
//! * **spend** is counted by the supervisor under the one cap (the box's monthly ledger and the run's own caps). A task that hits a
//!   cap pauses; the engine reports it to the hub as blocked, with the reason, and never keeps the run going;
//! * **a risky action** is an approval request of the box's own (ADR 0014, ADR 0041). A task waiting for one is reported as blocked
//!   ("needs a person on this box"); nothing here answers it, and a message from the hub is data, never a decision.
//!
//! The run is keyed by the task, so an agent that restarts finds its run again instead of starting a second one. It stores no secret
//! and puts none in an event: the text it reports is what the supervisor already redacted into the run's log, summary and error.

use std::collections::BTreeMap;

use ozbox_core::agent_engine::{AgentEngine, EngineError, EngineEvent, EngineStart};
use ozbox_core::engine_turn::capabilities_of;
use ozbox_core::hub::engine::Assign;
use ozbox_core::run::{
    ModelRef, Needs, RunCaps, RunOrigin, RunSpec, RunStarter, TaskState, TaskStore, MAX_INBOX,
    MAX_INBOX_CHARS,
};

use crate::agent::EngineFactory;

/// The engine a task runs on when the conductor named none: the box's default.
pub const DEFAULT_ENGINE: &str = "claude-code";

/// Makes the engine for a task: a supervised run on this box's task store.
pub struct SupervisedFactory {
    pub store: TaskStore,
    /// The hub's name, which the run is attributed to (`hub:<name>`).
    pub hub: String,
    /// The engine used when a task names none.
    pub default_engine: String,
}

impl SupervisedFactory {
    pub fn new(store: TaskStore, hub: &str) -> SupervisedFactory {
        SupervisedFactory {
            store,
            hub: hub.to_string(),
            default_engine: DEFAULT_ENGINE.to_string(),
        }
    }

    fn build(
        &self,
        engine: &str,
        lease_expiry_ms: Option<u64>,
    ) -> Result<Box<dyn AgentEngine>, String> {
        let id = if engine.is_empty() {
            self.default_engine.as_str()
        } else {
            engine
        };
        // an engine with no headless adapter (OpenCode, Aider) is refused by name here, not queued to fail on the box
        match capabilities_of(id) {
            Some(c) if c.headless.is_yes() => {}
            Some(c) => {
                let why = match c.headless {
                    ozbox_core::engine_turn::Support::Unsupported(w)
                    | ozbox_core::engine_turn::Support::Partly(w) => w,
                    ozbox_core::engine_turn::Support::Yes => "",
                };
                return Err(format!("the engine {id} cannot run headless here: {why}"));
            }
            None => return Err(format!("this box has no engine named {id}")),
        }
        Ok(Box::new(SupervisedEngine {
            store: self.store.clone(),
            hub: self.hub.clone(),
            id: id.to_string(),
            lease_expiry_ms,
            runs: BTreeMap::new(),
        }))
    }
}

impl EngineFactory for SupervisedFactory {
    fn make(&mut self, engine: &str) -> Result<Box<dyn AgentEngine>, String> {
        self.build(engine, None)
    }

    fn make_for(&mut self, a: &Assign) -> Result<Box<dyn AgentEngine>, String> {
        self.build(a.engine.as_deref().unwrap_or(""), Some(a.lease_expiry_ms))
    }
}

#[derive(Default)]
struct Seen {
    log: usize,
    /// The last state reported, so each change is said once.
    said: Option<String>,
    ended: bool,
}

/// An [`AgentEngine`] over the box's task store.
pub struct SupervisedEngine {
    store: TaskStore,
    hub: String,
    id: String,
    lease_expiry_ms: Option<u64>,
    runs: BTreeMap<String, Seen>,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// `provider:model` is a choice of the Models routing; anything else is a model name only the box's routing can place.
fn model_ref(model: Option<&str>) -> Option<ModelRef> {
    let (p, m) = model?.split_once(':')?;
    let ok =
        !p.is_empty() && p.len() <= 24 && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
    (ok && !m.is_empty()).then(|| ModelRef {
        provider_id: p.to_string(),
        model: m.to_string(),
    })
}

fn failed(e: impl std::fmt::Display) -> EngineError {
    EngineError::Failed(e.to_string())
}

impl AgentEngine for SupervisedEngine {
    fn id(&self) -> &str {
        &self.id
    }

    fn start(&mut self, req: &EngineStart) -> Result<String, EngineError> {
        let (orch, feature) = ozbox_core::engine_turn::split_task_id(&req.task_id);
        let now = now_ms();
        // the task's lease is its time limit: a worker that hears nothing by then stops, and so does the run
        let max_runtime_s = match self.lease_expiry_ms {
            Some(l) if l > now => Some(((l - now) / 1000).max(1)),
            Some(_) => return Err(failed("the task's lease has already ended")),
            None => req.max_runtime_s,
        };
        let spec = RunSpec {
            engine: self.id.clone(),
            prompt: req.prompt.clone(),
            skill: req.skill.clone(),
            box_name: req.box_name.clone(),
            repo: req.repo.clone(),
            branch: req.branch.clone(),
            caps: RunCaps {
                max_runtime_s,
                ..RunCaps::default()
            },
            deliver_to: Vec::new(),
            requested_by: format!("hub:{}", self.hub)
                .chars()
                .filter(|c| !c.is_control())
                .take(64)
                .collect(),
            origin: RunOrigin::Orchestration { id: orch, feature },
            // keyed by the task: an agent that restarts finds the run it started, it never starts a second
            idempotency_key: Some(format!("hub/{}/{}", self.hub, req.task_id)),
            model: model_ref(req.model.as_deref()),
            interactive: req.interactive,
        };
        let started = self.store.start_run(spec).map_err(failed)?;
        self.runs.insert(started.id.clone(), Seen::default());
        Ok(started.id)
    }

    fn poll(&mut self, handle: &str) -> Result<Vec<EngineEvent>, EngineError> {
        let book = self.store.load().map_err(failed)?;
        let Some(t) = book.task(handle) else {
            return Err(failed("that run is no longer in this box's task store"));
        };
        let seen = self.runs.entry(handle.to_string()).or_default();
        if seen.ended {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        // the run's log, already redacted by the supervisor; a log that was trimmed from the front is read from its start
        let from = seen.log.min(t.log.len());
        for line in &t.log[from..] {
            if let Some(tool) = line.strip_prefix("using ") {
                out.push(EngineEvent::ToolUse {
                    name: tool.to_string(),
                });
            } else {
                out.push(EngineEvent::Log(line.clone()));
            }
        }
        seen.log = t.log.len();
        let mut say = |key: String, ev: EngineEvent, out: &mut Vec<EngineEvent>| {
            if seen.said.as_deref() != Some(key.as_str()) {
                seen.said = Some(key);
                out.push(ev);
            }
        };
        match t.state {
            TaskState::Queued => {
                if let Some(why) = &t.queue_reason {
                    say(
                        format!("queued:{why}"),
                        EngineEvent::Log(format!("waiting to start: {why}")),
                        &mut out,
                    );
                }
            }
            TaskState::Running => {
                seen.said = None;
            }
            TaskState::NeedsYou => {
                let why = match &t.needs {
                    Some(Needs::Approval { .. }) => {
                        "an action needs a person's yes on this box".to_string()
                    }
                    Some(Needs::SpendCap) => "the run reached its spend cap on this box".into(),
                    Some(Needs::TimeCap) => "the run reached its time limit on this box".into(),
                    Some(Needs::TokenCap) => "the run reached its token cap on this box".into(),
                    Some(Needs::MonthlyCap { scope }) => {
                        format!("the {scope} monthly cap was reached on this box")
                    }
                    Some(Needs::Paused) => "a person paused the run on this box".into(),
                    None => "the run needs a person on this box".into(),
                };
                say(
                    format!("needs:{why}"),
                    EngineEvent::ProviderRefused(why),
                    &mut out,
                );
            }
            TaskState::Review | TaskState::Done => {
                seen.ended = true;
                out.push(EngineEvent::Finished {
                    summary: t.summary.clone().unwrap_or_default(),
                    links: t.links.clone(),
                });
            }
            TaskState::Failed => {
                seen.ended = true;
                out.push(EngineEvent::Failed(
                    t.error
                        .clone()
                        .unwrap_or_else(|| "the run failed on this box".into()),
                ));
            }
            TaskState::Cancelled => {
                seen.ended = true;
                out.push(EngineEvent::Failed(
                    "the run was stopped on this box".into(),
                ));
            }
        }
        Ok(out)
    }

    /// A supervised run's approvals are the box's own requests; a decision is theirs, never an answer an engine takes.
    fn resolve(&mut self, _handle: &str, _approved: bool) -> Result<(), EngineError> {
        Err(EngineError::Unavailable)
    }

    fn stop(&mut self, handle: &str) -> Result<(), EngineError> {
        let id = handle.to_string();
        self.store
            .update(|b| {
                if let Some(t) = b.task_mut(&id) {
                    if !t.state.is_terminal() {
                        t.cancel_requested = true;
                    }
                }
            })
            .map_err(failed)?;
        Ok(())
    }

    /// An answer or a merge result for a conversation: the supervisor hands it to the agent at its next tick. A run that is not a
    /// conversation takes none (the supervisor delivers messages to sessions only).
    fn send(&mut self, handle: &str, text: &str) -> Result<(), EngineError> {
        if text.is_empty() || text.chars().count() > MAX_INBOX_CHARS {
            return Err(failed("that message is empty or too long"));
        }
        // the same screen as every text that crosses the hub: a key-shaped message is not handed to an agent
        if ozbox_core::secret_shape::find_secret(text).is_some() {
            return Err(failed("that message looks like it holds a key"));
        }
        let id = handle.to_string();
        let msg = text.to_string();
        let r = self
            .store
            .update(|b| match b.task_mut(&id) {
                Some(t) if t.spec.interactive && t.inbox.len() < MAX_INBOX => {
                    t.inbox.push(msg);
                    Ok(())
                }
                Some(t) if t.spec.interactive => Err("the run has too many messages waiting"),
                Some(_) => Err("that run is not a conversation"),
                None => Err("that run is no longer in this box's task store"),
            })
            .map_err(failed)?;
        r.map_err(failed)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ozbox_core::engine_turn::{Task, Turn};

    fn store() -> (tempfile::TempDir, TaskStore) {
        let d = tempfile::tempdir().unwrap();
        let s = TaskStore::new(d.path().join("tasks.json"));
        (d, s)
    }

    fn req(model: Option<&str>) -> EngineStart {
        let _ = Task {
            id: String::new(),
            title: String::new(),
            instruction: String::new(),
            repo: None,
            branch: None,
        };
        EngineStart {
            task_id: "orch-1/parser".into(),
            box_name: "box-a".into(),
            prompt: "do it".into(),
            skill: None,
            repo: Some("billing".into()),
            branch: Some("feat/parser".into()),
            resume_from: None,
            secret_env: BTreeMap::new(),
            deny_commands: Vec::new(),
            max_runtime_s: None,
            model: model.map(str::to_string),
            on_fallback: false,
            interactive: false,
            resume_session: None,
            ask_for_edits: false,
        }
    }

    fn engine(s: &TaskStore) -> SupervisedEngine {
        let mut f = SupervisedFactory::new(s.clone(), "main");
        let a = ozbox_core::engine_turn::assign_of(
            &Task {
                id: "orch-1/parser".into(),
                title: String::new(),
                instruction: "x".into(),
                repo: None,
                branch: None,
            },
            Default::default(),
            now_ms() + 600_000,
        );
        let e = f.make_for(&a).unwrap();
        assert_eq!(e.id(), DEFAULT_ENGINE);
        // the trait object is the engine under test
        SupervisedEngine {
            store: s.clone(),
            hub: "main".into(),
            id: DEFAULT_ENGINE.into(),
            lease_expiry_ms: a.lease_expiry_ms.into(),
            runs: BTreeMap::new(),
        }
    }

    #[test]
    fn a_task_is_one_queued_run_of_the_box_keyed_by_the_task_with_the_leases_time_limit() {
        let (_d, s) = store();
        let mut e = engine(&s);
        let h = e.start(&req(None)).unwrap();
        let b = s.load().unwrap();
        let t = b.task(&h).unwrap();
        assert_eq!(t.state, TaskState::Queued);
        assert_eq!(t.spec.engine, "claude-code");
        assert_eq!(t.spec.requested_by, "hub:main");
        assert_eq!(
            t.spec.origin,
            RunOrigin::Orchestration {
                id: "orch-1".into(),
                feature: "parser".into()
            }
        );
        assert!(t
            .spec
            .caps
            .max_runtime_s
            .is_some_and(|s| (590..=600).contains(&s)));
        // the provider is the box's routing: no model that is not a provider:model is passed on
        assert!(t.spec.model.is_none());
        // starting the same task again (an agent that restarted) is the same run, not a second one
        let again = e.start(&req(None)).unwrap();
        assert_eq!(again, h);
        assert_eq!(s.load().unwrap().tasks.len(), 1);
    }

    #[test]
    fn only_a_provider_and_model_pair_is_a_choice_and_everything_else_is_left_to_the_boxs_routing()
    {
        let (_d, s) = store();
        let mut e = engine(&s);
        let h = e.start(&req(Some("claude-opus-9"))).unwrap();
        assert!(s.load().unwrap().task(&h).unwrap().spec.model.is_none());
        let mut r = req(Some("anthropic:claude-opus-9"));
        r.task_id = "orch-1/other".into();
        let h = e.start(&r).unwrap();
        let m = s.load().unwrap().task(&h).unwrap().spec.model.clone();
        assert_eq!(
            m,
            Some(ModelRef {
                provider_id: "anthropic".into(),
                model: "claude-opus-9".into()
            })
        );
    }

    #[test]
    fn the_runs_states_come_back_as_events_each_said_once_and_a_finished_run_reports_its_summary() {
        let (_d, s) = store();
        let mut e = engine(&s);
        let h = e.start(&req(None)).unwrap();
        // queued with a reason: said once
        s.update(|b| b.task_mut(&h).unwrap().queue_reason = Some("the box is full".into()))
            .unwrap();
        let first = e.poll(&h).unwrap();
        assert_eq!(
            first,
            vec![EngineEvent::Log("waiting to start: the box is full".into())]
        );
        assert!(e.poll(&h).unwrap().is_empty());
        // running, with a log the supervisor redacted
        s.update(|b| {
            let t = b.task_mut(&h).unwrap();
            t.state = TaskState::Running;
            t.push_log("reading the code");
            t.push_log("using Bash");
        })
        .unwrap();
        assert_eq!(
            e.poll(&h).unwrap(),
            vec![
                EngineEvent::Log("reading the code".into()),
                EngineEvent::ToolUse {
                    name: "Bash".into()
                }
            ]
        );
        // a cap pause is blocked with the reason, not a failure and not a grant
        s.update(|b| {
            let t = b.task_mut(&h).unwrap();
            t.state = TaskState::NeedsYou;
            t.needs = Some(Needs::SpendCap);
        })
        .unwrap();
        let ev = e.poll(&h).unwrap();
        assert!(matches!(&ev[..], [EngineEvent::ProviderRefused(w)] if w.contains("spend cap")));
        assert!(e.poll(&h).unwrap().is_empty());
        // finished: the summary and links, once
        s.update(|b| {
            let t = b.task_mut(&h).unwrap();
            t.state = TaskState::Review;
            t.needs = None;
            t.summary = Some("Parser built.".into());
        })
        .unwrap();
        assert_eq!(
            e.poll(&h).unwrap(),
            vec![EngineEvent::Finished {
                summary: "Parser built.".into(),
                links: Vec::new()
            }]
        );
        assert!(e.poll(&h).unwrap().is_empty());
        // and through the neutral model it is a result turn
        let _ = Turn::Say(String::new());
    }

    #[test]
    fn a_failed_or_stopped_run_is_a_failure_and_a_run_that_vanished_is_an_error() {
        let (_d, s) = store();
        let mut e = engine(&s);
        let h = e.start(&req(None)).unwrap();
        s.update(|b| {
            let t = b.task_mut(&h).unwrap();
            t.state = TaskState::Failed;
            t.error = Some("the engine stopped answering".into());
        })
        .unwrap();
        assert_eq!(
            e.poll(&h).unwrap(),
            vec![EngineEvent::Failed("the engine stopped answering".into())]
        );
        assert!(e.poll("t999").is_err());
    }

    #[test]
    fn stop_asks_the_supervisor_to_cancel_and_an_approval_is_never_answered_here() {
        let (_d, s) = store();
        let mut e = engine(&s);
        let h = e.start(&req(None)).unwrap();
        e.stop(&h).unwrap();
        assert!(s.load().unwrap().task(&h).unwrap().cancel_requested);
        // a decision is the box's own request flow's: the engine has no way to take one
        assert_eq!(e.resolve(&h, true), Err(EngineError::Unavailable));
    }

    #[test]
    fn a_message_reaches_only_a_conversation_and_never_one_that_looks_like_a_key() {
        let (_d, s) = store();
        let mut e = engine(&s);
        let h = e.start(&req(None)).unwrap();
        // a task that is not a conversation takes none
        assert!(e.send(&h, "merged: ok").is_err());
        let mut r = req(None);
        r.task_id = "orch-1/chat".into();
        r.interactive = true;
        let c = e.start(&r).unwrap();
        e.send(&c, "merged: ok").unwrap();
        assert_eq!(
            s.load().unwrap().task(&c).unwrap().inbox,
            vec!["merged: ok"]
        );
        let key = concat!("gh", "p_0123456789abcdef0123456789abcdef0123");
        assert!(e.send(&c, key).is_err());
        assert_eq!(s.load().unwrap().task(&c).unwrap().inbox.len(), 1);
    }

    #[test]
    fn an_engine_without_a_headless_adapter_or_an_unknown_one_is_refused_by_name() {
        let (_d, s) = store();
        let mut f = SupervisedFactory::new(s, "main");
        for (id, want) in [
            ("opencode", "cannot run headless"),
            ("nope", "no engine named"),
        ] {
            let e = f.make(id).err().unwrap();
            assert!(e.contains(want), "{id}: {e}");
        }
        assert!(f.make("codex").is_ok());
        assert!(f.make("gemini-cli").is_ok());
        assert!(f.make("").is_ok());
    }

    #[test]
    fn an_expired_lease_starts_nothing() {
        let (_d, s) = store();
        let mut e = engine(&s);
        e.lease_expiry_ms = Some(1);
        assert!(e.start(&req(None)).is_err());
        assert!(s.load().unwrap().tasks.is_empty());
    }
}
