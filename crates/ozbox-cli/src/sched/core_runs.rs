//! The real run system: schedules and triggers start runs through `ozbox_core::run`, the same `RunSpec` and
//! `start_run` everything else uses. A run is only queued here; the supervisor admits and supervises it.

use ozbox_core::permissions::{Action, ActorKind, Ctx};
use ozbox_core::run::{
    DeliverTo, RunCaps, RunOrigin, RunSpec, RunStarter as CoreStarter, TaskState, TaskStore,
};

use super::runner::{Poll, RunRequest, RunStarter, StartError};

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub struct CoreRuns {
    pub store: TaskStore,
}

fn origin(req: &RunRequest) -> RunOrigin {
    match req.source.as_str() {
        "trigger" => RunOrigin::Trigger {
            id: req.owner_id.clone(),
        },
        "manual" => RunOrigin::Schedule {
            id: req.owner_id.clone(),
        },
        _ => RunOrigin::Schedule {
            id: req.owner_id.clone(),
        },
    }
}

pub fn to_spec(req: &RunRequest) -> RunSpec {
    RunSpec {
        interactive: false,
        engine: req.engine.clone(),
        prompt: req.prompt.clone(),
        skill: req.skill.clone(),
        box_name: req.box_name.clone(),
        repo: None,
        branch: None,
        caps: RunCaps {
            max_runtime_s: req.caps.max_minutes.map(|m| u64::from(m) * 60),
            max_spend_cents: req.caps.max_spend_cents,
            max_tokens: None,
        },
        deliver_to: req
            .results_to
            .iter()
            .filter_map(|r| match r.as_str() {
                "alert" => Some(DeliverTo::Alert),
                "pull_request" => Some(DeliverTo::PullRequest),
                _ => None,
            })
            .collect(),
        requested_by: format!(
            "{}:{}",
            if req.source == "trigger" {
                "trigger"
            } else {
                "schedule"
            },
            req.owner_id
        ),
        origin: origin(req),
        // A retried firing of the same run id starts one task.
        idempotency_key: Some(format!("{}:{}", req.owner_id, req.run_id)),
        model: None,
    }
}

impl RunStarter for CoreRuns {
    fn start(&self, req: &RunRequest) -> Result<String, StartError> {
        // The permission engine decides whether a schedule or trigger may start a run here at all (a rule can forbid it). What
        // the run then does is decided action by action, as for any run.
        let actor = if req.source == "trigger" {
            ActorKind::Trigger
        } else {
            ActorKind::Schedule
        };
        let who = format!(
            "{}:{}",
            if req.source == "trigger" {
                "trigger"
            } else {
                "schedule"
            },
            req.owner_id
        );
        let ctx = Ctx {
            person: who.clone(),
            actor,
            box_name: Some(req.box_name.clone()),
            ..Ctx::default()
        };
        let allowed = self
            .store
            .update(|b| {
                ozbox_core::tool_gate::permit(b, &ctx, Action::RunStart, &who, None, now_ms())
            })
            .map_err(|e| StartError {
                reason: "refused".into(),
                detail: e.to_string(),
            })?;
        if let Err(why) = allowed {
            return Err(StartError {
                reason: "refused".into(),
                detail: why,
            });
        }
        self.store
            .start_run(to_spec(req))
            .map(|s| s.id)
            .map_err(|e| StartError {
                reason: "refused".into(),
                detail: e.to_string(),
            })
    }

    fn poll(&self, run_ref: &str) -> Poll {
        let Ok(book) = self.store.load() else {
            return Poll::Running;
        };
        let Some(t) = book.task(run_ref) else {
            return Poll::Unknown;
        };
        let url = t.links.first().map(|l| l.url.clone());
        let cost = Some(t.spend_cents as f64 / 100.0);
        match t.state {
            TaskState::Queued | TaskState::Running | TaskState::NeedsYou => Poll::Running,
            TaskState::Review | TaskState::Done => Poll::Finished {
                ok: true,
                detail: t.summary.clone().unwrap_or_default(),
                cost,
                result_url: url,
            },
            TaskState::Failed => Poll::Finished {
                ok: false,
                detail: t
                    .error
                    .clone()
                    .unwrap_or_else(|| crate::messages::t("sched.run_failed", &[])),
                cost,
                result_url: url,
            },
            TaskState::Cancelled => Poll::Finished {
                ok: false,
                detail: crate::messages::t("sched.run_cancelled", &[]),
                cost,
                result_url: url,
            },
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod permission_tests {
    use super::*;
    use crate::sched::model::Caps;
    use ozbox_core::permissions::{Effect, Mode, PermSettings, Rule, Scope};

    fn req(source: &str, id: &str) -> RunRequest {
        RunRequest {
            run_id: format!("{id}-1"),
            source: source.into(),
            owner_id: id.into(),
            engine: "fake".into(),
            prompt: "do it".into(),
            skill: None,
            box_name: "alpha".into(),
            caps: Caps::default(),
            results_to: vec![],
        }
    }

    #[test]
    fn a_schedule_and_a_trigger_start_through_the_engine_and_a_rule_can_forbid_it() {
        let dir = tempfile::tempdir().unwrap();
        let store = TaskStore::new(dir.path().join("tasks.json"));
        let runs = CoreRuns {
            store: store.clone(),
        };
        assert!(runs.start(&req("schedule", "s1")).is_ok());
        assert!(runs.start(&req("trigger", "t1")).is_ok());
        let words: Vec<(String, String)> = store
            .load()
            .unwrap()
            .audit
            .iter()
            .filter(|a| a.action.starts_with("permission."))
            .map(|a| (a.actor.clone(), a.action.clone()))
            .collect();
        assert_eq!(
            words,
            vec![
                ("schedule:s1".to_string(), "permission.allow".to_string()),
                ("trigger:t1".to_string(), "permission.allow".to_string())
            ]
        );
        store
            .update(|b| {
                b.perms
                    .apply_settings(PermSettings {
                        default_mode: Mode::Ask,
                        modes: vec![],
                        rules: vec![Rule {
                            id: String::new(),
                            effect: Effect::Deny,
                            action: "run.start".into(),
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
            })
            .unwrap();
        let e = runs.start(&req("schedule", "s1")).unwrap_err();
        assert_eq!(e.reason, "refused");
        assert!(e.detail.contains("forbids"), "{}", e.detail);
        // nothing was queued for the refused firing
        assert_eq!(store.load().unwrap().tasks.len(), 2);
        // plan-only does not stop a run from starting: what it does is judged action by action
        store
            .update(|b| {
                b.perms.rules.clear();
                b.perms.default_mode = Mode::PlanOnly;
            })
            .unwrap();
        assert!(runs.start(&req("trigger", "t2")).is_ok());
    }
}
