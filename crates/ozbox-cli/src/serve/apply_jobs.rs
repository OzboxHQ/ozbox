//! Changes to boxes run as jobs (`POST /v1/apply`).
//!
//! Creating, resuming, resizing, upgrading or destroying a box can take minutes (an instance boot, a `tofu apply`). The
//! server answers one request at a time, so doing that inside the request froze every other tab, poll and person until
//! it ended. Now the request checks the plan, starts the change on a thread of its own and answers `202` with a job.
//! The dashboard (and `ozbox`'s own clients) poll `GET /v1/jobs/<id>`.
//!
//! What this does not do: it adds no wait, no readiness check and no extra provider call inside `Provider::apply`. The
//! change that runs is the one that ran before, so the timing of spawn, resume, snapshot and teardown is the provider's
//! own. The dashboard's "ready" is still its poll of the box on top of that, never a provider metric.
//!
//! A job lives in memory, like the plans: it lasts as long as the server runs. The audit chain and Activity record the
//! outcome either way.

use std::collections::VecDeque;
use std::sync::Arc;

use ozbox_core::{BoxName, BoxRecord, Error, Operation, Plan, Risk};
use serde_json::{json, Value};

use super::worker::{Done, Job};
use super::{unix_ms, App, Resp};
use crate::run::upgrade::Step;

/// How many changes may run at once. Each has a thread and (on AWS) a provider process.
pub(super) const MAX_RUNNING: usize = 4;
/// How many finished jobs are kept to be asked about.
const KEEP_FINISHED: usize = 64;

enum State {
    Running,
    Done(Value),
    Failed { status: u16, body: Value },
}

struct ApplyJob {
    id: String,
    box_name: String,
    verb: &'static str,
    started_ms: u64,
    /// Who asked: the change finishes in some later request, which is not necessarily theirs.
    actor: super::Actor,
    state: State,
}

#[derive(Default)]
pub(super) struct Jobs {
    jobs: VecDeque<ApplyJob>,
}

impl Jobs {
    fn running(&self) -> usize {
        self.jobs
            .iter()
            .filter(|j| matches!(j.state, State::Running))
            .count()
    }

    fn running_on(&self, name: &str) -> bool {
        self.jobs
            .iter()
            .any(|j| j.box_name == name && matches!(j.state, State::Running))
    }

    fn get_mut(&mut self, id: &str) -> Option<&mut ApplyJob> {
        self.jobs.iter_mut().find(|j| j.id == id)
    }

    fn push(&mut self, job: ApplyJob) {
        self.jobs.push_back(job);
        // forget the oldest finished ones; a running job is never forgotten
        while self.jobs.len() > KEEP_FINISHED {
            match self
                .jobs
                .iter()
                .position(|j| !matches!(j.state, State::Running))
            {
                Some(i) => {
                    self.jobs.remove(i);
                }
                None => break,
            }
        }
    }
}

/// What a change to a box finished with, as the worker hands it back.
pub struct Applied {
    pub(super) job_id: String,
    pub(super) plan: Plan,
    pub(super) outcome: Result<Option<BoxRecord>, Error>,
    /// A change that stops the machine (a resize, an upgrade) first gets the box ready; an upgrade that does not stop it
    /// asks for a plain checkpoint. What that said.
    pub(super) upgrade_checkpoint: Option<Step>,
    /// The box that was made ready for a stop: released again if the change fails, so it does not keep refusing runs.
    pub(super) quiesced: Option<BoxRecord>,
    pub(super) new_store_accepted: bool,
    /// A backup restored into a new box: the box being made, so a failed create forgets the restore it remembered.
    pub(super) restore_to: Option<BoxName>,
}

fn job_json(j: &ApplyJob) -> Value {
    let mut v = json!({
        "id": j.id,
        "box": j.box_name,
        "operation": j.verb,
        "started_ms": j.started_ms,
    });
    match &j.state {
        State::Running => v["state"] = json!("running"),
        State::Done(result) => {
            v["state"] = json!("done");
            v["result"] = result.clone();
        }
        State::Failed { status, body } => {
            v["state"] = json!("failed");
            v["status"] = json!(status);
            v["failure"] = body.clone();
        }
    }
    v
}

impl App {
    /// A change that is not a restic action: run it on its own thread and answer with the job. `None` when the plan is a
    /// restic action, which is quick and goes through the box's agent on the request, as before.
    pub(super) fn start_apply_job(
        &mut self,
        plan: &Plan,
        new_store_accepted: bool,
        upgrade_checkpoint: Option<Step>,
        quiesced: Option<BoxRecord>,
    ) -> Option<Resp> {
        if matches!(
            plan.operation,
            Operation::ResticBackup { .. }
                | Operation::ResticForget { .. }
                | Operation::ResticRestore { .. }
        ) {
            return None;
        }
        let name = plan.operation.box_name().to_string();
        let job_id = match super::random_hex(8) {
            Ok(i) => i,
            Err(e) => return Some(Resp::error(500, "internal", &e)),
        };
        let provider = Arc::clone(&self.provider);
        let restore_to = match &plan.operation {
            Operation::RestoreToNewBox { from, to, snapshot } => {
                self.remember_new_box_restore(from, to, snapshot);
                Some(to.clone())
            }
            _ => None,
        };
        let (jid, p) = (job_id.clone(), plan.clone());
        let restoring = restore_to.clone();
        let job: Job = Box::new(move || {
            let outcome = if restoring.is_some() {
                crate::restore_new::create_box(provider.as_ref(), &p)
            } else {
                provider.apply(&p)
            };
            Done::Applied(Box::new(Applied {
                job_id: jid,
                plan: p,
                outcome,
                upgrade_checkpoint,
                quiesced,
                new_store_accepted,
                restore_to: restoring,
            }))
        });
        self.apply_jobs.push(ApplyJob {
            id: job_id.clone(),
            box_name: name.clone(),
            verb: plan.operation.verb(),
            started_ms: unix_ms(),
            actor: self.current_actor.clone(),
            state: State::Running,
        });
        if !self.worker.submit_detached(job) {
            if let Some(j) = self.apply_jobs.get_mut(&job_id) {
                j.state = State::Failed {
                    status: 503,
                    body: json!({
                        "code": "server_busy",
                        "message": "the change could not be started; plan again",
                        "error": "the change could not be started; plan again",
                    }),
                };
            }
            return Some(Resp::error(
                503,
                "server_busy",
                "the change could not be started; plan again",
            ));
        }
        if self.worker.is_inline() {
            // tests: the job already ran, so its result is applied now
            self.apply_done(unix_ms());
        }
        self.version
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let v = self
            .apply_jobs
            .get_mut(&job_id)
            .map_or_else(|| json!({ "id": job_id }), |j| job_json(j));
        Some(Resp::json(202, &json!({ "job_id": job_id, "job": v })))
    }

    /// The refusals that come before a change starts: one change per box at a time, and a bound on the total.
    pub(super) fn apply_job_refusal(&self, plan: &Plan) -> Option<Resp> {
        let name = plan.operation.box_name().to_string();
        if self.apply_jobs.running_on(&name) {
            return Some(Resp::error(
                409,
                "box_busy",
                "another change to this box is still running; wait for it to finish",
            ));
        }
        if self.apply_jobs.running() >= MAX_RUNNING {
            return Some(Resp::error(
                429,
                "too_many_changes",
                "too many changes are running; wait for one to finish",
            ));
        }
        None
    }

    /// `GET /v1/jobs/<id>`: where a change stands. A result the worker has finished is applied first.
    pub(super) fn apply_job(&mut self, id: &str) -> Resp {
        self.apply_done(unix_ms());
        match self.apply_jobs.get_mut(id) {
            Some(j) => Resp::json(200, &job_json(j)),
            None => Resp::error(
                404,
                "not_found",
                "no such change (this server keeps recent ones while it runs)",
            ),
        }
    }

    /// A change finished: the activity entry, the follow-up the plan needs, and the job's answer.
    pub(super) fn applied_done(&mut self, a: Applied) {
        let Applied {
            job_id,
            plan,
            outcome,
            upgrade_checkpoint,
            quiesced,
            new_store_accepted,
            restore_to,
        } = a;
        if let (Err(_), Some(to)) = (&outcome, &restore_to) {
            self.forget_new_box_restore_if_absent(to);
        }
        let asked_by = self.apply_jobs.get_mut(&job_id).map(|j| j.actor.clone());
        let was = std::mem::replace(
            &mut self.current_actor,
            asked_by.unwrap_or(super::Actor::Automation),
        );
        let finished = self.finish_apply(
            &plan,
            outcome,
            upgrade_checkpoint,
            quiesced.as_ref(),
            new_store_accepted,
        );
        self.current_actor = was;
        let state = match finished {
            Ok(v) => State::Done(v),
            Err(r) => State::Failed {
                status: r.status,
                body: serde_json::from_slice(&r.body).unwrap_or(Value::Null),
            },
        };
        if let Some(j) = self.apply_jobs.get_mut(&job_id) {
            j.state = state;
        }
        self.version
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    /// What follows a change the provider has carried out (or refused): Activity, the audit chain and the follow-ups.
    /// `Ok` is the body a client gets; `Err` is the refusal.
    pub(super) fn finish_apply(
        &mut self,
        plan: &Plan,
        outcome: Result<Option<BoxRecord>, Error>,
        upgrade_checkpoint: Option<Step>,
        quiesced: Option<&BoxRecord>,
        new_store_accepted: bool,
    ) -> Result<Value, Resp> {
        let verb = plan.operation.verb();
        let name = plan.operation.box_name().to_string();
        let risk: Option<Risk> = plan.max_risk();
        if outcome.is_ok() && matches!(plan.operation, Operation::Snapshot { .. }) {
            self.note_manual_run(&name, unix_ms());
        }
        match outcome {
            Ok(result) => {
                self.log_activity(&format!("apply {verb}"), &name, risk, "applied");
                if matches!(plan.operation, Operation::Destroy { .. }) {
                    // what is kept for the IDE and desktop of a box that is gone must not be offered to a box made again
                    // under its name
                    self.code.forget_box(&name);
                }
                self.after_upgrade_applied(plan, new_store_accepted);
                self.version
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut body = json!({ "plan": plan, "applied": true, "result": result });
                match (upgrade_checkpoint, &plan.operation) {
                    (Some(step), Operation::Upgrade { image, .. }) => {
                        body["upgrade"] = json!({ "image": image, "checkpoint": step });
                    }
                    (Some(step), Operation::Resize { .. }) => {
                        body["quiesce"] = json!(step);
                    }
                    _ => {}
                }
                // the copy of the old system disk an upgrade kept: its id, so the dashboard can say it
                if crate::run::upgrade::plan_keeps_old_disk(plan)
                    && matches!(plan.operation, Operation::Upgrade { .. })
                {
                    body["old_system_disk_snapshot"] =
                        json!(crate::run::upgrade::kept_copy_id(result.as_ref()).ok());
                }
                Ok(body)
            }
            Err(e) => {
                self.log_activity(&format!("apply {verb}"), &name, risk, "refused or failed");
                // the box did not stop: it must not keep refusing runs
                if let Some(rec) = quiesced {
                    crate::quiesce::release(self.agent.as_ref(), rec);
                }
                Err(Resp::from_core(&e))
            }
        }
    }
}
