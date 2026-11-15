//! How the scheduler starts work: two small traits, so it never owns a second run system.
//!
//! [`RunStarter`] is the one place a run begins. The task-board and supervised-run work provides the real one (caps,
//! live log, approvals); until it is connected the server uses [`NoRunSystem`], which says so plainly on every run
//! instead of pretending. [`BoxControl`] reads a box and wakes a
//! paused one through the provider's own plan and apply.

#[cfg(test)]
use std::collections::BTreeMap;
use std::sync::Arc;
#[cfg(test)]
use std::sync::Mutex;

use ozbox_core::{BoxName, BoxState, Operation, Provider};

use super::model::Caps;

/// Everything a run needs, from a schedule, a manual run or a trigger.
#[derive(Debug, Clone, PartialEq)]
pub struct RunRequest {
    /// Also the idempotency key: starting the same id twice starts one run.
    pub run_id: String,
    /// `schedule`, `manual` or `trigger`.
    pub source: String,
    /// The schedule or trigger id.
    pub owner_id: String,
    pub engine: String,
    /// The instruction. For a trigger this already carries the event as marked, untrusted data.
    pub prompt: String,
    pub skill: Option<String>,
    pub box_name: String,
    pub caps: Caps,
    pub results_to: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartError {
    /// A reason code (`not_connected`, `refused`, ...).
    pub reason: String,
    /// Words a person reads. Never a secret.
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Poll {
    Running,
    Finished {
        ok: bool,
        detail: String,
        cost: Option<f64>,
        result_url: Option<String>,
    },
    /// The run system does not know this reference (it was restarted, or lost it).
    Unknown,
}

pub trait RunStarter: Send + Sync {
    fn start(&self, req: &RunRequest) -> Result<String, StartError>;
    fn poll(&self, run_ref: &str) -> Poll;
}

/// What the scheduler needs from the fleet.
pub trait BoxControl: Send + Sync {
    /// `None` when the box does not exist.
    fn state(&self, name: &str) -> Result<Option<BoxState>, String>;
    /// Wake a paused box and wait until it runs.
    fn resume(&self, name: &str) -> Result<(), String>;
    /// The box to use for a profile: a running one first, else a paused one.
    fn pick(&self, profile: &str) -> Result<Option<String>, String>;
}

/// The run system is not connected: every start fails with that reason.
pub struct NoRunSystem;

impl RunStarter for NoRunSystem {
    fn start(&self, _: &RunRequest) -> Result<String, StartError> {
        Err(StartError {
            reason: "not_connected".into(),
            detail: crate::messages::t("sched.no_run_system", &[]),
        })
    }

    fn poll(&self, _: &str) -> Poll {
        Poll::Unknown
    }
}

/// A stand-in whose runs take `take_ms` and succeed, for tests of the scheduler's own behaviour. Nothing real happens.
#[cfg(test)]
#[derive(Default)]
pub struct SimulatedRuns {
    pub take_ms: u64,
    started: Mutex<BTreeMap<String, u64>>,
    pub clock: Mutex<Option<u64>>,
}

#[cfg(test)]
impl SimulatedRuns {
    pub fn new(take_ms: u64) -> Self {
        SimulatedRuns {
            take_ms,
            ..Default::default()
        }
    }

    fn now(&self) -> u64 {
        self.clock
            .lock()
            .ok()
            .and_then(|c| *c)
            .unwrap_or_else(super::now_ms)
    }
}

#[cfg(test)]
impl RunStarter for SimulatedRuns {
    fn start(&self, req: &RunRequest) -> Result<String, StartError> {
        let reference = format!("sim-{}", req.run_id);
        let now = self.now();
        if let Ok(mut s) = self.started.lock() {
            s.entry(reference.clone()).or_insert(now);
        }
        Ok(reference)
    }

    fn poll(&self, run_ref: &str) -> Poll {
        let Some(at) = self
            .started
            .lock()
            .ok()
            .and_then(|s| s.get(run_ref).copied())
        else {
            return Poll::Unknown;
        };
        if self.now().saturating_sub(at) >= self.take_ms {
            Poll::Finished {
                ok: true,
                detail: crate::messages::t("sched.sim_done", &[]),
                cost: None,
                result_url: None,
            }
        } else {
            Poll::Running
        }
    }
}

/// Reads and wakes boxes through the provider the server already holds.
pub struct ProviderBoxes {
    pub provider: Arc<dyn Provider>,
}

impl BoxControl for ProviderBoxes {
    fn state(&self, name: &str) -> Result<Option<BoxState>, String> {
        let n = BoxName::new(name).map_err(|e| e.to_string())?;
        self.provider
            .get(&n)
            .map(|r| r.map(|r| r.state))
            .map_err(|e| e.to_string())
    }

    fn resume(&self, name: &str) -> Result<(), String> {
        let n = BoxName::new(name).map_err(|e| e.to_string())?;
        // The same plan-then-apply every resume goes through; a schedule is the person's standing consent to it.
        let plan = self
            .provider
            .plan(&Operation::Resume { name: n })
            .map_err(|e| e.to_string())?;
        self.provider
            .apply(&plan)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    fn pick(&self, profile: &str) -> Result<Option<String>, String> {
        let recs = self.provider.list().map_err(|e| e.to_string())?;
        let mut paused = None;
        for r in recs {
            let has = r.spec.labels.get("profile").is_some_and(|v| v == profile);
            if !has {
                continue;
            }
            if r.state == BoxState::Running {
                return Ok(Some(r.spec.name.to_string()));
            }
            if r.state == BoxState::Paused && paused.is_none() {
                paused = Some(r.spec.name.to_string());
            }
        }
        Ok(paused)
    }
}
