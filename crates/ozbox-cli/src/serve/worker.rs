//! Background work for `ozbox serve`: alert delivery, price fetches, Telegram polling and closing idle box connections.
//!
//! Everything here can wait on the network, so none of it runs on the request thread. The server owns all state; a job
//! is a closure over copies of what it needs, and its [`Done`] result comes back through a queue that the server applies
//! on its next tick. The queue to the worker is bounded: when it is full a job is refused (and the caller says so),
//! never queued without limit.
//!
//! Tests use the inline mode, which runs a job on the spot and queues its result, so a tick is deterministic.

use std::collections::VecDeque;
use std::sync::mpsc::{channel, sync_channel, Receiver, Sender, SyncSender, TrySendError};

use serde_json::Value;

use crate::bill::{BillError, BillReport};
use crate::notify::{Alert, BoxObs, BudgetObs, Delivery};
use crate::orphans::{ItemResult, OrphanScan};
use crate::pricing::PriceBook;

/// What a poll of Telegram came back with. `me` is present only on the first poll of a run (and after a stop), and `webhook`
/// when a webhook was looked for (at start, and after a 409).
pub struct Polled {
    pub token: String,
    pub me: Option<Result<crate::telegram::BotInfo, crate::telegram::ApiError>>,
    pub webhook: Option<Option<String>>,
    pub polled: Option<Result<(Vec<Value>, i64), crate::telegram::ApiError>>,
}

/// What a finished job reports.
pub enum Done {
    Nothing,
    /// A message to Telegram, Slack or WhatsApp: whether the app took it, and the said-once notice it was for, if any.
    ChatSent {
        flag: Option<String>,
        to: &'static str,
        ok: bool,
    },
    Housekeeping,
    Prices {
        now_ms: u64,
        result: Option<Result<PriceBook, String>>,
    },
    /// The daily read of the provider's bill and of the account's forgotten resources (either may be absent).
    Bill {
        now_ms: u64,
        bill: Option<Result<BillReport, BillError>>,
        orphans: Option<OrphanScan>,
    },
    /// Forgotten resources deleted under a confirmed plan, and what the account looked like afterwards.
    OrphansDeleted {
        now_ms: u64,
        plan_id: String,
        results: Vec<ItemResult>,
        rescan: OrphanScan,
        /// Who asked for the delete: the outcome is theirs, whoever's request happens to drain it.
        actor: super::Actor,
    },
    /// What one poll of Telegram found (see `serve::telegram_bridge`).
    TelegramPoll(Box<Polled>),
    /// A message that carries a pointer link was sent: its id, so it can be deleted when the link lapses.
    TelegramSent {
        chat_id: i64,
        message_id: i64,
        expires_ms: u64,
    },
    Observed {
        now_ms: u64,
        budget: Option<BudgetObs>,
        boxes: Vec<BoxObs>,
    },
    /// The server's own install of the tools chosen at create time, for one box.
    ToolsInstalled {
        name: String,
        ok: bool,
        /// Who started it (the automation retry loop when nobody did).
        actor: super::Actor,
    },
    /// What an upgrade finished with (the box answering, its self-test, its backup credentials), seen from the worker.
    UpgradeSettled {
        /// `upgrade` or `restore`: what the follow-up was for.
        what: &'static str,
        name: String,
        ready: crate::run::upgrade::Step,
        selftest_ok: Option<bool>,
        backup: crate::run::upgrade::Step,
        /// Who applied the upgrade.
        actor: super::Actor,
    },
    /// Deliveries made under the routing rules (or retried), each with the plan entry it came from.
    Routed {
        now_ms: u64,
        alert: Alert,
        results: Vec<(crate::channels::routing::Planned, Delivery)>,
        /// What was decided without sending (quiet hours, not set up), recorded together with the results.
        skipped: Vec<Delivery>,
        retry: bool,
    },

    /// A change to a box that ran on a thread of its own (`POST /v1/apply`): what the provider answered. Applying it
    /// writes the activity entry and does the follow-up the plan needs (see `serve::apply_jobs`).
    Applied(Box<crate::serve::apply_jobs::Applied>),

    /// A test send that ran in the background: what each channel answered, for the activity list and the alert record.
    TestSent {
        alert: Alert,
        channel: String,
        results: Vec<(crate::channels::routing::Planned, Delivery)>,
    },
}

pub type Job = Box<dyn FnOnce() -> Done + Send>;

enum Mode {
    Inline(VecDeque<Done>),
    Threaded {
        jobs: SyncSender<Job>,
        /// A second thread for alert deliveries, so a slow mail server delays neither the other jobs nor the next alert's
        /// first delivery by more than that delivery's own bound.
        deliveries: SyncSender<Job>,
        done: Receiver<Done>,
        /// For a change to a box, which can take minutes (an instance boot): it gets a thread of its own so it never
        /// holds up the alert, price and housekeeping jobs that share the lane above.
        detached: Sender<Done>,
    },
}

pub struct Worker {
    mode: Mode,
}

/// How many jobs may wait for the worker.
pub const QUEUE: usize = 16;

impl Worker {
    pub fn inline() -> Self {
        Self {
            mode: Mode::Inline(VecDeque::new()),
        }
    }

    /// A worker thread with a bounded queue. The thread ends when the worker is dropped.
    pub fn threaded() -> Self {
        Self::threaded_with(QUEUE)
    }

    pub fn threaded_with(queue: usize) -> Self {
        let (tx, done) = channel::<Done>();
        let lane = |name: &str, tx: Sender<Done>| -> Option<SyncSender<Job>> {
            let (jobs, rx) = sync_channel::<Job>(queue);
            std::thread::Builder::new()
                .name(name.into())
                .spawn(move || {
                    for job in rx {
                        if tx.send(job()).is_err() {
                            break;
                        }
                    }
                })
                .ok()
                .map(|_| jobs)
        };
        let (Some(jobs), Some(deliveries)) = (
            lane("ozbox-serve-worker", tx.clone()),
            lane("ozbox-serve-delivery", tx.clone()),
        ) else {
            return Self::inline();
        };
        Self {
            mode: Mode::Threaded {
                jobs,
                deliveries,
                done,
                detached: tx,
            },
        }
    }

    /// Whether jobs run on the spot (tests): the caller can apply their results at once.
    pub fn is_inline(&self) -> bool {
        matches!(self.mode, Mode::Inline(_))
    }

    /// Hand over a job that may take minutes (a change to a box). It runs on its own thread and its result comes back
    /// through the same queue. The caller bounds how many it starts. `false` = the thread could not be started.
    pub fn submit_detached(&mut self, job: Job) -> bool {
        match &mut self.mode {
            Mode::Inline(q) => {
                q.push_back(job());
                true
            }
            Mode::Threaded { detached, .. } => {
                let tx = detached.clone();
                std::thread::Builder::new()
                    .name("ozbox-serve-apply".into())
                    .spawn(move || {
                        let _ = tx.send(job());
                    })
                    .is_ok()
            }
        }
    }

    /// Hand over an alert delivery job: it has its own thread and queue (see [`Mode::Threaded`]).
    pub fn submit_delivery(&mut self, job: Job) -> bool {
        match &mut self.mode {
            Mode::Inline(q) => {
                q.push_back(job());
                true
            }
            Mode::Threaded { deliveries, .. } => match deliveries.try_send(job) {
                Ok(()) => true,
                Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => false,
            },
        }
    }

    /// Hand over a job. `false` = the queue is full (or the worker is gone) and the job was dropped.
    pub fn submit(&mut self, job: Job) -> bool {
        match &mut self.mode {
            Mode::Inline(q) => {
                q.push_back(job());
                true
            }
            Mode::Threaded { jobs, .. } => match jobs.try_send(job) {
                Ok(()) => true,
                Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => false,
            },
        }
    }

    /// Results that are ready, oldest first. Never waits.
    pub fn drain(&mut self) -> Vec<Done> {
        match &mut self.mode {
            Mode::Inline(q) => q.drain(..).collect(),
            Mode::Threaded { done, .. } => done.try_iter().collect(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::time::{Duration, Instant};

    #[test]
    fn inline_runs_on_the_spot_and_queues_the_result() {
        let mut w = Worker::inline();
        assert!(w.submit(Box::new(|| Done::Housekeeping)));
        assert!(matches!(w.drain().as_slice(), [Done::Housekeeping]));
        assert!(w.drain().is_empty());
    }

    #[test]
    fn a_slow_job_does_not_hold_the_caller() {
        let mut w = Worker::threaded();
        let gate = Arc::new(Barrier::new(2));
        let g = gate.clone();
        let started = Instant::now();
        assert!(w.submit(Box::new(move || {
            g.wait(); // the job is parked until the test lets it go
            Done::Housekeeping
        })));
        assert!(started.elapsed() < Duration::from_millis(200));
        assert!(w.drain().is_empty(), "nothing is ready while the job waits");
        gate.wait();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut got = Vec::new();
        while got.is_empty() && Instant::now() < deadline {
            got = w.drain();
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(matches!(got.as_slice(), [Done::Housekeeping]));
    }

    #[test]
    fn the_queue_is_bounded() {
        let mut w = Worker::threaded_with(2);
        let gate = Arc::new(Barrier::new(2));
        let g = gate.clone();
        assert!(w.submit(Box::new(move || {
            g.wait();
            Done::Nothing
        })));
        // Wait until the worker has picked the first job up, then fill the queue.
        std::thread::sleep(Duration::from_millis(100));
        assert!(w.submit(Box::new(|| Done::Nothing)));
        assert!(w.submit(Box::new(|| Done::Nothing)));
        assert!(
            !w.submit(Box::new(|| Done::Nothing)),
            "a full queue refuses"
        );
        gate.wait();
    }
}
