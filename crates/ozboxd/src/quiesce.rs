//! Quiesce: get a box ready for a stop that is coming on purpose (a resize, or an upgrade that stops the machine).
//!
//! Two things happen, in this order, and a third is deliberately not done.
//!
//! 1. **Runs end cleanly.** Queued runs are dropped first (so a run that frees memory cannot admit the next one), new runs
//!    are refused for a while, every running run is asked to end (SIGTERM to the processes in its scope), the daemon waits
//!    up to a grace period, and whatever is left is killed with the run's existing stop. Each run is reported with how it
//!    ended; a run killed but not yet gone after a short settling time is reported as such, never dropped. Nothing waits for
//!    a program that ignores the request for longer than the grace.
//! 2. **Uncommitted work is snapshotted** (see [`crate::checkpoint::Checkpointer::snapshot_all_hidden`]): a commit under
//!    `refs/ozbox/wip/`, with the working tree, the index, the branch, the stash and the remotes untouched, and nothing
//!    pushed. With `strict` the snapshot is taken **first**, and when it is incomplete the runs are not touched at all (no
//!    hold, nothing ended); when it is complete the runs end and a second, small snapshot catches what they wrote last.
//! 3. **Coding agents in tmux are told nothing.** Nothing is typed into a pane; their records on `/work` already bring them
//!    back after the stop (ADR 0049).
//!
//! The whole job keeps to [`bound_s`] seconds (the answer to `POST` says how many), so a caller that waits that long, plus a
//! margin, never stops the machine in the middle of a git write.
//!
//! The work runs in a thread of its own: a checkpoint plus a grace period is longer than a request on the socket may take,
//! so `POST` starts it (or says it is already going) and `GET` reads where it is. A second `POST` while one runs does
//! nothing more. A `POST` soon after one has finished is refused (429): a hold on new runs can be renewed once in
//! [`MIN_GAP_S`] seconds, not in a loop. The hold ends by itself ([`crate::runs::HOLD_MAX_MS`]) and `DELETE` ends it at
//! once, for a change that failed or was refused before the box stopped.
//!
//! The route is on the box user's socket only. The dashboard's own socket (`ozbox_core::daemon_scope`) does not carry it:
//! a dashboard that runs on a box cannot resize or upgrade it, so it has no use for it. A coding agent on the box runs as
//! the same user and can end its own programs anyway; what a `POST` adds is the hold, which is why it is rate limited and
//! audited. A controlled run (one with a capability) is ended here without its capability: only its lifetime is exposed.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use serde::Serialize;

use crate::api::lock;
use crate::checkpoint::{CheckpointReport, SYNC_S};
use crate::http::Response;
use crate::runs::{RunError, RunManager, RunState, HOLD_MAX_MS};
use crate::timeutil::Clock;

/// The wait for runs to end by themselves when the caller names none.
pub const DEFAULT_GRACE_S: u64 = 10;
/// The longest grace a caller may ask for.
pub const MAX_GRACE_S: u64 = 60;
/// How often the wait looks at the runs.
const POLL: Duration = Duration::from_millis(200);
/// After a kill, how long the daemon waits for the run to be gone, and how often it looks.
const SETTLE: Duration = Duration::from_secs(2);
const SETTLE_POLL: Duration = Duration::from_millis(50);
/// The time the snapshot may take in all (a strict one splits it: 90 s before the runs end, 30 s after).
pub const SNAPSHOT_TOTAL_S: u64 = 120;
const STRICT_FIRST_S: u64 = 90;
const STRICT_SECOND_S: u64 = 30;
/// A `POST` this soon after a finished job is refused (unless a `DELETE` came between).
pub const MIN_GAP_S: u64 = 30;

/// The longest a job can take, whatever happens: the grace, the settling after the kills, the snapshot (and its flushes,
/// two when strict) and a little for the clock. A caller waits at least this long, plus a margin.
pub const fn bound_s(grace_s: u64) -> u64 {
    grace_s + SETTLE.as_secs() + SNAPSHOT_TOTAL_S + 2 * SYNC_S + 6
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EndedRun {
    pub id: String,
    pub program: String,
    /// `finished` (it ended before it was asked), `ended` (it ended when asked), `killed` (it did not end within the
    /// grace and is gone), `exiting` (it was killed and had not finished exiting after the settling time),
    /// `not_stopped` (the kill itself failed) or `cancelled` (it was queued and never started).
    pub how: &'static str,
    pub exit_code: Option<i32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct RunsReport {
    pub runs: Vec<EndedRun>,
    /// Runs that were not gone when the job finished (`exiting` and `not_stopped` above). The stop will end them.
    pub not_stopped: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct QuiesceReport {
    pub runs: RunsReport,
    pub checkpoint: CheckpointReport,
    /// A strict job whose snapshot was incomplete stopped before it touched a run.
    #[serde(default)]
    pub runs_untouched: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Job {
    Idle,
    Running {
        started_ms: u64,
        bound_s: u64,
    },
    Done {
        started_ms: u64,
        finished_ms: u64,
        bound_s: u64,
        report: Box<QuiesceReport>,
    },
}

type Sleeper = Arc<dyn Fn(Duration) + Send + Sync>;
/// Takes the snapshot, with the time it may take.
type Snapshot = Arc<dyn Fn(Duration) -> CheckpointReport + Send + Sync>;
type Audit = Arc<dyn Fn(&str) + Send + Sync>;

pub struct Quiescer {
    runs: Arc<Mutex<RunManager>>,
    snapshot: Snapshot,
    clock: Arc<dyn Clock>,
    sleep: Sleeper,
    audit: Audit,
    state: Mutex<(u64, Job)>,
    /// The number of the last job a `DELETE` asked to stop (0 = none). The job looks at it between its steps.
    cancel: AtomicU64,
}

impl Quiescer {
    /// `snapshot` is what takes the work-in-progress snapshot (the caller holds the checkpoint lock inside it).
    pub fn new(
        runs: Arc<Mutex<RunManager>>,
        snapshot: Snapshot,
        clock: Arc<dyn Clock>,
        sleep: Sleeper,
    ) -> Self {
        Self {
            runs,
            snapshot,
            clock,
            sleep,
            audit: Arc::new(|_| {}),
            state: Mutex::new((0, Job::Idle)),
            cancel: AtomicU64::new(0),
        }
    }

    /// One line for the daemon's log for every `POST` and `DELETE` (the method, the job, the outcome; nothing else).
    pub fn with_audit(mut self, audit: Audit) -> Self {
        self.audit = audit;
        self
    }

    /// Begin a quiesce unless one is running. Returns the job number either way.
    fn begin(&self, grace: Duration) -> Option<u64> {
        let mut st = lock(&self.state);
        if matches!(st.1, Job::Running { .. }) {
            return None;
        }
        st.0 += 1;
        st.1 = Job::Running {
            started_ms: self.clock.now_ms(),
            bound_s: bound_s(grace.as_secs()),
        };
        Some(st.0)
    }

    fn cancelled(&self, job: u64) -> bool {
        self.cancel.load(Ordering::SeqCst) == job
    }

    /// A job that was asked to stop ends here: the hold it may have placed is lifted, and the job is forgotten (its report is
    /// not wanted). What it already did (runs asked to end, a snapshot taken) is not undone.
    fn end_cancelled(&self, job: u64) {
        lock(&self.runs).release_hold();
        let mut st = lock(&self.state);
        if st.0 == job {
            st.1 = Job::Idle;
        }
        drop(st);
        (self.audit)(&format!("quiesce job={job} cancelled"));
    }

    /// The whole job, in this thread. Public so a test can drive it without a thread.
    pub fn run_job(&self, job: u64, grace: Duration, strict: bool) {
        let (started_ms, bound) = match &lock(&self.state).1 {
            Job::Running {
                started_ms,
                bound_s,
            } => (*started_ms, *bound_s),
            _ => (self.clock.now_ms(), bound_s(grace.as_secs())),
        };
        if self.cancelled(job) {
            return self.end_cancelled(job);
        }
        let report = if strict {
            // The snapshot first: a snapshot that is incomplete ends the job before a run is touched.
            let first = (self.snapshot)(Duration::from_secs(STRICT_FIRST_S));
            if self.cancelled(job) {
                return self.end_cancelled(job);
            }
            if first.errors.is_empty() {
                let Some(runs) = self.stop_runs(job, grace) else {
                    return self.end_cancelled(job);
                };
                // what the runs wrote last (the first snapshot is in the newest ref when nothing changed)
                let checkpoint = (self.snapshot)(Duration::from_secs(STRICT_SECOND_S));
                QuiesceReport {
                    runs,
                    checkpoint,
                    runs_untouched: false,
                }
            } else {
                QuiesceReport {
                    runs: RunsReport::default(),
                    checkpoint: first,
                    runs_untouched: true,
                }
            }
        } else {
            let Some(runs) = self.stop_runs(job, grace) else {
                return self.end_cancelled(job);
            };
            if self.cancelled(job) {
                return self.end_cancelled(job);
            }
            let checkpoint = (self.snapshot)(Duration::from_secs(SNAPSHOT_TOTAL_S));
            QuiesceReport {
                runs,
                checkpoint,
                runs_untouched: false,
            }
        };
        let mut st = lock(&self.state);
        if st.0 == job && matches!(st.1, Job::Running { .. }) {
            if self.cancelled(job) {
                drop(st);
                return self.end_cancelled(job);
            }
            st.1 = Job::Done {
                started_ms,
                finished_ms: self.clock.now_ms(),
                bound_s: bound,
                report: Box::new(report),
            };
        }
    }

    /// `None` when the job was asked to stop (checked before the hold, between the runs asked to end, while waiting and
    /// before any kill): a hold already placed is lifted by the caller and nothing is killed after the request.
    fn stop_runs(&self, job: u64, grace: Duration) -> Option<RunsReport> {
        let mut report = RunsReport::default();
        // 1. refuse new runs, drop the queue, and list what is running
        if self.cancelled(job) {
            return None;
        }
        let (to_end, queued) = {
            let mut m = lock(&self.runs);
            m.hold_new_runs(HOLD_MAX_MS);
            let queued = m.cancel_queued();
            (m.running(), queued)
        };
        for q in queued {
            report.runs.push(EndedRun {
                id: q.id,
                program: q.program,
                how: "cancelled",
                exit_code: None,
            });
        }
        // 2. ask each to end
        let mut gone_before = Vec::new();
        for r in &to_end {
            if self.cancelled(job) {
                return None;
            }
            if lock(&self.runs).terminate(&r.id) == Err(RunError::NotFound) {
                gone_before.push(r.id.clone());
            }
        }
        // 3. wait, bounded, with the lock released while sleeping
        let deadline = self.clock.now_ms().saturating_add(grace.as_millis() as u64);
        loop {
            let left = {
                let mut m = lock(&self.runs);
                m.tick();
                let running = m.running();
                to_end.iter().any(|r| running.iter().any(|x| x.id == r.id))
            };
            if !left || self.clock.now_ms() >= deadline {
                break;
            }
            if self.cancelled(job) {
                return None;
            }
            (self.sleep)(POLL);
        }
        // 4. kill what is left with the run's own stop
        let mut killed = Vec::new();
        let mut kill_failed = Vec::new();
        if self.cancelled(job) {
            return None;
        }
        {
            let mut m = lock(&self.runs);
            let still: Vec<String> = m
                .running()
                .into_iter()
                .filter(|x| to_end.iter().any(|r| r.id == x.id))
                .map(|x| x.id)
                .collect();
            for id in &still {
                match m.stop(id) {
                    Ok(_) => killed.push(id.clone()),
                    Err(_) => kill_failed.push(id.clone()),
                }
            }
        }
        // 5. a kill is not instant (the scope is emptied asynchronously): look until they are gone or the settling time ends
        let settle_until = self
            .clock
            .now_ms()
            .saturating_add(SETTLE.as_millis() as u64);
        loop {
            let left = {
                let mut m = lock(&self.runs);
                m.tick();
                let running = m.running();
                killed.iter().any(|id| running.iter().any(|x| &x.id == id))
            };
            if !left || self.clock.now_ms() >= settle_until {
                break;
            }
            (self.sleep)(SETTLE_POLL);
        }
        let all = lock(&self.runs).list();
        for r in &to_end {
            let info = all.iter().find(|i| i.id == r.id);
            let running = info.is_some_and(|i| i.state == RunState::Running);
            let how = if kill_failed.contains(&r.id) {
                "not_stopped"
            } else if running {
                "exiting"
            } else if killed.contains(&r.id) {
                "killed"
            } else if gone_before.contains(&r.id) {
                "finished"
            } else {
                "ended"
            };
            if how == "not_stopped" || how == "exiting" {
                report.not_stopped += 1;
            }
            report.runs.push(EndedRun {
                id: r.id.clone(),
                program: r.program.clone(),
                how,
                exit_code: info.and_then(|i| i.exit_code),
            });
        }
        Some(report)
    }

    fn status_json(&self) -> serde_json::Value {
        let st = lock(&self.state);
        match &st.1 {
            Job::Idle => serde_json::json!({ "state": "idle", "job": st.0 }),
            Job::Running {
                started_ms,
                bound_s,
            } => {
                serde_json::json!({ "state": "running", "job": st.0, "started_ms": started_ms, "bound_s": bound_s, "cancelling": self.cancelled(st.0) })
            }
            Job::Done {
                started_ms,
                bound_s,
                report,
                ..
            } => serde_json::json!({
                "state": "done", "job": st.0, "started_ms": started_ms, "bound_s": bound_s, "report": report
            }),
        }
    }

    /// `POST` starts a job (or reports the one going), `GET` reads it, `DELETE` ends the hold on new runs and forgets a
    /// finished job.
    pub fn route(self: &Arc<Self>, method: &str, body: &[u8]) -> Response {
        match method {
            "GET" => Response::json(200, &self.status_json()),
            "POST" => {
                let (grace_s, strict) = if body.is_empty() {
                    (DEFAULT_GRACE_S, false)
                } else {
                    match serde_json::from_slice::<serde_json::Value>(body) {
                        Ok(v) => (
                            v.get("grace_s")
                                .and_then(serde_json::Value::as_u64)
                                .unwrap_or(DEFAULT_GRACE_S),
                            v.get("strict")
                                .and_then(serde_json::Value::as_bool)
                                .unwrap_or(false),
                        ),
                        Err(_) => return Response::error(400, "the body is not valid JSON"),
                    }
                };
                let grace_s = grace_s.min(MAX_GRACE_S);
                // a hold may be renewed once in MIN_GAP_S, not in a loop
                if let Job::Done { finished_ms, .. } = &lock(&self.state).1 {
                    let since = self.clock.now_ms().saturating_sub(*finished_ms) / 1000;
                    if since < MIN_GAP_S {
                        (self.audit)("quiesce POST refused: too soon after the last one");
                        return Response::json(
                            429,
                            &serde_json::json!({
                                "code": "quiesce_too_soon",
                                "error": "a quiesce finished a moment ago; wait, or end it with DELETE /v1/quiesce",
                                "retry_after_s": MIN_GAP_S - since,
                            }),
                        );
                    }
                }
                if let Some(job) = self.begin(Duration::from_secs(grace_s)) {
                    (self.audit)(&format!(
                        "quiesce POST job={job} grace_s={grace_s} strict={strict}"
                    ));
                    let me = self.clone();
                    let spawned = std::thread::Builder::new()
                        .name("quiesce".into())
                        .spawn(move || me.run_job(job, Duration::from_secs(grace_s), strict));
                    if spawned.is_err() {
                        let mut st = lock(&self.state);
                        st.1 = Job::Idle;
                        return Response::error(503, "could not start the quiesce");
                    }
                }
                Response::json(202, &self.status_json())
            }
            "DELETE" => {
                let mut st = lock(&self.state);
                let job = st.0;
                // A job that is running is asked to stop and stays "running" until its thread has seen it (so a `POST` cannot
                // start a second job beside it); a finished one is forgotten.
                if matches!(st.1, Job::Running { .. }) {
                    self.cancel.store(job, Ordering::SeqCst);
                } else {
                    st.1 = Job::Idle;
                }
                drop(st);
                lock(&self.runs).release_hold();
                (self.audit)(&format!("quiesce DELETE job={job}: hold lifted"));
                Response::json(200, &self.status_json())
            }
            _ => Response::error(405, "method not allowed"),
        }
    }
}

static GLOBAL: OnceLock<Arc<Quiescer>> = OnceLock::new();

/// Make the daemon's quiesce service reachable from the API. The first call wins.
pub fn install(q: Arc<Quiescer>) {
    let _ = GLOBAL.set(q);
}

pub fn global() -> Option<&'static Arc<Quiescer>> {
    GLOBAL.get()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::CheckpointBranch;
    use crate::runs::testing::{FakeCgroup, FakeMemory, FakeSpawner};
    use crate::runs::{RunConfig, RunRequest};
    use crate::timeutil::FakeClock;
    use std::sync::atomic::Ordering;

    const GIB: u64 = 1 << 30;

    struct Rig {
        q: Arc<Quiescer>,
        runs: Arc<Mutex<RunManager>>,
        sp: Arc<FakeSpawner>,
        clock: Arc<FakeClock>,
        snaps: Arc<Mutex<usize>>,
    }

    fn rig(avail: u64) -> Rig {
        let cg = Arc::new(FakeCgroup::default());
        let mem = Arc::new(FakeMemory::new(16 * GIB, avail));
        let sp = Arc::new(FakeSpawner::default());
        let clock = Arc::new(FakeClock::new(1_794_182_400_000));
        let runs = Arc::new(Mutex::new(RunManager::new(
            RunConfig::default(),
            cg,
            mem,
            sp.clone(),
            clock.clone(),
        )));
        let snaps = Arc::new(Mutex::new(0usize));
        let s2 = snaps.clone();
        let c2 = clock.clone();
        let q = Arc::new(Quiescer::new(
            runs.clone(),
            Arc::new(move |_budget| {
                *s2.lock().unwrap() += 1;
                CheckpointReport {
                    repos_scanned: 1,
                    branches: vec![CheckpointBranch {
                        repo: "p".into(),
                        branch: "refs/ozbox/wip/20261109T123456Z".into(),
                    }],
                    ..CheckpointReport::default()
                }
            }),
            clock.clone(),
            Arc::new(move |d| c2.advance(d.as_millis() as u64)),
        ));
        Rig {
            q,
            runs,
            sp,
            clock,
            snaps,
        }
    }

    fn req(gib: u64) -> RunRequest {
        let mut r = RunRequest::new(vec!["/usr/bin/sleep".into(), "1000".into()]);
        r.memory_request_bytes = gib * GIB;
        r
    }

    fn job(r: &Rig, grace_s: u64) -> QuiesceReport {
        job_with(r, grace_s, false)
    }

    fn job_with(r: &Rig, grace_s: u64, strict: bool) -> QuiesceReport {
        let g = Duration::from_secs(grace_s);
        let n = r.q.begin(g).unwrap();
        r.q.run_job(n, g, strict);
        match &lock(&r.q.state).1 {
            Job::Done { report, .. } => (**report).clone(),
            other => panic!("not done: {other:?}"),
        }
    }

    #[test]
    fn a_program_that_ends_when_asked_is_reported_ended_not_killed() {
        let r = rig(16 * GIB);
        r.sp.obeys_term.store(true, Ordering::SeqCst);
        let (id, _) = lock(&r.runs).start(req(1)).unwrap();
        let rep = job(&r, 10);
        assert_eq!(rep.runs.runs.len(), 1);
        assert_eq!(rep.runs.runs[0].id, id);
        assert_eq!(rep.runs.runs[0].how, "ended");
        assert_eq!(rep.runs.runs[0].exit_code, Some(143));
        assert_eq!(*r.snaps.lock().unwrap(), 1);
        assert_eq!(rep.checkpoint.branches.len(), 1);
    }

    #[test]
    fn a_program_that_ignores_the_request_is_killed_after_the_grace_and_not_before() {
        let r = rig(16 * GIB);
        lock(&r.runs).start(req(1)).unwrap(); // does not obey
        let t0 = r.clock.now_ms();
        let rep = job(&r, 3);
        assert_eq!(rep.runs.runs[0].how, "killed");
        assert_eq!(rep.runs.runs[0].exit_code, Some(137));
        let waited = r.clock.now_ms() - t0;
        assert!(
            (3_000..3_000 + 400).contains(&waited),
            "waited the grace, not less and not much more: {waited} ms"
        );
        assert_eq!(rep.runs.not_stopped, 0);
    }

    #[test]
    fn queued_runs_are_cancelled_first_and_none_is_admitted_when_a_run_ends() {
        let r = rig(GIB); // room for one
        r.sp.obeys_term.store(true, Ordering::SeqCst);
        let (a, _) = lock(&r.runs).start(req(1)).unwrap();
        let (b, st) = lock(&r.runs).start(req(1)).unwrap();
        assert_eq!(st, RunState::Queued);
        let rep = job(&r, 5);
        let by_id = |id: &str| rep.runs.runs.iter().find(|e| e.id == id).unwrap().how;
        assert_eq!(by_id(&b), "cancelled");
        assert_eq!(by_id(&a), "ended");
        assert_eq!(
            r.sp.spawned.lock().unwrap().len(),
            1,
            "the queued run never started"
        );
    }

    #[test]
    fn new_runs_are_refused_while_held_and_the_hold_ends_by_itself_or_on_delete() {
        let r = rig(16 * GIB);
        job(&r, 1);
        assert!(lock(&r.runs).start(req(1)).is_err(), "held");
        r.clock.advance(HOLD_MAX_MS + 1);
        assert!(lock(&r.runs).start(req(1)).is_ok(), "expired on its own");
        job(&r, 1);
        assert!(lock(&r.runs).start(req(1)).is_err());
        let resp = r.q.route("DELETE", b"");
        assert_eq!(resp.status, 200);
        assert!(lock(&r.runs).start(req(1)).is_ok(), "DELETE ended the hold");
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["state"], "idle");
    }

    #[test]
    fn a_second_quiesce_while_one_runs_does_nothing_more_and_a_rerun_after_is_safe() {
        let r = rig(16 * GIB);
        let g = Duration::from_secs(1);
        let n = r.q.begin(g).unwrap();
        assert!(r.q.begin(g).is_none(), "one at a time");
        r.q.run_job(n, g, false);
        // re-run after it finished: starts a new job; nothing left to stop; the snapshot is asked again (it is idempotent)
        let rep = job(&r, 1);
        assert!(rep.runs.runs.is_empty());
        assert_eq!(*r.snaps.lock().unwrap(), 2);
    }

    #[test]
    fn the_route_posts_polls_and_validates() {
        let r = rig(16 * GIB);
        let resp = r.q.route("POST", br#"{"grace_s": 1}"#);
        assert_eq!(resp.status, 202);
        let mut done = false;
        for _ in 0..200 {
            let v: serde_json::Value = serde_json::from_slice(&r.q.route("GET", b"").body).unwrap();
            if v["state"] == "done" {
                assert_eq!(v["report"]["checkpoint"]["branches"][0]["repo"], "p");
                done = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(done, "the job finished");
        assert_eq!(r.q.route("POST", b"not json").status, 400);
        assert_eq!(r.q.route("PUT", b"").status, 405);
        // a grace over the cap is cut to the cap, never refused and never honoured
        let n = r.q.begin(Duration::from_secs(1));
        assert!(n.is_some());
    }

    #[test]
    fn a_delete_before_the_job_reaches_a_run_stops_it_before_any_hold_or_kill() {
        for strict in [false, true] {
            let r = rig(16 * GIB);
            let (id, _) = lock(&r.runs).start(req(1)).unwrap();
            let g = Duration::from_secs(1);
            let n = r.q.begin(g).unwrap();
            let resp = r.q.route("DELETE", b"");
            let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
            assert_eq!(
                (v["state"].as_str(), v["cancelling"].as_bool()),
                (Some("running"), Some(true)),
                "still the same job until its thread has seen the request"
            );
            assert!(
                r.q.begin(g).is_none(),
                "no second job beside the cancelling one"
            );
            r.q.run_job(n, g, strict);
            let v: serde_json::Value = serde_json::from_slice(&r.q.route("GET", b"").body).unwrap();
            assert_eq!(v["state"], "idle");
            assert!(
                lock(&r.runs).running().iter().any(|x| x.id == id),
                "the run was not asked to end or killed (strict={strict})"
            );
            assert!(lock(&r.runs).start(req(1)).is_ok(), "no hold was placed");
        }
    }

    #[test]
    fn a_delete_during_the_wait_stops_the_job_before_the_kill_and_lifts_the_hold() {
        let cg = Arc::new(FakeCgroup::default());
        let mem = Arc::new(FakeMemory::new(16 * GIB, 16 * GIB));
        let sp = Arc::new(FakeSpawner::default());
        let clock = Arc::new(FakeClock::new(1_794_182_400_000));
        let runs = Arc::new(Mutex::new(RunManager::new(
            RunConfig::default(),
            cg,
            mem,
            sp,
            clock.clone(),
        )));
        let cell: Arc<Mutex<Option<Arc<Quiescer>>>> = Arc::new(Mutex::new(None));
        let (c2, cell2) = (clock.clone(), cell.clone());
        let q = Arc::new(Quiescer::new(
            runs.clone(),
            Arc::new(|_| CheckpointReport::default()),
            clock.clone(),
            Arc::new(move |d| {
                c2.advance(d.as_millis() as u64);
                // the person's change failed while the job waits for a program that ignores the request
                if let Some(q) = cell2.lock().unwrap().clone() {
                    q.route("DELETE", b"");
                }
            }),
        ));
        *cell.lock().unwrap() = Some(q.clone());
        let (id, _) = lock(&runs).start(req(1)).unwrap(); // does not obey
        let n = q.begin(Duration::from_secs(5)).unwrap();
        q.run_job(n, Duration::from_secs(5), false);
        let v: serde_json::Value = serde_json::from_slice(&q.route("GET", b"").body).unwrap();
        assert_eq!(v["state"], "idle");
        assert!(
            lock(&runs).running().iter().any(|x| x.id == id),
            "never killed after the request to stop"
        );
        assert!(lock(&runs).start(req(1)).is_ok(), "the hold is lifted");
        // a POST while a job runs returns that job, not a second one
        *cell.lock().unwrap() = None;
        let n2 = q.begin(Duration::from_secs(1)).unwrap();
        let resp = q.route("POST", br#"{"grace_s":1}"#);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!((resp.status, v["job"].as_u64()), (202, Some(n2)));
    }

    #[test]
    fn a_run_that_is_still_exiting_after_the_kill_is_reported_never_dropped() {
        let r = rig(16 * GIB);
        r.sp.slow_kill.store(true, Ordering::SeqCst);
        let (id, _) = lock(&r.runs).start(req(1)).unwrap();
        // the child's exit shows up one look late: still there at the first look after the kill, gone at the second
        let sp = r.sp.clone();
        let c2 = r.clock.clone();
        let looks = Arc::new(Mutex::new(0u32));
        let l2 = looks.clone();
        let q = Arc::new(Quiescer::new(
            r.runs.clone(),
            Arc::new(|_| CheckpointReport::default()),
            r.clock.clone(),
            Arc::new(move |d| {
                c2.advance(d.as_millis() as u64);
                if d == SETTLE_POLL {
                    let mut n = l2.lock().unwrap();
                    *n += 1;
                    if *n == 2 {
                        sp.exit(1001, 137);
                    }
                }
            }),
        ));
        let g = Duration::from_secs(1);
        let n = q.begin(g).unwrap();
        q.run_job(n, g, false);
        let Job::Done { report, .. } = &lock(&q.state).1 else {
            panic!("not done")
        };
        assert_eq!(report.runs.runs.len(), 1, "the run is in the report");
        assert_eq!(report.runs.runs[0].id, id);
        assert_eq!(
            report.runs.runs[0].how, "killed",
            "it was gone after a look"
        );
        assert_eq!(report.runs.not_stopped, 0);
    }

    #[test]
    fn a_run_that_never_exits_is_reported_as_exiting_and_counted_not_stopped() {
        let r = rig(16 * GIB);
        r.sp.slow_kill.store(true, Ordering::SeqCst);
        let (id, _) = lock(&r.runs).start(req(1)).unwrap();
        let rep = job(&r, 1);
        assert_eq!(rep.runs.runs.len(), 1, "never dropped");
        assert_eq!(rep.runs.runs[0].id, id);
        assert_eq!(rep.runs.runs[0].how, "exiting");
        assert_eq!(rep.runs.not_stopped, 1);
    }

    #[test]
    fn strict_takes_the_snapshot_first_and_touches_no_run_when_it_is_incomplete() {
        let cg = Arc::new(FakeCgroup::default());
        let mem = Arc::new(FakeMemory::new(16 * GIB, GIB)); // room for one run
        let sp = Arc::new(FakeSpawner::default());
        let clock = Arc::new(FakeClock::new(1_794_182_400_000));
        let runs = Arc::new(Mutex::new(RunManager::new(
            RunConfig::default(),
            cg,
            mem.clone(),
            sp.clone(),
            clock.clone(),
        )));
        let q = Arc::new(Quiescer::new(
            runs.clone(),
            Arc::new(|_| CheckpointReport {
                repos_scanned: 1,
                errors: vec!["web: git add failed".into()],
                ..CheckpointReport::default()
            }),
            clock.clone(),
            Arc::new(|_| {}),
        ));
        let (id, _) = lock(&runs).start(req(1)).unwrap();
        let (queued, st) = lock(&runs).start(req(1)).unwrap();
        assert_eq!(st, RunState::Queued);
        let g = Duration::from_secs(5);
        let n = q.begin(g).unwrap();
        q.run_job(n, g, true);
        let Job::Done { report, .. } = &lock(&q.state).1 else {
            panic!("not done")
        };
        assert!(report.runs_untouched);
        assert!(report.runs.runs.is_empty());
        let m = lock(&runs);
        assert!(m.running().iter().any(|x| x.id == id), "the run still runs");
        assert!(
            m.list()
                .iter()
                .any(|x| x.id == queued && x.state == RunState::Queued),
            "the queue is intact"
        );
        drop(m);
        assert!(
            sp.terms.lock().unwrap().is_empty(),
            "nothing was asked to end"
        );
        // and no hold was placed: a new run is accepted
        mem.set_available(16 * GIB);
        assert!(lock(&runs).start(req(1)).is_ok());
    }

    #[test]
    fn strict_with_a_complete_snapshot_ends_the_runs_and_snapshots_again() {
        let r = rig(16 * GIB);
        r.sp.obeys_term.store(true, Ordering::SeqCst);
        lock(&r.runs).start(req(1)).unwrap();
        let rep = job_with(&r, 5, true);
        assert!(!rep.runs_untouched);
        assert_eq!(rep.runs.runs[0].how, "ended");
        assert_eq!(*r.snaps.lock().unwrap(), 2, "before and after the runs end");
    }

    #[test]
    fn a_post_soon_after_a_finished_job_is_refused_until_a_delete_or_the_gap() {
        let r = rig(16 * GIB);
        job(&r, 1);
        let resp = r.q.route("POST", b"");
        assert_eq!(resp.status, 429);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(v["retry_after_s"].as_u64().unwrap() <= MIN_GAP_S);
        assert!(
            lock(&r.runs).start(req(1)).is_err(),
            "still held, not renewed"
        );
        r.q.route("DELETE", b"");
        assert_eq!(r.q.route("POST", br#"{"grace_s":1}"#).status, 202);
    }

    #[test]
    fn the_answer_says_how_long_the_job_can_take_and_every_post_and_delete_is_audited() {
        let r = rig(16 * GIB);
        let lines = Arc::new(Mutex::new(Vec::<String>::new()));
        let l2 = lines.clone();
        let q = Arc::new(
            Quiescer::new(
                r.runs.clone(),
                Arc::new(|_| CheckpointReport::default()),
                r.clock.clone(),
                Arc::new(|_| {}),
            )
            .with_audit(Arc::new(move |l| l2.lock().unwrap().push(l.to_string()))),
        );
        let resp = q.route("POST", br#"{"grace_s":7,"strict":true}"#);
        let v: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(v["bound_s"], bound_s(7));
        assert!(bound_s(7) > 7 + SNAPSHOT_TOTAL_S, "covers the snapshot too");
        q.route("DELETE", b"");
        let l = lines.lock().unwrap().join("\n");
        assert!(
            l.contains("quiesce POST job=1 grace_s=7 strict=true"),
            "{l}"
        );
        assert!(l.contains("quiesce DELETE"), "{l}");
    }
}
