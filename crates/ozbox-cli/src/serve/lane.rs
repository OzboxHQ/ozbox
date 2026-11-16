//! The slow lane of `ozbox serve`: what keeps one slow cloud or box call from holding every other request.
//!
//! `ozbox serve` owns all of its state on one request loop (see `serve::serve`). That loop must never wait on a cloud or
//! on a box: listing the boxes of an AWS account is a handful of `aws` calls and takes ten to twenty seconds, and asking a
//! box for its usage goes through Session Manager. While the loop waited for one of those, `/v1/info`, the dashboard's
//! files and every other page waited behind it, and the dashboard gave up on a server that was only busy.
//!
//! So the loop checks who is asking (sign-in, same origin, role: everything `guard` does) and then, for the read-only
//! routes that wait on the cloud or on a box, hands the request to a **bounded pool of worker threads** instead of
//! answering it itself. A worker holds only shared handles (the provider, the box agent, and the caches below), never the
//! server's state, so nothing here needs the state to be thread-safe. Three things keep the work bounded:
//!
//! * [`ListCache`]: the box list is a snapshot with its age. A request gets the snapshot at once and, when it is old,
//!   starts **one** refresh (single-flight) and waits a short, fixed time for it; if the refresh is slower it answers with
//!   the snapshot, marked as refreshing. The first read after start has no snapshot and answers `warming` until it lands.
//! * [`Flights`]: every other slow call (one box's usage, its self-test, one provider `get`) is one flight per key. A
//!   second request for the same box joins the flight in progress instead of starting another call, each request waits
//!   at most its budget, and the flights running at once are capped. A box that does not answer is reported as not
//!   reached, after its budget, and the others are not held for it.
//! * [`Pool`]: a fixed number of workers and a fixed queue. A request that finds the queue full is answered `503 busy`
//!   at once, never queued without limit.
//!
//! Everything that changes something stays on the loop, in order. Tests drive [`App::handle`], which runs a deferred job
//! on the spot, so the answers are the same with or without a pool.

use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use ozbox_core::{BoxName, BoxRecord, BoxState, Error, MetricsSample, Provider};
use serde_json::json;

use super::agent::{AgentError, BoxAgent};
use super::{metrics_sim, parse_query, parse_rfc3339_ms, unix_ms, Resp, MAX_SERIES_POINTS};

/// What a deferred read answers with: the answer, and the headers that go with it.
pub(super) type Reply = (Resp, Vec<(String, String)>);

/// A read that waits on the cloud or on a box, run off the request loop.
pub(super) type Job = Box<dyn FnOnce() -> Reply + Send>;

/// What the request loop does with a request that passed the guard.
pub(super) enum Step {
    /// Answered on the loop, at once.
    Done(Resp),
    /// Waits on the cloud or a box: run on a worker (or on the spot, where there is no pool).
    Later(Job),
}

/// How many workers answer deferred reads, how many may wait for one, and how many cloud or box calls run at once.
pub(super) const POOL_WORKERS: usize = 12;
pub(super) const POOL_QUEUE: usize = 64;
const MAX_FLIGHTS: usize = 16;

/// The waits of the slow lane. The defaults are what the server runs with; a test shortens them.
#[derive(Debug, Clone, Copy)]
pub(super) struct Budgets {
    /// A snapshot younger than this is served without asking the provider again.
    pub list_fresh: Duration,
    /// How long a request waits for a refresh when it already has an older snapshot to show.
    pub list_wait_stale: Duration,
    /// How long the first request waits when there is no snapshot at all.
    pub list_wait_cold: Duration,
    /// How long the request loop itself waits for a refresh when it has an older snapshot to show: it answers a few
    /// reads of its own from the list (usage, cost, backups), and may be held this long, never for a whole read.
    pub loop_wait_stale: Duration,
    /// How long the server's own periodic rounds wait for the read they start.
    pub tick_wait: Duration,
    /// How old a snapshot may be and still stand in for a per-box lookup.
    pub record_max_age: Duration,
    /// One provider lookup of one box.
    pub get: Duration,
    /// One box's usage (now, series, incidents) and its image.
    pub status: Duration,
    /// One box's self-test, which runs real checks on the box.
    pub selftest: Duration,
    /// The provider check (a whole listing of the account).
    pub check: Duration,
}

impl Default for Budgets {
    fn default() -> Self {
        Budgets {
            list_fresh: Duration::from_secs(4),
            list_wait_stale: Duration::from_millis(1500),
            list_wait_cold: Duration::from_millis(2000),
            loop_wait_stale: Duration::from_millis(150),
            tick_wait: Duration::from_millis(100),
            record_max_age: Duration::from_secs(30),
            get: Duration::from_secs(10),
            status: Duration::from_secs(10),
            selftest: Duration::from_secs(25),
            check: Duration::from_secs(60),
        }
    }
}

impl Budgets {
    /// What `App::new` starts with. Under test a snapshot is never fresh, so a test that changes the provider behind the
    /// server's back (the demo's boxes are made through the provider, not the API) always reads the change.
    pub(super) fn for_app() -> Self {
        #[cfg(test)]
        {
            Budgets {
                list_fresh: Duration::ZERO,
                tick_wait: Duration::from_secs(2),
                loop_wait_stale: Duration::from_secs(2),
                ..Budgets::default()
            }
        }
        #[cfg(not(test))]
        {
            Budgets::default()
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn busy() -> Resp {
    Resp::error(
        503,
        "busy",
        "the server is already reading as many boxes as it will at once; try again in a moment",
    )
}

fn retry_after(secs: u64) -> Vec<(String, String)> {
    vec![("Retry-After".to_string(), secs.to_string())]
}

// ---------------------------------------------------------------------------------------------------------------------
// Flights: one call per key, shared by everyone who asks for it, each asker waiting at most its budget.
// ---------------------------------------------------------------------------------------------------------------------

/// A count of calls that may run at once. Taking a permit fails, rather than waits, when none is left.
pub(super) struct Permits {
    used: AtomicUsize,
    cap: usize,
}

impl Permits {
    pub(super) fn new(cap: usize) -> Arc<Self> {
        Arc::new(Permits {
            used: AtomicUsize::new(0),
            cap,
        })
    }

    fn take(self: &Arc<Self>) -> Option<Permit> {
        let mut now = self.used.load(Ordering::SeqCst);
        loop {
            if now >= self.cap {
                return None;
            }
            match self
                .used
                .compare_exchange(now, now + 1, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => return Some(Permit(Arc::clone(self))),
                Err(seen) => now = seen,
            }
        }
    }
}

struct Permit(Arc<Permits>);

impl Drop for Permit {
    fn drop(&mut self) {
        self.0.used.fetch_sub(1, Ordering::SeqCst);
    }
}

/// What one flight came to, as the asker sees it.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Flown<T> {
    Done(T),
    /// Still running when this asker's budget ended. It goes on, and its answer is kept for the next asker.
    TimedOut,
    /// Too many calls are already running; this one was not started.
    Busy,
    /// The call panicked, or its thread could not be started.
    Failed,
}

struct Flight<T> {
    /// `None` while running; `Some(None)` when it panicked.
    out: Mutex<Option<Option<T>>>,
    done: Condvar,
}

/// The calls in progress, by key.
pub(super) struct Flights<T> {
    open: Arc<Mutex<HashMap<String, Arc<Flight<T>>>>>,
    permits: Arc<Permits>,
}

impl<T: Clone + Send + 'static> Flights<T> {
    pub(super) fn new(permits: Arc<Permits>) -> Self {
        Flights {
            open: Arc::new(Mutex::new(HashMap::new())),
            permits,
        }
    }

    /// Run `work` unless a call for `key` is already running, in which case join that one; wait at most `budget` for the
    /// answer. A call still running when the budget ends is not stopped (nothing can stop a shell command from here): it
    /// finishes on its own thread, and because it holds the key until then, a box that never answers costs one thread, not
    /// one per request.
    pub(super) fn run(
        &self,
        key: &str,
        budget: Duration,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> Flown<T> {
        let (flight, started) = {
            let mut open = lock(&self.open);
            if let Some(f) = open.get(key) {
                (Arc::clone(f), None)
            } else {
                let Some(permit) = self.permits.take() else {
                    return Flown::Busy;
                };
                let f = Arc::new(Flight {
                    out: Mutex::new(None),
                    done: Condvar::new(),
                });
                open.insert(key.to_string(), Arc::clone(&f));
                (f, Some(permit))
            }
        };
        if let Some(permit) = started {
            let (mine, open, owned) =
                (Arc::clone(&flight), Arc::clone(&self.open), key.to_string());
            let spawned = std::thread::Builder::new()
                .name("ozbox-flight".into())
                .spawn(move || {
                    let _permit = permit;
                    let out = catch_unwind(AssertUnwindSafe(work)).ok();
                    // Leave the key first, so an asker that arrives from now on starts a fresh call; the ones already
                    // holding this flight still get its answer.
                    {
                        let mut open = lock(&open);
                        if open.get(&owned).is_some_and(|f| Arc::ptr_eq(f, &mine)) {
                            open.remove(&owned);
                        }
                    }
                    *lock(&mine.out) = Some(out);
                    mine.done.notify_all();
                });
            if spawned.is_err() {
                let mut open = lock(&self.open);
                if open.get(key).is_some_and(|f| Arc::ptr_eq(f, &flight)) {
                    open.remove(key);
                }
                return Flown::Failed;
            }
        }
        let guard = lock(&flight.out);
        let (guard, _) = flight
            .done
            .wait_timeout_while(guard, budget, |o| o.is_none())
            .unwrap_or_else(|e| e.into_inner());
        match &*guard {
            None => Flown::TimedOut,
            Some(Some(v)) => Flown::Done(v.clone()),
            Some(None) => Flown::Failed,
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// ListCache: the box list as a snapshot with its age, refreshed by one call at a time.
// ---------------------------------------------------------------------------------------------------------------------

/// The box list as the provider last gave it.
#[derive(Clone)]
pub(super) struct Snapshot {
    pub recs: Arc<Vec<BoxRecord>>,
    pub at: Instant,
    pub at_ms: u64,
    /// The server's change counter when the read began: a change applied since makes the snapshot stale at once.
    version: u64,
}

struct ListState {
    snap: Option<Snapshot>,
    running: bool,
    /// How the last refresh failed, kept until the next one starts. Only the words of the answer, never the provider's.
    failed: Option<Resp>,
    /// Counts refreshes started, so a waiter can tell its own refresh from an older one.
    started: u64,
}

/// What a request for the list got.
pub(super) enum Listed {
    Boxes {
        snap: Snapshot,
        /// A refresh is running, so the list may be about to change.
        refreshing: bool,
        /// The last refresh failed, so this is the last list that could be read.
        refresh_failed: bool,
    },
    /// No list has been read yet and the first read is not done.
    Warming,
    /// No list has been read, and the read that was made failed.
    Failed(Resp),
}

pub(super) struct ListCache {
    state: Mutex<ListState>,
    changed: Condvar,
    version: Arc<std::sync::atomic::AtomicU64>,
}

impl ListCache {
    pub(super) fn new(version: Arc<std::sync::atomic::AtomicU64>) -> Arc<Self> {
        Arc::new(ListCache {
            state: Mutex::new(ListState {
                snap: None,
                running: false,
                failed: None,
                started: 0,
            }),
            changed: Condvar::new(),
            version,
        })
    }

    fn current(&self) -> u64 {
        self.version.load(Ordering::SeqCst)
    }

    fn fresh(&self, s: &Snapshot, fresh_for: Duration) -> bool {
        s.version == self.current() && s.at.elapsed() < fresh_for
    }

    /// The list. A fresh snapshot is returned as it is. Otherwise one refresh is started (unless one is running) and
    /// waited for up to `wait_stale` (when there is a snapshot to fall back on) or `wait_cold` (when there is none).
    pub(super) fn get(self: &Arc<Self>, provider: &Arc<dyn Provider>, b: &Budgets) -> Listed {
        self.get_waiting(provider, b, b.list_wait_stale, b.list_wait_cold)
    }

    /// [`ListCache::get`] with the wait for a refresh, when there is an older snapshot to fall back on, given.
    pub(super) fn get_waiting(
        self: &Arc<Self>,
        provider: &Arc<dyn Provider>,
        b: &Budgets,
        wait_stale: Duration,
        wait_cold: Duration,
    ) -> Listed {
        let mut st = lock(&self.state);
        if let Some(s) = &st.snap {
            if self.fresh(s, b.list_fresh) {
                return Listed::Boxes {
                    snap: s.clone(),
                    refreshing: st.running,
                    refresh_failed: false,
                };
            }
        }
        if !st.running {
            st.running = true;
            st.failed = None;
            st.started += 1;
            let (me, provider) = (Arc::clone(self), Arc::clone(provider));
            let began = self.current();
            let spawned = std::thread::Builder::new()
                .name("ozbox-list".into())
                .spawn(move || me.refresh(provider.as_ref(), began));
            if spawned.is_err() {
                st.running = false;
                st.failed = Some(Resp::error(
                    500,
                    "internal",
                    "could not start reading the boxes",
                ));
            }
        }
        let mine = st.started;
        let wait = if st.snap.is_some() {
            wait_stale
        } else {
            wait_cold
        };
        let (st, _) = self
            .changed
            .wait_timeout_while(st, wait, |s| s.running && s.started == mine)
            .unwrap_or_else(|e| e.into_inner());
        match &st.snap {
            Some(s) => Listed::Boxes {
                snap: s.clone(),
                refreshing: st.running,
                refresh_failed: st.failed.is_some() && !st.running,
            },
            None if st.running => Listed::Warming,
            None => Listed::Failed(
                st.failed
                    .clone()
                    .unwrap_or_else(|| Resp::error(500, "internal", "the boxes could not be read")),
            ),
        }
    }

    /// The list for work the server starts on its own (alert rounds, price checks): whatever was last read, however old,
    /// after a short, fixed wait for the read that is started when the list is not fresh. `None` until a read has landed.
    pub(super) fn background(
        self: &Arc<Self>,
        provider: &Arc<dyn Provider>,
        b: &Budgets,
    ) -> Option<Snapshot> {
        match self.get_waiting(provider, b, b.tick_wait, b.tick_wait) {
            Listed::Boxes { snap, .. } => Some(snap),
            Listed::Warming | Listed::Failed(_) => None,
        }
    }

    fn refresh(&self, provider: &dyn Provider, began: u64) {
        /// Ends the refresh whatever happens to it, even a panic, so the list can be read again.
        struct Done<'a>(&'a ListCache);
        impl Drop for Done<'_> {
            fn drop(&mut self) {
                let mut st = lock(&self.0.state);
                if st.running {
                    st.running = false;
                    st.failed
                        .get_or_insert_with(|| Resp::error(500, "internal", "the read failed"));
                }
                drop(st);
                self.0.changed.notify_all();
            }
        }
        let _done = Done(self);
        let out = provider.list();
        let mut st = lock(&self.state);
        match out {
            Ok(recs) => {
                st.snap = Some(Snapshot {
                    recs: Arc::new(recs),
                    at: Instant::now(),
                    at_ms: unix_ms(),
                    version: began,
                });
                st.failed = None;
            }
            Err(e) => st.failed = Some(Resp::from_core(&e)),
        }
        st.running = false;
    }

    /// A box as the last list saw it, when that list is still good enough to stand in for a lookup of its own: no change
    /// has been applied since, and it is not older than `max_age`.
    fn record(&self, name: &BoxName, max_age: Duration) -> Option<BoxRecord> {
        let st = lock(&self.state);
        let s = st.snap.as_ref()?;
        if !self.fresh(s, max_age) {
            return None;
        }
        s.recs.iter().find(|r| &r.spec.name == name).cloned()
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// Pool: the workers, and the queue in front of them.
// ---------------------------------------------------------------------------------------------------------------------

/// A request handed to a worker, with the way to answer it.
pub(super) struct Work {
    pub request: tiny_http::Request,
    pub method: String,
    pub job: Job,
}

/// A fixed number of worker threads behind a fixed queue.
pub(super) struct Pool {
    tx: SyncSender<Box<Work>>,
}

impl Pool {
    pub(super) fn new(workers: usize, queue: usize) -> Pool {
        let (tx, rx) = sync_channel::<Box<Work>>(queue);
        let rx: Arc<Mutex<Receiver<Box<Work>>>> = Arc::new(Mutex::new(rx));
        for i in 0..workers {
            let rx = Arc::clone(&rx);
            let _ = std::thread::Builder::new()
                .name(format!("ozbox-lane-{i}"))
                .spawn(move || loop {
                    // Hold the receiver only while waiting for work, never while doing it.
                    let next = lock(&rx).recv();
                    let Ok(w) = next else { return };
                    let Work {
                        request,
                        method,
                        job,
                    } = *w;
                    let (resp, extra) = catch_unwind(AssertUnwindSafe(job)).unwrap_or_else(|_| {
                        (
                            Resp::error(500, "internal", "this request failed"),
                            Vec::new(),
                        )
                    });
                    super::send_answer(request, &method, resp, &extra);
                });
        }
        Pool { tx }
    }

    /// Queue `work`; when the queue is full it is given back, so the loop can answer `busy`.
    pub(super) fn submit(&self, work: Box<Work>) -> Result<(), Box<Work>> {
        match self.tx.try_send(work) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(w) | TrySendError::Disconnected(w)) => Err(w),
        }
    }
}

/// The answer for a request that found the queue full.
pub(super) fn busy_reply() -> Reply {
    (busy(), retry_after(1))
}

// ---------------------------------------------------------------------------------------------------------------------
// Lane: what is shared by every deferred read, and the reads themselves.
// ---------------------------------------------------------------------------------------------------------------------

/// The caches and limits shared by the reads of one server.
pub(super) struct Lane {
    pub budgets: Budgets,
    list: Arc<ListCache>,
    gets: Flights<Result<Option<BoxRecord>, Resp>>,
    calls: Flights<Resp>,
    /// The last provider check and when it was made (reused for a few seconds).
    check_last: Mutex<Option<(Instant, serde_json::Value)>>,
}

impl Lane {
    pub(super) fn new(version: Arc<std::sync::atomic::AtomicU64>, budgets: Budgets) -> Arc<Self> {
        let permits = Permits::new(MAX_FLIGHTS);
        Arc::new(Lane {
            budgets,
            list: ListCache::new(version),
            gets: Flights::new(Arc::clone(&permits)),
            calls: Flights::new(permits),
            check_last: Mutex::new(None),
        })
    }
}

impl Lane {
    /// The boxes for a read the request loop answers itself: the last read, held for a short, fixed time at most.
    pub(super) fn boxes_for_loop(
        &self,
        provider: &Arc<dyn Provider>,
    ) -> Result<Vec<BoxRecord>, Resp> {
        match self.list.get_waiting(
            provider,
            &self.budgets,
            self.budgets.loop_wait_stale,
            self.budgets.list_wait_cold,
        ) {
            Listed::Boxes { snap, .. } => Ok(snap.recs.as_ref().clone()),
            Listed::Warming => Err(Resp::error(
                503,
                "warming",
                "reading your boxes for the first time; this can take up to half a minute",
            )),
            Listed::Failed(r) => Err(r),
        }
    }

    /// The boxes for work the server starts on its own: never waits (see [`ListCache::background`]).
    pub(super) fn boxes_quietly(&self, provider: &Arc<dyn Provider>) -> Option<Vec<BoxRecord>> {
        self.list
            .background(provider, &self.budgets)
            .map(|s| s.recs.as_ref().clone())
    }
}

/// One deferred read: the handles it needs, and nothing of the server's state.
pub(super) struct ReadCtx {
    pub lane: Arc<Lane>,
    pub provider: Arc<dyn Provider>,
    pub agent: Arc<dyn BoxAgent>,
    pub simulated: bool,
    pub provider_id: String,
    /// `connected`, `this_box` or `demo`.
    pub mode: &'static str,
}

const AS_OF: &str = "X-Ozbox-Boxes-As-Of";
const REFRESHING: &str = "X-Ozbox-Boxes-Refreshing";
const REFRESH_FAILED: &str = "X-Ozbox-Boxes-Refresh-Failed";

impl ReadCtx {
    fn data_source(&self) -> &'static str {
        if self.simulated {
            "simulated"
        } else {
            "live"
        }
    }

    fn agent_error(e: &AgentError) -> Resp {
        match e {
            AgentError::Unreachable(why) => Resp::error(502, "agent_unreachable", why),
            AgentError::Unsupported(why) => Resp::error(501, "agent_unreachable", why),
        }
    }

    /// `GET /v1/provider/check`: whether the provider answers, asked now (or a few seconds ago, when asked again at once).
    pub(super) fn provider_check(&self) -> Reply {
        if let Some((at, body)) = &*lock(&self.lane.check_last) {
            if at.elapsed() < super::provider_check::REUSE_FOR {
                return (Resp::json(200, body), Vec::new());
            }
        }
        let (provider, id, mode) = (
            Arc::clone(&self.provider),
            self.provider_id.clone(),
            self.mode,
        );
        let budget = self.lane.budgets.check;
        let flown = self.lane.calls.run("provider-check", budget, move || {
            let body = super::provider_check::ask(provider.as_ref(), &id, mode);
            Resp::json(200, &body)
        });
        let resp = match flown {
            Flown::Done(r) => {
                if let Ok(body) = serde_json::from_slice::<serde_json::Value>(&r.body) {
                    *lock(&self.lane.check_last) = Some((Instant::now(), body));
                }
                r
            }
            Flown::TimedOut => Resp::error(
                504,
                "provider_slow",
                &format!(
                    "the provider did not answer within {} seconds",
                    budget.as_secs().max(1)
                ),
            ),
            Flown::Busy => busy(),
            Flown::Failed => Resp::error(500, "internal", "the check failed"),
        };
        (resp, Vec::new())
    }

    /// `GET /v1/boxes`: the list as of the last read, with how old it is.
    pub(super) fn boxes(&self) -> Reply {
        match self.lane.list.get(&self.provider, &self.lane.budgets) {
            Listed::Boxes {
                snap,
                refreshing,
                refresh_failed,
            } => {
                let mut h = vec![
                    (AS_OF.to_string(), snap.at_ms.to_string()),
                    (REFRESHING.to_string(), u8::from(refreshing).to_string()),
                ];
                if refresh_failed {
                    h.push((REFRESH_FAILED.to_string(), "1".to_string()));
                }
                (Resp::json(200, snap.recs.as_ref()), h)
            }
            Listed::Warming => (
                Resp::error(
                    503,
                    "warming",
                    "reading your boxes for the first time; this can take up to half a minute",
                ),
                retry_after(2),
            ),
            Listed::Failed(r) => (r, Vec::new()),
        }
    }

    /// The box, from the last list when that is still good, else from the provider (one lookup per box at a time).
    fn record(&self, name: &str) -> Result<BoxRecord, Resp> {
        let name = BoxName::new(name).map_err(|e| Resp::from_core(&e))?;
        if let Some(r) = self
            .lane
            .list
            .record(&name, self.lane.budgets.record_max_age)
        {
            return Ok(r);
        }
        let provider = Arc::clone(&self.provider);
        let asked = name.clone();
        let flown = self
            .lane
            .gets
            .run(&format!("get:{name}"), self.lane.budgets.get, move || {
                provider.get(&asked).map_err(|e| Resp::from_core(&e))
            });
        match flown {
            Flown::Done(Ok(Some(r))) => Ok(r),
            Flown::Done(Ok(None)) => Err(Resp::from_core(&Error::NotFound(name.to_string()))),
            Flown::Done(Err(r)) => Err(r),
            Flown::TimedOut => Err(Resp::error(
                504,
                "provider_slow",
                &format!(
                    "the provider did not answer within {} seconds",
                    self.lane.budgets.get.as_secs().max(1)
                ),
            )),
            Flown::Busy => Err(busy()),
            Flown::Failed => Err(Resp::error(500, "internal", "the lookup failed")),
        }
    }

    /// The box, provided it is running (only then does it report usage or answer its agent).
    fn running(&self, name: &str, why: &str) -> Result<BoxRecord, Resp> {
        let rec = self.record(name)?;
        if rec.state != BoxState::Running {
            return Err(Resp::error(
                409,
                "box_not_running",
                &format!("box {} is {}, so {why}", rec.spec.name, rec.state),
            ));
        }
        Ok(rec)
    }

    /// `GET /v1/boxes/<name>`.
    pub(super) fn get_box(&self, name: &str) -> Reply {
        (
            match self.record(name) {
                Ok(rec) => Resp::json(200, &rec),
                Err(r) => r,
            },
            Vec::new(),
        )
    }

    /// One call to a box, at most one at a time per box and kind, giving up on it after `budget`.
    fn ask(
        &self,
        kind: &str,
        rec: &BoxRecord,
        budget: Duration,
        call: impl FnOnce(&dyn BoxAgent, &BoxRecord) -> Resp + Send + 'static,
    ) -> Resp {
        let (agent, rec2) = (Arc::clone(&self.agent), rec.clone());
        let flown = self
            .lane
            .calls
            .run(&format!("{kind}:{}", rec.spec.name), budget, move || {
                call(agent.as_ref(), &rec2)
            });
        match flown {
            Flown::Done(r) => r,
            Flown::TimedOut => Self::agent_error(&AgentError::Unreachable(format!(
                "did not answer within {} seconds",
                budget.as_secs().max(1)
            ))),
            Flown::Busy => busy(),
            Flown::Failed => Resp::error(500, "internal", "the read failed"),
        }
    }

    /// `GET /v1/boxes/<name>/metrics/now`.
    pub(super) fn metrics_now(&self, name: &str) -> Reply {
        let rec = match self.running(name, "it reports no usage") {
            Ok(r) => r,
            Err(r) => return (r, Vec::new()),
        };
        let source = self.data_source();
        let resp = self.ask("now", &rec, self.lane.budgets.status, move |a, rec| match a
            .metrics_now(rec, unix_ms())
        {
            Ok(sample) => Resp::json(200, &json!({ "source": source, "sample": sample })),
            Err(e) => Self::agent_error(&e),
        });
        (resp, Vec::new())
    }

    /// `GET /v1/boxes/<name>/metrics`.
    pub(super) fn metrics_series(&self, name: &str, query: &str) -> Reply {
        let rec = match self.running(name, "it reports no usage") {
            Ok(r) => r,
            Err(r) => return (r, Vec::new()),
        };
        let params = parse_query(query);
        let step_label = params.get("step").map(String::as_str).unwrap_or("5s");
        let step_ms: u64 = match step_label {
            "5s" => 5_000,
            "1m" => 60_000,
            "1h" => 3_600_000,
            _ => {
                return (
                    Resp::error(400, "bad_request", "step must be 5s, 1m or 1h"),
                    Vec::new(),
                )
            }
        };
        let now = metrics_sim::bucket(unix_ms(), step_ms);
        let since = match params.get("since") {
            Some(s) => match parse_rfc3339_ms(s) {
                Some(ms) => ms,
                None => {
                    return (
                        Resp::error(400, "bad_request", "since must be an RFC 3339 timestamp"),
                        Vec::new(),
                    )
                }
            },
            None => now.saturating_sub(step_ms * 180),
        };
        let start = since.div_ceil(step_ms) * step_ms;
        let source = self.data_source();
        if start > now {
            return (
                Resp::json(
                    200,
                    &json!({ "source": source, "step": step_label, "samples": Vec::<MetricsSample>::new() }),
                ),
                Vec::new(),
            );
        }
        if (now - start) / step_ms + 1 > MAX_SERIES_POINTS {
            return (
                Resp::error(
                    400,
                    "range_too_large",
                    "that range has too many points; ask for a shorter range or a coarser step",
                ),
                Vec::new(),
            );
        }
        let label = step_label.to_string();
        let resp = self.ask(
            "series",
            &rec,
            self.lane.budgets.status,
            move |a, rec| match a.metrics_series(rec, start, now, step_ms) {
                Ok(samples) => Resp::json(
                    200,
                    &json!({ "source": source, "step": label, "samples": samples }),
                ),
                Err(e) => Self::agent_error(&e),
            },
        );
        (resp, Vec::new())
    }

    /// `GET /v1/boxes/<name>/selftest`.
    pub(super) fn selftest(&self, name: &str) -> Reply {
        let rec = match self.running(name, "its agent cannot be asked") {
            Ok(r) => r,
            Err(r) => return (r, Vec::new()),
        };
        let source = self.data_source();
        let resp = self.ask(
            "selftest",
            &rec,
            self.lane.budgets.selftest,
            move |a, rec| match a.selftest(rec, unix_ms()) {
                Ok(t) => Resp::json(200, &json!({ "source": source, "result": t })),
                Err(e) => Self::agent_error(&e),
            },
        );
        (resp, Vec::new())
    }

    /// `GET /v1/boxes/<name>/incidents`.
    pub(super) fn incidents(&self, name: &str, query: &str) -> Reply {
        let rec = match self.running(name, "its agent cannot be asked") {
            Ok(r) => r,
            Err(r) => return (r, Vec::new()),
        };
        let now = unix_ms();
        let since = match parse_query(query).get("since") {
            Some(s) => match parse_rfc3339_ms(s) {
                Some(ms) => ms,
                None => {
                    return (
                        Resp::error(400, "bad_request", "since must be an RFC 3339 timestamp"),
                        Vec::new(),
                    )
                }
            },
            None => now.saturating_sub(7 * 24 * 3_600_000),
        };
        let source = self.data_source();
        let resp = self.ask(
            "incidents",
            &rec,
            self.lane.budgets.status,
            move |a, rec| match a.incidents(rec, since, now) {
                Ok(v) => Resp::json(200, &json!({ "source": source, "incidents": v })),
                Err(e) => Self::agent_error(&e),
            },
        );
        (resp, Vec::new())
    }

    /// `GET /v1/boxes/<name>/image`: which image a box runs and which is the newest this account can see, for the Upgrade
    /// action. A box that is not running still answers: nothing here asks the box itself.
    pub(super) fn image_info(&self, name: &str) -> Reply {
        let rec = match self.record(name) {
            Ok(r) => r,
            Err(r) => return (r, Vec::new()),
        };
        let provider = Arc::clone(&self.provider);
        let region = rec.spec.region.clone();
        let budget = self.lane.budgets.status;
        let flown = self
            .lane
            .calls
            .run(&format!("image:{}", rec.spec.name), budget, move || {
                let (latest, latest_error) = match provider.latest_image(region.as_deref()) {
                    Ok(i) => (Some(i), None),
                    Err(e) => (None, Some(e.to_string())),
                };
                let current = rec.spec.image.clone();
                let upgrade_available = match (&current, &latest) {
                    (Some(c), Some(l)) => Some(*c != l.id),
                    _ => None,
                };
                Resp::json(
                    200,
                    &json!({
                        "box_name": rec.spec.name,
                        "current": current,
                        "latest": latest,
                        "latest_error": latest_error,
                        "upgrade_available": upgrade_available,
                        "unfinished_upgrade_to": rec.spec.labels.get(ozbox_core::UPGRADE_TO_LABEL),
                    }),
                )
            });
        let resp = match flown {
            Flown::Done(r) => r,
            Flown::TimedOut => Resp::error(
                504,
                "provider_slow",
                &format!(
                    "the provider did not answer within {} seconds",
                    budget.as_secs().max(1)
                ),
            ),
            Flown::Busy => busy(),
            Flown::Failed => Resp::error(500, "internal", "the read failed"),
        };
        (resp, Vec::new())
    }
}
