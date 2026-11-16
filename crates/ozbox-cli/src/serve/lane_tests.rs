//! The slow lane over a real loopback socket and a provider and box that are slow on purpose.
//!
//! The promise under test: a cloud or box call that takes seconds never holds any other request, the box list is one read
//! at a time and served with its age, one box that does not answer does not stall the list or the other boxes, and the
//! number of calls in flight is bounded.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ozbox_core::{BoxName, BoxRecord, BoxSpec, Operation, Plan, Provider, Size};
use serde_json::Value;

use super::agent::{AgentError, BoxAgent};
use super::lane::{Budgets, Flights, Flown, ListCache, Listed, Permits};
use super::{run_loop, App};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const TOKEN: &str = "lane-token";

// ---------------------------------------------------------------------------------------------------------------------
// Slow stand-ins
// ---------------------------------------------------------------------------------------------------------------------

/// The demo provider, with a list that takes a while and can be made to fail, and a count of the lists asked for.
struct SlowCloud {
    inner: ozbox_core::Engine<ozbox_provider_fake::FakeBackend>,
    list_delay: Duration,
    lists: Arc<AtomicUsize>,
    fail: Arc<AtomicBool>,
}

impl Provider for SlowCloud {
    fn id(&self) -> &str {
        self.inner.id()
    }
    fn capabilities(&self) -> ozbox_core::Capabilities {
        self.inner.capabilities()
    }
    fn list(&self) -> ozbox_core::Result<Vec<BoxRecord>> {
        self.lists.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(self.list_delay);
        if self.fail.load(Ordering::SeqCst) {
            return Err(ozbox_core::Error::Config("the cloud said no".into()));
        }
        self.inner.list()
    }
    fn get(&self, name: &BoxName) -> ozbox_core::Result<Option<BoxRecord>> {
        self.inner.get(name)
    }
    fn plan(&self, op: &Operation) -> ozbox_core::Result<Plan> {
        self.inner.plan(op)
    }
    fn apply(&self, plan: &Plan) -> ozbox_core::Result<Option<BoxRecord>> {
        self.inner.apply(plan)
    }
}

struct Cloud {
    provider: SlowCloud,
    lists: Arc<AtomicUsize>,
    fail: Arc<AtomicBool>,
}

fn cloud(
    dir: &std::path::Path,
    boxes: &[&str],
    list_delay: Duration,
) -> Result<Cloud, Box<dyn std::error::Error>> {
    let inner = ozbox_provider_fake::open(dir);
    for name in boxes {
        let spec = BoxSpec::new(BoxName::new(*name)?, Size::M);
        let plan = inner.plan(&Operation::Create { spec })?;
        inner.apply(&plan)?;
    }
    let (lists, fail) = (
        Arc::new(AtomicUsize::new(0)),
        Arc::new(AtomicBool::new(false)),
    );
    Ok(Cloud {
        provider: SlowCloud {
            inner,
            list_delay,
            lists: Arc::clone(&lists),
            fail: Arc::clone(&fail),
        },
        lists,
        fail,
    })
}

/// A box fleet where one box (`stuck`) never answers within any budget a test gives it, and the others answer at once.
struct Fleet {
    stuck: &'static str,
    stall: Duration,
    asked: Arc<AtomicUsize>,
}

fn sample() -> ozbox_core::MetricsSample {
    ozbox_core::MetricsSample {
        ts_ms: 1,
        ..Default::default()
    }
}

impl BoxAgent for Fleet {
    fn metrics_now(
        &self,
        rec: &BoxRecord,
        _: u64,
    ) -> Result<ozbox_core::MetricsSample, AgentError> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        if rec.spec.name.as_str() == self.stuck {
            std::thread::sleep(self.stall);
        }
        Ok(sample())
    }
    fn metrics_series(
        &self,
        _: &BoxRecord,
        _: u64,
        _: u64,
        _: u64,
    ) -> Result<Vec<ozbox_core::MetricsSample>, AgentError> {
        Err(AgentError::Unreachable("none".into()))
    }
    fn selftest(&self, _: &BoxRecord, _: u64) -> Result<super::agent::SelfTest, AgentError> {
        Err(AgentError::Unreachable("none".into()))
    }
    fn incidents(
        &self,
        _: &BoxRecord,
        _: u64,
        _: u64,
    ) -> Result<Vec<super::agent::Incident>, AgentError> {
        Err(AgentError::Unreachable("none".into()))
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// A running server on a loopback port, and a client that speaks to it
// ---------------------------------------------------------------------------------------------------------------------

struct Server {
    port: u16,
    stop: Arc<AtomicBool>,
    done: Option<std::thread::JoinHandle<()>>,
}

impl Server {
    fn start(
        provider: SlowCloud,
        agent: Option<Fleet>,
        budgets: Budgets,
        workers: usize,
        queue: usize,
    ) -> Server {
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = std::sync::mpsc::channel();
        let flag = Arc::clone(&stop);
        let done = std::thread::spawn(move || {
            let server =
                tiny_http::Server::http(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                    .expect("bind");
            let addr = server.server_addr().to_ip().expect("a tcp address");
            let mut app =
                App::new(Box::new(provider), false, addr, TOKEN.into()).with_lane_budgets(budgets);
            if let Some(a) = agent {
                app = app.with_agent(Box::new(a));
            }
            tx.send(addr.port()).expect("send the port");
            run_loop(&server, &mut app, &flag, workers, queue);
        });
        Server {
            port: rx.recv().expect("the port"),
            stop,
            done: Some(done),
        }
    }

    fn get(&self, path: &str) -> Answer {
        let started = Instant::now();
        let mut s = TcpStream::connect(("127.0.0.1", self.port)).expect("connect");
        s.set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        write!(
            s,
            "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer {TOKEN}\r\nConnection: close\r\n\r\n",
            self.port
        )
        .expect("write");
        let mut raw = Vec::new();
        let _ = s.read_to_end(&mut raw);
        let text = String::from_utf8_lossy(&raw).to_string();
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        let mut lines = head.lines();
        let status = lines
            .next()
            .and_then(|l| l.split(' ').nth(1))
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        let headers = lines
            .filter_map(|l| l.split_once(": "))
            .map(|(k, v)| (k.to_ascii_lowercase(), v.to_string()))
            .collect();
        Answer {
            status,
            headers,
            body: body.to_string(),
            took: started.elapsed(),
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(d) = self.done.take() {
            let _ = d.join();
        }
    }
}

struct Answer {
    status: u16,
    headers: HashMap<String, String>,
    body: String,
    took: Duration,
}

impl Answer {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }
}

fn quick() -> Budgets {
    Budgets {
        list_fresh: Duration::from_secs(60),
        list_wait_stale: Duration::from_millis(100),
        list_wait_cold: Duration::from_millis(200),
        loop_wait_stale: Duration::from_millis(100),
        tick_wait: Duration::from_millis(50),
        record_max_age: Duration::from_secs(60),
        get: Duration::from_secs(5),
        status: Duration::from_millis(400),
        selftest: Duration::from_millis(400),
        check: Duration::from_secs(5),
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// Over the socket
// ---------------------------------------------------------------------------------------------------------------------

#[test]
fn info_answers_at_once_while_a_box_list_takes_seconds() -> TestResult {
    let dir = tempfile::tempdir()?;
    let c = cloud(dir.path(), &["dev"], Duration::from_secs(3))?;
    let lists = Arc::clone(&c.lists);
    let s = Arc::new(Server::start(c.provider, None, quick(), 4, 8));
    // the page asks for the list and, right after, for what the server is
    let slow = {
        let s = Arc::clone(&s);
        std::thread::spawn(move || s.get("/v1/boxes"))
    };
    while lists.load(Ordering::SeqCst) == 0 {
        std::thread::sleep(Duration::from_millis(5));
    }
    for _ in 0..5 {
        let info = s.get("/v1/info");
        assert_eq!(info.status, 200);
        assert!(
            info.took < Duration::from_millis(500),
            "info waited {:?} behind a slow list",
            info.took
        );
    }
    let first = slow.join().expect("the list request");
    // the first read is still going: that is an answer that says so, not a hang
    assert_eq!(first.status, 503, "{}", first.body);
    assert_eq!(first.json()["code"], "warming");
    assert_eq!(
        first.headers.get("retry-after").map(String::as_str),
        Some("2")
    );
    Ok(())
}

#[test]
fn the_list_is_served_from_its_last_read_with_its_age_while_a_new_read_runs() -> TestResult {
    let dir = tempfile::tempdir()?;
    let c = cloud(dir.path(), &["dev", "other"], Duration::from_millis(0))?;
    let lists = Arc::clone(&c.lists);
    let b = Budgets {
        list_fresh: Duration::from_millis(0),
        ..quick()
    };
    let s = Server::start(c.provider, None, b, 4, 8);
    let first = s.get("/v1/boxes");
    assert_eq!(first.status, 200, "{}", first.body);
    assert_eq!(first.json().as_array().map(Vec::len), Some(2));
    let as_of: u64 = first
        .headers
        .get("x-ozbox-boxes-as-of")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    assert!(as_of > 1_700_000_000_000, "{:?}", first.headers);
    assert!(first.headers.contains_key("x-ozbox-boxes-refreshing"));
    assert!(lists.load(Ordering::SeqCst) >= 1);
    Ok(())
}

#[test]
fn a_page_that_asks_for_the_list_many_times_at_once_makes_one_read_of_the_cloud() -> TestResult {
    let dir = tempfile::tempdir()?;
    let c = cloud(dir.path(), &["dev"], Duration::from_millis(600))?;
    let lists = Arc::clone(&c.lists);
    let b = Budgets {
        list_wait_cold: Duration::from_secs(5),
        ..quick()
    };
    let s = Arc::new(Server::start(c.provider, None, b, 12, 32));
    let askers: Vec<_> = (0..10)
        .map(|_| {
            let s = Arc::clone(&s);
            std::thread::spawn(move || s.get("/v1/boxes"))
        })
        .collect();
    for a in askers {
        let a = a.join().expect("an asker");
        assert_eq!(a.status, 200, "{}", a.body);
    }
    assert_eq!(
        lists.load(Ordering::SeqCst),
        1,
        "every asker made its own read of the cloud"
    );
    Ok(())
}

#[test]
fn a_box_that_does_not_answer_is_reported_after_its_budget_and_does_not_stall_the_others(
) -> TestResult {
    let dir = tempfile::tempdir()?;
    let c = cloud(dir.path(), &["stuck", "fine"], Duration::from_millis(0))?;
    let fleet = Fleet {
        stuck: "stuck",
        stall: Duration::from_secs(4),
        asked: Arc::new(AtomicUsize::new(0)),
    };
    let s = Arc::new(Server::start(c.provider, Some(fleet), quick(), 8, 16));
    // the list is read first, as the dashboard does
    assert_eq!(s.get("/v1/boxes").status, 200);
    let stuck = {
        let s = Arc::clone(&s);
        std::thread::spawn(move || s.get("/v1/boxes/stuck/metrics/now"))
    };
    std::thread::sleep(Duration::from_millis(50));
    // what the server is answers at once while a box is being waited for
    let info = s.get("/v1/info");
    assert_eq!(info.status, 200);
    assert!(
        info.took < Duration::from_millis(200),
        "info waited {:?} behind a stuck box",
        info.took
    );
    let fine = s.get("/v1/boxes/fine/metrics/now");
    assert_eq!(fine.status, 200, "{}", fine.body);
    assert!(
        fine.took < Duration::from_millis(300),
        "the others waited {:?}",
        fine.took
    );
    let list = s.get("/v1/boxes");
    assert_eq!(list.status, 200);
    assert!(
        list.took < Duration::from_millis(300),
        "the list waited {:?}",
        list.took
    );
    let stuck = stuck.join().expect("the stuck box's request");
    assert_eq!(stuck.status, 502, "{}", stuck.body);
    assert_eq!(stuck.json()["code"], "agent_unreachable");
    assert!(
        stuck.took < Duration::from_secs(2),
        "the box was waited for {:?}, not for its budget",
        stuck.took
    );
    Ok(())
}

#[test]
fn asking_a_stuck_box_again_and_again_makes_one_call_to_it() -> TestResult {
    let dir = tempfile::tempdir()?;
    let c = cloud(dir.path(), &["stuck"], Duration::from_millis(0))?;
    let asked = Arc::new(AtomicUsize::new(0));
    let fleet = Fleet {
        stuck: "stuck",
        stall: Duration::from_millis(1500),
        asked: Arc::clone(&asked),
    };
    let s = Arc::new(Server::start(c.provider, Some(fleet), quick(), 8, 16));
    assert_eq!(s.get("/v1/boxes").status, 200);
    // the server's own alert round asks the box once, on its own; what is counted is what the page adds
    std::thread::sleep(Duration::from_millis(300));
    let before = asked.load(Ordering::SeqCst);
    let askers: Vec<_> = (0..6)
        .map(|_| {
            let s = Arc::clone(&s);
            std::thread::spawn(move || s.get("/v1/boxes/stuck/metrics/now"))
        })
        .collect();
    for a in askers {
        assert_eq!(a.join().expect("an asker").status, 502);
    }
    // a page polling a box that never answers must not pile a call on it for every poll
    assert_eq!(asked.load(Ordering::SeqCst) - before, 1);
    Ok(())
}

#[test]
fn more_reads_than_the_lane_holds_are_refused_at_once_instead_of_queued_without_limit() -> TestResult
{
    let dir = tempfile::tempdir()?;
    let c = cloud(dir.path(), &["stuck"], Duration::from_millis(0))?;
    let fleet = Fleet {
        stuck: "stuck",
        stall: Duration::from_millis(1500),
        asked: Arc::new(AtomicUsize::new(0)),
    };
    let b = Budgets {
        status: Duration::from_secs(3),
        ..quick()
    };
    // one worker and one place in the queue
    let s = Arc::new(Server::start(c.provider, Some(fleet), b, 1, 1));
    assert_eq!(s.get("/v1/boxes").status, 200);
    // the first read is taken by the one worker, the second waits in the one place in the queue
    let mut held = Vec::new();
    for _ in 0..2 {
        let s = Arc::clone(&s);
        held.push(std::thread::spawn(move || {
            s.get("/v1/boxes/stuck/metrics/now")
        }));
        std::thread::sleep(Duration::from_millis(200));
    }
    let refused = s.get("/v1/boxes/stuck/metrics/now");
    assert_eq!(refused.status, 503, "{}", refused.body);
    assert_eq!(refused.json()["code"], "busy");
    assert_eq!(
        refused.headers.get("retry-after").map(String::as_str),
        Some("1")
    );
    assert!(
        refused.took < Duration::from_millis(300),
        "{:?}",
        refused.took
    );
    // and the loop is still answering everything else
    assert_eq!(s.get("/v1/info").status, 200);
    for h in held {
        let _ = h.join();
    }
    Ok(())
}

#[test]
fn the_guard_still_runs_before_a_read_is_handed_to_a_worker() -> TestResult {
    let dir = tempfile::tempdir()?;
    let c = cloud(dir.path(), &["dev"], Duration::from_millis(0))?;
    let lists = Arc::clone(&c.lists);
    let s = Server::start(c.provider, None, quick(), 4, 8);
    // the server's own first round reads the boxes once, on its own; what is counted is what the refused requests add
    assert_eq!(s.get("/v1/info").status, 200);
    std::thread::sleep(Duration::from_millis(300));
    let before = lists.load(Ordering::SeqCst);
    // a wrong Host (DNS rebinding) and a wrong token are refused on the loop; the cloud is never asked
    let mut conn = TcpStream::connect(("127.0.0.1", s.port))?;
    write!(
        conn,
        "GET /v1/boxes HTTP/1.1\r\nHost: evil.example\r\nAuthorization: Bearer {TOKEN}\r\nConnection: close\r\n\r\n"
    )?;
    let mut raw = String::new();
    conn.read_to_string(&mut raw)?;
    assert!(raw.starts_with("HTTP/1.1 403"), "{raw}");
    let mut conn = TcpStream::connect(("127.0.0.1", s.port))?;
    write!(
        conn,
        "GET /v1/boxes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer nope\r\nConnection: close\r\n\r\n",
        s.port
    )?;
    let mut raw = String::new();
    conn.read_to_string(&mut raw)?;
    assert!(raw.starts_with("HTTP/1.1 401"), "{raw}");
    assert_eq!(lists.load(Ordering::SeqCst), before);
    Ok(())
}

// ---------------------------------------------------------------------------------------------------------------------
// The parts
// ---------------------------------------------------------------------------------------------------------------------

#[test]
fn flights_give_one_call_to_every_asker_of_the_same_key() {
    let flights: Arc<Flights<u32>> = Arc::new(Flights::new(Permits::new(8)));
    let calls = Arc::new(AtomicUsize::new(0));
    let askers: Vec<_> = (0..8)
        .map(|_| {
            let (f, calls) = (Arc::clone(&flights), Arc::clone(&calls));
            std::thread::spawn(move || {
                f.run("k", Duration::from_secs(5), move || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis(200));
                    7
                })
            })
        })
        .collect();
    for a in askers {
        assert_eq!(a.join().expect("an asker"), Flown::Done(7));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    // once it has finished, the next ask is a new call
    assert_eq!(
        flights.run("k", Duration::from_secs(5), || 8),
        Flown::Done(8)
    );
}

#[test]
fn a_flight_that_outlasts_its_budget_is_reported_and_still_holds_its_key() {
    let flights: Flights<u32> = Flights::new(Permits::new(8));
    let calls = Arc::new(AtomicUsize::new(0));
    let c = Arc::clone(&calls);
    let started = Instant::now();
    let out = flights.run("k", Duration::from_millis(50), move || {
        c.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(400));
        1
    });
    assert_eq!(out, Flown::TimedOut);
    assert!(started.elapsed() < Duration::from_millis(300));
    // the next asker joins the call that is still going instead of starting another
    let c = Arc::clone(&calls);
    let again = flights.run("k", Duration::from_secs(5), move || {
        c.fetch_add(1, Ordering::SeqCst);
        2
    });
    assert_eq!(again, Flown::Done(1));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn flights_refuse_what_would_run_past_the_cap_and_free_the_place_when_one_ends() {
    let flights: Flights<u32> = Flights::new(Permits::new(1));
    let held = std::thread::scope(|s| {
        let t = s.spawn(|| {
            flights.run("a", Duration::from_secs(5), || {
                std::thread::sleep(Duration::from_millis(300));
                1
            })
        });
        std::thread::sleep(Duration::from_millis(50));
        // a different key while the only place is taken
        assert_eq!(flights.run("b", Duration::from_secs(1), || 2), Flown::Busy);
        t.join().expect("the first flight")
    });
    assert_eq!(held, Flown::Done(1));
    assert_eq!(
        flights.run("b", Duration::from_secs(1), || 2),
        Flown::Done(2)
    );
}

#[test]
fn a_flight_that_panics_is_a_failure_and_the_key_can_be_asked_again() {
    let flights: Flights<u32> = Flights::new(Permits::new(2));
    assert_eq!(
        flights.run("k", Duration::from_secs(2), || panic!("boom")),
        Flown::Failed
    );
    assert_eq!(
        flights.run("k", Duration::from_secs(2), || 3),
        Flown::Done(3)
    );
}

fn provider_for(
    dir: &std::path::Path,
    delay: Duration,
) -> (Arc<dyn Provider>, Arc<AtomicUsize>, Arc<AtomicBool>) {
    let c = cloud(dir, &["dev"], delay).expect("a cloud");
    (Arc::new(c.provider), c.lists, c.fail)
}

#[test]
fn the_list_keeps_the_last_good_snapshot_when_a_read_fails_and_says_so() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (p, _, fail) = provider_for(dir.path(), Duration::from_millis(0));
    let version = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let cache = ListCache::new(Arc::clone(&version));
    let b = Budgets {
        list_fresh: Duration::from_millis(0),
        list_wait_stale: Duration::from_secs(2),
        list_wait_cold: Duration::from_secs(2),
        ..Budgets::default()
    };
    assert!(matches!(cache.get(&p, &b), Listed::Boxes { .. }));
    fail.store(true, Ordering::SeqCst);
    match cache.get(&p, &b) {
        Listed::Boxes {
            snap,
            refreshing,
            refresh_failed,
        } => {
            assert_eq!(snap.recs.len(), 1);
            assert!(!refreshing);
            assert!(refresh_failed);
        }
        _ => panic!("the last good list should still be shown"),
    }
    Ok(())
}

#[test]
fn a_first_read_that_fails_is_the_providers_failure_and_not_an_empty_list() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (p, _, fail) = provider_for(dir.path(), Duration::from_millis(0));
    fail.store(true, Ordering::SeqCst);
    let cache = ListCache::new(Arc::new(std::sync::atomic::AtomicU64::new(0)));
    let b = Budgets {
        list_wait_cold: Duration::from_secs(2),
        ..Budgets::default()
    };
    match cache.get(&p, &b) {
        Listed::Failed(r) => assert_eq!(r.status, 422),
        _ => panic!("a failed first read must say it failed"),
    }
    Ok(())
}

#[test]
fn a_change_applied_makes_the_snapshot_stale_at_once() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (p, lists, _) = provider_for(dir.path(), Duration::from_millis(0));
    let version = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let cache = ListCache::new(Arc::clone(&version));
    let b = Budgets {
        list_fresh: Duration::from_secs(3600),
        list_wait_stale: Duration::from_secs(2),
        list_wait_cold: Duration::from_secs(2),
        ..Budgets::default()
    };
    let _ = cache.get(&p, &b);
    let _ = cache.get(&p, &b);
    assert_eq!(
        lists.load(Ordering::SeqCst),
        1,
        "a fresh snapshot is not read again"
    );
    version.fetch_add(1, Ordering::SeqCst);
    let _ = cache.get(&p, &b);
    assert_eq!(
        lists.load(Ordering::SeqCst),
        2,
        "a change applied must be read again"
    );
    Ok(())
}

#[test]
fn a_slow_refresh_answers_with_the_old_snapshot_marked_as_refreshing() -> TestResult {
    let dir = tempfile::tempdir()?;
    let slow = Arc::new(Mutex::new(Duration::from_millis(0)));
    // a provider whose delay a test can change after the first read
    struct Moody {
        inner: SlowCloud,
        delay: Arc<Mutex<Duration>>,
    }
    impl Provider for Moody {
        fn id(&self) -> &str {
            self.inner.id()
        }
        fn capabilities(&self) -> ozbox_core::Capabilities {
            self.inner.capabilities()
        }
        fn list(&self) -> ozbox_core::Result<Vec<BoxRecord>> {
            std::thread::sleep(*self.delay.lock().unwrap_or_else(|e| e.into_inner()));
            self.inner.inner.list()
        }
        fn get(&self, n: &BoxName) -> ozbox_core::Result<Option<BoxRecord>> {
            self.inner.get(n)
        }
        fn plan(&self, op: &Operation) -> ozbox_core::Result<Plan> {
            self.inner.plan(op)
        }
        fn apply(&self, plan: &Plan) -> ozbox_core::Result<Option<BoxRecord>> {
            self.inner.apply(plan)
        }
    }
    let c = cloud(dir.path(), &["dev"], Duration::from_millis(0))?;
    let p: Arc<dyn Provider> = Arc::new(Moody {
        inner: c.provider,
        delay: Arc::clone(&slow),
    });
    let cache = ListCache::new(Arc::new(std::sync::atomic::AtomicU64::new(0)));
    let b = Budgets {
        list_fresh: Duration::from_millis(0),
        list_wait_stale: Duration::from_millis(50),
        list_wait_cold: Duration::from_secs(2),
        ..Budgets::default()
    };
    assert!(matches!(cache.get(&p, &b), Listed::Boxes { .. }));
    *slow.lock().unwrap_or_else(|e| e.into_inner()) = Duration::from_millis(600);
    let started = Instant::now();
    match cache.get(&p, &b) {
        Listed::Boxes { refreshing, .. } => assert!(refreshing),
        _ => panic!("the old list should be shown"),
    }
    assert!(
        started.elapsed() < Duration::from_millis(400),
        "waited {:?}",
        started.elapsed()
    );
    Ok(())
}
