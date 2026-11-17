//! The transport conformance suite: what any [`Transport`] under the hub must let the hub and its workers do. The in-memory one
//! and the network one both run it ([`crate::hub::mem`] in `hub/tests.rs`, [`crate::hub::net`] over a loopback network in its own
//! tests), so a transport that passes here behaves for the channel exactly as the in-memory one does.
//!
//! The suite drives the real hub and worker over the transport and waits for what it expects, so a transport that delivers later
//! (a network) passes and one that loses, misroutes or reorders for good does not. The crypto is the test crypto of
//! [`crate::hub::mem`]: what is measured is the transport, not the seal.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::engine::{Assign, Hub, HubError, HubState, RosterEntry};
use super::mem::{TestKey, TestRoster, TestSealer};
use super::refusal::KeyDeclaration;
use super::wire::Transport;
use super::worker::{WorkerEnd, WorkerState};

pub const HUB: &str = "main";
pub const W1: &str = "worker-1";
pub const W2: &str = "worker-2";
pub const HUB_FP: &str = "aa01";
pub const W1_FP: &str = "bb02";
pub const W2_FP: &str = "cc03";

/// The test keys a rig signs and verifies with (the same as the in-memory hub tests use).
pub struct Keys {
    pub hub: TestKey,
    pub w1: TestKey,
    pub w2: TestKey,
    pub roster_keys: TestRoster,
    pub roster: BTreeMap<String, RosterEntry>,
}

pub fn keys() -> Keys {
    let mut k = BTreeMap::new();
    k.insert(HUB_FP.to_string(), "k-main".to_string());
    k.insert(W1_FP.to_string(), "k-w1".to_string());
    k.insert(W2_FP.to_string(), "k-w2".to_string());
    let mut roster = BTreeMap::new();
    roster.insert(
        W1.to_string(),
        RosterEntry {
            key_fp: W1_FP.into(),
        },
    );
    roster.insert(
        W2.to_string(),
        RosterEntry {
            key_fp: W2_FP.into(),
        },
    );
    Keys {
        hub: TestKey("k-main".into()),
        w1: TestKey("k-w1".into()),
        w2: TestKey("k-w2".into()),
        roster_keys: TestRoster(k),
        roster,
    }
}

/// The three ends' transports. For the in-memory transport all three are the same value.
pub struct Nets<'a> {
    pub hub: &'a dyn Transport,
    pub w1: &'a dyn Transport,
    pub w2: &'a dyn Transport,
}

/// The wall clock in milliseconds: a network transport checks validity against it, so the suite uses it too.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

struct Rig<'a> {
    k: &'a Keys,
    n: &'a Nets<'a>,
    hs: HubState,
    w1s: WorkerState,
    w2s: WorkerState,
    hub_sealer: TestSealer,
    w1_sealer: TestSealer,
    w2_sealer: TestSealer,
}

impl<'a> Rig<'a> {
    fn new(k: &'a Keys, n: &'a Nets<'a>) -> Rig<'a> {
        Rig {
            k,
            n,
            hs: HubState::new(HUB, HUB_FP, 7),
            w1s: WorkerState::new(W1, W1_FP, HUB, HUB_FP, 7),
            w2s: WorkerState::new(W2, W2_FP, HUB, HUB_FP, 7),
            hub_sealer: TestSealer {
                my_fp: HUB_FP.into(),
            },
            w1_sealer: TestSealer {
                my_fp: W1_FP.into(),
            },
            w2_sealer: TestSealer {
                my_fp: W2_FP.into(),
            },
        }
    }

    fn hub(&self) -> Hub<'_> {
        Hub {
            me: HUB,
            my_fp: HUB_FP,
            roster: &self.k.roster,
            signer: &self.k.hub,
            verifier: &self.k.roster_keys,
            sealer: &self.hub_sealer,
            net: self.n.hub,
            deferred: false,
        }
    }

    fn w1(&self) -> WorkerEnd<'_> {
        WorkerEnd {
            me: W1,
            hub: HUB,
            signer: &self.k.w1,
            verifier: &self.k.roster_keys,
            sealer: &self.w1_sealer,
            net: self.n.w1,
        }
    }

    fn w2(&self) -> WorkerEnd<'_> {
        WorkerEnd {
            me: W2,
            hub: HUB,
            signer: &self.k.w2,
            verifier: &self.k.roster_keys,
            sealer: &self.w2_sealer,
            net: self.n.w2,
        }
    }

    /// One round of everybody taking what is waiting.
    fn round(&mut self) {
        let now = now_ms();
        let (hub, w1, w2) = (self.hub(), self.w1(), self.w2());
        let (mut hs, mut a, mut b) = (self.hs.clone(), self.w1s.clone(), self.w2s.clone());
        hub.poll(&mut hs, now);
        w1.poll(&mut a, now);
        w2.poll(&mut b, now);
        // the hub's flush and the workers' are idempotent per round; a second hub poll takes what the workers just said
        hub.poll(&mut hs, now);
        (self.hs, self.w1s, self.w2s) = (hs, a, b);
    }

    /// Rounds until `done` holds, or panic with `what` after the time a slow loopback network could need.
    fn until(&mut self, what: &str, done: impl Fn(&Rig<'_>) -> bool) {
        for _ in 0..1_500 {
            self.round();
            if done(self) {
                return;
            }
            std::thread::sleep(Duration::from_millis(4));
        }
        panic!("transport conformance: {what} did not happen");
    }

    fn connect(&mut self) {
        let now = now_ms();
        let w1 = self.w1();
        let mut a = self.w1s.clone();
        w1.hello(&mut a, now);
        self.w1s = a;
        let w2 = self.w2();
        let mut b = self.w2s.clone();
        w2.hello(&mut b, now);
        self.w2s = b;
        self.until("the hello both ways with both workers", |r| {
            r.hs.peer_inc(W1) == r.w1s.inc()
                && r.w1s.hub_inc() == r.hs.inc()
                && r.hs.peer_inc(W2) == r.w2s.inc()
                && r.w2s.hub_inc() == r.hs.inc()
        });
    }
}

fn assign(feature: &str, keys: KeyDeclaration, brief: String) -> Assign {
    Assign {
        orchestration: "orch-1".into(),
        feature: feature.into(),
        title: "Add the thing".into(),
        brief,
        branch: format!("feat/{feature}"),
        repo: Some("app".into()),
        claims: vec!["src/thing/**".into()],
        contracts: Vec::new(),
        keys,
        lease_expiry_ms: now_ms() + 3_600_000,
        engine: None,
        model: None,
    }
}

/// Run every case. Each starts from fresh states over the same transports, so the transports must also carry several sessions'
/// worth of traffic in one life.
pub fn run_all(k: &Keys, n: &Nets<'_>) {
    hello_completes_both_ways(k, n);
    an_assignment_is_accepted_and_the_reports_are_read(k, n);
    a_message_reaches_only_the_worker_it_is_for(k, n);
    production_is_refused_and_nothing_reaches_the_worker(k, n);
    many_reports_arrive_and_the_last_one_wins(k, n);
    a_body_near_the_cap_crosses(k, n);
}

pub fn hello_completes_both_ways(k: &Keys, n: &Nets<'_>) {
    Rig::new(k, n).connect();
}

pub fn an_assignment_is_accepted_and_the_reports_are_read(k: &Keys, n: &Nets<'_>) {
    let mut r = Rig::new(k, n);
    r.connect();
    let (hub, mut hs) = (r.hub(), r.hs.clone());
    hub.assign(
        &mut hs,
        W1,
        &assign("f1", KeyDeclaration::default(), "Build it.".into()),
        now_ms(),
    )
    .unwrap_or_else(|e| panic!("assign: {e}"));
    r.hs = hs;
    r.until("the worker accepting the task", |r| {
        r.w1s.tasks.len() == 1
            && r.hs
                .peers
                .get(W1)
                .and_then(|p| p.report.status.get("orch-1"))
                .and_then(|m| m.get("f1"))
                .is_some_and(|s| s.state == "accepted")
    });
    let (w1, mut a) = (r.w1(), r.w1s.clone());
    w1.report(&mut a, now_ms(), "orch-1", "f1", "halfway");
    w1.finish(&mut a, now_ms(), "orch-1", "f1", &"a".repeat(40), "done");
    r.w1s = a;
    r.until("the hub reading the report and the result", |r| {
        let Some(p) = r.hs.peers.get(W1).map(|p| &p.report) else {
            return false;
        };
        p.status
            .get("orch-1")
            .and_then(|m| m.get("f1"))
            .is_some_and(|s| s.state == "working")
            && p.results
                .get("orch-1")
                .and_then(|m| m.get("f1"))
                .is_some_and(|x| x.commit == "a".repeat(40))
    });
}

pub fn a_message_reaches_only_the_worker_it_is_for(k: &Keys, n: &Nets<'_>) {
    let mut r = Rig::new(k, n);
    r.connect();
    let (hub, mut hs) = (r.hub(), r.hs.clone());
    hub.assign(
        &mut hs,
        W2,
        &assign("f2", KeyDeclaration::default(), "For two.".into()),
        now_ms(),
    )
    .unwrap_or_else(|e| panic!("assign: {e}"));
    r.hs = hs;
    r.until("worker-2 accepting its task", |r| r.w2s.tasks.len() == 1);
    for _ in 0..20 {
        r.round();
    }
    assert!(r.w1s.tasks.is_empty(), "worker-1 was given worker-2's task");
}

pub fn production_is_refused_and_nothing_reaches_the_worker(k: &Keys, n: &Nets<'_>) {
    let mut r = Rig::new(k, n);
    r.connect();
    let (hub, mut hs) = (r.hub(), r.hs.clone());
    let refused = hub.assign(
        &mut hs,
        W1,
        &assign(
            "f3",
            KeyDeclaration {
                env: "production".into(),
                names: vec!["DB_URL".into()],
            },
            "No.".into(),
        ),
        now_ms(),
    );
    assert!(
        matches!(refused, Err(HubError::Refused(_))),
        "production was not refused"
    );
    r.hs = hs;
    for _ in 0..20 {
        r.round();
    }
    assert!(r.w1s.tasks.is_empty());
}

pub fn many_reports_arrive_and_the_last_one_wins(k: &Keys, n: &Nets<'_>) {
    let mut r = Rig::new(k, n);
    r.connect();
    let mut a = r.w1s.clone();
    for i in 0..50 {
        r.w1()
            .report(&mut a, now_ms(), "-", "-", &format!("step {i}"));
        // the channel takes a window at a time; let the hub acknowledge as it goes
        if i % 16 == 15 {
            r.w1s = a.clone();
            r.round();
            a = r.w1s.clone();
        }
    }
    r.w1s = a;
    r.until("the last of fifty reports", |r| {
        r.hs.peers
            .get(W1)
            .and_then(|p| p.report.status.get("-"))
            .and_then(|m| m.get("-"))
            .is_some_and(|s| s.text == "step 49")
    });
}

pub fn a_body_near_the_cap_crosses(k: &Keys, n: &Nets<'_>) {
    let mut r = Rig::new(k, n);
    r.connect();
    let (hub, mut hs) = (r.hub(), r.hs.clone());
    hub.assign(
        &mut hs,
        W1,
        &assign("big", KeyDeclaration::default(), "b".repeat(200_000)),
        now_ms(),
    )
    .unwrap_or_else(|e| panic!("assign: {e}"));
    r.hs = hs;
    r.until("a 200 KB assignment", |r| {
        r.w1s.tasks.iter().any(|t| t.brief.len() == 200_000)
    });
}
