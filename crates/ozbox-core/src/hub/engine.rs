//! The hub's side: assign a task to a worker in the roster, check what comes back, keep the latest report per worker.
//!
//! The hub is a state machine over a [`HubState`]: the channel's [`Core`] (sessions, outbox, window, audit backlog) plus what the hub
//! keeps about each worker's reports. The state persists through the channel's [`Store`] when the hub is run as a [`HubService`], so
//! a restart keeps its counters and its unacknowledged messages. The hub never opens a connection or runs a command: it queues,
//! then pushes through a [`Transport`]. Every decision it makes is an audit event the caller records.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::refusal::{refuse_production, KeyDeclaration, Refusal, AUDIT_REFUSED};
use super::wire::{Ext, Kind, Transport, WireError, PROFILE};
#[cfg(test)]
use crate::audit::NewEvent;
use crate::channel::audit::HasCore;
use crate::channel::flow::{receive_round, seal_drafts};
use crate::channel::session::{Core, Link};
use crate::channel::store::Store;
use crate::channel::wire::{Crypto, Sealed, Sealer, Signer, Verifier};

/// The epoch a worker is pinned at. A worker's epoch changes only if its state is restored and the roster says so.
pub const WORKER_EPOCH: u64 = 1;

/// What a task hands a worker (the body of `task.assign`). Names and ids, never a value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Assign {
    pub orchestration: String,
    pub feature: String,
    pub title: String,
    pub brief: String,
    pub branch: String,
    pub repo: Option<String>,
    pub claims: Vec<String>,
    pub contracts: Vec<String>,
    /// Keys the task wants, by name. Development and staging only; Production is refused (decision D2).
    pub keys: KeyDeclaration,
    /// The absolute end of the lease: a worker that hears nothing by then stops.
    pub lease_expiry_ms: u64,
}

/// A worker's report (the body of `status`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusBody {
    /// The orchestration the feature belongs to (feature ids are only unique inside one). `-` with feature `-` is a report
    /// about the worker itself, not a feature.
    pub orchestration: String,
    pub feature: String,
    /// `accepted`, `working`, `refused`, `unsupported`.
    pub state: String,
    pub text: String,
}

/// A worker's result (the body of `result`): the commit it reports, which is the SHA the merge queue merges.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultBody {
    pub orchestration: String,
    pub feature: String,
    pub commit: String,
    pub summary: String,
}

/// What the hub knows about one worker's reports.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerReport {
    pub last_seen_ms: u64,
    /// Latest status per orchestration, then feature.
    pub status: BTreeMap<String, BTreeMap<String, StatusBody>>,
    pub results: BTreeMap<String, BTreeMap<String, ResultBody>>,
    pub questions: Vec<String>,
}

/// What the hub keeps about one worker beside the channel's link: its reports, what it was handed, and whether it is quarantined.
/// (The counters, the incarnations and the window are the channel's, in [`HubState::core`].)
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerState {
    pub quarantined: Option<String>,
    pub report: WorkerReport,
    /// What this hub handed this worker: orchestration and feature.
    pub assigned: Vec<(String, String)>,
}

/// Everything the hub keeps. Plain data: it serialises into its store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HubState {
    pub core: Core,
    pub peers: BTreeMap<String, PeerState>,
}

impl HasCore for HubState {
    fn core(&self) -> &Core {
        &self.core
    }
    fn core_mut(&mut self) -> &mut Core {
        &mut self.core
    }
}

impl HubState {
    /// A new hub state. The roster names a worker's key by one fingerprint, which is the key the hub verifies and seals with, so the
    /// hub's own key is named the same way (`my_fp`). The epoch changes on a repin or a replace.
    pub fn new(me: &str, my_fp: &str, epoch: u64) -> HubState {
        HubState {
            core: Core::new(me, my_fp, my_fp, my_fp, epoch),
            peers: BTreeMap::new(),
        }
    }

    /// This hub's incarnation: fresh whenever the state is created or restored.
    pub fn inc(&self) -> u64 {
        self.core.incarnation
    }

    /// The worker's incarnation as learned from its `hello` (0 until then).
    pub fn peer_inc(&self, worker: &str) -> u64 {
        self.core.links.get(worker).map_or(0, |l| l.peer_inc)
    }

    /// Hand over every pending audit event and forget it. For tests only: a server hands events over by number with
    /// [`HubService::drain_audit`], so a crash between the state's write and the record's repeats none and loses none.
    #[cfg(test)]
    pub fn take_audit(&mut self) -> Vec<NewEvent> {
        std::mem::take(&mut self.core.audit)
    }

    fn note(&mut self, now: u64, action: &str, detail: String) {
        self.core.note(now, action, None, detail);
    }
}

/// A worker `main` may hand work to: a box the fleet lists as `ozbox-managed`, with the key its enrolment attested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterEntry {
    pub key_fp: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HubError {
    /// Not in the roster: not a managed box, or not enrolled.
    NotAWorker(String),
    Quarantined(String),
    /// No session with the worker yet (its incarnation is not known): a `hello` was started, so try again after the worker answers.
    NoSession(String),
    /// The channel to this worker is halted: its store or this one looks restored from a backup.
    Halted(String),
    /// The worker has too many messages waiting to be acknowledged, or the audit backlog is full.
    Backlog(&'static str),
    /// Production, or a malformed declaration: refused, and audited before this returned.
    Refused(Refusal),
    Wire(WireError),
}

impl std::fmt::Display for HubError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HubError::NotAWorker(w) => write!(f, "{w} is not a worker box this hub may reach"),
            HubError::Quarantined(w) => write!(f, "{w} is quarantined and is sent nothing"),
            HubError::NoSession(w) => write!(
                f,
                "{w} has not completed the hello yet: one was sent, so try again once the worker has answered"
            ),
            HubError::Halted(w) => write!(
                f,
                "the channel to {w} is halted because a store looks restored from a backup; acknowledge the restore first"
            ),
            HubError::Backlog(c) => write!(f, "the message was not queued: {c}"),
            HubError::Refused(r) => write!(f, "{r}"),
            HubError::Wire(e) => write!(f, "{e}"),
        }
    }
}

/// What the hub needs from outside: its identity, the roster and the three seams.
pub struct Hub<'a> {
    pub me: &'a str,
    pub my_fp: &'a str,
    pub roster: &'a BTreeMap<String, RosterEntry>,
    pub signer: &'a dyn Signer,
    pub verifier: &'a dyn Verifier,
    pub sealer: &'a dyn Sealer,
    pub net: &'a dyn Transport,
    /// A service persists the state **before** anything is sent, so it sets this and pushes itself ([`Hub::flush_all`]); a bare hub
    /// (a test, the fake fleet) pushes at the end of every call.
    pub deferred: bool,
}

impl Hub<'_> {
    fn cx(&self) -> Crypto<'_> {
        Crypto {
            signer: self.signer,
            verifier: self.verifier,
            sealer: self.sealer,
        }
    }

    /// Make the channel's pins match the roster: a worker the roster names gets a link keyed by its attested fingerprint, and a
    /// worker whose fingerprint changed gets a fresh one (nothing of the old session survives a new key).
    fn pins(&self, st: &mut HubState) {
        for (w, e) in self.roster {
            let current = st.core.links.get(w).is_some_and(|l| l.sign_key == e.key_fp);
            if !current {
                st.core
                    .pin(Link::new(w, &e.key_fp, &e.key_fp, &e.key_fp, WORKER_EPOCH));
            }
        }
    }

    /// Hand a task to a worker. The declaration is checked first and a refusal is audited before it is returned.
    pub fn assign(
        &self,
        st: &mut HubState,
        worker: &str,
        a: &Assign,
        now: u64,
    ) -> Result<(), HubError> {
        if !self.roster.contains_key(worker) {
            return Err(HubError::NotAWorker(worker.to_string()));
        }
        self.pins(st);
        let peer = st.peers.entry(worker.to_string()).or_default();
        if let Some(why) = &peer.quarantined {
            return Err(HubError::Quarantined(format!("{worker}: {why}")));
        }
        if let Err(r) = refuse_production(&a.keys) {
            st.note(
                now,
                AUDIT_REFUSED,
                format!("side=hub {}", r.audit_detail(worker, &a.feature)),
            );
            return Err(HubError::Refused(r));
        }
        let (ready, halted) = st
            .core
            .links
            .get(worker)
            .map_or((false, false), |l| (l.peer_inc != 0, l.halted.is_some()));
        if halted {
            return Err(HubError::Halted(worker.to_string()));
        }
        if !ready {
            self.hello(st, worker, now).map_err(HubError::Wire)?;
            return Err(HubError::NoSession(worker.to_string()));
        }
        let body = serde_json::to_vec(a).map_err(|_| {
            HubError::Wire(WireError::Channel(crate::channel::wire::WireError::BadSeal))
        })?;
        st.core
            .enqueue(
                &PROFILE,
                worker,
                Kind::TaskAssign.name(),
                Ext::at(0).encode(),
                body,
            )
            .map_err(HubError::Backlog)?;
        let peer = st.peers.entry(worker.to_string()).or_default();
        peer.assigned
            .push((a.orchestration.clone(), a.feature.clone()));
        st.note(
            now,
            "hub.assign",
            format!(
                "worker={worker} task={} orchestration={} keys={} env={}",
                a.feature,
                a.orchestration,
                a.keys.names.len(),
                if a.keys.names.is_empty() {
                    "-"
                } else {
                    &a.keys.env
                }
            ),
        );
        if !self.deferred {
            self.flush(st, worker, now).map_err(HubError::Wire)?;
        }
        Ok(())
    }

    /// Start a `hello` with a worker (step one: it names no incarnation of the worker's). Sent when a session is missing or a
    /// message named the wrong incarnation; rate-limited per peer, and a limited call sends nothing and succeeds.
    pub fn hello(&self, st: &mut HubState, worker: &str, now: u64) -> Result<(), WireError> {
        if !self.roster.contains_key(worker) {
            return Err(WireError::Channel(crate::channel::wire::WireError::Shape(
                "to",
            )));
        }
        self.pins(st);
        if let Some(l) = st.core.links.get_mut(worker) {
            l.hello_wanted = true;
        }
        if self.deferred {
            return Ok(());
        }
        self.flush(st, worker, now)
    }

    /// Push to one worker what the channel says it is owed: a `hello` when one is wanted, an acknowledgement, the messages not yet
    /// pushed, and the window again when it has gone unacknowledged for a while. Sends nothing to a quarantined worker. Changes
    /// only push bookkeeping, never what a restart must remember.
    pub fn flush(&self, st: &mut HubState, worker: &str, now: u64) -> Result<(), WireError> {
        if st
            .peers
            .get(worker)
            .is_some_and(|p| p.quarantined.is_some())
        {
            return Ok(());
        }
        let opts = st.core.push_opts(worker, now);
        let drafts = st.core.drafts(worker, now, opts);
        if drafts.is_empty() {
            return Ok(());
        }
        let sealed = seal_drafts(&PROFILE, &self.cx(), &drafts)?;
        for m in sealed {
            self.net.send(worker, m)?;
        }
        st.core.pushed(worker, now, &drafts);
        Ok(())
    }

    /// Push to every worker. A worker that cannot be reached is audited once and does not stop the others.
    pub fn flush_all(&self, st: &mut HubState, now: u64) {
        let workers: Vec<String> = st.core.links.keys().cloned().collect();
        for w in workers {
            if self.flush(st, &w, now).is_err() {
                st.note(now, "hub.send-failed", format!("worker={w}"));
            }
        }
    }

    /// Take every message waiting for the hub: verify, de-duplicate, order, apply. Returns how many were applied.
    pub fn poll(&self, st: &mut HubState, now: u64) -> usize {
        self.pins(st);
        let mut by_sender: BTreeMap<String, Vec<Sealed>> = BTreeMap::new();
        while let Some(m) = self.net.recv(self.me) {
            by_sender
                .entry(m.envelope.from.clone())
                .or_default()
                .push(m);
        }
        let cx = self.cx();
        let mut applied = 0;
        for (from, msgs) in by_sender {
            st.core.tick(now);
            let r = receive_round(&mut st.core, &PROFILE, &cx, &|_, _, _| Ok(()), now, &msgs);
            for d in r.deliveries {
                if self.take(st, &from, &d.kind, &d.ext, d.body, now) {
                    applied += 1;
                }
            }
        }
        if !self.deferred {
            self.flush_all(st, now);
        }
        applied
    }

    fn take(
        &self,
        st: &mut HubState,
        from: &str,
        kind: &str,
        ext: &[u8],
        body: Result<Vec<u8>, String>,
        now: u64,
    ) -> bool {
        let peer = st.peers.entry(from.to_string()).or_default();
        if peer.quarantined.is_some() {
            return false;
        }
        let (Some(ext), Ok(plain), Some(kind)) = (Ext::decode(ext), body, Kind::parse(kind)) else {
            st.note(now, "hub.rejected", format!("from={from} reason=malformed"));
            return false;
        };
        if !ext.via.is_empty() {
            st.note(now, "hub.rejected", format!("from={from} reason=relay"));
            return false;
        }
        if ext.level != 1 {
            st.note(now, "hub.rejected", format!("from={from} reason=level"));
            return false;
        }
        if kind.hub_to_worker() {
            // an authenticated worker sent a kind only the hub sends: its key may be in someone else's hands
            let peer = st.peers.entry(from.to_string()).or_default();
            peer.quarantined = Some(format!("sent {}", kind.name()));
            st.note(
                now,
                "hub.quarantine",
                format!("worker={from} kind={}", kind.name()),
            );
            return false;
        }
        let peer = st.peers.entry(from.to_string()).or_default();
        peer.report.last_seen_ms = now;
        match kind {
            Kind::Status => {
                if let Ok(s) = serde_json::from_slice::<StatusBody>(&plain) {
                    if peer.knows(&s.orchestration, &s.feature) {
                        peer.report
                            .status
                            .entry(s.orchestration.clone())
                            .or_default()
                            .insert(s.feature.clone(), s);
                    } else {
                        st.note(
                            now,
                            "hub.rejected",
                            format!("from={from} reason=unassigned-feature kind=status"),
                        );
                    }
                }
            }
            Kind::Result => {
                if let Ok(r) = serde_json::from_slice::<ResultBody>(&plain) {
                    if peer.knows(&r.orchestration, &r.feature) {
                        peer.report
                            .results
                            .entry(r.orchestration.clone())
                            .or_default()
                            .insert(r.feature.clone(), r);
                    } else {
                        st.note(
                            now,
                            "hub.rejected",
                            format!("from={from} reason=unassigned-feature kind=result"),
                        );
                    }
                }
            }
            Kind::Question | Kind::Blocked => {
                peer.report
                    .questions
                    .push(String::from_utf8_lossy(&plain).chars().take(2000).collect());
            }
            _ => {}
        }
        true
    }
}

impl PeerState {
    /// Whether the hub handed this worker that feature. `-`/`-` is the worker's report about itself.
    fn knows(&self, orchestration: &str, feature: &str) -> bool {
        (orchestration == "-" && feature == "-")
            || self
                .assigned
                .iter()
                .any(|(o, f)| o == orchestration && f == feature)
    }
}

/// The hub as one object a server holds: identity, roster, the three seams and the state behind a lock. Everything the server
/// does with the hub goes through [`HubService::with`], so a call sees one consistent state, and when a store is attached the state
/// is written **before** anything is pushed to a worker.
pub struct HubService {
    pub me: String,
    pub my_fp: String,
    pub roster: BTreeMap<String, RosterEntry>,
    pub signer: std::sync::Arc<dyn Signer>,
    pub verifier: std::sync::Arc<dyn Verifier>,
    pub sealer: std::sync::Arc<dyn Sealer>,
    pub net: std::sync::Arc<dyn Transport>,
    pub state: std::sync::Mutex<HubState>,
    /// Where the state persists. `None` keeps it in memory only (the fake fleet, tests).
    pub store: Option<Store<HubState>>,
}

impl HubService {
    /// Run `f` with the hub and its state, at time `now`. The state is written **first**, then whatever the channel owes the workers is
    /// pushed, so a crash never leaves a worker holding a message this hub has forgotten it sent. Returns `None` when the state cannot
    /// be used (the lock is poisoned or the store cannot be written); in that case nothing is pushed.
    pub fn with<T>(&self, now: u64, f: impl FnOnce(&Hub<'_>, &mut HubState) -> T) -> Option<T> {
        let hub = Hub {
            me: &self.me,
            my_fp: &self.my_fp,
            roster: &self.roster,
            signer: self.signer.as_ref(),
            verifier: self.verifier.as_ref(),
            sealer: self.sealer.as_ref(),
            net: self.net.as_ref(),
            deferred: true,
        };
        let mut st = self.state.lock().ok()?;
        let out = f(&hub, &mut st);
        if let Some(store) = &self.store {
            store.update(|disk| *disk = st.clone()).ok()?;
        }
        hub.flush_all(&mut st, now);
        Some(out)
    }

    /// Hand the pending audit events the sink does not hold to it, by source number (the channel's own drain, on the state this
    /// service holds), then forget what it holds. Events stay in the state until the sink says it has them; one the sink already
    /// holds is skipped, so a retry after a crash repeats nothing. Returns whether the sink could be written.
    pub fn drain_audit(&self, sink: &dyn crate::channel::audit::AuditSink) -> std::io::Result<()> {
        let mut st = self
            .state
            .lock()
            .map_err(|_| std::io::Error::other("the hub's state is not usable"))?;
        let last = sink.last_src()?;
        st.core.trim_logged(last.as_ref());
        if st.core.audit.is_empty() {
            return Ok(());
        }
        sink.record_many(st.core.audit.clone())?;
        let last = sink.last_src()?;
        st.core.trim_logged(last.as_ref());
        Ok(())
    }
}
