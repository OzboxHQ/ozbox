//! The hub's side: assign a task to a worker in the roster, check what comes back, keep the latest report per worker.
//!
//! The hub is a state machine over a [`HubState`] the caller keeps (in the task store, a later slice) and a [`Link`] per worker.
//! It never opens a connection or runs a command. Every decision it makes is also an [`AuditLine`] the caller records.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::refusal::{refuse_production, KeyDeclaration, Refusal, AUDIT_REFUSED};
use super::wire::{Kind, Link, Sealed, Sealer, Signer, Transport, Verifier, WireError};

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
    pub feature: String,
    /// `accepted`, `working`, `refused`, `unsupported`.
    pub state: String,
    pub text: String,
}

/// A worker's result (the body of `result`): the commit it reports, which is the SHA the merge queue merges.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultBody {
    pub feature: String,
    pub commit: String,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditLine {
    pub ts_ms: u64,
    pub action: String,
    pub detail: String,
}

/// What the hub knows about one worker's reports.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerReport {
    pub last_seen_ms: u64,
    pub status: BTreeMap<String, StatusBody>,
    pub results: BTreeMap<String, ResultBody>,
    pub questions: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerState {
    /// The worker's incarnation as learned from its `hello` (0 until then).
    pub peer_inc: u64,
    pub out_seq: u64,
    pub in_seq: u64,
    pub quarantined: Option<String>,
    pub report: WorkerReport,
    pub assigned: Vec<String>,
}

/// A fresh random incarnation. Never 0: 0 means "not learned yet" on the wire.
pub fn fresh_incarnation() -> u64 {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut b = [0u8; 8];
    loop {
        if SystemRandom::new().fill(&mut b).is_ok() {
            let n = u64::from_be_bytes(b);
            if n != 0 {
                return n;
            }
        }
    }
}

/// Everything the hub keeps, per worker. Plain data: it serialises into the task store.
///
/// Its counters are in memory in this slice: a hub restart is a new incarnation ([`HubState::inc`]), which the workers learn
/// from the next `hello`. Persisting counters waits for the outbox (ADR 0042 section 1, stated limit).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HubState {
    /// This hub's incarnation: fresh whenever the state is created.
    pub inc: u64,
    pub peers: BTreeMap<String, PeerState>,
    pub audit: Vec<AuditLine>,
    /// Messages dropped because they were duplicates (a retry of one already taken).
    pub duplicates: u64,
}

impl Default for HubState {
    fn default() -> Self {
        HubState {
            inc: fresh_incarnation(),
            peers: BTreeMap::new(),
            audit: Vec::new(),
            duplicates: 0,
        }
    }
}

impl HubState {
    /// Hand over the audit lines written since the last call, for the caller to record.
    pub fn take_audit(&mut self) -> Vec<AuditLine> {
        std::mem::take(&mut self.audit)
    }

    fn note(&mut self, now: u64, action: &str, detail: String) {
        self.audit.push(AuditLine {
            ts_ms: now,
            action: action.to_string(),
            detail,
        });
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
    /// Production, or a malformed declaration: refused, and audited before this returned.
    Refused(Refusal),
    Wire(WireError),
}

impl std::fmt::Display for HubError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HubError::NotAWorker(w) => write!(f, "{w} is not a worker box this hub may reach"),
            HubError::Quarantined(w) => write!(f, "{w} is quarantined and is sent nothing"),
            HubError::Refused(r) => write!(f, "{r}"),
            HubError::Wire(e) => write!(f, "{e}"),
        }
    }
}

/// What the hub needs from outside: its identity, the roster and the three seams.
pub struct Hub<'a> {
    pub me: &'a str,
    pub my_fp: &'a str,
    pub epoch: u64,
    pub roster: &'a BTreeMap<String, RosterEntry>,
    pub signer: &'a dyn Signer,
    pub verifier: &'a dyn Verifier,
    pub sealer: &'a dyn Sealer,
    pub net: &'a dyn Transport,
}

impl Hub<'_> {
    fn link<'l>(
        &'l self,
        worker: &'l str,
        peer_fp: &'l str,
        my_inc: u64,
        peer_inc: u64,
    ) -> Link<'l> {
        Link {
            my_inc,
            peer_inc,
            me: self.me,
            peer: worker,
            peer_fp,
            my_fp: self.my_fp,
            epoch: self.epoch,
            level: 0,
            signer: self.signer,
            verifier: self.verifier,
            sealer: self.sealer,
            net: self.net,
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
        let entry = self
            .roster
            .get(worker)
            .ok_or_else(|| HubError::NotAWorker(worker.to_string()))?;
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
        let body = serde_json::to_vec(a).map_err(|_| HubError::Wire(WireError::BadSeal))?;
        let peer = st.peers.entry(worker.to_string()).or_default();
        let seq = peer.out_seq + 1;
        let (ack, peer_inc) = (peer.in_seq, peer.peer_inc);
        let id = format!("{}-{}-{}", self.me, worker, seq);
        self.link(worker, &entry.key_fp, st.inc, peer_inc)
            .send(Kind::TaskAssign, seq, ack, id, now, &body)
            .map_err(HubError::Wire)?;
        let peer = st.peers.entry(worker.to_string()).or_default();
        peer.out_seq = seq;
        peer.assigned.push(a.feature.clone());
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
        Ok(())
    }

    /// Take every message waiting for the hub: verify, de-duplicate, order, apply. Returns how many were applied.
    pub fn poll(&self, st: &mut HubState, now: u64) -> usize {
        let mut applied = 0;
        while let Some(msg) = self.net.recv(self.me) {
            if self.take(st, &msg, now) {
                applied += 1;
            }
        }
        applied
    }

    fn take(&self, st: &mut HubState, msg: &Sealed, now: u64) -> bool {
        let from = msg.envelope.from.clone();
        let Some(entry) = self.roster.get(&from) else {
            st.note(
                now,
                "hub.rejected",
                format!("from={from} reason=not-in-roster"),
            );
            return false;
        };
        let peer_inc = st.peers.get(&from).map_or(0, |p| p.peer_inc);
        let link = self.link(&from, &entry.key_fp, st.inc, peer_inc);
        let (env, plain) = match link.open(msg) {
            Ok(x) => x,
            Err(e) => {
                // forged or damaged bytes are not the worker's fault, so nobody is quarantined for them
                st.note(now, "hub.rejected", format!("from={from} reason={e}"));
                return false;
            }
        };
        let peer = st.peers.entry(from.clone()).or_default();
        if peer.quarantined.is_some() {
            return false;
        }
        if env.level != 1 {
            st.note(now, "hub.rejected", format!("from={from} reason=level"));
            return false;
        }
        if env.seq <= peer.in_seq {
            st.duplicates += 1;
            return false;
        }
        if env.seq != peer.in_seq + 1 {
            // out of order: not taken, so the sender resends from its last acknowledged number
            st.note(
                now,
                "hub.rejected",
                format!("from={from} reason=out-of-order seq={}", env.seq),
            );
            return false;
        }
        if env.kind.hub_to_worker() {
            // an authenticated worker sent a kind only the hub sends: its key may be in someone else's hands
            let peer = st.peers.entry(from.clone()).or_default();
            peer.quarantined = Some(format!("sent {}", env.kind.name()));
            st.note(
                now,
                "hub.quarantine",
                format!("worker={from} kind={}", env.kind.name()),
            );
            return false;
        }
        peer.in_seq = env.seq;
        peer.report.last_seen_ms = now;
        match env.kind {
            Kind::Status => {
                if let Ok(s) = serde_json::from_slice::<StatusBody>(&plain) {
                    peer.report.status.insert(s.feature.clone(), s);
                }
            }
            Kind::Result => {
                if let Ok(r) = serde_json::from_slice::<ResultBody>(&plain) {
                    peer.report.results.insert(r.feature.clone(), r);
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

/// The hub as one object a server holds: identity, roster, the three seams and the state behind a lock. Everything the server
/// does with the hub goes through [`HubService::with`], so a call sees one consistent state.
pub struct HubService {
    pub me: String,
    pub my_fp: String,
    pub epoch: u64,
    pub roster: BTreeMap<String, RosterEntry>,
    pub signer: std::sync::Arc<dyn Signer>,
    pub verifier: std::sync::Arc<dyn Verifier>,
    pub sealer: std::sync::Arc<dyn Sealer>,
    pub net: std::sync::Arc<dyn Transport>,
    pub state: std::sync::Mutex<HubState>,
}

impl HubService {
    pub fn with<T>(&self, f: impl FnOnce(&Hub<'_>, &mut HubState) -> T) -> Option<T> {
        let hub = Hub {
            me: &self.me,
            my_fp: &self.my_fp,
            epoch: self.epoch,
            roster: &self.roster,
            signer: self.signer.as_ref(),
            verifier: self.verifier.as_ref(),
            sealer: self.sealer.as_ref(),
            net: self.net.as_ref(),
        };
        let mut st = self.state.lock().ok()?;
        Some(f(&hub, &mut st))
    }
}
