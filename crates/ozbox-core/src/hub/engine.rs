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
    /// Latest status per orchestration, then feature.
    pub status: BTreeMap<String, BTreeMap<String, StatusBody>>,
    pub results: BTreeMap<String, BTreeMap<String, ResultBody>>,
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
    /// What this hub handed this worker: orchestration and feature.
    pub assigned: Vec<(String, String)>,
    /// The last time a `hello` was started for this peer and the last time a below-counter duplicate was audited (each is
    /// rate-limited so a flood cannot fill the audit or the wire).
    #[serde(default)]
    pub last_hello_ms: u64,
    #[serde(default)]
    pub last_dup_audit_ms: u64,
}

/// At most one audit line and one `hello` per peer per this long.
pub const RATE_LIMIT_MS: u64 = 1000;
/// A below-counter duplicate is audited at most this often per peer.
pub const DUP_AUDIT_MS: u64 = 60_000;

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
    /// No session with the worker yet (its incarnation is not known): a `hello` was started, so try again after the worker answers.
    NoSession(String),
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
        if peer.peer_inc == 0 {
            self.hello(st, worker, now).map_err(HubError::Wire)?;
            return Err(HubError::NoSession(worker.to_string()));
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
        Ok(())
    }

    /// Start a `hello` with a worker (step one: it names no incarnation of the worker's). Sent when a session is missing or a
    /// message named the wrong incarnation; rate-limited per peer, and a limited call sends nothing and succeeds.
    pub fn hello(&self, st: &mut HubState, worker: &str, now: u64) -> Result<(), WireError> {
        let entry = self.roster.get(worker).ok_or(WireError::BadName("to"))?;
        let inc = st.inc;
        let peer = st.peers.entry(worker.to_string()).or_default();
        if peer.last_hello_ms != 0 && now < peer.last_hello_ms.saturating_add(RATE_LIMIT_MS) {
            return Ok(());
        }
        peer.last_hello_ms = now;
        self.send_hello(worker, &entry.key_fp, inc, 0, now)
    }

    fn send_hello(
        &self,
        worker: &str,
        fp: &str,
        my_inc: u64,
        receiver_inc: u64,
        now: u64,
    ) -> Result<(), WireError> {
        let id = format!("{}-hello-{}-{now}", self.me, worker);
        self.link(worker, fp, my_inc, receiver_inc)
            .send(Kind::Hello, 0, 0, id, now, b"{}")
            .map(|_| ())
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
        let (env, plain) = match link.open(msg, now) {
            Ok(x) => x,
            Err(e) => {
                if e == WireError::WrongIncarnation {
                    // signed by the worker's key but for another incarnation: a restart on one side. Never accepted; the remedy
                    // is a fresh hello (rate-limited), which is also how a hub restart is learned
                    st.note(
                        now,
                        "hub.rejected",
                        format!("from={from} reason=incarnation"),
                    );
                    if self.hello(st, &from, now).is_err() {
                        st.note(now, "hub.hello-failed", format!("worker={from}"));
                    }
                    return false;
                }
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
        if env.kind == Kind::Hello {
            return self.take_hello(
                st,
                &from,
                &entry.key_fp,
                env.sender_inc,
                env.receiver_inc,
                now,
            );
        }
        if env.seq <= peer.in_seq {
            let below = peer.in_seq;
            let audit = peer.last_dup_audit_ms == 0
                || now >= peer.last_dup_audit_ms.saturating_add(DUP_AUDIT_MS);
            if audit {
                peer.last_dup_audit_ms = now;
            }
            st.duplicates += 1;
            if audit {
                st.note(
                    now,
                    "hub.duplicate",
                    format!("from={from} seq={} below={below}", env.seq),
                );
            }
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

impl Hub<'_> {
    /// The two steps of a `hello`. A request (names no incarnation of ours) is answered by an echo that names the worker's; an
    /// echo of **our current** incarnation is what sets the worker's incarnation and restarts both sequences, and is answered
    /// once, only when it changed something, so the exchange ends.
    fn take_hello(
        &self,
        st: &mut HubState,
        worker: &str,
        fp: &str,
        sender_inc: u64,
        receiver_inc: u64,
        now: u64,
    ) -> bool {
        let inc = st.inc;
        if receiver_inc == 0 {
            if self.send_hello(worker, fp, inc, sender_inc, now).is_err() {
                st.note(now, "hub.hello-failed", format!("worker={worker}"));
            }
            return true;
        }
        let peer = st.peers.entry(worker.to_string()).or_default();
        if peer.peer_inc == sender_inc {
            return true;
        }
        peer.peer_inc = sender_inc;
        peer.in_seq = 0;
        peer.out_seq = 0;
        st.note(now, "hub.session", format!("worker={worker}"));
        if self.send_hello(worker, fp, inc, sender_inc, now).is_err() {
            st.note(now, "hub.hello-failed", format!("worker={worker}"));
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
