//! The worker's side: what the worker's own service does with what the hub sends.
//!
//! The worker trusts the hub for **delivery and nothing else**. Before it accepts a task it repeats the checks the hub made:
//! Production is refused here too (decision D2), so a hub that has been taken over still cannot hand a worker Production. A kind
//! this release does not build is refused and answered, never silently ignored.
//!
//! Sessions, order, replay and acknowledgement are the channel's ([`crate::channel`]); the worker keeps a [`Core`] with one link, to
//! the hub, and queues what it says in that link's outbox, so a report is never lost to a gap in the session.

use super::engine::{Assign, ResultBody, StatusBody};
use super::keys::{
    names_ok, DeliveryStore, KeyAsk, KeyDelivery, KeyRevoke, AUDIT_DELETED, AUDIT_STORED,
    CODE_ASK_INVALID, CODE_DELIVERY_INVALID, CODE_NOT_ASSIGNED, CODE_NOT_DECLARED, CODE_STORE,
};
use super::refusal::{
    refuse_production, KeyDeclaration, Refusal, AUDIT_REFUSED, CODE_PRODUCTION, CODE_UNSUPPORTED,
    CODE_VALUE_IN_DECLARATION,
};
use super::wire::{Ext, Kind, Transport, WireError, PROFILE};
#[cfg(test)]
use crate::audit::NewEvent;
use crate::channel::audit::HasCore;
use crate::channel::flow::{receive_round, seal_drafts};
use crate::channel::session::{Core, Link};
use crate::channel::wire::{Crypto, Sealed, Sealer, Signer, Verifier};

/// What the worker keeps. Disposable: losing it loses unacknowledged messages and nothing else (ADR 0020's invariant).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WorkerState {
    pub core: Core,
    pub tasks: Vec<Assign>,
    /// Decisions `main` relayed, waiting for this box's own service to verify them ([`WorkerEnd::apply_decisions`]). Evidence only:
    /// nothing here is a grant until the service has verified it.
    #[serde(default)]
    pub decisions: Vec<super::approvals::DecisionBody>,
    /// Requests announced to the hub, and when (they are announced again every 30 seconds while pending).
    #[serde(default)]
    pub announced: super::approvals::Announced,
    /// Lane shards handed to this worker, to run with the declared command.
    #[serde(default)]
    pub shards: Vec<super::lane::ShardAssign>,
    /// What the hub said back about this worker's features (a merge conflict, failing tests, an answer).
    #[serde(default)]
    pub answers: Vec<super::merge::AnswerBody>,
    /// Approver lists `main` carried, waiting for this box's own service to verify them ([`WorkerEnd::apply_approver_sets`]). Evidence
    /// only: nothing here changes who approves until the service has checked the owner's signature.
    #[serde(default)]
    pub approver_sets: Vec<super::approver_sync::SignedApprovers>,
}

impl HasCore for WorkerState {
    fn core(&self) -> &Core {
        &self.core
    }
    fn core_mut(&mut self) -> &mut Core {
        &mut self.core
    }
}

impl WorkerState {
    /// A new worker state: this worker's name and key fingerprint, and the hub it is pinned to (its name, key fingerprint and the
    /// hub's epoch). The incarnation is fresh, so losing the state can never make an old message verify again.
    pub fn new(me: &str, my_fp: &str, hub: &str, hub_fp: &str, hub_epoch: u64) -> WorkerState {
        let mut core = Core::new(me, my_fp, my_fp, my_fp, super::engine::WORKER_EPOCH);
        core.pin(Link::new(hub, hub_fp, hub_fp, hub_fp, hub_epoch));
        WorkerState {
            core,
            tasks: Vec::new(),
            decisions: Vec::new(),
            announced: Default::default(),
            shards: Vec::new(),
            answers: Vec::new(),
            approver_sets: Vec::new(),
        }
    }

    pub fn inc(&self) -> u64 {
        self.core.incarnation
    }

    /// The hub's incarnation as learned from its `hello` (0 until then).
    pub fn hub_inc(&self) -> u64 {
        self.core.links.values().next().map_or(0, |l| l.peer_inc)
    }

    #[cfg(test)]
    pub fn take_audit(&mut self) -> Vec<NewEvent> {
        std::mem::take(&mut self.core.audit)
    }

    fn note(&mut self, now: u64, action: &str, detail: String) {
        self.core.note(now, action, None, detail);
    }
}

/// The worker's end of its one link, to the hub.
pub struct WorkerEnd<'a> {
    pub me: &'a str,
    pub hub: &'a str,
    pub signer: &'a dyn Signer,
    pub verifier: &'a dyn Verifier,
    pub sealer: &'a dyn Sealer,
    pub net: &'a dyn Transport,
}

impl WorkerEnd<'_> {
    fn cx(&self) -> Crypto<'_> {
        Crypto {
            signer: self.signer,
            verifier: self.verifier,
            sealer: self.sealer,
        }
    }

    /// Push what the channel says the hub is owed. A transport that cannot take it is said, never dropped silently; the outbox
    /// keeps it and the next push sends it again.
    fn flush(&self, st: &mut WorkerState, now: u64) {
        let opts = st.core.push_opts(self.hub, now);
        let drafts = st.core.drafts(self.hub, now, opts);
        if drafts.is_empty() {
            return;
        }
        let sent: Result<(), WireError> = seal_drafts(&PROFILE, &self.cx(), &drafts)
            .map_err(WireError::from)
            .and_then(|sealed| {
                sealed
                    .into_iter()
                    .try_for_each(|m| self.net.send(self.hub, m))
            });
        match sent {
            Ok(()) => st.core.pushed(self.hub, now, &drafts),
            Err(e) => st.note(now, "worker.send-failed", format!("reason={e}")),
        }
    }

    fn say(&self, st: &mut WorkerState, now: u64, kind: Kind, plain: &[u8]) {
        if let Err(c) = st.core.enqueue(
            &PROFILE,
            self.hub,
            kind.name(),
            Ext::at(1).encode(),
            plain.to_vec(),
        ) {
            st.note(
                now,
                "worker.send-failed",
                format!("kind={} reason={c}", kind.name()),
            );
            return;
        }
        self.flush(st, now);
    }

    /// Step one of a `hello`: tell the hub this worker's incarnation (it names none of the hub's). Rate-limited.
    pub fn hello(&self, st: &mut WorkerState, now: u64) {
        if let Some(l) = st.core.links.get_mut(self.hub) {
            l.hello_wanted = true;
        }
        self.flush(st, now);
    }

    fn status(
        &self,
        st: &mut WorkerState,
        now: u64,
        orchestration: &str,
        feature: &str,
        state: &str,
        text: &str,
    ) {
        let body = StatusBody {
            orchestration: orchestration.to_string(),
            feature: feature.to_string(),
            state: state.to_string(),
            text: text.to_string(),
        };
        if let Ok(b) = serde_json::to_vec(&body) {
            self.say(st, now, Kind::Status, &b);
        }
    }

    /// Take every message waiting for this worker. Returns how many were applied. Key delivery is answered `unsupported`: a worker
    /// whose service can store a delivery polls with [`WorkerEnd::poll_keys`].
    pub fn poll(&self, st: &mut WorkerState, now: u64) -> usize {
        self.poll_inner(st, now, None)
    }

    /// As [`WorkerEnd::poll`], with the worker's service behind it: a `keys.deliver` that passes the worker's own checks (D2, the task
    /// held, the names declared) is handed to [`DeliveryStore::store_delivery`], which alone opens it; `keys.revoke` and `task.end`
    /// delete that task's keys.
    pub fn poll_keys(&self, st: &mut WorkerState, now: u64, store: &dyn DeliveryStore) -> usize {
        self.poll_inner(st, now, Some(store))
    }

    fn poll_inner(
        &self,
        st: &mut WorkerState,
        now: u64,
        store: Option<&dyn DeliveryStore>,
    ) -> usize {
        let mut msgs: Vec<Sealed> = Vec::new();
        while let Some(m) = self.net.recv(self.me) {
            msgs.push(m);
        }
        st.core.tick(now);
        let cx = self.cx();
        let keyed = store.is_some();
        let admit = move |kind: &str, ext: &[u8], plain: &[u8]| {
            if keyed {
                screen_keys(kind, ext, plain)
            } else {
                screen(kind, ext, plain)
            }
        };
        let r = receive_round(&mut st.core, &PROFILE, &cx, &admit, now, &msgs);
        let mut applied = 0;
        for d in r.deliveries {
            let level_ok = Ext::decode(&d.ext).is_some_and(|e| e.level == 0 && e.via.is_empty());
            let Some(kind) = Kind::parse(&d.kind).filter(|_| level_ok) else {
                st.note(now, "worker.rejected", "reason=shape".to_string());
                continue;
            };
            if !kind.hub_to_worker() {
                st.note(
                    now,
                    "worker.rejected",
                    format!("kind={} reason=shape", kind.name()),
                );
                continue;
            }
            let plain = match d.body {
                Ok(p) => p,
                Err(code) => {
                    // refused by the screen: the content is gone, only the kind and the code are left
                    if code == CODE_UNSUPPORTED {
                        applied += 1;
                        self.unsupported(st, now, kind);
                    } else if code == super::approver_sync::CODE_NOT_AN_APPROVER_SET {
                        st.note(
                            now,
                            super::approver_sync::AUDIT_WORKER_REFUSED,
                            format!("kind={} code={code}", kind.name()),
                        );
                    } else if code == super::approvals::CODE_NOT_A_DECISION {
                        st.note(
                            now,
                            super::approvals::AUDIT_WORKER_REFUSED,
                            format!("kind={} code={code}", kind.name()),
                        );
                    } else if code == CODE_DELIVERY_INVALID || code == CODE_PRODUCTION {
                        st.note(
                            now,
                            AUDIT_REFUSED,
                            format!(
                                "side=worker worker={} task=- kind={} code={code}",
                                self.me,
                                kind.name()
                            ),
                        );
                        self.status(
                            st,
                            now,
                            "-",
                            "-",
                            "refused",
                            "a key delivery was refused by this worker's own checks",
                        );
                    } else if code == CODE_VALUE_IN_DECLARATION {
                        st.note(
                            now,
                            AUDIT_REFUSED,
                            format!("side=worker worker={} task=- code={code}", self.me),
                        );
                        self.status(
                            st,
                            now,
                            "-",
                            "-",
                            "refused",
                            "an assignment's key declaration carried more than an environment and names, so it was refused",
                        );
                    } else {
                        st.note(now, "worker.rejected", "reason=shape".to_string());
                    }
                    continue;
                }
            };
            applied += 1;
            match kind {
                Kind::TaskAssign => self.assigned(st, now, &plain),
                Kind::ApprovalDecision => {
                    // the screen has already refused anything that is not exactly a decision body
                    if let Ok(d) = serde_json::from_slice::<super::approvals::DecisionBody>(&plain)
                    {
                        if st.decisions.len() < 64 {
                            st.decisions.push(d);
                        } else {
                            st.note(
                                now,
                                super::approvals::AUDIT_WORKER_REFUSED,
                                "reason=backlog".into(),
                            );
                        }
                    }
                }
                Kind::ShardAssign => {
                    if let Ok(a) = serde_json::from_slice::<super::lane::ShardAssign>(&plain) {
                        st.note(
                            now,
                            "worker.shard.assigned",
                            format!("run={} shard={} specs={}", a.run, a.shard, a.specs.len()),
                        );
                        st.shards.push(a);
                    }
                }
                Kind::Answer => {
                    if let Ok(a) = serde_json::from_slice::<super::merge::AnswerBody>(&plain) {
                        if st.answers.len() >= 200 {
                            st.answers.remove(0);
                        }
                        st.answers.push(a);
                    }
                }
                Kind::KeysDeliver if store.is_some() => {
                    if let Some(store) = store {
                        self.delivered(st, now, &plain, store);
                    }
                }
                Kind::KeysRevoke | Kind::TaskEnd if store.is_some() => {
                    if let (Some(store), Ok(r)) =
                        (store, serde_json::from_slice::<KeyRevoke>(&plain))
                    {
                        store.delete_task(&r.orchestration, &r.feature);
                        if kind == Kind::TaskEnd {
                            st.tasks.retain(|t| {
                                !(t.orchestration == r.orchestration && t.feature == r.feature)
                            });
                        }
                        st.note(
                            now,
                            AUDIT_DELETED,
                            format!(
                                "worker={} task={} reason={}",
                                self.me,
                                r.feature,
                                kind.name()
                            ),
                        );
                    }
                }
                Kind::PinsSet => {
                    // the screen has already refused anything that is not exactly a signed approver list
                    if let Ok(a) =
                        serde_json::from_slice::<super::approver_sync::SignedApprovers>(&plain)
                    {
                        if st.approver_sets.len() < 4 {
                            st.approver_sets.push(a);
                        } else {
                            st.note(
                                now,
                                super::approver_sync::AUDIT_WORKER_REFUSED,
                                "reason=backlog".into(),
                            );
                        }
                    }
                }
                Kind::KeysDeliver | Kind::KeysRevoke | Kind::LaptopRelay => {
                    // the screen refuses these first; kept so a screen that ever lets one through still answers
                    self.unsupported(st, now, kind);
                }
                _ => {}
            }
        }
        self.flush(st, now);
        applied
    }

    /// Key delivery, pins and the laptop relay are not built in this release: said, never ignored.
    fn unsupported(&self, st: &mut WorkerState, now: u64, kind: Kind) {
        st.note(now, "worker.unsupported", format!("kind={}", kind.name()));
        self.status(
            st,
            now,
            "-",
            "-",
            "unsupported",
            &format!("{} is not supported in this release", kind.name()),
        );
    }

    fn assigned(&self, st: &mut WorkerState, now: u64, plain: &[u8]) {
        let Ok(a) = serde_json::from_slice::<Assign>(plain) else {
            st.note(
                now,
                "worker.rejected",
                "kind=task.assign reason=malformed".to_string(),
            );
            return;
        };
        if let Err(r) = refuse_production(&a.keys) {
            st.note(
                now,
                AUDIT_REFUSED,
                format!("side=worker {}", r.audit_detail(self.me, &a.feature)),
            );
            self.status(st, now, &a.orchestration, &a.feature, "refused", &r.message);
            return;
        }
        if a.lease_expiry_ms <= now {
            // a captured or stale assignment: the lease is the task's life
            st.note(
                now,
                "worker.rejected",
                "kind=task.assign reason=lease-expired".to_string(),
            );
            self.status(
                st,
                now,
                &a.orchestration,
                &a.feature,
                "refused",
                "the lease on this assignment has expired",
            );
            return;
        }
        self.status(st, now, &a.orchestration, &a.feature, "accepted", "");
        st.tasks.push(a);
    }

    /// A delivery that passed the screen: checked against the task this worker holds, then handed to its service.
    fn delivered(&self, st: &mut WorkerState, now: u64, plain: &[u8], store: &dyn DeliveryStore) {
        let Ok(d) = serde_json::from_slice::<KeyDelivery>(plain) else {
            st.note(
                now,
                "worker.rejected",
                "kind=keys.deliver reason=malformed".into(),
            );
            return;
        };
        let held = st
            .tasks
            .iter()
            .find(|t| t.orchestration == d.orchestration && t.feature == d.feature);
        let code = match held {
            None => Some(CODE_NOT_ASSIGNED),
            Some(t) if t.keys.env != d.env || d.names.iter().any(|n| !t.keys.names.contains(n)) => {
                Some(CODE_NOT_DECLARED)
            }
            Some(_) => None,
        };
        let code = match code {
            Some(c) => Err(c),
            None => store.store_delivery(&d).map_err(|_| CODE_STORE),
        };
        match code {
            Ok(()) => {
                st.note(
                    now,
                    AUDIT_STORED,
                    format!(
                        "worker={} task={} env={} names={} request={}",
                        self.me,
                        d.feature,
                        d.env,
                        d.names.join(","),
                        d.request_id
                    ),
                );
                self.status(
                    st,
                    now,
                    &d.orchestration,
                    &d.feature,
                    "working",
                    "keys stored",
                );
            }
            Err(c) => {
                st.note(
                    now,
                    AUDIT_REFUSED,
                    format!("side=worker worker={} task={} code={c}", self.me, d.feature),
                );
                self.status(
                    st,
                    now,
                    &d.orchestration,
                    &d.feature,
                    "refused",
                    "a key delivery for this task was refused by the worker",
                );
            }
        }
    }

    /// Ask the hub for keys by name, for a task this worker holds. Only names its declaration lists, and never Production: refused
    /// here before anything is sent (D2 on the worker, before the hub's own check).
    pub fn ask_keys(
        &self,
        st: &mut WorkerState,
        now: u64,
        orchestration: &str,
        feature: &str,
        names: &[String],
    ) -> Result<(), Refusal> {
        let Some(t) = st
            .tasks
            .iter()
            .find(|t| t.orchestration == orchestration && t.feature == feature)
        else {
            return Err(Refusal {
                code: CODE_NOT_ASSIGNED,
                message: "this worker does not hold that task".into(),
            });
        };
        if !names_ok(names) || names.iter().any(|n| !t.keys.names.contains(n)) {
            return Err(Refusal {
                code: CODE_NOT_DECLARED,
                message: "a worker asks only for keys its task declared, by name".into(),
            });
        }
        refuse_production(&KeyDeclaration {
            env: t.keys.env.clone(),
            names: names.to_vec(),
        })?;
        let body =
            serde_json::to_vec(&KeyAsk::new(orchestration, feature, names)).map_err(|_| {
                Refusal {
                    code: CODE_ASK_INVALID,
                    message: "the ask could not be written".into(),
                }
            })?;
        self.say(st, now, Kind::Blocked, &body);
        Ok(())
    }

    /// The hub cannot be reached: delete every key this worker holds, at once (ADR 0042 section 5.3), and say so in the audit.
    /// The hub agent calls this when its transport stops being connected ([`crate::hub::net::NetWorker::reach`]).
    pub fn hub_lost(&self, st: &mut WorkerState, now: u64, store: &dyn DeliveryStore) {
        store.delete_all();
        st.note(
            now,
            AUDIT_DELETED,
            format!("worker={} task=* reason=hub-lost", self.me),
        );
    }

    pub fn report(
        &self,
        st: &mut WorkerState,
        now: u64,
        orchestration: &str,
        feature: &str,
        text: &str,
    ) {
        self.status(st, now, orchestration, feature, "working", text);
    }

    pub fn finish(
        &self,
        st: &mut WorkerState,
        now: u64,
        orchestration: &str,
        feature: &str,
        commit: &str,
        summary: &str,
    ) {
        let body = ResultBody {
            orchestration: orchestration.to_string(),
            feature: feature.to_string(),
            commit: commit.to_string(),
            summary: summary.to_string(),
        };
        if let Ok(b) = serde_json::to_vec(&body) {
            self.say(st, now, Kind::Result, &b);
        }
    }

    /// Announce this box's pending requests to the hub: each one's signed envelope, again every 30 seconds while it is pending (the
    /// hub does not rely on one delivery). Returns how many were sent.
    pub fn announce_approvals(
        &self,
        st: &mut WorkerState,
        svc: &dyn super::approvals::ApprovalService,
        now: u64,
    ) -> usize {
        let pending = svc.pending(now);
        let live: std::collections::BTreeSet<String> = pending
            .iter()
            .filter_map(|e| serde_json::from_str::<serde_json::Value>(&e.canonical).ok())
            .filter_map(|v| v["id"].as_str().map(str::to_string))
            .collect();
        st.announced.retain(|id, _| live.contains(id));
        let mut sent = 0;
        for signed in pending {
            let Some(id) = serde_json::from_str::<serde_json::Value>(&signed.canonical)
                .ok()
                .and_then(|v| v["id"].as_str().map(str::to_string))
            else {
                continue;
            };
            if st
                .announced
                .get(&id)
                .is_some_and(|t| now.saturating_sub(*t) < super::approvals::ANNOUNCE_EVERY_MS)
            {
                continue;
            }
            let Ok(b) = serde_json::to_vec(&super::approvals::RequestBody { signed }) else {
                continue;
            };
            self.say(st, now, Kind::ApprovalRequest, &b);
            st.announced.insert(id, now);
            sent += 1;
        }
        sent
    }

    /// Hand each relayed decision to this box's own service, which verifies it. What the service says is reported back to the hub as
    /// the worker's own status, so the person sees the worker's answer, not `main`'s relay.
    pub fn apply_decisions(
        &self,
        st: &mut WorkerState,
        svc: &mut dyn super::approvals::ApprovalService,
        now: u64,
    ) -> Vec<(String, Result<String, String>)> {
        let mut out = Vec::new();
        for d in std::mem::take(&mut st.decisions) {
            let r = svc.decide_from_fleet(self.hub, &d, now);
            match &r {
                Ok(state) => {
                    st.note(
                        now,
                        super::approvals::AUDIT_WORKER_DECIDED,
                        format!(
                            "request={} outcome={} state={state} via=fleet:{}",
                            d.request_id,
                            d.outcome.word(),
                            self.hub
                        ),
                    );
                    self.status(
                        st,
                        now,
                        "-",
                        "-",
                        "approval",
                        &format!("request {} is {state}", d.request_id),
                    );
                }
                Err(why) => {
                    st.note(
                        now,
                        super::approvals::AUDIT_WORKER_REFUSED,
                        format!("request={} outcome={}", d.request_id, d.outcome.word()),
                    );
                    self.status(
                        st,
                        now,
                        "-",
                        "-",
                        "approval-refused",
                        &format!("request {}: {why}", d.request_id),
                    );
                }
            }
            out.push((d.request_id.clone(), r));
        }
        out
    }

    /// Hand each approver list `main` carried to this box's own service, which verifies the owner's signature and writes it only then.
    /// What the service says is reported back as the worker's own status (the version it holds, or its refusal), so the person sees the
    /// worker's answer and not `main`'s.
    pub fn apply_approver_sets(
        &self,
        st: &mut WorkerState,
        svc: &mut dyn super::approvals::ApprovalService,
        now: u64,
    ) -> Vec<Result<u64, String>> {
        use super::approver_sync::{
            AUDIT_WORKER_REFUSED, AUDIT_WORKER_SET, STATE_HELD, STATE_REFUSED,
        };
        let mut out = Vec::new();
        for a in std::mem::take(&mut st.approver_sets) {
            let r = svc.set_approvers(&a, now);
            match &r {
                Ok(seq) => {
                    st.note(
                        now,
                        AUDIT_WORKER_SET,
                        format!("seq={seq} via=fleet:{}", self.hub),
                    );
                    self.status(st, now, "-", "-", STATE_HELD, &format!("seq={seq}"));
                }
                Err(why) => {
                    st.note(now, AUDIT_WORKER_REFUSED, "reason=service".to_string());
                    self.status(st, now, "-", "-", STATE_REFUSED, why);
                }
            }
            out.push(r);
        }
        out
    }

    /// Report a lane shard's results (all at once, or as they come; `finished` when the runner is done).
    pub fn shard_result(&self, st: &mut WorkerState, now: u64, r: &super::lane::ShardResult) {
        if let Ok(b) = serde_json::to_vec(r) {
            self.say(st, now, Kind::ShardResult, &b);
        }
    }

    /// Ask the hub a question about a feature (`worker_ask`). A question asks; it never grants.
    pub fn ask(&self, st: &mut WorkerState, now: u64, text: &str) {
        self.say(st, now, Kind::Question, text.as_bytes());
    }

    /// Send one of an engine's turns, as the kind and body [`crate::engine_turn::to_hub`] made of it. The kinds a worker may send are
    /// the channel's; the hub refuses any other and quarantines a worker that sends one it alone may.
    pub fn send_body(&self, st: &mut WorkerState, now: u64, kind: Kind, plain: &[u8]) {
        self.say(st, now, kind, plain);
    }

    /// Send a message of a kind the hub alone may send. Exists only so a test can show the hub's reaction to it.
    #[cfg(test)]
    pub fn say_raw(&self, st: &mut WorkerState, now: u64, kind: Kind, plain: &[u8]) {
        self.say(st, now, kind, plain);
    }
}

/// The worker's screen, run on a body before it is held for a gap or applied. What this release builds no use for (a key value,
/// pins, the laptop relay) is refused here, so its content is never written to the worker's state, even while it waits for an
/// earlier message. An assignment's key declaration may hold its environment and names and nothing else.
fn screen(kind: &str, _ext: &[u8], plain: &[u8]) -> Result<(), &'static str> {
    match Kind::parse(kind) {
        Some(Kind::KeysDeliver | Kind::KeysRevoke | Kind::LaptopRelay) => Err(CODE_UNSUPPORTED),
        // an approver list is exactly its two fields and no larger than a list may be; whether it is the owner's is the service's to say
        Some(Kind::PinsSet) => {
            if plain.len() > super::approver_sync::MAX_SET_BYTES + 1024 {
                return Err(super::approver_sync::CODE_NOT_AN_APPROVER_SET);
            }
            serde_json::from_slice::<super::approver_sync::SignedApprovers>(plain)
                .map(|_| ())
                .map_err(|_| super::approver_sync::CODE_NOT_AN_APPROVER_SET)
        }
        Some(Kind::TaskAssign) => declaration_is_names_only(plain),
        // a message can ask and never grant: a decision is exactly its fields, so a grant, a token or a flag beside them is refused
        // before the body is held
        Some(Kind::ApprovalDecision) => {
            serde_json::from_slice::<super::approvals::DecisionBody>(plain)
                .map(|_| ())
                .map_err(|_| super::approvals::CODE_NOT_A_DECISION)
        }
        Some(Kind::ShardAssign) => serde_json::from_slice::<super::lane::ShardAssign>(plain)
            .map(|_| ())
            .map_err(|_| super::approvals::CODE_NOT_A_DECISION),
        _ => Ok(()),
    }
}

/// The screen of a worker whose service can store a delivery. `keys.deliver` must be exactly a [`KeyDelivery`] whose labels are not
/// Production (D2 on the worker, before the body is held for a gap); `keys.revoke` and `task.end` exactly a [`KeyRevoke`]. Anything
/// else of those kinds is refused here, so its content is never held.
fn screen_keys(kind: &str, ext: &[u8], plain: &[u8]) -> Result<(), &'static str> {
    match Kind::parse(kind) {
        Some(Kind::KeysDeliver) => {
            let d =
                serde_json::from_slice::<KeyDelivery>(plain).map_err(|_| CODE_DELIVERY_INVALID)?;
            if !names_ok(&d.names) || d.sealed.is_empty() {
                return Err(CODE_DELIVERY_INVALID);
            }
            refuse_production(&KeyDeclaration {
                env: d.env,
                names: d.names,
            })
            .map_err(|_| CODE_PRODUCTION)
        }
        Some(Kind::KeysRevoke | Kind::TaskEnd) => serde_json::from_slice::<KeyRevoke>(plain)
            .map(|_| ())
            .map_err(|_| CODE_DELIVERY_INVALID),
        _ => screen(kind, ext, plain),
    }
}

fn declaration_is_names_only(plain: &[u8]) -> Result<(), &'static str> {
    // a body that is not JSON is refused as malformed when it is applied; it carries no declaration to screen
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(plain) else {
        return Ok(());
    };
    match v.get("keys") {
        None => Ok(()),
        Some(serde_json::Value::Object(m)) if m.keys().all(|k| k == "env" || k == "names") => {
            Ok(())
        }
        Some(_) => Err(CODE_VALUE_IN_DECLARATION),
    }
}
