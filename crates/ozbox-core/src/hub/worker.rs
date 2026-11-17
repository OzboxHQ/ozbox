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
                Kind::KeysDeliver | Kind::KeysRevoke | Kind::PinsSet | Kind::LaptopRelay => {
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
        Some(Kind::KeysDeliver | Kind::KeysRevoke | Kind::PinsSet | Kind::LaptopRelay) => {
            Err(CODE_UNSUPPORTED)
        }
        Some(Kind::TaskAssign) => declaration_is_names_only(plain),
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
