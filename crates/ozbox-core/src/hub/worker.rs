//! The worker's side: what the worker's own service does with what the hub sends.
//!
//! The worker trusts the hub for **delivery and nothing else**. Before it accepts a task it repeats the checks the hub made:
//! Production is refused here too (decision D2), so a hub that has been taken over still cannot hand a worker Production. A kind
//! this release does not build is refused and answered, never silently ignored.
//!
//! Sessions, order, replay and acknowledgement are the channel's ([`crate::channel`]); the worker keeps a [`Core`] with one link, to
//! the hub, and queues what it says in that link's outbox, so a report is never lost to a gap in the session.

use super::engine::{Assign, ResultBody, StatusBody};
use super::refusal::{refuse_production, AUDIT_REFUSED};
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
    /// hub's epoch). The incarnation is fresh, so losing the state can never make an old message verify again (ADR 0042 H-2).
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

    /// Take every message waiting for this worker. Returns how many were applied.
    pub fn poll(&self, st: &mut WorkerState, now: u64) -> usize {
        let mut msgs: Vec<Sealed> = Vec::new();
        while let Some(m) = self.net.recv(self.me) {
            msgs.push(m);
        }
        st.core.tick(now);
        let cx = self.cx();
        let r = receive_round(&mut st.core, &PROFILE, &cx, &|_, _, _| Ok(()), now, &msgs);
        let mut applied = 0;
        for d in r.deliveries {
            let kind = Kind::parse(&d.kind);
            let level_ok = Ext::decode(&d.ext).is_some_and(|e| e.level == 0 && e.via.is_empty());
            let (Some(kind), Ok(plain), true) = (kind, d.body, level_ok) else {
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
            applied += 1;
            match kind {
                Kind::TaskAssign => self.assigned(st, now, &plain),
                Kind::KeysDeliver | Kind::KeysRevoke | Kind::PinsSet | Kind::LaptopRelay => {
                    // key delivery, pins and the laptop relay are not built in this release: said, never ignored
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
                _ => {}
            }
        }
        self.flush(st, now);
        applied
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
