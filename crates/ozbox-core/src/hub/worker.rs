//! The worker's side: what the worker's own service does with what the hub sends.
//!
//! The worker trusts the hub for **delivery and nothing else**. Before it accepts a task it repeats the checks the hub made:
//! Production is refused here too (decision D2), so a hub that has been taken over still cannot hand a worker Production. A kind
//! this release does not build is refused and answered, never silently ignored.

use super::engine::{Assign, AuditLine, ResultBody, StatusBody, DUP_AUDIT_MS, RATE_LIMIT_MS};
use super::refusal::{refuse_production, AUDIT_REFUSED};
use super::wire::{Kind, Link, WireError};

/// What the worker keeps. Disposable: losing it loses unacknowledged messages and nothing else (ADR 0020's invariant).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerState {
    /// This worker's incarnation: fresh whenever the state is created, so losing the state can never make an old message
    /// verify again (ADR 0042 H-2).
    pub inc: u64,
    /// The hub's incarnation as learned from its `hello` (0 until then).
    pub hub_inc: u64,
    pub out_seq: u64,
    pub in_seq: u64,
    pub tasks: Vec<Assign>,
    pub audit: Vec<AuditLine>,
    /// Rate limits (see the hub's `PeerState`).
    pub last_hello_ms: u64,
    pub last_dup_audit_ms: u64,
}

impl Default for WorkerState {
    fn default() -> Self {
        WorkerState {
            inc: super::engine::fresh_incarnation(),
            hub_inc: 0,
            out_seq: 0,
            in_seq: 0,
            tasks: Vec::new(),
            audit: Vec::new(),
            last_hello_ms: 0,
            last_dup_audit_ms: 0,
        }
    }
}

impl WorkerState {
    fn note(&mut self, now: u64, action: &str, detail: String) {
        self.audit.push(AuditLine {
            ts_ms: now,
            action: action.to_string(),
            detail,
        });
    }
}

/// The worker's end of its one link, to the hub.
pub struct WorkerEnd<'a> {
    pub link: Link<'a>,
}

impl WorkerEnd<'_> {
    fn say(&self, st: &mut WorkerState, now: u64, kind: Kind, plain: &[u8]) {
        if st.hub_inc == 0 {
            // no session yet: the hub would refuse it, so it is not sent (and not counted)
            st.note(now, "worker.no-session", format!("kind={}", kind.name()));
            return;
        }
        st.out_seq += 1;
        let id = format!("{}-{}", self.link.me, st.out_seq);
        let link = self.link.with_incarnations(st.inc, st.hub_inc);
        if let Err(e) = link.send(kind, st.out_seq, st.in_seq, id, now, plain) {
            // a message that cannot be built or sent is said, never dropped silently; the hub's resync asks again
            st.out_seq -= 1;
            st.note(
                now,
                "worker.send-failed",
                format!("kind={} reason={e}", kind.name()),
            );
        }
    }

    /// Step one of a `hello`: tell the hub this worker's incarnation (it names none of the hub's). Rate-limited.
    pub fn hello(&self, st: &mut WorkerState, now: u64) {
        self.send_hello(st, now, 0, true);
    }

    fn send_hello(&self, st: &mut WorkerState, now: u64, receiver_inc: u64, limited: bool) {
        if limited && st.last_hello_ms != 0 && now < st.last_hello_ms.saturating_add(RATE_LIMIT_MS)
        {
            return;
        }
        st.last_hello_ms = now;
        let link = self.link.with_incarnations(st.inc, receiver_inc);
        let id = format!("{}-hello-{now}", self.link.me);
        if let Err(e) = link.send(Kind::Hello, 0, 0, id, now, b"{}") {
            st.note(now, "worker.send-failed", format!("kind=hello reason={e}"));
        }
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

    fn hello_taken(&self, st: &mut WorkerState, now: u64, sender_inc: u64, receiver_inc: u64) {
        if receiver_inc == 0 {
            // the hub's request: answer with an echo naming its incarnation; nothing changes yet
            self.send_hello(st, now, sender_inc, false);
            return;
        }
        if st.hub_inc == sender_inc {
            return;
        }
        st.hub_inc = sender_inc;
        st.in_seq = 0;
        st.out_seq = 0;
        st.note(now, "worker.session", String::new());
        self.send_hello(st, now, sender_inc, false);
    }

    /// Take every message waiting for this worker. Returns how many were applied.
    pub fn poll(&self, st: &mut WorkerState, now: u64) -> usize {
        let mut applied = 0;
        while let Some(msg) = self.link.net.recv(self.link.me) {
            let link = self.link.with_incarnations(st.inc, st.hub_inc);
            let (env, plain) = match link.open(&msg, now) {
                Ok(x) => x,
                Err(e @ (WireError::WrongIncarnation | WireError::Stale)) => {
                    st.note(
                        now,
                        "worker.rejected",
                        format!(
                            "reason={}",
                            if e == WireError::Stale {
                                "stale"
                            } else {
                                "incarnation"
                            }
                        ),
                    );
                    if e == WireError::WrongIncarnation {
                        // a restart on one side: ask for a fresh session (rate-limited), never accept the message
                        self.hello(st, now);
                    }
                    continue;
                }
                Err(_) => {
                    st.note(now, "worker.rejected", "reason=unverified".to_string());
                    continue;
                }
            };
            if env.kind == Kind::Hello {
                self.hello_taken(st, now, env.sender_inc, env.receiver_inc);
                continue;
            }
            if env.seq <= st.in_seq {
                if st.last_dup_audit_ms == 0
                    || now >= st.last_dup_audit_ms.saturating_add(DUP_AUDIT_MS)
                {
                    st.last_dup_audit_ms = now;
                    st.note(
                        now,
                        "worker.duplicate",
                        format!("seq={} below={}", env.seq, st.in_seq),
                    );
                }
                continue;
            }
            if env.seq != st.in_seq + 1 || env.level != 0 || !env.kind.hub_to_worker() {
                st.note(
                    now,
                    "worker.rejected",
                    format!("kind={} reason=shape", env.kind.name()),
                );
                continue;
            }
            st.in_seq = env.seq;
            applied += 1;
            match env.kind {
                Kind::TaskAssign => self.assigned(st, now, &plain),
                Kind::KeysDeliver | Kind::KeysRevoke | Kind::PinsSet | Kind::LaptopRelay => {
                    // key delivery, pins and the laptop relay are not built in this release: said, never ignored
                    st.note(
                        now,
                        "worker.unsupported",
                        format!("kind={}", env.kind.name()),
                    );
                    self.status(
                        st,
                        now,
                        "-",
                        "-",
                        "unsupported",
                        &format!("{} is not supported in this release", env.kind.name()),
                    );
                }
                _ => {}
            }
        }
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
                format!("side=worker {}", r.audit_detail(self.link.me, &a.feature)),
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
