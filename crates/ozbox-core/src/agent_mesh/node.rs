//! One endpoint: its state, its keys, its screen and its audit trail, and the things it does with a peer. A laptop and `main` run the
//! same code; only the names and the way they reach each other differ.
//!
//! Every change is **one** write of the state under the store's lock, with the audit events written in the same write and handed to
//! the audit log afterwards (by source number, so a crash or two processes at once can neither lose nor repeat one). A round with a
//! peer is one write for everything it took, and no write at all when nothing changed.

use super::model::{Part, State as TState};
use super::state::{NewTask, State};
use super::{Screen, PROFILE};
use crate::channel::audit::{change, change_if, drain, guard, AuditSink, JournalError};
use crate::channel::flow::seal_drafts;
use crate::channel::session::DraftOpts;
use crate::channel::store::{Store, StoreError};
use crate::channel::wire::{Crypto, Sealed};

#[derive(Debug)]
pub struct NodeError(pub String);

impl std::fmt::Display for NodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<StoreError> for NodeError {
    fn from(e: StoreError) -> Self {
        NodeError(e.to_string())
    }
}

impl From<JournalError> for NodeError {
    fn from(e: JournalError) -> Self {
        NodeError(e.0)
    }
}

/// Moves sealed envelopes between two endpoints. The network is not trusted: a transport only moves bytes. One call carries what this
/// end has for the peer and returns what the peer has for this end (a request and its reply).
pub trait Transport {
    fn exchange(&self, peer: &str, outbound: &[Sealed]) -> Result<Vec<Sealed>, String>;
}

/// What one round with a peer did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Round {
    pub sent: usize,
    /// Messages of any kind that were applied.
    pub applied: usize,
    pub buffered: usize,
    pub duplicates: usize,
    pub refused: Vec<String>,
}

pub struct Node<'a> {
    pub store: &'a Store<State>,
    pub crypto: Crypto<'a>,
    pub screen: &'a dyn Screen,
    pub audit: &'a dyn AuditSink,
    pub clock: &'a dyn Fn() -> u64,
}

impl Node<'_> {
    fn now(&self) -> u64 {
        (self.clock)()
    }

    /// Refuse to work when the audit log is ahead of this store (it was rolled back and nobody said so).
    pub fn guard(&self) -> Result<(), NodeError> {
        let st = self.store.read()?;
        Ok(guard(&st.core, self.audit)?)
    }

    /// Hand pending audit events to the audit log, under the store's lock.
    pub fn drain_audit(&self) -> Result<(), NodeError> {
        Ok(drain(self.store, self.audit)?)
    }

    fn change<T>(&self, f: impl FnOnce(&mut State, u64) -> T) -> Result<T, NodeError> {
        let now = self.now();
        let out = change(self.store, self.audit, |s| f(s, now))?;
        self.drain_audit()?;
        Ok(out)
    }

    pub fn submit(&self, n: NewTask) -> Result<String, NodeError> {
        let screen = self.screen;
        self.change(|s, now| s.submit(screen, now, n))?
            .map_err(|c| NodeError(format!("refused: {c}")))
    }

    pub fn reply(
        &self,
        task_id: &str,
        parts: Vec<Part>,
        to_state: Option<(TState, Option<String>)>,
    ) -> Result<(), NodeError> {
        let screen = self.screen;
        self.change(|s, now| s.reply(screen, now, task_id, parts, to_state))?
            .map_err(|c| NodeError(format!("refused: {c}")))
    }

    pub fn cancel(&self, task_id: &str) -> Result<(), NodeError> {
        self.change(|s, now| s.cancel(now, task_id))?
            .map_err(|c| NodeError(format!("refused: {c}")))
    }

    /// Housekeeping, only when it would change something.
    fn tick(&self) -> Result<(), NodeError> {
        let now = self.now();
        if self.store.read()?.tick_needed(now) {
            self.change(|s, now| s.tick(now))?;
        }
        Ok(())
    }

    /// The signed, sealed envelopes for a peer, built fresh (new nonce, new validity) on every call: a `hello` first, then the oldest
    /// unacknowledged messages, at most a window's worth.
    pub fn outbound(&self, peer: &str) -> Result<Vec<Sealed>, NodeError> {
        let now = self.now();
        let st = self.store.read()?;
        if !st.core.links.contains_key(peer) {
            return Err(NodeError("that peer is not pinned".into()));
        }
        let drafts = st.core.drafts(
            peer,
            now,
            DraftOpts {
                hello: true,
                ack: false,
                resend: true,
            },
        );
        seal_drafts(&PROFILE, &self.crypto, &drafts)
            .map_err(|e| NodeError(format!("a message could not be sealed or signed: {e}")))
    }

    /// Take a batch from a peer, all in one write (and none when there is nothing to take or nothing changed).
    pub fn receive_all(&self, msgs: &[Sealed]) -> Result<Round, NodeError> {
        if msgs.is_empty() {
            return Ok(Round::default());
        }
        let (cx, screen) = (self.crypto, self.screen);
        let now = self.now();
        // a round that took nothing durable (a quiet `hello` each way) costs no write
        let r = change_if(self.store, self.audit, |st| {
            let r = st.receive_round(&cx, screen, now, msgs);
            let changed = !r.deliveries.is_empty();
            (r, changed)
        })?;
        self.drain_audit()?;
        Ok(Round {
            sent: 0,
            applied: r.deliveries.len() + r.control,
            buffered: r.buffered,
            duplicates: r.duplicates,
            refused: r.refused,
        })
    }

    /// The answering side of a round: take what the peer sent, and return what this side has for it.
    pub fn serve(&self, peer: &str, inbound: &[Sealed]) -> Result<(Round, Vec<Sealed>), NodeError> {
        self.tick()?;
        let round = self.receive_all(inbound)?;
        Ok((round, self.outbound(peer)?))
    }

    /// The calling side of a round: send what is waiting, take the reply. A transport failure is returned and leaves every task where
    /// it was; the outbox keeps what was not acknowledged.
    pub fn sync(&self, peer: &str, net: &dyn Transport) -> Result<Round, NodeError> {
        self.tick()?;
        let mut total = Round::default();
        // The first contact (and the first contact after either side restarted) takes a second exchange to learn each other's
        // incarnation before anything is sent. A person should not have to know that, so while messages are still waiting and the last
        // exchange made progress, go again (at most three).
        for attempt in 0..3 {
            let out = self.outbound(peer)?;
            let sent = out.len();
            let back = net
                .exchange(peer, &out)
                .map_err(|e| NodeError(format!("{peer} could not be reached: {e}")))?;
            let r = self.receive_all(&back)?;
            total.sent += sent;
            total.applied += r.applied;
            total.buffered += r.buffered;
            total.duplicates += r.duplicates;
            total.refused.extend(r.refused);
            let waiting = self
                .store
                .read()?
                .core
                .links
                .get(peer)
                .is_some_and(|l| !l.outbox.is_empty() && l.halted.is_none());
            if !waiting || attempt == 2 || r.applied == 0 {
                break;
            }
        }
        Ok(total)
    }
}
