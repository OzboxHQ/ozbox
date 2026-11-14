//! One endpoint: its state, its keys, its screen and its audit trail, and the four things it does with a peer. A laptop and
//! `main` run the same code; only the names and the way they reach each other differ.

use super::model::{Label, Part, State as TState};
use super::state::{NewTask, State, Verdict};
use super::store::{Store, StoreError};
use super::wire::{Sealed, Sealer, Signer, Transport, Verifier};
use super::{AuditSink, Screen};

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

/// What one round with a peer did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Round {
    pub sent: usize,
    pub applied: usize,
    pub duplicates: usize,
    pub refused: Vec<String>,
}

pub struct Node<'a> {
    pub store: &'a Store,
    pub signer: &'a dyn Signer,
    pub verifier: &'a dyn Verifier,
    pub sealer: &'a dyn Sealer,
    pub screen: &'a dyn Screen,
    pub audit: &'a dyn AuditSink,
    pub clock: &'a dyn Fn() -> u64,
}

impl Node<'_> {
    fn now(&self) -> u64 {
        (self.clock)()
    }

    /// Hand pending audit events to the audit log. The events were written with the change they describe; a failure here leaves
    /// them pending, and the event's source number keeps a retry from logging one twice.
    pub fn drain_audit(&self) -> Result<(), NodeError> {
        let st = self.store.read()?;
        if st.audit.is_empty() {
            return Ok(());
        }
        let n = st.audit.len();
        for ev in st.audit {
            self.audit.record(ev).map_err(|e| {
                NodeError(format!("the audit log could not be written: {}", e.kind()))
            })?;
        }
        self.store.update(|s| {
            let k = n.min(s.audit.len());
            s.audit.drain(..k);
        })?;
        Ok(())
    }

    fn change<T>(&self, f: impl FnOnce(&mut State, u64) -> T) -> Result<T, NodeError> {
        let now = self.now();
        let out = self.store.update(|s| f(s, now))?;
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
        label: Label,
        to_state: Option<(TState, Option<String>)>,
    ) -> Result<(), NodeError> {
        let screen = self.screen;
        self.change(|s, now| s.reply(screen, now, task_id, parts, label, to_state))?
            .map_err(|c| NodeError(format!("refused: {c}")))
    }

    pub fn cancel(&self, task_id: &str) -> Result<(), NodeError> {
        self.change(|s, now| s.cancel(now, task_id))?
            .map_err(|c| NodeError(format!("refused: {c}")))
    }

    /// The signed, sealed envelopes for a peer, built fresh (new nonce, new validity) on every call.
    pub fn outbound(&self, peer: &str) -> Result<Vec<Sealed>, NodeError> {
        let now = self.now();
        let st = self.store.read()?;
        let seal_to = st
            .peers
            .get(peer)
            .map(|p| p.seal_public.clone())
            .ok_or_else(|| NodeError("that peer is not pinned".into()))?;
        let mut out = Vec::new();
        for (mut env, plain) in st.drafts(peer, now) {
            env.body = Vec::new();
            let aad = env.aad();
            env.body = self
                .sealer
                .seal(&seal_to, &aad, &plain)
                .map_err(|e| NodeError(format!("a message could not be sealed: {e}")))?;
            env.check()
                .map_err(|e| NodeError(format!("a message is not valid: {e}")))?;
            let signature = self
                .signer
                .sign(&env.canonical())
                .map_err(|e| NodeError(format!("a message could not be signed: {e}")))?;
            out.push(Sealed {
                envelope: env,
                signature,
            });
        }
        Ok(out)
    }

    /// Take messages from a peer. Each is written before the next is looked at, so what is acknowledged is what is kept.
    pub fn receive_all(&self, msgs: &[Sealed]) -> Result<Round, NodeError> {
        let mut r = Round::default();
        for m in msgs {
            let (screen, v, s) = (self.screen, self.verifier, self.sealer);
            let verdict = self.change(|st, now| st.receive(v, s, screen, now, m))?;
            match verdict {
                Verdict::Applied | Verdict::Buffered => r.applied += 1,
                Verdict::Duplicate => r.duplicates += 1,
                Verdict::Refused(c) => r.refused.push(c),
            }
        }
        Ok(r)
    }

    /// The answering side of a round: take what the peer sent, and return what this side has for it.
    pub fn serve(&self, peer: &str, inbound: &[Sealed]) -> Result<(Round, Vec<Sealed>), NodeError> {
        let _ = self.change(|s, now| s.tick(now))?;
        let round = self.receive_all(inbound)?;
        Ok((round, self.outbound(peer)?))
    }

    /// The calling side of a round: send what is waiting, take the reply. A transport failure is returned and leaves every task
    /// where it was; the outbox keeps what was not acknowledged.
    pub fn sync(&self, peer: &str, net: &dyn Transport) -> Result<Round, NodeError> {
        let _ = self.change(|s, now| s.tick(now))?;
        let out = self.outbound(peer)?;
        let sent = out.len();
        let back = net
            .exchange(peer, &out)
            .map_err(|e| NodeError(format!("{peer} could not be reached: {e}")))?;
        let mut r = self.receive_all(&back)?;
        r.sent = sent;
        Ok(r)
    }
}
