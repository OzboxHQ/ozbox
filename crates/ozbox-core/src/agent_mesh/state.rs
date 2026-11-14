//! The durable state of one endpoint and the pure logic that changes it (ADR 0044 sections 2.3, 2.4, 3 and 4).
//!
//! Every function here takes the state and a clock and does no I/O: the [`super::store::Store`] persists the result **before**
//! anything is acknowledged, and [`super::node::Node`] does the signing, sealing and moving. That is what keeps a send from
//! holding the store's lock and what makes a crash safe (the outbox is part of the state, written in the same write as the
//! task it carries).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::model::{
    code, may_move, new_id, Act, Artifact, Body, Label, Message, Part, Side, State as TState, Task,
    TaskKind, MAX_INLINE, MAX_TITLE,
};
use super::wire::{Envelope, Kind, Sealed, Sealer, Verifier, ENVELOPE_VERSION, SKEW_MS};
use super::{crypto, Screen};
use crate::approval_subject::{to_hex, Encoder};
use crate::audit::NewEvent;

pub const STATE_VERSION: u32 = 1;
/// How many sequence numbers ahead of the next expected one are buffered. Past it the receiver asks for a resync.
pub const WINDOW: u64 = 64;
/// Starting values, tuned later (ADR 0044 section 2.4).
pub const MAX_OUTBOX: usize = 200;
pub const MAX_OPEN_TASKS: usize = 50;
pub const MAX_TASKS: usize = 2000;
pub const NEW_TASKS_PER_MIN: usize = 20;
pub const MESSAGES_PER_MIN: usize = 120;
pub const SEEN_TASK_KEEP_MS: u64 = 7 * 24 * 3600 * 1000;
pub const DEFAULT_DEADLINE_MS: u64 = 24 * 3600 * 1000;
const MAX_REASON: usize = 120;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outgoing {
    pub seq: u64,
    pub kind: Kind,
    pub task_id: String,
    pub body: Body,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Held {
    pub task_id: String,
    pub body: Body,
    pub hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peer {
    pub name: String,
    pub sign_public: String,
    pub seal_public: String,
    /// The epoch pinned for the peer. A peer that restores changes epoch, and the owner pins the new one.
    pub epoch: u64,
    /// The command that reaches the peer's `exchange` (an argv, never a shell string). Empty on the answering side.
    #[serde(default)]
    pub via: Vec<String>,
    pub out_seq: u64,
    pub outbox: Vec<Outgoing>,
    pub peer_incarnation: u64,
    pub last_hello_ms: u64,
    pub next_in: u64,
    pub held_in: BTreeMap<u64, Held>,
    pub recent: Vec<(u64, bool)>,
    pub resync_wanted: bool,
    pub dups: u64,
    pub last_seen_ms: u64,
}

impl Peer {
    pub fn new(
        name: &str,
        sign_public: &str,
        seal_public: &str,
        epoch: u64,
        via: Vec<String>,
    ) -> Peer {
        Peer {
            name: name.to_string(),
            sign_public: sign_public.to_string(),
            seal_public: seal_public.to_string(),
            epoch,
            via,
            out_seq: 0,
            outbox: Vec::new(),
            peer_incarnation: 0,
            last_hello_ms: 0,
            next_in: 1,
            held_in: BTreeMap::new(),
            recent: Vec::new(),
            resync_wanted: false,
            dups: 0,
            last_seen_ms: 0,
        }
    }

    pub fn seal_fingerprint(&self) -> String {
        crypto::fingerprint(&self.seal_public)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Seen {
    pub hash: String,
    pub ts_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub version: u32,
    pub me: String,
    pub store_id: String,
    pub epoch: u64,
    pub incarnation: u64,
    pub sign_public: String,
    pub seal_public: String,
    pub peers: BTreeMap<String, Peer>,
    pub tasks: BTreeMap<String, Task>,
    pub seen_tasks: BTreeMap<String, Seen>,
    pub nonces: BTreeMap<String, u64>,
    /// Audit events not yet handed to the audit log. Written in the same write as the change they describe.
    pub audit: Vec<NewEvent>,
    pub audit_n: u64,
}

/// What a receive did, for the caller (a count and a log line, never text).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Applied,
    Buffered,
    Duplicate,
    Refused(String),
}

/// What a person asks for when they start a task.
pub struct NewTask {
    pub to: String,
    pub kind: TaskKind,
    pub title: String,
    pub parts: Vec<Part>,
    pub label: Label,
    pub act: Option<Act>,
    pub parent: Option<String>,
    pub deadline_ms: Option<u64>,
}

fn hash_body(b: &Body) -> String {
    let mut e = Encoder::new("ozbox-mesh-body");
    e.text(&serde_json::to_string(b).unwrap_or_default());
    to_hex(&e.digest())
}

impl State {
    pub fn new(me: &str, sign_public: &str, seal_public: &str, now: u64) -> State {
        State {
            version: STATE_VERSION,
            me: me.to_string(),
            store_id: new_id(now),
            epoch: 1,
            incarnation: now.max(1),
            sign_public: sign_public.to_string(),
            seal_public: seal_public.to_string(),
            peers: BTreeMap::new(),
            tasks: BTreeMap::new(),
            seen_tasks: BTreeMap::new(),
            nonces: BTreeMap::new(),
            audit: Vec::new(),
            audit_n: 0,
        }
    }

    pub fn seal_fingerprint(&self) -> String {
        crypto::fingerprint(&self.seal_public)
    }

    pub fn note(&mut self, now: u64, action: &str, subject: Option<&str>, detail: String) {
        self.audit_n += 1;
        let ev = NewEvent {
            ts_ms: now,
            actor: format!("mesh:{}", self.me),
            action: action.to_string(),
            subject: subject.map(str::to_string),
            detail: detail.chars().take(150).collect(),
            src: Some((self.store_id.clone(), self.audit_n)),
        };
        self.audit.push(ev);
    }

    /// After a restore from a backup: a new epoch and a new incarnation, so envelopes captured before it no longer verify, and
    /// the peer is told to pin the new epoch. Nothing sent before is replayable, and nothing in flight survives.
    pub fn restored(&mut self, now: u64) {
        self.epoch += 1;
        self.incarnation = now.max(self.incarnation + 1);
        self.nonces.clear();
        for p in self.peers.values_mut() {
            p.out_seq = 0;
            p.outbox.clear();
            p.peer_incarnation = 0;
            p.last_hello_ms = 0;
            p.next_in = 1;
            p.held_in.clear();
        }
        self.note(now, "mesh.restored", None, format!("epoch={}", self.epoch));
    }

    // ---- sending ------------------------------------------------------------------------------------------------

    fn enqueue(
        &mut self,
        peer: &str,
        kind: Kind,
        task_id: &str,
        body: Body,
    ) -> Result<u64, &'static str> {
        let p = self.peers.get_mut(peer).ok_or("unknown-peer")?;
        if p.outbox.len() >= MAX_OUTBOX {
            return Err(code::RATE);
        }
        p.out_seq += 1;
        let seq = p.out_seq;
        p.outbox.push(Outgoing {
            seq,
            kind,
            task_id: task_id.to_string(),
            body,
        });
        Ok(seq)
    }

    fn check_parts(screen: &dyn Screen, title: &str, parts: &[Part]) -> Result<(), &'static str> {
        if title.len() > MAX_TITLE || parts.iter().map(Part::size).sum::<usize>() > MAX_INLINE {
            return Err(code::TOO_BIG);
        }
        let mut all: Vec<String> = vec![title.to_string()];
        all.extend(parts.iter().flat_map(Part::strings));
        if all.iter().any(|s| screen.find(s).is_some()) {
            return Err(code::KEY_SHAPED);
        }
        Ok(())
    }

    /// Start a task. It is written `held` with its envelope in the outbox, in the same write. Refusals are named.
    pub fn submit(
        &mut self,
        screen: &dyn Screen,
        now: u64,
        n: NewTask,
    ) -> Result<String, &'static str> {
        if !self.peers.contains_key(&n.to) {
            return Err("unknown-peer");
        }
        if n.title.trim().is_empty() {
            return Err("title-missing");
        }
        Self::check_parts(screen, &n.title, &n.parts)?;
        match (&n.kind, &n.act) {
            (TaskKind::LaptopAct, Some(a)) => {
                a.valid()?;
                // refused in code at the sender too: no flag, no setting, no approval text turns this off
                if a.is_production() {
                    return Err(code::PRODUCTION);
                }
            }
            (TaskKind::LaptopAct, None) => return Err("act-missing"),
            (_, Some(_)) => return Err("act-not-allowed"),
            _ => {}
        }
        if self.tasks.len() >= MAX_TASKS {
            return Err(code::JOURNAL_FULL);
        }
        let id = new_id(now);
        let deadline = n.deadline_ms.unwrap_or(now + DEFAULT_DEADLINE_MS);
        let message = Message {
            id: format!("{id}-0"),
            from: self.me.clone(),
            ts_ms: now,
            label: n.label,
            parts: n.parts,
        };
        let body = Body::Task {
            kind: n.kind,
            title: n.title.clone(),
            context_id: None,
            parent: n.parent.clone(),
            deadline_ms: deadline,
            act: n.act.clone(),
            approval_ref: None,
            message: message.clone(),
        };
        let seq = self.enqueue(&n.to, Kind::Task, &id, body)?;
        self.tasks.insert(
            id.clone(),
            Task {
                id: id.clone(),
                from: self.me.clone(),
                to: n.to.clone(),
                kind: n.kind,
                title: n.title,
                state: TState::Held,
                reason: None,
                context_id: None,
                parent: n.parent,
                deadline_ms: deadline,
                created_ms: now,
                updated_ms: now,
                messages: vec![message],
                artifacts: Vec::new(),
                act: n.act,
                approval_ref: None,
                sent_seq: Some(seq),
                unread: false,
            },
        );
        self.note(
            now,
            "mesh.task.sent",
            Some(&id),
            format!("kind={} to={}", n.kind.name(), n.to),
        );
        Ok(id)
    }

    fn side_of(&self, t: &Task) -> Side {
        if t.from == self.me {
            Side::Sender
        } else {
            Side::Receiver
        }
    }

    fn other(&self, t: &Task) -> String {
        if t.from == self.me {
            t.to.clone()
        } else {
            t.from.clone()
        }
    }

    /// Say something on a task, and optionally move the state (the receiver's authority only).
    pub fn reply(
        &mut self,
        screen: &dyn Screen,
        now: u64,
        task_id: &str,
        parts: Vec<Part>,
        label: Label,
        to_state: Option<(TState, Option<String>)>,
    ) -> Result<(), &'static str> {
        let t = self.tasks.get(task_id).ok_or("unknown-task")?.clone();
        let peer = self.other(&t);
        if t.state.terminal() {
            return Err("task-finished");
        }
        if !parts.is_empty() {
            Self::check_parts(screen, "", &parts)?;
        }
        if let Some((s, r)) = &to_state {
            if self.side_of(&t) != Side::Receiver || !may_move(t.state, *s, Side::Receiver) {
                return Err("state-not-yours-to-move");
            }
            if let Some(r) = r {
                Self::check_parts(screen, r, &[])?;
                if r.len() > MAX_REASON {
                    return Err(code::TOO_BIG);
                }
            }
        }
        if !parts.is_empty() {
            let message = Message {
                id: new_id(now),
                from: self.me.clone(),
                ts_ms: now,
                label,
                parts,
            };
            self.enqueue(
                &peer,
                Kind::Message,
                task_id,
                Body::Message {
                    message: message.clone(),
                },
            )?;
            if let Some(tt) = self.tasks.get_mut(task_id) {
                tt.messages.push(message);
                tt.updated_ms = now;
            }
        }
        if let Some((s, r)) = to_state {
            self.enqueue(
                &peer,
                Kind::Status,
                task_id,
                Body::Status {
                    state: s,
                    reason: r.clone(),
                },
            )?;
            if let Some(tt) = self.tasks.get_mut(task_id) {
                tt.state = s;
                tt.reason = r;
                tt.updated_ms = now;
                tt.unread = false;
            }
            self.note(
                now,
                "mesh.task.state",
                Some(task_id),
                format!("state={}", s.name()),
            );
        } else if let Some(tt) = self.tasks.get_mut(task_id) {
            tt.unread = false;
        }
        Ok(())
    }

    /// Ask the other side to stop. A cancel is a request: the receiver decides. A task still `held` is canceled here at once.
    pub fn cancel(&mut self, now: u64, task_id: &str) -> Result<(), &'static str> {
        let t = self.tasks.get(task_id).ok_or("unknown-task")?.clone();
        if t.state.terminal() {
            return Err("task-finished");
        }
        let peer = self.other(&t);
        if self.side_of(&t) == Side::Receiver {
            // the receiver ends its own copy and says so
            self.enqueue(
                &peer,
                Kind::Status,
                task_id,
                Body::Status {
                    state: TState::Canceled,
                    reason: None,
                },
            )?;
            if let Some(tt) = self.tasks.get_mut(task_id) {
                tt.state = TState::Canceled;
                tt.updated_ms = now;
            }
        } else {
            self.enqueue(&peer, Kind::Cancel, task_id, Body::Cancel)?;
            if t.state == TState::Held {
                if let Some(tt) = self.tasks.get_mut(task_id) {
                    tt.state = TState::Canceled;
                    tt.updated_ms = now;
                }
            }
        }
        self.note(now, "mesh.task.cancel", Some(task_id), String::new());
        Ok(())
    }

    /// Mark a task read.
    pub fn mark_read(&mut self, task_id: &str) {
        if let Some(t) = self.tasks.get_mut(task_id) {
            t.unread = false;
        }
    }

    /// Housekeeping: expire what is past its deadline (each side only what it owns) and forget old nonces and task ids.
    pub fn tick(&mut self, now: u64) {
        self.nonces.retain(|_, v| *v >= now);
        self.seen_tasks
            .retain(|_, s| s.ts_ms + SEEN_TASK_KEEP_MS >= now);
        let due: Vec<(String, Side)> = self
            .tasks
            .values()
            .filter(|t| !t.state.terminal() && t.deadline_ms <= now)
            .map(|t| (t.id.clone(), self.side_of(t)))
            .filter(|(id, side)| {
                let st = self.tasks.get(id).map(|t| t.state);
                matches!(
                    (side, st),
                    (Side::Sender, Some(TState::Held)) | (Side::Receiver, Some(_))
                )
            })
            .collect();
        for (id, side) in due {
            let peer = self
                .tasks
                .get(&id)
                .map(|t| self.other(t))
                .unwrap_or_default();
            if let Some(t) = self.tasks.get_mut(&id) {
                t.state = TState::Failed;
                t.reason = Some(code::EXPIRED.to_string());
                t.updated_ms = now;
            }
            if side == Side::Receiver {
                let _ = self.enqueue(
                    &peer,
                    Kind::Status,
                    &id,
                    Body::Status {
                        state: TState::Failed,
                        reason: Some(code::EXPIRED.into()),
                    },
                );
            }
            self.note(now, "mesh.task.expired", Some(&id), String::new());
        }
    }

    // ---- what to send -------------------------------------------------------------------------------------------

    /// The envelopes to send to a peer now, unsigned, with plain bodies: a Hello first (it carries the acknowledgement and the
    /// lowest sequence number still available), then a Resync if one is wanted, then the oldest unacknowledged messages, at
    /// most a window's worth, oldest first. Read-only: the node signs them fresh on every attempt.
    pub fn drafts(&self, peer: &str, now: u64) -> Vec<(Envelope, Vec<u8>)> {
        let Some(p) = self.peers.get(peer) else {
            return Vec::new();
        };
        let ack = p.next_in.saturating_sub(1);
        let mk = |kind: Kind, seq: u64, task_id: &str, id: String, body: &Body| {
            let plain = serde_json::to_vec(body).unwrap_or_default();
            let mut nonce = [0u8; 16];
            let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut nonce);
            (
                Envelope {
                    version: ENVELOPE_VERSION,
                    kind,
                    from: self.me.clone(),
                    to: p.name.clone(),
                    receiver_fp: p.seal_fingerprint(),
                    sender_epoch: self.epoch,
                    receiver_epoch: p.epoch,
                    incarnation: self.incarnation,
                    seq,
                    ack_seq: ack,
                    id,
                    task_id: task_id.to_string(),
                    ts_ms: now,
                    valid_until_ms: now + 5 * 60 * 1000,
                    nonce: nonce.to_vec(),
                    body: Vec::new(),
                },
                plain,
            )
        };
        let floor = p.outbox.first().map_or(p.out_seq + 1, |o| o.seq);
        let mut out = vec![mk(
            Kind::Hello,
            0,
            "",
            format!("h-{}", new_id(now)),
            &Body::Hello { out_floor: floor },
        )];
        if p.resync_wanted {
            out.push(mk(
                Kind::Resync,
                0,
                "",
                format!("r-{}", new_id(now)),
                &Body::Resync {
                    have: p.next_in.saturating_sub(1),
                },
            ));
        }
        for o in p.outbox.iter().take(WINDOW as usize) {
            out.push(mk(
                o.kind,
                o.seq,
                &o.task_id,
                format!("{}-{}-{}", self.me, self.incarnation, o.seq),
                &o.body,
            ));
        }
        out
    }

    // ---- receiving ----------------------------------------------------------------------------------------------

    fn refuse(&mut self, now: u64, from: &str, e: &Envelope, why: &str) -> Verdict {
        self.note(
            now,
            "mesh.refused",
            if e.task_id.is_empty() {
                None
            } else {
                Some(&e.task_id)
            },
            format!("from={from} kind={} code={why}", e.kind.name()),
        );
        Verdict::Refused(why.to_string())
    }

    /// Check an envelope and, when every check passes, apply it. The order is fixed and nothing is acted on until all pass:
    /// shape and version, addressing, the signature (against the pinned key), epochs, validity (this clock), the seal, the nonce,
    /// the incarnation, the acknowledgement, then the sequence window and the effect.
    pub fn receive(
        &mut self,
        verifier: &dyn Verifier,
        sealer: &dyn Sealer,
        screen: &dyn Screen,
        now: u64,
        msg: &Sealed,
    ) -> Verdict {
        let e = &msg.envelope;
        if let Err(x) = e.check() {
            return self.refuse(now, "?", e, &x.to_string());
        }
        if e.to != self.me {
            return self.refuse(now, "?", e, "not-for-me");
        }
        let from = e.from.clone();
        let Some(peer) = self.peers.get(&from) else {
            return self.refuse(now, &from, e, "unknown-sender");
        };
        if e.receiver_fp != self.seal_fingerprint() {
            return self.refuse(now, &from, e, "wrong-receiver");
        }
        if !verifier.verify(&peer.sign_public, &e.canonical(), &msg.signature) {
            return self.refuse(now, &from, e, "bad-signature");
        }
        if e.receiver_epoch != self.epoch || e.sender_epoch != peer.epoch {
            return self.refuse(now, &from, e, "epoch");
        }
        if e.valid_until_ms < now {
            return self.refuse(now, &from, e, "envelope-expired");
        }
        if e.ts_ms > now + SKEW_MS {
            return self.refuse(now, &from, e, "from-the-future");
        }
        let nonce_hex = to_hex(&e.nonce);
        if self.nonces.contains_key(&nonce_hex) {
            return Verdict::Duplicate;
        }
        let Ok(plain) = sealer.open(&e.aad(), &e.body) else {
            return self.refuse(now, &from, e, "unopenable");
        };
        let Ok(body) = serde_json::from_slice::<Body>(&plain) else {
            return self.refuse(now, &from, e, "malformed");
        };
        let kind_ok = matches!(
            (&body, e.kind),
            (Body::Hello { .. }, Kind::Hello)
                | (Body::Task { .. }, Kind::Task)
                | (Body::Message { .. }, Kind::Message)
                | (Body::Status { .. }, Kind::Status)
                | (Body::Artifact { .. }, Kind::Artifact)
                | (Body::Cancel, Kind::Cancel)
                | (Body::Resync { .. }, Kind::Resync)
        );
        if !kind_ok {
            return self.refuse(now, &from, e, "kind-mismatch");
        }
        // incarnation: a lower one is a replay of an older life; a higher one is accepted only through a Hello
        let cur = self.peers.get(&from).map_or(0, |p| p.peer_incarnation);
        if e.incarnation < cur {
            return self.refuse(now, &from, e, "stale-incarnation");
        }
        if e.incarnation > cur && e.kind != Kind::Hello {
            return self.refuse(now, &from, e, "hello-needed");
        }
        if let Body::Hello { .. } = &body {
            let last = self.peers.get(&from).map_or(0, |p| p.last_hello_ms);
            if e.ts_ms < last {
                return self.refuse(now, &from, e, "stale-hello");
            }
        }
        let out_seq = self.peers.get(&from).map_or(0, |p| p.out_seq);
        if e.ack_seq > out_seq {
            return self.refuse(now, &from, e, "ack-ahead");
        }
        // every check passed
        self.nonces.insert(nonce_hex, e.valid_until_ms);
        self.apply_ack(&from, e.ack_seq, now);
        if let Some(p) = self.peers.get_mut(&from) {
            p.last_seen_ms = now;
            if e.incarnation > p.peer_incarnation {
                p.peer_incarnation = e.incarnation;
                p.held_in.clear();
                p.next_in = 1;
            }
        }
        match body {
            Body::Hello { out_floor } => {
                if let Some(p) = self.peers.get_mut(&from) {
                    p.last_hello_ms = e.ts_ms;
                    // a sender that has nothing below this number: what we have not applied by then is gone (state loss)
                    if out_floor > p.next_in
                        && e.incarnation == p.peer_incarnation
                        && p.held_in.is_empty()
                        && p.next_in == 1
                    {
                        p.next_in = out_floor;
                    }
                }
                Verdict::Applied
            }
            Body::Resync { have } => {
                self.note(now, "mesh.resync", None, format!("from={from} have={have}"));
                Verdict::Applied
            }
            seqd => self.sequenced(screen, now, &from, e, seqd),
        }
    }

    fn apply_ack(&mut self, from: &str, ack: u64, _now: u64) {
        let mut delivered: Vec<String> = Vec::new();
        if let Some(p) = self.peers.get_mut(from) {
            p.outbox.retain(|o| {
                let gone = o.seq <= ack;
                if gone && o.kind == Kind::Task {
                    delivered.push(o.task_id.clone());
                }
                !gone
            });
        }
        for id in delivered {
            if let Some(t) = self.tasks.get_mut(&id) {
                if t.state == TState::Held && t.from == self.me {
                    t.state = TState::Submitted;
                    t.sent_seq = None;
                }
            }
        }
    }

    fn sequenced(
        &mut self,
        screen: &dyn Screen,
        now: u64,
        from: &str,
        e: &Envelope,
        body: Body,
    ) -> Verdict {
        let hash = hash_body(&body);
        let Some(p) = self.peers.get_mut(from) else {
            return Verdict::Refused("unknown-sender".into());
        };
        if e.seq < p.next_in {
            p.dups += 1;
            return Verdict::Duplicate;
        }
        if e.seq >= p.next_in + WINDOW {
            p.resync_wanted = true;
            return self.refuse(now, from, e, "gap-beyond-window");
        }
        if let Some(h) = p.held_in.get(&e.seq) {
            if h.hash == hash {
                p.dups += 1;
                return Verdict::Duplicate;
            }
            return self.refuse(now, from, e, "seq-conflict");
        }
        p.held_in.insert(
            e.seq,
            Held {
                task_id: e.task_id.clone(),
                body,
                hash,
            },
        );
        p.resync_wanted = false;
        let mut applied = 0;
        loop {
            let next = self.peers.get(from).map_or(0, |p| p.next_in);
            let Some(h) = self
                .peers
                .get_mut(from)
                .and_then(|p| p.held_in.remove(&next))
            else {
                break;
            };
            if let Some(p) = self.peers.get_mut(from) {
                p.next_in += 1;
            }
            self.apply(screen, now, from, &h);
            applied += 1;
        }
        if applied > 0 {
            Verdict::Applied
        } else {
            Verdict::Buffered
        }
    }

    fn rate_ok(&mut self, from: &str, now: u64, is_task: bool) -> bool {
        let Some(p) = self.peers.get_mut(from) else {
            return false;
        };
        p.recent.retain(|(t, _)| *t + 60_000 > now);
        let (tasks, all) = (p.recent.iter().filter(|(_, k)| *k).count(), p.recent.len());
        if (is_task && tasks >= NEW_TASKS_PER_MIN) || all >= MESSAGES_PER_MIN {
            return false;
        }
        p.recent.push((now, is_task));
        true
    }

    fn tell_status(&mut self, peer: &str, task_id: &str, state: TState, reason: Option<String>) {
        let _ = self.enqueue(peer, Kind::Status, task_id, Body::Status { state, reason });
    }

    fn apply(&mut self, screen: &dyn Screen, now: u64, from: &str, h: &Held) {
        match &h.body {
            Body::Task {
                kind,
                title,
                context_id,
                parent,
                deadline_ms,
                act,
                approval_ref,
                message,
            } => self.apply_task(
                screen,
                now,
                from,
                &h.task_id,
                &h.hash,
                (
                    *kind,
                    title,
                    context_id,
                    parent,
                    *deadline_ms,
                    act,
                    approval_ref,
                    message,
                ),
            ),
            Body::Message { message } => {
                let ok = self.tasks.get(&h.task_id).is_some_and(|t| {
                    !t.state.terminal()
                        && (t.from == from || t.to == from)
                        && !t.messages.iter().any(|m| m.id == message.id)
                });
                if !ok {
                    self.note(
                        now,
                        "mesh.message.dropped",
                        Some(&h.task_id),
                        format!("from={from}"),
                    );
                    return;
                }
                let refusal = if !self.rate_ok(from, now, false) {
                    Some(code::RATE)
                } else if message.from != from {
                    Some("sender-mismatch")
                } else {
                    Self::check_parts(screen, "", &message.parts).err()
                };
                if let Some(c) = refusal {
                    self.note(
                        now,
                        "mesh.message.refused",
                        Some(&h.task_id),
                        format!("from={from} code={c}"),
                    );
                    let st = self
                        .tasks
                        .get(&h.task_id)
                        .map_or(TState::Working, |t| t.state);
                    self.tell_status(from, &h.task_id, st, Some(c.to_string()));
                    return;
                }
                if let Some(t) = self.tasks.get_mut(&h.task_id) {
                    t.messages.push(message.clone());
                    t.updated_ms = now;
                    t.unread = true;
                }
            }
            Body::Status { state, reason } => {
                self.apply_status(screen, now, from, &h.task_id, *state, reason.clone())
            }
            Body::Artifact { artifact } => {
                let ok = self
                    .tasks
                    .get(&h.task_id)
                    .is_some_and(|t| t.from == self.me && t.to == from);
                let bad = Self::check_parts(screen, &artifact.name, &artifact.parts).is_err()
                    || *artifact
                        != Artifact::new(&artifact.id, &artifact.name, artifact.parts.clone());
                if !ok || bad {
                    self.note(
                        now,
                        "mesh.artifact.refused",
                        Some(&h.task_id),
                        format!("from={from}"),
                    );
                    return;
                }
                if let Some(t) = self.tasks.get_mut(&h.task_id) {
                    if !t.artifacts.iter().any(|a| a.id == artifact.id) {
                        t.artifacts.push(artifact.clone());
                    }
                    t.updated_ms = now;
                    t.unread = true;
                }
            }
            Body::Cancel => {
                let Some(t) = self.tasks.get(&h.task_id).cloned() else {
                    return;
                };
                if t.to != self.me || t.from != from {
                    return;
                }
                if t.state.terminal() {
                    self.tell_status(from, &h.task_id, t.state, Some("too-late".into()));
                } else {
                    if let Some(tt) = self.tasks.get_mut(&h.task_id) {
                        tt.state = TState::Canceled;
                        tt.updated_ms = now;
                        tt.unread = true;
                    }
                    self.tell_status(from, &h.task_id, TState::Canceled, None);
                    self.note(
                        now,
                        "mesh.task.state",
                        Some(&h.task_id),
                        "state=canceled".into(),
                    );
                }
            }
            Body::Hello { .. } | Body::Resync { .. } => {}
        }
    }

    #[allow(clippy::type_complexity)]
    fn apply_task(
        &mut self,
        screen: &dyn Screen,
        now: u64,
        from: &str,
        task_id: &str,
        hash: &str,
        t: (
            TaskKind,
            &String,
            &Option<String>,
            &Option<String>,
            u64,
            &Option<Act>,
            &Option<String>,
            &Message,
        ),
    ) {
        let (kind, title, context_id, parent, deadline, act, approval_ref, message) = t;
        let key = format!("{from}/{task_id}");
        if let Some(seen) = self.seen_tasks.get(&key) {
            if seen.hash == hash {
                return;
            }
            // the same id with other content: refused, and an alert (no box may squat another's task id)
            self.note(
                now,
                "mesh.task.conflict",
                Some(task_id),
                format!("from={from}"),
            );
            return;
        }
        let open = self
            .tasks
            .values()
            .filter(|x| x.from == from && !x.state.terminal())
            .count();
        let reject: Option<&'static str> = if self.tasks.len() >= MAX_TASKS {
            Some(code::JOURNAL_FULL)
        } else if open >= MAX_OPEN_TASKS || !self.rate_ok(from, now, true) {
            Some(code::RATE)
        } else if message.from != from {
            Some("sender-mismatch")
        } else if let Err(c) = Self::check_parts(screen, title, &message.parts) {
            Some(c)
        } else if deadline <= now {
            Some(code::EXPIRED)
        } else {
            match (kind, act) {
                (TaskKind::LaptopAct, Some(a)) => match a.valid() {
                    Err(c) => Some(c),
                    Ok(()) if a.is_production() => Some(code::PRODUCTION),
                    // approval_ref and any "approved" text grant nothing: there is no approval path to the laptop yet
                    Ok(()) => Some(code::NO_APPROVAL_PATH),
                },
                (TaskKind::LaptopAct, None) => Some("act-missing"),
                (_, Some(_)) => Some("act-not-allowed"),
                _ => None,
            }
        };
        self.seen_tasks.insert(
            key,
            Seen {
                hash: hash.to_string(),
                ts_ms: now,
            },
        );
        if reject == Some(code::JOURNAL_FULL) {
            self.note(
                now,
                "mesh.task.refused",
                Some(task_id),
                format!("from={from} code={}", code::JOURNAL_FULL),
            );
            self.tell_status(
                from,
                task_id,
                TState::Rejected,
                Some(code::JOURNAL_FULL.into()),
            );
            return;
        }
        let refused_for_content =
            matches!(reject, Some(c) if c == code::KEY_SHAPED || c == code::TOO_BIG);
        let (state, reason) = match reject {
            Some(c) => (TState::Rejected, Some(c.to_string())),
            None => (TState::Submitted, None),
        };
        self.tasks.insert(
            task_id.to_string(),
            Task {
                id: task_id.to_string(),
                from: from.to_string(),
                to: self.me.clone(),
                kind,
                // refused content is never stored
                title: if refused_for_content {
                    "[refused]".into()
                } else {
                    title.clone()
                },
                state,
                reason: reason.clone(),
                context_id: context_id.clone(),
                parent: parent.clone(),
                deadline_ms: deadline,
                created_ms: now,
                updated_ms: now,
                messages: if reject.is_some() {
                    Vec::new()
                } else {
                    vec![message.clone()]
                },
                artifacts: Vec::new(),
                act: if reject.is_some() { None } else { act.clone() },
                approval_ref: None,
                sent_seq: None,
                unread: true,
            },
        );
        let _ = approval_ref;
        match &reason {
            Some(c) => {
                self.note(
                    now,
                    "mesh.task.refused",
                    Some(task_id),
                    format!("from={from} kind={} code={c}", kind.name()),
                );
                self.tell_status(from, task_id, TState::Rejected, reason);
            }
            None => self.note(
                now,
                "mesh.task.received",
                Some(task_id),
                format!("from={from} kind={}", kind.name()),
            ),
        }
    }

    fn apply_status(
        &mut self,
        screen: &dyn Screen,
        now: u64,
        from: &str,
        task_id: &str,
        state: TState,
        reason: Option<String>,
    ) {
        let Some(t) = self.tasks.get(task_id).cloned() else {
            return;
        };
        // only the receiver of a task reports its state
        if t.from != self.me || t.to != from {
            self.note(
                now,
                "mesh.status.refused",
                Some(task_id),
                format!("from={from}"),
            );
            return;
        }
        let reason = reason
            .filter(|r| r.len() <= MAX_REASON && screen.find(r).is_none())
            .map(|r| super::printable(&r));
        let mut cur = t.state;
        if cur == TState::Held {
            cur = TState::Submitted;
        }
        if state == cur {
            if let Some(tt) = self.tasks.get_mut(task_id) {
                tt.state = cur;
                tt.reason = reason;
                tt.unread = true;
            }
            return;
        }
        if !may_move(cur, state, Side::Receiver) {
            self.note(
                now,
                "mesh.status.refused",
                Some(task_id),
                format!("from={from} to={}", state.name()),
            );
            return;
        }
        if let Some(tt) = self.tasks.get_mut(task_id) {
            tt.state = state;
            tt.reason = reason;
            tt.sent_seq = None;
            tt.updated_ms = now;
            tt.unread = true;
        }
        self.note(
            now,
            "mesh.task.state",
            Some(task_id),
            format!("state={}", state.name()),
        );
    }

    // ---- why ----------------------------------------------------------------------------------------------------

    /// Why a task is where it is, in a few plain sentences that name the next actor.
    pub fn why(&self, task_id: &str, now: u64) -> Vec<String> {
        let Some(t) = self.tasks.get(task_id) else {
            return vec!["There is no such task.".into()];
        };
        let me_sender = t.from == self.me;
        let peer = if me_sender { &t.to } else { &t.from };
        let mut out = vec![format!(
            "Task {} is {}. It was {} {}.",
            t.id,
            t.state.name(),
            if me_sender {
                "sent to"
            } else {
                "received from"
            },
            peer
        )];
        if let Some(r) = &t.reason {
            out.push(format!("Reason: {r}."));
        }
        let unsent = self
            .peers
            .get(peer)
            .map_or(0, |p| p.outbox.iter().filter(|o| o.task_id == t.id).count());
        match t.state {
            TState::Held => out.push(format!(
                "It has not been acknowledged by {peer} yet ({unsent} message(s) waiting to be delivered). Next: run `ozbox tasks sync` while {peer} is reachable."
            )),
            TState::Submitted => out.push(if me_sender {
                format!("{peer} has it and has not started. Next actor: {peer}.")
            } else {
                "It is waiting for you: answer with `ozbox tasks reply`.".into()
            }),
            TState::Working | TState::InputRequired => out.push(if t.state == TState::InputRequired {
                "It is waiting for an answer.".into()
            } else {
                format!("{} is working on it.", if me_sender { peer } else { "You are" })
            }),
            TState::ApprovalRequired => out.push("It waits for an approval decided by a passkey; no approval path to this endpoint exists in this release.".into()),
            TState::Rejected => out.push(match t.reason.as_deref() {
                Some(code::NO_APPROVAL_PATH) => "Acts that need an approval are refused until the passkey approval path exists; no text can stand in for it.".into(),
                Some(code::PRODUCTION) => "A Production act is never run from a task in this release.".into(),
                Some(code::KEY_SHAPED) => "The text looked like a key or a token, and a task never carries one.".into(),
                _ => "The receiver's rules refused it.".into(),
            }),
            _ => {}
        }
        if !t.state.terminal() && t.deadline_ms > now {
            out.push(format!(
                "It expires in about {} minute(s).",
                (t.deadline_ms - now) / 60_000
            ));
        }
        out
    }
}
