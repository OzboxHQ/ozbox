//! The task state of one endpoint and the logic that applies what the channel delivers (ADR 0044 sections 2.3, 2.4, 3 and 4).
//!
//! Every function here takes the state and a clock and does no I/O: the channel's store persists the result **before** anything is
//! acknowledged, and [`super::node::Node`] does the signing, sealing and moving. The sessions, the order, the replay set and the
//! outbox are the channel's [`Core`]; this file holds the tasks, the tombstones, the per-peer rate window and the transport commands.
//!
//! Tasks are stored under `<sender>/<id>` ([`super::task_key`]), so an id chosen by a peer can never replace a task this end sent or
//! another peer's. A finished task is kept for [`RETAIN_MS`] and then reduced to a tombstone of its key and hash, so a replay or a
//! reused id is still recognised while the cap counts only what is open.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::model::{
    code, may_move, new_id, Act, Artifact, Body, Label, Message, Part, Side, State as TState, Task,
    TaskKind, MAX_INLINE, MAX_TITLE,
};
use super::{split_key, task_key, Screen, PROFILE};
use crate::approval_subject::{to_hex, Encoder};
use crate::channel::audit::HasCore;
use crate::channel::flow::{receive_round, RoundReport};
use crate::channel::session::{Core, Delivery, Link};
use crate::channel::wire::{fingerprint, normalize_hex, unhex, Crypto};

pub const STATE_VERSION: u32 = 2;
/// Starting values, tuned later (ADR 0044 section 2.4).
pub const MAX_OPEN_TASKS: usize = 50;
/// The most tasks held at once (open and recently finished). Finished ones leave after [`RETAIN_MS`], so this is a cap on what is
/// happening, not on what ever happened.
pub const MAX_TASKS: usize = 2000;
pub const MAX_MESSAGES_PER_TASK: usize = 200;
pub const MAX_ARTIFACTS_PER_TASK: usize = 50;
/// The most inline text and artifact bytes the whole state holds.
pub const MAX_STATE_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_TOMBS: usize = 20_000;
pub const NEW_TASKS_PER_MIN: usize = 20;
pub const MESSAGES_PER_MIN: usize = 120;
/// A finished task stays whole this long, then becomes a tombstone.
pub const RETAIN_MS: u64 = 30 * 24 * 3600 * 1000;
pub const DEFAULT_DEADLINE_MS: u64 = 24 * 3600 * 1000;
pub const MAX_REASON: usize = 120;
/// The most deliveries of tasks one cancel-requested reason keeps.
const MAX_ID: usize = 64;

/// What is left of a finished task: its key and the hash of the body that created it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tomb {
    pub hash: String,
    pub ts_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub version: u32,
    pub core: Core,
    /// The command that reaches a peer's `exchange` (an argv, never a shell string), per peer. Empty on the answering side.
    #[serde(default)]
    pub vias: BTreeMap<String, Vec<String>>,
    pub tasks: BTreeMap<String, Task>,
    pub tombs: BTreeMap<String, Tomb>,
    /// Inline text and artifact bytes held in `tasks`.
    #[serde(default)]
    pub bytes: u64,
    /// The recent receive times per peer, for the rate limits.
    #[serde(default)]
    pub recent: BTreeMap<String, Vec<(u64, bool)>>,
}

impl HasCore for State {
    fn core(&self) -> &Core {
        &self.core
    }
    fn core_mut(&mut self) -> &mut Core {
        &mut self.core
    }
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

/// What a person sees of a peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeerView {
    pub name: String,
    pub epoch: u64,
    pub outbox: usize,
    pub sign_fingerprint: String,
    pub seal_fingerprint: String,
    pub last_seen_ms: u64,
    pub halted: Option<String>,
    pub via: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FindError {
    NoSuchTask,
    /// Two tasks have this id (one from each end, say): name it as `<sender>/<id>`.
    Ambiguous(Vec<String>),
}

fn hash_body(b: &Body) -> String {
    let mut e = Encoder::new("ozbox-mesh-body");
    e.text(&serde_json::to_string(b).unwrap_or_default());
    to_hex(&e.digest())
}

fn task_bytes(t: &Task) -> u64 {
    let msgs: usize = t
        .messages
        .iter()
        .map(|m| m.parts.iter().map(Part::size).sum::<usize>() + 64)
        .sum();
    let arts: usize = t
        .artifacts
        .iter()
        .map(|a| a.parts.iter().map(Part::size).sum::<usize>() + 128)
        .sum();
    (msgs + arts + t.title.len() + 256) as u64
}

/// The shape and content checks every inbound body must pass **before it is held or applied**: ids are names, sizes are bounded,
/// and no string in it looks like a key. A body that fails is never written down.
pub fn check_body(screen: &dyn Screen, body: &Body) -> Result<(), &'static str> {
    let id_ok = |s: &str| word_ok_len(s);
    let opt_ok = |o: &Option<String>| o.as_deref().is_none_or(word_ok_len);
    match body {
        Body::Task {
            title,
            context_id,
            parent,
            message,
            approval_ref,
            act,
            ..
        } => {
            if title.len() > MAX_TITLE
                || message.parts.iter().map(Part::size).sum::<usize>() > MAX_INLINE
            {
                return Err(code::TOO_BIG);
            }
            if !(id_ok(&message.id)
                && id_ok(&message.from)
                && opt_ok(context_id)
                && opt_ok(parent)
                && opt_ok(approval_ref))
            {
                return Err("bad-id");
            }
            if let Some(a) = act {
                // an act's fields are names and an object id: shaped, never free text, so nothing key-like is held for one
                a.valid()?;
            }
        }
        Body::Message { message } => {
            if message.parts.iter().map(Part::size).sum::<usize>() > MAX_INLINE {
                return Err(code::TOO_BIG);
            }
            if !(id_ok(&message.id) && id_ok(&message.from)) {
                return Err("bad-id");
            }
        }
        Body::Status { reason, .. } => {
            if reason.as_deref().is_some_and(|r| r.len() > MAX_REASON) {
                return Err(code::TOO_BIG);
            }
        }
        Body::Artifact { artifact } => {
            if artifact.name.len() > MAX_TITLE
                || artifact.parts.iter().map(Part::size).sum::<usize>() > MAX_INLINE
            {
                return Err(code::TOO_BIG);
            }
            if !id_ok(&artifact.id) {
                return Err("bad-id");
            }
        }
        Body::Cancel => {}
    }
    if body.strings().iter().any(|s| screen.find(s).is_some()) {
        return Err(code::KEY_SHAPED);
    }
    Ok(())
}

fn word_ok_len(s: &str) -> bool {
    s.len() <= MAX_ID && super::word_ok(s)
}

/// The channel's admission screen for the mesh: the body parses, is the right shape for its kind, and passes [`check_body`].
pub fn admit(
    screen: &dyn Screen,
    kind: &str,
    _ext: &[u8],
    plain: &[u8],
) -> Result<(), &'static str> {
    let body: Body = serde_json::from_slice(plain).map_err(|_| "malformed")?;
    if body.kind_name() != kind {
        return Err("kind-mismatch");
    }
    check_body(screen, &body)
}

impl State {
    pub fn new(me: &str, sign_public: &str, seal_public: &str) -> State {
        let seal_fp = unhex(seal_public)
            .map(|b| fingerprint(&b))
            .unwrap_or_default();
        State {
            version: STATE_VERSION,
            core: Core::new(me, sign_public, seal_public, &seal_fp, 1),
            vias: BTreeMap::new(),
            tasks: BTreeMap::new(),
            tombs: BTreeMap::new(),
            bytes: 0,
            recent: BTreeMap::new(),
        }
    }

    pub fn me(&self) -> &str {
        &self.core.me
    }

    pub fn epoch(&self) -> u64 {
        self.core.epoch
    }

    pub fn sign_public(&self) -> &str {
        &self.core.sign_public
    }

    pub fn seal_public(&self) -> &str {
        &self.core.seal_public
    }

    pub fn note(&mut self, now: u64, action: &str, subject: Option<&str>, detail: String) {
        self.core.note(now, action, subject, detail);
    }

    /// The fingerprint of this end's sealing key (the one function over the key bytes).
    pub fn seal_fingerprint(&self) -> String {
        self.core.seal_fp.clone()
    }

    /// The fingerprint of this end's signing key (over the key bytes).
    pub fn sign_fingerprint(&self) -> String {
        unhex(&self.core.sign_public)
            .map(|b| fingerprint(&b))
            .unwrap_or_default()
    }

    pub fn peers(&self) -> Vec<PeerView> {
        self.core
            .links
            .values()
            .map(|l| PeerView {
                name: l.name.clone(),
                epoch: l.epoch,
                outbox: l.outbox.len(),
                sign_fingerprint: unhex(&l.sign_key)
                    .map(|b| fingerprint(&b))
                    .unwrap_or_default(),
                seal_fingerprint: l.seal_fp.clone(),
                last_seen_ms: l.last_seen_ms,
                halted: l.halted.clone(),
                via: self.vias.get(&l.name).cloned().unwrap_or_default(),
            })
            .collect()
    }

    pub fn via(&self, peer: &str) -> Vec<String> {
        self.vias.get(peer).cloned().unwrap_or_default()
    }

    /// Pin a peer (keys are stored in one form, lower-case hex). The same keys at a new epoch keep what was in flight; other keys
    /// start clean. `via` replaces the transport command when given.
    pub fn pin(
        &mut self,
        now: u64,
        name: &str,
        sign_public: &str,
        seal_public: &str,
        epoch: u64,
        via: Option<Vec<String>>,
    ) -> Result<PinChange, &'static str> {
        let sign = normalize_hex(sign_public).ok_or("bad-key")?;
        let seal = normalize_hex(seal_public).ok_or("bad-key")?;
        let seal_fp = unhex(&seal).map(|b| fingerprint(&b)).ok_or("bad-key")?;
        let old = self.core.links.get(name).cloned();
        let mut link = Link::new(name, &sign, &seal, &seal_fp, epoch);
        let same_keys = old
            .as_ref()
            .is_some_and(|o| o.sign_key == sign && o.seal_key == seal);
        if let (Some(o), true) = (&old, same_keys) {
            // the same keys at a new epoch (or a new via): what was in flight stays, the window starts over
            link.out_seq = o.out_seq;
            link.outbox = o.outbox.clone();
            link.out_chain = o.out_chain.clone();
            link.acked_chain = o.acked_chain.clone();
        }
        let before_via = self.vias.get(name).cloned().unwrap_or_default();
        if let Some(v) = via {
            self.vias.insert(name.to_string(), v);
        }
        let after_via = self.vias.get(name).cloned().unwrap_or_default();
        let change = PinChange {
            new: old.is_none(),
            keys_changed: old.as_ref().is_some_and(|_| !same_keys),
            epoch_changed: old.as_ref().is_some_and(|o| o.epoch != epoch),
            via_changed: before_via != after_via,
            via: after_via,
        };
        if old.is_some() && !same_keys {
            // a task this end sent to the old keys was never delivered to these ones, and the numbers start again: it is failed, so
            // it is sent again on purpose and never settled by a later message that happens to reuse its number
            self.fail_held_for(now, name, "peer-replaced");
        }
        self.core.pin(link);
        self.note(
            now,
            "mesh.peer.pinned",
            None,
            format!(
                "peer={name} epoch={epoch} keys_changed={} via_changed={} sign={} seal={}",
                change.keys_changed,
                change.via_changed,
                unhex(&sign).map(|b| fingerprint(&b)).unwrap_or_default(),
                seal_fp
            ),
        );
        Ok(change)
    }

    /// After a restore from a backup: the channel starts a new epoch, incarnation and audit source epoch, and a task that was still
    /// waiting for its first delivery (its envelope is gone with the outbox) is failed, so the person sends it again.
    pub fn restored(&mut self, now: u64) {
        self.core.restored(now);
        let me = self.core.me.clone();
        for t in self.tasks.values_mut() {
            if t.from == me && t.state == TState::Held {
                t.state = TState::Failed;
                t.reason = Some("store-restored".into());
                t.sent_seq = None;
                t.updated_ms = now;
            }
        }
        self.recent.clear();
    }

    /// Fail every task this end sent to `peer` that is still waiting for its first delivery.
    fn fail_held_for(&mut self, now: u64, peer: &str, why: &str) {
        let me = self.core.me.clone();
        for t in self.tasks.values_mut() {
            if t.from == me && t.to == peer && t.state == TState::Held {
                t.state = TState::Failed;
                t.reason = Some(why.to_string());
                t.sent_seq = None;
                t.updated_ms = now;
            }
        }
    }

    /// Find a task by `<sender>/<id>`, or by its id alone when that is unambiguous.
    pub fn find(&self, id: &str) -> Result<&Task, FindError> {
        if let Some(t) = self.tasks.get(id) {
            return Ok(t);
        }
        let mut hits: Vec<&Task> = self.tasks.values().filter(|t| t.id == id).collect();
        match hits.len() {
            0 => Err(FindError::NoSuchTask),
            1 => Ok(hits.remove(0)),
            _ => Err(FindError::Ambiguous(
                hits.iter().map(|t| task_key(&t.from, &t.id)).collect(),
            )),
        }
    }

    fn key_of(&self, id: &str) -> Result<String, &'static str> {
        match self.find(id) {
            Ok(t) => Ok(task_key(&t.from, &t.id)),
            Err(FindError::NoSuchTask) => Err("unknown-task"),
            Err(FindError::Ambiguous(_)) => Err("ambiguous-id"),
        }
    }

    // ---- sending ------------------------------------------------------------------------------------------------

    fn enqueue(
        &mut self,
        peer: &str,
        kind: &str,
        key: &str,
        body: &Body,
    ) -> Result<u64, &'static str> {
        let plain = serde_json::to_vec(body).map_err(|_| "malformed")?;
        self.core
            .enqueue(&PROFILE, peer, kind, key.as_bytes().to_vec(), plain)
    }

    fn add_bytes(&mut self, n: u64) -> Result<(), &'static str> {
        if self.bytes.saturating_add(n) > MAX_STATE_BYTES {
            return Err(code::JOURNAL_FULL);
        }
        self.bytes += n;
        Ok(())
    }

    /// Start a task. It is written `held` with its envelope in the outbox, in the same write. Refusals are named.
    pub fn submit(
        &mut self,
        screen: &dyn Screen,
        now: u64,
        n: NewTask,
    ) -> Result<String, &'static str> {
        if !self.core.links.contains_key(&n.to) {
            return Err("unknown-peer");
        }
        if n.title.trim().is_empty() {
            return Err("title-missing");
        }
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
        let me = self.core.me.clone();
        let id = new_id(now);
        let deadline = n
            .deadline_ms
            .unwrap_or(now.saturating_add(DEFAULT_DEADLINE_MS));
        let message = Message {
            id: format!("{id}-0"),
            from: me.clone(),
            ts_ms: now,
            // an end never claims a person wrote it: "who wrote this" is the receiver's judgement, not the sender's say-so
            label: Label::Fleet,
            parts: n.parts,
            provenance: "self".into(),
            untrusted: false,
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
        check_body(screen, &body)?;
        let key = task_key(&me, &id);
        let hash = hash_body(&body);
        let task = Task {
            id: id.clone(),
            from: me,
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
            sent_seq: None,
            unread: false,
            hash,
            cancel_requested: false,
        };
        self.add_bytes(task_bytes(&task))?;
        let seq = match self.enqueue(&n.to, "task", &key, &body) {
            Ok(s) => s,
            Err(c) => {
                self.bytes = self.bytes.saturating_sub(task_bytes(&task));
                return Err(c);
            }
        };
        let mut task = task;
        task.sent_seq = Some(seq);
        self.tasks.insert(key, task);
        self.note(
            now,
            "mesh.task.sent",
            Some(&id),
            format!("kind={} to={}", n.kind.name(), n.to),
        );
        Ok(id)
    }

    fn side_of(&self, t: &Task) -> Side {
        if t.from == self.core.me {
            Side::Sender
        } else {
            Side::Receiver
        }
    }

    fn other(&self, t: &Task) -> String {
        if t.from == self.core.me {
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
        to_state: Option<(TState, Option<String>)>,
    ) -> Result<(), &'static str> {
        let key = self.key_of(task_id)?;
        let t = self.tasks.get(&key).ok_or("unknown-task")?.clone();
        let peer = self.other(&t);
        if t.state.terminal() {
            return Err("task-finished");
        }
        if t.messages.len() >= MAX_MESSAGES_PER_TASK && !parts.is_empty() {
            return Err(code::RATE);
        }
        if let Some((s, r)) = &to_state {
            if self.side_of(&t) != Side::Receiver || !may_move(t.state, *s, Side::Receiver) {
                return Err("state-not-yours-to-move");
            }
            if r.as_deref().is_some_and(|r| r.len() > MAX_REASON) {
                return Err(code::TOO_BIG);
            }
        }
        let me = self.core.me.clone();
        let message = (!parts.is_empty()).then(|| Message {
            id: new_id(now),
            from: me,
            ts_ms: now,
            label: Label::Fleet,
            parts,
            provenance: "self".into(),
            untrusted: false,
        });
        let msg_body = message
            .as_ref()
            .map(|m| Body::Message { message: m.clone() });
        let st_body = to_state.as_ref().map(|(s, r)| Body::Status {
            state: *s,
            reason: r.clone(),
        });
        for b in msg_body.iter().chain(st_body.iter()) {
            check_body(screen, b)?;
        }
        if let Some(m) = &message {
            let n: u64 = m.parts.iter().map(Part::size).sum::<usize>() as u64 + 64;
            self.add_bytes(n)?;
        }
        if let Some(b) = &msg_body {
            self.enqueue(&peer, "message", &key, b)?;
        }
        if let Some(b) = &st_body {
            self.enqueue(&peer, "status", &key, b)?;
        }
        if let Some(tt) = self.tasks.get_mut(&key) {
            if let Some(m) = message {
                tt.messages.push(m);
                tt.updated_ms = now;
            }
            tt.unread = false;
            if let Some((s, r)) = &to_state {
                tt.state = *s;
                tt.reason = r.clone();
                tt.updated_ms = now;
            }
        }
        if let Some((s, _)) = to_state {
            self.note(
                now,
                "mesh.task.state",
                Some(&t.id),
                format!("state={}", s.name()),
            );
        }
        Ok(())
    }

    /// Ask the other side to stop. The sender's cancel is a **request**: the receiver decides (it may answer with a state, or not).
    /// A task still `held` was never delivered and is canceled here at once. The receiver ending its own copy is its own authority.
    pub fn cancel(&mut self, now: u64, task_id: &str) -> Result<(), &'static str> {
        let key = self.key_of(task_id)?;
        let t = self.tasks.get(&key).ok_or("unknown-task")?.clone();
        if t.state.terminal() {
            return Err("task-finished");
        }
        let peer = self.other(&t);
        if self.side_of(&t) == Side::Receiver {
            self.enqueue(
                &peer,
                "status",
                &key,
                &Body::Status {
                    state: TState::Canceled,
                    reason: None,
                },
            )?;
            if let Some(tt) = self.tasks.get_mut(&key) {
                tt.state = TState::Canceled;
                tt.updated_ms = now;
            }
        } else {
            self.enqueue(&peer, "cancel", &key, &Body::Cancel)?;
            if let Some(tt) = self.tasks.get_mut(&key) {
                tt.cancel_requested = true;
                if t.state == TState::Held {
                    tt.state = TState::Canceled;
                }
                tt.updated_ms = now;
            }
        }
        self.note(now, "mesh.task.cancel", Some(&t.id), String::new());
        Ok(())
    }

    /// Mark a task read.
    pub fn mark_read(&mut self, task_id: &str) {
        if let Ok(key) = self.key_of(task_id) {
            if let Some(t) = self.tasks.get_mut(&key) {
                t.unread = false;
            }
        }
    }

    /// Whether [`State::tick`] would change anything at `now`. Lets a caller skip the write when it would not.
    pub fn tick_needed(&self, now: u64) -> bool {
        self.core.nonces.values().any(|v| *v < now)
            || self.tasks.values().any(|t| {
                (!t.state.terminal() && t.deadline_ms <= now && self.expirable(t))
                    || (t.state.terminal() && t.updated_ms.saturating_add(RETAIN_MS) <= now)
            })
            || self.tombs.len() > MAX_TOMBS
    }

    fn expirable(&self, t: &Task) -> bool {
        matches!(
            (self.side_of(t), t.state),
            (Side::Sender, TState::Held) | (Side::Receiver, _)
        )
    }

    /// Housekeeping: expire what is past its deadline (each side only what it owns), forget old nonces, and reduce long-finished tasks
    /// to tombstones so the cap measures what is open.
    pub fn tick(&mut self, now: u64) {
        self.core.tick(now);
        // the byte count is measured from what is held, so it can never drift from the data (it is a running figure between ticks)
        self.bytes = self.tasks.values().map(task_bytes).sum();
        let due: Vec<String> = self
            .tasks
            .iter()
            .filter(|(_, t)| !t.state.terminal() && t.deadline_ms <= now && self.expirable(t))
            .map(|(k, _)| k.clone())
            .collect();
        for key in due {
            let Some(t) = self.tasks.get(&key).cloned() else {
                continue;
            };
            let side = self.side_of(&t);
            let peer = self.other(&t);
            if let Some(tt) = self.tasks.get_mut(&key) {
                tt.state = TState::Failed;
                tt.reason = Some(code::EXPIRED.to_string());
                tt.updated_ms = now;
            }
            if side == Side::Receiver {
                let _ = self.enqueue(
                    &peer,
                    "status",
                    &key,
                    &Body::Status {
                        state: TState::Failed,
                        reason: Some(code::EXPIRED.into()),
                    },
                );
            }
            self.note(now, "mesh.task.expired", Some(&t.id), String::new());
        }
        let old: Vec<String> = self
            .tasks
            .iter()
            .filter(|(_, t)| t.state.terminal() && t.updated_ms.saturating_add(RETAIN_MS) <= now)
            .map(|(k, _)| k.clone())
            .collect();
        for key in old {
            if let Some(t) = self.tasks.remove(&key) {
                self.bytes = self.bytes.saturating_sub(task_bytes(&t));
                self.tombs.insert(
                    key,
                    Tomb {
                        hash: t.hash,
                        ts_ms: now,
                    },
                );
            }
        }
        while self.tombs.len() > MAX_TOMBS {
            let oldest = self
                .tombs
                .iter()
                .min_by_key(|(_, t)| t.ts_ms)
                .map(|(k, _)| k.clone());
            match oldest {
                Some(k) => {
                    self.tombs.remove(&k);
                }
                None => break,
            }
        }
        self.settle_held();
    }

    /// A task this end sent is `submitted` once the peer has acknowledged its envelope (it has left the outbox).
    pub fn settle_held(&mut self) {
        let me = self.core.me.clone();
        let delivered: Vec<String> =
            self.tasks
                .iter()
                .filter(|(_, t)| t.from == me && t.state == TState::Held)
                .filter(|(_, t)| {
                    let Some(seq) = t.sent_seq else { return false };
                    self.core.links.get(&t.to).is_some_and(|l| {
                        l.halted.is_none() && !l.outbox.iter().any(|o| o.seq == seq)
                    })
                })
                .map(|(k, _)| k.clone())
                .collect();
        for k in delivered {
            if let Some(t) = self.tasks.get_mut(&k) {
                t.state = TState::Submitted;
                t.sent_seq = None;
            }
        }
    }

    // ---- receiving ----------------------------------------------------------------------------------------------

    /// Take a batch from a peer through the channel's fixed checks and apply what is deliverable, in one pass. The caller writes the
    /// result once.
    pub fn receive_round(
        &mut self,
        cx: &Crypto<'_>,
        screen: &dyn Screen,
        now: u64,
        msgs: &[crate::channel::wire::Sealed],
    ) -> RoundReport {
        let r = receive_round(
            &mut self.core,
            &PROFILE,
            cx,
            &|k: &str, e: &[u8], p: &[u8]| admit(screen, k, e, p),
            now,
            msgs,
        );
        let mut r = r;
        let deliveries = std::mem::take(&mut r.deliveries);
        for d in &deliveries {
            self.apply(now, d);
        }
        self.settle_held();
        r.deliveries = deliveries;
        r
    }

    fn rate_ok(&mut self, from: &str, now: u64, is_task: bool) -> bool {
        let recent = self.recent.entry(from.to_string()).or_default();
        recent.retain(|(t, _)| t.saturating_add(60_000) > now);
        let (tasks, all) = (recent.iter().filter(|(_, k)| *k).count(), recent.len());
        if (is_task && tasks >= NEW_TASKS_PER_MIN) || all >= MESSAGES_PER_MIN {
            return false;
        }
        recent.push((now, is_task));
        true
    }

    fn tell_status(&mut self, peer: &str, key: &str, state: TState, reason: Option<String>) {
        let _ = self.enqueue(peer, "status", key, &Body::Status { state, reason });
    }

    /// Stamp a message a peer sent: this end decides what it is, never the sender. A peer's text is untrusted data whatever it says
    /// it is; the sender's word is kept only as what it claimed.
    fn stamp(m: &Message, from: &str) -> Message {
        Message {
            provenance: format!("peer:{from}"),
            untrusted: true,
            ..m.clone()
        }
    }

    fn apply(&mut self, now: u64, d: &Delivery) {
        let Some(ext) = std::str::from_utf8(&d.ext).ok().and_then(split_key) else {
            return;
        };
        let (origin, id) = (ext.0.to_string(), ext.1.to_string());
        let key = task_key(&origin, &id);
        let from = d.from.clone();
        let plain = match &d.body {
            Ok(p) => p,
            Err(c) => {
                // refused by the admission screen: nothing but the key, the kind and the code is kept
                if d.kind == "task" && origin == from {
                    self.reject_stub(now, &from, &key, &id, &d.hash, c);
                } else {
                    self.note(
                        now,
                        "mesh.message.refused",
                        Some(&id),
                        format!("from={from} kind={} code={c}", d.kind),
                    );
                }
                return;
            }
        };
        let Ok(body) = serde_json::from_slice::<Body>(plain) else {
            return;
        };
        match body {
            Body::Task {
                kind,
                title,
                context_id,
                parent,
                deadline_ms,
                act,
                message,
                ..
            } => {
                if origin != from {
                    self.note(
                        now,
                        "mesh.task.refused",
                        Some(&id),
                        format!("from={from} code=sender-mismatch"),
                    );
                    return;
                }
                self.apply_task(
                    now,
                    &from,
                    &key,
                    &id,
                    &d.hash,
                    TaskIn {
                        kind,
                        title,
                        context_id,
                        parent,
                        deadline_ms,
                        act,
                        message,
                    },
                );
            }
            Body::Message { message } => self.apply_message(now, &from, &key, &id, &message),
            Body::Status { state, reason } => {
                self.apply_status(now, &from, &key, &id, state, reason)
            }
            Body::Artifact { artifact } => self.apply_artifact(now, &from, &key, &id, &artifact),
            Body::Cancel => self.apply_cancel(now, &from, &key, &id),
        }
    }

    /// A task refused for what it said: the id, the kind and the code, and nothing it said.
    fn reject_stub(&mut self, now: u64, from: &str, key: &str, id: &str, hash: &str, c: &str) {
        if self.tasks.contains_key(key) || self.tombs.contains_key(key) {
            return;
        }
        // a stub is a task like any other for the caps: a peer cannot fill the store with refusals
        if self.tasks.len() >= MAX_TASKS || !self.rate_ok(from, now, true) {
            self.note(
                now,
                "mesh.task.refused",
                Some(id),
                format!("from={from} kind=task code={}", code::RATE),
            );
            return;
        }
        let stub = Task {
            id: id.to_string(),
            from: from.to_string(),
            to: self.core.me.clone(),
            // the body is gone, so the kind it asked for is not known; this is a placeholder, and the state says why
            kind: TaskKind::Note,
            title: "[refused]".into(),
            state: TState::Rejected,
            reason: Some(c.to_string()),
            context_id: None,
            parent: None,
            deadline_ms: now,
            created_ms: now,
            updated_ms: now,
            messages: Vec::new(),
            artifacts: Vec::new(),
            act: None,
            approval_ref: None,
            sent_seq: None,
            unread: true,
            hash: hash.to_string(),
            cancel_requested: false,
        };
        self.bytes = self.bytes.saturating_add(task_bytes(&stub));
        self.tasks.insert(key.to_string(), stub);
        self.note(
            now,
            "mesh.task.refused",
            Some(id),
            format!("from={from} kind=task code={c}"),
        );
        self.tell_status(from, key, TState::Rejected, Some(c.to_string()));
    }

    fn apply_message(&mut self, now: u64, from: &str, key: &str, id: &str, message: &Message) {
        let ok = self.tasks.get(key).is_some_and(|t| {
            !t.state.terminal()
                && (t.from == from || t.to == from)
                && !t.messages.iter().any(|m| m.id == message.id)
                && t.messages.len() < MAX_MESSAGES_PER_TASK
        });
        if !ok {
            self.note(
                now,
                "mesh.message.dropped",
                Some(id),
                format!("from={from}"),
            );
            return;
        }
        let refusal = if !self.rate_ok(from, now, false) {
            Some(code::RATE)
        } else if message.from != from {
            Some("sender-mismatch")
        } else {
            let n = message.parts.iter().map(Part::size).sum::<usize>() as u64 + 64;
            self.add_bytes(n).err()
        };
        if let Some(c) = refusal {
            self.note(
                now,
                "mesh.message.refused",
                Some(id),
                format!("from={from} code={c}"),
            );
            let st = self.tasks.get(key).map_or(TState::Working, |t| t.state);
            self.tell_status(from, key, st, Some(c.to_string()));
            return;
        }
        if let Some(t) = self.tasks.get_mut(key) {
            t.messages.push(Self::stamp(message, from));
            t.updated_ms = now;
            t.unread = true;
        }
    }

    fn apply_artifact(&mut self, now: u64, from: &str, key: &str, id: &str, artifact: &Artifact) {
        let ok = self.tasks.get(key).is_some_and(|t| {
            t.from == self.core.me && t.to == from && t.artifacts.len() < MAX_ARTIFACTS_PER_TASK
        });
        let bad = *artifact != Artifact::new(&artifact.id, &artifact.name, artifact.parts.clone());
        let n = artifact.parts.iter().map(Part::size).sum::<usize>() as u64 + 128;
        if !ok || bad || self.add_bytes(n).is_err() {
            self.note(
                now,
                "mesh.artifact.refused",
                Some(id),
                format!("from={from}"),
            );
            return;
        }
        if let Some(t) = self.tasks.get_mut(key) {
            if !t.artifacts.iter().any(|a| a.id == artifact.id) {
                t.artifacts.push(artifact.clone());
            }
            t.updated_ms = now;
            t.unread = true;
        }
    }

    /// A cancel is a request. The receiver records it and tells the sender it arrived; the task ends only when the receiver moves it.
    fn apply_cancel(&mut self, now: u64, from: &str, key: &str, id: &str) {
        let Some(t) = self.tasks.get(key).cloned() else {
            return;
        };
        if t.to != self.core.me || t.from != from {
            return;
        }
        if t.state.terminal() {
            self.tell_status(from, key, t.state, Some("too-late".into()));
            return;
        }
        if let Some(tt) = self.tasks.get_mut(key) {
            tt.cancel_requested = true;
            tt.updated_ms = now;
            tt.unread = true;
        }
        self.tell_status(from, key, t.state, Some("cancel-requested".into()));
        self.note(
            now,
            "mesh.task.cancel-requested",
            Some(id),
            format!("from={from}"),
        );
    }

    fn apply_task(&mut self, now: u64, from: &str, key: &str, id: &str, hash: &str, t: TaskIn) {
        if let Some(existing) = self
            .tasks
            .get(key)
            .map(|x| x.hash.clone())
            .or_else(|| self.tombs.get(key).map(|x| x.hash.clone()))
        {
            if existing != hash {
                // the same key with other content: refused, and an alert (no end may squat a task id)
                self.note(now, "mesh.task.conflict", Some(id), format!("from={from}"));
            }
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
        } else if t.message.from != from {
            Some("sender-mismatch")
        } else if t.deadline_ms <= now {
            Some(code::EXPIRED)
        } else if self
            .bytes
            .saturating_add(t.message.parts.iter().map(Part::size).sum::<usize>() as u64 + 256)
            > MAX_STATE_BYTES
        {
            Some(code::JOURNAL_FULL)
        } else {
            match (t.kind, &t.act) {
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
        let (state, reason) = match reject {
            Some(c) => (TState::Rejected, Some(c.to_string())),
            None => (TState::Submitted, None),
        };
        // a refused task keeps nothing the sender said beyond its id and the code
        let task = Task {
            id: id.to_string(),
            from: from.to_string(),
            to: self.core.me.clone(),
            kind: t.kind,
            title: if reject.is_some() {
                "[refused]".into()
            } else {
                t.title
            },
            state,
            reason: reason.clone(),
            context_id: if reject.is_some() { None } else { t.context_id },
            parent: if reject.is_some() { None } else { t.parent },
            deadline_ms: t.deadline_ms,
            created_ms: now,
            updated_ms: now,
            messages: if reject.is_some() {
                Vec::new()
            } else {
                vec![Self::stamp(&t.message, from)]
            },
            artifacts: Vec::new(),
            act: if reject.is_some() { None } else { t.act },
            approval_ref: None,
            sent_seq: None,
            unread: true,
            hash: hash.to_string(),
            cancel_requested: false,
        };
        // charged for what is kept (a refused task keeps almost nothing), by the one formula that is also used to release it
        self.bytes = self.bytes.saturating_add(task_bytes(&task));
        self.tasks.insert(key.to_string(), task);
        match &reason {
            Some(c) => {
                self.note(
                    now,
                    "mesh.task.refused",
                    Some(id),
                    format!("from={from} kind={} code={c}", t.kind.name()),
                );
                self.tell_status(from, key, TState::Rejected, reason);
            }
            None => self.note(
                now,
                "mesh.task.received",
                Some(id),
                format!("from={from} kind={}", t.kind.name()),
            ),
        }
    }

    fn apply_status(
        &mut self,
        now: u64,
        from: &str,
        key: &str,
        id: &str,
        state: TState,
        reason: Option<String>,
    ) {
        let Some(t) = self.tasks.get(key).cloned() else {
            return;
        };
        // only the receiver of a task reports its state
        if t.from != self.core.me || t.to != from {
            self.note(now, "mesh.status.refused", Some(id), format!("from={from}"));
            return;
        }
        let reason = reason.map(|r| super::printable_line(&r));
        let mut cur = t.state;
        if cur == TState::Held {
            cur = TState::Submitted;
        }
        if state == cur {
            if let Some(tt) = self.tasks.get_mut(key) {
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
                Some(id),
                format!("from={from} to={}", state.name()),
            );
            return;
        }
        if let Some(tt) = self.tasks.get_mut(key) {
            tt.state = state;
            tt.reason = reason;
            tt.sent_seq = None;
            tt.updated_ms = now;
            tt.unread = true;
        }
        self.note(
            now,
            "mesh.task.state",
            Some(id),
            format!("state={}", state.name()),
        );
    }

    // ---- why ----------------------------------------------------------------------------------------------------

    /// Why a task is where it is, in a few plain sentences that name the next actor.
    pub fn why(&self, task_id: &str, now: u64) -> Vec<String> {
        let t = match self.find(task_id) {
            Ok(t) => t,
            Err(FindError::NoSuchTask) => return vec!["There is no such task.".into()],
            Err(FindError::Ambiguous(keys)) => {
                return vec![format!(
                    "More than one task has that id: name it as one of {}.",
                    keys.join(", ")
                )]
            }
        };
        let me_sender = t.from == self.core.me;
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
            super::printable_line(peer)
        )];
        if let Some(r) = &t.reason {
            out.push(format!("Reason: {}.", super::printable_line(r)));
        }
        let unsent = self.core.links.get(peer).map_or(0, |l| {
            l.outbox
                .iter()
                .filter(|o| o.ext == task_key(&t.from, &t.id).as_bytes())
                .count()
        });
        if self
            .core
            .links
            .get(peer)
            .is_some_and(|l| l.halted.is_some())
        {
            out.push("The channel to this peer is halted: a store looks restored from a backup. Run `ozbox tasks restored` on the end that was restored.".into());
        }
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
                format!("{} is working on it.", if me_sender { peer.as_str() } else { "You are" })
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
        if t.cancel_requested && !t.state.terminal() {
            out.push(if me_sender {
                format!("You asked {peer} to stop. A cancel is a request: it stops when {peer} says so.")
            } else {
                format!("{peer} asked you to stop. Answer with `ozbox tasks reply --state canceled` to stop, or carry on.")
            });
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

/// What changed when a peer was pinned, for the audit line and the person's screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinChange {
    pub new: bool,
    pub keys_changed: bool,
    pub epoch_changed: bool,
    pub via_changed: bool,
    pub via: Vec<String>,
}

struct TaskIn {
    kind: TaskKind,
    title: String,
    context_id: Option<String>,
    parent: Option<String>,
    deadline_ms: u64,
    act: Option<Act>,
    message: Message,
}
