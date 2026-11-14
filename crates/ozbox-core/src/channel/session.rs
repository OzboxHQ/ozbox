//! The session layer: one end's durable protocol state and the pure logic that changes it. No I/O, no clock of its own, no
//! transport. The file store persists the result **before** anything is acknowledged, and a node signs, seals and moves the
//! envelopes this produces; that is what keeps a send from holding the store's lock and what makes a crash safe (the outbox is
//! part of the state, written in the same write as the message it carries).
//!
//! What it decides, once, for every profile:
//! * **Sessions.** An end's incarnation is random and fresh whenever its state is created or restored. A peer's incarnation is
//!   adopted only from a signed `hello` that names this end's *current* incarnation, and a `hello` older than the last one taken
//!   is refused (so a captured, never-delivered `hello` cannot roll a session back).
//! * **Order.** Sequenced messages are applied in `seq` order from a window, de-duplicated, and acknowledged cumulatively.
//!   The hash of every applied number is kept for a window, so a retry (same content) is told from a conflicting reuse of the
//!   number (a sender restored from a backup without saying so), which is refused, alerted and told to the sender.
//! * **Order of checks.** Shape, addressing, signature (all counted, never one audit entry each, because the sender is not
//!   authenticated yet), then epochs, validity, the nonce, the seal, the profile's admission screen, incarnations, the
//!   acknowledgement, and only then the sequence window and the effect. Nothing takes effect until every check passes.

use std::collections::BTreeMap;

use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

use super::wire::{
    hex, hex_bytes, Crypto, Envelope, Profile, Sealed, KIND_ACK, KIND_HELLO, MAX_SKEW_MS,
    MAX_VALIDITY_MS, VERSION, WINDOW,
};
use crate::approval_subject::{to_hex, Encoder};
use crate::audit::NewEvent;

pub const STATE_VERSION: u32 = 1;
/// The most messages waiting for one peer's acknowledgement.
pub const MAX_OUTBOX: usize = 200;
/// How many audit events may wait for the log at once. Past this a change is refused, so an unwritable log cannot grow the state
/// without bound and nothing is silently dropped.
pub const MAX_PENDING_AUDIT: usize = 2000;
/// A `hello` is sent at most this often per peer by a push transport. (A round-based transport sends one every round.)
pub const HELLO_EVERY_MS: u64 = 1000;
/// A push transport resends an unacknowledged window after this long.
pub const RESEND_AFTER_MS: u64 = 5000;

/// The codes a refusal is named by that the channel itself produces.
pub mod code {
    pub const RATE: &str = "resource-exhausted";
    pub const TOO_BIG: &str = "too-big";
    pub const UNKNOWN_PEER: &str = "unknown-peer";
    pub const JOURNAL_FULL: &str = "journal-full";
    pub const AUDIT_FULL: &str = "audit-backlog";
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outgoing {
    pub seq: u64,
    pub kind: String,
    #[serde(with = "hex_bytes")]
    pub ext: Vec<u8>,
    /// The plain body. It is sealed fresh on every delivery attempt.
    #[serde(with = "hex_bytes")]
    pub body: Vec<u8>,
}

/// A message received out of order and waiting for the gap to fill. **Only what the profile's screen passed is kept**: a body that
/// failed it is held as its hash and the refusal code, so refused content never reaches the disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Held {
    pub kind: String,
    #[serde(with = "hex_bytes")]
    pub ext: Vec<u8>,
    pub hash: String,
    pub body: Option<HeldBody>,
    pub refusal: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldBody(#[serde(with = "hex_bytes")] pub Vec<u8>);

/// What one end keeps about one peer: the pin (names and keys), the outbox, and the receive window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Link {
    pub name: String,
    /// Handed to the [`super::wire::Verifier`] as is (a public key in hex, or a key fingerprint).
    pub sign_key: String,
    /// Handed to the [`super::wire::Sealer`] as is.
    pub seal_key: String,
    /// The fingerprint of the sealing key: it goes into every envelope's receiver field.
    pub seal_fp: String,
    /// The epoch pinned for the peer. A peer that restores changes epoch, and the owner pins the new one.
    pub epoch: u64,
    pub out_seq: u64,
    pub outbox: Vec<Outgoing>,
    /// The peer's incarnation, learned from its `hello` (0 until then).
    pub peer_inc: u64,
    /// The incarnation the next `hello` names as the receiver's: the last one the peer announced.
    pub named_inc: u64,
    pub last_hello_ms: u64,
    pub next_in: u64,
    pub held_in: BTreeMap<u64, Held>,
    /// The hash of each applied sequence number, for the last window.
    pub applied: BTreeMap<u64, String>,
    pub dups: u64,
    pub last_seen_ms: u64,
    /// Set when this end must stop sending to the peer and why (an acknowledgement ahead of what was sent, or the peer saw a
    /// number reused): the store looks restored from a backup. Cleared only by [`Core::restored`].
    pub halted: Option<String>,
    /// Said in every `hello` until the peer's incarnation changes: this end saw a sequence number reused with other content.
    pub notice: Option<String>,
    /// The highest sequence number already pushed, and when (a push transport sends the rest, and the window again after a while).
    pub pushed_hi: u64,
    pub last_push_ms: u64,
    pub ack_dirty: bool,
    /// A `hello` is wanted: no session yet, or a message named the wrong incarnation. Sent at most every [`HELLO_EVERY_MS`].
    pub hello_wanted: bool,
    /// A `hello` was taken that must be answered (a request, or one that changed the session). Never rate-limited: each `hello`
    /// taken causes at most one answer, and an answer that changes nothing causes none, so the exchange ends.
    pub hello_reply: bool,
    pub last_hello_sent_ms: u64,
}

impl Link {
    pub fn new(name: &str, sign_key: &str, seal_key: &str, seal_fp: &str, epoch: u64) -> Link {
        Link {
            name: name.to_string(),
            sign_key: sign_key.to_string(),
            seal_key: seal_key.to_string(),
            seal_fp: seal_fp.to_string(),
            epoch,
            out_seq: 0,
            outbox: Vec::new(),
            peer_inc: 0,
            named_inc: 0,
            last_hello_ms: 0,
            next_in: 1,
            held_in: BTreeMap::new(),
            applied: BTreeMap::new(),
            dups: 0,
            last_seen_ms: 0,
            halted: None,
            notice: None,
            pushed_hi: 0,
            last_push_ms: 0,
            ack_dirty: false,
            hello_wanted: true,
            hello_reply: false,
            last_hello_sent_ms: 0,
        }
    }

    fn reset_session(&mut self) {
        self.out_seq = 0;
        self.outbox.clear();
        self.peer_inc = 0;
        self.named_inc = 0;
        self.last_hello_ms = 0;
        self.next_in = 1;
        self.held_in.clear();
        self.applied.clear();
        self.halted = None;
        self.notice = None;
        self.pushed_hi = 0;
        self.last_push_ms = 0;
        self.ack_dirty = false;
        self.hello_wanted = true;
        self.hello_reply = false;
    }

    /// Whether a sequenced message to this peer would be accepted now: it has told this end its incarnation, and nothing halted it.
    pub fn session_ready(&self) -> bool {
        self.peer_inc != 0 && self.halted.is_none()
    }
}

/// What happened in a round, counted so a flood costs one audit event and not thousands. Transient: never written, and never part of
/// whether two states are equal.
#[derive(Debug, Clone, Default)]
pub struct Tally {
    /// Something durable changed since the state was read (a message taken, an event noted, a session moved). A caller that holds the
    /// store's lock writes only when this is set, so a round in which nothing happened costs no write.
    pub dirty: bool,
    /// Refused before the signature verified, by code. The sender is not authenticated, so its words are never logged.
    pub unverified: BTreeMap<String, u64>,
    /// Duplicates taken from an authenticated peer, by peer.
    pub duplicates: BTreeMap<String, u64>,
}

impl PartialEq for Tally {
    fn eq(&self, _: &Tally) -> bool {
        true
    }
}

impl Eq for Tally {}

/// One end: identity, every peer's link, the replay set and the audit backlog. Embedded in the profile's own state (the hub's, the
/// mesh's task state), so a message and everything it changes are written together.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Core {
    pub version: u32,
    pub me: String,
    /// The source epoch of this end's audit events. New whenever the state is restored, so the log's de-duplication never
    /// swallows what a restored end writes.
    pub store_id: String,
    pub epoch: u64,
    pub incarnation: u64,
    pub sign_public: String,
    pub seal_public: String,
    pub seal_fp: String,
    pub links: BTreeMap<String, Link>,
    pub nonces: BTreeMap<String, u64>,
    /// Audit events not yet taken by the audit log. Written in the same write as the change they describe.
    pub audit: Vec<NewEvent>,
    pub audit_n: u64,
    #[serde(skip)]
    pub tally: Tally,
}

/// A random incarnation. Never 0: 0 means "not learned yet" on the wire.
pub fn fresh_incarnation() -> u64 {
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

fn fresh_id() -> String {
    let mut b = [0u8; 8];
    let _ = SystemRandom::new().fill(&mut b);
    hex(&b)
}

/// The body of a `hello`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloBody {
    /// The lowest sequence number the sender can still send (everything below was acknowledged or never existed).
    pub out_floor: u64,
    /// A thing the sender wants its peer to know (`seq-conflict`), or nothing.
    #[serde(default)]
    pub notice: Option<String>,
    /// The incarnation of the receiver this end has adopted (0 if none): lets the receiver see that this end has not adopted *its*
    /// current incarnation yet, and say so, so a session one end believes in and the other does not still converges.
    #[serde(default)]
    pub heard: u64,
}

pub const NOTICE_SEQ_CONFLICT: &str = "seq-conflict";
pub const HALT_ACK_AHEAD: &str = "ack-ahead";
pub const HALT_PEER_SAW_CONFLICT: &str = "peer-saw-seq-conflict";

/// A screen run on a body before it is held or applied: `(kind, ext, plain)` to `Ok` or a refusal code. The profile owns the rule.
pub type Admit<'a> = &'a dyn Fn(&str, &[u8], &[u8]) -> Result<(), &'static str>;

/// A message that passed every check and is next in order, for the profile to apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivery {
    pub from: String,
    pub seq: u64,
    pub kind: String,
    pub ext: Vec<u8>,
    pub hash: String,
    /// The plain body, or the code the profile's screen refused it with (the content is then gone).
    pub body: Result<Vec<u8>, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Received {
    /// Refused, with the code. Already counted or audited.
    Refused(String),
    Duplicate,
    /// A `hello` or an `ack`, taken.
    Control,
    /// Sequenced and stored, but nothing is deliverable yet.
    Buffered,
    Delivered(Vec<Delivery>),
}

/// An envelope to send, before sealing and signing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Draft {
    pub env: Envelope,
    pub plain: Vec<u8>,
    pub seal_key: String,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DraftOpts {
    pub hello: bool,
    /// An `ack` with nothing else to say, when messages were taken and nothing else carries the acknowledgement.
    pub ack: bool,
    /// The whole window again, not only what was never pushed.
    pub resend: bool,
}

pub fn hash_message(kind: &str, ext: &[u8], plain: &[u8]) -> String {
    let mut e = Encoder::new("ozbox-channel-message");
    e.text(kind).field(ext).field(plain);
    to_hex(&e.digest())
}

impl Core {
    pub fn new(me: &str, sign_public: &str, seal_public: &str, seal_fp: &str, epoch: u64) -> Core {
        Core {
            version: STATE_VERSION,
            me: me.to_string(),
            store_id: fresh_id(),
            epoch,
            incarnation: fresh_incarnation(),
            sign_public: sign_public.to_string(),
            seal_public: seal_public.to_string(),
            seal_fp: seal_fp.to_string(),
            links: BTreeMap::new(),
            nonces: BTreeMap::new(),
            audit: Vec::new(),
            audit_n: 0,
            tally: Tally::default(),
        }
    }

    /// Pin a peer, or replace its pin (new keys or epoch), keeping nothing of an earlier session.
    pub fn pin(&mut self, link: Link) {
        self.tally.dirty = true;
        self.links.insert(link.name.clone(), link);
    }

    pub fn note(&mut self, now: u64, action: &str, subject: Option<&str>, detail: String) {
        self.tally.dirty = true;
        self.audit_n += 1;
        self.audit.push(NewEvent {
            ts_ms: now,
            actor: format!("channel:{}", self.me),
            action: action.to_string(),
            subject: subject.map(str::to_string),
            detail: detail.chars().take(150).collect(),
            src: Some((self.store_id.clone(), self.audit_n)),
        });
    }

    /// Drop the events the audit log already holds (its last source number for this store), by number, never by count.
    pub fn trim_logged(&mut self, last: Option<&(String, u64)>) {
        if let Some((ep, n)) = last {
            if *ep == self.store_id {
                self.audit
                    .retain(|e| e.src.as_ref().map_or(true, |(_, k)| k > n));
            }
        }
    }

    /// After a restore from a backup: a new epoch, a new incarnation and a new audit source epoch. Envelopes captured before it
    /// no longer verify, the peers are told to pin the new epoch, and nothing in flight survives.
    pub fn restored(&mut self, now: u64) {
        self.tally.dirty = true;
        self.epoch += 1;
        self.incarnation = fresh_incarnation();
        self.store_id = fresh_id();
        self.audit_n = 0;
        self.nonces.clear();
        for l in self.links.values_mut() {
            l.reset_session();
        }
        self.note(
            now,
            "channel.restored",
            None,
            format!("epoch={}", self.epoch),
        );
    }

    /// Forget expired nonces.
    pub fn tick(&mut self, now: u64) {
        self.nonces.retain(|_, v| *v >= now);
    }

    // ---- sending ------------------------------------------------------------------------------------------------

    /// Queue a message for a peer. Returns its sequence number.
    pub fn enqueue(
        &mut self,
        p: &Profile,
        peer: &str,
        kind: &str,
        ext: Vec<u8>,
        body: Vec<u8>,
    ) -> Result<u64, &'static str> {
        if !p.sequenced(kind) {
            return Err("kind-not-allowed");
        }
        if body.len() > p.max_body {
            return Err(code::TOO_BIG);
        }
        if self.audit.len() >= MAX_PENDING_AUDIT {
            return Err(code::AUDIT_FULL);
        }
        let l = self.links.get_mut(peer).ok_or(code::UNKNOWN_PEER)?;
        if l.outbox.len() >= MAX_OUTBOX {
            return Err(code::RATE);
        }
        self.tally.dirty = true;
        l.out_seq += 1;
        let seq = l.out_seq;
        l.outbox.push(Outgoing {
            seq,
            kind: kind.to_string(),
            ext,
            body,
        });
        Ok(seq)
    }

    /// The envelopes to send to a peer now, unsigned, with plain bodies. Read-only: the node signs them fresh (new nonce, new
    /// validity) on every attempt.
    ///
    /// A `hello` first when asked (it carries the acknowledgement and the lowest sequence number still available), then the
    /// oldest unacknowledged messages, at most a window's worth, oldest first. Nothing sequenced is offered until the peer has
    /// told this end its incarnation, and nothing at all once the link is halted.
    pub fn drafts(&self, peer: &str, now: u64, o: DraftOpts) -> Vec<Draft> {
        let Some(l) = self.links.get(peer) else {
            return Vec::new();
        };
        let ack = l.next_in.saturating_sub(1);
        let mk = |kind: &str, seq: u64, ext: &[u8], receiver_inc: u64, plain: Vec<u8>| {
            let mut nonce = [0u8; 16];
            let _ = SystemRandom::new().fill(&mut nonce);
            Draft {
                env: Envelope {
                    version: VERSION,
                    kind: kind.to_string(),
                    from: self.me.clone(),
                    to: l.name.clone(),
                    receiver_fp: l.seal_fp.clone(),
                    sender_epoch: self.epoch,
                    receiver_epoch: l.epoch,
                    sender_inc: self.incarnation,
                    receiver_inc,
                    seq,
                    ack_seq: ack,
                    id: format!("{seq}-{}", hex(&nonce[..6])),
                    ts_ms: now,
                    valid_until_ms: now + MAX_VALIDITY_MS,
                    nonce: nonce.to_vec(),
                    ext: ext.to_vec(),
                    body: Vec::new(),
                },
                plain,
                seal_key: l.seal_key.clone(),
            }
        };
        let mut out = Vec::new();
        if o.hello {
            let floor = l.outbox.first().map_or(l.out_seq + 1, |x| x.seq);
            let body = HelloBody {
                out_floor: floor,
                heard: l.peer_inc,
                // a notice is about the session this end holds; to a peer whose new incarnation this end has not adopted yet it
                // would describe the old one
                notice: if l.named_inc == l.peer_inc {
                    l.notice.clone()
                } else {
                    None
                },
            };
            out.push(mk(
                KIND_HELLO,
                0,
                &[],
                l.named_inc,
                serde_json::to_vec(&body).unwrap_or_default(),
            ));
        }
        let mut carried = false;
        if l.session_ready() {
            for x in l.outbox.iter().take(WINDOW as usize) {
                if o.resend || x.seq > l.pushed_hi {
                    out.push(mk(&x.kind, x.seq, &x.ext, l.peer_inc, x.body.clone()));
                    carried = true;
                }
            }
        }
        if o.ack && l.ack_dirty && !carried && l.peer_inc != 0 {
            out.push(mk(KIND_ACK, 0, &[], l.peer_inc, b"{}".to_vec()));
        }
        out
    }

    /// Record that a push transport sent what [`Core::drafts`] offered: what was pushed, when, and that a `hello` or `ack` went.
    pub fn pushed(&mut self, peer: &str, now: u64, drafts: &[Draft]) {
        let Some(l) = self.links.get_mut(peer) else {
            return;
        };
        for d in drafts {
            match d.env.kind.as_str() {
                KIND_HELLO => {
                    l.hello_wanted = false;
                    l.hello_reply = false;
                    l.last_hello_sent_ms = now;
                }
                KIND_ACK => l.ack_dirty = false,
                _ => {
                    l.pushed_hi = l.pushed_hi.max(d.env.seq);
                    l.last_push_ms = now;
                    l.ack_dirty = false;
                }
            }
        }
    }

    /// What a push transport should offer a peer now.
    pub fn push_opts(&self, peer: &str, now: u64) -> DraftOpts {
        let Some(l) = self.links.get(peer) else {
            return DraftOpts::default();
        };
        DraftOpts {
            hello: l.hello_reply
                || ((l.hello_wanted || l.peer_inc == 0)
                    && (l.last_hello_sent_ms == 0
                        || now >= l.last_hello_sent_ms.saturating_add(HELLO_EVERY_MS))),
            ack: true,
            resend: l.last_push_ms != 0 && now >= l.last_push_ms.saturating_add(RESEND_AFTER_MS),
        }
    }

    // ---- receiving ----------------------------------------------------------------------------------------------

    fn unverified(&mut self, code: String) -> Received {
        *self.tally.unverified.entry(code.clone()).or_insert(0) += 1;
        Received::Refused(code)
    }

    fn refuse(&mut self, p: &Profile, now: u64, from: &str, e: &Envelope, why: &str) -> Received {
        // a profile whose ext is a task id gets it as the audit subject; binary ext is not a subject
        let subject = String::from_utf8(e.ext.clone())
            .ok()
            .filter(|s| super::wire::word_ok(s));
        self.note(
            now,
            &format!("{}.refused", p.audit),
            subject.as_deref(),
            format!("from={from} kind={} code={why}", e.kind),
        );
        Received::Refused(why.to_string())
    }

    /// Emit the round's counted events (one per kind of refusal, one for duplicates) and reset the tally. Call once per round,
    /// inside the same write as the receives.
    pub fn end_round(&mut self, p: &Profile, now: u64) {
        // the round's counts are reported and cleared; whether anything durable changed is not
        let dirty = self.tally.dirty;
        let t = std::mem::take(&mut self.tally);
        self.tally.dirty = dirty;
        if !t.unverified.is_empty() {
            let total: u64 = t.unverified.values().sum();
            let by: Vec<String> = t
                .unverified
                .iter()
                .map(|(c, n)| format!("{c}={n}"))
                .collect();
            self.note(
                now,
                &format!("{}.unverified", p.audit),
                None,
                format!("n={total} {}", by.join(" ")),
            );
        }
        for (peer, n) in t.duplicates {
            self.note(
                now,
                &format!("{}.duplicate", p.audit),
                None,
                format!("from={peer} n={n}"),
            );
        }
    }

    /// Check an envelope and, when every check passes, take it. See the module docs for the fixed order.
    pub fn receive(
        &mut self,
        p: &Profile,
        cx: &Crypto<'_>,
        admit: Admit<'_>,
        now: u64,
        msg: &Sealed,
    ) -> Received {
        let e = &msg.envelope;
        if let Err(x) = e.check(p) {
            return self.unverified(x.code());
        }
        if e.to != self.me {
            return self.unverified("not-for-me".into());
        }
        let Some(link) = self.links.get(&e.from) else {
            return self.unverified("unknown-sender".into());
        };
        if e.receiver_fp != self.seal_fp {
            return self.unverified("wrong-receiver".into());
        }
        if !cx
            .verifier
            .verify(&link.sign_key, &e.canonical(p), &msg.signature)
        {
            return self.unverified("bad-signature".into());
        }
        // authenticated from here: a refusal is the peer's, and is audited by name
        let from = e.from.clone();
        if e.receiver_epoch != self.epoch || e.sender_epoch != link.epoch {
            return self.refuse(p, now, &from, e, "epoch");
        }
        if e.valid_until_ms <= now {
            return self.refuse(p, now, &from, e, "expired");
        }
        if e.ts_ms.abs_diff(now) > MAX_SKEW_MS {
            return self.refuse(p, now, &from, e, "skew");
        }
        let nonce_hex = to_hex(&e.nonce);
        if self.nonces.contains_key(&nonce_hex) {
            *self.tally.duplicates.entry(from).or_insert(0) += 1;
            return Received::Duplicate;
        }
        let plain = match cx.sealer.open(&e.aad(p), &e.body) {
            Ok(x) => x,
            Err(_) => return self.refuse(p, now, &from, e, "unopenable"),
        };
        let hello = if e.kind == KIND_HELLO {
            match serde_json::from_slice::<HelloBody>(&plain) {
                Ok(h) => Some(h),
                Err(_) => return self.refuse(p, now, &from, e, "malformed"),
            }
        } else {
            None
        };
        // the profile's screen runs before anything is held, so refused content is never written down
        let admitted = if p.sequenced(&e.kind) {
            Some(
                admit(&e.kind, &e.ext, &plain)
                    .map(|()| plain.clone())
                    .map_err(str::to_string),
            )
        } else {
            None
        };
        let (cur_inc, last_hello, out_seq) = self
            .links
            .get(&from)
            .map_or((0, 0, 0), |l| (l.peer_inc, l.last_hello_ms, l.out_seq));
        if hello.is_some() {
            if e.receiver_inc != 0 && e.receiver_inc != self.incarnation {
                // for an earlier life of this end: the peer learns the current one from the next hello
                if let Some(l) = self.links.get_mut(&from) {
                    l.hello_wanted = true;
                    l.named_inc = e.sender_inc;
                }
                return self.refuse(p, now, &from, e, "incarnation");
            }
            if e.ts_ms < last_hello {
                return self.refuse(p, now, &from, e, "stale-hello");
            }
        } else if cur_inc == 0 || e.receiver_inc != self.incarnation || e.sender_inc != cur_inc {
            if let Some(l) = self.links.get_mut(&from) {
                l.hello_wanted = true;
            }
            return self.refuse(p, now, &from, e, "incarnation");
        }
        // an acknowledgement belongs to a session: a `hello` that opens a new one (the peer's incarnation changed) carries the old
        // session's number, which says nothing about this one
        let ack_valid =
            hello.is_none() || (e.sender_inc == cur_inc && e.receiver_inc == self.incarnation);
        if ack_valid && e.ack_seq > out_seq {
            // the peer has applied more than this end ever sent: this end's store was rolled back
            self.tally.dirty = true;
            if let Some(l) = self.links.get_mut(&from) {
                l.halted = Some(HALT_ACK_AHEAD.into());
            }
            self.note(
                now,
                &format!("{}.halted", p.audit),
                None,
                format!("from={from} code={HALT_ACK_AHEAD}"),
            );
            return self.refuse(p, now, &from, e, HALT_ACK_AHEAD);
        }
        // every check passed
        self.nonces.insert(nonce_hex, e.valid_until_ms);
        if let Some(l) = self.links.get_mut(&from) {
            l.last_seen_ms = now;
        }
        if let Some(h) = hello {
            return self.take_hello(p, now, &from, e, &h);
        }
        self.apply_ack(&from, e.ack_seq);
        if e.kind == KIND_ACK {
            return Received::Control;
        }
        match admitted {
            Some(a) => self.sequenced(p, now, &from, e, a),
            None => Received::Control,
        }
    }

    fn take_hello(
        &mut self,
        p: &Profile,
        now: u64,
        from: &str,
        e: &Envelope,
        h: &HelloBody,
    ) -> Received {
        let me_inc = self.incarnation;
        let mut halted_now = false;
        let mut adopted = false;
        let established = self
            .links
            .get(from)
            .is_some_and(|l| e.sender_inc == l.peer_inc && e.receiver_inc == me_inc);
        if let Some(l) = self.links.get_mut(from) {
            l.last_hello_ms = e.ts_ms;
            if l.named_inc != e.sender_inc {
                // what the next `hello` names must outlive a restart, or the session could never be completed
                l.named_inc = e.sender_inc;
                self.tally.dirty = true;
            }
            if e.receiver_inc == 0 {
                // a request: the peer does not know this end's incarnation, so this end says it
                l.hello_reply = true;
            } else if e.receiver_inc == me_inc && e.sender_inc == l.peer_inc && h.heard != me_inc {
                // the peer is in a session with this end's old life: tell it the current one (at the unsolicited rate)
                l.hello_wanted = true;
            }
            if e.receiver_inc == me_inc && e.sender_inc != l.peer_inc {
                l.peer_inc = e.sender_inc;
                l.next_in = 1;
                l.held_in.clear();
                l.applied.clear();
                l.notice = None;
                l.ack_dirty = false;
                l.hello_reply = true;
                adopted = true;
                self.tally.dirty = true;
            }
            if h.notice.as_deref() == Some(NOTICE_SEQ_CONFLICT) && l.halted.is_none() {
                l.halted = Some(HALT_PEER_SAW_CONFLICT.into());
                halted_now = true;
            }
            // a sender that has nothing below this number: what this end has not applied by then is gone (state loss)
            if e.receiver_inc == me_inc
                && h.out_floor > l.next_in
                && e.sender_inc == l.peer_inc
                && l.held_in.is_empty()
                && l.next_in == 1
            {
                l.next_in = h.out_floor;
            }
        }
        if halted_now {
            self.note(
                now,
                &format!("{}.halted", p.audit),
                None,
                format!("from={from} code={HALT_PEER_SAW_CONFLICT}"),
            );
        } else if established {
            // the acknowledgement a hello carries is real only inside a session, and only while the link is not halted
            self.apply_ack(from, e.ack_seq);
        }
        if adopted {
            self.note(
                now,
                &format!("{}.session", p.audit),
                None,
                format!("from={from}"),
            );
        }
        Received::Control
    }

    /// Apply a cumulative acknowledgement: what the peer has applied leaves the outbox. A halted link acknowledges nothing.
    fn apply_ack(&mut self, from: &str, ack: u64) {
        if let Some(l) = self.links.get_mut(from) {
            if l.halted.is_some() {
                return;
            }
            let before = l.outbox.len();
            l.outbox.retain(|o| o.seq > ack);
            if l.outbox.len() != before {
                self.tally.dirty = true;
            }
        }
    }

    fn sequenced(
        &mut self,
        p: &Profile,
        now: u64,
        from: &str,
        e: &Envelope,
        admitted: Result<Vec<u8>, String>,
    ) -> Received {
        let plain_for_hash: &[u8] = match &admitted {
            Ok(b) => b,
            Err(_) => &[],
        };
        // a refused body has no content to hash; its hash is over what the sender said it was
        let hash = match &admitted {
            Ok(_) => hash_message(&e.kind, &e.ext, plain_for_hash),
            Err(c) => hash_message(&e.kind, &e.ext, c.as_bytes()),
        };
        let Some(l) = self.links.get_mut(from) else {
            return Received::Refused("unknown-sender".into());
        };
        if e.seq < l.next_in {
            if l.applied.get(&e.seq).is_some_and(|h| *h != hash) {
                l.notice = Some(NOTICE_SEQ_CONFLICT.into());
                l.hello_wanted = true;
                self.note(
                    now,
                    &format!("{}.alert", p.audit),
                    None,
                    format!("from={from} code=seq-conflict seq={}", e.seq),
                );
                return self.refuse(p, now, from, e, "seq-conflict");
            }
            l.dups += 1;
            *self.tally.duplicates.entry(from.to_string()).or_insert(0) += 1;
            return Received::Duplicate;
        }
        if e.seq >= l.next_in + WINDOW {
            return self.refuse(p, now, from, e, "gap-beyond-window");
        }
        if let Some(h) = l.held_in.get(&e.seq) {
            if h.hash == hash {
                l.dups += 1;
                *self.tally.duplicates.entry(from.to_string()).or_insert(0) += 1;
                return Received::Duplicate;
            }
            return self.refuse(p, now, from, e, "seq-conflict");
        }
        self.tally.dirty = true;
        let (body, refusal) = match admitted {
            Ok(b) => (Some(HeldBody(b)), None),
            Err(c) => (None, Some(c)),
        };
        l.held_in.insert(
            e.seq,
            Held {
                kind: e.kind.clone(),
                ext: e.ext.clone(),
                hash,
                body,
                refusal,
            },
        );
        let mut out = Vec::new();
        loop {
            let next = l.next_in;
            let Some(h) = l.held_in.remove(&next) else {
                break;
            };
            l.next_in += 1;
            l.applied.insert(next, h.hash.clone());
            while l.applied.len() as u64 > WINDOW {
                let Some(first) = l.applied.keys().next().copied() else {
                    break;
                };
                l.applied.remove(&first);
            }
            l.ack_dirty = true;
            out.push(Delivery {
                from: from.to_string(),
                seq: next,
                kind: h.kind,
                ext: h.ext,
                hash: h.hash,
                body: match (h.body, h.refusal) {
                    (Some(b), _) => Ok(b.0),
                    (None, c) => Err(c.unwrap_or_else(|| "refused".into())),
                },
            });
        }
        if out.is_empty() {
            Received::Buffered
        } else {
            Received::Delivered(out)
        }
    }
}
