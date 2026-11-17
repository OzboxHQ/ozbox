//! One peer's link at the transport layer: what is queued to it, what came from it, and how it is doing. Pure: no socket and no
//! clock of its own, so ordering, retries, replay and back-pressure are tested here without a network.
//!
//! The transport numbers frames per direction within a **transport session** (random, fresh whenever this process makes the link).
//! It retransmits what the peer has not acknowledged, after a reconnect and after a timeout; the receiver puts frames back in order
//! from a window, drops duplicates by number, and refuses an envelope it has already passed on (by its id and nonce, for as long as
//! the envelope is valid). None of this is the channel's guarantee: the channel orders, de-duplicates and refuses replays again,
//! end to end, on the signed envelope. The transport's job is to waste less and to say honestly whether the peer is reachable.

use std::collections::{BTreeMap, VecDeque};

use super::frame::{encode, Frame};
use crate::channel::wire::{Sealed, MAX_SKEW_MS};
use crate::hub::wire::PROFILE;

/// How many frames may be unacknowledged on the wire at once, per direction, and how far ahead of the next expected number the
/// receiver keeps frames that arrived early.
pub const WINDOW: u64 = 64;

/// How many frames, and how many bytes of them, a link holds for a peer that has not taken them. Past either, `send` refuses: the
/// caller (the channel's outbox) keeps the message and sends it again on the next round, so nothing is lost to the refusal.
pub const OUTBOX_FRAMES: usize = 256;
pub const OUTBOX_BYTES: usize = crate::channel::wire::TRANSPORT_CAP;

/// How many envelopes a receiver holds for its owner before it stops reading the connection (so the peer's outbox fills and its
/// `send` refuses: back-pressure end to end).
pub const INBOX_FRAMES: usize = 256;

/// The first retransmission timeout, doubled per try up to the cap.
pub const RTO_MS: u64 = 1_000;
pub const RTO_CAP_MS: u64 = 8_000;

/// The most envelope ids a link remembers for the replay window. Older ones fall out by expiry first.
pub const SEEN_CAP: usize = 4_096;

/// Counters a person and the hub's status can read. Words and numbers only: never a byte of a body.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct Stats {
    pub queued: u64,
    pub sent: u64,
    pub retransmitted: u64,
    pub delivered: u64,
    pub duplicates: u64,
    pub held_early: u64,
    pub beyond_window: u64,
    /// Envelopes whose id and nonce were already passed on: refused, never handed to the channel twice.
    pub replays: u64,
    /// Envelopes past their validity (and the skew): dropped, since the channel would refuse them.
    pub expired: u64,
    /// Envelopes that name another sender or another receiver than this connection proved: dropped.
    pub misaddressed: u64,
    pub malformed: u64,
    /// `send` calls refused because the link held too much for a peer that is not taking it.
    pub refused_full: u64,
    pub connections: u64,
    pub handshake_failures: u64,
}

/// Whether the peer can be reached, as honestly as the transport knows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum Reach {
    /// No connection has ever been made in this process's life.
    Never,
    /// Connected, authenticated both ways, since this time (ms since the epoch).
    Connected { since_ms: u64 },
    /// Was connected; nothing has been heard since this time. The person sees "not answering", never "working".
    NotAnswering { last_heard_ms: u64 },
}

/// The link holds as much as it may for a peer that is not taking it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Full;

struct Out {
    tseq: u64,
    frame: Vec<u8>,
    valid_until_ms: u64,
    sent_at_ms: Option<u64>,
    tries: u32,
}

/// One peer's link.
pub struct LinkState {
    me: String,
    peer: String,
    tx_session: u64,
    next: u64,
    out: VecDeque<Out>,
    out_bytes: usize,
    rx_session: u64,
    rx_upto: u64,
    early: BTreeMap<u64, Sealed>,
    seen: BTreeMap<(String, Vec<u8>), u64>,
    ack_owed: bool,
    /// The last acknowledgement heard and how many times in a row it did not move while frames were out: a receiver that keeps
    /// acknowledging the same number is holding later frames behind a lost one, so the first is sent again without waiting.
    last_ack: u64,
    same_acks: u32,
    pub stats: Stats,
    /// The peer sent a heartbeat; the writer answers it (the reader never writes, so frames never interleave).
    pub pong_owed: bool,
    /// Which connection owns the link; a newer one replaces an older, which stops.
    pub gen: u64,
    connected_since: Option<u64>,
    last_heard: Option<u64>,
}

/// What each side tells the other in the handshake about this link: its sending session and the number below which it holds
/// nothing, and the session it last received from and the highest number it passed on from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Resume {
    pub tx_session: u64,
    pub tx_base: u64,
    pub rx_session: u64,
    pub rx_upto: u64,
}

fn expired(valid_until_ms: u64, now: u64) -> bool {
    valid_until_ms.saturating_add(MAX_SKEW_MS) < now
}

impl LinkState {
    pub fn new(me: &str, peer: &str, tx_session: u64) -> LinkState {
        LinkState {
            me: me.to_string(),
            peer: peer.to_string(),
            tx_session,
            next: 1,
            out: VecDeque::new(),
            out_bytes: 0,
            rx_session: 0,
            rx_upto: 0,
            early: BTreeMap::new(),
            seen: BTreeMap::new(),
            ack_owed: false,
            last_ack: 0,
            same_acks: 0,
            stats: Stats::default(),
            pong_owed: false,
            gen: 0,
            connected_since: None,
            last_heard: None,
        }
    }

    pub fn connected(&self) -> bool {
        self.connected_since.is_some()
    }

    pub fn reach(&self) -> Reach {
        match (self.connected_since, self.last_heard) {
            (Some(since_ms), _) => Reach::Connected { since_ms },
            (None, Some(last_heard_ms)) => Reach::NotAnswering { last_heard_ms },
            (None, None) => Reach::Never,
        }
    }

    pub fn last_heard(&self) -> Option<u64> {
        self.last_heard
    }

    /// How many frames are waiting for the peer to acknowledge them.
    pub fn queued(&self) -> usize {
        self.out.len()
    }

    /// Queue an envelope for the peer. Refused (and counted) when the link already holds as much as it may: the caller keeps the
    /// message. While the peer is away, envelopes that have expired are dropped first, since nobody would accept them.
    pub fn queue(&mut self, msg: &Sealed, now: u64) -> Result<(), Full> {
        if !self.connected() {
            self.purge_expired(now);
        }
        let tseq = self.next;
        let frame = encode(&Frame::Data(tseq, Box::new(msg.clone())));
        if self.out.len() >= OUTBOX_FRAMES || self.out_bytes + frame.len() > OUTBOX_BYTES {
            self.stats.refused_full += 1;
            return Err(Full);
        }
        self.next += 1;
        self.out_bytes += frame.len();
        self.out.push_back(Out {
            tseq,
            frame,
            valid_until_ms: msg.envelope.valid_until_ms,
            sent_at_ms: None,
            tries: 0,
        });
        self.stats.queued += 1;
        Ok(())
    }

    fn purge_expired(&mut self, now: u64) {
        let before = self.out.len();
        self.out.retain(|o| !expired(o.valid_until_ms, now));
        if self.out.len() != before {
            self.out_bytes = self.out.iter().map(|o| o.frame.len()).sum();
        }
    }

    /// What this end says in the handshake.
    pub fn resume(&self, now: u64) -> Resume {
        // everything below the first frame still held is acknowledged or was given up as expired
        let first = self
            .out
            .iter()
            .find(|o| !expired(o.valid_until_ms, now))
            .map_or(self.next, |o| o.tseq);
        Resume {
            tx_session: self.tx_session,
            tx_base: first - 1,
            rx_session: self.rx_session,
            rx_upto: self.rx_upto,
        }
    }

    /// A connection was authenticated; `peer` is what the other end said. Drops what the peer already has and marks the rest to be
    /// sent again on this connection, in order.
    pub fn on_connected(&mut self, peer: Resume, now: u64) {
        self.purge_expired(now);
        if peer.rx_session == self.tx_session {
            self.drop_acked(peer.rx_upto);
        }
        for o in &mut self.out {
            o.sent_at_ms = None;
            o.tries = 0;
        }
        if peer.tx_session != self.rx_session {
            // a new sending session on the peer (it started, or restarted): what came before is gone with it
            self.rx_session = peer.tx_session;
            self.rx_upto = peer.tx_base;
            self.early.clear();
        } else if peer.tx_base > self.rx_upto {
            // the peer gave up frames it could no longer deliver (expired): skip past them
            self.rx_upto = peer.tx_base;
            self.early.retain(|n, _| *n > peer.tx_base);
        }
        self.connected_since = Some(now);
        self.last_heard = Some(now);
        self.ack_owed = true;
        self.same_acks = 0;
        self.stats.connections += 1;
    }

    pub fn on_disconnected(&mut self) {
        self.connected_since = None;
    }

    pub fn heard(&mut self, now: u64) {
        self.last_heard = Some(now);
    }

    fn drop_acked(&mut self, upto: u64) {
        while self.out.front().is_some_and(|o| o.tseq <= upto) {
            if let Some(o) = self.out.pop_front() {
                self.out_bytes -= o.frame.len();
            }
        }
    }

    /// A cumulative acknowledgement from the peer.
    pub fn on_ack(&mut self, upto: u64) {
        if upto >= self.next {
            return;
        }
        if upto == self.last_ack && self.out.front().is_some_and(|o| o.sent_at_ms.is_some()) {
            self.same_acks += 1;
            if self.same_acks >= 2 {
                // fast retransmit: make the first frame due now
                if let Some(o) = self.out.front_mut() {
                    o.sent_at_ms = Some(0);
                }
                self.same_acks = 0;
            }
        } else {
            self.same_acks = 0;
        }
        self.last_ack = upto;
        self.drop_acked(upto);
    }

    /// A data frame from the peer. Envelopes the owner may take are appended to `inbox`, in order.
    pub fn on_data(&mut self, tseq: u64, msg: Sealed, now: u64, inbox: &mut VecDeque<Sealed>) {
        self.ack_owed = true;
        if tseq <= self.rx_upto {
            self.stats.duplicates += 1;
            return;
        }
        if tseq > self.rx_upto + WINDOW {
            self.stats.beyond_window += 1;
            return;
        }
        if tseq > self.rx_upto + 1 {
            if self.early.insert(tseq, msg).is_none() {
                self.stats.held_early += 1;
            } else {
                self.stats.duplicates += 1;
            }
            return;
        }
        self.rx_upto = tseq;
        self.admit(msg, now, inbox);
        while let Some(m) = self.early.remove(&(self.rx_upto + 1)) {
            self.rx_upto += 1;
            self.admit(m, now, inbox);
        }
    }

    /// The checks the transport can make without a key: the envelope is addressed from the peer this connection proved, to this
    /// end; it is well formed; it is still valid; and it was not passed on before. The signature, the seal, the session, order and
    /// replay are checked again by the channel, which is the guarantee.
    fn admit(&mut self, msg: Sealed, now: u64, inbox: &mut VecDeque<Sealed>) {
        let e = &msg.envelope;
        // the conversation fabric rides this connection under `<box>.fabric` endpoints (its own profile and kinds); everything
        // else is the worker channel's
        let fabric =
            e.from == format!("{}.fabric", self.peer) && e.to == format!("{}.fabric", self.me);
        if !fabric && (e.from != self.peer || e.to != self.me) {
            self.stats.misaddressed += 1;
            return;
        }
        let shaped = if fabric {
            e.check(&crate::fabric::wire::PROFILE)
        } else {
            e.check(&PROFILE)
        };
        if shaped.is_err() {
            self.stats.malformed += 1;
            return;
        }
        if expired(e.valid_until_ms, now) {
            self.stats.expired += 1;
            return;
        }
        self.seen.retain(|_, until| !expired(*until, now));
        let key = (e.id.clone(), e.nonce.clone());
        if self.seen.contains_key(&key) {
            self.stats.replays += 1;
            return;
        }
        if self.seen.len() >= SEEN_CAP {
            // the oldest-expiring falls out first; the channel's own nonce memory still holds it
            if let Some(k) = self
                .seen
                .iter()
                .min_by_key(|(_, u)| **u)
                .map(|(k, _)| k.clone())
            {
                self.seen.remove(&k);
            }
        }
        self.seen.insert(key, e.valid_until_ms);
        self.stats.delivered += 1;
        inbox.push_back(msg);
    }

    /// The acknowledgement to send, if one is owed.
    pub fn take_ack(&mut self) -> Option<u64> {
        std::mem::take(&mut self.ack_owed).then_some(self.rx_upto)
    }

    /// The frames to write now: those within the window not yet sent on this connection, and those whose timeout has passed.
    pub fn due(&mut self, now: u64) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let first = self.out.front().map_or(self.next, |o| o.tseq);
        for o in self.out.iter_mut() {
            if o.tseq >= first + WINDOW {
                break;
            }
            let due = match o.sent_at_ms {
                None => true,
                Some(at) => {
                    let rto = (RTO_MS << o.tries.min(3)).min(RTO_CAP_MS);
                    now >= at + rto
                }
            };
            if due {
                if o.sent_at_ms.is_some() {
                    self.stats.retransmitted += 1;
                    o.tries += 1;
                } else {
                    self.stats.sent += 1;
                }
                o.sent_at_ms = Some(now);
                out.push(o.frame.clone());
            }
        }
        out
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::channel::wire::{Envelope, VERSION};
    use crate::hub::wire::Ext;

    const NOW: u64 = 1_000_000;

    fn env(from: &str, to: &str, id: &str, nonce: u8) -> Sealed {
        Sealed {
            envelope: Envelope {
                version: VERSION,
                kind: "status".into(),
                from: from.into(),
                to: to.into(),
                receiver_fp: "ab".into(),
                sender_epoch: 1,
                receiver_epoch: 1,
                sender_inc: 5,
                receiver_inc: 6,
                seq: 1,
                ack_seq: 0,
                id: id.into(),
                ts_ms: NOW,
                valid_until_ms: NOW + 60_000,
                nonce: vec![nonce; 16],
                ext: Ext::at(1).encode(),
                body: b"ciphertext".to_vec(),
            },
            signature: vec![1, 2, 3],
        }
    }

    fn pair() -> (LinkState, LinkState) {
        let mut a = LinkState::new("w", "main", 11);
        let mut b = LinkState::new("main", "w", 22);
        let (ra, rb) = (a.resume(NOW), b.resume(NOW));
        a.on_connected(rb, NOW);
        b.on_connected(ra, NOW);
        (a, b)
    }

    fn frames(v: Vec<Vec<u8>>) -> Vec<(u64, Sealed)> {
        v.into_iter()
            .map(|b| {
                let mut rd = super::super::frame::FrameReader::default();
                let mut s: &[u8] = &b;
                match rd.next(&mut s, super::super::frame::MAX_FRAME) {
                    Ok(Some(Frame::Data(n, m))) => (n, *m),
                    other => panic!("not a data frame: {other:?}"),
                }
            })
            .collect()
    }

    #[test]
    fn reordered_and_duplicated_frames_reach_the_owner_once_and_in_order() {
        let (mut w, mut hub) = pair();
        for i in 0..5u8 {
            w.queue(&env("w", "main", &format!("m{i}"), i), NOW)
                .unwrap();
        }
        let mut fs = frames(w.due(NOW));
        fs.reverse();
        fs.push(fs[1].clone());
        let mut inbox = VecDeque::new();
        for (n, m) in fs {
            hub.on_data(n, m, NOW, &mut inbox);
        }
        let ids: Vec<_> = inbox.iter().map(|m| m.envelope.id.clone()).collect();
        assert_eq!(ids, ["m0", "m1", "m2", "m3", "m4"]);
        assert_eq!(hub.stats.duplicates, 1);
        assert_eq!(hub.take_ack(), Some(5));
    }

    #[test]
    fn a_dropped_frame_is_sent_again_after_its_timeout_and_fills_the_gap() {
        let (mut w, mut hub) = pair();
        for i in 0..3u8 {
            w.queue(&env("w", "main", &format!("m{i}"), i), NOW)
                .unwrap();
        }
        let fs = frames(w.due(NOW));
        let mut inbox = VecDeque::new();
        // the first is lost on the way
        for (n, m) in fs.into_iter().skip(1) {
            hub.on_data(n, m, NOW, &mut inbox);
        }
        assert!(inbox.is_empty());
        w.on_ack(hub.take_ack().unwrap());
        assert!(
            w.due(NOW + 10).is_empty(),
            "nothing is due before the timeout"
        );
        let again = frames(w.due(NOW + RTO_MS));
        assert_eq!(again.len(), 3, "the unacknowledged window is sent again");
        for (n, m) in again {
            hub.on_data(n, m, NOW + RTO_MS, &mut inbox);
        }
        assert_eq!(inbox.len(), 3);
        w.on_ack(hub.take_ack().unwrap());
        assert_eq!(w.queued(), 0);
        assert_eq!(w.stats.retransmitted, 3);
    }

    #[test]
    fn an_acknowledgement_that_does_not_move_resends_the_first_frame_at_once() {
        let (mut w, mut hub) = pair();
        for i in 0..4u8 {
            w.queue(&env("w", "main", &format!("m{i}"), i), NOW)
                .unwrap();
        }
        let mut inbox = VecDeque::new();
        for (n, m) in frames(w.due(NOW)).into_iter().skip(1) {
            hub.on_data(n, m, NOW, &mut inbox);
            w.on_ack(hub.take_ack().unwrap());
        }
        let again = frames(w.due(NOW + 1));
        assert_eq!(again.first().map(|(n, _)| *n), Some(1));
    }

    #[test]
    fn an_envelope_passed_on_once_is_refused_again_under_a_new_transport_number() {
        let (mut w, mut hub) = pair();
        let m = env("w", "main", "m0", 9);
        let mut inbox = VecDeque::new();
        hub.on_data(1, m.clone(), NOW, &mut inbox);
        // a party on the path writes the captured envelope into the stream under the next number
        hub.on_data(2, m, NOW + 5, &mut inbox);
        assert_eq!(inbox.len(), 1);
        assert_eq!(hub.stats.replays, 1);
        let _ = w.due(NOW);
    }

    #[test]
    fn an_envelope_from_another_sender_or_for_another_receiver_is_dropped() {
        let (_, mut hub) = pair();
        let mut inbox = VecDeque::new();
        hub.on_data(1, env("w2", "main", "a", 1), NOW, &mut inbox);
        hub.on_data(2, env("w", "other", "b", 2), NOW, &mut inbox);
        assert!(inbox.is_empty());
        assert_eq!(hub.stats.misaddressed, 2);
    }

    #[test]
    fn an_expired_envelope_is_dropped_and_not_sent_to_a_peer_that_is_away() {
        let (mut w, mut hub) = pair();
        let mut inbox = VecDeque::new();
        hub.on_data(
            1,
            env("w", "main", "a", 1),
            NOW + 60_000 + MAX_SKEW_MS + 1,
            &mut inbox,
        );
        assert_eq!(hub.stats.expired, 1);
        w.on_disconnected();
        w.queue(&env("w", "main", "b", 2), NOW).unwrap();
        let mut c = env("w", "main", "c", 3);
        c.envelope.valid_until_ms = NOW + 300_000;
        w.queue(&c, NOW + 200_000).unwrap();
        // the first expired while the hub was away: the next session starts past it
        let r = w.resume(NOW + 60_000 + MAX_SKEW_MS + 1);
        assert_eq!(r.tx_base, 1);
    }

    #[test]
    fn a_full_link_refuses_and_counts_so_the_channel_keeps_the_message() {
        let (mut w, _) = pair();
        for i in 0..OUTBOX_FRAMES {
            w.queue(&env("w", "main", &format!("m{i}"), 1), NOW)
                .unwrap();
        }
        assert!(w.queue(&env("w", "main", "one-more", 1), NOW).is_err());
        assert_eq!(w.stats.refused_full, 1);
    }

    #[test]
    fn only_a_window_of_frames_is_on_the_wire_at_once() {
        let (mut w, _) = pair();
        for i in 0..(WINDOW as usize + 10) {
            w.queue(&env("w", "main", &format!("m{i}"), 1), NOW)
                .unwrap();
        }
        assert_eq!(w.due(NOW).len(), WINDOW as usize);
    }

    #[test]
    fn a_reconnect_resends_only_what_the_peer_did_not_pass_on() {
        let (mut w, mut hub) = pair();
        for i in 0..4u8 {
            w.queue(&env("w", "main", &format!("m{i}"), i), NOW)
                .unwrap();
        }
        let fs = frames(w.due(NOW));
        let mut inbox = VecDeque::new();
        for (n, m) in fs.into_iter().take(2) {
            hub.on_data(n, m, NOW, &mut inbox);
        }
        // the connection drops before the ack reaches the worker
        w.on_disconnected();
        hub.on_disconnected();
        let (rw, rh) = (w.resume(NOW), hub.resume(NOW));
        w.on_connected(rh, NOW);
        hub.on_connected(rw, NOW);
        let again = frames(w.due(NOW));
        assert_eq!(again.iter().map(|(n, _)| *n).collect::<Vec<_>>(), [3, 4]);
        for (n, m) in again {
            hub.on_data(n, m, NOW, &mut inbox);
        }
        assert_eq!(inbox.len(), 4);
    }

    #[test]
    fn a_peer_that_restarted_is_taken_from_its_new_session() {
        let (mut w, mut hub) = pair();
        let mut inbox = VecDeque::new();
        w.queue(&env("w", "main", "a", 1), NOW).unwrap();
        for (n, m) in frames(w.due(NOW)) {
            hub.on_data(n, m, NOW, &mut inbox);
        }
        // the worker's process restarts: a new link, a new session, numbers from 1 again
        let mut w2 = LinkState::new("w", "main", 99);
        w2.queue(&env("w", "main", "b", 2), NOW).unwrap();
        hub.on_disconnected();
        let (rw, rh) = (w2.resume(NOW), hub.resume(NOW));
        w2.on_connected(rh, NOW);
        hub.on_connected(rw, NOW);
        for (n, m) in frames(w2.due(NOW)) {
            hub.on_data(n, m, NOW, &mut inbox);
        }
        assert_eq!(inbox.len(), 2);
    }

    #[test]
    fn reach_says_never_then_connected_then_not_answering() {
        let mut l = LinkState::new("main", "w", 1);
        assert_eq!(l.reach(), Reach::Never);
        l.on_connected(LinkState::new("w", "main", 2).resume(NOW), NOW);
        assert_eq!(l.reach(), Reach::Connected { since_ms: NOW });
        l.heard(NOW + 5);
        l.on_disconnected();
        assert_eq!(
            l.reach(),
            Reach::NotAnswering {
                last_heard_ms: NOW + 5
            }
        );
    }
}
