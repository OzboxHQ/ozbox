//! The two moves every node makes with a [`Core`]: seal and sign what a peer is owed, and take what a peer sent, as one round.

use super::session::{Admit, Core, Delivery, Draft, Received};
use super::wire::{seal_and_sign, Crypto, Profile, Sealed, WireError, WINDOW};

/// The most envelopes one round takes from a peer: a `hello`, an `ack` and a window of messages. Anything beyond is counted as one
/// refusal and never looked at, so one reply cannot cost thousands of checks, writes or audit entries.
pub const MAX_PER_ROUND: usize = WINDOW as usize + 2;

/// Seal and sign drafts: a fresh nonce and validity were put in at draft time, so every attempt is a new envelope.
pub fn seal_drafts(
    p: &Profile,
    cx: &Crypto<'_>,
    drafts: &[Draft],
) -> Result<Vec<Sealed>, WireError> {
    drafts
        .iter()
        .map(|d| seal_and_sign(p, d.env.clone(), &d.seal_key, &d.plain, cx))
        .collect()
}

/// What a round took.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RoundReport {
    pub deliveries: Vec<Delivery>,
    pub control: usize,
    pub buffered: usize,
    pub duplicates: usize,
    /// The refusal codes, in order (also counted or audited by the core).
    pub refused: Vec<String>,
}

/// Take a batch from a peer: each envelope through the fixed checks, the surplus counted, the round's events emitted once. Call
/// inside one store write.
pub fn receive_round(
    core: &mut Core,
    p: &Profile,
    cx: &Crypto<'_>,
    admit: Admit<'_>,
    now: u64,
    msgs: &[Sealed],
) -> RoundReport {
    let mut r = RoundReport::default();
    for m in msgs.iter().take(MAX_PER_ROUND) {
        match core.receive(p, cx, admit, now, m) {
            Received::Refused(c) => r.refused.push(c),
            Received::Duplicate => r.duplicates += 1,
            Received::Control => r.control += 1,
            Received::Buffered => r.buffered += 1,
            Received::Delivered(d) => r.deliveries.extend(d),
        }
    }
    let surplus = msgs.len().saturating_sub(MAX_PER_ROUND);
    if surplus > 0 {
        *core
            .tally
            .unverified
            .entry("round-too-large".into())
            .or_insert(0) += surplus as u64;
        r.refused.push("round-too-large".into());
    }
    core.end_round(p, now);
    r
}
