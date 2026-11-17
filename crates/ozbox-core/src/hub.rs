//! The hub: `main` hands work to worker boxes and reads their reports (ADR 0042), as the **pure core** of it.
//!
//! What is here, and only this (the first slice of phase H1, and the Production refusal of decision D2):
//!
//! * [`wire`]: the worker channel's **profile** of the shared envelope ([`crate::channel`], which the agent mesh uses too): the closed
//!   list of message kinds and who may send which, and the signed `ext` (the sender's level in the tree and the relay hops). The
//!   envelope, its canonical bytes, sessions, order, replay and acknowledgement are the channel's. The kinds, `level` and `via` are
//!   pinned by golden vectors in `hub/tests.rs` (computed by a separate script): a change to any of them fails there first. The format
//!   freezes when the first real transport ships; until then it is revised with new vectors.
//! * [`refusal`]: a worker is never given a Production credential in this release. One function, [`refusal::refuse_production`],
//!   with no flag, no setting and no argument that turns it off. It runs **on the hub before an assignment is made and again on
//!   the worker before it is accepted**, so a hub that has been taken over still cannot hand a worker a Production *label*. These are label checks (the declaration's
//!   environment and key names); the check of the delivered value is H3a and is not built yet.
//! * [`engine`]: the hub's side. It assigns a task to a worker named in the roster, checks every report (through the channel's fixed
//!   order of checks) and keeps the latest report per worker so the conductor can read it. Its state (the channel's core plus the
//!   reports) persists through the channel's store when it runs as a service. It opens no network connection and no shell.
//! * [`worker`]: the worker's side, the part the worker's own service runs.
//! * [`mem`]: an in-memory transport for tests and for the fake fleet.
//! * [`net`]: the transport on a network. Workers dial out to the hub; the hub listens on a loopback or private address only;
//!   a signed handshake under its own tag on each connection; order, retransmission, a replay window, back-pressure and honest
//!   reachability at the transport layer. It carries sealed envelopes and never opens one.
//! * [`conformance`]: what any transport must let the hub and its workers do; the in-memory and the network transport both pass it.
//!
//! What is **not** here: `ozbox-hubd` (the process the network reaches), enrolment and key attestation, sealed key delivery, the
//! merge queue over the channel, test lanes, and the approval path. Signing and sealing are traits ([`wire::Signer`],
//! [`wire::Sealer`]); the real ones are the secrets service's operations and `ozbox-seal`, wired in the next slice. A fleet role
//! (ADR 0040) is not needed to *decide* a hand-off; it is needed to *reach* a box, and that is the transport's job.

#[doc(hidden)]
pub mod conformance;
pub mod engine;
pub mod mem;
pub mod net;
pub mod refusal;
pub mod wire;
pub mod worker;

#[cfg(test)]
mod tests;
