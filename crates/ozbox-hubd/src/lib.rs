//! The hub daemon on `main`, worker enrolment with key attestation, and the real signer and sealer (ADR 0042).
//!
//! * [`identity`]: an end's four purpose keys (public) and the fingerprints that name them.
//! * [`keys`]: the private halves and the operations the **secrets service** answers with them (it calls [`keys::handle`]).
//! * [`ops`]: the seam to that service ([`ops::KeyOps`]): its socket, or the same handler in-process for tests.
//! * [`crypto`]: the signer, sealer and verifier behind `ozbox_core::channel`'s seams: HPKE through `ozbox-seal`, Ed25519.
//! * [`seams`]: those put together for the hub (`HubService`) and for a worker.
//! * [`enrol`]: invites, requests, attestations, plan and apply.
//! * [`daemon`]: `ozbox-hubd` itself: verify, spool, enrol, handshake, and its socket.
//! * [`selftest`]: what must hold before it is trusted.
//! * [`setup`]: the units and folders, written by the script this program carries.
//!
//! What is **not** here: the network transport (a worker dials out to the hub; built behind `ozbox_core::hub::wire::Transport`
//! separately), sealed key delivery, the approval path and the merge queue over the channel.

#![cfg(unix)]

pub mod crypto;
pub mod daemon;
pub mod enrol;
pub mod identity;
pub mod keys;
pub mod ops;
pub mod seams;
pub mod selftest;
pub mod setup;

#[cfg(test)]
mod tests;
