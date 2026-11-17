//! The hub daemon on `main`, worker enrolment with key attestation, and the real signer and sealer (ADR 0042).
//!
//! * [`identity`]: an end's four purpose keys (public) and the fingerprints that name them.
//! * [`keys`]: the private halves and the operations the **secrets service** answers with them (it calls [`keys::handle`]).
//! * [`ops`]: the seam to that service ([`ops::KeyOps`]): its socket, or the same handler in-process for tests.
//! * [`crypto`]: the signer, sealer and verifier behind `ozbox_core::channel`'s seams: HPKE through `ozbox-seal`, Ed25519.
//! * [`seams`]: those put together for the hub (`HubService`) and for a worker.
//! * [`enrol`]: invites, requests, attestations, plan and apply.
//! * [`daemon`]: `ozbox-hubd` itself: verify, spool, enrol, handshake, and its socket.
//! * [`registrar`]: the registrars that vouch for a worker (AWS claim path, your computer, `repin`).
//! * [`selftest`]: what must hold before it is trusted.
//! * [`setup`]: the units and folders, written by the script this program carries.
//!
//! * [`agent`]: a worker's hub agent: the worker's end of the channel, the engine runs, keys by name, the loss rule.
//! * [`nethost`]: the network end, inside the daemon: workers dial out, the daemon checks and spools, the roster follows enrolment.
//! * [`supervised`]: the worker's real run path: a task is a supervised run of the box (ADR 0014), queued in its task store.
//! * [`fleet`]: the three seams of sealed key delivery, backed by enrolment's attestations and the secrets service.
//!
//! What is **not** here: the registrars that vouch for a worker's keys on a real box (a separate crate module).

#![cfg(unix)]

pub mod agent;
pub mod crypto;
pub mod daemon;
pub mod enrol;
pub mod fleet;
pub mod identity;
pub mod keys;
pub mod nethost;
pub mod ops;
pub mod registrar;
pub mod seams;
pub mod selftest;
pub mod setup;
pub mod supervised;
pub mod workerbin;

#[cfg(test)]
mod tests;
