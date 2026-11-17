//! The channel: the one signed, sealed, ordered, de-duplicated session between two pinned Oz Box ends (ADR 0042 and 0044).
//!
//! The worker channel ([`crate::hub`]) and the agent mesh ([`crate::agent_mesh`]) are **profiles** over this module: a profile
//! says what its kinds, bodies and signed `ext` are, and the channel does everything that is the same for both.
//!
//! * [`wire`]: the [`wire::Envelope`], its canonical bytes, the [`wire::Profile`], the three crypto seams and the one
//!   [`wire::fingerprint`].
//! * [`session`]: [`session::Core`], the durable per-peer state (sessions, outbox, receive window, replay set, audit backlog) and
//!   the fixed order of checks a receiver runs.
//! * [`store`]: the generic file store (atomic, advisory-locked, fsynced before anything is acknowledged).
//! * [`audit`]: taking the audit backlog into the log under the lock, once and complete.
//! * [`ring_crypto`]: Ed25519 through `ring`.
//!
//! The module opens no connection and runs no command: a transport only moves [`wire::Sealed`] values.

pub mod audit;
pub mod flow;
pub mod ring_crypto;
pub mod session;
pub mod store;
pub mod wire;

#[cfg(test)]
pub mod testkit;
#[cfg(test)]
mod tests;
