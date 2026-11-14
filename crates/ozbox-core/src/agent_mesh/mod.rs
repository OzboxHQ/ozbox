//! The agent mesh: a typed, signed, ordered, de-duplicated task channel between two endpoints that pinned each other
//! (ADR 0044, Preview). The first channel runs between a person's laptop and `main`, and replaces notes passed by hand.
//!
//! This module is self-contained on purpose. It does **not** use the hub's wire types (`crate::hub::wire`): the hub's
//! envelope is still changing, and the mesh has its own explicit version field, both epochs, an incarnation, a nonce and a
//! validity window. When the hub's sealed channel is ready the mesh bodies ride it unchanged (the body schema is the contract).
//!
//! What is here:
//! * [`wire`]: the envelope, its canonical bytes, and the fallible crypto and transport seams.
//! * [`model`]: tasks, messages, parts, artifacts, the closed list of kinds, the state table and who may move a state.
//! * [`state`]: the durable state and the pure receive and send logic that works on it.
//! * [`store`]: the file that holds the state (atomic, locked, fsynced before anything is acknowledged).
//! * [`node`]: one endpoint (state plus crypto plus audit) with `submit`, `flush`, `receive` and `exchange`.
//! * [`crypto`]: Ed25519 signing and verification through `ring`.
//!
//! What a message can do: ask. A task carries no permission, no secret and no approval. Gated acts are refused **by name**
//! in this release (there is no approval path to the laptop yet), and a Production act is refused in code at both ends.

pub mod crypto;
pub mod model;
pub mod node;
pub mod state;
pub mod store;
pub mod wire;

#[cfg(test)]
pub mod testkit;
#[cfg(test)]
mod tests;

/// A message screen: finds key-shaped content. Injected, so this crate holds no list of key shapes of its own.
pub trait Screen: Send + Sync {
    /// What kind of secret the text looks like, or `None`. Never returns the text.
    fn find(&self, text: &str) -> Option<&'static str>;
}

/// Where audit events go. The audit trail holds kinds, ids and codes, never message text.
pub trait AuditSink: Send + Sync {
    fn record(&self, ev: crate::audit::NewEvent) -> std::io::Result<()>;
}

impl AuditSink for crate::audit::AuditLog {
    fn record(&self, ev: crate::audit::NewEvent) -> std::io::Result<()> {
        self.append(ev).map(|_| ())
    }
}

/// Drop control characters (escape sequences, carriage returns) from text a peer supplied before it is printed to a terminal.
pub fn printable(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect()
}
