//! The agent mesh: a typed task channel between two endpoints that pinned each other (ADR 0044, Preview). The first channel runs
//! between a person's laptop and `main`, and replaces notes passed by hand.
//!
//! The mesh is a **profile** of the shared channel ([`crate::channel`]): the envelope, the sessions, the order, the replay set, the
//! durable store and the audit drain are the channel's, and are the same code the worker channel runs. What is the mesh's own is here:
//!
//! * [`PROFILE`]: the domain tag, the five kinds (`task`, `message`, `status`, `artifact`, `cancel`), the body cap and the signed
//!   `ext`, which names the task as `<sender of the task>/<task id>`.
//! * [`model`]: tasks, messages, parts, artifacts, the state table and who may move a state.
//! * [`state`]: the task state beside the channel's core, and the logic that applies what the channel delivers.
//! * [`node`]: one endpoint (state, crypto, screen, audit) with `submit`, `reply`, `outbound`, `receive_all`, `serve` and `sync`.
//!
//! What a message can do: ask. A task carries no permission, no secret and no approval. Gated acts are refused **by name** in this
//! release (there is no approval path to the laptop yet), and a Production act is refused in code at both ends.

pub mod model;
pub mod node;
pub mod state;

#[cfg(test)]
pub mod testkit;
#[cfg(test)]
mod tests;

pub use crate::channel::audit::AuditSink;
pub use crate::channel::wire::word_ok;
use crate::channel::wire::Profile;

/// The mesh as a profile of the channel.
pub static PROFILE: Profile = Profile {
    tag: "ozbox-mesh-envelope",
    audit: "mesh",
    kinds: &["task", "message", "status", "artifact", "cancel"],
    max_body: 96 * 1024,
    check_ext: |_, ext| split_key_bytes(ext).is_some(),
};

/// The key a task is stored and addressed under: the **sender of the task**, a slash, the task's id. Two ends can therefore never
/// overwrite each other's tasks by choosing the same id, and an id means the same thing on the wire and on disk.
pub fn task_key(origin: &str, id: &str) -> String {
    format!("{origin}/{id}")
}

/// The two halves of a task key, when it is well formed.
pub fn split_key(key: &str) -> Option<(&str, &str)> {
    let (origin, id) = key.split_once('/')?;
    (word_ok(origin) && word_ok(id)).then_some((origin, id))
}

fn split_key_bytes(ext: &[u8]) -> Option<(&str, &str)> {
    split_key(std::str::from_utf8(ext).ok()?)
}

/// A message screen: finds key-shaped content. Injected, so this crate holds no list of key shapes of its own.
pub trait Screen: Send + Sync {
    /// What kind of secret the text looks like, or `None`. Never returns the text.
    fn find(&self, text: &str) -> Option<&'static str>;
}

/// Unicode "format" characters: bidirectional overrides and isolates, zero-width characters, the byte order mark and the like. They
/// are invisible and reorder what is drawn, so a line can show other words than it holds.
fn is_format(c: char) -> bool {
    matches!(c,
        '\u{00AD}' | '\u{0600}'..='\u{0605}' | '\u{061C}' | '\u{06DD}' | '\u{070F}' | '\u{180E}'
        | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2064}'
        | '\u{2066}'..='\u{206F}' | '\u{FEFF}' | '\u{FFF9}'..='\u{FFFB}' | '\u{E0001}' | '\u{E0020}'..='\u{E007F}')
}

/// Text a peer supplied, made safe to print to a terminal: control characters (escape sequences, carriage returns) and format
/// characters (bidi overrides) are dropped. A newline and a tab stay, so a message body keeps its lines.
pub fn printable(text: &str) -> String {
    text.chars()
        .filter(|c| (!c.is_control() || *c == '\n' || *c == '\t') && !is_format(*c))
        .collect()
}

/// For a field that must stay on one line (a title, a name, a reason, a state): like [`printable`] but line breaks become spaces,
/// so a peer cannot print what looks like another row of the inbox.
pub fn printable_line(text: &str) -> String {
    text.chars()
        .filter(|c| !is_format(*c))
        // U+2028 and U+2029 are line and paragraph separators that are neither control nor format characters
        .map(|c| {
            if c.is_control() || c == '\u{2028}' || c == '\u{2029}' {
                ' '
            } else {
                c
            }
        })
        .collect()
}
