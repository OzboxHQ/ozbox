//! Durable agent memory and reviewed skills.
//!
//! **Memory** ([`memory`]) is plain Markdown files in a git repository (readable, diffable, reviewable, revertible),
//! searched through a SQLite full-text index that is rebuilt from the files whenever they change underneath it. Notes
//! belong to a scope (a person, a project or a box). An agent reaches memory only through the tool host, and only for the
//! scopes its session is bound to; what an agent writes is a proposal that no agent can read until a person approves it.
//! No secret is ever stored: every write is scanned for the shapes of keys and tokens and refused.
//!
//! **Skills** ([`skills`]) are folders with a `SKILL.md` (the open Agent Skills format). A skill is content-addressed:
//! installing one snapshots its files under their hash, and it is usable only while a person has approved that exact
//! hash. Any change to the files is a different hash, so it needs a new approval.
//!
//! Neither module starts a run, calls a model or touches the network.

pub mod bundled;
pub mod fabric;
mod lock;
pub mod memory;
pub mod skills;

pub use lock::FileLock;
pub use ozbox_core::secret_shape;

/// Milliseconds since the Unix epoch, now.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Twelve random lowercase hex characters.
pub(crate) fn random_id() -> String {
    let mut b = [0u8; 6];
    let _ = getrandom::getrandom(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub use ozbox_core::skill_pack::name_ok;

/// Write a file by writing a sibling and renaming it over the target, so a reader never sees half a file.
pub(crate) fn write_atomic(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".{}.tmp", random_id()));
    let tmp = std::path::PathBuf::from(tmp);
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}
