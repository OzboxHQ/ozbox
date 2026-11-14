//! A skill as a set of files: what it may hold, how it is checked, and the hash a person approves.
//!
//! This is the one place the rules live. The dashboard's library, the box daemon (which re-checks and re-hashes what it is
//! sent before it writes anything to a box's disk) and the command line all use it, so a skill that passes one passes all.
//! A skill is a folder with a `SKILL.md` (the open Agent Skills format) and a few text files beside it. Only text: a skill
//! is content an agent will follow, so a person must be able to read all of it.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::Path;

use ring::digest;

use crate::secret_shape::find_secret;

pub const MAX_FILES: usize = 50;
pub const MAX_FILE_BYTES: usize = 128 * 1024;
pub const MAX_TOTAL_BYTES: usize = 512 * 1024;
/// The largest JSON body that can carry a skill's files: the worst case is every byte written as a six-byte `\u00XX`
/// escape, plus room for 50 paths and the wrapper. A request over this is refused before it is read.
pub const MAX_PACK_BODY: usize = 6 * MAX_TOTAL_BYTES + 32 * 1024;
const _: () = assert!(MAX_PACK_BODY > 6 * MAX_TOTAL_BYTES);

const TEXT_EXT: &[&str] = &[
    "md", "txt", "json", "yaml", "yml", "toml", "sh", "py", "js", "ts", "rs", "sql", "html", "css",
    "csv",
];
/// Files an agent may run, not only read. They stay text, are never made executable, and the review marks them.
const SCRIPT_EXT: &[&str] = &["sh", "py", "js", "ts", "rs", "sql"];

pub fn text_extensions() -> &'static [&'static str] {
    TEXT_EXT
}

/// What a file in a skill is: the instructions, a script an agent may run, or other text.
pub fn file_kind(path: &str) -> &'static str {
    if path == "SKILL.md" {
        return "instructions";
    }
    let ext = path.rsplit('.').next().unwrap_or("");
    if SCRIPT_EXT.contains(&ext) {
        "script"
    } else {
        "text"
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkillError {
    Invalid(String),
    NotFound,
    /// Not allowed (not installed, a stale approval, a name already taken).
    Refused(String),
    /// A person has not approved these exact files, so nothing may hand them to an agent.
    NotApproved(String),
    Io(String),
}

impl fmt::Display for SkillError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SkillError::Invalid(s)
            | SkillError::Refused(s)
            | SkillError::NotApproved(s)
            | SkillError::Io(s) => f.write_str(s),
            SkillError::NotFound => f.write_str("there is no such skill"),
        }
    }
}

impl std::error::Error for SkillError {}

fn io<E: fmt::Display>(e: E) -> SkillError {
    SkillError::Io(format!("the skills store could not be used: {e}"))
}

/// A name that is safe to use as a file or folder name: letters, digits, `.`, `_`, `-`; 1 to 64; no leading dot.
pub fn name_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && !s.starts_with('.')
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

/// A skill's name: a folder name with no dot.
pub fn skill_name_ok(s: &str) -> bool {
    name_ok(s) && !s.contains('.')
}

/// A skill's files, in memory. Built from a folder, from files sent over the wire, or from those shipped in the program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillPack {
    pub name: String,
    pub description: String,
    pub version: String,
    /// The author's licence as an SPDX identifier, from the `license:` line of the front matter. Optional here so that
    /// existing skills keep loading; shown before a skill is approved.
    pub license: Option<String>,
    pub files: BTreeMap<String, Vec<u8>>,
}

/// Does this look like an SPDX licence expression (`Apache-2.0`, `MIT OR Apache-2.0`)? Plain characters only.
pub fn spdx_ok(l: &str) -> bool {
    !l.is_empty()
        && l.len() <= 64
        && l.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+' | b' ' | b'(' | b')')
        })
}

/// `key: value` lines between the first two `---` lines of a `SKILL.md`.
fn front_matter(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut lines = text.lines();
    if lines.next().map(str::trim) != Some("---") {
        return out;
    }
    for l in lines {
        if l.trim() == "---" {
            break;
        }
        if let Some((k, v)) = l.split_once(':') {
            let v = v.trim().trim_matches(['"', '\'']);
            out.insert(k.trim().to_string(), v.to_string());
        }
    }
    out
}

fn path_ok(p: &str) -> bool {
    let parts: Vec<&str> = p.split('/').collect();
    !parts.is_empty() && parts.len() <= 4 && parts.iter().all(|c| name_ok(c))
}

/// A character a reviewer cannot see or that changes how text reads: control characters (other than newline, return and
/// tab), zero-width and direction-changing characters, and Unicode tag characters. A skill with one would not say to the
/// agent what it says to the person who approved it.
fn hidden(c: char) -> bool {
    (c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
        || matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}' | '\u{FEFF}' | '\u{00AD}' | '\u{E0000}'..='\u{E007F}'
            | '\u{FE00}'..='\u{FE0F}' | '\u{180E}')
}

impl SkillPack {
    pub fn from_files(files: BTreeMap<String, Vec<u8>>) -> Result<SkillPack, SkillError> {
        if files.len() > MAX_FILES {
            return Err(SkillError::Invalid(format!(
                "a skill has at most {MAX_FILES} files"
            )));
        }
        let total: usize = files.values().map(Vec::len).sum();
        if total > MAX_TOTAL_BYTES {
            return Err(SkillError::Invalid(format!(
                "a skill is at most {} KB in all",
                MAX_TOTAL_BYTES / 1024
            )));
        }
        let mut lower = BTreeMap::new();
        for p in files.keys() {
            if lower.insert(p.to_ascii_lowercase(), p).is_some() {
                return Err(SkillError::Invalid(format!(
                    "{p}: two files differ only by upper and lower case"
                )));
            }
        }
        for p in files.keys() {
            if files.keys().any(|q| {
                q.len() > p.len() && q.starts_with(p.as_str()) && q.as_bytes()[p.len()] == b'/'
            }) {
                return Err(SkillError::Invalid(format!(
                    "{p} is both a file and a folder"
                )));
            }
        }
        for (p, b) in &files {
            if !path_ok(p) {
                return Err(SkillError::Invalid(format!(
                    "{p} is not an allowed file name"
                )));
            }
            let ext = p.rsplit('.').next().unwrap_or("");
            if !TEXT_EXT.contains(&ext) {
                return Err(SkillError::Invalid(format!(
                    "{p}: a skill holds text files only ({})",
                    TEXT_EXT.join(", ")
                )));
            }
            if b.len() > MAX_FILE_BYTES {
                return Err(SkillError::Invalid(format!(
                    "{p} is over {} KB",
                    MAX_FILE_BYTES / 1024
                )));
            }
            let text = std::str::from_utf8(b)
                .map_err(|_| SkillError::Invalid(format!("{p} is not text")))?;
            if let Some(c) = text.chars().find(|c| hidden(*c)) {
                return Err(SkillError::Invalid(format!(
                    "{p} holds a hidden or control character (U+{:04X}); a person could not see what an agent would read",
                    c as u32
                )));
            }
            if let Some(kind) = find_secret(text) {
                return Err(SkillError::Invalid(format!(
                    "{p} looks like it holds {kind}. A skill never holds a secret."
                )));
            }
        }
        let main = files
            .get("SKILL.md")
            .ok_or_else(|| SkillError::Invalid("a skill needs a SKILL.md".into()))?;
        let fm = front_matter(&String::from_utf8_lossy(main));
        let name = fm.get("name").cloned().ok_or_else(|| {
            SkillError::Invalid("SKILL.md needs a name: line in its front matter".into())
        })?;
        if !skill_name_ok(&name) {
            return Err(SkillError::Invalid(
                "a skill name is letters, digits, dash and underscore".into(),
            ));
        }
        let description = fm.get("description").cloned().unwrap_or_default();
        if description.is_empty() || description.chars().count() > 1024 {
            return Err(SkillError::Invalid(
                "SKILL.md needs a description of 1 to 1024 characters".into(),
            ));
        }
        Ok(SkillPack {
            name,
            description,
            version: fm.get("version").cloned().unwrap_or_else(|| "1".into()),
            license: fm.get("license").filter(|l| spdx_ok(l)).cloned(),
            files,
        })
    }

    /// Read a skill folder. Symbolic links and anything that is not a plain file are refused.
    pub fn from_dir(dir: &Path) -> Result<SkillPack, SkillError> {
        let mut files = BTreeMap::new();
        fn walk(
            base: &Path,
            dir: &Path,
            out: &mut BTreeMap<String, Vec<u8>>,
        ) -> Result<(), SkillError> {
            for e in fs::read_dir(dir).map_err(io)?.flatten() {
                let p = e.path();
                let meta = fs::symlink_metadata(&p).map_err(io)?;
                let rel = p
                    .strip_prefix(base)
                    .map_err(io)?
                    .to_string_lossy()
                    .replace('\\', "/");
                if meta.is_dir() {
                    if rel.starts_with('.') || rel.contains("/.") {
                        continue;
                    }
                    walk(base, &p, out)?;
                } else if meta.is_file() {
                    if rel.starts_with('.') || rel.contains("/.") {
                        continue;
                    }
                    if out.len() > MAX_FILES {
                        return Err(SkillError::Invalid(format!(
                            "a skill has at most {MAX_FILES} files"
                        )));
                    }
                    out.insert(rel, fs::read(&p).map_err(io)?);
                } else {
                    return Err(SkillError::Invalid(format!(
                        "{rel} is a link or a special file; a skill holds plain files only"
                    )));
                }
            }
            Ok(())
        }
        walk(dir, dir, &mut files)?;
        let pack = SkillPack::from_files(files)?;
        if dir.file_name().and_then(|n| n.to_str()) != Some(pack.name.as_str()) {
            return Err(SkillError::Invalid(
                "the folder must be named for the skill (the name in SKILL.md)".into(),
            ));
        }
        Ok(pack)
    }

    /// SHA-256 over every path and file, length-prefixed so no two different skills can collide by moving bytes around.
    pub fn hash(&self) -> String {
        hash_files(&self.files)
    }
}

pub fn hash_files(files: &BTreeMap<String, Vec<u8>>) -> String {
    let mut ctx = digest::Context::new(&digest::SHA256);
    for (p, b) in files {
        ctx.update(&(p.len() as u64).to_be_bytes());
        ctx.update(p.as_bytes());
        ctx.update(&(b.len() as u64).to_be_bytes());
        ctx.update(b);
    }
    ctx.finish()
        .as_ref()
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

/// A folder a coding agent reads skills from, under the box user's home.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SkillAgent {
    pub id: &'static str,
    /// What the dashboard calls it.
    pub label: &'static str,
    /// Which programs read this folder.
    pub reaches: &'static str,
    /// The folder, relative to the home directory.
    pub folder: &'static str,
    /// A folder whose presence says the program is set up for this person.
    pub marker: &'static str,
}

/// The folders a skill can be put in. Claude Code reads `~/.claude/skills`. Codex, Gemini CLI and OpenCode each document
/// `~/.agents/skills` as a user-level skills folder, so one shared folder reaches all three.
pub const SKILL_AGENTS: &[SkillAgent] = &[
    SkillAgent {
        id: "claude-code",
        label: "Claude Code",
        reaches: "Claude Code",
        folder: ".claude/skills",
        marker: ".claude",
    },
    SkillAgent {
        id: "agents",
        label: "Shared agents folder",
        reaches: "Codex, Gemini CLI and OpenCode",
        folder: ".agents/skills",
        marker: ".agents",
    },
];

pub fn skill_agent(id: &str) -> Option<&'static SkillAgent> {
    SKILL_AGENTS.iter().find(|a| a.id == id)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn files(extra: &[(&str, &str)]) -> BTreeMap<String, Vec<u8>> {
        let mut m = BTreeMap::new();
        m.insert(
            "SKILL.md".to_string(),
            b"---\nname: demo\ndescription: Does a thing.\nversion: 2\n---\nDo it.\n".to_vec(),
        );
        for (p, t) in extra {
            m.insert((*p).to_string(), t.as_bytes().to_vec());
        }
        m
    }

    #[test]
    fn a_plain_skill_loads_and_hashes_the_same_every_time() {
        let a = SkillPack::from_files(files(&[("notes.md", "x")])).unwrap();
        let b = SkillPack::from_files(files(&[("notes.md", "x")])).unwrap();
        assert_eq!((a.name.as_str(), a.version.as_str()), ("demo", "2"));
        assert_eq!(a.hash(), b.hash());
        let c = SkillPack::from_files(files(&[("notes.md", "y")])).unwrap();
        assert_ne!(a.hash(), c.hash());
    }

    #[test]
    fn hidden_characters_are_refused_so_the_reviewer_sees_what_the_agent_reads() {
        for bad in [
            "a\u{202E}b",
            "a\u{200B}b",
            "a\u{E0041}b",
            "a\u{0000}b",
            "a\u{001B}b",
            "a\u{FEFF}b",
        ] {
            assert!(
                SkillPack::from_files(files(&[("n.md", bad)])).is_err(),
                "{bad:?}"
            );
        }
        assert!(SkillPack::from_files(files(&[("n.md", "tabs\tand\r\nlines é 日本")])).is_ok());
    }

    #[test]
    fn paths_and_kinds_are_policed() {
        for bad in [
            "../x.md",
            "a/../b.md",
            "/abs.md",
            ".hidden.md",
            "a//b.md",
            "a.exe",
            "bin",
            "a/b/c/d/e.md",
        ] {
            assert!(
                SkillPack::from_files(files(&[(bad, "x")])).is_err(),
                "{bad}"
            );
        }
        assert!(SkillPack::from_files(files(&[("a.md", "x"), ("A.md", "y")])).is_err());
        assert!(SkillPack::from_files(files(&[("a", "x"), ("a/b.md", "y")])).is_err());
        let mut m = files(&[]);
        m.insert("blob.md".into(), vec![0xff, 0xfe]);
        assert!(SkillPack::from_files(m).is_err());
        assert_eq!(file_kind("SKILL.md"), "instructions");
        assert_eq!(file_kind("run.sh"), "script");
        assert_eq!(file_kind("a/b.md"), "text");
    }

    #[test]
    fn limits_and_secrets_are_enforced() {
        let big = "x".repeat(MAX_FILE_BYTES + 1);
        assert!(SkillPack::from_files(files(&[("b.md", &big)])).is_err());
        let many: Vec<(String, String)> = (0..MAX_FILES)
            .map(|i| (format!("f{i}.md"), "x".into()))
            .collect();
        let refs: Vec<(&str, &str)> = many.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
        assert!(SkillPack::from_files(files(&refs)).is_err());
        let key = concat!("the key is s", "k-abcdefghijklmnopqrstuvwxyz0123");
        assert!(SkillPack::from_files(files(&[("k.md", key)])).is_err());
    }

    #[test]
    fn the_agent_table_has_unique_ids_and_folders() {
        let mut ids: Vec<_> = SKILL_AGENTS.iter().map(|a| a.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), SKILL_AGENTS.len());
        assert!(skill_agent("claude-code").is_some() && skill_agent("nope").is_none());
    }
}
