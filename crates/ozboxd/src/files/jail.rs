//! The root jail and the secret-file rules. Pure path logic plus `canonicalize`; no request handling.
//!
//! A caller names a path such as `/work/exchange/report.txt`. It must start with one of the configured roots, carry no
//! `..`, and, once symlinks are resolved, still sit inside that root. Names that can hold secrets are refused for every
//! read; `.git` internals are refused for every write; the daemon's own state directory is never reachable.

use std::path::{Component, Path, PathBuf};

/// The name of the daemon's state directory inside a root. It holds the trash, the token key and the audit log.
pub const STATE_DIR: &str = ".ozbox";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// Not an absolute path, contains `..` or a NUL, or is empty.
    BadPath,
    /// Not under any root.
    Outside,
    /// A symlink leads out of the root.
    SymlinkEscape,
    /// Device, socket, pipe or anything that is not a file or a folder.
    NotRegular,
    /// The daemon's own state.
    Internal,
    /// A file that can hold secrets.
    Secret,
    /// A write into `.git` internals.
    GitInternal,
    Io(std::io::ErrorKind),
    NotFound,
}

impl Refusal {
    pub fn code(&self) -> &'static str {
        match self {
            Refusal::BadPath => "bad_path",
            Refusal::Outside => "outside_root",
            Refusal::SymlinkEscape => "symlink_escape",
            Refusal::NotRegular => "not_regular",
            Refusal::Internal => "internal",
            Refusal::Secret => "secret_blocked",
            Refusal::GitInternal => "git_internal",
            Refusal::Io(_) => "io",
            Refusal::NotFound => "not_found",
        }
    }

    pub fn status(&self) -> u16 {
        match self {
            Refusal::BadPath => 400,
            Refusal::NotFound => 404,
            Refusal::Io(_) => 500,
            Refusal::NotRegular => 422,
            _ => 403,
        }
    }

    /// An English fallback. The dashboard translates by `code`.
    pub fn message(&self) -> &'static str {
        match self {
            Refusal::BadPath => "That is not a valid path.",
            Refusal::Outside => "That path is outside the folders this box shares.",
            Refusal::SymlinkEscape => "That link leads outside the folders this box shares.",
            Refusal::NotRegular => "That is not an ordinary file or folder.",
            Refusal::Internal => "That is Oz Box's own folder and is not available here.",
            Refusal::Secret => "This file can hold secrets, so it is not shown, moved or sent here. To use its values, run `ozbox secrets import` on your own computer.",
            Refusal::GitInternal => "Git's own files cannot be changed here.",
            Refusal::Io(_) => "The file system could not do that.",
            Refusal::NotFound => "That file or folder does not exist.",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Read,
    Write,
    /// Delete to the trash: a leftover secret file may be removed, though never read.
    Remove,
}

/// Why a path is off limits for `op`, judged by its components alone (no file system access).
pub fn blocked(rel: &Path, op: Op) -> Option<Refusal> {
    let parts: Vec<String> = rel
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_string_lossy().to_ascii_lowercase()),
            _ => None,
        })
        .collect();
    if parts.iter().any(|p| p == STATE_DIR) {
        return Some(Refusal::Internal);
    }
    for (i, p) in parts.iter().enumerate() {
        if p == ".git" && op != Op::Read {
            return Some(Refusal::GitInternal);
        }
        if op == Op::Remove {
            continue;
        }
        let dir_like = matches!(
            p.as_str(),
            ".ssh" | ".aws" | ".gnupg" | ".azure" | ".kube" | ".docker"
        ) || (p == "gcloud" && i > 0 && parts[i - 1] == ".config");
        if dir_like {
            return Some(Refusal::Secret);
        }
    }
    if let Some(name) = parts.last().filter(|_| op != Op::Remove) {
        if secret_name(name) {
            return Some(Refusal::Secret);
        }
    }
    None
}

fn secret_name(name: &str) -> bool {
    if name.starts_with(".env") {
        return name != ".env.example";
    }
    if name.starts_with("id_") {
        return !name.ends_with(".pub");
    }
    if name.starts_with("service-account") && name.ends_with(".json") {
        return true;
    }
    const EXT: [&str; 7] = [
        ".pem",
        ".key",
        ".p12",
        ".pfx",
        ".keystore",
        ".jks",
        ".tfstate",
    ];
    const EXACT: [&str; 8] = [
        ".netrc",
        ".git-credentials",
        ".npmrc",
        ".pypirc",
        "credentials.json",
        "kubeconfig",
        "secrets.json",
        "token.json",
    ];
    EXT.iter().any(|e| name.ends_with(e)) || EXACT.contains(&name)
}

/// A name for a new file or folder: one component, not `.` or `..`, no NUL or slash, at most 255 bytes.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name != "."
        && name != ".."
        && !name.contains(['/', '\\', '\0'])
        && !name.chars().any(char::is_control)
}

#[derive(Debug, Clone)]
struct Root {
    /// As shown to callers, e.g. `/work`.
    shown: PathBuf,
    canon: PathBuf,
    label: String,
}

#[derive(Debug, Clone)]
pub struct Jail {
    roots: Vec<Root>,
}

#[derive(Debug, Clone)]
pub struct Resolved {
    /// The real path on disk, symlinks resolved (the final component too, unless asked not to).
    pub real: PathBuf,
    pub root: usize,
    /// Relative to the root, as the caller wrote it.
    pub rel: PathBuf,
    /// The path as the caller should see it again.
    pub shown: PathBuf,
}

fn lexical(path: &str) -> Result<Vec<String>, Refusal> {
    if path.is_empty() || !path.starts_with('/') || path.contains('\0') || path.len() > 4096 {
        return Err(Refusal::BadPath);
    }
    let mut out = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => return Err(Refusal::BadPath),
            s => out.push(s.to_string()),
        }
    }
    Ok(out)
}

impl Jail {
    pub fn new(roots: &[PathBuf]) -> std::io::Result<Self> {
        let mut out = Vec::new();
        for r in roots {
            let canon = std::fs::canonicalize(r)?;
            let label = r
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "root".into());
            out.push(Root {
                shown: r.clone(),
                canon,
                label,
            });
        }
        Ok(Self { roots: out })
    }

    pub fn roots(&self) -> Vec<(String, PathBuf)> {
        self.roots
            .iter()
            .map(|r| (r.label.clone(), r.shown.clone()))
            .collect()
    }

    pub fn root_shown(&self, i: usize) -> &Path {
        &self.roots[i].shown
    }

    pub fn root_canon(&self, i: usize) -> &Path {
        &self.roots[i].canon
    }

    /// `label:rel` for audit lines: a path that never leaves the box and never contains contents.
    pub fn audit_name(&self, r: &Resolved) -> String {
        format!("{}:{}", self.roots[r.root].label, r.rel.display())
    }

    /// Resolve `input`. With `follow_final`, a symlink in the last position is followed (and must stay inside the
    /// root); without it the last component is kept as a name (for delete, rename and mkdir), but its parent is
    /// resolved and checked all the same. `op` selects the secret rules.
    pub fn resolve(&self, input: &str, op: Op, follow_final: bool) -> Result<Resolved, Refusal> {
        let segs = lexical(input)?;
        let (idx, rest) = self
            .roots
            .iter()
            .enumerate()
            .find_map(|(i, r)| {
                let root_segs = lexical(&r.shown.to_string_lossy()).ok()?;
                (segs.len() >= root_segs.len() && segs[..root_segs.len()] == root_segs[..])
                    .then(|| (i, segs[root_segs.len()..].to_vec()))
            })
            .ok_or(Refusal::Outside)?;
        let rel: PathBuf = rest.iter().collect();
        if let Some(r) = blocked(&rel, op) {
            return Err(r);
        }
        let canon = &self.roots[idx].canon;
        let shown = self.roots[idx].shown.join(&rel);
        let joined = canon.join(&rel);
        let real = if rest.is_empty() {
            canon.clone()
        } else if follow_final {
            resolve_existing_prefix(&joined)?
        } else {
            let parent = joined.parent().ok_or(Refusal::BadPath)?;
            let name = joined.file_name().ok_or(Refusal::BadPath)?;
            resolve_existing_prefix(parent)?.join(name)
        };
        if !real.starts_with(canon) {
            return Err(Refusal::SymlinkEscape);
        }
        // A link may lead to a place the lexical name did not reveal: judge the resolved path as well.
        let real_rel = real
            .strip_prefix(canon)
            .map_err(|_| Refusal::SymlinkEscape)?;
        if let Some(r) = blocked(real_rel, op) {
            return Err(r);
        }
        Ok(Resolved {
            real,
            root: idx,
            rel,
            shown,
        })
    }
}

/// Canonicalize the deepest part of `p` that exists and re-attach what does not. A name that does not exist cannot be a
/// symlink, so only the existing part can lead out.
fn resolve_existing_prefix(p: &Path) -> Result<PathBuf, Refusal> {
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut cur = p.to_path_buf();
    loop {
        match std::fs::canonicalize(&cur) {
            Ok(c) => {
                let mut out = c;
                for t in tail.iter().rev() {
                    out.push(t);
                }
                return Ok(out);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // A dangling symlink is "not found" too; refuse it rather than treat its name as a new file.
                if std::fs::symlink_metadata(&cur).is_ok() {
                    return Err(Refusal::SymlinkEscape);
                }
                let name = cur.file_name().ok_or(Refusal::BadPath)?.to_owned();
                tail.push(name);
                if !cur.pop() {
                    return Err(Refusal::BadPath);
                }
            }
            Err(e) => return Err(Refusal::Io(e.kind())),
        }
    }
}

// ---- types ------------------------------------------------------------------------------------------------------

/// A media type for the few kinds a browser may show inline. Everything else is a download.
pub fn mime_for(name: &str) -> &'static str {
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase());
    match ext.as_deref() {
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("bmp") => "image/bmp",
        Some("ico") => "image/x-icon",
        Some("pdf") => "application/pdf",
        Some("txt" | "md" | "log" | "csv" | "toml" | "yaml" | "yml" | "ini" | "conf") => {
            "text/plain"
        }
        Some("json") => "application/json",
        Some("zip") => "application/zip",
        _ => "application/octet-stream",
    }
}

/// May a browser show this inline from a download link? Never anything that can run script (HTML, SVG).
pub fn inline_safe(mime: &str) -> bool {
    matches!(
        mime,
        "image/png" | "image/jpeg" | "image/gif" | "image/webp" | "image/bmp" | "application/pdf"
    )
}

pub fn is_image(name: &str) -> bool {
    mime_for(name).starts_with("image/")
}

/// Text means: no NUL in the first 8 KiB and valid UTF-8 (a multi-byte character cut at the end is fine).
pub fn looks_like_text(head: &[u8]) -> bool {
    let head = &head[..head.len().min(8192)];
    if head.contains(&0) {
        return false;
    }
    match std::str::from_utf8(head) {
        Ok(_) => true,
        Err(e) => e.error_len().is_none(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jail() -> (tempfile::TempDir, Jail) {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("work");
        std::fs::create_dir_all(root.join("a/b")).unwrap();
        std::fs::write(root.join("a/hello.txt"), "hi").unwrap();
        let j = Jail::new(&[root]).unwrap();
        (d, j)
    }

    fn p(d: &tempfile::TempDir, rel: &str) -> String {
        format!("{}/work/{rel}", d.path().display())
    }

    #[test]
    fn paths_are_checked_lexically_first() {
        let (d, j) = jail();
        let ok = |s: &str| j.resolve(s, Op::Read, true).map(|r| r.rel);
        assert!(ok(&p(&d, "a/hello.txt")).is_ok());
        assert!(ok(&p(&d, "a/./b/../hello.txt")).is_err()); // `..` is refused, not normalised
        assert_eq!(ok(&p(&d, "a/../../etc")), Err(Refusal::BadPath));
        assert_eq!(ok("relative/path"), Err(Refusal::BadPath));
        assert_eq!(ok(""), Err(Refusal::BadPath));
        assert_eq!(ok("/etc/passwd"), Err(Refusal::Outside));
        assert_eq!(ok("/work/x\0y"), Err(Refusal::BadPath));
        // A sibling that merely shares the prefix is not inside the root.
        assert_eq!(
            ok(&format!("{}/work-evil/x", d.path().display())),
            Err(Refusal::Outside)
        );
        assert!(j.resolve(&p(&d, ""), Op::Read, true).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_cannot_lead_out_of_the_root() {
        use std::os::unix::fs::symlink;
        let (d, j) = jail();
        let root = d.path().join("work");
        let outside = d.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("secret.txt"), "x").unwrap();
        symlink(&outside, root.join("escape")).unwrap();
        symlink(outside.join("secret.txt"), root.join("a/file-link")).unwrap();
        symlink("../../..", root.join("a/b/up")).unwrap();
        symlink("nowhere", root.join("dangling")).unwrap();
        symlink(root.join("a"), root.join("inside")).unwrap();

        let r = |s: String| j.resolve(&s, Op::Read, true).map(|r| r.real);
        assert_eq!(r(p(&d, "escape")), Err(Refusal::SymlinkEscape));
        assert_eq!(r(p(&d, "escape/secret.txt")), Err(Refusal::SymlinkEscape));
        assert_eq!(r(p(&d, "a/file-link")), Err(Refusal::SymlinkEscape));
        assert_eq!(r(p(&d, "a/b/up/x")), Err(Refusal::SymlinkEscape));
        assert_eq!(r(p(&d, "escape/new.txt")), Err(Refusal::SymlinkEscape));
        assert_eq!(r(p(&d, "dangling")), Err(Refusal::SymlinkEscape));
        // A link that stays inside is fine, and resolves to the target.
        assert!(r(p(&d, "inside/hello.txt"))
            .unwrap()
            .ends_with("a/hello.txt"));
        // Without following the final link, the link itself can be named (to delete or rename it)...
        assert!(j.resolve(&p(&d, "escape"), Op::Write, false).is_ok());
        // ...but not through a link in the middle.
        assert_eq!(
            j.resolve(&p(&d, "escape/secret.txt"), Op::Write, false)
                .map(|r| r.real),
            Err(Refusal::SymlinkEscape)
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_link_to_a_secret_or_to_the_state_dir_is_judged_by_where_it_leads() {
        use std::os::unix::fs::symlink;
        let (d, j) = jail();
        let root = d.path().join("work");
        std::fs::create_dir_all(root.join(".ozbox/files")).unwrap();
        std::fs::write(root.join(".ozbox/files/token.key"), "k").unwrap();
        std::fs::write(root.join("a/.env"), "S=1").unwrap();
        symlink(
            root.join(".ozbox/files/token.key"),
            root.join("innocent.txt"),
        )
        .unwrap();
        symlink(root.join("a/.env"), root.join("notes.txt")).unwrap();
        assert_eq!(
            j.resolve(&p(&d, "innocent.txt"), Op::Read, true)
                .map(|r| r.real),
            Err(Refusal::Internal)
        );
        assert_eq!(
            j.resolve(&p(&d, "notes.txt"), Op::Read, true)
                .map(|r| r.real),
            Err(Refusal::Secret)
        );
    }

    #[test]
    fn secret_names_are_refused_with_the_right_reason() {
        let r = |s: &str, op| blocked(Path::new(s), op);
        for s in [
            ".env",
            ".env.local",
            "app/.env.production",
            "x/.envrc",
            "cert.pem",
            "a/b/server.KEY",
            "id_rsa",
            "id_ed25519",
            ".ssh/config",
            ".aws/credentials",
            "home/.config/gcloud/creds.db",
            ".netrc",
            "creds/service-account-prod.json",
            "terraform.tfstate",
        ] {
            assert_eq!(r(s, Op::Read), Some(Refusal::Secret), "{s}");
        }
        for s in [
            ".env.example",
            "id_rsa.pub",
            "keys.txt",
            "environment.md",
            "monkey.txt",
            "src/env.ts",
        ] {
            assert_eq!(r(s, Op::Read), None, "{s}");
        }
        assert_eq!(r(".ozbox/trash/x", Op::Read), Some(Refusal::Internal));
        assert_eq!(r("a/.OZBOX", Op::Write), Some(Refusal::Internal));
        assert_eq!(r("repo/.git/config", Op::Write), Some(Refusal::GitInternal));
        assert_eq!(r("repo/.git/config", Op::Read), None);
        assert_eq!(r("repo/.github/ci.yml", Op::Write), None);
        // Refusal text points at the supported route for secrets.
        assert!(Refusal::Secret.message().contains("ozbox secrets import"));
    }

    #[test]
    fn names_for_new_entries() {
        for ok in ["a.txt", "dir name", ".hidden", "ünï.txt"] {
            assert!(valid_name(ok), "{ok}");
        }
        for bad in [
            "",
            ".",
            "..",
            "a/b",
            "a\\b",
            "a\0b",
            "a\nb",
            &"x".repeat(256),
        ] {
            assert!(!valid_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn text_detection_and_inline_types() {
        assert!(looks_like_text(b"hello\nworld"));
        assert!(looks_like_text("héllo".as_bytes()));
        assert!(looks_like_text(&"é".as_bytes()[..1])); // a cut character at the end
        assert!(!looks_like_text(b"a\0b"));
        assert!(!looks_like_text(&[0xff, 0xfe, 0x41]));
        assert!(inline_safe(mime_for("a.PNG")) && inline_safe(mime_for("b.pdf")));
        assert!(!inline_safe(mime_for("x.svg")) && !inline_safe(mime_for("x.html")));
    }
}
