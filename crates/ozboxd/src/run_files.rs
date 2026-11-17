//! Files handed to ONE run, in a folder of its own that is removed when the run ends (ADR 0055).
//!
//! An engine that must read a sign-in from a file (Codex reads `auth.json` under `CODEX_HOME`) is handed it here, and only
//! when the person turned that on for that engine. The dashboard sends the file's text in the run's start request, beside
//! the environment, and the daemon:
//!
//! - writes it under `<root>/<run id>/`, where `<root>` is a folder in the box user's runtime directory (a memory-backed
//!   file system that only the box user may enter): never `/work`, never the disk a snapshot or a backup copies;
//! - makes the folder `0700` and each file `0600`, creates each file anew (an existing path is refused, so a link planted
//!   there is not followed), and sets the one variable the engine's own documentation reads to the folder;
//! - removes the folder when the run ends, is cancelled or fails to start, and removes any folder left by a run that is
//!   no longer going when it takes runs over after a restart.
//!
//! The text is never logged, never put in the run's record on disk, and never passed to the spawner: the spawner sees only
//! the variable that names the folder. An agent in that run, running as the box user, CAN read the file while the run is
//! going. That is the risk ADR 0055 accepts, per engine, only after the person typed the confirmation.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// The variables a run file's folder may be named by: each is one engine's documented home folder. Only these, so a start
/// request cannot use this to point `PATH`, `HOME` or a loader variable at a folder of its own.
pub const DIR_VARS: &[&str] = &["CODEX_HOME"];
/// The most files one run may be handed.
pub const MAX_FILES: usize = 4;
/// The most text one file may hold.
pub const MAX_FILE_BYTES: usize = 64 * 1024;

/// One file for one run. Not `Debug`-printable with its text, and never serialized.
#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RunFile {
    /// The variable set to the run's folder (one of [`DIR_VARS`]).
    pub dir_env: String,
    /// Where in that folder: one or two plain names, such as `auth.json`.
    pub path: String,
    /// The file's text. Secret.
    pub contents: String,
}

impl fmt::Debug for RunFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunFile")
            .field("dir_env", &self.dir_env)
            .field("path", &self.path)
            .field("bytes", &self.contents.len())
            .finish()
    }
}

fn plain_part(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 64
        && p != "."
        && p != ".."
        && p.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Why a request's files are refused, or `None`.
pub fn invalid(files: &[RunFile], env: &BTreeMap<String, String>) -> Option<&'static str> {
    if files.is_empty() {
        return None;
    }
    if files.len() > MAX_FILES {
        return Some("too many run files");
    }
    let dir = &files[0].dir_env;
    if !DIR_VARS.contains(&dir.as_str()) {
        return Some("a run file must name a known engine folder variable");
    }
    if env.contains_key(dir) {
        return Some("a run file's folder variable is also in the environment");
    }
    let mut seen = std::collections::BTreeSet::new();
    for f in files {
        if &f.dir_env != dir {
            return Some("a run's files share one folder");
        }
        let parts: Vec<&str> = f.path.split('/').collect();
        if parts.len() > 2 || !parts.iter().all(|p| plain_part(p)) {
            return Some("a run file's path is not allowed");
        }
        if f.contents.len() > MAX_FILE_BYTES || f.contents.contains('\0') {
            return Some("a run file is too long or not text");
        }
        if !seen.insert(f.path.as_str()) {
            return Some("a run file is named twice");
        }
    }
    None
}

/// The folder a run's files go in.
pub fn dir_of(root: &Path, id: &str) -> PathBuf {
    root.join(id)
}

/// Write a run's files and return the variable to set and its value. On any failure the folder is removed again.
#[cfg(unix)]
pub fn materialise(root: &Path, id: &str, files: &[RunFile]) -> io::Result<(String, String)> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
    let Some(first) = files.first() else {
        return Err(io::Error::other("no files"));
    };
    if !plain_part(id) {
        return Err(io::Error::other("a run id is not a plain name"));
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(root)?;
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
    let dir = dir_of(root, id);
    // a folder already there is not this run's: refuse rather than write into it
    std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
    let write = || -> io::Result<()> {
        for f in files {
            let target = dir.join(&f.path);
            if let Some(parent) = target.parent().filter(|p| *p != dir) {
                std::fs::DirBuilder::new().mode(0o700).create(parent)?;
            }
            let mut out = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&target)?;
            out.write_all(f.contents.as_bytes())?;
            out.sync_all()?;
        }
        Ok(())
    };
    if let Err(e) = write() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(e);
    }
    Ok((first.dir_env.clone(), dir.to_string_lossy().into_owned()))
}

#[cfg(not(unix))]
pub fn materialise(_: &Path, _: &str, _: &[RunFile]) -> io::Result<(String, String)> {
    Err(io::Error::other("run files need a Unix box"))
}

/// Remove a run's folder. Nothing there is not an error.
pub fn remove(root: &Path, id: &str) {
    if plain_part(id) {
        let _ = std::fs::remove_dir_all(dir_of(root, id));
    }
}

/// Remove every folder under `root` whose run is not in `keep`. Returns how many were removed.
pub fn sweep(root: &Path, keep: &[String]) -> usize {
    let Ok(rd) = std::fs::read_dir(root) else {
        return 0;
    };
    let mut n = 0;
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if !keep.contains(&name) && std::fs::remove_dir_all(e.path()).is_ok() {
            n += 1;
        }
    }
    n
}

/// The root for a box daemon: the box user's runtime folder (memory-backed, the box user's alone), or none.
pub fn default_root(xdg_runtime_dir: Option<&str>) -> Option<PathBuf> {
    xdg_runtime_dir
        .filter(|d| d.starts_with('/'))
        .map(|d| Path::new(d).join("ozbox-run-files"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(path: &str, contents: &str) -> RunFile {
        RunFile {
            dir_env: "CODEX_HOME".into(),
            path: path.into(),
            contents: contents.into(),
        }
    }

    #[test]
    fn only_a_known_folder_variable_and_plain_paths_are_accepted() {
        let env = BTreeMap::new();
        assert_eq!(invalid(&[], &env), None);
        assert_eq!(invalid(&[f("auth.json", "{}")], &env), None);
        for bad in ["../x", "/abs", "a/b/c", "", "a b", ".."] {
            assert!(invalid(&[f(bad, "{}")], &env).is_some(), "{bad}");
        }
        let mut p = f("auth.json", "{}");
        p.dir_env = "PATH".into();
        assert!(invalid(&[p], &env).is_some());
        let mut env2 = BTreeMap::new();
        env2.insert("CODEX_HOME".to_string(), "/tmp".to_string());
        assert!(invalid(&[f("auth.json", "{}")], &env2).is_some());
        assert!(invalid(&[f("a", "x"), f("a", "y")], &env).is_some());
        assert!(invalid(&[f("a", &"x".repeat(MAX_FILE_BYTES + 1))], &env).is_some());
        assert!(invalid(&[f("a", "x\0")], &env).is_some());
        let many: Vec<RunFile> = (0..5).map(|i| f(&format!("f{i}"), "x")).collect();
        assert!(invalid(&many, &env).is_some());
    }

    #[test]
    fn debug_never_prints_the_text() {
        let s = format!("{:?}", f("auth.json", "SENTINEL-run-file-text"));
        assert!(!s.contains("SENTINEL"));
    }

    #[cfg(unix)]
    #[test]
    fn written_private_and_removed() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("rf");
        let (k, v) = materialise(
            &root,
            "r1",
            &[f("auth.json", "SENTINEL"), f("config.toml", "x = 1")],
        )
        .unwrap();
        assert_eq!(k, "CODEX_HOME");
        let dir = PathBuf::from(&v);
        assert_eq!(
            std::fs::read_to_string(dir.join("auth.json")).unwrap(),
            "SENTINEL"
        );
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&root), 0o700);
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&dir.join("auth.json")), 0o600);
        // a second run with the same id is refused: its folder is not this run's
        assert!(materialise(&root, "r1", &[f("auth.json", "x")]).is_err());
        remove(&root, "r1");
        assert!(!dir.exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_planted_link_is_not_followed_and_the_folder_is_cleaned_up() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("rf");
        std::fs::create_dir_all(&root).unwrap();
        // something made the run's folder first: refused, nothing written through it
        let outside = t.path().join("outside");
        std::os::unix::fs::symlink(&outside, root.join("r2")).unwrap();
        assert!(materialise(&root, "r2", &[f("auth.json", "SENTINEL")]).is_err());
        assert!(!outside.exists());
    }

    #[cfg(unix)]
    #[test]
    fn sweep_keeps_only_going_runs() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("rf");
        materialise(&root, "a", &[f("auth.json", "x")]).unwrap();
        materialise(&root, "b", &[f("auth.json", "x")]).unwrap();
        assert_eq!(sweep(&root, &["a".to_string()]), 1);
        assert!(dir_of(&root, "a").exists() && !dir_of(&root, "b").exists());
        assert_eq!(sweep(&t.path().join("none"), &[]), 0);
    }

    #[test]
    fn the_root_is_the_runtime_folder_never_work() {
        assert_eq!(
            default_root(Some("/run/user/1000")),
            Some(PathBuf::from("/run/user/1000/ozbox-run-files"))
        );
        assert_eq!(default_root(None), None);
        assert_eq!(default_root(Some("relative")), None);
    }
}
