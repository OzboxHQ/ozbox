//! Keeping the box's secrets across a system-disk replacement (`ozbox upgrade`).
//!
//! The encrypted store lives on the system disk (ADR 0018), and an upgrade replaces that disk and keeps only `/work`, so the
//! store would be lost. The secrets service therefore keeps a **copy of the store on `/work`**, in a folder only the secrets
//! user can open, refreshed while it runs, and puts it back at start when the system disk has none.
//!
//! **The key is never copied.** `/work` is what a disk snapshot, a clone and a restic backup copy, so a key file beside the
//! ciphertext would make every one of them decrypt the whole store. What is on `/work` is ciphertext under a key that is
//! not on `/work`: with KMS the instance role is needed, with a TPM the machine, and on a box that keeps its key in a file
//! the key stays on the system disk and is escrowed off the box (see `secrets_escrow`). A key file an older version left in
//! the folder is overwritten and removed the first time the service saves.
//!
//! **A copy that belongs to another box is not restored.** A clone's `/work` starts as a copy of another box's, and so does
//! a disk restored from a snapshot of one: the store's own scope says whose it is, and a copy that is not this box's is
//! removed rather than put back (it is useless here, and should not travel further).
//!
//! Nothing here is plaintext, nothing is returned over a socket, and a copy is only made once the folder is known to be on the
//! persistent disk, so a `/work` that failed to mount never receives a copy that the mount later hides.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// The files that make a store whole, beside the store file. The key file is not one of them.
const FILES: &[&str] = &["secrets.json", "broker-pins.json", "workload-audit.log"];

/// The key file a box with neither KMS nor a TPM keeps beside its store. Never copied to `/work`.
pub const KEY_FILE: &str = "kek.key";

fn names(store: &Path) -> Vec<String> {
    let own = store
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut v: Vec<String> = FILES.iter().map(|s| (*s).to_string()).collect();
    if !own.is_empty() && !v.contains(&own) && own != KEY_FILE {
        v.push(own);
    }
    v
}

#[cfg(unix)]
fn private_copy(from: &Path, to: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let tmp = to.with_extension("copying");
    std::fs::copy(from, &tmp)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    std::fs::rename(&tmp, to)
}

#[cfg(unix)]
fn private_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
}

/// Overwrite a file with zeros and remove it. Best effort on a journaled disk; the point is that the folder stops holding it.
pub fn destroy(p: &Path) {
    if let Ok(m) = std::fs::symlink_metadata(p) {
        if m.is_file() {
            let _ = std::fs::write(p, vec![0u8; m.len() as usize]);
        }
        let _ = std::fs::remove_file(p);
    }
}

/// Whether `dir` sits on a different device from `/`: that is, the persistent disk is really mounted there.
#[cfg(unix)]
pub fn on_persistent_disk(dir: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let probe = dir.ancestors().find(|a| a.exists());
    match (
        probe.and_then(|p| std::fs::metadata(p).ok()),
        std::fs::metadata("/"),
    ) {
        (Some(d), Ok(r)) => d.dev() != r.dev(),
        _ => false,
    }
}

/// The scope (the box) a store file belongs to, read from its plain header. `None` when it is not a store.
pub fn store_scope(file: &Path) -> Option<String> {
    let text = std::fs::read_to_string(file).ok()?;
    serde_json::from_str::<serde_json::Value>(&text).ok()?["scope"]
        .as_str()
        .map(str::to_string)
}

/// What [`restore`] did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Restored {
    /// The names put back on the system disk.
    pub names: Vec<String>,
    /// The copy on `/work` belonged to another box (a clone, or a disk restored from another box's snapshot) and was removed.
    pub foreign: Option<String>,
}

/// Put back what the system disk lacks, if the copy is this box's (`scope`). A key file is never restored from `/work`
/// except once from a copy an older version left there, which is then removed: the box that made it had it there already,
/// and refusing it would lose the store on the upgrade that brings this version.
#[cfg(unix)]
pub fn restore(store: &Path, persist: &Path, scope: &str) -> Restored {
    let mut out = Restored::default();
    let Some(dir) = store.parent() else {
        return out;
    };
    let copy = persist.join(store.file_name().unwrap_or_default());
    if let Some(theirs) = store_scope(&copy).filter(|s| s != scope) {
        for n in names(store).iter().map(String::as_str).chain([KEY_FILE]) {
            destroy(&persist.join(n));
        }
        out.foreign = Some(theirs);
        return out;
    }
    for n in names(store).iter().map(String::as_str).chain([KEY_FILE]) {
        let (src, dst) = (persist.join(n), dir.join(n));
        // never overwrite what the system disk has: only a missing store is restored
        if src.is_file() && !dst.exists() && private_copy(&src, &dst).is_ok() {
            out.names.push(n.to_string());
        }
    }
    // the older version's key copy has done its one job
    destroy(&persist.join(KEY_FILE));
    out
}

/// Copy what changed to the persistent folder, and remove a key file an older version left there. Returns the names copied.
#[cfg(unix)]
pub fn save(store: &Path, persist: &Path) -> Vec<String> {
    let Some(dir) = store.parent() else {
        return Vec::new();
    };
    if private_dir(persist).is_err() {
        return Vec::new();
    }
    destroy(&persist.join(KEY_FILE));
    let mut done = Vec::new();
    for n in names(store) {
        let (src, dst) = (dir.join(&n), persist.join(&n));
        let (Ok(a), b) = (std::fs::metadata(&src), std::fs::metadata(&dst)) else {
            continue;
        };
        if !a.is_file() {
            continue;
        }
        let stale = match b {
            Err(_) => true,
            Ok(b) => {
                b.len() != a.len()
                    || a.modified()
                        .ok()
                        .zip(b.modified().ok())
                        .is_some_and(|(x, y)| x > y)
            }
        };
        if stale && private_copy(&src, &dst).is_ok() {
            done.push(n);
        }
    }
    done
}

/// Keep the copy fresh while the service runs. `require_mount` is true on a box (the folder is under `/work`): nothing is
/// copied until the persistent disk is really there.
#[cfg(unix)]
pub fn spawn_saver(store: PathBuf, persist: PathBuf, require_mount: bool) {
    std::thread::spawn(move || loop {
        if !require_mount || on_persistent_disk(&persist) {
            let _ = save(&store, &persist);
        }
        std::thread::sleep(Duration::from_secs(30));
    });
    let _ = SystemTime::now();
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn store_text(scope: &str) -> String {
        format!("{{\"store_id\":\"s1\",\"scope\":\"{scope}\",\"entries\":{{}}}}")
    }

    #[test]
    fn a_new_system_disk_gets_the_store_back_and_never_the_key_and_an_existing_one_is_never_overwritten(
    ) {
        let d = tempfile::tempdir().unwrap();
        let (old, persist) = (d.path().join("old"), d.path().join("work/persist"));
        std::fs::create_dir_all(&old).unwrap();
        std::fs::write(old.join("secrets.json"), store_text("box-a")).unwrap();
        std::fs::write(old.join("kek.key"), "KEYFILE").unwrap();
        let saved = save(&old.join("secrets.json"), &persist);
        assert!(saved.contains(&"secrets.json".to_string()));
        // the key is never on /work: a snapshot, a clone or a backup of /work would otherwise open the store
        assert!(!persist.join("kek.key").exists());
        assert!(!saved.contains(&"kek.key".to_string()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&persist).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        // the system disk is replaced: the store comes back, the key does not
        let new = d.path().join("new");
        std::fs::create_dir_all(&new).unwrap();
        let back = restore(&new.join("secrets.json"), &persist, "box-a");
        assert_eq!(back.names, vec!["secrets.json".to_string()]);
        assert!(!new.join("kek.key").exists());
        // a store that is already there is never replaced by an older copy
        std::fs::write(new.join("secrets.json"), "NEWER").unwrap();
        assert!(restore(&new.join("secrets.json"), &persist, "box-a")
            .names
            .is_empty());
        assert_eq!(
            std::fs::read_to_string(new.join("secrets.json")).unwrap(),
            "NEWER"
        );
    }

    #[test]
    fn a_key_copy_an_older_version_left_on_work_is_used_once_then_destroyed() {
        let d = tempfile::tempdir().unwrap();
        let (new, persist) = (d.path().join("new"), d.path().join("p"));
        std::fs::create_dir_all(&new).unwrap();
        std::fs::create_dir_all(&persist).unwrap();
        std::fs::write(persist.join("secrets.json"), store_text("box-a")).unwrap();
        std::fs::write(persist.join("kek.key"), "OLDKEY").unwrap();
        let back = restore(&new.join("secrets.json"), &persist, "box-a");
        assert!(back.names.contains(&"kek.key".to_string()));
        assert_eq!(
            std::fs::read_to_string(new.join("kek.key")).unwrap(),
            "OLDKEY"
        );
        assert!(!persist.join("kek.key").exists());
        // and a save removes one that appears again
        std::fs::write(persist.join("kek.key"), "OLDKEY").unwrap();
        save(&new.join("secrets.json"), &persist);
        assert!(!persist.join("kek.key").exists());
    }

    #[test]
    fn a_copy_that_belongs_to_another_box_is_removed_not_restored() {
        let d = tempfile::tempdir().unwrap();
        let (new, persist) = (d.path().join("new"), d.path().join("p"));
        std::fs::create_dir_all(&new).unwrap();
        std::fs::create_dir_all(&persist).unwrap();
        std::fs::write(persist.join("secrets.json"), store_text("source-box")).unwrap();
        std::fs::write(persist.join("broker-pins.json"), "{}").unwrap();
        let back = restore(&new.join("secrets.json"), &persist, "clone-box");
        assert_eq!(back.foreign.as_deref(), Some("source-box"));
        assert!(back.names.is_empty());
        assert!(!new.join("secrets.json").exists());
        assert!(
            !persist.join("secrets.json").exists() && !persist.join("broker-pins.json").exists()
        );
    }

    #[test]
    fn only_what_changed_is_copied_again() {
        let d = tempfile::tempdir().unwrap();
        let (dir, persist) = (d.path().join("s"), d.path().join("p"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("secrets.json"), "A").unwrap();
        let store = dir.join("secrets.json");
        assert_eq!(save(&store, &persist), vec!["secrets.json".to_string()]);
        assert!(save(&store, &persist).is_empty());
        std::fs::write(&store, "AB").unwrap();
        assert_eq!(save(&store, &persist), vec!["secrets.json".to_string()]);
        assert_eq!(
            std::fs::read_to_string(persist.join("secrets.json")).unwrap(),
            "AB"
        );
    }
}
