//! What a box keeps of its backup set-up across an upgrade (`ozbox upgrade` replaces the system disk and keeps `/work`).
//!
//! Two things live on `/work` in a folder that root owns, next to the secrets store's own copy:
//!
//! - **A record that backups were set up here.** Without it nothing can tell a box that never had backups from a box whose
//!   backups silently stopped (a new secrets store, a repository that is gone). With it the self-test fails loudly in the
//!   second case, the box says so in its backup status, and the upgrade's report says so.
//! - **The non-secret settings** that a person may have put in the `[backup]` section of `/etc/ozbox/ozboxd.toml`: what is
//!   backed up (`paths`, `excludes`) and how often the box's own timer would run (`interval_hours`). `/etc` is on the
//!   system disk and starts again from the first-boot file, so a hand edit would be gone after every upgrade.
//!
//! **Why it is safe to read from `/work`.** The box user can write much of `/work`, but `/work` itself is root's, so the box
//! user cannot replace a root folder directly under it, and the daemon only trusts a folder and a file that root owns and
//! that no one else can write. A folder that fails that check is ignored (and said), never obeyed. The file is written only
//! by the root helper that already installs the repository credentials, and what it writes comes from root's own
//! `/etc/ozbox/ozboxd.toml`: the box user chooses none of it, so it cannot change what is backed up or where it goes.
//!
//! **What is deliberately not carried.** `enabled` (the dashboard owns the schedule; two schedules would back `/work` up
//! twice: the first-boot file writes it `false` on purpose), `env_file` and `service_socket` (where credentials come from is
//! the image's to say, never `/work`'s). **Credentials are never here**: the repository, its password and the cloud keys are
//! in the secrets service's encrypted store, which survives an upgrade by itself (see `secrets_persist`). Nothing in this
//! file is a secret, and nothing is ever put in a log line or an error.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::BackupSection;

/// The folder under `/work` (root-owned, directly under the root-owned `/work`).
pub const DIR_NAME: &str = "ozbox-backup";
pub const FILE: &str = "backup.toml";
const MAX_BYTES: u64 = 16 * 1024;

pub fn dir_for(work_dir: &Path) -> PathBuf {
    work_dir.join(DIR_NAME)
}

/// What is kept. `configured` is the record that backups were set up; the rest are settings a person chose.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Carried {
    pub configured: bool,
    #[serde(default)]
    pub paths: Option<Vec<String>>,
    #[serde(default)]
    pub excludes: Option<Vec<String>>,
    #[serde(default)]
    pub interval_hours: Option<u64>,
}

fn under_work(p: &str) -> bool {
    p.len() <= 512
        && (p == "/work" || p.starts_with("/work/"))
        && !p.split('/').any(|c| c == "..")
        && !p
            .bytes()
            .any(|b| b.is_ascii_control() || b == b'"' || b == b'\\')
}

/// One exclude, as restic reads it: an absolute path must be under `/work` (it can only ever name something there), and a
/// relative pattern (`*.tmp`, `node_modules`, `cache/*`) matches at any depth, so it can name nothing outside `/work`
/// either. Both are common in a real `/etc/ozbox/ozboxd.toml`. What is refused is a `..` step, a control character and an
/// absolute path elsewhere.
fn exclude_ok(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 512
        && !p.split('/').any(|c| c == "..")
        && !p.bytes().any(|b| b.is_ascii_control())
        && (!p.starts_with('/') || p == "/work" || p.starts_with("/work/"))
}

fn paths_valid(p: &[String]) -> Result<(), String> {
    if p.is_empty() || p.len() > 32 || !p.iter().all(|x| under_work(x)) {
        return Err("paths must be 1 to 32 folders under /work".into());
    }
    Ok(())
}

fn excludes_valid(e: &[String]) -> Result<(), String> {
    if e.len() > 256 || !e.iter().all(|x| exclude_ok(x)) {
        return Err(
            "excludes must be at most 256 patterns: paths under /work, or relative patterns".into(),
        );
    }
    Ok(())
}

fn interval_valid(h: u64) -> Result<(), String> {
    if !(1..=8760).contains(&h) {
        return Err("interval_hours must be 1 to 8760".into());
    }
    Ok(())
}

impl Carried {
    pub fn validate(&self) -> Result<(), String> {
        if !self.configured {
            return Err("the record does not say backups were set up".into());
        }
        if let Some(p) = &self.paths {
            paths_valid(p)?;
        }
        if let Some(e) = &self.excludes {
            excludes_valid(e)?;
        }
        if let Some(h) = self.interval_hours {
            interval_valid(h)?;
        }
        Ok(())
    }

    /// The file's text. Strings are written as JSON strings, which are valid TOML strings, and every value was validated.
    pub fn render(&self) -> String {
        let list = |v: &[String]| serde_json::to_string(v).unwrap_or_else(|_| "[]".into());
        let mut out = String::from(
            "# Written by the box's root helper from /etc/ozbox/ozboxd.toml, kept on /work so an upgrade keeps it.\n# No secrets here: the repository and its credentials are in the secrets store.\nconfigured = true\n",
        );
        if let Some(p) = &self.paths {
            out.push_str(&format!("paths = {}\n", list(p)));
        }
        if let Some(e) = &self.excludes {
            out.push_str(&format!("excludes = {}\n", list(e)));
        }
        if let Some(h) = self.interval_hours {
            out.push_str(&format!("interval_hours = {h}\n"));
        }
        out
    }
}

#[cfg(unix)]
fn root_only(m: &std::fs::Metadata, uid: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    m.uid() == uid && m.mode() & 0o022 == 0
}

/// Read the carried record. `Ok(None)`: there is none. `Err`: there is one that cannot be trusted or understood, which is
/// never obeyed (the reason holds no content). `trusted_uid` is root's (0) on a box.
#[cfg(unix)]
pub fn read(dir: &Path, trusted_uid: u32) -> Result<Option<Carried>, String> {
    use std::io::Read;
    let dm = match std::fs::symlink_metadata(dir) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("the backup record's folder cannot be read".into()),
    };
    if !dm.is_dir() || !root_only(&dm, trusted_uid) {
        return Err("the backup record's folder is not root's, so it is ignored".into());
    }
    let path = dir.join(FILE);
    let fm = match std::fs::symlink_metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("the backup record cannot be read".into()),
    };
    if !fm.is_file() || !root_only(&fm, trusted_uid) {
        return Err("the backup record is not root's, so it is ignored".into());
    }
    let mut text = String::new();
    std::fs::File::open(&path)
        .and_then(|f| f.take(MAX_BYTES + 1).read_to_string(&mut text))
        .map_err(|_| "the backup record cannot be read".to_string())?;
    if text.len() as u64 > MAX_BYTES {
        return Err("the backup record is too large".into());
    }
    let c: Carried =
        toml::from_str(&text).map_err(|_| "the backup record is not valid".to_string())?;
    c.validate()
        .map_err(|why| format!("the backup record is not valid: {why}"))?;
    Ok(Some(c))
}

/// The `[backup]` settings the daemon uses: a value root put in `/etc` wins (it differs from the built-in default), then
/// what `/work` carried, then the default. A new system disk has the defaults, so a carried value is what applies there.
pub fn effective(etc: BackupSection, carried: Option<&Carried>) -> BackupSection {
    let Some(c) = carried else { return etc };
    let default = BackupSection::default();
    let mut out = etc;
    if out.paths == default.paths {
        if let Some(p) = &c.paths {
            out.paths = p.clone();
        }
    }
    if out.excludes == default.excludes {
        if let Some(e) = &c.excludes {
            out.excludes = e.clone();
        }
    }
    if out.interval_hours == default.interval_hours {
        if let Some(h) = c.interval_hours {
            out.interval_hours = h;
        }
    }
    out
}

/// What to keep after credentials were set: the record, and every setting root's `/etc` holds that differs from the default,
/// over what was already carried (a new system disk's defaults must not overwrite a carried choice).
pub fn merge(existing: Option<&Carried>, etc: &BackupSection) -> Carried {
    merge_checked(existing, etc).0
}

/// As [`merge`], and what was left out. A setting the record cannot hold (too many folders, a path outside `/work`, an
/// interval that is not 1 to 8760 hours) is skipped on its own, keeping what was carried before, and named in the second
/// answer: one odd setting must never stop the record that backups were set up from being written, because without that
/// record an upgrade cannot tell a box whose backups stopped from one that never had any. The names hold no value.
pub fn merge_checked(existing: Option<&Carried>, etc: &BackupSection) -> (Carried, Vec<String>) {
    let default = BackupSection::default();
    let mut skipped = Vec::new();
    let mut keep = |name: &str, verdict: Result<(), String>| -> bool {
        if verdict.is_err() {
            skipped.push(format!(
                "the [backup] setting `{name}` in /etc/ozbox/ozboxd.toml cannot be kept across an upgrade and was left out"
            ));
        }
        verdict.is_ok()
    };
    let paths = if etc.paths != default.paths && keep("paths", paths_valid(&etc.paths)) {
        Some(etc.paths.clone())
    } else {
        existing.and_then(|c| c.paths.clone())
    };
    let excludes =
        if etc.excludes != default.excludes && keep("excludes", excludes_valid(&etc.excludes)) {
            Some(etc.excludes.clone())
        } else {
            existing.and_then(|c| c.excludes.clone())
        };
    let interval_hours = if etc.interval_hours != default.interval_hours
        && keep("interval_hours", interval_valid(etc.interval_hours))
    {
        Some(etc.interval_hours)
    } else {
        existing.and_then(|c| c.interval_hours)
    };
    (
        Carried {
            configured: true,
            paths,
            excludes,
            interval_hours,
        },
        skipped,
    )
}

/// Write the record where only root can change it, whole or not at all. Root's helper only. A folder that is already there
/// must be a real folder owned by `trusted_uid` (root, 0, on a box): a link, or a folder someone else made, is refused
/// before anything is created or its permissions are changed (root's helper must not be turned on a path it was pointed at).
#[cfg(unix)]
pub fn write(dir: &Path, c: &Carried, trusted_uid: u32) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    c.validate()?;
    let fail = |_: std::io::Error| "the backup record could not be written".to_string();
    match std::fs::symlink_metadata(dir) {
        Ok(m) if m.is_dir() && m.uid() == trusted_uid => {}
        Ok(_) => {
            return Err("the backup record's folder is not root's, so nothing was written".into())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(dir).map_err(fail)?
        }
        Err(e) => return Err(fail(e)),
    }
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).map_err(fail)?;
    let tmp = dir.join(format!(".{FILE}.tmp"));
    let _ = std::fs::remove_file(&tmp);
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&tmp)
        .and_then(|mut f| {
            f.write_all(c.render().as_bytes())
                .and_then(|()| f.sync_all())
        })
        .and_then(|()| std::fs::rename(&tmp, dir.join(FILE)))
        .inspect_err(|_| {
            let _ = std::fs::remove_file(&tmp);
        })
        .map_err(fail)
}

/// Forget that backups were set up (the person removed the repository on purpose), so the self-test does not fail for it.
pub fn remove(dir: &Path) -> Result<(), String> {
    match std::fs::remove_file(dir.join(FILE)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("the backup record could not be removed".into()),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn me() -> u32 {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(".").unwrap().uid()
    }

    fn custom() -> BackupSection {
        BackupSection {
            paths: vec!["/work".into(), "/work/extra".into()],
            excludes: vec!["/work/.ozbox/metrics".into(), "/work/cache".into()],
            interval_hours: 6,
            ..BackupSection::default()
        }
    }

    #[test]
    fn a_record_round_trips_and_holds_only_what_was_chosen() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join(DIR_NAME);
        assert_eq!(read(&dir, me()), Ok(None));
        let kept = merge(None, &custom());
        write(&dir, &kept, me()).unwrap();
        assert_eq!(read(&dir, me()).unwrap(), Some(kept.clone()));
        let text = std::fs::read_to_string(dir.join(FILE)).unwrap();
        assert!(text.contains("configured = true") && text.contains("interval_hours = 6"));
        // nothing about where credentials come from, and no value that looks like one
        for word in ["env_file", "service_socket", "enabled", "password", "KEY"] {
            assert!(!text.contains(word), "{word}");
        }
        // a default box carries the record and no settings
        let plain = merge(None, &BackupSection::default());
        assert_eq!(
            (plain.paths, plain.excludes, plain.interval_hours),
            (None, None, None)
        );
    }

    #[test]
    fn a_new_system_disk_keeps_the_carried_settings_and_a_hand_edit_still_wins() {
        let kept = merge(None, &custom());
        // the new disk's /etc is all defaults: what was carried applies
        let on_new_disk = effective(BackupSection::default(), Some(&kept));
        assert_eq!(on_new_disk.paths, custom().paths);
        assert_eq!(on_new_disk.excludes, custom().excludes);
        assert_eq!(on_new_disk.interval_hours, 6);
        // ... and never the image's own choices
        assert!(!on_new_disk.enabled);
        assert_eq!(on_new_disk.env_file, BackupSection::default().env_file);
        assert_eq!(on_new_disk.service_socket, None);
        // a root edit made since wins over the carried value
        let edited = BackupSection {
            interval_hours: 12,
            ..BackupSection::default()
        };
        let now = effective(edited.clone(), Some(&kept));
        assert_eq!(now.interval_hours, 12);
        assert_eq!(now.paths, custom().paths);
        // setting credentials again on the new disk (defaults in /etc) must not overwrite the carried choice
        let again = merge(Some(&kept), &BackupSection::default());
        assert_eq!(again, kept);
        // no record at all: nothing changes
        assert_eq!(effective(edited, None).interval_hours, 12);
    }

    #[test]
    fn a_record_root_does_not_own_or_others_can_write_is_ignored_never_obeyed() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join(DIR_NAME);
        write(&dir, &merge(None, &custom()), me()).unwrap();
        // another uid than the trusted one: the box user's files are not root's
        assert!(read(&dir, me() + 1).unwrap_err().contains("not root's"));
        // a writable folder or file is no better
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(read(&dir, me()).is_err());
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(dir.join(FILE), std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(read(&dir, me()).is_err());
        // a link in its place is not followed
        std::fs::remove_file(dir.join(FILE)).unwrap();
        std::fs::write(d.path().join("elsewhere.toml"), "configured = true\n").unwrap();
        std::os::unix::fs::symlink(d.path().join("elsewhere.toml"), dir.join(FILE)).unwrap();
        assert!(read(&dir, me()).is_err());
    }

    #[test]
    fn a_record_with_a_path_outside_work_or_a_key_nobody_defined_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join(DIR_NAME);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        for bad in [
            "configured = true\npaths = [\"/etc\"]\n",
            "configured = true\npaths = [\"/work/../etc\"]\n",
            "configured = true\nexcludes = [\"../relative\"]\n",
            "configured = true\nexcludes = [\"/etc/passwd\"]\n",
            "configured = true\ninterval_hours = 0\n",
            "configured = true\nenv_file = \"/work/x.env\"\n",
            "configured = true\nservice_socket = \"/work/s.sock\"\n",
            "configured = true\nenabled = true\n",
            "configured = false\n",
            "not toml [",
        ] {
            let f = dir.join(FILE);
            std::fs::write(&f, bad).unwrap();
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(read(&dir, me()).is_err(), "{bad}");
        }
    }

    #[test]
    fn real_world_excludes_are_kept_and_an_odd_setting_never_stops_the_record() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join(DIR_NAME);
        // relative patterns are what people write: restic matches them at any depth
        let real = BackupSection {
            excludes: vec![
                "*.tmp".into(),
                "node_modules".into(),
                "target/debug".into(),
                "/work/.ozbox/metrics".into(),
            ],
            ..BackupSection::default()
        };
        let (kept, skipped) = merge_checked(None, &real);
        assert!(skipped.is_empty(), "{skipped:?}");
        write(&dir, &kept, me()).unwrap();
        assert_eq!(
            read(&dir, me()).unwrap().unwrap().excludes,
            Some(real.excludes.clone())
        );
        // a setting the record cannot hold is left out by itself: the record is still written, and the rest is kept
        let odd = BackupSection {
            paths: vec!["/sentinel-path".into()],
            excludes: vec!["../sentinel-exclude".into()],
            interval_hours: 6,
            ..BackupSection::default()
        };
        let (kept, skipped) = merge_checked(None, &odd);
        assert!(kept.configured && kept.paths.is_none() && kept.excludes.is_none());
        assert_eq!(kept.interval_hours, Some(6));
        assert_eq!(skipped.len(), 2, "{skipped:?}");
        assert!(skipped.iter().all(|w| !w.contains("sentinel")));
        kept.validate().unwrap();
        write(&dir, &kept, me()).unwrap();
        // an earlier good choice survives a later odd one
        let before = merge(None, &real);
        assert_eq!(merge(Some(&before), &odd).excludes, before.excludes);
        // what stays refused: a parent step, a control character, an absolute path elsewhere
        for bad in ["a/../b", "/etc/passwd", "x\ny", ""] {
            assert!(!exclude_ok(bad), "{bad:?}");
        }
    }

    #[test]
    fn removing_the_record_is_safe_to_repeat() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join(DIR_NAME);
        write(&dir, &merge(None, &BackupSection::default()), me()).unwrap();
        remove(&dir).unwrap();
        remove(&dir).unwrap();
        assert_eq!(read(&dir, me()), Ok(None));
    }

    #[test]
    fn writing_never_follows_a_link_or_adopts_a_folder_someone_else_made() {
        let d = tempfile::tempdir().unwrap();
        let rec = merge(None, &BackupSection::default());
        // a link where the folder goes: refused, and the place it points at is untouched
        let target = d.path().join("elsewhere");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
        let link = d.path().join(DIR_NAME);
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(write(&link, &rec, me()).unwrap_err().contains("not root's"));
        assert!(std::fs::read_dir(&target).unwrap().next().is_none());
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o700,
            "its permissions are not changed through the link"
        );
        // a folder that another user owns: refused
        std::fs::remove_file(&link).unwrap();
        std::fs::create_dir(&link).unwrap();
        assert!(write(&link, &rec, me() + 1).is_err());
        // a real folder of the trusted user is used
        write(&link, &rec, me()).unwrap();
    }
}
