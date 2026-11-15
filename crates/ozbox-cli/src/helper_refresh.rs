//! `ozbox host-guard helper refresh`: replace the root helper (`/usr/local/sbin/ozbox-admin.sh`) with the one the installed
//! `ozbox` program carries, but only when that one is a strictly NEWER revision (ADR 0045, M2 and N2).
//!
//! The helper is plain shell written once, at first boot. This is the path by which a helper addition reaches a box whose
//! installed program already carries it, without a machine replace. It does NOT bring a program forward: the program on a box
//! changes only when its release is installed (a reinstall of the pinned release, or a machine replace), and a program that is
//! older than the helper has nothing newer to give.
//!
//! The text comes from THIS program (`HELPER`, compiled in from the same file first boot reads), which is root-owned and
//! installed from the signed release, never from a file or an argument the box user can reach. The box user can ask for the
//! refresh but cannot choose what is written.
//!
//! **Never a downgrade.** The helper carries a revision in its code (`helper_rev=N`, a line first boot keeps: it strips only
//! comments). A helper with no such line is revision 0. The refresh installs only a strictly greater revision; an equal or a
//! lower one changes nothing and says so, and every install and refusal is appended to a small log with both revisions. A fix
//! that tightens a gate in the helper can therefore not be undone by an older program, with or without anyone asking.
//!
//! Safe to run again. The new text is written beside the old one, syntax-checked by `bash -n`, the old one kept as
//! `ozbox-admin.sh.prev`, then renamed over it in one step. A helper that is running while it is replaced finishes on the old
//! text (the shell holds the old file open); the next request runs the new one.

use std::io::Write;
use std::path::PathBuf;

use ozbox_core::{CommandRunner, CommandSpec};

/// The helper this release ships: the file first boot installs, with its comments (first boot drops them to fit its size limit,
/// which a refresh has no reason to do).
pub const HELPER: &str = include_str!("../../../infra/cloud-init/scripts/ozbox-admin.sh");

/// What a refusal begins with, so the upgrade can tell "kept the helper that is already newer" from a real failure.
pub const KEPT: &str = "the root helper was not changed";

#[derive(Debug, Clone)]
pub struct Paths {
    /// `/usr/local/sbin/ozbox-admin.sh`.
    pub helper: PathBuf,
    /// Where each install and refusal is written (action words and revision numbers only).
    pub log: PathBuf,
}

impl Default for Paths {
    fn default() -> Self {
        Self {
            helper: "/usr/local/sbin/ozbox-admin.sh".into(),
            log: "/var/log/ozbox-helper-refresh.log".into(),
        }
    }
}

/// The revision a helper's text declares: its `helper_rev=N` line (code, not a comment). No such line means revision 0.
pub fn revision(text: &str) -> Option<u64> {
    text.lines()
        .find_map(|l| l.trim_end().strip_prefix("helper_rev="))
        .and_then(|n| n.parse().ok())
}

/// Whether text is plausibly the root helper (a guard against writing something else over it by a mistake in a build).
fn looks_like_the_helper(text: &str) -> bool {
    text.starts_with("#!/usr/bin/env bash\n")
        && text.contains("action_gates=")
        && text.contains("run_action()")
        && revision(text).is_some()
}

fn note(paths: &Paths, line: &str) {
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&paths.log)
    {
        let _ = writeln!(f, "{line}");
    }
}

pub fn refresh(runner: &dyn CommandRunner, paths: &Paths) -> Result<String, String> {
    refresh_with(runner, paths, HELPER)
}

pub fn refresh_with(
    runner: &dyn CommandRunner,
    paths: &Paths,
    text: &str,
) -> Result<String, String> {
    if !looks_like_the_helper(text) {
        return Err(
            "this program carries no root helper to install (a build mistake); nothing was changed"
                .into(),
        );
    }
    let offered = revision(text).unwrap_or(0);
    let dest = &paths.helper;
    let io = |what: &str, e: std::io::Error| format!("{what}: {}", e.kind());
    let installed_text = std::fs::read_to_string(dest).ok();
    let installed = installed_text
        .as_deref()
        .map_or(0, |t| revision(t).unwrap_or(0));
    if installed_text.as_deref() == Some(text) {
        return Ok(format!(
            "the root helper is already the one this release ships (revision {installed})"
        ));
    }
    if installed_text.is_some() && offered <= installed {
        let why = if offered == installed {
            "the same"
        } else {
            "an older"
        };
        note(
            paths,
            &format!("refresh refused: installed revision {installed}, offered revision {offered}"),
        );
        return Err(format!(
            "{KEPT}: it is revision {installed} and this program carries {why} revision ({offered}). A helper is only ever replaced by a newer one; install the newer release (a reinstall of the pinned release or a machine replace) to bring this program forward"
        ));
    }
    let dir = dest
        .parent()
        .ok_or("the helper has no folder")?
        .to_path_buf();
    let new = dir.join(".ozbox-admin.sh.new");
    let _ = std::fs::remove_file(&new);
    std::fs::write(&new, text).map_err(|e| io("could not write the new root helper", e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&new, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| io("could not set the new root helper's mode", e))?;
    }
    // a helper that does not parse would lock the box out of its own repair path: check before anything is replaced
    let checked = runner.run(
        &CommandSpec::new("bash")
            .arg("-n")
            .arg(new.display().to_string()),
    );
    if !matches!(checked, Ok(ref o) if o.status == Some(0)) {
        let _ = std::fs::remove_file(&new);
        return Err("the new root helper did not pass `bash -n`, so the old one was kept".into());
    }
    if dest.exists() {
        let prev = dir.join("ozbox-admin.sh.prev");
        std::fs::copy(dest, &prev).map_err(|e| io("could not keep the old root helper", e))?;
    }
    std::fs::rename(&new, dest).map_err(|e| io("could not put the new root helper in place", e))?;
    note(
        paths,
        &format!("refreshed: installed revision {installed}, now revision {offered}"),
    );
    Ok(format!("the root helper was refreshed from revision {installed} to revision {offered} (the old one is kept as ozbox-admin.sh.prev); the next request uses it"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ozbox_core::{Output, RecordingRunner};

    struct Syntax(i32);
    impl CommandRunner for Syntax {
        fn run(&self, _: &CommandSpec) -> ozbox_core::Result<Output> {
            Ok(Output {
                status: Some(self.0),
                stdout: String::new(),
                stderr: String::new(),
            })
        }
    }

    fn paths(d: &std::path::Path) -> Paths {
        Paths {
            helper: d.join("sbin/ozbox-admin.sh"),
            log: d.join("refresh.log"),
        }
    }

    fn text(rev: u32, tag: &str) -> String {
        format!("#!/usr/bin/env bash\nhelper_rev={rev}\naction_gates=\"{tag}\"\nrun_action() {{ :; }}\n")
    }

    fn installed(p: &Paths, body: &str) {
        std::fs::create_dir_all(p.helper.parent().unwrap()).unwrap();
        std::fs::write(&p.helper, body).unwrap();
    }

    #[test]
    fn the_helper_this_release_ships_is_the_one_first_boot_installs() {
        assert!(looks_like_the_helper(HELPER));
        // it carries the refresh itself, and a revision in its code (first boot strips comments, never code lines)
        assert!(HELPER.contains("helper refresh"));
        assert!(revision(HELPER).is_some_and(|n| n >= 1));
        let stripped: String = HELPER
            .lines()
            .filter(|l| !l.trim_start().starts_with('#') || l.starts_with("#!"))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(revision(&stripped), revision(HELPER));
        assert!(!looks_like_the_helper("#!/bin/sh\necho hi\n"));
        // a helper with no revision line is not one this program will install
        assert!(!looks_like_the_helper(
            "#!/usr/bin/env bash\naction_gates=\"x\"\nrun_action() { :; }\n"
        ));
    }

    #[test]
    fn a_newer_revision_replaces_the_helper_with_the_old_one_kept_and_the_same_text_is_left_alone()
    {
        let d = tempfile::tempdir().unwrap();
        let p = paths(d.path());
        installed(&p, &text(1, "old"));
        let new = text(2, "new");
        let msg = refresh_with(&Syntax(0), &p, &new).unwrap();
        assert!(msg.contains("from revision 1 to revision 2"), "{msg}");
        assert_eq!(std::fs::read_to_string(&p.helper).unwrap(), new);
        // the old one is kept as .prev
        assert_eq!(
            std::fs::read_to_string(p.helper.with_file_name("ozbox-admin.sh.prev")).unwrap(),
            text(1, "old")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&p.helper).unwrap().permissions().mode() & 0o777,
                0o755
            );
        }
        // the install is in the log with both revisions
        let log = std::fs::read_to_string(&p.log).unwrap();
        assert!(
            log.contains("installed revision 1, now revision 2"),
            "{log}"
        );
        // again: nothing to do, and no checker is even run
        let r = RecordingRunner::new();
        assert!(refresh_with(&r, &p, &new).unwrap().contains("already"));
        assert!(r.calls().is_empty());
        // no half-written file is left behind
        assert!(!p.helper.with_file_name(".ozbox-admin.sh.new").exists());
    }

    #[test]
    fn a_helper_that_predates_revisions_is_revision_zero_and_a_missing_one_is_installed() {
        let d = tempfile::tempdir().unwrap();
        let p = paths(d.path());
        installed(&p, "#!/usr/bin/env bash\n# made before revisions\n");
        assert!(refresh_with(&Syntax(0), &p, &text(1, "new")).is_ok());
        // no helper at all (nothing to keep): installed, and no .prev
        let d2 = tempfile::tempdir().unwrap();
        let p2 = paths(d2.path());
        std::fs::create_dir_all(p2.helper.parent().unwrap()).unwrap();
        assert!(refresh_with(&Syntax(0), &p2, &text(1, "new")).is_ok());
        assert!(!p2.helper.with_file_name("ozbox-admin.sh.prev").exists());
    }

    #[test]
    fn an_older_revision_is_refused_and_the_installed_helper_and_its_prev_are_untouched() {
        let d = tempfile::tempdir().unwrap();
        let p = paths(d.path());
        installed(&p, &text(5, "installed"));
        std::fs::write(p.helper.with_file_name("ozbox-admin.sh.prev"), "prev").unwrap();
        let r = RecordingRunner::new();
        let e = refresh_with(&r, &p, &text(3, "older")).unwrap_err();
        assert!(e.starts_with(KEPT), "{e}");
        assert!(
            e.contains("revision 5") && e.contains("older revision (3)"),
            "{e}"
        );
        assert_eq!(
            std::fs::read_to_string(&p.helper).unwrap(),
            text(5, "installed")
        );
        assert_eq!(
            std::fs::read_to_string(p.helper.with_file_name("ozbox-admin.sh.prev")).unwrap(),
            "prev"
        );
        assert!(r.calls().is_empty(), "nothing was even syntax-checked");
        assert!(!p.helper.with_file_name(".ozbox-admin.sh.new").exists());
        let log = std::fs::read_to_string(&p.log).unwrap();
        assert!(
            log.contains("refresh refused: installed revision 5, offered revision 3"),
            "{log}"
        );
    }

    #[test]
    fn an_equal_revision_with_different_text_is_refused_too() {
        let d = tempfile::tempdir().unwrap();
        let p = paths(d.path());
        installed(&p, &text(4, "installed"));
        let e = refresh_with(&Syntax(0), &p, &text(4, "other")).unwrap_err();
        assert!(
            e.starts_with(KEPT) && e.contains("the same revision (4)"),
            "{e}"
        );
        assert_eq!(
            std::fs::read_to_string(&p.helper).unwrap(),
            text(4, "installed")
        );
        assert!(!p.helper.with_file_name("ozbox-admin.sh.prev").exists());
        let log = std::fs::read_to_string(&p.log).unwrap();
        assert!(
            log.contains("installed revision 4, offered revision 4"),
            "{log}"
        );
    }

    #[test]
    fn a_helper_that_does_not_parse_never_replaces_the_working_one() {
        let d = tempfile::tempdir().unwrap();
        let p = paths(d.path());
        installed(&p, "old");
        let new = text(2, "x");
        let e = refresh_with(&Syntax(2), &p, &new).unwrap_err();
        assert!(e.contains("bash -n"), "{e}");
        assert_eq!(std::fs::read_to_string(&p.helper).unwrap(), "old");
        assert!(!p.helper.with_file_name(".ozbox-admin.sh.new").exists());
        // and something that is not the helper is refused before a byte is written
        assert!(refresh_with(&Syntax(0), &p, "echo hi").is_err());
        assert_eq!(std::fs::read_to_string(&p.helper).unwrap(), "old");
    }
}
