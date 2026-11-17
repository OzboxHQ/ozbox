//! `ozbox first-boot install-scripts`: write the root helper scripts a box needs from the text this program carries, so the
//! first-boot user data does not have to. The user data is limited by the provider (16 KB on AWS), and each script that moved
//! here left room for the next first-boot addition.
//!
//! What it writes, each root-owned and mode 0755 under `/usr/local/sbin`: the root helper (`ozbox-admin.sh`), the secrets setup
//! (`ozbox-secrets-setup.sh`) and the box-user services script (`ozbox-user-manager.sh`). Each is the file as it is in the
//! source, comments included (first boot used to drop them to fit the limit; a refresh of the helper still compares revisions,
//! and the text is the same code). Safe to run again: each file is written beside the old one and renamed over it in one step,
//! so a script that is running finishes on the old text.
//!
//! The text comes from THIS program, which is root-owned and installed from the signed release, never from a file or an
//! argument the box user can reach. Not for typing by hand: first-boot configuration runs it, after the program is installed
//! and before anything runs these scripts.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::run::CliError;

/// Where the scripts go on a box.
pub const DEST: &str = "/usr/local/sbin";

/// The scripts, by the name they are installed under.
pub const SCRIPTS: [(&str, &str); 3] = [
    (
        "ozbox-admin.sh",
        include_str!("../../../infra/cloud-init/scripts/ozbox-admin.sh"),
    ),
    (
        "ozbox-secrets-setup.sh",
        include_str!("../../../infra/cloud-init/scripts/ozbox-secrets-setup.sh"),
    ),
    (
        "ozbox-user-manager.sh",
        include_str!("../../../infra/cloud-init/scripts/ozbox-user-manager.sh"),
    ),
];

/// Write every script into `dir`. Returns the names written.
pub fn install_into(dir: &Path) -> Result<Vec<&'static str>, String> {
    let mut done = Vec::new();
    for (name, text) in SCRIPTS {
        let target = dir.join(name);
        let tmp = dir.join(format!(".{name}.new"));
        let write = || -> std::io::Result<()> {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(text.as_bytes())?;
            f.sync_all()?;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
            std::fs::rename(&tmp, &target)
        };
        if write().is_err() {
            let _ = std::fs::remove_file(&tmp);
            return Err(format!("{name} could not be written"));
        }
        done.push(name);
    }
    Ok(done)
}

pub fn run(words: &[String]) -> Result<(), CliError> {
    match words.first().map(String::as_str) {
        Some("install-scripts") if words.len() == 1 => {
            let done = install_into(Path::new(DEST)).map_err(CliError::Msg)?;
            println!("installed {} box scripts in {DEST}", done.len());
            Ok(())
        }
        _ => Err(CliError::Msg(
            "usage: ozbox first-boot install-scripts".into(),
        )),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn it_writes_every_script_executable_and_identical_to_the_source() {
        let d = tempfile::tempdir().unwrap();
        let done = install_into(d.path()).unwrap();
        assert_eq!(done.len(), SCRIPTS.len());
        for (name, text) in SCRIPTS {
            let p = d.path().join(name);
            assert_eq!(std::fs::read_to_string(&p).unwrap(), text);
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o755, "{name}");
            assert!(text.starts_with("#!"), "{name} begins with a shebang");
        }
    }

    #[test]
    fn running_again_replaces_a_changed_file_and_leaves_no_temporary_one() {
        let d = tempfile::tempdir().unwrap();
        install_into(d.path()).unwrap();
        std::fs::write(d.path().join("ozbox-admin.sh"), "old").unwrap();
        install_into(d.path()).unwrap();
        assert_eq!(
            std::fs::read_to_string(d.path().join("ozbox-admin.sh")).unwrap(),
            SCRIPTS[0].1
        );
        let names: Vec<_> = std::fs::read_dir(d.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(names.iter().all(|n| !n.starts_with('.')), "{names:?}");
    }

    #[test]
    fn a_missing_folder_is_an_error_in_words_not_a_panic() {
        let e = install_into(Path::new("/nonexistent-ozbox-dir")).unwrap_err();
        assert!(e.contains("could not be written"));
    }

    #[test]
    fn it_takes_one_word_and_refuses_anything_else() {
        assert!(run(&[]).is_err());
        assert!(run(&["install-scripts".into(), "x".into()]).is_err());
    }
}
