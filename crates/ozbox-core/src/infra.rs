//! The box infrastructure a program renders: the OpenTofu modules (`infra/tofu/modules/*`) and the first-boot
//! configuration they render (`infra/cloud-init/**`). They belong to the program's version (ADR 0036): the `ozbox` program
//! carries its own copy, extracts it to a folder keyed by version and content hash, and checks it by hash before every use.
//!
//! Two hashes are computed with one rule, [`listing_hash`]:
//!
//! - the **bundle** hash, over every file of the bundle (all five modules and the first-boot configuration), which says
//!   whether a folder on disk is exactly the program's copy;
//! - the **first-boot** hash, over the files that decide what a new machine is given at first boot (the first-boot
//!   configuration and the two box modules that render it), which is what the signed image manifest records (`first_boot`)
//!   and what a box records about itself in `/etc/ozbox/first-boot`.
//!
//! The rule is simple enough to reproduce with standard tools, so a person can check a folder by hand: list the files
//! (relative paths with `/`, sorted by bytes), write one line `"<sha256 of the file>  <path>\n"` per file, exactly what
//! `sha256sum` prints, and take the SHA-256 of that text. Hidden files and folders (a name starting with `.`, such as the
//! `.terraform.lock.hcl` OpenTofu writes beside a module) and `tests` folders are not part of the bundle.

use std::path::{Path, PathBuf};

use crate::{Error, Result};

/// The folders of the bundle, relative to its root (`infra/` in a checkout).
pub const BUNDLE_DIRS: [&str; 2] = ["cloud-init", "tofu/modules"];

/// The parts of the bundle that decide a machine's first boot.
pub const FIRST_BOOT_DIRS: [&str; 3] = [
    "cloud-init",
    "tofu/modules/aws-box",
    "tofu/modules/hcloud-box",
];

/// The name of the record written beside an extracted copy (a hidden file, so it is not part of the hash).
pub const RECORD_FILE: &str = ".ozbox-infra.json";

/// The root-owned file on a box that says which first-boot configuration it was made with.
pub const BOX_RECORD_PATH: &str = "/etc/ozbox/first-boot";

/// The kinds of file a box module is made of: OpenTofu files, the first-boot template and its scripts, and the YAML/JSON
/// data files a module reads with `file()`. Nothing else is part of the bundle (state, variables or a saved plan above all;
/// the build refuses those, and `*.tfvars.json` is one of them). The same rule as the program's build
/// (`crates/ozbox-cli/infra_select.rs`) and `scripts/first-boot-hash.sh`.
pub const BUNDLE_EXTENSIONS: &[&str] = &["tf", "tftpl", "sh", "yaml", "yml", "json"];

/// Is `rel` (a `/`-separated path relative to the bundle root) a file of the bundle?
pub fn is_bundle_path(rel: &str) -> bool {
    let parts: Vec<&str> = rel.split('/').collect();
    let carried = parts
        .last()
        .and_then(|n| n.rsplit_once('.'))
        .is_some_and(|(stem, ext)| !stem.is_empty() && BUNDLE_EXTENSIONS.contains(&ext));
    carried
        && parts
            .iter()
            .all(|p| !p.is_empty() && !p.starts_with('.') && *p != "tests")
        && BUNDLE_DIRS.iter().any(|d| under(rel, d))
}

/// Is `rel` one of the files that decide a machine's first boot?
pub fn is_first_boot_path(rel: &str) -> bool {
    is_bundle_path(rel) && FIRST_BOOT_DIRS.iter().any(|d| under(rel, d))
}

fn under(rel: &str, dir: &str) -> bool {
    rel.strip_prefix(dir)
        .is_some_and(|rest| rest.starts_with('/') && rest.len() > 1)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn sha256(bytes: &[u8]) -> String {
    hex(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref())
}

/// The SHA-256 of the `sha256sum`-style listing of `files` (see the module documentation). The order given does not
/// matter; the files are sorted by path.
pub fn listing_hash<'a>(files: impl IntoIterator<Item = (&'a str, &'a [u8])>) -> String {
    let mut lines: Vec<(&str, String)> = files
        .into_iter()
        .map(|(path, bytes)| (path, sha256(bytes)))
        .collect();
    lines.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    let mut text = String::new();
    for (path, sum) in lines {
        text.push_str(&sum);
        text.push_str("  ");
        text.push_str(path);
        text.push('\n');
    }
    sha256(text.as_bytes())
}

/// The two hashes of a bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hashes {
    /// Over every file of the bundle.
    pub bundle: String,
    /// Over the files that decide a machine's first boot.
    pub first_boot: String,
}

/// Both hashes of `files` (path relative to the bundle root, contents). Files that are not part of the bundle are left out.
pub fn hashes<'a, I>(files: I) -> Hashes
where
    I: IntoIterator<Item = (&'a str, &'a [u8])>,
    I::IntoIter: Clone,
{
    let it = files.into_iter();
    Hashes {
        bundle: listing_hash(it.clone().filter(|(p, _)| is_bundle_path(p))),
        first_boot: listing_hash(it.filter(|(p, _)| is_first_boot_path(p))),
    }
}

/// Every file of the bundle under `root` (the folder that holds `cloud-init/` and `tofu/modules/`), as relative path and
/// contents. Symbolic links and anything that is not a regular file are left out (and so make a copy differ).
pub fn read_bundle(root: &Path) -> Result<Vec<(String, Vec<u8>)>> {
    let mut out = Vec::new();
    for dir in BUNDLE_DIRS {
        walk(&root.join(dir), dir, &mut out)?;
    }
    out.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    Ok(out)
}

fn walk(dir: &Path, rel: &str, out: &mut Vec<(String, Vec<u8>)>) -> Result<()> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    for e in entries {
        let e = e?;
        let name = e.file_name().to_string_lossy().to_string();
        let path = format!("{rel}/{name}");
        let meta = std::fs::symlink_metadata(e.path())?;
        if name.starts_with('.') || name == "tests" {
            continue;
        }
        if meta.is_dir() {
            walk(&e.path(), &path, out)?;
        } else if meta.is_file() && is_bundle_path(&path) {
            out.push((path, std::fs::read(e.path())?));
        }
    }
    Ok(())
}

/// The hashes of the bundle under `root`.
pub fn hashes_of_dir(root: &Path) -> Result<Hashes> {
    let files = read_bundle(root)?;
    Ok(hashes(
        files.iter().map(|(p, b)| (p.as_str(), b.as_slice())),
    ))
}

/// The bundle root a module folder belongs to: `<root>/tofu/modules/<module>` → `<root>`.
pub fn root_of_module_dir(module_dir: &Path) -> Option<PathBuf> {
    let modules = module_dir.parent()?;
    let tofu = modules.parent()?;
    (modules.file_name()? == "modules" && tofu.file_name()? == "tofu")
        .then(|| tofu.parent().map(Path::to_path_buf))
        .flatten()
}

/// Write `files` as the extracted copy of the program's bundle under `dest_root`, in `<version>-<first 16 of the bundle
/// hash>`, and return that folder. A folder that is already there and has exactly these files is used as it is; one that
/// differs (a file was changed or added by hand) is set aside and written again. The copy is made in a temporary folder
/// beside it and moved into place, so another process never sees half of it.
pub fn extract(files: &[(&str, &[u8])], version: &str, dest_root: &Path) -> Result<PathBuf> {
    let want = hashes(files.iter().copied());
    if files.iter().any(|(p, _)| !is_bundle_path(p)) {
        return Err(Error::Config(
            "the program's copy of the box modules has a file outside the bundle".into(),
        ));
    }
    let safe_version: String = version
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
        .collect();
    let dest = dest_root.join(format!("{safe_version}-{}", &want.bundle[..16]));
    if dest.is_dir() {
        if hashes_of_dir(&dest).is_ok_and(|h| h == want) {
            return Ok(dest);
        }
        // Changed on disk: keep it for a person to look at, never delete it, and write a fresh copy.
        let aside = dest_root.join(format!(
            "{safe_version}-{}.changed-{}",
            &want.bundle[..16],
            unique()
        ));
        std::fs::rename(&dest, &aside)?;
    }
    std::fs::create_dir_all(dest_root)?;
    let tmp = dest_root.join(format!(".tmp-{}", unique()));
    let written = (|| -> Result<()> {
        for (rel, bytes) in files {
            let path = tmp.join(rel);
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            std::fs::write(&path, bytes)?;
        }
        let record = serde_json::json!({
            "version": version,
            "bundle_sha256": want.bundle,
            "first_boot_sha256": want.first_boot,
        });
        std::fs::write(tmp.join(RECORD_FILE), format!("{record}\n"))?;
        if hashes_of_dir(&tmp)? != want {
            return Err(Error::Provider(
                "the extracted box modules did not verify".into(),
            ));
        }
        Ok(())
    })();
    if let Err(e) = written {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(e);
    }
    match std::fs::rename(&tmp, &dest) {
        Ok(()) => Ok(dest),
        Err(e) => {
            let _ = std::fs::remove_dir_all(&tmp);
            // Another process put the same copy there first: use it when it verifies.
            if hashes_of_dir(&dest).is_ok_and(|h| h == want) {
                Ok(dest)
            } else {
                Err(e.into())
            }
        }
    }
}

fn unique() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    format!("{}-{nanos}", std::process::id())
}

/// The version recorded beside an extracted copy, when there is one.
pub fn recorded_version(root: &Path) -> Option<String> {
    let text = std::fs::read_to_string(root.join(RECORD_FILE)).ok()?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    v["version"].as_str().map(str::to_string)
}

/// Is `s` a lowercase SHA-256 in hex?
pub fn is_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The first-boot hash in a box's record (`first_boot_sha256=<hash>` on a line of its own). `None` when there is no
/// such line or it is not a hash (a box made before the record existed, or with no hash given).
pub fn parse_box_record(text: &str) -> Option<String> {
    text.lines().find_map(|l| {
        l.trim()
            .strip_prefix("first_boot_sha256=")
            .map(str::trim)
            .filter(|h| is_sha256(h))
            .map(str::to_string)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    type R = std::result::Result<(), Box<dyn std::error::Error>>;

    fn sample() -> Vec<(&'static str, &'static [u8])> {
        vec![
            ("cloud-init/box.yaml.tftpl", b"#cloud-config\n".as_slice()),
            ("cloud-init/scripts/a.sh", b"echo a\n".as_slice()),
            ("tofu/modules/aws-box/main.tf", b"# aws\n".as_slice()),
            ("tofu/modules/hcloud-box/main.tf", b"# hcloud\n".as_slice()),
            ("tofu/modules/aws-network/main.tf", b"# net\n".as_slice()),
        ]
    }

    #[test]
    fn the_listing_is_what_sha256sum_prints_sorted_by_path() {
        // sha256("a") and sha256("b"); the listing is sorted by path whatever order it is given in.
        let a = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb";
        let b = "3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d";
        let listing = format!("{a}  x/a\n{b}  x/b\n");
        let want = sha256(listing.as_bytes());
        assert_eq!(
            listing_hash([("x/b", b"b".as_slice()), ("x/a", b"a")]),
            want
        );
        assert_eq!(
            listing_hash([("x/a", b"a".as_slice()), ("x/b", b"b")]),
            want
        );
    }

    #[test]
    fn hidden_files_tests_and_other_folders_are_not_part_of_the_bundle() {
        assert!(is_bundle_path("cloud-init/box.yaml.tftpl"));
        assert!(is_bundle_path("tofu/modules/aws-network/main.tf"));
        assert!(!is_bundle_path("tofu/modules/aws-box/.terraform.lock.hcl"));
        assert!(!is_bundle_path("tofu/modules/aws-box/tests/x.tftest.hcl"));
        assert!(!is_bundle_path("packer/x.pkr.hcl"));
        assert!(!is_bundle_path("tofu/check-no-ingress.sh"));
        assert!(!is_bundle_path("cloud-init"));
        assert!(is_first_boot_path("tofu/modules/hcloud-box/variables.tf"));
        assert!(!is_first_boot_path("tofu/modules/aws-network/main.tf"));
    }

    #[test]
    fn only_first_boot_files_change_the_first_boot_hash() {
        let base = hashes(sample());
        let mut other = sample();
        other[4].1 = b"# net changed\n";
        let h = hashes(other);
        assert_ne!(h.bundle, base.bundle);
        assert_eq!(h.first_boot, base.first_boot);
        let mut other = sample();
        other[0].1 = b"#cloud-config\nchanged\n";
        let h = hashes(other);
        assert_ne!(h.first_boot, base.first_boot);
    }

    #[test]
    fn an_extracted_copy_verifies_is_reused_and_is_rewritten_when_changed() -> R {
        let d = tempfile::tempdir()?;
        let files = sample();
        let dest = extract(&files, "0.1.1-alpha.0", d.path())?;
        assert!(dest
            .file_name()
            .is_some_and(|n| n.to_string_lossy().starts_with("0.1.1-alpha.0-")));
        assert_eq!(hashes_of_dir(&dest)?, hashes(files.clone()));
        assert_eq!(recorded_version(&dest).as_deref(), Some("0.1.1-alpha.0"));
        // OpenTofu writes a lock file beside the module: that is not a change.
        std::fs::write(dest.join("tofu/modules/aws-box/.terraform.lock.hcl"), "x")?;
        assert_eq!(extract(&files, "0.1.1-alpha.0", d.path())?, dest);
        // A file changed by hand is set aside (never deleted) and the copy written again.
        std::fs::write(dest.join("cloud-init/box.yaml.tftpl"), "edited")?;
        let again = extract(&files, "0.1.1-alpha.0", d.path())?;
        assert_eq!(again, dest);
        assert_eq!(hashes_of_dir(&again)?, hashes(files));
        let aside = std::fs::read_dir(d.path())?
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(".changed-"))
            .count();
        assert_eq!(aside, 1);
        Ok(())
    }

    #[test]
    fn an_added_file_makes_a_folder_differ() -> R {
        let d = tempfile::tempdir()?;
        let dest = extract(&sample(), "0.1.1", d.path())?;
        let before = hashes_of_dir(&dest)?;
        std::fs::write(dest.join("tofu/modules/aws-box/override.tf"), "x")?;
        let after = hashes_of_dir(&dest)?;
        assert_ne!(before.bundle, after.bundle);
        assert_ne!(before.first_boot, after.first_boot);
        Ok(())
    }

    #[test]
    fn the_root_of_a_module_folder() {
        assert_eq!(
            root_of_module_dir(Path::new("/x/infra/tofu/modules/aws-box")),
            Some(PathBuf::from("/x/infra"))
        );
        assert_eq!(root_of_module_dir(Path::new("/x/aws-box")), None);
    }

    #[test]
    fn a_box_record_names_a_hash_or_nothing() {
        let h = "a".repeat(64);
        assert_eq!(
            parse_box_record(&format!("first_boot_sha256={h}\n")),
            Some(h)
        );
        assert_eq!(parse_box_record("first_boot_sha256=\n"), None);
        assert_eq!(parse_box_record("first_boot_sha256=not-a-hash\n"), None);
        assert_eq!(parse_box_record(""), None);
    }

    /// The repository's own bundle, by the rule above, reproduced the way a person (or the image workflow) would.
    #[test]
    fn the_repository_bundle_hashes_like_sha256sum_would() -> R {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../infra");
        let files = read_bundle(&root)?;
        assert!(files.iter().any(|(p, _)| p == "cloud-init/box.yaml.tftpl"));
        assert!(files
            .iter()
            .any(|(p, _)| p == "tofu/modules/aws-security-baseline/main.tf"));
        assert!(!files.iter().any(|(p, _)| p.contains("/tests/")));
        let mut listing = String::new();
        for (p, b) in files.iter().filter(|(p, _)| is_first_boot_path(p)) {
            listing.push_str(&format!("{}  {p}\n", sha256(b)));
        }
        assert_eq!(hashes_of_dir(&root)?.first_boot, sha256(listing.as_bytes()));
        Ok(())
    }

    /// The shell recipe a person (and the image workflow) uses gives the same hash as the program.
    #[test]
    fn the_shell_recipe_matches() -> R {
        let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let out = std::process::Command::new("sh")
            .arg(repo.join("scripts/first-boot-hash.sh"))
            .arg(repo.join("infra"))
            .output()?;
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let shell = String::from_utf8(out.stdout)?.trim().to_string();
        assert_eq!(shell, hashes_of_dir(&repo.join("infra"))?.first_boot);
        Ok(())
    }
}
