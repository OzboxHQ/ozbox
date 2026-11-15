//! Which box modules and first-boot configuration this program renders (ADR 0036, amendment "the modules belong to the
//! program").
//!
//! The program carries its own copy (embedded at build time by `build.rs`), extracts it to a folder keyed by version and
//! content hash (`$OZBOX_INFRA_DIR`, else `$XDG_DATA_HOME/ozbox/infra`, else `~/.local/share/ozbox/infra`) and checks it
//! by hash before every use. A `module_dir` in the config is a developer override: it is used only when its files are
//! exactly the program's, or when the person says so (`dev_modules = true`, or `--dev-modules`), and then every plan says
//! so. A `module_dir` that points at some other copy (a folder copied by hand from an older version) is ignored with a
//! warning that says why and what to do, and the program's own copy is used.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use ozbox_core::infra::{self, Hashes};

use crate::messages::t;

include!(concat!(env!("OUT_DIR"), "/infra_assets.rs"));

/// This program's own files, as `(path relative to infra/, contents)`.
pub fn embedded() -> Vec<(&'static str, &'static [u8])> {
    EMBEDDED_INFRA.to_vec()
}

/// The hashes of this program's own copy.
pub fn program_hashes() -> &'static Hashes {
    static H: OnceLock<Hashes> = OnceLock::new();
    H.get_or_init(|| infra::hashes(EMBEDDED_INFRA.iter().copied()))
}

/// The first 12 characters of a hash, for a line a person reads.
pub fn short(h: &str) -> String {
    h.chars().take(12).collect()
}

/// Where the extracted copies are kept.
pub fn data_root() -> Option<PathBuf> {
    if let Some(d) = std::env::var_os("OZBOX_INFRA_DIR").filter(|d| !d.is_empty()) {
        return Some(PathBuf::from(d));
    }
    if let Some(d) = std::env::var_os("XDG_DATA_HOME").filter(|d| !d.is_empty()) {
        return Some(PathBuf::from(d).join("ozbox/infra"));
    }
    dirs::home_dir().map(|h| h.join(".local/share/ozbox/infra"))
}

/// What the person configured for one provider.
#[derive(Debug, Clone, Default)]
pub struct Wanted<'a> {
    /// The config section's name (`aws`, `hcloud`), for messages.
    pub section: &'a str,
    /// The module folder name (`aws-box`, `hcloud-box`).
    pub module: &'a str,
    /// `module_dir` from the config.
    pub module_dir: Option<PathBuf>,
    /// `dev_modules` from the config, or `--dev-modules`.
    pub dev: bool,
    /// Where the boxes' OpenTofu state lives: state a configured folder still holds is moved out before it is dropped.
    pub state_root: Option<PathBuf>,
}

/// Which modules a provider uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// The box module folder (`<root>/tofu/modules/<module>`).
    pub module_dir: PathBuf,
    /// The first-boot hash of what is rendered, passed to the module and recorded on a new box.
    pub first_boot: String,
    /// The developer folder in use, when it is not the program's own copy.
    pub dev: Option<PathBuf>,
    /// Lines for every plan (the developer-modules note).
    pub plan_notes: Vec<String>,
    /// Warnings to print once, on standard error.
    pub warnings: Vec<String>,
}

fn expand_home(p: &Path) -> PathBuf {
    match (p.strip_prefix("~"), dirs::home_dir()) {
        (Ok(rest), Some(h)) => h.join(rest),
        _ => p.to_path_buf(),
    }
}

/// Decide which modules to use. `files` and `ours` are this program's copy (passed in so tests can supply their own);
/// `extract_root` is where it is extracted.
pub fn resolve_with(
    want: &Wanted<'_>,
    files: &[(&str, &[u8])],
    ours: &Hashes,
    extract_root: Option<&Path>,
) -> std::result::Result<Resolved, String> {
    let version = env!("CARGO_PKG_VERSION");
    let own = |warnings: Vec<String>| -> std::result::Result<Resolved, String> {
        let root = extract_root.ok_or_else(|| t("infra.no_home", &[]))?;
        let dir = infra::extract(files, version, root).map_err(|e| {
            t(
                "infra.extract_failed",
                &[
                    ("dir", &root.display().to_string()),
                    ("why", &e.to_string()),
                ],
            )
        })?;
        Ok(Resolved {
            module_dir: dir.join("tofu/modules").join(want.module),
            first_boot: ours.first_boot.clone(),
            dev: None,
            plan_notes: Vec::new(),
            warnings,
        })
    };
    let Some(configured) = want.module_dir.as_deref().map(expand_home) else {
        if want.dev {
            return Err(t("infra.dev_needs_dir", &[("section", want.section)]));
        }
        return own(Vec::new());
    };
    let shown = configured.display().to_string();
    let theirs = infra::root_of_module_dir(&configured)
        .ok_or_else(|| "it is not inside a tofu/modules folder".to_string())
        .and_then(|root| {
            if !configured.join("main.tf").is_file() {
                return Err("it has no main.tf".to_string());
            }
            infra::hashes_of_dir(&root).map_err(|e| e.to_string())
        });
    let theirs = match theirs {
        Ok(h) => h,
        Err(why) => {
            if want.dev {
                return Err(t(
                    "infra.missing_module_dir",
                    &[
                        ("dir", &shown),
                        ("section", want.section),
                        ("why", &why),
                        ("used", "nothing (--dev-modules was given)"),
                    ],
                ));
            }
            let used = extract_root
                .map(|r| r.display().to_string())
                .unwrap_or_default();
            return own(vec![t(
                "infra.missing_module_dir",
                &[
                    ("dir", &shown),
                    ("section", want.section),
                    ("why", &why),
                    ("used", &used),
                ],
            )]);
        }
    };
    if theirs == *ours {
        // Exactly the program's files: the same thing, wherever it is.
        return Ok(Resolved {
            module_dir: configured,
            first_boot: ours.first_boot.clone(),
            dev: None,
            plan_notes: Vec::new(),
            warnings: Vec::new(),
        });
    }
    let args = |used: &str| {
        vec![
            ("dir", shown.clone()),
            ("section", want.section.to_string()),
            ("theirs", short(&theirs.first_boot)),
            ("ours", short(&ours.first_boot)),
            ("version", version.to_string()),
            ("used", used.to_string()),
        ]
    };
    let call = |key: &str, used: &str| {
        let a = args(used);
        let refs: Vec<(&str, &str)> = a.iter().map(|(k, v)| (*k, v.as_str())).collect();
        t(key, &refs)
    };
    if want.dev {
        return Ok(Resolved {
            module_dir: configured.clone(),
            first_boot: theirs.first_boot.clone(),
            dev: Some(configured),
            plan_notes: vec![call("infra.dev_note", "")],
            warnings: vec![call("infra.dev_warning", "")],
        });
    }
    // The folder is dropped: any box state an older version kept inside it is copied out first (copy, verify, never
    // delete), so no box goes missing because its state stayed behind.
    if let Some(state_root) = &want.state_root {
        ozbox_core::tofu::StateLayout::new(state_root, &configured)
            .migrate_legacy(&configured)
            .map_err(|e| {
                t(
                    "infra.legacy_failed",
                    &[("dir", &shown), ("why", &e.to_string())],
                )
            })?;
    }
    let mut r = own(Vec::new())?;
    let used = r
        .module_dir
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    r.warnings.push(call("infra.ignored_module_dir", &used));
    Ok(r)
}

/// [`resolve_with`] with this program's own copy and folder.
pub fn resolve(want: &Wanted<'_>) -> std::result::Result<Resolved, String> {
    let files = embedded();
    resolve_with(want, &files, program_hashes(), data_root().as_deref())
}

static DEV_FLAG: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// `--dev-modules` was given.
pub fn set_dev_flag(on: bool) {
    DEV_FLAG.store(on, std::sync::atomic::Ordering::SeqCst);
}

pub fn dev_flag() -> bool {
    DEV_FLAG.load(std::sync::atomic::Ordering::SeqCst)
}

/// The developer-modules note for the provider in use, set when the provider is built, read by every plan printer.
static PLAN_NOTES: OnceLock<std::sync::Mutex<Vec<String>>> = OnceLock::new();

/// Remember the lines every plan must carry (the developer-modules note), replacing what was there.
pub fn set_plan_notes(notes: Vec<String>) {
    let m = PLAN_NOTES.get_or_init(Default::default);
    if let Ok(mut g) = m.lock() {
        *g = notes;
    }
}

/// The lines every plan must carry.
pub fn plan_notes() -> Vec<String> {
    PLAN_NOTES
        .get()
        .and_then(|m| m.lock().ok().map(|g| g.clone()))
        .unwrap_or_default()
}

/// The first-boot hash the provider in use renders (this program's own unless developer modules are in use).
static EFFECTIVE: OnceLock<std::sync::Mutex<Option<String>>> = OnceLock::new();

pub fn set_effective_first_boot(h: &str) {
    let m = EFFECTIVE.get_or_init(Default::default);
    if let Ok(mut g) = m.lock() {
        *g = Some(h.to_string());
    }
}

pub fn effective_first_boot() -> String {
    EFFECTIVE
        .get()
        .and_then(|m| m.lock().ok().and_then(|g| g.clone()))
        .unwrap_or_else(|| program_hashes().first_boot.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    type R = std::result::Result<(), Box<dyn std::error::Error>>;

    fn files() -> Vec<(&'static str, &'static [u8])> {
        vec![
            (
                "cloud-init/box.yaml.tftpl",
                b"#cloud-config\nnew\n".as_slice(),
            ),
            ("tofu/modules/aws-box/main.tf", b"# aws new\n".as_slice()),
            ("tofu/modules/hcloud-box/main.tf", b"# hcloud\n".as_slice()),
        ]
    }

    fn hand_copy(root: &Path, template: &str) -> R {
        std::fs::create_dir_all(root.join("cloud-init"))?;
        std::fs::create_dir_all(root.join("tofu/modules/aws-box"))?;
        std::fs::create_dir_all(root.join("tofu/modules/hcloud-box"))?;
        std::fs::write(root.join("cloud-init/box.yaml.tftpl"), template)?;
        std::fs::write(root.join("tofu/modules/aws-box/main.tf"), "# aws new\n")?;
        std::fs::write(root.join("tofu/modules/hcloud-box/main.tf"), "# hcloud\n")?;
        Ok(())
    }

    fn want(dir: Option<PathBuf>, dev: bool) -> Wanted<'static> {
        Wanted {
            section: "aws",
            module: "aws-box",
            module_dir: dir,
            dev,
            state_root: None,
        }
    }

    #[test]
    fn with_no_module_dir_the_program_renders_its_own_extracted_copy() -> R {
        let d = tempfile::tempdir()?;
        let f = files();
        let ours = infra::hashes(f.clone());
        let r = resolve_with(&want(None, false), &f, &ours, Some(d.path()))?;
        assert!(r.module_dir.starts_with(d.path()));
        assert!(r.module_dir.ends_with("tofu/modules/aws-box"));
        assert_eq!(r.first_boot, ours.first_boot);
        assert!(r.warnings.is_empty() && r.plan_notes.is_empty() && r.dev.is_none());
        let root = r.module_dir.join("../../..");
        assert_eq!(infra::hashes_of_dir(&root)?, ours);
        Ok(())
    }

    /// The incident: a module folder copied by hand from an older version. It is not rendered.
    #[test]
    fn a_stale_hand_copy_is_ignored_with_a_warning_and_the_own_copy_is_used() -> R {
        let d = tempfile::tempdir()?;
        let stale = d.path().join("share/ozbox");
        hand_copy(&stale, "#cloud-config\nold\n")?;
        let f = files();
        let ours = infra::hashes(f.clone());
        let extract = d.path().join("infra");
        let r = resolve_with(
            &want(Some(stale.join("tofu/modules/aws-box")), false),
            &f,
            &ours,
            Some(&extract),
        )?;
        assert!(r.module_dir.starts_with(&extract), "{r:?}");
        assert_eq!(r.first_boot, ours.first_boot);
        assert!(r.dev.is_none() && r.plan_notes.is_empty());
        let w = r.warnings.join("\n");
        assert!(
            w.contains("not this program's copy") && w.contains("dev_modules = true"),
            "{w}"
        );
        Ok(())
    }

    #[test]
    fn developer_modules_are_used_only_when_asked_and_every_plan_says_so() -> R {
        let d = tempfile::tempdir()?;
        let dev = d.path().join("checkout/infra");
        hand_copy(&dev, "#cloud-config\nwork in progress\n")?;
        let f = files();
        let ours = infra::hashes(f.clone());
        let r = resolve_with(
            &want(Some(dev.join("tofu/modules/aws-box")), true),
            &f,
            &ours,
            Some(&d.path().join("infra")),
        )?;
        assert_eq!(r.module_dir, dev.join("tofu/modules/aws-box"));
        assert_eq!(r.first_boot, infra::hashes_of_dir(&dev)?.first_boot);
        assert_ne!(r.first_boot, ours.first_boot);
        assert!(r.plan_notes.iter().any(|n| n.contains("DEVELOPER MODULES")));
        // --dev-modules with no folder is an error, never a silent fall back
        assert!(resolve_with(&want(None, true), &f, &ours, Some(d.path())).is_err());
        Ok(())
    }

    #[test]
    fn a_folder_identical_to_the_program_copy_is_used_silently() -> R {
        let d = tempfile::tempdir()?;
        let same = d.path().join("infra");
        hand_copy(&same, "#cloud-config\nnew\n")?;
        let f = files();
        let ours = infra::hashes(f.clone());
        let r = resolve_with(
            &want(Some(same.join("tofu/modules/aws-box")), false),
            &f,
            &ours,
            Some(&d.path().join("x")),
        )?;
        assert_eq!(r.module_dir, same.join("tofu/modules/aws-box"));
        assert!(r.warnings.is_empty() && r.plan_notes.is_empty());
        Ok(())
    }

    #[test]
    fn a_module_dir_that_is_not_a_module_is_ignored_with_a_warning() -> R {
        let d = tempfile::tempdir()?;
        let f = files();
        let ours = infra::hashes(f.clone());
        let r = resolve_with(
            &want(Some(d.path().join("nowhere/aws-box")), false),
            &f,
            &ours,
            Some(&d.path().join("x")),
        )?;
        assert!(r.module_dir.starts_with(d.path().join("x")));
        assert!(r.warnings.iter().any(|w| w.contains("is not a box module")));
        Ok(())
    }

    #[test]
    fn state_left_inside_a_dropped_folder_is_copied_out_first() -> R {
        let d = tempfile::tempdir()?;
        let stale = d.path().join("old");
        hand_copy(&stale, "#cloud-config\nold\n")?;
        let module = stale.join("tofu/modules/aws-box");
        std::fs::create_dir_all(module.join("terraform.tfstate.d/main"))?;
        std::fs::write(
            module.join("terraform.tfstate.d/main/terraform.tfstate"),
            "{\"version\":4}",
        )?;
        let state_root = d.path().join("state");
        let f = files();
        let ours = infra::hashes(f.clone());
        let mut w = want(Some(module), false);
        w.state_root = Some(state_root.clone());
        resolve_with(&w, &f, &ours, Some(&d.path().join("x")))?;
        assert!(state_root
            .join("aws-box/workspaces/main/terraform.tfstate")
            .is_file());
        Ok(())
    }

    /// The program carries exactly the repository's modules and first-boot configuration.
    #[test]
    fn the_embedded_copy_is_the_repository_tree() -> R {
        let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../infra");
        assert_eq!(*program_hashes(), infra::hashes_of_dir(&repo)?);
        let names: Vec<&str> = EMBEDDED_INFRA.iter().map(|(p, _)| *p).collect();
        for want in [
            "cloud-init/box.yaml.tftpl",
            "tofu/modules/aws-box/main.tf",
            "tofu/modules/hcloud-box/main.tf",
            "tofu/modules/aws-network/main.tf",
            "tofu/modules/aws-security-baseline/main.tf",
            "tofu/modules/aws-secrets-key/main.tf",
            "tofu/modules/aws-adopt-command/main.tf",
        ] {
            assert!(names.contains(&want), "{want} is not embedded");
        }
        assert!(!names.iter().any(|p| p.contains("/tests/")));
        Ok(())
    }

    /// M1: the build carries only what a module is made of, and refuses state, variables or a saved plan lying in the
    /// tree (a module folder held box state before 2026-11-10, and state can hold secrets).
    mod build_rule {
        include!("../infra_select.rs");

        type R = std::result::Result<(), Box<dyn std::error::Error>>;

        #[test]
        fn state_in_the_tree_refuses_the_build_and_only_module_files_are_carried() -> R {
            let d = tempfile::tempdir()?;
            let m = d.path().join("aws-box");
            std::fs::create_dir_all(m.join("terraform.tfstate.d/main"))?;
            std::fs::create_dir_all(m.join(".terraform/providers"))?;
            std::fs::create_dir_all(m.join("tests"))?;
            std::fs::write(m.join("main.tf"), "# module")?;
            std::fs::write(m.join("setup.sh"), "#!/bin/sh")?;
            std::fs::write(m.join("README.md"), "notes")?;
            std::fs::write(m.join("terraform.tfstate.d/main/terraform.tfstate"), "{}")?;
            std::fs::write(m.join("terraform.tfstate.backup"), "{}")?;
            std::fs::write(m.join("prod.tfvars"), "token = \"x\"")?;
            std::fs::write(m.join("change.tfplan"), "plan")?;
            std::fs::write(m.join("tests/a.tftest.hcl"), "run")?;
            let mut found = InfraFound::default();
            collect_infra(d.path(), "", &mut found)?;
            let carried: Vec<&str> = found.files.iter().map(|(r, _)| r.as_str()).collect();
            assert_eq!(carried, ["aws-box/main.tf", "aws-box/setup.sh"]);
            let mut refused: Vec<String> = found
                .refused
                .iter()
                .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
                .collect();
            refused.sort();
            assert_eq!(
                refused,
                [
                    "change.tfplan",
                    "prod.tfvars",
                    "terraform.tfstate.backup",
                    "terraform.tfstate.d"
                ]
            );
            assert!(!found.dirs.is_empty());
            Ok(())
        }

        /// N4: a link standing where a module file belongs refuses the build instead of being silently left out.
        #[cfg(unix)]
        #[test]
        fn a_symlinked_module_file_refuses_the_build() -> R {
            let d = tempfile::tempdir()?;
            let m = d.path().join("aws-box");
            std::fs::create_dir_all(&m)?;
            std::fs::write(m.join("main.tf"), "# module")?;
            std::fs::write(d.path().join("elsewhere.tf"), "# not the module's")?;
            std::os::unix::fs::symlink(d.path().join("elsewhere.tf"), m.join("variables.tf"))?;
            // a link that is not a module file (a README link) is simply not carried
            std::os::unix::fs::symlink(d.path().join("elsewhere.tf"), m.join("README.md"))?;
            let mut found = InfraFound::default();
            collect_infra(d.path(), "", &mut found)?;
            let carried: Vec<&str> = found.files.iter().map(|(r, _)| r.as_str()).collect();
            assert_eq!(carried, ["aws-box/main.tf", "elsewhere.tf"]);
            let refused: Vec<String> = found
                .refused
                .iter()
                .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
                .collect();
            assert_eq!(refused, ["variables.tf"]);
            Ok(())
        }

        /// The build's rule and the core's agree, so what is embedded is what is hashed.
        #[test]
        fn the_build_rule_is_the_core_rule() {
            for name in [
                "main.tf",
                "box.yaml.tftpl",
                "a.sh",
                "README.md",
                "x.tfvars",
                ".tf",
                "tf",
                "a.tf.bak",
            ] {
                assert_eq!(
                    is_carried_name(name),
                    ozbox_core::infra::is_bundle_path(&format!("tofu/modules/aws-box/{name}")),
                    "{name}"
                );
            }
        }
    }
}
