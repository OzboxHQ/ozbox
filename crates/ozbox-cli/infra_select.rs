// Which files of `infra/` the program carries. Shared, by `include!`, between `build.rs` (which embeds them) and a test
// of this crate (which proves the rule), so the two cannot drift. The same rule is `ozbox_core::infra::is_bundle_path`
// and `scripts/first-boot-hash.sh`; a test holds all three to the repository tree.
//
// Only what a module is made of is carried: OpenTofu files, the first-boot template and its scripts. Anything else on
// disk is left out, and a state, variables or plan file (which a module folder held in versions before 2026-11-10, and
// which can hold secrets) refuses the build instead of being carried into every binary.

/// The kinds of file a box module is made of.
const CARRIED_EXTENSIONS: &[&str] = &["tf", "tftpl", "sh"];

/// Is `name` a file the program carries?
fn is_carried_name(name: &str) -> bool {
    name.rsplit_once('.')
        .is_some_and(|(stem, ext)| !stem.is_empty() && CARRIED_EXTENSIONS.contains(&ext))
}

/// Is `name` OpenTofu state, variables or a saved plan: something that must never be carried, nor sit in the tree.
fn is_state_name(name: &str) -> bool {
    name.contains(".tfstate")
        || name == "terraform.tfstate.d"
        || name.ends_with(".tfvars")
        || name.ends_with(".tfvars.json")
        || name.ends_with(".tfplan")
}

/// What one walk of an `infra/` folder found.
#[derive(Default)]
struct InfraFound {
    /// Carried files: `/`-separated path relative to the folder walked, and the file.
    files: Vec<(String, std::path::PathBuf)>,
    /// Every folder walked (a new file in one must rebuild the program).
    dirs: Vec<std::path::PathBuf>,
    /// State, variables or plan files found, or a link standing where a module file belongs: the build is refused while any is there.
    refused: Vec<std::path::PathBuf>,
}

/// Walk `dir`, skipping hidden names and `tests` folders (a hidden `.terraform` folder holds providers, never carried).
fn collect_infra(dir: &std::path::Path, rel: &str, found: &mut InfraFound) -> std::io::Result<()> {
    found.dirs.push(dir.to_path_buf());
    let mut entries: Vec<_> = std::fs::read_dir(dir)?.collect::<Result<_, _>>()?;
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let name = e.file_name().to_string_lossy().into_owned();
        let path = e.path();
        if is_state_name(&name) {
            found.refused.push(path);
            continue;
        }
        if name.starts_with('.') || name == "tests" {
            continue;
        }
        let here = if rel.is_empty() {
            name.clone()
        } else {
            format!("{rel}/{name}")
        };
        let meta = std::fs::symlink_metadata(&path)?;
        if meta.is_dir() {
            collect_infra(&path, &here, found)?;
        } else if meta.is_file() && is_carried_name(&name) {
            found.files.push((here, path));
        } else if meta.file_type().is_symlink() && is_carried_name(&name) {
            // A link where a module file belongs would be left out of the program and out of its hash (the hash script
            // skips links too), so the machine would be built from a different module than the one in the tree: refuse.
            found.refused.push(path);
        }
    }
    Ok(())
}
