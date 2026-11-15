//! One version for the program, the box daemon and the image: the workspace version. This fails if a crate takes its own
//! version, if the version is not `MAJOR.MINOR.PATCH`, or if a release workflow stops insisting on it.

use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(root().join(rel)).unwrap_or_default()
}

fn workspace_version() -> String {
    let text = read("Cargo.toml");
    let section = text.split("[workspace.package]").nth(1).unwrap_or("");
    section
        .lines()
        .find_map(|l| l.trim().strip_prefix("version = \""))
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or("")
        .to_string()
}

#[test]
fn the_workspace_has_one_semantic_version() {
    let v = workspace_version();
    let core = v.split('-').next().unwrap_or("");
    let parts: Vec<&str> = core.split('.').collect();
    assert!(
        parts.len() == 3
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit())),
        "the workspace version {v:?} must be MAJOR.MINOR.PATCH (a pre-release suffix is allowed)"
    );
    assert!(
        parts[0].parse::<u32>().unwrap_or(9999) < 2000,
        "a date is not a version: {v}"
    );
}

#[test]
fn every_crate_takes_the_workspace_version() {
    let mut checked = 0;
    for entry in std::fs::read_dir(root().join("crates"))
        .into_iter()
        .flatten()
        .flatten()
    {
        let manifest = entry.path().join("Cargo.toml");
        let Ok(text) = std::fs::read_to_string(&manifest) else {
            continue;
        };
        checked += 1;
        assert!(
            text.contains("version.workspace = true"),
            "{} must take its version from the workspace (one version for the program, the daemon and the image)",
            manifest.display()
        );
    }
    assert!(checked >= 5, "the crates were not found");
}

#[test]
fn the_release_workflows_require_the_product_version() {
    let image = read(".github/workflows/image.yml");
    assert!(
        image.contains("must be the product version in Cargo.toml"),
        "image.yml no longer ties the image version to Cargo.toml"
    );
    assert!(
        !image.contains("date -u +%Y.%m.%d)\""),
        "the image version must not default to a date"
    );
    let cli =
        read(".github/workflows/cli-release.yml") + &read(".github/workflows/release-build.yml");
    assert!(
        cli.contains("Cargo.toml"),
        "the program release no longer checks its version against Cargo.toml"
    );
}
