//! The program-release workflow and the code that trusts it must agree, and the workflow must keep the properties that
//! make its signature worth trusting. This reads the workflow file as text, so it runs anywhere with no network.

use ozbox_core::release::identity_regexp;
use ozbox_core::ReleaseKind;

fn workflow() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../.github/workflows/cli-release.yml");
    std::fs::read_to_string(path).unwrap_or_default()
}

/// The reusable workflow cli-release.yml calls: it builds the programs and writes the manifest. The signing job (and so
/// the certificate identity) stays in cli-release.yml.
fn build_workflow() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../.github/workflows/release-build.yml");
    std::fs::read_to_string(path).unwrap_or_default()
}

#[test]
fn the_workflow_builds_signs_and_publishes_what_the_installer_looks_for() {
    let w = format!("{}\n{}", workflow(), build_workflow());
    assert!(!w.is_empty(), "the program-release workflow was not found");
    for needle in [
        // the identity the verifier pins is this workflow's name and tag
        "tags: [\"v*\"]",
        "tag=\"v$VERSION\"",
        // both machine types, statically linked
        "x86_64-unknown-linux-musl",
        "aarch64-unknown-linux-musl",
        "statically linked|static-pie linked",
        // the files the installer reads, and the keys it reads from the manifest
        "ozbox-cli-manifest.json",
        "ozbox-$os-$arch",
        "ozbox-darwin-$ARCH",
        "{os: $os, arch: $arch, asset: $asset, sha256: $sha}",
        "binaries: $binaries[0]",
        "version: $version",
        // keyless signing, in all three forms, and the checksum
        "cosign sign-blob --yes",
        "--output-signature \"$f.sig\"",
        "--output-certificate \"$f.pem\"",
        "--bundle \"$f.sigstore.json\"",
        "sha256sum",
        "gh release upload",
    ] {
        assert!(
            w.contains(needle),
            "the workflow no longer contains {needle:?}"
        );
    }
}

#[test]
fn the_signing_identity_names_the_workflow_file_that_signs() {
    let w = workflow();
    assert!(
        w.starts_with("name: CLI release"),
        "the workflow this identity names is cli-release.yml"
    );
    let re = identity_regexp("example-org/example-repo", ReleaseKind::Cli);
    assert!(re.contains("workflows/cli-release\\.yml@"));
    assert!(re.contains("tags/v"));
}

#[test]
fn the_workflow_never_publishes_on_its_own_and_holds_no_more_power_than_it_needs() {
    let w = workflow();
    // only an owner's tag or a manual run starts it
    let on: String = w
        .lines()
        .skip_while(|l| !l.starts_with("on:"))
        .take_while(|l| !l.starts_with("permissions:"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(on.contains("workflow_dispatch") && on.contains("push:"));
    for bad in ["pull_request", "schedule", "workflow_run"] {
        assert!(!on.contains(bad), "{bad} must not start a release");
    }
    // read-only by default; the publishing job alone may write and sign
    assert!(w.contains("\npermissions:\n  contents: read\n"));
    assert_eq!(w.matches("id-token: write").count(), 1);
    assert_eq!(w.matches("contents: write").count(), 1);
    // every action is pinned to a commit
    for line in w.lines().filter(|l| l.trim_start().starts_with("- uses:")) {
        let spec = line.trim_start().trim_start_matches("- uses:").trim();
        let sha = spec.split('@').nth(1).unwrap_or("");
        assert!(
            sha.len() >= 40 && sha.chars().take(40).all(|c| c.is_ascii_hexdigit()),
            "not pinned to a commit: {line}"
        );
    }
    // no workflow input reaches a shell: it goes through env first
    let mut in_run = false;
    for line in w.lines() {
        let t = line.trim();
        if t.starts_with("run:") {
            in_run = t.ends_with('|');
            assert!(!t.contains("${{"), "an expression in a run line: {line}");
        } else if in_run {
            if !line.starts_with("          ") && !t.is_empty() {
                in_run = false;
            } else {
                assert!(!t.contains("${{"), "an expression in a run block: {line}");
            }
        }
    }
}

/// The dashboard check asks the PROGRAM what it embedded. A byte-search for the content hash is not sound: the compiler may
/// store the 64-character constant in pieces (an optimized x86_64 macOS build kept only 8 characters of it contiguous), so a
/// workflow that searches for it fails on a correct build and passes on a wrong one by luck of code generation.
#[test]
fn the_dashboard_check_runs_the_program_and_never_searches_it_for_the_hash() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../");
    let script =
        std::fs::read_to_string(root.join("scripts/release/check-embedded-dashboard.sh")).unwrap();
    for needle in [
        "build-info --json",
        ".dashboard.sha256",
        ".placeholder_page",
    ] {
        assert!(script.contains(needle), "the check script lost {needle:?}");
    }
    let image = std::fs::read_to_string(root.join(".github/workflows/image.yml")).unwrap();
    let release = build_workflow();
    for (name, w) in [("image.yml", &image), ("release-build.yml", &release)] {
        assert!(
            w.contains("scripts/release/check-embedded-dashboard.sh \"$DASH\""),
            "{name} does not ask the program which dashboard it embedded"
        );
        // no search for the hash, in any form
        for line in w.lines().filter(|l| l.contains("grep")) {
            assert!(
                !line.contains("$DASH"),
                "{name} searches a binary for the dashboard hash: {line}"
            );
        }
        // the placeholder literal is still searched for, with a search macOS's grep does not miss in a large binary
        assert!(
            w.contains("LC_ALL=C grep -aqF \"The dashboard is not built\""),
            "{name} lost the placeholder search"
        );
    }
    // darwin: both processors are asked, x86_64 under Rosetta, installed when the runner lacks it
    for needle in [
        "arch -x86_64",
        "softwareupdate --install-rosetta --agree-to-license",
    ] {
        assert!(
            release.contains(needle),
            "release-build.yml lost {needle:?}"
        );
    }
    // and every program of the release is asked, not only the ones that happen to run natively
    let linux = release
        .split("build-macos:")
        .next()
        .unwrap_or_default()
        .to_string();
    assert!(
        linux.contains("qemu-aarch64"),
        "the arm64 Linux program is not asked"
    );
}
