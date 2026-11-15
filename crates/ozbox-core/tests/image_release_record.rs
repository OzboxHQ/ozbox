//! Every image's release record (`/etc/ozbox/image-release`) is readable by the laptop's one parser.
//!
//! The record is written by the image build (`infra/packer/ozbox-image/scripts/provision.sh`). This test runs that
//! script's own writing line, with sample values, and reads the result with [`parse_image_release`], the reader the
//! dashboard installer and `ozbox upgrade` both use. A key added to the record, or the record's order changing, can then
//! never again make an image look as if it had no record (the installer read only the first line, which is
//! `image_version=…`, not a version).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::process::Command;

use ozbox_core::release::{parse_image_release, IMAGE_RELEASE_PATH};

fn provision() -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../infra/packer/ozbox-image/scripts/provision.sh");
    std::fs::read_to_string(p).unwrap()
}

/// The `printf … >/etc/ozbox/image-release` statement of the image build, as one shell command.
fn writer() -> String {
    let text = provision();
    let lines: Vec<&str> = text.lines().collect();
    let end = lines
        .iter()
        .position(|l| l.contains(&format!(">{IMAGE_RELEASE_PATH}")))
        .expect("provision.sh writes the record");
    // the statement starts at the `printf` before it and may be continued with backslashes
    let start = (0..=end)
        .rev()
        .find(|&i| lines[i].trim_start().starts_with("printf"))
        .expect("the record is written with printf");
    lines[start..=end].join("\n")
}

fn render(version: &str, chrome: &str) -> String {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("image-release");
    let cmd = writer().replace(IMAGE_RELEASE_PATH, &dest.to_string_lossy());
    let sha = "c".repeat(64);
    let st = Command::new("bash")
        .args(["-c", &cmd])
        .env("OZBOX_IMAGE_VERSION", version)
        .env("OZBOXD_SHA256", &sha)
        .env("OZBOX_CLI_SHA256", &sha)
        .env("OZBOX_SOURCE_COMMIT", "339e501")
        .env("disk_generation", "d".repeat(64))
        .env("chrome_version", chrome)
        .env(
            "chrome_sha256",
            if chrome == "none" { "none" } else { &sha },
        )
        .status()
        .unwrap();
    assert!(st.success());
    std::fs::read_to_string(dest).unwrap()
}

#[test]
fn the_record_the_image_build_writes_names_its_version_to_the_laptop() {
    for (version, chrome) in [
        ("0.1.1-alpha.0", "142.0.7444.59-1"),
        ("0.1.2", "none"),
        ("2026.11.10-1", "none"),
    ] {
        let text = render(version, chrome);
        // the browser's lines (and whatever comes after) are part of the record, and the version is still found
        assert!(text.contains("chrome_version="), "{text}");
        let r = parse_image_release(&text);
        assert!(r.present, "{text}");
        assert_eq!(r.version.as_deref(), Some(version), "{text}");
        assert_eq!(r.ozbox_sha256, Some("c".repeat(64)));
        assert_eq!(r.ozboxd_sha256, Some("c".repeat(64)));
        // the disk generation the image build computed (ADR 0038) is on the record
        assert_eq!(r.disk_generation, Some("d".repeat(64)));
    }
}

#[test]
fn the_record_is_world_readable_on_the_image() {
    // the installer and the upgrade read it as the box user, over SSH
    let text = provision();
    assert!(text.contains(&format!("chmod 0644 {IMAGE_RELEASE_PATH}")));
}

#[test]
fn records_from_the_first_images_and_damaged_ones_are_read_strictly() {
    // the first images wrote the bare version
    assert_eq!(
        parse_image_release("2026.11.09\n").version.as_deref(),
        Some("2026.11.09")
    );
    // nothing that is not a version is ever taken for one
    let r = parse_image_release("image_version=latest; rm -rf /\nozbox_sha256=12\n");
    assert_eq!((r.version, r.ozbox_sha256), (None, None));
    assert!(r.present);
    // a shell's noise around an absent record says nothing
    let r = parse_image_release("Welcome!\narch=x86_64\n");
    assert!(!r.present && r.version.is_none());
    // an image built before the disk generation existed has none, which means "replace"
    let old = parse_image_release("image_version=0.1.1\nozbox_sha256=");
    assert_eq!(old.disk_generation, None);
    assert_eq!(
        parse_image_release("disk_generation=nope\n").disk_generation,
        None
    );
    assert_eq!(
        parse_image_release(&format!("disk_generation={}\n", "E".repeat(64))).disk_generation,
        Some("e".repeat(64))
    );
    // two bare versions: ambiguous, so none
    assert_eq!(parse_image_release("0.1.0\n0.1.1\n").version, None);
}
