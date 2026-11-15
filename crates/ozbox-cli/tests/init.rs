//! `ozbox init` end to end: the free sandbox needs no cloud, a dry run changes nothing, a script without --yes is refused.

use assert_cmd::Command;
use predicates::prelude::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn cmd(dir: &std::path::Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_ozbox"));
    c.env("OZBOX_STATE_DIR", dir.join("state"))
        .env("OZBOX_CONFIG", dir.join("config.toml"))
        .env("OZBOX_SETTINGS", dir.join("settings.json"))
        .env("OZBOX_SECRET_STORE", "memory")
        .env("HOME", dir)
        .env_remove("HCLOUD_TOKEN")
        .write_stdin("");
    c
}

#[test]
fn the_free_sandbox_is_set_up_without_a_cloud() -> TestResult {
    let d = tempfile::tempdir()?;
    cmd(d.path())
        .args(["--provider", "fake", "--yes", "init"])
        .assert()
        .success()
        .stdout(predicate::str::contains("sandbox"));
    let config = std::fs::read_to_string(d.path().join("config.toml"))?;
    assert!(config.contains("provider = \"fake\""));
    let setup = std::fs::read_to_string(d.path().join("setup.json"))?;
    assert!(setup.contains("\"completed\": true"), "{setup}");
    // Run again: nothing breaks.
    cmd(d.path())
        .args(["--provider", "fake", "--yes", "init"])
        .assert()
        .success();
    Ok(())
}

#[test]
fn a_dry_run_changes_nothing_and_a_script_without_yes_is_refused() -> TestResult {
    let d = tempfile::tempdir()?;
    cmd(d.path())
        .args(["--provider", "fake", "--dry-run", "init"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Dry run"));
    assert!(!d.path().join("config.toml").exists());
    cmd(d.path())
        .args(["--provider", "fake", "init"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("--yes"));
    assert!(!d.path().join("config.toml").exists());
    Ok(())
}

#[test]
fn a_cloud_needs_to_be_named() -> TestResult {
    let d = tempfile::tempdir()?;
    cmd(d.path())
        .args(["--yes", "init"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("--provider"));
    Ok(())
}
