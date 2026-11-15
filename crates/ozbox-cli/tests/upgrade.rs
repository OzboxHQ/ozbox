//! End-to-end: `ozbox upgrade` against the fake provider and the simulated agent, state in a temp dir.

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Env {
    dir: tempfile::TempDir,
}

impl Env {
    fn new() -> Result<Self, std::io::Error> {
        Ok(Self {
            dir: tempfile::tempdir()?,
        })
    }

    fn cmd(&self) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_ozbox"));
        c.env("OZBOX_STATE_DIR", self.dir.path().join("state"))
            .env("OZBOX_CONFIG", self.dir.path().join("config.toml"))
            .env("HOME", self.dir.path())
            .env_remove("HCLOUD_TOKEN")
            .write_stdin("");
        c
    }

    fn create(&self, name: &str, extra: &[&str]) {
        self.cmd()
            .args(["create", name, "--size", "S", "--disk", "50", "--yes"])
            .args(extra)
            .assert()
            .success();
    }
}

#[test]
fn upgrade_replaces_the_system_disk_keeps_work_and_runs_the_self_test() -> TestResult {
    let e = Env::new()?;
    e.create("dev", &[]);
    // a dry run shows the whole plan, including what is NOT touched, and changes nothing
    e.cmd()
        .args(["upgrade", "dev", "--dry-run"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("Newest image: fake-image-2026.12.0")
                .and(predicate::str::contains("Release signature: not checked"))
                .and(predicate::str::contains("Replace the system disk of dev"))
                .and(predicate::str::contains("the /work disk is NOT touched"))
                .and(predicate::str::contains("Dry run: nothing was changed.")),
        );
    e.cmd()
        .args(["show", "dev"])
        .assert()
        .success()
        .stdout(predicate::str::contains("image:").not());
    e.cmd()
        .args(["upgrade", "dev", "--yes"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("Upgraded. dev is running on image fake-image-2026.12.0")
                .and(predicate::str::contains("pass     work disk mounted"))
                .and(predicate::str::contains("Self-test passed.")),
        );
    e.cmd().args(["show", "dev"]).assert().success().stdout(
        predicate::str::contains("image:      fake-image-2026.12.0")
            .and(predicate::str::contains("work disk:  50 GB")),
    );
    // again: nothing to do, and no confirmation needed
    e.cmd()
        .args(["upgrade", "dev"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Nothing to do"));
    Ok(())
}

#[test]
fn json_output_carries_the_plan_and_what_happened_around_it() -> TestResult {
    let e = Env::new()?;
    e.create("dev", &[]);
    let out = e
        .cmd()
        .args([
            "upgrade",
            "dev",
            "--image",
            "fake-image-2",
            "--yes",
            "--json",
        ])
        .output()?;
    assert!(out.status.success());
    let v: Value = serde_json::from_slice(&out.stdout)?;
    assert_eq!(v["applied"], true);
    assert_eq!(v["plan"]["operation"]["op"], "upgrade");
    assert_eq!(v["result"]["spec"]["image"], "fake-image-2");
    assert_eq!(v["upgrade"]["image"], "fake-image-2");
    assert_eq!(v["upgrade"]["checkpoint"]["outcome"], "done");
    assert_eq!(v["upgrade"]["ready"]["outcome"], "done");
    assert_eq!(v["upgrade"]["selftest"]["ok"], true);
    Ok(())
}

#[test]
fn an_image_for_another_architecture_is_refused_and_nothing_changes() -> TestResult {
    let e = Env::new()?;
    e.create("dev", &[]);
    e.cmd()
        .args(["upgrade", "dev", "--image", "fake-image-arm64", "--yes"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("arm64"));
    e.cmd()
        .args(["show", "dev"])
        .assert()
        .success()
        .stdout(predicate::str::contains("image:").not());
    Ok(())
}

#[test]
fn an_upgrade_without_yes_on_a_non_terminal_is_refused_after_showing_the_plan() -> TestResult {
    let e = Env::new()?;
    e.create("dev", &[]);
    e.cmd()
        .args(["upgrade", "dev"])
        .assert()
        .failure()
        .stdout(predicate::str::contains("Replace the system disk"))
        .stderr(predicate::str::contains("without confirmation"));
    Ok(())
}

#[test]
fn a_failed_self_test_is_shown_and_makes_the_command_fail_though_the_box_was_upgraded() -> TestResult
{
    let e = Env::new()?;
    e.create("dev", &["--label", "sim_profile=failing"]);
    e.cmd()
        .args(["upgrade", "dev", "--yes"])
        .assert()
        .failure()
        .stdout(
            predicate::str::contains("FAILED   tunnels up")
                .and(predicate::str::contains("Self-test FAILED.")),
        )
        .stderr(predicate::str::contains("self-test failed"));
    e.cmd()
        .args(["show", "dev"])
        .assert()
        .success()
        .stdout(predicate::str::contains("image:      fake-image-2026.12.0"));
    Ok(())
}

#[test]
fn a_missing_box_and_a_paused_box_are_handled() -> TestResult {
    let e = Env::new()?;
    e.cmd()
        .args(["upgrade", "ghost", "--yes"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("ghost"));
    e.create("dev", &[]);
    e.cmd().args(["pause", "dev", "--yes"]).assert().success();
    e.cmd()
        .args(["upgrade", "dev", "--yes"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("leaves it running")
                .and(predicate::str::contains("Upgraded. dev is running")),
        );
    Ok(())
}

impl Env {
    /// The fake cloud refuses the next machine an upgrade creates, after the old one is gone.
    fn refuse_next_machine(&self) -> TestResult {
        let path = self.dir.path().join("state").join("state.json");
        let mut v: Value = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
        v["refuse_next_create"] = Value::Bool(true);
        std::fs::write(&path, serde_json::to_vec(&v)?)?;
        Ok(())
    }
}

#[test]
fn a_refused_new_machine_leaves_a_listed_box_that_the_same_command_finishes() -> TestResult {
    let e = Env::new()?;
    e.create("dev", &[]);
    e.refuse_next_machine()?;
    // The failure says plainly: /work is safe, nothing runs, and the exact command to re-run.
    e.cmd()
        .args(["upgrade", "dev", "--image", "fake-image-2", "--yes"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("/work is safe")
                .and(predicate::str::contains("no running machine"))
                .and(predicate::str::contains("ozbox upgrade dev")),
        );
    // Listed, in a state that says what to do.
    e.cmd().arg("list").assert().success().stdout(
        predicate::str::contains("instance missing").and(predicate::str::contains(
            "Run `ozbox upgrade dev` to finish",
        )),
    );
    e.cmd()
        .args(["show", "dev"])
        .assert()
        .success()
        .stdout(predicate::str::contains("state:      instance missing"));
    // The default goes to the image it was marked with, not to the newest, and the plan keeps /work.
    e.cmd()
        .args(["upgrade", "dev", "--dry-run"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("finishing the interrupted upgrade to fake-image-2")
                .and(predicate::str::contains("Create a new machine for dev"))
                .and(predicate::str::contains("/work disk is NOT touched"))
                .and(predicate::str::contains("Delete").not()),
        );
    // Nothing else acts on it.
    e.cmd().args(["pause", "dev", "--yes"]).assert().failure();
    e.cmd()
        .args(["upgrade", "dev", "--yes"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Upgraded. dev is running on image fake-image-2",
        ));
    Ok(())
}

#[test]
fn the_json_of_an_interrupted_upgrade_says_so_in_an_additive_field() -> TestResult {
    let e = Env::new()?;
    e.create("dev", &[]);
    e.refuse_next_machine()?;
    let out = e
        .cmd()
        .args([
            "upgrade",
            "dev",
            "--image",
            "fake-image-2",
            "--yes",
            "--json",
        ])
        .output()?;
    assert!(!out.status.success());
    let v: Value = serde_json::from_slice(&out.stdout)?;
    assert_eq!(v["applied"], false);
    assert_eq!(v["interrupted"]["state"], "instance_missing");
    assert_eq!(v["interrupted"]["work_kept"], true);
    assert_eq!(v["interrupted"]["rerun"], "ozbox upgrade dev");
    assert_eq!(v["interrupted"]["image"], "fake-image-2");
    Ok(())
}

impl Env {
    /// The sandbox's newest image reports that its release signature could not be verified.
    fn mark_images_unsigned(&self) -> TestResult {
        let path = self.dir.path().join("state").join("state.json");
        let mut v: Value = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
        v["unsigned_images"] = Value::Bool(true);
        std::fs::write(&path, serde_json::to_vec(&v)?)?;
        Ok(())
    }
}

#[test]
fn an_image_that_could_not_be_verified_is_refused_unless_the_flag_names_it() -> TestResult {
    let e = Env::new()?;
    e.create("dev", &[]);
    e.mark_images_unsigned()?;
    // refused before anything is confirmed, even as a dry run, and nothing changes
    e.cmd()
        .args(["upgrade", "dev", "--dry-run"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("Refusing to upgrade")
                .and(predicate::str::contains("--allow-unverified-image")),
        );
    e.cmd()
        .args(["show", "dev"])
        .assert()
        .success()
        .stdout(predicate::str::contains("image:").not());
    // asked for by name: the plan says so in a warning, and it goes ahead
    e.cmd()
        .args(["upgrade", "dev", "--allow-unverified-image", "--yes"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("note: WARNING: image fake-image-2026.12.0")
                .and(predicate::str::contains("Upgraded. dev is running")),
        );
    Ok(())
}

#[test]
fn the_final_output_says_exactly_what_to_do_about_backup_credentials() -> TestResult {
    let e = Env::new()?;
    e.create("dev", &[]);
    e.cmd()
        .args(["upgrade", "dev", "--yes"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("Send credentials")
                .and(predicate::str::contains("NOT restored"))
                .and(predicate::str::contains("note: Backups:")),
        );
    let out = e
        .cmd()
        .args([
            "upgrade",
            "dev",
            "--image",
            "fake-image-3",
            "--yes",
            "--json",
        ])
        .output()?;
    let v: Value = serde_json::from_slice(&out.stdout)?;
    assert_eq!(v["upgrade"]["backup_credentials"]["outcome"], "skipped");
    Ok(())
}

#[test]
fn a_box_with_no_machine_can_be_destroyed_by_typing_its_name() -> TestResult {
    let e = Env::new()?;
    e.create("dev", &[]);
    e.refuse_next_machine()?;
    e.cmd()
        .args(["upgrade", "dev", "--image", "fake-image-2", "--yes"])
        .assert()
        .failure();
    // the plan says what goes (typing the name is the interactive confirmation of every destroy)
    e.cmd()
        .args(["destroy", "dev", "--dry-run"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("already missing")
                .and(predicate::str::contains("/work"))
                .and(predicate::str::contains("final snapshot")),
        );
    e.cmd().args(["destroy", "dev", "--yes"]).assert().success();
    e.cmd().args(["show", "dev"]).assert().failure();
    Ok(())
}

#[test]
fn admin_describes_an_allow_listed_action_first_and_refuses_anything_else() -> TestResult {
    let e = Env::new()?;
    e.create("dev", &[]);
    e.cmd()
        .args([
            "admin",
            "dev",
            "--dry-run",
            "--",
            "reown",
            "--from-uid",
            "1000",
        ])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("as root: put the files")
                .and(predicate::str::contains("owner 1000"))
                .and(predicate::str::contains("Dry run: nothing was changed.")),
        );
    // no shell, no other command, nothing is sent to the box
    for bad in [
        ["bash", "-c", "id"],
        ["reown", "--path", "/etc"],
        ["restart-services", "ssh", ""],
    ] {
        let words: Vec<&str> = bad.iter().copied().filter(|w| !w.is_empty()).collect();
        e.cmd()
            .args(["admin", "dev", "--yes", "--"])
            .args(&words)
            .assert()
            .failure();
    }
    // without --yes and without a terminal it refuses rather than asks
    e.cmd()
        .args(["admin", "dev", "--", "collect-logs"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("without confirmation"));
    Ok(())
}
