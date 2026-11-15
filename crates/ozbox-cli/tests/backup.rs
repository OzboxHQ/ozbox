//! End-to-end: `ozbox backup` against the fake provider, state in a temp dir.

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
            .env("OZBOX_SECRET_STORE", "memory")
            .env("HOME", self.dir.path())
            .env_remove("HCLOUD_TOKEN")
            .write_stdin("");
        c
    }

    fn create(&self, name: &str) {
        self.cmd()
            .args(["create", name, "--size", "S", "--disk", "50", "--yes"])
            .assert()
            .success();
    }

    fn json(&self, args: &[&str]) -> Result<Value, Box<dyn std::error::Error>> {
        let out = self.cmd().args(args).arg("--json").output()?;
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        Ok(serde_json::from_slice(&out.stdout)?)
    }
}

#[test]
fn the_schedule_is_shown_changed_and_remembered_and_a_dry_run_saves_nothing() -> TestResult {
    let e = Env::new()?;
    e.cmd()
        .args(["backup", "schedule"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("Schedule: off").and(predicate::str::contains(
                "Keeps 7 daily, 4 weekly, 6 monthly",
            )),
        );
    e.cmd()
        .args([
            "backup",
            "schedule",
            "--every",
            "daily",
            "--at",
            "03:30",
            "--dry-run",
        ])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("every day at 03:30")
                .and(predicate::str::contains("nothing was saved")),
        );
    e.cmd()
        .args(["backup", "schedule"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Schedule: off"));
    e.cmd()
        .args([
            "backup",
            "schedule",
            "--every",
            "weekly",
            "--on",
            "sun",
            "--at",
            "02:00",
            "--keep-daily",
            "3",
        ])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("every sun at 02:00").and(predicate::str::contains("Saved.")),
        );
    let v = e.json(&["backup", "schedule"])?;
    assert_eq!(v["schedule"]["kind"], "weekly");
    assert_eq!(v["schedule"]["weekday"], 6);
    assert_eq!(v["retention"]["keep_daily"], 3);
    // one box off, the fleet unchanged
    e.cmd()
        .args(["backup", "schedule", "--box", "dev", "--every", "off"])
        .assert()
        .success();
    let one = e.json(&["backup", "schedule", "--box", "dev"])?;
    assert_eq!(one["schedule"]["kind"], "off");
    assert_eq!(
        e.json(&["backup", "schedule"])?["schedule"]["kind"],
        "weekly"
    );
    Ok(())
}

#[test]
fn a_schedule_that_cannot_work_is_refused_and_says_why() -> TestResult {
    let e = Env::new()?;
    e.cmd()
        .args(["backup", "schedule", "--every", "daily", "--at", "25:00"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("HH:MM"));
    e.cmd()
        .args([
            "backup", "schedule", "--every", "weekly", "--on", "someday", "--at", "02:00",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not a weekday"));
    e.cmd()
        .args([
            "backup",
            "schedule",
            "--keep-daily",
            "0",
            "--keep-weekly",
            "0",
            "--keep-monthly",
            "0",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("at least one backup"));
    Ok(())
}

#[test]
fn back_up_list_restore_to_a_new_box_and_delete_through_plans() -> TestResult {
    let e = Env::new()?;
    e.create("dev");
    e.cmd()
        .args(["backup", "list", "dev"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No backups of dev yet"));
    // a dry run plans and changes nothing
    e.cmd()
        .args(["backup", "now", "dev", "--dry-run"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Snapshot").and(predicate::str::contains("Dry run")));
    assert_eq!(
        e.json(&["backup", "list", "dev"])?["items"]
            .as_array()
            .map(Vec::len),
        Some(0)
    );
    e.cmd()
        .args(["backup", "now", "dev", "--yes"])
        .assert()
        .success();
    let list = e.json(&["backup", "list", "dev"])?;
    let items = list["items"].as_array().ok_or("no items")?;
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["kind"], "snapshot");
    assert_eq!(items[0]["includes_work"], true);
    assert!(items[0]["created_at"].is_string() && items[0]["size_bytes"].is_u64());
    let id = items[0]["id"].as_str().ok_or("no id")?.to_string();

    // restore needs a target; to a new box it clones from that snapshot, and the original keeps it
    e.cmd()
        .args(["backup", "restore", "dev", &id])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--new-box"));
    e.cmd()
        .args([
            "backup",
            "restore",
            "dev",
            &id,
            "--new-box",
            "copy",
            "--yes",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "restored from snapshot {id}"
        )));
    e.cmd().args(["show", "copy"]).assert().success();
    // in place: high risk, and the way back is taken first (a second snapshot appears)
    e.cmd()
        .args(["backup", "restore", "dev", &id, "--in-place", "--dry-run"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("CANNOT BE UNDONE")
                .and(predicate::str::contains("as it is now")),
        );
    e.cmd()
        .args(["backup", "restore", "dev", &id, "--in-place", "--yes"])
        .assert()
        .success();
    assert_eq!(
        e.json(&["backup", "list", "dev"])?["items"]
            .as_array()
            .map(Vec::len),
        Some(2)
    );

    // delete: an id that is not the box's is refused by name, a real one is removed
    e.cmd()
        .args(["backup", "delete", "dev", "nope"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("is not a backup of dev"));
    e.cmd()
        .args(["backup", "delete", "dev", &id, "--yes"])
        .assert()
        .success();
    let left = e.json(&["backup", "list", "dev"])?;
    assert_eq!(left["items"].as_array().map(Vec::len), Some(1));
    assert_ne!(left["items"][0]["id"], Value::String(id));
    Ok(())
}

#[test]
fn a_repository_backup_without_a_repository_says_to_set_one_up_and_never_plans() -> TestResult {
    let e = Env::new()?;
    e.create("dev");
    e.cmd()
        .args(["backup", "now", "dev", "--to", "restic", "--yes"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no backup repository is set up"));
    e.cmd()
        .args(["backup", "list", "dev"])
        .assert()
        .success()
        .stdout(predicate::str::contains("no repository is set up"));
    Ok(())
}
