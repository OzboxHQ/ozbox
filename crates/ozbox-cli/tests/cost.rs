//! `ozbox cost`: the real binary on the demo provider (a made-up bill, a made-up account) and with a cloud selected but
//! `--dry-run`, which names what would be read and reads nothing.

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
            .env("OZBOX_SETTINGS", self.dir.path().join("settings.json"))
            .env("HOME", self.dir.path())
            .env_remove("HCLOUD_TOKEN")
            .write_stdin("");
        c
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
fn the_demo_bill_is_listed_by_box_and_service() -> TestResult {
    let e = Env::new()?;
    let v = e.json(&["cost", "bill"])?;
    assert_eq!(v["ok"], true);
    assert_eq!(v["currency"], "USD");
    assert!(v["boxes"]
        .as_array()
        .is_some_and(|b| b.iter().any(|x| x["box"] == "alpha")));
    assert!(v["services"].as_array().is_some_and(|s| !s.is_empty()));
    assert_eq!(v["lag_hours"], 24);
    e.cmd()
        .args(["cost", "bill"])
        .assert()
        .success()
        .stdout(predicate::str::contains("billed through"));
    Ok(())
}

#[test]
fn reconcile_names_the_flagged_days_and_their_cause() -> TestResult {
    let e = Env::new()?;
    let v = e.json(&["cost", "reconcile"])?;
    let drift = v["reconciliation"]["drift"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert_eq!(drift.len(), 4);
    assert_eq!(v["drift_threshold"]["percent"], 25.0);
    e.cmd()
        .args(["cost", "reconcile"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Amazon Virtual Private Cloud"));
    Ok(())
}

#[test]
fn orphans_are_listed_and_a_delete_needs_the_words_the_plan_names() -> TestResult {
    let e = Env::new()?;
    let v = e.json(&["cost", "orphans"])?;
    assert_eq!(v["scan"]["items"].as_array().map(Vec::len), Some(5));
    // a plan stops at --dry-run and changes nothing
    let v = e.json(&[
        "cost",
        "orphans",
        "--delete",
        "vol-0demo000retired",
        "--dry-run",
    ])?;
    assert_eq!(v["dry_run"], true);
    assert_eq!(v["plan"]["confirm_text"], "vol-0demo000retired");
    // without the words, and with --yes alone, nothing is deleted
    e.cmd()
        .args([
            "cost",
            "orphans",
            "--delete",
            "vol-0demo000retired",
            "--yes",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--confirm vol-0demo000retired"));
    e.cmd()
        .args([
            "cost",
            "orphans",
            "--delete",
            "vol-0demo000retired",
            "--confirm",
            "nope",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("type vol-0demo000retired exactly"));
    // an untagged lookalike can never be planned
    e.cmd()
        .args([
            "cost",
            "orphans",
            "--delete",
            "i-0demo000stray",
            "--confirm",
            "i-0demo000stray",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not something Oz Box may delete"));
    // the right words delete it (the demo account is made up, and fresh on every run)
    let v = e.json(&[
        "cost",
        "orphans",
        "--delete",
        "vol-0demo000retired",
        "--confirm",
        "vol-0demo000retired",
    ])?;
    assert_eq!(v["ok"], true);
    Ok(())
}

#[test]
fn a_dry_run_on_a_real_cloud_names_the_reads_and_runs_none() -> TestResult {
    let e = Env::new()?;
    let v = e.json(&["--provider", "aws", "--dry-run", "cost", "bill"])?;
    assert_eq!(v["dry_run"], true);
    let reads = v["reads"].as_array().cloned().unwrap_or_default();
    assert_eq!(reads.len(), 1);
    let read = reads[0].as_str().unwrap_or_default();
    assert!(read.starts_with("aws ce get-cost-and-usage"), "{read}");
    assert!(
        read.contains("Type=TAG,Key=ozbox-box") && read.contains("ozbox-managed"),
        "{read}"
    );
    let v = e.json(&[
        "--provider",
        "aws",
        "--dry-run",
        "cost",
        "orphans",
        "--region",
        "us-east-1",
    ])?;
    let reads = v["reads"].as_array().cloned().unwrap_or_default();
    assert_eq!(reads.len(), 4);
    assert!(reads
        .iter()
        .all(|r| r.as_str().is_some_and(|s| s.contains("describe-"))));
    Ok(())
}

#[test]
fn hetzner_has_no_bill_and_says_so_plainly() -> TestResult {
    let e = Env::new()?;
    e.cmd()
        .args(["--provider", "hcloud", "cost", "bill"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("does not publish invoices"));
    let out = e
        .cmd()
        .args(["--provider", "hcloud", "--json", "cost", "bill"])
        .output()?;
    assert!(!out.status.success());
    let v: Value = serde_json::from_slice(&out.stdout)?;
    assert_eq!(v["problem"], "unsupported");
    Ok(())
}
