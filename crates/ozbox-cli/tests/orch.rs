//! End-to-end: `ozbox orch` against a task store in a temp dir. Starting a feature only records it; `ozbox serve` makes the
//! worker's task (covered by the server tests).

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
fn an_orchestration_is_started_followed_and_stopped_from_the_command_line() -> TestResult {
    let e = Env::new()?;
    std::fs::write(
        e.dir.path().join("rules.md"),
        "---\nmax_workers: 2\nmax_sub_agents: 9\ntest_command: make test\n---\nSmall commits.\n",
    )?;
    let rules = e.dir.path().join("rules.md");
    // the rules file is checked, and what the settings do not allow is named
    let p = e.json(&["orch", "rules", rules.to_str().ok_or("path")?])?;
    assert_eq!(
        (p["max_workers"].clone(), p["max_sub_agents"].clone()),
        (2.into(), 3.into())
    );
    assert!(p["notes"].as_array().map_or(0, Vec::len) >= 1);
    e.cmd()
        .args(["orch", "start", "--goal", "x", "--box", "main", "--dry-run"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Nothing was started"));
    let v = e.json(&[
        "orch",
        "start",
        "--goal",
        "Add invoices",
        "--box",
        "main",
        "--rules-file",
        rules.to_str().ok_or("path")?,
        "--max-spend",
        "20",
    ])?;
    let id = v["id"].as_str().ok_or("no id")?.to_string();
    let show = e.json(&["orch", "show", &id])?;
    assert_eq!(show["policy"]["max_workers"], 2);
    assert_eq!(show["cap_cents"], 2000);
    // features: a claim overlap is refused, a fourth sub-agent is refused
    e.cmd()
        .args([
            "orch",
            "feature",
            &id,
            "--title",
            "API",
            "--brief",
            "build the api",
            "--claim",
            "src/api",
            "--box",
            "w-a",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Added feature f1"));
    e.cmd()
        .args([
            "orch",
            "feature",
            &id,
            "--title",
            "Dup",
            "--brief",
            "x",
            "--claim",
            "src/api/users",
            "--box",
            "w-b",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("overlaps"));
    e.cmd()
        .args([
            "orch",
            "feature",
            &id,
            "--title",
            "Big",
            "--brief",
            "x",
            "--sub-agents",
            "4",
            "--box",
            "w-b",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("sub-agents"));
    // claims, a contract and a message
    let c = e.json(&[
        "orch",
        "claims",
        &id,
        "f1",
        "--check",
        "src/api/x.rs,src/web/y.rs",
    ])?;
    assert_eq!(
        (
            c["paths"][0]["allowed"].clone(),
            c["paths"][1]["allowed"].clone()
        ),
        (true.into(), false.into())
    );
    std::fs::write(e.dir.path().join("api.yaml"), "GET /invoices")?;
    let k = e.json(&[
        "orch",
        "contract",
        &id,
        "--name",
        "Invoices API",
        "--body-file",
        e.dir.path().join("api.yaml").to_str().ok_or("path")?,
    ])?;
    assert_eq!(
        (k["id"].as_str(), k["version"].as_u64()),
        (Some("invoices-api"), Some(1))
    );
    e.json(&["orch", "message", &id, "f1", "--text", "use postgres"])?;
    assert_eq!(
        e.json(&["orch", "messages", &id])?["messages"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );
    let b = e.json(&["orch", "budget", &id])?;
    assert_eq!(
        (b["cap_cents"].clone(), b["spent_cents"].clone()),
        (2000.into(), 0.into())
    );
    assert_eq!(
        e.json(&["orch", "budget", &id, "--add", "5"])?["cap_cents"],
        2500
    );
    assert_eq!(
        e.json(&["orch", "merge", &id])?["queue"]
            .as_array()
            .map(Vec::len),
        Some(0)
    );
    assert_eq!(e.json(&["orch", "list"])?["items"][0]["features"], 1);
    e.cmd()
        .args(["orch", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Add invoices"));
    // pause, resume and stop; a stopped orchestration cannot be resumed
    e.json(&["orch", "pause", &id])?;
    assert_eq!(e.json(&["orch", "show", &id])?["state"], "paused");
    e.json(&["orch", "resume", &id])?;
    e.json(&["orch", "stop", &id])?;
    assert_eq!(e.json(&["orch", "show", &id])?["state"], "stopped");
    e.cmd().args(["orch", "resume", &id]).assert().failure();
    e.cmd()
        .args(["orch", "show", "nope"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no orchestration"));
    Ok(())
}

#[test]
fn the_limits_can_be_changed_and_the_mcp_settings_printed_with_no_secret() -> TestResult {
    let e = Env::new()?;
    assert_eq!(e.json(&["orch", "settings"])?["max_workers"], 3);
    assert_eq!(
        e.json(&[
            "orch",
            "settings",
            "--max-workers",
            "5",
            "--merge-approval",
            "conductor"
        ])?["max_workers"],
        5
    );
    e.cmd()
        .args(["orch", "settings", "--max-workers", "0"])
        .assert()
        .failure();
    e.cmd()
        .args(["orch", "settings", "--merge-approval", "anyone"])
        .assert()
        .failure();
    let cfg = e.json(&["orch", "mcp-config"])?;
    let text = cfg.to_string();
    assert!(text.contains("${OZBOX_MCP_URL}") && text.contains("${OZBOX_MCP_TOKEN}"));
    assert!(!text.contains("ozmt_"));
    Ok(())
}
