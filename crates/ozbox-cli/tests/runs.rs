//! End-to-end: `ozbox run` and `ozbox approvals` against a task store in a temp dir. Starting a run only queues it;
//! the supervisor (in `ozbox serve`) is covered by the core and server tests.

use assert_cmd::Command;
use ozbox_core::run::{
    ActionKind, ApprovalRequest, ApprovalState, RunCaps, RunOrigin, RunSpec, TaskState, TaskStore,
};
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

    fn store(&self) -> TaskStore {
        TaskStore::new(self.dir.path().join("tasks.json"))
    }
}

#[test]
fn a_run_is_queued_listed_shown_stopped_and_started_again() -> TestResult {
    let e = Env::new()?;
    let v = e.json(&[
        "run",
        "start",
        "--engine",
        "fake",
        "--box",
        "alpha",
        "--prompt",
        "fix it",
        "--max-spend",
        "5",
        "--max-minutes",
        "30",
        "--deliver",
        "pr,alert",
    ])?;
    let id = v["id"].as_str().ok_or("no id")?.to_string();
    assert_eq!(
        (v["state"].as_str(), v["created"].as_bool()),
        (Some("queued"), Some(true))
    );
    let list = e.json(&["run", "list", "--state", "queued"])?;
    assert_eq!(list["items"][0]["id"], id);
    assert_eq!(list["items"][0]["caps"]["max_spend_cents"], 500);
    assert_eq!(list["items"][0]["caps"]["max_runtime_s"], 1800);
    let show = e.json(&["run", "show", &id])?;
    assert_eq!(show["prompt"], "fix it");
    assert_eq!(
        e.json(&["run", "list", "--box", "bravo"])?["items"]
            .as_array()
            .map(Vec::len),
        Some(0)
    );
    e.cmd()
        .args(["run", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("queued").and(predicate::str::contains("alpha")));
    // a queued run is cancelled at once; it can then be retried, and a finished one cannot be cancelled again
    e.cmd().args(["run", "cancel", &id]).assert().success();
    assert_eq!(e.json(&["run", "show", &id])?["state"], "cancelled");
    e.cmd().args(["run", "cancel", &id]).assert().failure();
    let retried = e.json(&["run", "retry", &id])?;
    assert_eq!(retried["retry_of"], id);
    Ok(())
}

#[test]
fn a_dry_run_and_a_bad_request_change_nothing() -> TestResult {
    let e = Env::new()?;
    let v = e.json(&[
        "run",
        "start",
        "--engine",
        "fake",
        "--box",
        "alpha",
        "--prompt",
        "x",
        "--dry-run",
    ])?;
    assert_eq!(v["dry_run"], true);
    assert!(!e.dir.path().join("tasks.json").exists());
    e.cmd()
        .args(["run", "start", "--engine", "fake", "--box", "alpha"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Say what the agent should do"));
    e.cmd()
        .args([
            "run",
            "start",
            "--engine",
            "Bad Engine",
            "--box",
            "alpha",
            "--prompt",
            "x",
        ])
        .assert()
        .failure();
    e.cmd()
        .args([
            "run",
            "start",
            "--engine",
            "fake",
            "--box",
            "alpha",
            "--prompt",
            "x",
            "--deliver",
            "fax",
        ])
        .assert()
        .failure();
    e.cmd()
        .args(["run", "resume", "t1"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Say how much to add"));
    assert!(!e.dir.path().join("tasks.json").exists());
    Ok(())
}

#[test]
fn the_same_idempotency_key_returns_the_first_run() -> TestResult {
    let e = Env::new()?;
    let args = [
        "run",
        "start",
        "--engine",
        "fake",
        "--box",
        "alpha",
        "--prompt",
        "x",
        "--idempotency-key",
        "nightly:1",
    ];
    let a = e.json(&args)?;
    let b = e.json(&args)?;
    assert_eq!(
        (a["id"].clone(), b["created"].clone()),
        (b["id"].clone(), Value::Bool(false))
    );
    Ok(())
}

fn seed_approval(e: &Env, step_up: bool) -> String {
    let spec = RunSpec {
        interactive: false,
        engine: "fake".into(),
        prompt: "x".into(),
        skill: None,
        box_name: "alpha".into(),
        repo: None,
        branch: None,
        caps: RunCaps::default(),
        deliver_to: vec![],
        requested_by: "owner".into(),
        origin: RunOrigin::Manual,
        idempotency_key: None,
        model: None,
    };
    e.store()
        .update(|b| {
            let (id, _) = b.enqueue(spec, 1, None).unwrap_or_default();
            if let Some(t) = b.task_mut(&id) {
                t.state = TaskState::NeedsYou;
            }
            b.approvals.push(ApprovalRequest {
                id: "a1".into(),
                task_id: id,
                kind: ActionKind::PushProtectedBranch,
                action: "git push origin main".into(),
                box_name: "alpha".into(),
                asked_by: "fake for owner".into(),
                production: step_up,
                needs_step_up: step_up,
                state: ApprovalState::Pending,
                created_ms: 1,
                expires_ms: u64::MAX / 2,
                reminders: 0,
                decided_by: None,
                decided_ms: None,
                decided_with_step_up: false,
                delivered: false,
                used: false,
            });
            "a1".to_string()
        })
        .unwrap_or_default()
}

#[test]
fn approvals_are_listed_decided_once_and_audited() -> TestResult {
    let e = Env::new()?;
    e.cmd()
        .args(["approvals", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Nothing is waiting"));
    let id = seed_approval(&e, false);
    let list = e.json(&["approvals", "list"])?;
    assert_eq!(list["items"][0]["action"], "git push origin main");
    e.cmd()
        .args(["approvals", "approve", &id, "--dry-run"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Nothing was changed"));
    assert_eq!(
        e.json(&["approvals", "list"])?["items"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );
    let v = e.json(&["approvals", "approve", &id])?;
    assert_eq!(v["state"], "approved");
    e.cmd().args(["approvals", "deny", &id]).assert().failure();
    assert_eq!(
        e.json(&["approvals", "list"])?["items"]
            .as_array()
            .map(Vec::len),
        Some(0)
    );
    let all = e.json(&["approvals", "list", "--all"])?;
    assert_eq!(all["items"][0]["decided_by"], "owner");
    let book = e.store().load()?;
    assert!(book.audit.iter().any(|a| a.action == "approval.approved"));
    e.cmd()
        .args(["approvals", "approve", "nope"])
        .assert()
        .failure();
    Ok(())
}

#[test]
fn a_request_that_needs_a_second_factor_needs_an_explicit_yes_here() -> TestResult {
    let e = Env::new()?;
    let id = seed_approval(&e, true);
    e.cmd()
        .args(["approvals", "approve", &id])
        .assert()
        .failure()
        .stderr(predicate::str::contains("second factor"));
    assert_eq!(
        e.json(&["approvals", "list"])?["items"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );
    // denying never needs it
    e.cmd().args(["approvals", "deny", &id]).assert().success();
    Ok(())
}

#[test]
fn a_run_can_name_its_model_and_a_price_is_set_and_cleared() -> TestResult {
    let e = Env::new()?;
    let settings = e.dir.path().join("settings.json");
    let run = |args: &[&str]| -> Result<Value, Box<dyn std::error::Error>> {
        let out = e
            .cmd()
            .env("OZBOX_SETTINGS", &settings)
            .args(args)
            .arg("--json")
            .output()?;
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        Ok(serde_json::from_slice(&out.stdout)?)
    };
    // a malformed model is refused before anything is queued
    e.cmd()
        .args([
            "run", "start", "--engine", "fake", "--box", "alpha", "--prompt", "x", "--model",
            "nonsense",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("provider/model"));
    let v = run(&[
        "run",
        "start",
        "--engine",
        "fake",
        "--box",
        "alpha",
        "--prompt",
        "x",
        "--model",
        "main/gpt-4o",
    ])?;
    let id = v["id"].as_str().ok_or("no id")?.to_string();
    let task = e.store().load()?.task(&id).cloned().ok_or("no task")?;
    assert_eq!(
        task.spec.model.as_ref().map(|m| m.model.as_str()),
        Some("gpt-4o")
    );
    // prices: a provider must exist first
    e.cmd()
        .env("OZBOX_SETTINGS", &settings)
        .args([
            "models", "price", "set", "main", "gpt-4o", "--input", "1", "--output", "2",
        ])
        .assert()
        .failure();
    run(&["models", "add", "main", "--kind", "openai"])?;
    let set = run(&[
        "models", "price", "set", "main", "gpt-4o", "--input", "1.5", "--output", "6",
    ])?;
    assert_eq!(set["price_set"], true);
    let saved: Value = serde_json::from_str(&std::fs::read_to_string(&settings)?)?;
    assert_eq!(
        saved["models"]["prices"]["main/gpt-4o"]["input_per_mtok_usd"],
        1.5
    );
    let dry = run(&["--dry-run", "models", "price", "clear", "main", "gpt-4o"])?;
    assert_eq!(dry["dry_run"], true);
    assert!(
        std::fs::read_to_string(&settings)?.contains("main/gpt-4o"),
        "a dry run changes nothing"
    );
    run(&["models", "price", "clear", "main", "gpt-4o"])?;
    assert!(!std::fs::read_to_string(&settings)?.contains("main/gpt-4o"));
    Ok(())
}
