//! End to end: the real binary against the fake provider and its simulated tool installer.

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
            .env("OZBOX_PROFILES", self.dir.path().join("profiles"))
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

    fn create(&self, name: &str) -> TestResult {
        self.cmd()
            .args(["create", name, "--size", "M", "--disk", "100", "--yes"])
            .assert()
            .success();
        Ok(())
    }
}

#[test]
fn plan_changes_nothing_and_install_needs_yes_without_a_terminal() -> TestResult {
    let e = Env::new()?;
    e.create("dev")?;
    e.cmd()
        .args(["tools", "plan", "dev", "bundle:ai-agents"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("Plan for dev")
                .and(predicate::str::contains("Node.js 22"))
                .and(predicate::str::contains("needed by")),
        );
    let v = e.json(&["tools", "list", "dev"])?;
    assert!(v["tools"]
        .as_array()
        .ok_or("tools")?
        .iter()
        .all(|t| t["installed"] == false));
    e.cmd()
        .args(["tools", "install", "dev", "jq"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("without confirmation"));
    e.cmd()
        .args(["tools", "install", "dev", "jq", "--dry-run"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Dry run"));
    // An unverified tool is refused with its reason, a typo with a clear message.
    e.cmd()
        .args(["tools", "install", "dev", "docker", "--yes"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not verified"));
    e.cmd()
        .args(["tools", "plan", "dev", "nope"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no tool named nope"));
    e.cmd()
        .args(["tools", "plan", "dev"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Name at least one"));
    Ok(())
}

#[test]
fn installing_a_bundle_then_removing_one_tool() -> TestResult {
    let e = Env::new()?;
    e.create("dev")?;
    e.cmd()
        .args(["tools", "install", "dev", "bundle:ai-agents", "--yes"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("Done.").and(predicate::str::contains("Sign in on the box")),
        );
    let v = e.json(&["tools", "list", "dev"])?;
    let on: Vec<&str> = v["tools"]
        .as_array()
        .ok_or("t")?
        .iter()
        .filter(|t| t["installed"] == true)
        .filter_map(|t| t["id"].as_str())
        .collect();
    assert!(on.contains(&"claude-code") && on.contains(&"aider") && on.contains(&"node"));
    // A second install is a no-op.
    e.cmd()
        .args(["tools", "install", "dev", "claude-code", "--yes"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Nothing to do"));
    // A tool another one needs is not removed by itself.
    e.cmd()
        .args(["tools", "remove", "dev", "node", "--yes"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("needed by"));
    e.cmd()
        .args(["tools", "remove", "dev", "codex", "--yes"])
        .assert()
        .success();
    let v = e.json(&["tools", "list", "dev"])?;
    assert!(v["tools"]
        .as_array()
        .ok_or("t")?
        .iter()
        .any(|t| t["id"] == "codex" && t["installed"] == false));
    Ok(())
}

#[test]
fn profiles_save_list_show_delete_and_create_from() -> TestResult {
    let e = Env::new()?;
    e.create("dev")?;
    e.cmd()
        .args(["tools", "install", "dev", "jq", "neovim", "--yes"])
        .assert()
        .success();
    e.cmd()
        .args([
            "profile",
            "save",
            "dev",
            "mine",
            "--description",
            "My setup",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Saved profile mine"));
    let file = e.dir.path().join("profiles/mine.toml");
    let text = std::fs::read_to_string(&file)?;
    assert!(
        text.contains("jq")
            && text.contains("neovim")
            && text.contains("size = \"M\"")
            && text.contains("disk_gb = 100")
    );
    e.cmd()
        .args(["profile", "save", "dev", "mine"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
    e.cmd()
        .args(["profile", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("mine").and(predicate::str::contains("My setup")));
    e.cmd()
        .args(["profile", "show", "mine"])
        .assert()
        .success()
        .stdout(predicate::str::contains("[box]"));
    // A box from the profile has its size, disk and tools.
    e.cmd()
        .args(["create", "copy", "--profile", "mine", "--yes"])
        .assert()
        .success();
    let shown = e.json(&["show", "copy"])?;
    assert_eq!(shown["spec"]["work_disk_gb"], 100);
    let v = e.json(&["tools", "list", "copy"])?;
    let on: Vec<&str> = v["tools"]
        .as_array()
        .ok_or("t")?
        .iter()
        .filter(|t| t["installed"] == true)
        .filter_map(|t| t["id"].as_str())
        .collect();
    assert!(on.contains(&"jq") && on.contains(&"neovim"));
    // A hand-edited bad profile is refused with the reason.
    std::fs::write(&file, "tools = [\"docker\"]\n")?;
    e.cmd()
        .args(["create", "bad", "--profile", "mine", "--yes"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not verified"));
    e.cmd()
        .args(["profile", "delete", "mine"])
        .assert()
        .success();
    e.cmd().args(["profile", "show", "mine"]).assert().failure();
    Ok(())
}

#[test]
fn create_with_tools_installs_them_on_the_demo_provider() -> TestResult {
    let e = Env::new()?;
    e.cmd()
        .args(["create", "dev", "--yes", "--tools", "bundle:web,htop"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Done."));
    let v = e.json(&["tools", "list", "dev"])?;
    let on: Vec<&str> = v["tools"]
        .as_array()
        .ok_or("t")?
        .iter()
        .filter(|t| t["installed"] == true)
        .filter_map(|t| t["id"].as_str())
        .collect();
    assert!(on.contains(&"node") && on.contains(&"podman") && on.contains(&"htop"));
    e.cmd()
        .args(["create", "x", "--yes", "--tools", "nope"])
        .assert()
        .failure();
    Ok(())
}

#[test]
fn agent_requests_are_listed_and_decided_by_the_owner() -> TestResult {
    let e = Env::new()?;
    e.create("dev")?;
    e.cmd()
        .args(["tools", "requests", "dev"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No tool requests"));
    e.cmd()
        .args(["tools", "approve", "dev", "rnope"])
        .assert()
        .failure();
    Ok(())
}
