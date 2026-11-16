//! End-to-end: the real binary against the fake provider, state in a temp dir.

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
fn full_lifecycle() -> TestResult {
    let e = Env::new()?;
    e.cmd()
        .args([
            "create",
            "dev",
            "--size",
            "M",
            "--disk",
            "100",
            "--label",
            "purpose=review",
            "--yes",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Done. dev is running"));
    e.cmd()
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("dev").and(predicate::str::contains("running")));
    e.cmd().args(["pause", "dev", "--yes"]).assert().success();
    e.cmd()
        .args(["show", "dev"])
        .assert()
        .success()
        .stdout(predicate::str::contains("state:      paused"));
    // pausing again is a no-op and needs no confirmation
    e.cmd()
        .args(["pause", "dev"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Nothing to do"));
    e.cmd().args(["resume", "dev", "--yes"]).assert().success();
    e.cmd()
        .args(["resize", "dev", "--size", "L", "--disk", "150", "--yes"])
        .assert()
        .success()
        .stdout(predicate::str::contains("stops it"));
    e.cmd()
        .args(["snapshot", "dev", "--yes"])
        .assert()
        .success();
    e.cmd()
        .args(["clone", "dev", "dev-2", "--yes"])
        .assert()
        .success();
    let show = e.json(&["show", "dev-2"])?;
    assert_eq!(show["spec"]["work_disk_gb"], 150);
    assert_eq!(show["spec"]["size"], "L");
    e.cmd()
        .args(["destroy", "dev", "--yes"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Done. dev is destroyed"));
    e.cmd()
        .args(["show", "dev"])
        .assert()
        .code(1)
        .stderr(predicate::str::starts_with("error: no box named"));
    let list = e.json(&["list"])?;
    assert_eq!(list.as_array().map(Vec::len), Some(1));
    Ok(())
}

#[test]
fn dry_run_changes_nothing() -> TestResult {
    let e = Env::new()?;
    e.cmd()
        .args(["create", "dev", "--size", "S", "--dry-run"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Dry run: nothing was changed"));
    assert_eq!(e.json(&["list"])?.as_array().map(Vec::len), Some(0));
    assert!(!e.dir.path().join("state/state.json").exists());
    Ok(())
}

#[test]
fn a_mutation_without_yes_on_a_non_terminal_is_refused() -> TestResult {
    let e = Env::new()?;
    e.cmd()
        .args(["create", "dev", "--size", "S", "--yes"])
        .assert()
        .success();
    e.cmd()
        .args(["destroy", "dev"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "refusing to destroy dev without confirmation",
        ));
    e.cmd().args(["show", "dev"]).assert().success();
    Ok(())
}

#[test]
fn bad_names_and_arguments_are_usage_errors() -> TestResult {
    let e = Env::new()?;
    for bad in ["Dev", "1box", "a--b", "../x", "a_b"] {
        e.cmd()
            .args(["create", bad, "--size", "S", "--yes"])
            .assert()
            .code(2);
    }
    e.cmd()
        .args(["create", "dev", "--size", "HUGE"])
        .assert()
        .code(2);
    e.cmd().args(["resize", "dev"]).assert().code(2);
    e.cmd().arg("frobnicate").assert().code(2);
    Ok(())
}

#[test]
fn json_output_parses_for_plans_and_records() -> TestResult {
    let e = Env::new()?;
    let v = e.json(&["create", "dev", "--size", "S", "--yes"])?;
    assert_eq!(v["applied"], true);
    assert_eq!(v["plan"]["operation"]["op"], "create");
    assert_eq!(v["result"]["state"], "running");
    let dry = e.json(&["destroy", "dev", "--dry-run"])?;
    assert_eq!(dry["applied"], false);
    assert_eq!(dry["dry_run"], true);
    assert_eq!(dry["plan"]["changes"].as_array().map(Vec::len), Some(2));
    let noop = e.json(&["resume", "dev"])?;
    assert_eq!(noop["plan"]["changes"].as_array().map(Vec::len), Some(0));
    assert_eq!(e.json(&["sizes"])?.as_array().map(Vec::len), Some(8));
    assert_eq!(e.json(&["providers"])?.as_array().map(Vec::len), Some(3));
    Ok(())
}

#[test]
fn a_conflicting_create_and_unsupported_shrink_are_errors() -> TestResult {
    let e = Env::new()?;
    e.cmd()
        .args(["create", "dev", "--size", "S", "--disk", "100", "--yes"])
        .assert()
        .success();
    e.cmd()
        .args(["create", "dev", "--size", "XL", "--yes"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("already exists"));
    e.cmd()
        .args(["resize", "dev", "--disk", "50", "--yes"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("cannot shrink").or(predicate::str::contains("shrink")));
    Ok(())
}

#[test]
fn connect_never_invents_a_domain() -> TestResult {
    let e = Env::new()?;
    e.cmd()
        .args(["create", "dev", "--size", "S", "--yes"])
        .assert()
        .success();
    e.cmd().args(["connect", "dev"]).assert().success().stdout(
        predicate::str::contains("no web address yet")
            .and(predicate::str::contains("example.com").not()),
    );
    std::fs::write(
        e.dir.path().join("config.toml"),
        "domain = \"boxes.example.org\"\n",
    )?;
    e.cmd()
        .args(["connect", "dev"])
        .assert()
        .success()
        .stdout(predicate::str::contains("https://dev.boxes.example.org"));
    Ok(())
}

#[test]
fn version_is_the_semver_of_the_workspace() -> TestResult {
    let e = Env::new()?;
    e.cmd()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(format!("ozbox {}", env!("CARGO_PKG_VERSION"))));
    Ok(())
}

#[test]
fn hcloud_without_a_token_fails_cleanly_not_with_a_panic() -> TestResult {
    let e = Env::new()?;
    e.cmd()
        .args(["--provider", "hcloud", "list"])
        .assert()
        .code(1)
        .stderr(
            predicate::str::contains("HCLOUD_TOKEN")
                .and(predicate::str::contains("panicked").not()),
        );
    Ok(())
}

#[test]
fn connect_ssh_prints_the_config_entry_only_with_a_domain() -> TestResult {
    let e = Env::new()?;
    e.cmd()
        .args(["create", "dev", "--size", "S", "--yes"])
        .assert()
        .success();
    // no domain: an honest refusal, no invented address
    e.cmd()
        .args(["connect", "dev", "--ssh"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("no SSH route yet")
                .and(predicate::str::contains("HostName").not()),
        );
    std::fs::write(
        e.dir.path().join("config.toml"),
        "domain = \"example.com\"\n",
    )?;
    e.cmd()
        .args(["connect", "dev", "--ssh"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("Host ozbox-dev")
                .and(predicate::str::contains("HostName ssh-dev.example.com"))
                .and(predicate::str::contains(
                    "ProxyCommand cloudflared access ssh",
                )),
        );
    let v = e.json(&["connect", "dev", "--ssh"])?;
    assert_eq!(v["ssh_host"], "ozbox-dev");
    assert!(v["ssh_config"]
        .as_str()
        .is_some_and(|s| s.contains("Host ozbox-dev")));
    assert_eq!(v["ssh_route"], "cloudflare");
    Ok(())
}

#[test]
fn connect_ssh_write_adds_one_include_line_and_a_managed_file() -> TestResult {
    let e = Env::new()?;
    e.cmd()
        .args(["create", "dev", "--size", "S", "--yes"])
        .assert()
        .success();
    std::fs::write(
        e.dir.path().join("config.toml"),
        "domain = \"example.com\"\n",
    )?;
    let ssh = e.dir.path().join("sshdir");
    std::fs::create_dir_all(&ssh)?;
    std::fs::write(ssh.join("config"), "Host mine\n    User me\n")?;
    for _ in 0..2 {
        e.cmd()
            .env("OZBOX_SSH_DIR", &ssh)
            .args(["connect", "dev", "--ssh", "--write"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Connect with: ssh ozbox-dev"));
    }
    let main = std::fs::read_to_string(ssh.join("config"))?;
    assert_eq!(main.matches("Include ~/.ssh/ozbox/config").count(), 1);
    assert!(main.ends_with("Host mine\n    User me\n"));
    let managed = std::fs::read_to_string(ssh.join("ozbox/config"))?;
    assert_eq!(managed.matches("Host ozbox-dev\n").count(), 1);
    // and the ingress account's entry for the same route, once
    assert_eq!(managed.matches("Host ozbox-dev-ingress\n").count(), 1);
    let backups = std::fs::read_dir(&ssh)?
        .filter_map(Result::ok)
        .filter(|f| {
            f.file_name()
                .to_string_lossy()
                .starts_with("config.ozbox-backup-")
        })
        .count();
    assert_eq!(backups, 1);
    // --write without --ssh is refused by the grammar
    e.cmd()
        .args(["connect", "dev", "--write"])
        .assert()
        .failure();
    Ok(())
}

#[test]
fn create_uses_the_box_defaults_and_the_fleet_cap_refuses() -> TestResult {
    let e = Env::new()?;
    let settings = e.dir.path().join("settings.json");
    std::fs::write(
        &settings,
        r#"{"budget":{"max_running_boxes":1},"defaults":{"size":"L","work_disk_gb":250}}"#,
    )?;
    let run = |args: &[&str]| {
        let mut c = e.cmd();
        c.env("OZBOX_SETTINGS", &settings).args(args);
        c
    };
    run(&["create", "one", "--yes"]).assert().success();
    let v = e.json(&["show", "one"])?;
    assert_eq!(v["spec"]["size"], "L");
    assert_eq!(v["spec"]["work_disk_gb"], 250);
    run(&["create", "two", "--size", "S", "--yes"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("fleet cap is 1"));
    // a refused create made nothing
    assert!(run(&["show", "two"])
        .assert()
        .failure()
        .get_output()
        .stdout
        .is_empty());
    Ok(())
}
