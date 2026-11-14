//! End to end: two `ozbox tasks` endpoints, a "laptop" and a "box", reaching each other through the real binary (the box's
//! side is run by the laptop's `--via` command, exactly as `ssh <box> ozbox` would run it).

use assert_cmd::Command;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct End {
    dir: std::path::PathBuf,
    home: tempfile::TempDir,
}

impl End {
    fn new() -> Result<Self, std::io::Error> {
        let home = tempfile::tempdir()?;
        Ok(Self {
            dir: home.path().join("channel"),
            home,
        })
    }

    fn cmd(&self) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_ozbox"));
        c.env("OZBOX_TASKS_DIR", &self.dir)
            .env("HOME", self.home.path())
            .env("OZBOX_SECRET_STORE", "memory")
            .write_stdin("");
        c
    }

    fn ok(&self, args: &[&str]) -> Result<String, Box<dyn std::error::Error>> {
        let out = self.cmd().args(args).output()?;
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    fn fails(&self, args: &[&str]) -> Result<String, Box<dyn std::error::Error>> {
        let out = self.cmd().args(args).output()?;
        assert!(!out.status.success(), "{args:?} should have failed");
        Ok(String::from_utf8_lossy(&out.stderr).into_owned())
    }
}

fn pair() -> Result<(End, End), Box<dyn std::error::Error>> {
    let (laptop, boxx) = (End::new()?, End::new()?);
    laptop.ok(&["tasks", "init", "--name", "laptop"])?;
    boxx.ok(&["tasks", "init", "--name", "main"])?;
    let (lf, bf) = (
        laptop.home.path().join("laptop.json"),
        boxx.home.path().join("main.json"),
    );
    std::fs::write(&lf, laptop.ok(&["tasks", "identity"])?)?;
    std::fs::write(&bf, boxx.ok(&["tasks", "identity"])?)?;
    let via = format!(
        "env OZBOX_TASKS_DIR={} HOME={} OZBOX_SECRET_STORE=memory {}",
        boxx.dir.display(),
        boxx.home.path().display(),
        env!("CARGO_BIN_EXE_ozbox")
    );
    laptop.ok(&[
        "--yes",
        "tasks",
        "pin",
        bf.to_str().unwrap_or_default(),
        "--via",
        &via,
    ])?;
    boxx.ok(&["--yes", "tasks", "pin", lf.to_str().unwrap_or_default()])?;
    Ok((laptop, boxx))
}

fn first_id(inbox: &str) -> String {
    inbox
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_string()
}

#[test]
fn a_task_goes_to_the_box_is_answered_and_the_answer_comes_back() -> TestResult {
    let (laptop, boxx) = pair()?;
    let out = laptop.ok(&[
        "tasks",
        "send",
        "--to",
        "main",
        "--title",
        "release check",
        "--text",
        "is the image built?",
    ])?;
    let id = out
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_string();
    assert!(laptop.ok(&["tasks", "why", &id])?.contains("held"));
    assert!(laptop.ok(&["tasks", "sync"])?.contains("sent"));
    let inbox = boxx.ok(&["tasks", "inbox"])?;
    assert!(
        inbox.contains("release check") && first_id(&inbox) == id,
        "{inbox}"
    );
    boxx.ok(&[
        "tasks",
        "reply",
        &id,
        "--text",
        "built, digest pinned",
        "--state",
        "completed",
    ])?;
    laptop.ok(&["tasks", "sync"])?;
    laptop.ok(&["tasks", "sync"])?;
    let shown = laptop.ok(&["tasks", "status", &id])?;
    assert!(
        shown.contains("completed") && shown.contains("built, digest pinned"),
        "{shown}"
    );
    Ok(())
}

#[test]
fn refusals_reach_the_person_in_plain_words() -> TestResult {
    let (laptop, _boxx) = pair()?;
    let e = laptop.fails(&[
        "tasks",
        "send",
        "--to",
        "main",
        "--title",
        "x",
        "--text",
        &format!("token sk_{}_0123456789abcdefghijklmn", "live"),
    ])?;
    assert!(e.contains("key-shaped-content"), "{e}");
    let e = laptop.fails(&[
        "tasks",
        "push-ref",
        "--to",
        "main",
        "--repo",
        "r/x",
        "--remote",
        "origin",
        "--ref",
        "rel",
        "--sha",
        "0123456789abcdef0123456789abcdef01234567",
        "--env",
        "production",
    ])?;
    assert!(e.contains("production-act-refused"), "{e}");
    laptop.ok(&[
        "tasks",
        "push-ref",
        "--to",
        "main",
        "--repo",
        "r/x",
        "--remote",
        "origin",
        "--ref",
        "rel",
        "--sha",
        "0123456789abcdef0123456789abcdef01234567",
        "--env",
        "staging",
    ])?;
    laptop.ok(&["tasks", "sync"])?;
    laptop.ok(&["tasks", "sync"])?;
    let all = laptop.ok(&["tasks", "inbox", "--all"])?;
    assert!(all.contains("rejected"), "{all}");
    Ok(())
}

#[test]
fn an_unpinned_endpoint_is_not_heard_and_init_never_overwrites() -> TestResult {
    let (laptop, boxx) = pair()?;
    assert!(laptop
        .fails(&["tasks", "init", "--name", "again"])?
        .contains("already"));
    let stranger = End::new()?;
    stranger.ok(&["tasks", "init", "--name", "stranger"])?;
    let bf = boxx.home.path().join("main2.json");
    std::fs::write(&bf, boxx.ok(&["tasks", "identity"])?)?;
    let via = format!(
        "env OZBOX_TASKS_DIR={} HOME={} OZBOX_SECRET_STORE=memory {}",
        boxx.dir.display(),
        boxx.home.path().display(),
        env!("CARGO_BIN_EXE_ozbox")
    );
    stranger.ok(&[
        "--yes",
        "tasks",
        "pin",
        bf.to_str().unwrap_or_default(),
        "--via",
        &via,
    ])?;
    stranger.ok(&[
        "tasks",
        "send",
        "--to",
        "main",
        "--title",
        "hello",
        "--text",
        "let me in",
    ])?;
    let why = stranger.fails(&["tasks", "sync"])?;
    assert!(why.contains("not pinned"), "{why}");
    assert!(boxx
        .ok(&["tasks", "inbox", "--all"])?
        .contains("Nothing waiting"));
    Ok(())
}
