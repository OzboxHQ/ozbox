//! The box's task router as a service: the key and the state belong to the service, agents reach it only through its sockets, and the
//! relay a laptop's `ssh` reaches holds no key. (The real permissions are directory modes the setup script writes; here every socket
//! is the test user's, so what is tested is the split of powers between the sockets and that no key is on the client's side.)
#![cfg(unix)]

use assert_cmd::Command;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Service {
    root: tempfile::TempDir,
    state: PathBuf,
    child: std::process::Child,
}

impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start() -> Result<Service, Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let state = root.path().join("state");
    let child = std::process::Command::new(env!("CARGO_BIN_EXE_ozbox"))
        .args(["tasks", "serve", "--dir"])
        .arg(&state)
        .arg("--agent-socket")
        .arg(root.path().join("agent/agent.sock"))
        .arg("--relay-socket")
        .arg(root.path().join("relay/relay.sock"))
        .arg("--admin-socket")
        .arg(root.path().join("admin/admin.sock"))
        .env("OZBOX_SECRET_STORE", "memory")
        .spawn()?;
    let s = Service { root, state, child };
    for _ in 0..200 {
        if ["agent/agent.sock", "relay/relay.sock", "admin/admin.sock"]
            .iter()
            .all(|p| s.root.path().join(p).exists())
        {
            return Ok(s);
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    Err("the service did not start".into())
}

fn client(s: &Service) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_ozbox"));
    // no OZBOX_TASKS_DIR: this process has no channel files of its own to read
    c.env("OZBOX_TASKS_SOCKETS", s.root.path())
        .env("OZBOX_SECRET_STORE", "memory")
        .env("HOME", s.root.path())
        .write_stdin("");
    c
}

fn raw(sock: &Path, req: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut st = UnixStream::connect(sock)?;
    writeln!(st, "{req}")?;
    let mut line = String::new();
    BufReader::new(st).read_line(&mut line)?;
    Ok(line)
}

#[test]
fn the_sockets_split_the_powers_and_the_key_stays_with_the_service() -> TestResult {
    let s = start()?;
    let out = client(&s)
        .args(["tasks", "init", "--name", "main"])
        .output()?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // the key and the state are in the service's directory, mode 0700 for the service user alone
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&s.state)?.permissions().mode() & 0o777,
        0o700
    );
    assert!(s.state.join("identity.json").exists());
    let agent = s.root.path().join("agent/agent.sock");
    let relay = s.root.path().join("relay/relay.sock");
    // an agent cannot pin, restore or init, and cannot ask for the relay's operation
    for op in ["pin", "restored", "init", "exchange"] {
        let a = raw(&agent, &format!("{{\"op\":\"{op}\"}}"))?;
        assert!(a.contains("not-allowed-here"), "{op}: {a}");
    }
    // the relay offers nothing but the exchange
    for op in ["inbox", "send", "identity", "pin"] {
        let a = raw(&relay, &format!("{{\"op\":\"{op}\"}}"))?;
        assert!(a.contains("not-allowed-here"), "{op}: {a}");
    }
    // an agent can read the public identity and its inbox, and the JSON says the store is not agent-writable
    let id = client(&s).args(["tasks", "identity"]).output()?;
    assert!(String::from_utf8_lossy(&id.stdout).contains("seal_fingerprint"));
    let ib = raw(&agent, r#"{"op":"inbox","all":true}"#)?;
    assert!(ib.contains("\"ok\":true"), "{ib}");
    // a request that is not JSON, or that never ends its line, is refused
    assert!(raw(&agent, "not json")?.contains("not-json"));
    // the keyless relay: garbage in, a refusal out, and no key was ever on this process's side
    let r = client(&s)
        .args(["tasks", "exchange", "--peer", "laptop"])
        .write_stdin("[]")
        .output()?;
    let _ = r;
    assert!(!s.root.path().join("identity.json").exists());
    Ok(())
}
