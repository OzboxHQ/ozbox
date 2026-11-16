//! The daemon's side of the box's secrets service (a different system user, see the CLI's `secrets_service`). The daemon
//! runs as the box user, so it must never hold backup credentials; instead it asks the service to run one of a few exact
//! restic commands, and to say whether credentials exist. One JSON line each way over a Unix socket. Who may connect is
//! the permission of the socket's directory.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ozbox_core::{CommandRunner, CommandSpec, Error, Output, Result};
use serde_json::{json, Value};

/// The sockets of the service on a box.
pub const BROKER_SOCKET: &str = "/run/ozbox-secrets/broker/broker.sock";
pub const ADMIN_SOCKET: &str = "/run/ozbox-secrets/admin/admin.sock";

/// The names the backup credentials are kept under in the store.
pub const RESTIC_ENV: &str = "restic-env";
pub const RESTIC_PASSWORD: &str = "restic-password";

/// The settings travel and rest as hex: the store takes plain single-line values only.
pub fn hex_encode(text: &str) -> String {
    text.bytes().map(|b| format!("{b:02x}")).collect()
}

pub fn hex_decode(h: &str) -> Option<String> {
    if !h.len().is_multiple_of(2) {
        return None;
    }
    let bytes: Option<Vec<u8>> = (0..h.len() / 2)
        .map(|i| u8::from_str_radix(h.get(2 * i..2 * i + 2)?, 16).ok())
        .collect();
    String::from_utf8(bytes?).ok()
}

/// The box socket that sits beside the service socket (`<run>/broker/broker.sock` -> `<run>/box/box.sock`).
pub fn box_socket_for(service_socket: &Path) -> PathBuf {
    service_socket
        .parent()
        .and_then(Path::parent)
        .map(|d| d.join("box/box.sock"))
        .unwrap_or_else(|| PathBuf::from("/run/ozbox-secrets/box/box.sock"))
}

fn unreachable_err() -> String {
    "the box's secrets service is not reachable".into()
}

/// One request, one answer. `wait` bounds the read (a backup can run for hours, so the runner passes none).
pub fn call(
    socket: &Path,
    req: &Value,
    wait: Option<Duration>,
) -> std::result::Result<Value, String> {
    let mut s = UnixStream::connect(socket).map_err(|_| unreachable_err())?;
    s.set_read_timeout(wait).ok();
    s.write_all(format!("{req}\n").as_bytes())
        .map_err(|_| unreachable_err())?;
    let mut line = String::new();
    BufReader::new(&s)
        .read_line(&mut line)
        .map_err(|_| unreachable_err())?;
    let v: Value = serde_json::from_str(&line).map_err(|_| unreachable_err())?;
    if v["ok"].as_bool() == Some(true) {
        Ok(v)
    } else {
        Err(v["error"]
            .as_str()
            .unwrap_or("the request was refused")
            .to_string())
    }
}

/// Whether a secret of this name exists (never its value). `Err` when the service cannot be asked (it is not up yet, or
/// does not answer): a missing secret and a service that is not ready are different things, and a caller must not report
/// the second as the first.
pub fn exists_checked(box_socket: &Path, name: &str) -> std::result::Result<bool, String> {
    call(
        box_socket,
        &json!({"op": "exists", "name": name}),
        Some(Duration::from_secs(10)),
    )
    .map(|v| v["flag"].as_bool() == Some(true))
}

/// Whether a secret of this name exists (never its value); `false` also when the service cannot be asked.
pub fn exists(box_socket: &Path, name: &str) -> bool {
    exists_checked(box_socket, name).unwrap_or(false)
}

/// Runs a restic command through the service. The environment of `cmd` is ignored on purpose: the credentials are the
/// service's to supply.
pub struct ServiceRunner {
    pub socket: PathBuf,
}

impl CommandRunner for ServiceRunner {
    fn run(&self, cmd: &CommandSpec) -> Result<Output> {
        let v = call(
            &self.socket,
            &json!({"op": "restic", "args": cmd.args}),
            None,
        )
        .map_err(Error::Provider)?;
        Ok(Output {
            status: v["status"].as_i64().and_then(|c| i32::try_from(c).ok()),
            stdout: v["stdout"].as_str().unwrap_or("").to_string(),
            stderr: String::new(),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    #[test]
    fn the_runner_sends_arguments_only_and_returns_what_the_service_answers() {
        let d = tempfile::tempdir().unwrap();
        let sock = d.path().join("s.sock");
        let l = UnixListener::bind(&sock).unwrap();
        let t = std::thread::spawn(move || {
            let (c, _) = l.accept().unwrap();
            let mut line = String::new();
            BufReader::new(&c).read_line(&mut line).unwrap();
            let mut w = &c;
            w.write_all(b"{\"ok\":true,\"status\":0,\"stdout\":\"[]\"}\n")
                .unwrap();
            line
        });
        let mut spec = CommandSpec::new("restic").args(["snapshots", "--json"]);
        spec.env
            .insert("RESTIC_PASSWORD".into(), "SENTINEL-pw".into());
        let out = ServiceRunner { socket: sock }.run(&spec).unwrap();
        assert_eq!((out.status, out.stdout.as_str()), (Some(0), "[]"));
        let sent = t.join().unwrap();
        assert!(sent.contains("snapshots") && !sent.contains("SENTINEL"));
    }

    #[test]
    fn a_refusal_and_a_missing_service_are_plain_errors() {
        let d = tempfile::tempdir().unwrap();
        assert!(!exists(&d.path().join("none.sock"), "restic-env"));
        let r = ServiceRunner {
            socket: d.path().join("none.sock"),
        }
        .run(&CommandSpec::new("restic"));
        assert!(r.is_err());
        assert_eq!(
            box_socket_for(Path::new("/run/ozbox-secrets/broker/broker.sock")),
            PathBuf::from("/run/ozbox-secrets/box/box.sock")
        );
    }
}
