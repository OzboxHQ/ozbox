//! Joining a box to the tailnet. The box runs its own Tailscale client in user space, as a service of the box user (no
//! root, no network device, ADR 0011), signed in to the person's Headscale server with a one-use key that carries the
//! box's tag. The client forwards the tailnet's port 22 to the box's own loopback SSH server, so SSH stays closed to
//! every network the box is on (ADR 0005).
//!
//! The key arrives in the script, on standard input of `ssh … bash -s`, never in an argument; the script puts it in a
//! private temporary file for the one command that reads it and deletes it.

use ozbox_core::{BoxName, CommandSpec};

use super::headscale::key_ok;
use super::MeshFile;

/// Where the box keeps the client's socket and state, relative to the box user's home.
pub const STATE_DIR: &str = ".local/state/ozbox-mesh";

/// `ssh-ed25519 AAAA… comment`: one public key line, plain characters only.
pub fn public_key_ok(line: &str) -> bool {
    let mut parts = line.trim().splitn(3, ' ');
    let kind = parts.next().unwrap_or("");
    let body = parts.next().unwrap_or("");
    let comment = parts.next().unwrap_or("");
    matches!(
        kind,
        "ssh-ed25519"
            | "ecdsa-sha2-nistp256"
            | "ecdsa-sha2-nistp384"
            | "sk-ssh-ed25519@openssh.com"
    ) && body.len() >= 20
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
        && comment.len() <= 100
        && comment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'@' | b'.' | b'_' | b'-' | b' '))
}

/// The words a person reads before anything runs.
pub fn plan(box_name: &str, with_ssh_key: bool) -> Vec<String> {
    let mut p = vec![
        format!("On {box_name}: run Tailscale's client in user space as the box user's own service (no root, no new open port)."),
        format!("Sign it in to your Headscale server with a one-use key tagged {}, valid for one hour.", super::box_tag(box_name)),
        "Forward the tailnet's port 22 to the box's own SSH server, which stays on loopback.".to_string(),
    ];
    if with_ssh_key {
        p.push("Add your public key to the box user's authorized keys.".to_string());
    }
    p
}

/// The script for the box. `key` and every other word were checked; an unchecked one is refused, not quoted.
pub fn script(
    file: &MeshFile,
    box_name: &str,
    key: &str,
    ssh_public_key: Option<&str>,
) -> Result<String, &'static str> {
    if !key_ok(key) {
        return Err("mesh.bad_key");
    }
    BoxName::new(box_name).map_err(|_| "mesh.bad_box")?;
    file.validate()?;
    if let Some(k) = ssh_public_key {
        if !public_key_ok(k) {
            return Err("mesh.bad_ssh_key");
        }
    }
    let url = &file.control_url;
    let add_key = match ssh_public_key {
        Some(k) => format!(
            "mkdir -p \"$HOME/.ssh\" && chmod 700 \"$HOME/.ssh\"\ntouch \"$HOME/.ssh/authorized_keys\" && chmod 600 \"$HOME/.ssh/authorized_keys\"\ngrep -qxF '{k}' \"$HOME/.ssh/authorized_keys\" || printf '%s\\n' '{k}' >>\"$HOME/.ssh/authorized_keys\"\n",
            k = k.trim()
        ),
        None => String::new(),
    };
    Ok(format!(
        r#"set -euo pipefail
umask 077
command -v tailscale >/dev/null 2>&1 || {{ echo "tailscale is not installed on this box" >&2; exit 12; }}
command -v tailscaled >/dev/null 2>&1 || {{ echo "tailscaled is not installed on this box" >&2; exit 12; }}
STATE="$HOME/{STATE_DIR}"
mkdir -p "$STATE" "$HOME/.config/systemd/user"
cat >"$HOME/.config/systemd/user/ozbox-mesh.service" <<'UNIT'
[Unit]
Description=Oz Box mesh client (user space)
After=network-online.target

[Service]
ExecStart=%h/{STATE_DIR}/run-tailscaled
Restart=on-failure

[Install]
WantedBy=default.target
UNIT
cat >"$STATE/run-tailscaled" <<'RUN'
#!/bin/sh
exec tailscaled --tun=userspace-networking --state="$HOME/{STATE_DIR}/tailscaled.state" --socket="$HOME/{STATE_DIR}/tailscaled.sock"
RUN
chmod 700 "$STATE/run-tailscaled"
systemctl --user daemon-reload
systemctl --user enable --now ozbox-mesh.service
SOCK="$STATE/tailscaled.sock"
for _ in 1 2 3 4 5 6 7 8 9 10; do [ -S "$SOCK" ] && break; sleep 1; done
KEYFILE="$(mktemp)"
trap 'rm -f "$KEYFILE"' EXIT
printf '%s' '{key}' >"$KEYFILE"
tailscale --socket="$SOCK" up --login-server='{url}' --auth-key="file:$KEYFILE" --hostname='{box_name}' --accept-dns=false --accept-routes=false
rm -f "$KEYFILE"
tailscale --socket="$SOCK" serve --bg --tcp=22 tcp://127.0.0.1:22
{add_key}echo "joined"
"#
    ))
}

/// Run the script on the box over the SSH route that already reaches it. The script is the standard input.
pub fn command(box_name: &str, script: String) -> CommandSpec {
    CommandSpec::new("ssh")
        .args([
            "-o".to_string(),
            "BatchMode=yes".to_string(),
            crate::sshconfig::host_alias(box_name),
            "bash".to_string(),
            "-s".to_string(),
        ])
        .stdin(script.into_bytes())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::super::tests::sample;
    use super::*;

    const KEY: &str = "hskey-auth-SENTINELKEY-0123456789abcdef";
    const PUB: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPlaceholderPlaceholder1234 alice@laptop";

    #[test]
    fn the_key_is_in_the_script_on_standard_input_and_never_in_an_argument() {
        let s = script(&sample(), "dev", KEY, None).unwrap();
        let c = command("dev", s.clone());
        assert!(c.args.iter().all(|a| !a.contains("SENTINELKEY")));
        assert_eq!(c.stdin.as_deref(), Some(s.as_bytes()));
        assert!(s.contains("--login-server='https://headscale.example.com'"));
        assert!(s.contains("--auth-key=\"file:$KEYFILE\""));
        // the key is written to a private file, not placed on the client's command line
        assert!(!s.contains("--auth-key=hskey"));
        assert!(s.contains("trap 'rm -f \"$KEYFILE\"' EXIT"));
    }

    #[test]
    fn nothing_listens_and_nothing_needs_root() {
        let s = script(&sample(), "dev", KEY, None).unwrap();
        assert!(!s.contains("sudo"));
        assert!(s.contains("--tun=userspace-networking"));
        // port 22 on the tailnet goes to the box's own loopback SSH server
        assert!(s.contains("tcp://127.0.0.1:22"));
        assert!(!s.contains("0.0.0.0"));
    }

    #[test]
    fn unchecked_words_are_refused_rather_than_quoted() {
        assert_eq!(
            script(&sample(), "dev", "x'; rm -rf / #aaaaaaaaaaaaaaaa", None),
            Err("mesh.bad_key")
        );
        assert_eq!(script(&sample(), "Dev;", KEY, None), Err("mesh.bad_box"));
        assert_eq!(
            script(&sample(), "dev", KEY, Some("ssh-ed25519 a'b")),
            Err("mesh.bad_ssh_key")
        );
    }

    #[test]
    fn a_public_key_is_added_once() {
        let s = script(&sample(), "dev", KEY, Some(PUB)).unwrap();
        assert!(s.contains("grep -qxF"));
        assert!(s.contains(PUB));
        assert!(plan("dev", true).len() > plan("dev", false).len());
    }
}
