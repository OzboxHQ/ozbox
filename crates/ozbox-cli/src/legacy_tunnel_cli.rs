//! `ozbox dashboard retire-legacy-tunnel <box>`: remove a tunnel an older setup left running AS THE BOX USER.
//!
//! That setup ran `cloudflared` from a user unit (`oz-cloudflared.service`) with `--token-file ~/.config/ozbox-tunnel/token`. The
//! token is therefore readable by the box user and by every coding agent it runs. The box's own connector (`ozbox-cloudflared`, run
//! by the secrets user, its token in the secrets store) replaces it, and this command retires the old one, but only once the new
//! one is seen working: stopping the old connector first would take the address down if the new one is not up.
//!
//! Everything runs as the box user over the box's own route (the root helper is not involved: the files are the box user's, and
//! root deleting paths under a home the box user controls is how a link swapped in between a check and a delete reaches a file
//! elsewhere). The token is NOT imported into the store: it was readable, so it is destroyed and must be rotated in Cloudflare.
//! Plan, then apply (ADR 0002): the probe is read-only, the change needs `--yes` or a typed yes.

use std::io::{BufRead, Write};

use ozbox_core::{CommandRunner, CommandSpec};
use serde_json::json;

use crate::messages::t;
use crate::run::CliError;

/// Read-only. Prints one `key: value` line per fact; never a token, a path under the person's home, or a connection address.
pub(crate) const PROBE_SCRIPT: &str = r#"export XDG_RUNTIME_DIR="/run/user/$(id -u)"
u=oz-cloudflared.service
[ -e "$HOME/.config/ozbox-tunnel/token" ] || [ -L "$HOME/.config/ozbox-tunnel/token" ] && echo 'legacy: token'
[ -e "$HOME/.config/systemd/user/$u" ] && echo 'legacy: unit'
echo "legacy-active: $(systemctl --user is-active $u 2>/dev/null || true)"
echo "system: $(systemctl is-active ozbox-cloudflared.service 2>/dev/null || true)"
echo "system-restarts: $(systemctl show -p NRestarts --value ozbox-cloudflared.service 2>/dev/null || echo unknown)"
command -v ss >/dev/null 2>&1 && echo 'ss: yes' || echo 'ss: no'
for port in 20241 20242 20243 20244 20245; do
  r=$(curl -fsS -m 2 "http://127.0.0.1:$port/ready" 2>/dev/null) || continue
  n=$(printf '%s' "$r" | sed -n 's/.*"readyConnections":\([0-9]*\).*/\1/p')
  mine=no
  ss -ltnpH "sport = :$port" 2>/dev/null | grep -q 'pid=' && mine=yes
  echo "connector: ready=${n:-0} mine=$mine"
done
"#;

/// The change. As the box user, on its own files only.
pub(crate) const RETIRE_SCRIPT: &str = r#"export XDG_RUNTIME_DIR="/run/user/$(id -u)"
systemctl --user disable --now oz-cloudflared.service >/dev/null 2>&1 || true
rm -f "$HOME/.config/systemd/user/oz-cloudflared.service"
systemctl --user daemon-reload >/dev/null 2>&1 || true
t="$HOME/.config/ozbox-tunnel/token"
if [ -L "$t" ]; then rm -f "$t"; elif [ -e "$t" ]; then shred -u "$t" 2>/dev/null || rm -f "$t"; fi
rmdir "$HOME/.config/ozbox-tunnel" 2>/dev/null || true
echo 'retire: done'
"#;

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Probe {
    pub token: bool,
    pub unit: bool,
    pub legacy_running: bool,
    pub system_active: bool,
    pub system_restarts_zero: bool,
    pub ss_present: bool,
    /// `(ready connections, answered by a process of the box user)` per metrics port that answered.
    pub connectors: Vec<(u32, bool)>,
}

pub(crate) fn parse_probe(out: &str) -> Probe {
    let mut p = Probe::default();
    for line in out.lines() {
        let Some((k, v)) = line.split_once(": ") else {
            continue;
        };
        let v = v.trim();
        match k {
            "legacy" => match v {
                "token" => p.token = true,
                "unit" => p.unit = true,
                _ => {}
            },
            "legacy-active" => p.legacy_running = v == "active",
            "system" => p.system_active = v == "active",
            "system-restarts" => p.system_restarts_zero = v == "0",
            "ss" => p.ss_present = v == "yes",
            "connector" => {
                let ready = v
                    .split_whitespace()
                    .find_map(|w| w.strip_prefix("ready="))
                    .and_then(|n| n.parse().ok())
                    .unwrap_or(0);
                let mine = v.split_whitespace().any(|w| w == "mine=yes");
                p.connectors.push((ready, mine));
            }
            _ => {}
        }
    }
    p
}

impl Probe {
    pub(crate) fn anything_to_retire(&self) -> bool {
        self.token || self.unit
    }

    /// The box's own connector is up AND has connections of its own. Ports answered by a process of the box user are the old
    /// connector's, never counted. When the old connector is not running, whatever answers is the box's own; when it is, a box
    /// with no `ss` cannot tell the two apart, which is not a pass.
    pub(crate) fn system_healthy(&self) -> bool {
        if !self.system_active || !self.system_restarts_zero {
            return false;
        }
        self.connectors.iter().any(|(ready, mine)| {
            *ready >= 1 && (!self.legacy_running || (self.ss_present && !*mine))
        })
    }
}

fn ssh(name: &str, script: &str) -> CommandSpec {
    CommandSpec::new("ssh")
        .args([
            "-o".to_string(),
            "BatchMode=yes".to_string(),
            crate::sshconfig::host_alias(name),
            "sh".to_string(),
            "-s".to_string(),
        ])
        .stdin(script.as_bytes().to_vec())
}

fn ask(runner: &dyn CommandRunner, name: &str, script: &str) -> Result<String, CliError> {
    match runner.run(&ssh(name, script)) {
        Ok(o) if o.status == Some(0) => Ok(o.stdout),
        _ => Err(CliError::Msg(t(
            "legacy_tunnel.unreachable",
            &[("box", name)],
        ))),
    }
}

pub(crate) fn run(
    name: &ozbox_core::BoxName,
    yes: bool,
    dry_run: bool,
    json_out: bool,
    runner: &dyn CommandRunner,
    input: &mut dyn BufRead,
    tty: bool,
) -> Result<(), CliError> {
    let n = name.as_str();
    let probe = parse_probe(&ask(runner, n, PROBE_SCRIPT)?);
    let say = |s: String| {
        if !json_out {
            println!("{s}");
        }
    };
    if !probe.anything_to_retire() {
        if json_out {
            println!("{}", json!({"box": n, "retired": false, "found": false}));
        } else {
            say(t("legacy_tunnel.none", &[("box", n)]));
        }
        return Ok(());
    }
    let healthy = probe.system_healthy();
    say(t("legacy_tunnel.found", &[("box", n)]));
    if !healthy {
        // nothing is changed: the old connector may be what keeps the address up
        if json_out {
            println!(
                "{}",
                json!({"box": n, "retired": false, "found": true, "system_connector_healthy": false})
            );
        }
        return Err(CliError::Msg(t("legacy_tunnel.not_healthy", &[("box", n)])));
    }
    say(t("legacy_tunnel.plan", &[("box", n)]));
    if dry_run {
        say(t("dashboard.dry_run", &[]));
        return Ok(());
    }
    if !yes {
        if !tty {
            return Err(CliError::Msg(t("dashboard.refuse_no_tty", &[("box", n)])));
        }
        print!("{}", t("dashboard.prompt", &[]));
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        let _ = input.read_line(&mut line);
        if !matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            say(t("dashboard.aborted", &[]));
            return Ok(());
        }
    }
    let done = ask(runner, n, RETIRE_SCRIPT)?;
    if !done.contains("retire: done") {
        return Err(CliError::Msg(t("legacy_tunnel.unreachable", &[("box", n)])));
    }
    if json_out {
        println!(
            "{}",
            json!({"box": n, "retired": true, "rotate_tunnel_token": true})
        );
    } else {
        say(t("legacy_tunnel.done", &[("box", n)]));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ozbox_core::{Output, RecordingRunner};

    const OLD_AND_NEW: &str = "legacy: token\nlegacy: unit\nlegacy-active: active\nsystem: active\nsystem-restarts: 0\nss: yes\nconnector: ready=4 mine=yes\nconnector: ready=4 mine=no\n";

    fn reply(r: &RecordingRunner, out: &str) {
        r.reply(Output {
            status: Some(0),
            stdout: out.into(),
            stderr: String::new(),
        });
    }

    #[test]
    fn the_boxs_own_connector_needs_connections_of_its_own() {
        assert!(parse_probe(OLD_AND_NEW).system_healthy());
        // only the old connector answers: not healthy, whatever the system unit says
        let only_old = OLD_AND_NEW.replace("connector: ready=4 mine=no\n", "");
        assert!(!parse_probe(&only_old).system_healthy());
        // no connections yet
        assert!(
            !parse_probe(&OLD_AND_NEW.replace("ready=4 mine=no", "ready=0 mine=no"))
                .system_healthy()
        );
        // a unit that is down or restarting
        assert!(
            !parse_probe(&OLD_AND_NEW.replace("system: active", "system: failed")).system_healthy()
        );
        assert!(
            !parse_probe(&OLD_AND_NEW.replace("system-restarts: 0", "system-restarts: 3"))
                .system_healthy()
        );
        // the old one runs and `ss` is missing: the two cannot be told apart
        assert!(!parse_probe(&OLD_AND_NEW.replace("ss: yes", "ss: no")).system_healthy());
        // the old one is not running: whatever answers is the box's own
        let stopped = "legacy: token\nlegacy-active: inactive\nsystem: active\nsystem-restarts: 0\nss: no\nconnector: ready=2 mine=no\n";
        assert!(parse_probe(stopped).system_healthy());
    }

    #[test]
    fn nothing_is_changed_unless_the_boxs_own_tunnel_is_up_and_the_change_needs_a_yes() {
        let name = ozbox_core::BoxName::new("dev").unwrap();
        // not healthy: one question, no change, an error that says why
        let r = RecordingRunner::new();
        reply(
            &r,
            "legacy: token\nlegacy-active: active\nsystem: failed\nsystem-restarts: 0\nss: yes\n",
        );
        let e = run(&name, true, false, false, &r, &mut std::io::empty(), false).unwrap_err();
        assert!(e.to_string().contains("Not retired"), "{e}");
        assert_eq!(r.calls().len(), 1);
        // healthy, no yes, no terminal: refused before the change
        let r = RecordingRunner::new();
        reply(&r, OLD_AND_NEW);
        assert!(run(&name, false, false, false, &r, &mut std::io::empty(), false).is_err());
        assert_eq!(r.calls().len(), 1);
        // dry run: still one question
        let r = RecordingRunner::new();
        reply(&r, OLD_AND_NEW);
        run(&name, true, true, false, &r, &mut std::io::empty(), false).unwrap();
        assert_eq!(r.calls().len(), 1);
        // with --yes: the second call is the change, and it runs as the box user over ssh (no root helper)
        let r = RecordingRunner::new();
        reply(&r, OLD_AND_NEW);
        reply(&r, "retire: done\n");
        run(&name, true, false, false, &r, &mut std::io::empty(), false).unwrap();
        let calls = r.calls();
        assert_eq!(calls.len(), 2);
        assert!(calls.iter().all(|c| c.program == "ssh"));
        assert!(calls[1]
            .stdin
            .as_deref()
            .is_some_and(|s| String::from_utf8_lossy(s).contains("shred -u")));
    }

    #[test]
    fn a_box_with_nothing_left_is_told_so_and_nothing_is_asked_twice() {
        let name = ozbox_core::BoxName::new("dev").unwrap();
        let r = RecordingRunner::new();
        reply(&r, "legacy-active: inactive\nsystem: active\n");
        run(&name, true, false, false, &r, &mut std::io::empty(), false).unwrap();
        assert_eq!(r.calls().len(), 1);
    }
}
