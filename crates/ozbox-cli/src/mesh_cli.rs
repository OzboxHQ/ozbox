//! `ozbox mesh …`: the tailnet you run yourself (ADR 0028). Every change is shown first, then confirmed (ADR 0002).

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use ozbox_core::{BoxName, CommandRunner};
use serde_json::json;

use crate::cli::MeshCommand;
use crate::mesh::headscale::Headscale;
use crate::mesh::{self, Allow, MeshFile};
use crate::messages::t;
use crate::run::CliError;
use crate::secrets::SecretStore;

pub fn mesh_path() -> Option<PathBuf> {
    crate::config::Config::path().map(|p| p.with_file_name("mesh.toml"))
}

/// For the SSH routes: the account on a box and the tailnet's base domain, when `mesh.toml` exists and is valid.
pub fn route_setting() -> Option<(String, String)> {
    let f = MeshFile::load(&mesh_path()?).ok().flatten()?;
    f.validate().ok()?;
    Some((f.ssh_user().to_string(), f.base_domain.clone()))
}

fn msg(key: &str) -> CliError {
    CliError::Msg(t(key, &[]))
}

/// The secret that holds a box's own one-use key, when the person made one by hand with `ozbox mesh key`.
pub fn key_secret(box_name: &str) -> String {
    format!("mesh-authkey-{box_name}")
}

#[derive(Clone, Copy)]
pub struct Flags {
    pub yes: bool,
    pub dry_run: bool,
    pub json: bool,
}

/// Everything the commands touch, so a test can stand in for each.
pub struct Deps<'a> {
    pub runner: &'a dyn CommandRunner,
    pub secrets: &'a dyn SecretStore,
    pub path: PathBuf,
    /// Names of the boxes in the fleet.
    pub boxes: Vec<String>,
    pub stdin: &'a mut dyn BufRead,
    pub interactive: bool,
    pub out: &'a mut dyn Write,
}

fn say(d: &mut Deps, line: &str) {
    let _ = writeln!(d.out, "{line}");
}

/// Show the plan; stop on `--dry-run`; otherwise confirm. `Ok(false)` means nothing is to be done.
fn plan_then_confirm(d: &mut Deps, f: Flags, lines: &[String]) -> Result<bool, CliError> {
    if f.json {
        // the plan is part of the answer
    } else {
        say(d, &t("mesh.plan_head", &[]));
        for l in lines {
            say(d, &format!("  - {l}"));
        }
    }
    if f.dry_run {
        if !f.json {
            say(d, &t("mesh.dry_run", &[]));
        }
        return Ok(false);
    }
    if f.yes {
        return Ok(true);
    }
    if !d.interactive {
        return Err(msg("mesh.refuse_no_tty"));
    }
    let _ = write!(d.out, "{} [y/N] ", t("mesh.proceed", &[]));
    let _ = d.out.flush();
    let mut line = String::new();
    let _ = d.stdin.read_line(&mut line);
    if matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        Ok(true)
    } else {
        Err(msg("mesh.aborted"))
    }
}

fn load(d: &Deps) -> Result<MeshFile, CliError> {
    let f = MeshFile::load(&d.path)
        .map_err(CliError::Msg)?
        .ok_or_else(|| msg("mesh.not_set_up"))?;
    f.validate().map_err(msg)?;
    Ok(f)
}

fn known_box(d: &Deps, name: &BoxName) -> Result<(), CliError> {
    if d.boxes.iter().any(|b| b == name.as_str()) {
        Ok(())
    } else {
        Err(CliError::Msg(t(
            "mesh.no_such_box",
            &[("box", name.as_str())],
        )))
    }
}

fn pretty(v: &serde_json::Value) -> String {
    serde_json::to_string_pretty(v).unwrap_or_default()
}

pub fn run_with(cmd: &MeshCommand, d: &mut Deps, f: Flags) -> Result<(), CliError> {
    match cmd {
        MeshCommand::Setup {
            control_url,
            user,
            admin_host,
            ssh_user,
            base_domain,
        } => {
            let prev = MeshFile::load(&d.path)
                .map_err(CliError::Msg)?
                .unwrap_or_default();
            let file = MeshFile {
                control_url: control_url.trim().trim_end_matches('/').to_string(),
                user: user.trim().to_string(),
                admin_host: admin_host.clone().unwrap_or_default(),
                ssh_user: ssh_user.clone().unwrap_or_default(),
                base_domain: base_domain.clone().unwrap_or_default(),
                allow: prev.allow,
            };
            file.validate().map_err(msg)?;
            let lines = vec![t(
                "mesh.plan_save",
                &[("url", &file.control_url), ("user", &file.user)],
            )];
            if !plan_then_confirm(d, f, &lines)? {
                return Ok(());
            }
            file.save(&d.path).map_err(CliError::Msg)?;
            if f.json {
                say(
                    d,
                    &json!({"saved": true, "control_url": file.control_url, "user": file.user})
                        .to_string(),
                );
            } else {
                say(d, &t("mesh.saved", &[("url", &file.control_url)]));
                say(d, &t("mesh.next_policy", &[]));
            }
            Ok(())
        }
        MeshCommand::Allow { from, to, port } => {
            let mut file = load(d)?;
            known_box(d, from)?;
            known_box(d, to)?;
            file.allow
                .retain(|a| !(a.from == from.as_str() && a.to == to.as_str()));
            file.allow.push(Allow {
                from: from.to_string(),
                to: to.to_string(),
                ports: port.clone(),
            });
            file.validate().map_err(msg)?;
            let ports = port
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(",");
            let lines = vec![t(
                "mesh.plan_allow",
                &[
                    ("from", from.as_str()),
                    ("to", to.as_str()),
                    ("ports", &ports),
                ],
            )];
            if !plan_then_confirm(d, f, &lines)? {
                return Ok(());
            }
            file.save(&d.path).map_err(CliError::Msg)?;
            say(d, &t("mesh.next_policy", &[]));
            Ok(())
        }
        MeshCommand::Deny { from, to } => {
            let mut file = load(d)?;
            let before = file.allow.len();
            file.allow
                .retain(|a| !(a.from == from.as_str() && a.to == to.as_str()));
            if file.allow.len() == before {
                return Err(msg("mesh.no_such_rule"));
            }
            let lines = vec![t(
                "mesh.plan_deny",
                &[("from", from.as_str()), ("to", to.as_str())],
            )];
            if !plan_then_confirm(d, f, &lines)? {
                return Ok(());
            }
            file.save(&d.path).map_err(CliError::Msg)?;
            say(d, &t("mesh.next_policy", &[]));
            Ok(())
        }
        MeshCommand::Policy { out, apply } => {
            let file = load(d)?;
            let doc = mesh::policy::generate(&file, &d.boxes).map_err(msg)?;
            let text = pretty(&doc);
            if let Some(p) = out {
                std::fs::write(p, format!("{text}\n")).map_err(|_| msg("mesh.write_failed"))?;
                say(
                    d,
                    &t("mesh.policy_written", &[("path", &p.display().to_string())]),
                );
            } else if !*apply {
                say(d, &text);
            }
            if *apply {
                let lines = vec![
                    t("mesh.plan_policy", &[("boxes", &d.boxes.len().to_string())]),
                    t("mesh.plan_policy_mode", &[]),
                ];
                if !plan_then_confirm(d, f, &lines)? {
                    return Ok(());
                }
                Headscale::new(d.runner, &file.admin_host)
                    .set_policy(&text)
                    .map_err(msg)?;
                say(d, &t("mesh.policy_applied", &[]));
            }
            Ok(())
        }
        MeshCommand::Key { name, clear } => {
            let _ = load(d)?;
            known_box(d, name)?;
            let secret = key_secret(name.as_str());
            if *clear {
                d.secrets
                    .delete(&secret)
                    .map_err(|e| CliError::Msg(e.to_string()))?;
                say(d, &t("mesh.key_cleared", &[]));
                return Ok(());
            }
            let mut line = String::new();
            d.stdin
                .read_line(&mut line)
                .map_err(|_| msg("mesh.key_unreadable"))?;
            let key = line.trim();
            if !mesh::headscale::key_ok(key) {
                return Err(msg("mesh.bad_key"));
            }
            d.secrets
                .set(&secret, key)
                .map_err(|e| CliError::Msg(e.to_string()))?;
            say(d, &t("mesh.key_saved", &[]));
            Ok(())
        }
        MeshCommand::Join {
            name,
            ssh_key,
            policy_managed_elsewhere,
        } => {
            let file = load(d)?;
            known_box(d, name)?;
            let pubkey = match ssh_key {
                Some(p) => Some(read_public_key(p)?),
                None => None,
            };
            let hs = Headscale::new(d.runner, &file.admin_host);
            // Headscale with no policy, or another one, lets every node reach every other: a box joined then could reach
            // the person's laptop. So the rules in force must be the deny-by-default ones generated from the fleet.
            if !*policy_managed_elsewhere {
                let want = mesh::policy::generate(&file, &d.boxes).map_err(msg)?;
                match hs.policy() {
                    Ok(have) if have == want => {}
                    Ok(_) => return Err(msg("mesh.policy_differs")),
                    Err(_) => return Err(msg("mesh.policy_unknown")),
                }
            }
            let lines = mesh::join::plan(name.as_str(), pubkey.is_some());
            if !plan_then_confirm(d, f, &lines)? {
                return Ok(());
            }
            let secret = key_secret(name.as_str());
            let stored = d
                .secrets
                .get(&secret)
                .map_err(|e| CliError::Msg(e.to_string()))?
                .map(zeroize::Zeroizing::new);
            let used_stored = stored.is_some();
            let id = hs.user_id(&file.user).map_err(msg)?;
            let key = match stored {
                Some(k) => {
                    // A key made by hand is used only if the server says it is what a minted one would be.
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |t| t.as_secs() as i64);
                    let fit = hs
                        .preauth_keys(id)
                        .map_err(msg)?
                        .iter()
                        .any(|i| i.key == k.as_str() && i.fit_for(name.as_str(), now));
                    if !fit {
                        return Err(CliError::Msg(t(
                            "mesh.stored_key_unfit",
                            &[("box", name.as_str()), ("user", &file.user)],
                        )));
                    }
                    k
                }
                None => zeroize::Zeroizing::new(hs.mint_key(id, name.as_str()).map_err(msg)?),
            };
            let script =
                mesh::join::script(&file, name.as_str(), &key, pubkey.as_deref()).map_err(msg)?;
            d.runner
                .run_ok(&mesh::join::command(name.as_str(), script))
                .map_err(|_| msg("mesh.join_failed"))?;
            if used_stored {
                let _ = d.secrets.delete(&secret);
            }
            if f.json {
                say(d, &json!({"joined": name.as_str()}).to_string());
            } else {
                say(d, &t("mesh.joined", &[("box", name.as_str())]));
            }
            Ok(())
        }
        MeshCommand::Status => {
            let file = load(d)?;
            let nodes = Headscale::new(d.runner, &file.admin_host)
                .nodes()
                .map_err(msg)?;
            let mut rows = Vec::new();
            for b in &d.boxes {
                let tag = mesh::box_tag(b);
                let node = nodes.iter().find(|n| n.tags.contains(&tag));
                let state = match node {
                    None => "not_joined",
                    Some(n) if n.online => "online",
                    Some(_) => "offline",
                };
                rows.push((b.clone(), state));
            }
            if f.json {
                let v: Vec<_> = rows
                    .iter()
                    .map(|(b, s)| json!({"box": b, "state": s}))
                    .collect();
                say(
                    d,
                    &json!({"control_url": file.control_url, "boxes": v}).to_string(),
                );
            } else {
                say(d, &t("mesh.status_head", &[("url", &file.control_url)]));
                for (b, s) in &rows {
                    say(
                        d,
                        &format!("{b:<24} {}", t(&format!("mesh.state_{s}"), &[])),
                    );
                }
            }
            Ok(())
        }
        MeshCommand::Forward { name, port } => {
            let file = load(d)?;
            known_box(d, name)?;
            if *port < 1024 {
                return Err(msg("mesh.bad_port"));
            }
            let _ = file;
            say(
                d,
                &format!(
                    "ssh -N -L {port}:127.0.0.1:{port} {}",
                    crate::sshconfig::host_alias(name.as_str())
                ),
            );
            say(d, &t("mesh.forward_note", &[("port", &port.to_string())]));
            Ok(())
        }
        MeshCommand::Client => {
            let file = load(d)?;
            say(d, &t("mesh.client_head", &[]));
            say(
                d,
                &format!("  tailscale up --login-server {}", file.control_url),
            );
            say(d, &t("mesh.client_register", &[("user", &file.user)]));
            Ok(())
        }
        MeshCommand::Remove => {
            let _ = load(d)?;
            let lines = vec![t("mesh.plan_remove", &[])];
            if !plan_then_confirm(d, f, &lines)? {
                return Ok(());
            }
            let _ = std::fs::remove_file(&d.path);
            say(d, &t("mesh.removed", &[]));
            Ok(())
        }
    }
}

fn read_public_key(p: &Path) -> Result<String, CliError> {
    let text = std::fs::read_to_string(p).map_err(|_| msg("mesh.ssh_key_unreadable"))?;
    let line = text.lines().next().unwrap_or("").trim().to_string();
    if mesh::join::public_key_ok(&line) {
        Ok(line)
    } else {
        Err(msg("mesh.bad_ssh_key"))
    }
}

pub fn run(cmd: &MeshCommand, boxes: Vec<String>, f: Flags) -> Result<(), CliError> {
    use std::io::IsTerminal;
    let path = mesh_path().ok_or_else(|| msg("init.cli_no_home"))?;
    let secrets = crate::secrets_file::select();
    let stdin = std::io::stdin();
    let mut lock = stdin.lock();
    let mut out = std::io::stdout();
    let mut d = Deps {
        runner: &ozbox_core::SystemRunner,
        secrets: secrets.as_ref(),
        path,
        boxes,
        stdin: &mut lock,
        interactive: std::io::stdin().is_terminal(),
        out: &mut out,
    };
    run_with(cmd, &mut d, f)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::secrets::MemorySecrets;
    use ozbox_core::{Output, RecordingRunner};

    const KEY: &str = "hskey-auth-SENTINELKEY-0123456789abcdef";

    struct H {
        runner: RecordingRunner,
        secrets: MemorySecrets,
        dir: tempfile::TempDir,
    }

    fn h() -> H {
        H {
            runner: RecordingRunner::new(),
            secrets: MemorySecrets::default(),
            dir: tempfile::tempdir().unwrap(),
        }
    }

    fn go(h: &H, cmd: &MeshCommand, input: &str, f: Flags) -> (Result<(), CliError>, String) {
        let mut stdin = std::io::Cursor::new(input.as_bytes().to_vec());
        let mut out = Vec::new();
        let mut d = Deps {
            runner: &h.runner,
            secrets: &h.secrets,
            path: h.dir.path().join("mesh.toml"),
            boxes: vec!["dev".into(), "build".into()],
            stdin: &mut stdin,
            interactive: false,
            out: &mut out,
        };
        let r = run_with(cmd, &mut d, f);
        (r, String::from_utf8(out).unwrap())
    }

    const YES: Flags = Flags {
        yes: true,
        dry_run: false,
        json: false,
    };

    fn setup() -> MeshCommand {
        MeshCommand::Setup {
            control_url: "https://headscale.example.com/".into(),
            user: "alice".into(),
            admin_host: None,
            ssh_user: None,
            base_domain: Some("tail.example.com".into()),
        }
    }

    fn name(s: &str) -> BoxName {
        BoxName::new(s).unwrap()
    }

    fn ok(h: &H, stdout: &str) {
        h.runner.reply(Output {
            status: Some(0),
            stdout: stdout.into(),
            stderr: String::new(),
        });
    }

    /// The server answers `policy get` with the rules generated from the fleet.
    fn loaded_policy(h: &H) {
        let file = MeshFile::load(&h.dir.path().join("mesh.toml"))
            .unwrap()
            .unwrap();
        let doc = mesh::policy::generate(&file, &["dev".into(), "build".into()]).unwrap();
        ok(h, &doc.to_string());
    }

    /// `preauthkeys list` for alice: the stored key, single use, unused, an hour from now, tagged for dev.
    fn listed_key(h: &H, reusable: bool) {
        let soon = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        ok(
            h,
            &format!(
                r#"[{{"key":"{KEY}","reusable":{reusable},"used":false,"expiration":{{"seconds":{soon}}},"acl_tags":["tag:ozbox-dev"]}}]"#
            ),
        );
    }

    #[test]
    fn setup_is_planned_and_a_dry_run_writes_nothing() {
        let h = h();
        let (r, out) = go(
            &h,
            &setup(),
            "",
            Flags {
                dry_run: true,
                ..YES
            },
        );
        r.unwrap();
        assert!(out.contains("headscale.example.com") && !h.dir.path().join("mesh.toml").exists());
        let (r, _) = go(&h, &setup(), "", Flags { yes: false, ..YES });
        assert!(
            r.is_err(),
            "a change without --yes on a non-terminal is refused"
        );
        assert!(!h.dir.path().join("mesh.toml").exists());
        go(&h, &setup(), "", YES).0.unwrap();
        assert!(h.dir.path().join("mesh.toml").exists());
    }

    #[test]
    fn nothing_works_before_setup() {
        let h = h();
        let (r, _) = go(&h, &MeshCommand::Status, "", YES);
        assert!(r.is_err());
    }

    #[test]
    fn the_policy_follows_the_fleet_and_a_declared_rule() {
        let h = h();
        go(&h, &setup(), "", YES).0.unwrap();
        go(
            &h,
            &MeshCommand::Allow {
                from: name("build"),
                to: name("dev"),
                port: vec![5432],
            },
            "",
            YES,
        )
        .0
        .unwrap();
        let (r, out) = go(
            &h,
            &MeshCommand::Policy {
                out: None,
                apply: false,
            },
            "",
            YES,
        );
        r.unwrap();
        assert!(out.contains("tag:ozbox-build") && out.contains("tag:ozbox-dev:5432"));
        let (r, _) = go(
            &h,
            &MeshCommand::Allow {
                from: name("build"),
                to: name("ghost"),
                port: vec![22],
            },
            "",
            YES,
        );
        assert!(
            r.is_err(),
            "a rule for a box that does not exist is refused"
        );
        go(
            &h,
            &MeshCommand::Deny {
                from: name("build"),
                to: name("dev"),
            },
            "",
            YES,
        )
        .0
        .unwrap();
        let (_, out) = go(
            &h,
            &MeshCommand::Policy {
                out: None,
                apply: false,
            },
            "",
            YES,
        );
        assert!(!out.contains("5432"));
    }

    #[test]
    fn applying_the_policy_sends_it_on_standard_input() {
        let h = h();
        go(&h, &setup(), "", YES).0.unwrap();
        go(
            &h,
            &MeshCommand::Policy {
                out: None,
                apply: true,
            },
            "",
            YES,
        )
        .0
        .unwrap();
        let c = &h.runner.calls()[0];
        assert_eq!(c.args[..3], ["policy", "set", "--file"]);
        assert!(String::from_utf8(c.stdin.clone().unwrap())
            .unwrap()
            .contains("tagOwners"));
    }

    #[test]
    fn joining_mints_a_key_and_the_key_is_only_on_standard_input() {
        let h = h();
        go(&h, &setup(), "", YES).0.unwrap();
        loaded_policy(&h);
        h.runner.reply(Output {
            status: Some(0),
            stdout: r#"[{"id":7,"name":"alice"}]"#.into(),
            stderr: String::new(),
        });
        h.runner.reply(Output {
            status: Some(0),
            stdout: format!(r#"{{"key":"{KEY}"}}"#),
            stderr: String::new(),
        });
        let (r, out) = go(
            &h,
            &MeshCommand::Join {
                name: name("dev"),
                ssh_key: None,
                policy_managed_elsewhere: false,
            },
            "",
            YES,
        );
        r.unwrap();
        assert!(!out.contains("SENTINELKEY"));
        let calls = h.runner.calls();
        let ssh = calls.last().unwrap();
        assert_eq!(ssh.program, "ssh");
        assert!(ssh.args.iter().all(|a| !a.contains("SENTINELKEY")));
        assert!(String::from_utf8(ssh.stdin.clone().unwrap())
            .unwrap()
            .contains("SENTINELKEY"));
    }

    #[test]
    fn a_stored_key_is_used_once_and_then_removed() {
        let h = h();
        go(&h, &setup(), "", YES).0.unwrap();
        let (r, out) = go(
            &h,
            &MeshCommand::Key {
                name: name("dev"),
                clear: false,
            },
            &format!("{KEY}\n"),
            YES,
        );
        r.unwrap();
        assert!(!out.contains("SENTINELKEY"));
        assert!(h.secrets.exists("mesh-authkey-dev").unwrap());
        loaded_policy(&h);
        ok(&h, r#"[{"id":7,"name":"alice"}]"#);
        listed_key(&h, false);
        go(
            &h,
            &MeshCommand::Join {
                name: name("dev"),
                ssh_key: None,
                policy_managed_elsewhere: false,
            },
            "",
            YES,
        )
        .0
        .unwrap();
        // nothing was minted: the key the server listed is the one used, then removed
        let calls = h.runner.calls();
        assert!(!calls.iter().any(|c| c.args.iter().any(|a| a == "create")));
        assert_eq!(calls.last().unwrap().program, "ssh");
        assert!(!h.secrets.exists("mesh-authkey-dev").unwrap());
    }

    #[test]
    fn a_join_is_refused_unless_the_deny_by_default_rules_are_loaded() {
        let h = h();
        go(&h, &setup(), "", YES).0.unwrap();
        let join = |elsewhere: bool| MeshCommand::Join {
            name: name("dev"),
            ssh_key: None,
            policy_managed_elsewhere: elsewhere,
        };
        // no policy at all (Headscale's default allows everything), another policy, and a server that cannot show one
        ok(&h, "{}");
        let (r, _) = go(&h, &join(false), "", YES);
        assert!(r.unwrap_err().to_string().contains("mesh policy --apply"));
        ok(
            &h,
            r#"{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}"#,
        );
        assert!(go(&h, &join(false), "", YES).0.is_err());
        h.runner.reply(Output {
            status: Some(1),
            stdout: String::new(),
            stderr: "policy is in file mode".into(),
        });
        let (r, _) = go(&h, &join(false), "", YES);
        assert!(r
            .unwrap_err()
            .to_string()
            .contains("--policy-managed-elsewhere"));
        // nothing was minted and nothing reached the box
        let calls = h.runner.calls();
        assert!(calls.iter().all(|c| c.program == "headscale"));
        assert!(!calls.iter().any(|c| c.args.iter().any(|a| a == "create")));
        // the person's explicit word skips the check, and only that
        ok(&h, r#"[{"id":7,"name":"alice"}]"#);
        ok(&h, &format!(r#"{{"key":"{KEY}"}}"#));
        go(&h, &join(true), "", YES).0.unwrap();
        assert!(!h
            .runner
            .calls()
            .iter()
            .skip(calls.len())
            .any(|c| c.args.iter().any(|a| a == "policy")));
    }

    #[test]
    fn a_stored_key_the_server_does_not_list_as_single_use_for_this_box_is_not_used() {
        let h = h();
        go(&h, &setup(), "", YES).0.unwrap();
        go(
            &h,
            &MeshCommand::Key {
                name: name("dev"),
                clear: false,
            },
            &format!("{KEY}\n"),
            YES,
        )
        .0
        .unwrap();
        loaded_policy(&h);
        ok(&h, r#"[{"id":7,"name":"alice"}]"#);
        listed_key(&h, true);
        let (r, out) = go(
            &h,
            &MeshCommand::Join {
                name: name("dev"),
                ssh_key: None,
                policy_managed_elsewhere: false,
            },
            "",
            YES,
        );
        let e = r.unwrap_err().to_string();
        assert!(
            e.contains("single use") && !e.contains("SENTINELKEY") && !out.contains("SENTINELKEY")
        );
        assert!(!h.runner.calls().iter().any(|c| c.program == "ssh"));
    }

    #[test]
    fn a_badly_shaped_key_is_not_stored() {
        let h = h();
        go(&h, &setup(), "", YES).0.unwrap();
        let (r, _) = go(
            &h,
            &MeshCommand::Key {
                name: name("dev"),
                clear: false,
            },
            "short\n",
            YES,
        );
        assert!(r.is_err());
        assert!(!h.secrets.exists("mesh-authkey-dev").unwrap());
    }

    #[test]
    fn a_failed_join_says_so_without_the_output() {
        let h = h();
        go(&h, &setup(), "", YES).0.unwrap();
        go(
            &h,
            &MeshCommand::Key {
                name: name("dev"),
                clear: false,
            },
            &format!("{KEY}\n"),
            YES,
        )
        .0
        .unwrap();
        loaded_policy(&h);
        ok(&h, r#"[{"id":7,"name":"alice"}]"#);
        listed_key(&h, false);
        h.runner.reply(Output {
            status: Some(1),
            stdout: "SENTINELKEY".into(),
            stderr: "SENTINELKEY".into(),
        });
        let (r, _) = go(
            &h,
            &MeshCommand::Join {
                name: name("dev"),
                ssh_key: None,
                policy_managed_elsewhere: false,
            },
            "",
            YES,
        );
        let e = r.unwrap_err().to_string();
        assert!(!e.contains("SENTINELKEY"));
        assert!(
            h.secrets.exists("mesh-authkey-dev").unwrap(),
            "the key stays until a join succeeds"
        );
    }

    #[test]
    fn status_tells_joined_from_not_joined() {
        let h = h();
        go(&h, &setup(), "", YES).0.unwrap();
        h.runner.reply(Output {
            status: Some(0),
            stdout: r#"[{"given_name":"dev","online":true,"forced_tags":["tag:ozbox-dev"]}]"#
                .into(),
            stderr: String::new(),
        });
        let (r, out) = go(&h, &MeshCommand::Status, "", Flags { json: true, ..YES });
        r.unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["boxes"][0]["state"], "online");
        assert_eq!(v["boxes"][1]["state"], "not_joined");
    }

    #[test]
    fn forward_prints_an_ssh_local_forward_through_the_box_alias() {
        let h = h();
        go(&h, &setup(), "", YES).0.unwrap();
        let (r, out) = go(
            &h,
            &MeshCommand::Forward {
                name: name("dev"),
                port: 7878,
            },
            "",
            YES,
        );
        r.unwrap();
        assert!(out.contains("ssh -N -L 7878:127.0.0.1:7878 ozbox-dev"));
        let (r, _) = go(
            &h,
            &MeshCommand::Forward {
                name: name("dev"),
                port: 80,
            },
            "",
            YES,
        );
        assert!(r.is_err());
    }
}
