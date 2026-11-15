//! `ozbox tunnel setup | status | remove`, and the tunnel `ozbox serve --tunnel` starts.

use std::io::BufRead;
use std::path::PathBuf;
use std::sync::Arc;

use ozbox_core::SystemRunner;
use serde_json::json;

use crate::cli::TunnelCommand;
use crate::messages::t;
use crate::netguard::UreqClient;
use crate::run::CliError;
use crate::tunnel::{self, CaddyCfg, Kind, State, TunnelFile, DEFAULT_PORT};

/// What `serve` is told to start.
pub struct TunnelStart {
    pub file: TunnelFile,
    pub state_path: Option<PathBuf>,
}

fn beside(name: &str) -> Option<PathBuf> {
    crate::config::Config::path().map(|p| p.with_file_name(name))
}

/// `tunnel.toml`, beside the main configuration.
pub fn tunnel_path() -> Option<PathBuf> {
    beside("tunnel.toml")
}

pub fn state_path() -> Option<PathBuf> {
    beside("tunnel-state.json")
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn msg(e: &str) -> CliError {
    CliError::Msg(e.to_string())
}

/// The tunnel for `ozbox serve --public-url … --tunnel …`: the saved settings, with the flags laid over them.
pub fn for_serve(
    tunnel_flag: Option<&str>,
    public_url: Option<&str>,
) -> Result<Option<TunnelStart>, String> {
    let Some(flag) = tunnel_flag else {
        return Ok(None);
    };
    let kind = Kind::parse(flag).ok_or_else(|| t("tunnel.bad_provider", &[]))?;
    let saved = match tunnel_path() {
        Some(p) => TunnelFile::load(&p)?,
        None => None,
    };
    let mut file = match saved {
        // Saved settings for another provider say nothing about this one's extra fields, but the address carries over.
        Some(f) if f.kind() == Some(kind) => f,
        Some(f) => TunnelFile {
            provider: kind.id().into(),
            public_url: f.public_url,
            caddy: None,
        },
        None => TunnelFile {
            provider: kind.id().into(),
            ..Default::default()
        },
    };
    if let Some(u) = public_url {
        file.public_url = u.trim().trim_end_matches('/').to_string();
    }
    if file.public_url.is_empty() {
        return Err(t("tunnel.need_address", &[]));
    }
    file.validate().map_err(|k| t(k, &[]))?;
    Ok(Some(TunnelStart {
        file,
        state_path: state_path(),
    }))
}

/// The terminal, for a confirmation that standard input (which carries a token) cannot give. None when there is none.
pub fn tty_reader() -> Option<std::io::BufReader<std::fs::File>> {
    std::fs::File::open("/dev/tty")
        .ok()
        .map(std::io::BufReader::new)
}

/// What a replacement of a stored tunnel token needs: the flag, and a place to read a typed word from.
pub struct ReplaceCheck<'a> {
    pub replace: bool,
    pub typed: Option<&'a mut dyn BufRead>,
}

impl<'a> ReplaceCheck<'a> {
    #[cfg(test)]
    pub fn none() -> Self {
        Self {
            replace: false,
            typed: None,
        }
    }
    pub fn new(replace: bool, typed: Option<&'a mut std::io::BufReader<std::fs::File>>) -> Self {
        Self {
            replace,
            typed: typed.map(|r| r as &mut dyn BufRead),
        }
    }
}

/// A token that is already stored is never overwritten quietly: it decides where the dashboard is reached from, so a
/// replacement needs `--replace` and the provider's name typed by a person at a terminal. Nothing is asked when no token
/// is stored.
pub fn confirm_replace(exists: bool, word: &str, rc: ReplaceCheck<'_>) -> Result<(), CliError> {
    if !exists {
        return Ok(());
    }
    if !rc.replace {
        return Err(msg(&t("tunnel.token_exists", &[])));
    }
    let Some(input) = rc.typed else {
        return Err(msg(&t("tunnel.replace_need_terminal", &[])));
    };
    eprint!("{}", t("tunnel.replace_prompt", &[("word", word)]));
    let mut line = String::new();
    let _ = input.read_line(&mut line);
    if line.trim() == word {
        Ok(())
    } else {
        Err(msg(&t("tunnel.replace_refused", &[])))
    }
}

fn read_token_line() -> Result<String, CliError> {
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|_| msg(&t("tunnel.token_unreadable", &[])))?;
    let token = line.trim().to_string();
    crate::secrets::check_value(&token).map_err(|e| CliError::Msg(e.to_string()))?;
    Ok(token)
}

pub fn run(cmd: &TunnelCommand, json_out: bool) -> Result<(), CliError> {
    match cmd {
        TunnelCommand::Setup {
            tunnel_provider,
            public_url,
            token_stdin,
            ssh_host,
            ssh_user,
            ssh_port,
            ssh_key,
            remote_port,
            on_box: _,
            replace,
            approval,
            approval_stdin,
        } => {
            // A code a person brought (or the dashboard installer passed in the environment, which keeps it out of the
            // box's process list): its shape is checked here, and the box's secrets service spends it.
            let approval = approval
                .clone()
                .or_else(|| std::env::var("OZBOX_TUNNEL_APPROVAL").ok())
                .filter(|c| !c.trim().is_empty());
            if let Some(code) = &approval {
                if !crate::secrets_approval::is_code_shape(code) {
                    return Err(msg(&t("tunnel.bad_approval", &[])));
                }
            }
            let kind =
                Kind::parse(tunnel_provider).ok_or_else(|| msg(&t("tunnel.bad_provider", &[])))?;
            let caddy = (kind == Kind::Caddy).then(|| CaddyCfg {
                host: ssh_host.clone().unwrap_or_default(),
                user: ssh_user.clone().unwrap_or_default(),
                ssh_port: *ssh_port,
                key_file: ssh_key.clone().unwrap_or_default(),
                remote_port: *remote_port,
            });
            let file = TunnelFile {
                provider: kind.id().into(),
                public_url: public_url.trim().trim_end_matches('/').to_string(),
                caddy,
            };
            file.validate().map_err(|k| msg(&t(k, &[])))?;
            let path = tunnel_path().ok_or_else(|| msg(&t("init.cli_no_home", &[])))?;
            let secrets = crate::secrets_file::select();
            let secret = kind.token_secret();
            if *token_stdin {
                let name = secret.ok_or_else(|| msg(&t("tunnel.no_token_needed", &[])))?;
                // On a box the secrets service decides (the root helper asks it for the approval, and says how to get one), so
                // nothing is asked here: a word typed by the box user is no control against the box user. Anywhere else a stored
                // token is replaced only with --replace and the provider's name typed at a terminal.
                if !secrets.gates_replacement() {
                    let mut tty = tty_reader();
                    confirm_replace(
                        secrets.exists(name).unwrap_or(false),
                        kind.id(),
                        ReplaceCheck::new(*replace, tty.as_mut()),
                    )?;
                }
                let token = read_token_line()?;
                // the code may follow the token on its own line, so it is in no argument and no environment
                let approval = if *approval_stdin {
                    let mut line = String::new();
                    let _ = std::io::stdin().lock().read_line(&mut line);
                    let line = line.trim().to_string();
                    if line.is_empty() {
                        approval.clone()
                    } else if crate::secrets_approval::is_code_shape(&line) {
                        Some(line)
                    } else {
                        return Err(msg(&t("tunnel.bad_approval", &[])));
                    }
                } else {
                    approval.clone()
                };
                #[cfg(unix)]
                if let Some(code) = &approval {
                    crate::secrets_service::give_tunnel_approval(code);
                }
                secrets
                    .set(name, &token)
                    .map_err(|e| CliError::Msg(e.to_string()))?;
            }
            file.save(&path).map_err(CliError::Msg)?;
            let token_ok = secret.map(|name| secrets.exists(name).unwrap_or(false));
            if json_out {
                println!(
                    "{}",
                    json!({ "saved": true, "provider": kind.id(), "public_url": file.public_url, "token_set": token_ok })
                );
            } else {
                println!(
                    "{}",
                    t(
                        "tunnel.saved",
                        &[("provider", kind.id()), ("address", &file.public_url)]
                    )
                );
                if token_ok == Some(false) {
                    println!("{}", t("tunnel.token_missing", &[]));
                }
                if let Some(c) = &file.caddy {
                    println!("{}", t("tunnel.caddyfile", &[]));
                    print!(
                        "{}",
                        tunnel::caddy::caddyfile(&file.public_url, c.remote_port)
                    );
                }
                println!(
                    "{}",
                    t(
                        "tunnel.next",
                        &[("address", &file.public_url), ("provider", kind.id())]
                    )
                );
            }
            Ok(())
        }
        TunnelCommand::Status { no_probe } => status(*no_probe, json_out),
        TunnelCommand::Remove { on_box: _ } => {
            let path = tunnel_path().ok_or_else(|| msg(&t("init.cli_no_home", &[])))?;
            let saved = TunnelFile::load(&path).map_err(CliError::Msg)?;
            let _ = std::fs::remove_file(&path);
            // Every provider's token goes, not only the saved provider's: one left behind from an earlier choice
            // would sit in the store with nothing to explain it.
            let secrets = crate::secrets_file::select();
            for name in tunnel::ALL_KINDS.iter().filter_map(|k| k.token_secret()) {
                let _ = secrets.delete(name);
            }
            if json_out {
                println!("{}", json!({ "removed": saved.is_some() }));
            } else {
                println!("{}", t("tunnel.removed", &[]));
            }
            Ok(())
        }
    }
}

fn state_word(s: State) -> &'static str {
    match s {
        State::Running => "running",
        State::Stopped => "stopped",
        State::Failed => "failed",
    }
}

fn status(no_probe: bool, json_out: bool) -> Result<(), CliError> {
    let path = tunnel_path().ok_or_else(|| msg(&t("init.cli_no_home", &[])))?;
    let Some(file) = TunnelFile::load(&path).map_err(CliError::Msg)? else {
        if json_out {
            println!("{}", json!({ "configured": false }));
        } else {
            println!("{}", t("tunnel.none", &[]));
        }
        return Ok(());
    };
    let Some(kind) = file.kind() else {
        return Err(msg(&t("tunnel.bad_provider", &[])));
    };
    let secrets = crate::secrets_file::select();
    let token_set = kind
        .token_secret()
        .map(|n| secrets.exists(n).unwrap_or(false));
    let server = state_path()
        .and_then(|p| tunnel::runner::read_state(&p, now_ms()))
        .filter(|(s, _)| s.provider == kind.id());
    // Tailscale keeps its forwarding in its own daemon, whether or not `ozbox serve` is running, so ask it.
    let (live, health) = if matches!(kind, Kind::TailscaleFunnel | Kind::TailscaleServe) {
        let port = server.as_ref().map_or(DEFAULT_PORT, |(s, _)| {
            if s.port == 0 {
                DEFAULT_PORT
            } else {
                s.port
            }
        });
        let env = tunnel::Env {
            port,
            spawner: Arc::new(tunnel::SystemSpawner),
            runner: Arc::new(SystemRunner),
            secrets: Arc::clone(&secrets),
        };
        match tunnel::build(&file, &env) {
            Ok(mut tn) => {
                let st = tn.status();
                let h = if no_probe {
                    None
                } else {
                    Some(tn.health(&UreqClient))
                };
                (Some(st), h)
            }
            Err(_) => (None, None),
        }
    } else if no_probe {
        (None, None)
    } else {
        (None, Some(tunnel::probe(&UreqClient, &file.public_url)))
    };
    if json_out {
        let srv = server.as_ref().map(|(s, fresh)| {
            json!({
                "running": *fresh && s.state == State::Running,
                "fresh": fresh,
                "state": state_word(s.state),
                "code": s.code,
                "restarts": s.restarts,
                "updated_ms": s.updated_ms,
            })
        });
        println!(
            "{}",
            json!({
                "configured": true,
                "provider": kind.id(),
                "public_url": file.public_url,
                "public": kind.is_public(),
                "token_set": token_set,
                "server": srv,
                "live": live.as_ref().map(|l| json!({ "state": state_word(l.state), "code": l.code })),
                "health": health.as_ref().map(|h| json!({ "ok": h.ok, "code": h.code, "http_status": h.http_status })),
            })
        );
        return Ok(());
    }
    println!(
        "{}",
        t(
            "tunnel.st_head",
            &[("provider", kind.id()), ("address", &file.public_url)]
        )
    );
    if !kind.is_public() {
        println!("{}", t("tunnel.st_private", &[]));
    }
    match token_set {
        Some(true) => println!("{}", t("tunnel.st_token_set", &[])),
        Some(false) => println!("{}", t("tunnel.token_missing", &[])),
        None => {}
    }
    match (&live, &server) {
        (Some(l), _) => println!(
            "{}",
            t(
                "tunnel.st_state",
                &[("state", state_word(l.state)), ("code", &code_text(l.code))]
            )
        ),
        (None, Some((s, true))) => println!(
            "{}",
            t(
                "tunnel.st_state",
                &[
                    ("state", state_word(s.state)),
                    ("code", &code_text(s.code.as_deref()))
                ]
            )
        ),
        _ => println!("{}", t("tunnel.st_not_serving", &[])),
    }
    if let Some(h) = &health {
        let key = if h.ok {
            "tunnel.st_health_ok"
        } else {
            "tunnel.st_health_bad"
        };
        println!(
            "{}",
            t(
                key,
                &[("code", &t(&format!("tunnel.code_{}", h.code), &[]))]
            )
        );
    }
    Ok(())
}

fn code_text(code: Option<&str>) -> String {
    match code {
        Some(c) => format!(": {}", t(&format!("tunnel.code_{c}"), &[])),
        None => String::new(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::io::BufRead;

    use clap::{CommandFactory, Parser};

    use super::{confirm_replace, ReplaceCheck};

    use crate::cli::{Cli, Command, DashboardCommand, TunnelCommand};

    #[test]
    fn the_grammar_is_consistent_and_the_new_commands_parse() {
        Cli::command().debug_assert();
        let c = Cli::try_parse_from([
            "ozbox",
            "tunnel",
            "setup",
            "cloudflare",
            "--public-url",
            "https://ozbox.example.com",
            "--token-stdin",
        ])
        .unwrap();
        let Command::Tunnel {
            command:
                TunnelCommand::Setup {
                    tunnel_provider,
                    token_stdin,
                    ssh_port,
                    remote_port,
                    ..
                },
        } = c.command
        else {
            panic!("not a tunnel setup");
        };
        assert_eq!(
            (tunnel_provider.as_str(), token_stdin),
            ("cloudflare", true)
        );
        assert_eq!((ssh_port, remote_port), (22, 7878));
        let c = Cli::try_parse_from(["ozbox", "--json", "tunnel", "status", "--no-probe"]).unwrap();
        assert!(
            c.json
                && matches!(
                    c.command,
                    Command::Tunnel {
                        command: TunnelCommand::Status { no_probe: true }
                    }
                )
        );
        // the global --provider (where boxes run) is still its own thing
        assert!(Cli::try_parse_from(["ozbox", "--provider", "fake", "tunnel", "status"]).is_ok());
        let c = Cli::try_parse_from([
            "ozbox",
            "serve",
            "--public-url",
            "https://ozbox.example.com",
            "--tunnel",
            "ngrok",
        ])
        .unwrap();
        let Command::Serve {
            public_url,
            tunnel,
            public_behind_tunnel,
            ..
        } = c.command
        else {
            panic!("not serve");
        };
        assert_eq!(
            (
                public_url.as_deref(),
                tunnel.as_deref(),
                public_behind_tunnel
            ),
            (Some("https://ozbox.example.com"), Some("ngrok"), false)
        );
        let c = Cli::try_parse_from([
            "ozbox",
            "dashboard",
            "install",
            "dash",
            "--public-url",
            "https://ozbox.example.com",
            "--binary-url",
            "https://downloads.example.com/ozbox",
            "--binary-sha256",
            &"ab".repeat(32),
            "--person",
            "owner",
        ])
        .unwrap();
        assert!(matches!(
            c.command,
            Command::Dashboard {
                command: DashboardCommand::Install { .. }
            }
        ));
    }

    #[test]
    fn a_stored_token_is_replaced_only_with_the_flag_and_a_typed_word() {
        let ask = |exists, replace, typed: Option<&str>| {
            let mut r = std::io::Cursor::new(typed.unwrap_or("").as_bytes().to_vec());
            confirm_replace(
                exists,
                "cloudflare",
                ReplaceCheck {
                    replace,
                    typed: typed.map(|_| &mut r as &mut dyn BufRead),
                },
            )
        };
        assert!(
            ask(false, false, None).is_ok(),
            "nothing stored: nothing to confirm"
        );
        assert!(ask(true, false, Some("cloudflare\n")).is_err(), "no flag");
        assert!(ask(true, true, None).is_err(), "no terminal");
        assert!(ask(true, true, Some("yes\n")).is_err(), "wrong word");
        assert!(ask(true, true, Some("cloudflare\n")).is_ok());
    }
}
