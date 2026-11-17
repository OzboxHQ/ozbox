//! `ozbox-hubd`: the hub daemon on `main` (ADR 0042). Run by systemd as the user `ozbox-hub`; see `ozbox_hubd::daemon`.
//!
//! ```text
//! ozbox-hubd serve     --dir DIR --socket PATH --secrets-socket PATH --registrars PATH --box-id ID [--name NAME]
//! ozbox-hubd self-test --dir DIR --socket PATH --secrets-socket PATH --registrars PATH --box-id ID [--name NAME]
//! ozbox-hubd setup     BOX-ID      (as root: the units, folders and registrars file)
//! ozbox-hubd --version
//! ```

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use ozbox_hubd::daemon::{bind, now_ms, Config, Hubd};
use ozbox_hubd::ops::SocketKeyOps;

/// The name of the socket unit systemd hands the supervisor socket over from.
const SOCKET_UNIT: &str = "ozbox-hubd.socket";

const USAGE: &str = "usage: ozbox-hubd serve|self-test --dir DIR --socket PATH --secrets-socket PATH --registrars PATH --box-id ID [--name NAME]";

struct Args {
    cmd: String,
    cfg: Config,
    secrets: PathBuf,
}

fn parse(argv: &[String]) -> Result<Args, String> {
    let cmd = argv.first().cloned().ok_or(USAGE)?;
    let get = |flag: &str| -> Option<String> {
        argv.windows(2).find(|w| w[0] == flag).map(|w| w[1].clone())
    };
    let need = |v: Option<String>, f: &str| v.ok_or_else(|| format!("{f} is needed\n{USAGE}"));
    let cfg = Config {
        dir: PathBuf::from(need(get("--dir"), "--dir")?),
        socket: PathBuf::from(need(get("--socket"), "--socket")?),
        registrars: PathBuf::from(need(get("--registrars"), "--registrars")?),
        box_id: need(get("--box-id"), "--box-id")?,
        name: get("--name").unwrap_or_else(|| "main".into()),
    };
    let secrets = PathBuf::from(need(get("--secrets-socket"), "--secrets-socket")?);
    Ok(Args { cmd, cfg, secrets })
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.first().map(String::as_str) == Some("--version") {
        println!("ozbox-hubd {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    if argv.first().map(String::as_str) == Some("setup") {
        let box_id = argv.get(1).map(String::as_str).unwrap_or_default();
        return match ozbox_hubd::setup::run(&ozbox_core::SystemRunner, box_id) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("{e}");
                ExitCode::FAILURE
            }
        };
    }
    let a = match parse(&argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let ops = Arc::new(SocketKeyOps::new(&a.secrets));
    match a.cmd.as_str() {
        "self-test" => {
            let checks = ozbox_hubd::selftest::self_test(&a.cfg, ops.as_ref(), 0, now_ms());
            let mut ok = true;
            for c in &checks {
                println!(
                    "{} {}: {}",
                    if c.ok { "ok  " } else { "FAIL" },
                    c.name,
                    c.detail
                );
                ok &= c.ok;
            }
            if ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        "serve" => {
            let hub = match Hubd::open(a.cfg.clone(), ops) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("ozbox-hubd: {e}");
                    return ExitCode::FAILURE;
                }
            };
            // systemd binds the socket as root in a directory root owns (socket activation); without it, bind here
            let (listener, path) = match ozbox_listenfd::take_unix_listener_named(SOCKET_UNIT) {
                Some(Ok(l)) => (l, None),
                Some(Err(e)) => {
                    eprintln!("ozbox-hubd: the socket systemd passed is not usable: {e}");
                    return ExitCode::FAILURE;
                }
                None => match bind(&a.cfg.socket, 0o750) {
                    Ok(l) => (l, Some(a.cfg.socket.clone())),
                    Err(_) => {
                        eprintln!("ozbox-hubd: the socket could not be bound");
                        return ExitCode::FAILURE;
                    }
                },
            };
            let running = match hub.serve(listener, path) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("ozbox-hubd: {e}");
                    return ExitCode::FAILURE;
                }
            };
            eprintln!(
                "ozbox-hubd: serving hub {} ({})",
                hub.identity().identity_fp(),
                ozbox_listenfd::DAEMON_MARKER
            );
            running.wait();
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}
