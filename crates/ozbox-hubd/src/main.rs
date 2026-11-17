//! `ozbox-hubd`: the hub daemon on `main` (ADR 0042). Run by systemd as the user `ozbox-hub`; see `ozbox_hubd::daemon`.
//!
//! ```text
//! ozbox-hubd serve     --dir DIR --socket PATH --secrets-socket PATH --registrars PATH --box-id ID [--name NAME] [--listen ADDR:PORT]
//! ozbox-hubd self-test --dir DIR --socket PATH --secrets-socket PATH --registrars PATH --box-id ID [--name NAME]
//! ozbox-hubd setup     BOX-ID [ADDR:PORT]   (as root: the units, folders and registrars file; the address workers dial)
//! ozbox-hubd agent-setup NAME ADDR:PORT HUB-IDENTITY-FP   (as root, on a worker: the agent's unit)
//! ozbox-hubd enrol     --name NAME --token-file PATH --attestation PATH --hub-addr ADDR:PORT --hub-identity-fp FP --secrets-socket PATH
//! ozbox-hubd agent     --name NAME --hub-addr ADDR:PORT --hub-identity PATH --hub-identity-fp FP --secrets-socket PATH --hub-secrets-socket PATH [--hub NAME]
//! ozbox-hubd ctl       --socket PATH OP [JSON]   (the owner's way to the daemon: roster, invite_plan, enrol_receive, ...)
//! ozbox-hubd --version
//! ```

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use ozbox_hubd::daemon::{bind, now_ms, Config, Hubd};
use ozbox_hubd::nethost::NetHost;
use ozbox_hubd::ops::SocketKeyOps;

/// The name of the socket unit systemd hands the supervisor socket over from.
const SOCKET_UNIT: &str = "ozbox-hubd.socket";

const USAGE: &str = "usage: ozbox-hubd serve|self-test --dir DIR --socket PATH --secrets-socket PATH --registrars PATH --box-id ID [--name NAME]";

struct Args {
    cmd: String,
    cfg: Config,
    secrets: PathBuf,
    listen: Option<std::net::SocketAddr>,
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
    let listen = match get("--listen") {
        Some(l) => Some(
            l.parse::<std::net::SocketAddr>()
                .map_err(|_| format!("--listen is an address and a port\n{USAGE}"))?,
        ),
        None => None,
    };
    Ok(Args {
        cmd,
        cfg,
        secrets,
        listen,
    })
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.first().map(String::as_str) == Some("--version") {
        println!("ozbox-hubd {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    if argv.first().map(String::as_str) == Some("agent-setup") {
        let get = |i: usize| argv.get(i).map(String::as_str).unwrap_or_default();
        return match ozbox_hubd::setup::run_agent(&ozbox_core::SystemRunner, get(1), get(2), get(3))
        {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("{e}");
                ExitCode::FAILURE
            }
        };
    }
    if argv.first().map(String::as_str) == Some("setup") {
        let box_id = argv.get(1).map(String::as_str).unwrap_or_default();
        let listen = argv.get(2).map(String::as_str);
        return match ozbox_hubd::setup::run(&ozbox_core::SystemRunner, box_id, listen) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("{e}");
                ExitCode::FAILURE
            }
        };
    }
    if argv.first().map(String::as_str) == Some("ctl") {
        return ctl(&argv);
    }
    if matches!(argv.first().map(String::as_str), Some("enrol" | "agent")) {
        return match ozbox_hubd::workerbin::run(&argv) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("ozbox-hubd: {e}");
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
            let hub = match Hubd::open(a.cfg.clone(), ops.clone()) {
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
            // the network end: workers dial out to this address; nothing is opened unless the unit was set up with one
            let _host = match a.listen {
                Some(addr) => match NetHost::start(hub.clone(), ops.clone(), addr) {
                    Ok(h) => {
                        let h = Arc::new(h);
                        let pump = h.clone();
                        std::thread::spawn(move || {
                            let mut tick = 0u64;
                            loop {
                                pump.pump(now_ms());
                                tick += 1;
                                if tick % 20 == 0 {
                                    let _ = pump.sync_roster();
                                }
                                std::thread::sleep(std::time::Duration::from_millis(100));
                            }
                        });
                        eprintln!("ozbox-hubd: workers dial {}", h.local_addr());
                        Some(h)
                    }
                    Err(e) => {
                        eprintln!("ozbox-hubd: {e}");
                        return ExitCode::FAILURE;
                    }
                },
                None => None,
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

/// `ozbox-hubd ctl --socket PATH OP [JSON]`: one request to the daemon's socket (as the supervisor's group or root), the answer
/// printed. The JSON is the request's other fields: `ctl --socket S invite_plan '{"spec":{...}}'`.
fn ctl(argv: &[String]) -> ExitCode {
    let at = argv.iter().position(|a| a == "--socket");
    let (Some(sock), Some(op)) = (
        at.and_then(|i| argv.get(i + 1)).cloned(),
        at.and_then(|i| argv.get(i + 2))
            .cloned()
            .filter(|o| !o.starts_with('{')),
    ) else {
        eprintln!("usage: ozbox-hubd ctl --socket PATH OP [JSON]");
        return ExitCode::from(2);
    };
    let mut req = match argv.last().filter(|l| l.starts_with('{')) {
        Some(j) => match serde_json::from_str::<serde_json::Value>(j) {
            Ok(v) if v.is_object() => v,
            _ => {
                eprintln!("the JSON is not an object");
                return ExitCode::from(2);
            }
        },
        None => serde_json::json!({}),
    };
    req["op"] = serde_json::Value::String(op);
    match ozbox_hubd::daemon::ask(std::path::Path::new(&sock), &req) {
        Ok(v) => {
            println!("{v}");
            if v["ok"].as_bool() == Some(true) {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
