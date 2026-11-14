//! `ozbox tasks ...`: the typed task channel between two endpoints (ADR 0044, Preview). The same commands run on a laptop and on a
//! box; only the names and the way they reach each other differ. Everything that is not a printout is in
//! [`crate::tasks_ops`] (the operations, shared with the box's router service) and `ozbox_core::agent_mesh`; this file is the command
//! line: it picks where the operations run, takes the person's answers and prints.
//!
//! * **On a laptop** the operations run in this process, against the person's own files. One user holds the key.
//! * **On a box** the channel runs as the service `ozbox tasks serve` under a system user of its own, and these commands are clients
//!   of its sockets (an agent's `tasks send` goes to the agent socket; `init`, `pin` and `restored` need root and go to the admin
//!   socket; the laptop's `ssh` reaches the keyless relay). A box with no such service runs as a laptop does, and says so.

use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;
use std::time::Duration;

use ozbox_core::agent_mesh::node::Transport;
use ozbox_core::channel::wire::{normalize_hex, unhex, word_ok, Sealed};
use ozbox_core::{CommandRunner, CommandSpec, Error, Result, SystemRunner};
use serde_json::{json, Value};

use crate::cli::TasksCommand;
use crate::messages::t;
use crate::runs_cli::Flags;
use crate::tasks_ops::{self as ops, dispatch, Ends, Offer, Policy};
use crate::tasks_service as service;

fn cfg(key: &str, args: &[(&str, &str)]) -> Error {
    Error::Config(t(key, args))
}

/// Where this endpoint keeps its channel when it runs here: `OZBOX_TASKS_DIR`, else beside the settings file.
pub fn dir() -> Result<PathBuf> {
    if let Some(d) = std::env::var_os("OZBOX_TASKS_DIR") {
        return Ok(PathBuf::from(d));
    }
    crate::settings::Settings::path()
        .map(|p| p.with_file_name("tasks-channel"))
        .ok_or_else(|| cfg("tasks.no_dir", &[]))
}

/// Where the box's router service listens: `OZBOX_TASKS_SOCKETS`, else the system location.
fn sockets_root() -> PathBuf {
    std::env::var_os("OZBOX_TASKS_SOCKETS")
        .map_or_else(|| PathBuf::from("/run/ozbox-mesh"), PathBuf::from)
}

/// Where the operations run.
enum Backend {
    /// In this process, on files this user owns.
    Local(PathBuf),
    /// Through the router service's sockets.
    Service(PathBuf),
}

impl Backend {
    fn detect() -> Result<Backend> {
        let root = sockets_root();
        if root.join("agent").join("agent.sock").exists()
            || std::env::var_os("OZBOX_TASKS_SOCKETS").is_some()
        {
            return Ok(Backend::Service(root));
        }
        Ok(Backend::Local(dir()?))
    }

    fn is_service(&self) -> bool {
        matches!(self, Backend::Service(_))
    }

    /// Run one operation. `owner` operations need the admin socket (root) when there is a service.
    fn call(&self, op: &str, mut args: Value, owner: bool) -> Result<Value> {
        if let Some(o) = args.as_object_mut() {
            o.insert("op".into(), json!(op));
        }
        match self {
            Backend::Local(d) => {
                let ends = Ends::open(d).map_err(|e| map_err(&e))?;
                // on a laptop the store is the person's own file, and so is any agent's that runs as the person
                dispatch(&ends, Policy::Admin, &args, true).map_err(|e| map_err(&e))
            }
            Backend::Service(root) => {
                let sock = if owner {
                    root.join("admin").join("admin.sock")
                } else {
                    root.join("agent").join("agent.sock")
                };
                service::call(&sock, &args, service::MAX_REPLY).map_err(|e| match e.as_str() {
                    "permission-denied" if owner => cfg("tasks.admin_needed", &[]),
                    "permission-denied" => cfg("tasks.service_denied", &[]),
                    "no-service" => cfg("tasks.service_down", &[]),
                    _ => map_err(&e),
                })
            }
        }
    }
}

/// An operation's refusal, in the person's words.
fn map_err(e: &str) -> Error {
    match e {
        "not-initialised" => cfg("tasks.not_inited", &[]),
        "bad-name" => cfg("tasks.bad_name", &[]),
        "already-initialised" => cfg("tasks.already_inited", &[]),
        "pin-bad" => cfg("tasks.pin_bad", &[]),
        "pin-self" => cfg("tasks.pin_self", &[]),
        "text-needed" => cfg("tasks.text_needed", &[]),
        "unknown-task" => cfg("tasks.unknown", &[("id", "")]),
        "not-allowed-here" => cfg("tasks.not_allowed_here", &[]),
        s if s.starts_with("pin-exists:") => {
            cfg("tasks.pin_exists", &[("name", &s["pin-exists:".len()..])])
        }
        s if s.starts_with("bad-state:") => {
            cfg("tasks.bad_state", &[("state", &s["bad-state:".len()..])])
        }
        s if s.starts_with("refused: ") => {
            cfg("tasks.refused", &[("why", &s["refused: ".len()..])])
        }
        other => Error::Config(ozbox_core::agent_mesh::printable_line(other)),
    }
}

const MAX_REPLY: usize = 8 * 1024 * 1024;
/// How long a transport command may take before it is stopped. A starting value (ADR 0044 open question 7); a test may shorten it.
fn transport_timeout() -> Duration {
    std::env::var("OZBOX_TASKS_TRANSPORT_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map_or(Duration::from_secs(60), |ms| {
            Duration::from_millis(ms.max(1))
        })
}

/// Reaches the peer by running its `exchange` through a command (for example `ssh my-box /usr/local/bin/ozbox`). An argv, never a shell
/// string. It is stopped after [`transport_timeout`], and what it writes is read through a cap, so one hung or hostile far end cannot
/// stop `sync` or fill memory.
struct CommandTransport<'a> {
    runner: &'a dyn CommandRunner,
    via: Vec<String>,
    me: String,
}

impl Transport for CommandTransport<'_> {
    fn exchange(
        &self,
        _peer: &str,
        outbound: &[Sealed],
    ) -> std::result::Result<Vec<Sealed>, String> {
        let (program, rest) = self
            .via
            .split_first()
            .ok_or("no way to reach the peer is set")?;
        let mut args: Vec<String> = rest.to_vec();
        args.extend(["tasks", "exchange", "--peer", &self.me].map(String::from));
        let spec = CommandSpec {
            program: program.clone(),
            args,
            cwd: None,
            env: Default::default(),
            stdin: Some(serde_json::to_vec(outbound).map_err(|e| e.to_string())?),
        };
        let out = self
            .runner
            .run_limited(&spec, transport_timeout(), MAX_REPLY)
            .map_err(|e| e.to_string())?;
        if out.status != Some(0) {
            let why: String = ozbox_core::agent_mesh::printable_line(out.stderr.trim())
                .chars()
                .take(300)
                .collect();
            return Err(format!("the command failed ({:?}): {why}", out.status));
        }
        if out.stdout.len() > MAX_REPLY {
            return Err("the reply is too large".into());
        }
        serde_json::from_str(out.stdout.trim())
            .map_err(|_| "the reply was not a task channel reply".to_string())
    }
}

fn read_stdin_text() -> Result<String> {
    let mut s = String::new();
    std::io::stdin().take(70_000).read_to_string(&mut s)?;
    if s.len() > 65_536 {
        return Err(cfg("tasks.stdin_big", &[]));
    }
    Ok(s)
}

fn text_arg(text: &Option<String>, stdin: bool) -> Result<String> {
    match (text, stdin) {
        (Some(x), _) => Ok(x.clone()),
        (None, true) => read_stdin_text(),
        _ => Err(cfg("tasks.text_needed", &[])),
    }
}

fn print_json(v: &Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

fn row(tk: &Value, mark: &str) -> String {
    t(
        "tasks.inbox_row",
        &[
            ("mark", mark),
            ("id", s(tk, "id")),
            ("state", s(tk, "state")),
            ("from", s(tk, "from")),
            ("to", s(tk, "to")),
            ("title", s(tk, "title")),
        ],
    )
}

/// Print one task as a person reads it: every message says who wrote it and that a peer's words are a claim.
fn print_task(tk: &Value) {
    let reason = tk
        .get("reason")
        .and_then(Value::as_str)
        .map(|r| format!(" ({r})"))
        .unwrap_or_default();
    println!(
        "{}",
        t(
            "tasks.show_head",
            &[
                ("id", s(tk, "id")),
                ("title", s(tk, "title")),
                ("from", s(tk, "from")),
                ("to", s(tk, "to")),
                ("kind", s(tk, "kind")),
                ("state", s(tk, "state")),
                ("reason", &reason)
            ]
        )
    );
    if tk.get("cancel_requested").and_then(Value::as_bool) == Some(true) {
        println!("{}", t("tasks.show_cancel", &[]));
    }
    for m in tk
        .get("messages")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let trust = if m.get("untrusted").and_then(Value::as_bool) == Some(true) {
            "untrusted"
        } else {
            "yours"
        };
        let claimed = m
            .get("claimed_label")
            .and_then(Value::as_str)
            .unwrap_or("fleet");
        for p in m
            .get("parts")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let txt = match p.get("type").and_then(Value::as_str) {
                Some("text") => s(p, "text").to_string(),
                _ => format!("[data: {}]", s(p, "schema")),
            };
            println!(
                "{}",
                t(
                    "tasks.show_msg",
                    &[
                        ("prov", s(m, "provenance")),
                        ("trust", trust),
                        ("claimed", claimed),
                        ("who", s(m, "from")),
                        ("text", &txt)
                    ]
                )
            );
        }
    }
    for a in tk
        .get("artifacts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let h = s(a, "hash");
        println!(
            "{}",
            t(
                "tasks.show_artifact",
                &[("name", s(a, "name")), ("hash", &h[..12.min(h.len())])]
            )
        );
    }
}

fn fingerprints_of(offer: &Offer) -> (String, String) {
    (
        offer.sign_fingerprint.clone(),
        offer.seal_fingerprint.clone(),
    )
}

fn sync_once(
    dir: &std::path::Path,
    peer: &str,
    runner: &dyn CommandRunner,
    json: bool,
) -> Result<()> {
    let ends = Ends::open(dir).map_err(|e| map_err(&e))?;
    let st = ends.state().map_err(|e| map_err(&e))?;
    if !st.core.links.contains_key(peer) {
        return Err(cfg("tasks.unknown_peer", &[("name", peer)]));
    }
    let via = st.via(peer);
    if via.is_empty() {
        return Err(cfg("tasks.no_via", &[("name", peer)]));
    }
    let net = CommandTransport {
        runner,
        via,
        me: st.me().to_string(),
    };
    ends.guard().map_err(|e| map_err(&e))?;
    let r = ends.node().sync(peer, &net).map_err(|e| {
        cfg(
            "tasks.unreachable",
            &[
                ("peer", peer),
                (
                    "why",
                    &ozbox_core::agent_mesh::printable_line(&e.to_string()),
                ),
            ],
        )
    })?;
    if json {
        return print_json(
            &json!({"peer": peer, "sent": r.sent, "applied": r.applied, "buffered": r.buffered, "duplicates": r.duplicates, "refused": r.refused}),
        );
    }
    println!(
        "{}",
        t(
            "tasks.round",
            &[
                ("peer", peer),
                ("sent", &r.sent.to_string()),
                ("applied", &r.applied.to_string()),
                ("dups", &r.duplicates.to_string()),
                ("refused", &r.refused.len().to_string())
            ]
        )
    );
    if !r.refused.is_empty() {
        println!(
            "{}",
            t("tasks.round_refused", &[("codes", &r.refused.join(", "))])
        );
    }
    let halted = ends
        .state()
        .map_err(|e| map_err(&e))?
        .core
        .links
        .get(peer)
        .and_then(|l| l.halted.clone());
    if let Some(h) = halted {
        println!("{}", t("tasks.halted", &[("peer", peer), ("why", &h)]));
    }
    Ok(())
}

/// The one peer when only one is pinned, or the named one.
fn peer_name(peers: &[Value], wanted: &Option<String>) -> Result<String> {
    match wanted {
        Some(n) if peers.iter().any(|p| s(p, "name") == n) => Ok(n.clone()),
        Some(n) => Err(cfg("tasks.unknown_peer", &[("name", n)])),
        None => match peers {
            [] => Err(cfg("tasks.no_peers", &[])),
            [one] => Ok(s(one, "name").to_string()),
            _ => Err(cfg("tasks.which_peer", &[])),
        },
    }
}

pub fn run(cmd: &TasksCommand, f: &Flags) -> Result<()> {
    run_with(cmd, f, &SystemRunner)
}

pub fn run_with(cmd: &TasksCommand, f: &Flags, runner: &dyn CommandRunner) -> Result<()> {
    if let TasksCommand::Serve {
        dir,
        agent_socket,
        relay_socket,
        admin_socket,
    } = cmd
    {
        return service::serve(&service::Paths {
            dir: dir.clone(),
            agent: agent_socket.clone(),
            relay: relay_socket.clone(),
            admin: admin_socket.clone(),
        });
    }
    let be = Backend::detect()?;
    match cmd {
        TasksCommand::Init { name } => {
            if !word_ok(name) {
                return Err(cfg("tasks.bad_name", &[]));
            }
            match &be {
                Backend::Local(d) => {
                    ops::init(d, name).map_err(|e| map_err(&e))?;
                }
                Backend::Service(_) => {
                    be.call("init", json!({"name": name}), true)?;
                }
            }
            println!("{}", t("tasks.inited", &[("name", name)]));
            if !be.is_service()
                && cfg!(target_os = "linux")
                && std::path::Path::new("/usr/local/bin/ozbox").exists()
            {
                // a box without the router service: the keys sit where an agent that runs as this user can read them
                println!("{}", t("tasks.service_gap", &[]));
            }
            Ok(())
        }
        TasksCommand::Identity => print_json(&be.call("identity", json!({}), false)?),
        TasksCommand::Pin {
            file,
            via_arg,
            replace,
        } => {
            let raw = if file.as_os_str() == "-" {
                read_stdin_text()?
            } else {
                std::fs::read_to_string(file)?
            };
            let offer: Offer = serde_json::from_str(&raw).map_err(|_| cfg("tasks.pin_bad", &[]))?;
            let offer = offer.checked().ok_or_else(|| cfg("tasks.pin_bad", &[]))?;
            let (sign, seal) = fingerprints_of(&offer);
            println!(
                "{}",
                t(
                    "tasks.pin_show",
                    &[
                        ("name", &offer.name),
                        ("sign", &sign),
                        ("seal", &seal),
                        ("epoch", &offer.epoch.to_string())
                    ]
                )
            );
            if !via_arg.is_empty() {
                println!("{}", t("tasks.pin_via", &[("via", &via_arg.join(" "))]));
            }
            if !f.yes {
                if !std::io::stdin().is_terminal() {
                    return Err(cfg("tasks.pin_need_yes", &[]));
                }
                print!("{}", t("tasks.pin_confirm", &[]));
                std::io::stdout().flush()?;
                let mut a = String::new();
                std::io::stdin().read_line(&mut a)?;
                if !a.trim().eq_ignore_ascii_case("y") {
                    return Ok(());
                }
            }
            let via = if via_arg.is_empty() {
                Value::Null
            } else {
                json!(via_arg)
            };
            let r = be.call(
                "pin",
                json!({"offer": offer_json(&offer), "via": via, "replace": replace}),
                true,
            )?;
            if r.get("keys_changed").and_then(Value::as_bool) == Some(true) {
                println!("{}", t("tasks.pin_keys_changed", &[("name", &offer.name)]));
            }
            if r.get("via_changed").and_then(Value::as_bool) == Some(true) {
                let v: Vec<String> = r["via"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect();
                println!("{}", t("tasks.pin_via_changed", &[("via", &v.join(" "))]));
            }
            println!("{}", t("tasks.pin_done", &[("name", &offer.name)]));
            Ok(())
        }
        TasksCommand::Send {
            to,
            title,
            text,
            stdin,
            note,
            minutes,
        } => {
            let body = text_arg(text, *stdin)?;
            let r = be.call(
                "send",
                json!({"to": to, "title": title, "text": body, "note": note, "minutes": minutes}),
                false,
            )?;
            if f.json {
                return print_json(&json!({"id": r["id"]}));
            }
            println!("{}", t("tasks.sent", &[("id", s(&r, "id")), ("to", to)]));
            Ok(())
        }
        TasksCommand::PushRef {
            to,
            repo,
            remote,
            r#ref,
            sha,
            env,
        } => {
            let r = be.call(
                "push_ref",
                json!({"to": to, "repo": repo, "remote": remote, "ref": r#ref, "sha": sha, "env": env}),
                false,
            )?;
            println!("{}", t("tasks.sent", &[("id", s(&r, "id")), ("to", to)]));
            Ok(())
        }
        TasksCommand::Inbox { all, for_model } => {
            let v = be.call("inbox", json!({"all": all, "for_model": for_model}), false)?;
            if f.json {
                return print_json(&v);
            }
            let tasks = v.as_array().cloned().unwrap_or_default();
            if tasks.is_empty() {
                println!("{}", t("tasks.inbox_none", &[]));
            }
            for x in &tasks {
                println!("{}", row(x, if x["unread"] == true { "*" } else { " " }));
            }
            Ok(())
        }
        TasksCommand::Status { id, for_model } => match id {
            None => {
                let peers = be.call("peers", json!({}), false)?;
                for p in peers.as_array().into_iter().flatten() {
                    let seen = match p["last_seen_ms"].as_u64() {
                        Some(0) | None => "never".to_string(),
                        Some(ms) => format!("{}s ago", ops::now_ms().saturating_sub(ms) / 1000),
                    };
                    println!(
                        "{}",
                        t(
                            "tasks.peer_row",
                            &[
                                ("name", s(p, "name")),
                                ("epoch", &p["epoch"].to_string()),
                                ("out", &p["outbox"].to_string()),
                                ("fp", s(p, "seal_fingerprint")),
                                ("seen", &seen)
                            ]
                        )
                    );
                    if let Some(h) = p["halted"].as_str() {
                        println!(
                            "{}",
                            t("tasks.halted", &[("peer", s(p, "name")), ("why", h)])
                        );
                    }
                }
                Ok(())
            }
            Some(id) => {
                let tk = be.call("task", json!({"id": id, "for_model": for_model}), false)?;
                if f.json {
                    return print_json(&tk);
                }
                print_task(&tk);
                Ok(())
            }
        },
        TasksCommand::Reply {
            id,
            text,
            stdin,
            state,
            reason,
        } => {
            let body = if text.is_some() || *stdin {
                text_arg(text, *stdin)?
            } else {
                String::new()
            };
            be.call(
                "reply",
                json!({"id": id, "text": body, "state": state, "reason": reason}),
                false,
            )?;
            println!("{}", t("tasks.replied", &[("id", id)]));
            Ok(())
        }
        TasksCommand::Cancel { id } => {
            be.call("cancel", json!({"id": id}), false)?;
            println!("{}", t("tasks.canceled", &[("id", id)]));
            Ok(())
        }
        TasksCommand::Why { id } => {
            let r = be.call("why", json!({"id": id}), false)?;
            for l in r["lines"].as_array().into_iter().flatten() {
                println!("{}", l.as_str().unwrap_or(""));
            }
            Ok(())
        }
        TasksCommand::Sync { peer } => {
            let Backend::Local(d) = &be else {
                return Err(cfg("tasks.box_answers", &[]));
            };
            let peers = be.call("peers", json!({}), false)?;
            let name = peer_name(peers.as_array().map_or(&[][..], Vec::as_slice), peer)?;
            sync_once(d, &name, runner, f.json)
        }
        TasksCommand::Watch {
            peer,
            every,
            rounds,
        } => {
            let Backend::Local(d) = &be else {
                return Err(cfg("tasks.box_answers", &[]));
            };
            if *every == 0 {
                return Err(cfg("tasks.every_zero", &[]));
            }
            let peers = be.call("peers", json!({}), false)?;
            let name = peer_name(peers.as_array().map_or(&[][..], Vec::as_slice), peer)?;
            println!(
                "{}",
                t(
                    "tasks.watching",
                    &[("peer", &name), ("secs", &every.to_string())]
                )
            );
            // what has been told: bounded, so a long watch cannot grow without limit (the oldest entries are forgotten)
            let mut told: std::collections::VecDeque<String> = std::collections::VecDeque::new();
            let mut n = 0u64;
            loop {
                if let Err(e) = sync_once(d, &name, runner, false) {
                    eprintln!("{e}");
                }
                let v = be.call("inbox", json!({"all": false, "for_model": false}), false)?;
                for x in v
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|x| x["unread"] == true)
                {
                    let key = format!("{}:{}", s(x, "key"), x["updated_ms"]);
                    if !told.contains(&key) {
                        told.push_back(key);
                        if told.len() > 1000 {
                            told.pop_front();
                        }
                        println!(
                            "{}",
                            t(
                                "tasks.new_line",
                                &[
                                    ("id", s(x, "id")),
                                    ("state", s(x, "state")),
                                    ("from", s(x, "from")),
                                    ("title", s(x, "title"))
                                ]
                            )
                        );
                    }
                }
                n += 1;
                if rounds.is_some_and(|r| n >= r) {
                    return Ok(());
                }
                std::thread::sleep(Duration::from_secs(*every));
            }
        }
        TasksCommand::Exchange { peer } => {
            // The answering side of a sync. Over the router service this process holds no key: it hands the envelope bytes it was given
            // to the relay socket and prints what comes back, and it can do nothing else with them. Without a service it runs as before.
            let inbound = read_big_stdin()?;
            let out = match &be {
                Backend::Service(root) => {
                    let sock = root.join("relay").join("relay.sock");
                    let r = service::call(
                        &sock,
                        &json!({"op": "exchange", "peer": peer, "inbound": inbound}),
                        service::MAX_REPLY,
                    )
                    .map_err(|e| map_err(&e))?;
                    r["outbound"].as_str().unwrap_or("[]").to_string()
                }
                Backend::Local(d) => {
                    let ends = Ends::open(d).map_err(|e| map_err(&e))?;
                    let r = dispatch(
                        &ends,
                        Policy::Relay,
                        &json!({"op": "exchange", "peer": peer, "inbound": inbound}),
                        true,
                    )
                    .map_err(|e| map_err(&e))?;
                    r["outbound"].as_str().unwrap_or("[]").to_string()
                }
            };
            println!("{out}");
            Ok(())
        }
        TasksCommand::Serve { .. } => Ok(()),
        TasksCommand::Restored => {
            let r = be.call("restored", json!({}), true)?;
            println!(
                "{}",
                t("tasks.restored", &[("epoch", &r["epoch"].to_string())])
            );
            Ok(())
        }
    }
}

fn offer_json(o: &Offer) -> Value {
    json!({
        "name": o.name,
        "sign_public": o.sign_public,
        "seal_public": o.seal_public,
        "epoch": o.epoch,
    })
}

fn read_big_stdin() -> Result<String> {
    let mut s = String::new();
    std::io::stdin()
        .take(8 * 1024 * 1024 + 1)
        .read_to_string(&mut s)?;
    Ok(s)
}

#[allow(dead_code)]
fn _hex_helpers_are_used(a: &str) -> Option<(String, Vec<u8>)> {
    Some((normalize_hex(a)?, unhex(a)?))
}
