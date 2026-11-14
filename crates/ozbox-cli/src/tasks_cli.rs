//! `ozbox tasks ...`: the typed task channel between two endpoints (ADR 0044, Preview). The same commands run on a laptop and
//! on a box; only the names and the way they reach each other differ. Everything that is not a printout is in
//! `ozbox_core::agent_mesh`; this file holds the key files, the sealing with `ozbox-seal`, the command transport and the output.

use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;

use ozbox_core::agent_mesh::crypto::{self, RingSigner, RingVerifier};
use ozbox_core::agent_mesh::model::{Act, Label, Part, State as TState, Task, TaskKind};
use ozbox_core::agent_mesh::node::Node;
use ozbox_core::agent_mesh::printable;
use ozbox_core::agent_mesh::state::{NewTask, Peer, State};
use ozbox_core::agent_mesh::store::Store;
use ozbox_core::agent_mesh::wire::{word_ok, Sealed, Sealer, Transport};
use ozbox_core::agent_mesh::Screen;
use ozbox_core::audit::AuditLog;
use ozbox_core::{CommandRunner, CommandSpec, Error, Result, SystemRunner};
use ozbox_seal::ServiceKey;
use serde::{Deserialize, Serialize};

use crate::cli::TasksCommand;
use crate::messages::t;
use crate::runs_cli::Flags;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn cfg(key: &str, args: &[(&str, &str)]) -> Error {
    Error::Config(t(key, args))
}

/// Where this endpoint keeps its channel: `OZBOX_TASKS_DIR`, else beside the settings file.
pub fn dir() -> Result<PathBuf> {
    if let Some(d) = std::env::var_os("OZBOX_TASKS_DIR") {
        return Ok(PathBuf::from(d));
    }
    crate::settings::Settings::path()
        .map(|p| p.with_file_name("tasks-channel"))
        .ok_or_else(|| cfg("tasks.no_dir", &[]))
}

/// The key file. Mode 0600, in a directory of mode 0700. A process of the same user can read it: on a box, run the channel as
/// a service user of its own (ADR 0044 open question 6), so that an agent's user cannot.
#[derive(Serialize, Deserialize)]
struct IdentityFile {
    name: String,
    sign_pkcs8: String,
    seal_secret: String,
}

/// What is shared with the other side. Public halves only.
#[derive(Serialize, Deserialize)]
struct Offer {
    name: String,
    sign_public: String,
    seal_public: String,
    epoch: u64,
}

struct SealCrypto {
    key: ServiceKey,
}

fn info_for(pk: &[u8; 32]) -> Vec<u8> {
    ozbox_seal::info("mesh-body", &ozbox_seal::fingerprint(pk))
}

impl Sealer for SealCrypto {
    fn seal(
        &self,
        receiver_hex: &str,
        aad: &[u8],
        plain: &[u8],
    ) -> std::result::Result<Vec<u8>, String> {
        let pk = ozbox_seal::public_from_hex(receiver_hex)
            .map_err(|_| "the peer's sealing key is not valid".to_string())?;
        let (enc, ct) = ozbox_seal::seal(&pk, &info_for(&pk), aad, plain)
            .map_err(|_| "sealing failed".to_string())?;
        let mut out = enc;
        out.extend(ct);
        Ok(out)
    }

    fn open(&self, aad: &[u8], sealed: &[u8]) -> std::result::Result<Vec<u8>, String> {
        if sealed.len() < 32 {
            return Err("short".into());
        }
        let (enc, ct) = sealed.split_at(32);
        self.key
            .open(&info_for(&self.key.public()), aad, enc, ct)
            .map(|z| z.to_vec())
            .map_err(|_| "cannot open".to_string())
    }
}

/// Finds key-shaped text with the same screen agent memory uses.
struct MemScreen;

impl Screen for MemScreen {
    fn find(&self, text: &str) -> Option<&'static str> {
        ozbox_memory::secret_shape::find_secret(text)
    }
}

struct Ends {
    store: Store,
    signer: RingSigner,
    sealer: SealCrypto,
    audit: AuditLog,
    clock: Box<dyn Fn() -> u64>,
}

impl Ends {
    fn open() -> Result<Ends> {
        let d = dir()?;
        let store = Store::new(&d);
        if !store.exists() {
            return Err(cfg("tasks.not_inited", &[]));
        }
        let id: IdentityFile = serde_json::from_slice(&std::fs::read(d.join("identity.json"))?)?;
        let signer = RingSigner::from_pkcs8(&crypto::from_hex(&id.sign_pkcs8).unwrap_or_default())
            .map_err(Error::Config)?;
        let secret = crypto::from_hex(&id.seal_secret).unwrap_or_default();
        let key = ServiceKey::from_secret_bytes(&secret)
            .map_err(|_| Error::Config("the sealing key is not valid".into()))?;
        let audit = AuditLog::beside(&d.join("mesh.json"));
        Ok(Ends {
            store,
            signer,
            sealer: SealCrypto { key },
            audit,
            clock: Box::new(now_ms),
        })
    }

    fn node(&self) -> Node<'_> {
        Node {
            store: &self.store,
            signer: &self.signer,
            verifier: &RingVerifier,
            sealer: &self.sealer,
            screen: &MemScreen,
            audit: &self.audit,
            clock: &*self.clock,
        }
    }

    fn state(&self) -> Result<State> {
        self.store.read().map_err(|e| Error::Config(e.to_string()))
    }
}

/// Reaches the peer by running its `exchange` through a command (for example `ssh my-box ozbox`). An argv, never a shell string.
struct CommandTransport<'a> {
    runner: &'a dyn CommandRunner,
    via: Vec<String>,
    me: String,
}

const MAX_REPLY: usize = 8 * 1024 * 1024;

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
        let out = self.runner.run_ok(&spec).map_err(|e| e.to_string())?;
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

fn text_arg(text: &Option<String>, stdin: bool) -> Result<(String, bool)> {
    match (text, stdin) {
        (Some(x), _) => Ok((x.clone(), std::io::stdin().is_terminal())),
        (None, true) => Ok((read_stdin_text()?, false)),
        _ => Err(cfg("tasks.text_needed", &[])),
    }
}

fn label(from_terminal: bool) -> Label {
    if from_terminal {
        Label::Person
    } else {
        Label::Fleet
    }
}

fn peer_name(st: &State, wanted: &Option<String>) -> Result<String> {
    match wanted {
        Some(n) if st.peers.contains_key(n) => Ok(n.clone()),
        Some(n) => Err(cfg("tasks.unknown_peer", &[("name", n)])),
        None => {
            let mut it = st.peers.keys();
            match (it.next(), it.next()) {
                (Some(n), None) => Ok(n.clone()),
                (None, _) => Err(cfg("tasks.no_peers", &[])),
                _ => Err(cfg("tasks.which_peer", &[])),
            }
        }
    }
}

fn print_json(v: &serde_json::Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

fn row(tk: &Task, mark: &str) -> String {
    t(
        "tasks.inbox_row",
        &[
            ("mark", mark),
            ("id", &tk.id),
            ("state", tk.state.name()),
            ("from", &printable(&tk.from)),
            ("to", &printable(&tk.to)),
            ("title", &printable(&tk.title)),
        ],
    )
}

fn needs_you(me: &str, tk: &Task) -> bool {
    tk.unread || (tk.to == me && !tk.state.terminal())
}

fn refused(e: impl std::fmt::Display) -> Error {
    cfg("tasks.refused", &[("why", &e.to_string())])
}

fn sync_once(ends: &Ends, peer: &str, runner: &dyn CommandRunner, json: bool) -> Result<()> {
    let st = ends.state()?;
    let p = st
        .peers
        .get(peer)
        .ok_or_else(|| cfg("tasks.unknown_peer", &[("name", peer)]))?;
    if p.via.is_empty() {
        return Err(cfg("tasks.no_via", &[("name", peer)]));
    }
    let net = CommandTransport {
        runner,
        via: p.via.clone(),
        me: st.me.clone(),
    };
    let r = ends.node().sync(peer, &net).map_err(|e| {
        cfg(
            "tasks.unreachable",
            &[("peer", peer), ("why", &printable(&e.to_string()))],
        )
    })?;
    if json {
        return print_json(
            &serde_json::json!({"peer": peer, "sent": r.sent, "applied": r.applied, "duplicates": r.duplicates, "refused": r.refused}),
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
    Ok(())
}

pub fn run(cmd: &TasksCommand, f: &Flags) -> Result<()> {
    run_with(cmd, f, &SystemRunner)
}

pub fn run_with(cmd: &TasksCommand, f: &Flags, runner: &dyn CommandRunner) -> Result<()> {
    match cmd {
        TasksCommand::Init { name } => {
            if !word_ok(name) {
                return Err(cfg("tasks.bad_name", &[]));
            }
            let d = dir()?;
            let store = Store::new(&d);
            if store.exists() {
                return Err(cfg("tasks.already_inited", &[]));
            }
            let (pkcs8, sign_public) = crypto::generate().map_err(Error::Config)?;
            let key =
                ServiceKey::generate().map_err(|_| Error::Config("no random numbers".into()))?;
            let file = IdentityFile {
                name: name.clone(),
                sign_pkcs8: crypto::to_hex(&pkcs8),
                seal_secret: crypto::to_hex(&key.secret_bytes()[..]),
            };
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(&d)?;
            }
            #[cfg(not(unix))]
            std::fs::create_dir_all(&d)?;
            write_private(&d.join("identity.json"), &serde_json::to_vec(&file)?)?;
            store
                .create(&State::new(
                    name,
                    &sign_public,
                    &ozbox_seal::public_to_hex(&key.public()),
                    now_ms(),
                ))
                .map_err(|e| Error::Config(e.to_string()))?;
            println!("{}", t("tasks.inited", &[("name", name)]));
            Ok(())
        }
        TasksCommand::Identity => {
            let st = Ends::open()?.state()?;
            print_json(&serde_json::to_value(Offer {
                name: st.me.clone(),
                sign_public: st.sign_public.clone(),
                seal_public: st.seal_public.clone(),
                epoch: st.epoch,
            })?)
        }
        TasksCommand::Pin { file, via, replace } => {
            let ends = Ends::open()?;
            let raw = if file.as_os_str() == "-" {
                read_stdin_text()?
            } else {
                std::fs::read_to_string(file)?
            };
            let offer: Offer = serde_json::from_str(&raw).map_err(|_| cfg("tasks.pin_bad", &[]))?;
            let st = ends.state()?;
            if !word_ok(&offer.name)
                || crypto::from_hex(&offer.sign_public).is_none_or(|b| b.len() != 32)
                || ozbox_seal::public_from_hex(&offer.seal_public).is_err()
                || offer.epoch == 0
            {
                return Err(cfg("tasks.pin_bad", &[]));
            }
            if offer.name == st.me || offer.sign_public == st.sign_public {
                return Err(cfg("tasks.pin_self", &[]));
            }
            if let Some(old) = st.peers.get(&offer.name) {
                let same = old.sign_public == offer.sign_public
                    && old.seal_public == offer.seal_public
                    && old.epoch == offer.epoch;
                if !same && !replace {
                    return Err(cfg("tasks.pin_exists", &[("name", &offer.name)]));
                }
            }
            println!(
                "{}",
                t(
                    "tasks.pin_show",
                    &[
                        ("name", &offer.name),
                        ("sign", &crypto::fingerprint(&offer.sign_public)),
                        ("seal", &crypto::fingerprint(&offer.seal_public)),
                        ("epoch", &offer.epoch.to_string())
                    ]
                )
            );
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
            let via: Vec<String> = via
                .as_deref()
                .map(|v| v.split_whitespace().map(String::from).collect())
                .unwrap_or_default();
            let name = offer.name.clone();
            ends.store
                .update(|s| {
                    let keep = s.peers.get(&name).map(|p| (p.out_seq, p.outbox.clone()));
                    let mut p = Peer::new(
                        &name,
                        &offer.sign_public,
                        &offer.seal_public,
                        offer.epoch,
                        via.clone(),
                    );
                    if let Some(old) = s.peers.get(&name) {
                        if old.sign_public == offer.sign_public
                            && old.seal_public == offer.seal_public
                        {
                            // the same keys at a new epoch (or a new via): what was in flight stays, the window starts over
                            if via.is_empty() {
                                p.via = old.via.clone();
                            }
                            if let Some((seq, ob)) = keep {
                                p.out_seq = seq;
                                p.outbox = ob;
                            }
                        }
                    }
                    s.peers.insert(name.clone(), p);
                    s.note(
                        now_ms(),
                        "mesh.peer.pinned",
                        None,
                        format!("peer={name} epoch={}", offer.epoch),
                    );
                })
                .map_err(|e| Error::Config(e.to_string()))?;
            ends.node()
                .drain_audit()
                .map_err(|e| Error::Config(e.to_string()))?;
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
            let ends = Ends::open()?;
            let (body, term) = text_arg(text, *stdin)?;
            let now = now_ms();
            let id = ends
                .node()
                .submit(NewTask {
                    to: to.clone(),
                    kind: if *note {
                        TaskKind::Note
                    } else {
                        TaskKind::Question
                    },
                    title: title.clone(),
                    parts: vec![Part::Text { text: body }],
                    label: label(term),
                    act: None,
                    parent: None,
                    deadline_ms: minutes.map(|m| now + m.saturating_mul(60_000)),
                })
                .map_err(refused)?;
            if f.json {
                return print_json(&serde_json::json!({"id": id}));
            }
            println!("{}", t("tasks.sent", &[("id", &id), ("to", to)]));
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
            let ends = Ends::open()?;
            let id = ends
                .node()
                .submit(NewTask {
                    to: to.clone(),
                    kind: TaskKind::LaptopAct,
                    title: format!("push {}", printable(r#ref)),
                    parts: vec![Part::Text {
                        text: "Please push this commit.".into(),
                    }],
                    label: Label::Fleet,
                    act: Some(Act::PushRef {
                        repo: repo.clone(),
                        remote: remote.clone(),
                        r#ref: r#ref.clone(),
                        sha: sha.clone(),
                        env: env.clone(),
                    }),
                    parent: None,
                    deadline_ms: None,
                })
                .map_err(refused)?;
            println!("{}", t("tasks.sent", &[("id", &id), ("to", to)]));
            Ok(())
        }
        TasksCommand::Inbox { all } => {
            let st = Ends::open()?.state()?;
            let mut tasks: Vec<&Task> = st
                .tasks
                .values()
                .filter(|x| *all || needs_you(&st.me, x))
                .collect();
            tasks.sort_by_key(|x| x.created_ms);
            if f.json {
                return print_json(&serde_json::to_value(&tasks)?);
            }
            if tasks.is_empty() {
                println!("{}", t("tasks.inbox_none", &[]));
            }
            for x in tasks {
                println!("{}", row(x, if x.unread { "*" } else { " " }));
            }
            Ok(())
        }
        TasksCommand::Status { id } => {
            let ends = Ends::open()?;
            let st = ends.state()?;
            match id {
                None => {
                    for p in st.peers.values() {
                        let seen = if p.last_seen_ms == 0 {
                            "never".to_string()
                        } else {
                            format!("{}s ago", now_ms().saturating_sub(p.last_seen_ms) / 1000)
                        };
                        println!(
                            "{}",
                            t(
                                "tasks.peer_row",
                                &[
                                    ("name", &p.name),
                                    ("epoch", &p.epoch.to_string()),
                                    ("out", &p.outbox.len().to_string()),
                                    ("fp", &p.seal_fingerprint()),
                                    ("seen", &seen)
                                ]
                            )
                        );
                    }
                    Ok(())
                }
                Some(id) => {
                    let tk = st
                        .tasks
                        .get(id)
                        .ok_or_else(|| cfg("tasks.unknown", &[("id", id)]))?;
                    if f.json {
                        return print_json(&serde_json::to_value(tk)?);
                    }
                    let reason = tk
                        .reason
                        .as_deref()
                        .map(|r| format!(" ({})", printable(r)))
                        .unwrap_or_default();
                    println!(
                        "{}",
                        t(
                            "tasks.show_head",
                            &[
                                ("id", &tk.id),
                                ("title", &printable(&tk.title)),
                                ("from", &tk.from),
                                ("to", &tk.to),
                                ("kind", tk.kind.name()),
                                ("state", tk.state.name()),
                                ("reason", &reason)
                            ]
                        )
                    );
                    for m in &tk.messages {
                        for p in &m.parts {
                            let txt = match p {
                                Part::Text { text } => printable(text),
                                Part::Data { schema, .. } => {
                                    format!("[data: {}]", printable(schema))
                                }
                            };
                            let lab = serde_json::to_value(m.label)?
                                .as_str()
                                .unwrap_or("untrusted")
                                .to_string();
                            println!(
                                "{}",
                                t(
                                    "tasks.show_msg",
                                    &[
                                        ("label", &lab),
                                        ("who", &printable(&m.from)),
                                        ("text", &txt)
                                    ]
                                )
                            );
                        }
                    }
                    for a in &tk.artifacts {
                        println!(
                            "{}",
                            t(
                                "tasks.show_artifact",
                                &[
                                    ("name", &printable(&a.name)),
                                    ("hash", &a.hash[..12.min(a.hash.len())])
                                ]
                            )
                        );
                    }
                    let _ = ends.store.update(|s| s.mark_read(id));
                    Ok(())
                }
            }
        }
        TasksCommand::Reply {
            id,
            text,
            stdin,
            state,
            reason,
        } => {
            let ends = Ends::open()?;
            let (body, term) = if text.is_some() || *stdin {
                text_arg(text, *stdin)?
            } else {
                (String::new(), false)
            };
            let to_state = match state.as_deref() {
                None => None,
                Some(s) => match TState::parse(s) {
                    Some(x)
                        if matches!(
                            x,
                            TState::Working
                                | TState::InputRequired
                                | TState::Completed
                                | TState::Failed
                        ) =>
                    {
                        Some((x, reason.clone()))
                    }
                    _ => return Err(cfg("tasks.bad_state", &[("state", s)])),
                },
            };
            if body.is_empty() && to_state.is_none() {
                return Err(cfg("tasks.text_needed", &[]));
            }
            let parts = if body.is_empty() {
                Vec::new()
            } else {
                vec![Part::Text { text: body }]
            };
            ends.node()
                .reply(id, parts, label(term), to_state)
                .map_err(refused)?;
            println!("{}", t("tasks.replied", &[("id", id)]));
            Ok(())
        }
        TasksCommand::Cancel { id } => {
            Ends::open()?.node().cancel(id).map_err(refused)?;
            println!("{}", t("tasks.canceled", &[("id", id)]));
            Ok(())
        }
        TasksCommand::Why { id } => {
            for l in Ends::open()?.state()?.why(id, now_ms()) {
                println!("{}", printable(&l));
            }
            Ok(())
        }
        TasksCommand::Sync { peer } => {
            let ends = Ends::open()?;
            let name = peer_name(&ends.state()?, peer)?;
            sync_once(&ends, &name, runner, f.json)
        }
        TasksCommand::Watch {
            peer,
            every,
            rounds,
        } => {
            let ends = Ends::open()?;
            let name = peer_name(&ends.state()?, peer)?;
            println!(
                "{}",
                t(
                    "tasks.watching",
                    &[("peer", &name), ("secs", &every.to_string())]
                )
            );
            let mut told: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
            let mut n = 0u64;
            loop {
                if let Err(e) = sync_once(&ends, &name, runner, false) {
                    eprintln!("{e}");
                }
                let st = ends.state()?;
                for x in st.tasks.values().filter(|x| x.unread) {
                    if told.insert(format!("{}:{}", x.id, x.updated_ms)) {
                        println!(
                            "{}",
                            t(
                                "tasks.new_line",
                                &[
                                    ("id", &x.id),
                                    ("state", x.state.name()),
                                    ("from", &printable(&x.from)),
                                    ("title", &printable(&x.title))
                                ]
                            )
                        );
                    }
                }
                n += 1;
                if rounds.is_some_and(|r| n >= r) {
                    return Ok(());
                }
                std::thread::sleep(std::time::Duration::from_secs(*every));
            }
        }
        TasksCommand::Exchange { peer } => {
            let ends = Ends::open()?;
            let inbound: Vec<Sealed> = serde_json::from_str(&read_big_stdin()?)
                .map_err(|_| refused("not a task channel request"))?;
            let (_, out) = ends
                .node()
                .serve(peer, &inbound)
                .map_err(|e| Error::Config(printable(&e.to_string())))?;
            println!("{}", serde_json::to_string(&out)?);
            Ok(())
        }
        TasksCommand::Restored => {
            let ends = Ends::open()?;
            ends.store
                .update(|s| s.restored(now_ms()))
                .map_err(|e| Error::Config(e.to_string()))?;
            ends.node()
                .drain_audit()
                .map_err(|e| Error::Config(e.to_string()))?;
            println!(
                "{}",
                t(
                    "tasks.restored",
                    &[("epoch", &ends.state()?.epoch.to_string())]
                )
            );
            Ok(())
        }
    }
}

fn read_big_stdin() -> Result<String> {
    let mut s = String::new();
    std::io::stdin()
        .take(8 * 1024 * 1024)
        .read_to_string(&mut s)?;
    Ok(s)
}

fn write_private(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)?.write_all(bytes)?;
    Ok(())
}
