//! The command line of workload secrets: `ozbox secrets import`, `ozbox env run`, `ozbox env policy`, and the box ends they
//! talk to (`secrets receive`, `secrets run-as`). Values are read where they are, travel on standard input or a socket,
//! and are printed nowhere.

use std::io::BufRead;
use std::path::Path;

use ozbox_core::CommandRunner;
use serde_json::{json, Value};

use crate::cli::{EnvCommand, PolicyCommand};
use crate::import_report::{Outcome, Report};
use crate::messages::t;
use crate::run::CliError;
use crate::secrets_file::open_from_env;
use crate::workload::{invalid_name_reason, parse_env_report, plan, Row, Status};
use crate::workload_policy::Policy;

fn fail(e: crate::secrets::SecretError) -> CliError {
    CliError::Msg(e.0)
}

/// The box user's socket for the commit barrier and guard override (`scan`, `override`): it takes no keys in.
pub const IMPORT_SOCKET: &str = "/run/ozbox-secrets/import/import.sock";
/// The largest request sent in one go. The box reads a sealed line of at most 1 MiB and 4 KiB, and sealing turns the request
/// into base64 (a third larger) plus a small envelope, so the plain request must stay under about three quarters of that.
const MAX_RECEIVE_BYTES: usize = 700 * 1024;

pub struct ImportArgs<'a> {
    pub file: &'a Path,
    pub project: &'a str,
    pub env: &'a str,
    pub allow_live: &'a [String],
    /// `--allow-live-all`: every production-looking key in the file, behind the same typed confirmation. Never combined with
    /// `allow_live` (the command line refuses it).
    pub allow_live_all: bool,
    /// Names the person marked PUBLIC (`--public NAME`).
    pub public: &'a [String],
    pub on_box: Option<&'a str>,
    /// An approval code from the dashboard, for a box whose dashboard has a second factor.
    pub approval: Option<&'a str>,
}

/// Making a production-looking key available to a box needs a person typing a word that cannot be pasted in by a script
/// that has no terminal. The dashboard's equivalent is a fresh passkey.
/// `rerun` is the exact command a person runs in a terminal; the refusal from a script says so.
pub fn typed_confirmation(
    input: &mut dyn BufRead,
    tty: bool,
    word: &str,
    rerun: &str,
) -> Result<(), CliError> {
    if !tty {
        return Err(CliError::Msg(t(
            "secrets.confirm_need_terminal",
            &[("command", rerun)],
        )));
    }
    eprint!("{}", t("secrets.confirm_live", &[("word", word)]));
    let mut line = String::new();
    let _ = input.read_line(&mut line);
    if line.trim() == word {
        Ok(())
    } else {
        Err(CliError::Msg(t("secrets.confirm_refused", &[])))
    }
}

/// Send one request to the box's secrets service: sealed to its pinned key and sent as the ingress account (see
/// `ingress_client`). The request is on standard input and is never readable by a process of the box user; the only words
/// on the command line are the alias.
pub fn ssh_receive(
    runner: &dyn CommandRunner,
    box_name: &str,
    req: &Value,
) -> Result<Value, CliError> {
    // refused here, before anything is sent: an op the box's sealed route does not take, or a request whose sealed form
    // (base64, plus the envelope) would not fit the line the box reads
    if !crate::secrets_ingress::SEALED_OPS.contains(&req["op"].as_str().unwrap_or("")) {
        return Err(CliError::Msg(t("secrets.receive_bad", &[])));
    }
    if req.to_string().len() > MAX_RECEIVE_BYTES {
        return Err(CliError::Msg(t("secrets.import_too_big", &[])));
    }
    crate::ingress_client::call(runner, box_name, req)
}

/// A row that is skipped (never sent, never stored) with the words that say why. Names and reasons only, never a value.
fn skippable(r: &Row) -> Option<String> {
    match &r.status {
        Status::Invalid => Some(format!(
            "not a valid variable name: {}",
            invalid_name_reason(&r.name)
        )),
        Status::Blank => Some("skipped: the value is blank".into()),
        Status::Unstorable(why) => Some(format!("cannot be stored: {why}")),
        _ => None,
    }
}

/// A word safe to paste into a shell as it stands: quoted only when it has to be.
fn shell_word(w: &str) -> String {
    let plain = !w.is_empty()
        && w.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-./:@%+=,".contains(&b));
    if plain {
        w.to_string()
    } else {
        format!("'{}'", w.replace('\'', "'\\''"))
    }
}

/// The command a person runs in a terminal to do this same import with the confirmation. Names and paths only.
fn rerun_command(a: &ImportArgs<'_>, allow: &[String]) -> String {
    let mut c = vec![
        "ozbox".to_string(),
        "secrets".into(),
        "import".into(),
        shell_word(&a.file.to_string_lossy()),
        "--project".into(),
        shell_word(a.project),
        "--env".into(),
        shell_word(a.env),
    ];
    if let Some(b) = a.on_box {
        c.extend(["--box".to_string(), shell_word(b)]);
    }
    if a.allow_live_all {
        c.push("--allow-live-all".into());
    } else {
        for n in allow {
            c.extend(["--allow-live".to_string(), shell_word(n)]);
        }
    }
    for n in a.public {
        c.extend(["--public".to_string(), shell_word(n)]);
    }
    c.push("--yes".into());
    c.join(" ")
}

/// `ozbox secrets import`: preview, then (with --yes) store here, or send to the box with --box. Values are never printed.
pub fn import(
    a: &ImportArgs<'_>,
    runner: &dyn CommandRunner,
    input: &mut dyn BufRead,
    tty: bool,
    json: bool,
    yes: bool,
    out: &mut dyn std::io::Write,
) -> Result<(), CliError> {
    let text = zeroize::Zeroizing::new(
        std::fs::read_to_string(a.file)
            .map_err(|_| CliError::Msg(t("secrets.import_unreadable", &[])))?,
    );
    // A production file is not imported under another environment's name: the flag the box keeps is a guess made from the names and
    // values, and a file that says production in its name is the clearest evidence there is (G5 second review, N-M4).
    let fname = a
        .file
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let says_prod = ["prod", "live"].iter().any(|w| fname.contains(w));
    if says_prod && !matches!(a.env, "production" | "prod" | "live") {
        return Err(CliError::Msg(format!(
            "{} says production in its name but --env is {}: a production key is not stored under another environment's name. Import it with --env production (it is held back unless you name each key and confirm), or rename the file if it is not production",
            fname, a.env
        )));
    }
    let parsed = parse_env_report(&text);
    if parsed.entries() == 0 {
        return Err(CliError::Msg(t("secrets.import_empty", &[])));
    }
    let (lines, duplicates, rejected) = (parsed.lines, parsed.duplicates, parsed.rejected);
    let rows = plan(&lines, a.project, a.env);
    // The names allowed to be stored although they look like production. `--allow-live-all` allows exactly the names this file's
    // production-looking rows carry, which the person sees listed before typing the confirmation. A value the store already
    // holds as production under another name is judged by the store and still held back, and the report says so.
    let allow: Vec<String> = if a.allow_live_all {
        rows.iter()
            .filter(|r| matches!(r.status, Status::Live(_)))
            .map(|r| r.name.clone())
            .collect()
    } else {
        a.allow_live.to_vec()
    };
    let allow_live = &allow[..];
    // A public mark is the person's explicit word, and is refused as a whole before anything is sent or stored, so a mark that
    // cannot be honoured never leaves the value stored as a secret the person believes is public (ADR 0029 Amendment 12).
    for n in a.public {
        if !lines.iter().any(|l| &l.name == n) {
            return Err(CliError::Msg(format!(
                "{n} is marked public but is not in the file"
            )));
        }
    }
    for (l, r) in lines.iter().zip(&rows) {
        if a.public.iter().any(|p| p == &l.name) {
            if let Some(why) = crate::workload_policy::public_mark_refusal(
                &l.name,
                &l.value,
                matches!(r.status, Status::Live(_)),
            ) {
                return Err(CliError::Msg(format!(
                    "{} cannot be marked public: {why}. Nothing was imported",
                    l.name
                )));
            }
        }
    }
    let held = |name: &str, s: &Status| {
        matches!(s, Status::Live(_)) && !allow_live.iter().any(|x| x == name)
    };
    let mut stored: Option<Vec<String>> = None;
    let mut held_back: Option<usize> = None;
    let mut needs_newer: Vec<String> = Vec::new();
    let mut unchanged: Vec<String> = Vec::new();
    // names the box or the store itself held back (it knows a value as production that the file does not show)
    let mut held_by_service: Vec<String> = Vec::new();
    if yes {
        if a.allow_live_all || !a.allow_live.is_empty() {
            // the person sees exactly which production-looking keys they are agreeing to, before being asked to type anything
            let named: Vec<&Row> = rows
                .iter()
                .filter(|r| matches!(r.status, Status::Live(_)) && allow_live.contains(&r.name))
                .collect();
            let mut listing = t(
                "secrets.confirm_list",
                &[
                    ("count", &named.len().to_string()),
                    ("project", a.project),
                    ("env", a.env),
                ],
            );
            for r in &named {
                listing.push_str(&format!("\n  {}  {}", r.name, r.fingerprint));
            }
            if json {
                eprintln!("{listing}");
            } else {
                let _ = writeln!(out, "{listing}");
            }
            typed_confirmation(input, tty, a.project, &rerun_command(a, a.allow_live))?;
        }
        match a.on_box {
            Some(b) => {
                // what is not sent cannot be stored: a production-looking key goes only if it was named
                let going: Vec<(&crate::workload::EnvLine, &crate::workload::Row)> = lines
                    .iter()
                    .zip(&rows)
                    .filter(|(_, r)| !held(&r.name, &r.status) && skippable(r).is_none())
                    .collect();
                // A value the plain rule does not hold goes as base64, and only to a box that says it can read that: a
                // box from before encoded values would fail on the missing `value` (storing nothing wrongly), but it is
                // asked first so the person is told which keys wait for an upgrade. One more connection, only when needed.
                // A box that does not answer `public_values` would drop the mark and store the value unmarked: asked first, and the
                // person is told to upgrade instead.
                if !a.public.is_empty() {
                    let ok = ssh_receive(runner, b, &json!({"op": "capabilities"}))
                        .map(|v| v["result"]["public_values"] == json!(true))
                        .unwrap_or(false);
                    if !ok {
                        return Err(CliError::Msg(
                            "this box cannot mark a value public yet: upgrade it (`ozbox upgrade`) and run the import again. Nothing was imported".to_string(),
                        ));
                    }
                }
                let can_encode = !going.iter().any(|(_, r)| r.encoded)
                    || ssh_receive(runner, b, &json!({"op": "capabilities"}))
                        .map(|v| v["result"]["encoded_values"] == json!(true))
                        .unwrap_or(false);
                let send: Vec<Value> = going
                    .iter()
                    .filter_map(|(l, r)| match (r.encoded, can_encode) {
                        (false, _) => {
                            let mut line = json!({"name": l.name, "value": l.value.as_str()});
                            if a.public.contains(&l.name) {
                                line["public"] = json!(true);
                            }
                            Some(line)
                        }
                        (true, true) => {
                            let mut line = json!({"name": l.name,
                                "value_b64": crate::serve::auth::b64::encode_std(l.value.as_bytes())});
                            if a.public.contains(&l.name) {
                                line["public"] = json!(true);
                            }
                            Some(line)
                        }
                        (true, false) => {
                            needs_newer.push(r.name.clone());
                            None
                        }
                    })
                    .collect();
                if send.is_empty() {
                    return Err(CliError::Msg(if needs_newer.is_empty() {
                        t("secrets.import_nothing", &[])
                    } else {
                        t(
                            "secrets.import_needs_newer",
                            &[("names", &needs_newer.join(", "))],
                        )
                    }));
                }
                let req = json!({"op": "import", "project": a.project, "env": a.env,
                    "allowed": allow_live, "text": std::env::var("USER").unwrap_or_default(),
                    "approval": a.approval.unwrap_or(""), "lines": send});
                let v = ssh_receive(runner, b, &req)?;
                let names = |k: &str| -> Vec<String> {
                    v[k].as_array()
                        .map(|x| {
                            x.iter()
                                .filter_map(|n| n.as_str().map(str::to_string))
                                .collect()
                        })
                        .unwrap_or_default()
                };
                stored = Some(names("names"));
                held_by_service = names("held");
                held_back = Some(rows.iter().filter(|r| held(&r.name, &r.status)).count());
            }
            None => {
                let store = open_from_env().map_err(fail)?;
                let owner = std::env::var("USER").unwrap_or_default();
                // a name stored exactly so already is not written again, and is reported as unchanged
                unchanged = crate::workload::unchanged_names(
                    &store,
                    a.project,
                    a.env,
                    &lines,
                    &rows,
                    &|n| allow_live.iter().any(|x| x == n),
                    a.public,
                )
                .map_err(fail)?;
                let to_write: Vec<crate::workload::EnvLine> = lines
                    .iter()
                    .filter(|l| !unchanged.contains(&l.name))
                    .map(|l| crate::workload::EnvLine {
                        name: l.name.clone(),
                        value: l.value.clone(),
                        line: l.line,
                        malformed: l.malformed,
                    })
                    .collect();
                let done = crate::workload::apply_marked(
                    &store, a.project, a.env, &to_write, allow_live, a.public, &owner,
                )
                .map_err(fail)?;
                held_back = Some(done.held_back.len());
                held_by_service = done.held_back;
                stored = Some(done.stored);
            }
        }
    }
    // Where every kept entry ended up. A name the box or the store did not report as stored, and that nothing else explains, is
    // reported as skipped rather than dropped, so the buckets always add up to the entries of the file.
    let applied = stored.is_some();
    let outcomes: Vec<Outcome> = rows
        .iter()
        .map(|r| {
            if let Some(why) = skippable(r) {
                Outcome::Skipped(why)
            } else if unchanged.contains(&r.name) {
                Outcome::Unchanged
            } else if held(&r.name, &r.status) || held_by_service.contains(&r.name) {
                Outcome::HeldBack
            } else if !applied {
                Outcome::Ready
            } else if stored.as_ref().is_some_and(|s| s.contains(&r.name)) {
                Outcome::Stored
            } else if needs_newer.contains(&r.name) {
                Outcome::Skipped("only a newer box can store it (see above)".into())
            } else {
                Outcome::Skipped("it was not stored".into())
            }
        })
        .collect();
    let report = Report::new(&outcomes, &duplicates, &rejected, applied);
    if json {
        let r: Vec<_> = rows
            .iter()
            .zip(&outcomes)
            .map(|(r, o)| {
                json!({"name": (r.status != Status::Invalid).then(|| r.name.clone()), "line": r.line,
                    "fingerprint": r.fingerprint,
                    "status": match &r.status { Status::Ready => "ready", Status::Live(_) => "production_looking", Status::Invalid => "invalid", Status::Blank => "blank", Status::Unstorable(_) => "cannot_be_stored" },
                    "reason": skippable(r),
                    "outcome": o.word(),
                    "encoded": r.encoded,
                    "public": a.public.contains(&r.name),
                    "held_back": held(&r.name, &r.status)})
            })
            .collect();
        let _ = writeln!(
            out,
            "{}",
            json!({"project": a.project, "env": a.env, "keys": r, "stored": stored, "box": a.on_box,
                "needs_newer_box": needs_newer,
                "summary": report.json(),
                "duplicates": crate::import_report::duplicates_json(&duplicates),
                "rejected_lines": crate::import_report::rejected_json(&rejected),
                "unchanged": unchanged})
        );
    } else {
        for r in &rows {
            let enc = if r.encoded { "  (stored encoded)" } else { "" };
            let enc = if a.public.contains(&r.name) {
                format!("{enc}  (marked PUBLIC: given to a declared command as plain environment)")
            } else {
                enc.to_string()
            };
            let note = match &r.status {
                Status::Ready => enc.clone(),
                Status::Live(why) => format!("  production-looking ({why}){enc}"),
                _ => format!("  {}", skippable(r).unwrap_or_default()),
            };
            let _ = writeln!(
                out,
                "{}",
                t(
                    "secrets.import_line",
                    &[
                        ("name", &r.label()),
                        ("fingerprint", &r.fingerprint),
                        ("note", &note)
                    ]
                )
            );
        }
        for x in &rejected {
            let _ = writeln!(
                out,
                "{}",
                t(
                    "secrets.report_rejected_line",
                    &[("line", &x.line.to_string()), ("reason", x.reason)]
                )
            );
        }
        for d in &duplicates {
            let _ = writeln!(
                out,
                "{}",
                t(
                    "secrets.report_dup_line",
                    &[
                        ("name", &d.name),
                        ("detail", &crate::import_report::duplicate_detail(d))
                    ]
                )
            );
        }
        let skipped = rows.iter().filter(|r| skippable(r).is_some()).count() + rejected.len();
        if skipped > 0 {
            let _ = writeln!(
                out,
                "{}",
                t("secrets.import_skipped", &[("count", &skipped.to_string())])
            );
        }
        if !needs_newer.is_empty() {
            let _ = writeln!(
                out,
                "{}",
                t(
                    "secrets.import_needs_newer",
                    &[("names", &needs_newer.join(", "))]
                )
            );
        }
        let _ = match (&stored, held_back) {
            (Some(s), Some(h)) => writeln!(
                out,
                "{}",
                t(
                    "secrets.import_done",
                    &[("count", &s.len().to_string()), ("held", &h.to_string())]
                )
            ),
            _ => writeln!(out, "{}", t("secrets.import_preview", &[])),
        };
        let _ = writeln!(out, "{}", report.line(&duplicates));
    }
    Ok(())
}

/// The box end, run by the ingress account's forced command: one request line on standard input, handed to the secrets
/// service's ingress socket, whose answer is printed as it came. Three requests only: the service's public key, a sealed
/// request, and the owner's copy of the store's key while the service is down. The line is never put in an argument.
#[cfg(unix)]
pub fn receive(socket: Option<&Path>) -> Result<(), CliError> {
    use std::io::Read;
    let mut line = String::new();
    std::io::BufReader::new(std::io::stdin().take(crate::secrets_ingress::MAX_LINE_BYTES))
        .read_line(&mut line)
        .map_err(|_| CliError::Msg(t("secrets.import_unreadable", &[])))?;
    let v: Value = serde_json::from_str(line.trim_end())
        .map_err(|_| CliError::Msg(t("secrets.receive_bad", &[])))?;
    let path = socket
        .map(Path::to_path_buf)
        .or_else(|| {
            std::env::var_os("OZBOX_INGRESS_SOCKET")
                .filter(|p| !p.is_empty())
                .map(std::path::PathBuf::from)
        })
        .unwrap_or_else(|| std::path::PathBuf::from(crate::ingress_guard::SOCKET));
    match v["op"].as_str() {
        Some("service_key" | "sealed") => {
            let ans =
                crate::secrets_service::ask_raw(&path, line.trim_end()).map_err(CliError::Msg)?;
            println!("{ans}");
            Ok(())
        }
        Some("kek_place") => {
            let up = std::os::unix::net::UnixStream::connect(&path).is_ok();
            crate::secrets_ingress::place_kek(
                &crate::secrets_ingress::inbox_dir(),
                v["kek"].as_str().unwrap_or(""),
                up,
            )
            .map_err(CliError::Msg)?;
            println!("{}", json!({"ok": true, "placed": true}));
            Ok(())
        }
        _ => Err(CliError::Msg(t("secrets.receive_bad", &[]))),
    }
}

#[cfg(not(unix))]
pub fn receive(_: Option<&Path>) -> Result<(), CliError> {
    Err(CliError::Msg(t("secrets.serve_unix_only", &[])))
}

/// The box's command launcher (root): see `runner.rs`.
#[cfg(unix)]
pub fn run_as() -> Result<(), CliError> {
    use crate::runner::{serve_stdio, SystemBackend};
    use crate::secrets_service::SocketSecrets;
    let sock = |var: &str, default: &str| {
        SocketSecrets::new(std::path::PathBuf::from(
            std::env::var(var).unwrap_or_else(|_| default.to_string()),
        ))
    };
    let be = SystemBackend {
        admin: sock(
            "OZBOX_SECRETS_ADMIN_SOCKET",
            "/run/ozbox-secrets/admin/admin.sock",
        ),
        resolver: sock(
            "OZBOX_SECRETS_RUNNER_SOCKET",
            "/run/ozbox-secrets/resolver/resolver.sock",
        ),
        audit_log: std::path::PathBuf::from("/var/log/ozbox-run.log"),
        launch_lock: std::sync::Mutex::new(None),
    };
    serve_stdio(&be);
    Ok(())
}

/// The step inside the sandbox unit: the environment line is on standard input, the command follows `--`. See `runner.rs`.
#[cfg(unix)]
pub fn exec_env(command: &[String]) -> Result<(), CliError> {
    crate::runner::exec_env_main(command).map_err(CliError::Msg)
}

/// The step inside a service's unit with `credential_env`: the credentials are files in `$CREDENTIALS_DIRECTORY`, the program
/// follows `--`. See `runner.rs`.
#[cfg(unix)]
pub fn exec_cred(command: &[String]) -> Result<(), CliError> {
    crate::runner::exec_cred_main(command).map_err(CliError::Msg)
}

/// A service's egress proxy unit: see `runner_egress`.
pub fn egress_serve(port: u16, uid: u32, rules: &[String], tcp: &[String]) -> Result<(), CliError> {
    crate::runner_egress::serve_main(port, uid, rules, tcp).map_err(CliError::Msg)
}

#[cfg(not(unix))]
pub fn exec_cred(_: &[String]) -> Result<(), CliError> {
    Err(CliError::Msg(t("secrets.serve_unix_only", &[])))
}

#[cfg(not(unix))]
pub fn exec_env(_: &[String]) -> Result<(), CliError> {
    Err(CliError::Msg(t("secrets.serve_unix_only", &[])))
}

#[cfg(not(unix))]
pub fn run_as() -> Result<(), CliError> {
    Err(CliError::Msg(t("secrets.serve_unix_only", &[])))
}

/// `ozbox env run | policy`.
pub fn run_env(command: &EnvCommand, json: bool) -> Result<(), CliError> {
    match command {
        EnvCommand::Policy { command } => policy(command, &ozbox_core::SystemRunner, json),
        EnvCommand::Run {
            project,
            env,
            allow,
            vars,
            named,
            pass,
            start,
            stop,
            status,
            command,
        } => {
            let action = match (start, stop, status) {
                (true, _, _) => "start",
                (_, true, _) => "stop",
                (_, _, true) => "status",
                _ => "run",
            };
            let pass = parse_pass(pass)?;
            run_command(
                project,
                env,
                allow,
                vars,
                named.as_deref(),
                command,
                json,
                action,
                &pass,
            )
        }
    }
}

/// Whether this machine is a box: it has a command launcher's socket. (A person's computer has none.)
fn on_a_box() -> bool {
    #[cfg(unix)]
    {
        launcher_socket().is_some()
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// `git` in `dir`: the checkout's commit and whether it is clean.
fn git_state(dir: &std::path::Path) -> Result<(String, bool), String> {
    let run = |args: &[&str]| -> Result<String, String> {
        let o = std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|_| "git is not available".to_string())?;
        if !o.status.success() {
            return Err(format!("{} is not a git checkout", dir.display()));
        }
        Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
    };
    Ok((
        run(&["rev-parse", "HEAD"])?,
        run(&["status", "--porcelain"])?.is_empty(),
    ))
}

/// The rule for where a digest an owner will approve may be computed (see `PolicyCommand::Pin`): off the box, at the commit the box
/// reports, in a clean checkout; or on the box only when the person says so.
fn check_pin_origin(
    dir: &std::path::Path,
    commit: Option<&str>,
    on_box_flag: bool,
) -> Result<(), CliError> {
    if on_a_box() {
        if !on_box_flag {
            return Err(CliError::Msg("this is a box: a digest computed here only freezes what is here now, which an agent may already have changed. Run `ozbox env policy pin` on your computer, in your own checkout at the commit the box reports (--commit), or add --on-box to freeze what is here knowingly".into()));
        }
        eprintln!("note: computed on the box: this freezes what is here now; it does not show that it is what you reviewed");
        return Ok(());
    }
    if on_box_flag {
        return Ok(());
    }
    let Some(want) = commit else {
        return Err(CliError::Msg("pass --commit SHA: the commit the box reports for the project folder (`git rev-parse HEAD` there), so the digests are of the code the box runs".into()));
    };
    let (head, clean) = git_state(dir).map_err(CliError::Msg)?;
    if want.len() < 7 || !head.starts_with(want) {
        return Err(CliError::Msg(format!(
            "your checkout is at {}, not at the box's commit {want}: check out that commit first",
            &head[..head.len().min(12)]
        )));
    }
    if !clean {
        return Err(CliError::Msg("your checkout has uncommitted changes: a digest of files the box does not have would never match".into()));
    }
    Ok(())
}

fn policy(c: &PolicyCommand, runner: &dyn CommandRunner, json: bool) -> Result<(), CliError> {
    match c {
        PolicyCommand::Set {
            file,
            project,
            on_box,
            approval,
        } => {
            let text = std::fs::read_to_string(file)
                .map_err(|_| CliError::Msg(t("secrets.import_unreadable", &[])))?;
            let p = Policy::parse(&text).map_err(fail)?;
            let compact = serde_json::to_string(&p).unwrap_or_default();
            match on_box {
                Some(b) => {
                    // A box from before this format would read the declaration, drop what it does not know and store the
                    // rest, with the owner's approval covering a declaration that is not the one written. So ask first.
                    if p.needs_v2() || p.needs_runner_uids() || p.needs_public_values() {
                        let caps = ssh_receive(runner, b.as_str(), &json!({"op": "capabilities"}));
                        let has = |k: &str| {
                            caps.as_ref()
                                .map(|v| v["result"][k] == json!(true))
                                .unwrap_or(false)
                        };
                        if p.needs_v2() && !has("declaration_v2") {
                            return Err(CliError::Msg(t("secrets.policy_needs_newer_box", &[])));
                        }
                        // public names and a service that receives a secret are read only by a box that answers `public_values`
                        if p.needs_public_values() && !has("public_values") {
                            return Err(CliError::Msg(t("secrets.policy_needs_newer_box", &[])));
                        }
                        // such a box would run the command that receives a secret and the others as ONE user
                        if p.needs_runner_uids() && !has("runner_uids") {
                            return Err(CliError::Msg(t("secrets.policy_needs_runner_uids", &[])));
                        }
                    }
                    ssh_receive(
                        runner,
                        b.as_str(),
                        &json!({"op": "policy", "project": project, "text": compact,
                            "approval": approval.as_deref().unwrap_or("")}),
                    )?;
                }
                None => crate::workload_policy::save(&open_from_env().map_err(fail)?, project, &p)
                    .map_err(fail)?,
            }
            if json {
                println!(
                    "{}",
                    json!({"saved": true, "commands": p.commands.keys().collect::<Vec<_>>()})
                );
            } else {
                println!(
                    "{}",
                    t(
                        "secrets.policy_saved",
                        &[("count", &p.commands.len().to_string())]
                    )
                );
            }
            Ok(())
        }
        PolicyCommand::Pin {
            dir,
            entry,
            tree,
            tool,
            browser,
            release,
            revision,
            arch,
            browser_cache,
            commit,
            on_box,
            files,
        } => {
            if files.is_empty()
                && entry.is_empty()
                && tree.is_empty()
                && tool.is_empty()
                && browser.is_empty()
            {
                return Err(CliError::Msg(t("secrets.pin_nothing", &[])));
            }
            // Every digest the owner approves is computed OFF the box, from bytes the box user (and any agent) cannot have written:
            // on the box it would only freeze what is there now (G5 second review, N-H2).
            // (a tool or browser fetched from the vendor, or a folder you extracted, has no checkout to compare)
            let project_files = !(files.is_empty() && entry.is_empty() && tree.is_empty());
            let tool_from_box = tool.iter().any(|n| !n.contains('=') && release.is_none());
            let browser_from_box =
                !browser.is_empty() && revision.is_empty() && browser_cache.is_none();
            if project_files || tool_from_box || browser_from_box {
                check_pin_origin(dir, commit.as_deref(), *on_box)?;
            }
            let arch = crate::pin_fetch::parse_arch(arch.as_deref().unwrap_or("amd64"))
                .map_err(CliError::Msg)?;
            let mut pin = crate::runner_pins::digests(dir, files).map_err(CliError::Msg)?;
            let mut pin_tree: Vec<crate::workload_policy::TreePin> = Vec::new();
            for e in entry {
                let (f, t2) = crate::runner_pins::closure_pins(dir, e).map_err(CliError::Msg)?;
                for p in f {
                    if !pin.iter().any(|x| x.file == p.file) {
                        pin.push(p);
                    }
                }
                for t3 in t2 {
                    if !pin_tree.iter().any(|x| x.path == t3.path) {
                        pin_tree.push(t3);
                    }
                }
            }
            for t3 in tree {
                let rel = t3.trim_start_matches("./").trim_end_matches('/');
                let sha =
                    crate::runner_setup::tree_digest(&dir.join(rel)).map_err(CliError::Msg)?;
                if !pin_tree.iter().any(|x| x.path == rel) {
                    pin_tree.push(crate::workload_policy::TreePin {
                        path: rel.to_string(),
                        sha256: sha,
                    });
                }
            }
            // a plain list of files keeps the shape it always had
            if entry.is_empty() && tree.is_empty() && tool.is_empty() && browser.is_empty() {
                println!("{}", serde_json::to_string_pretty(&pin).unwrap_or_default());
                return Ok(());
            }
            let mut out = serde_json::Map::new();
            if !pin.is_empty() {
                out.insert("pin".into(), json!(pin));
            }
            if !pin_tree.is_empty() {
                out.insert("pin_tree".into(), json!(pin_tree));
            }
            if !tool.is_empty() {
                let mut tools = Vec::new();
                for n in tool {
                    let (name, d) = match n.split_once('=') {
                        Some((name, folder)) => {
                            (name.to_string(), crate::runner_setup::tree_digest(std::path::Path::new(folder)).map_err(CliError::Msg)?)
                        }
                        None if release.is_some() && !*on_box => {
                            let catalog = ozbox_catalog::embedded().map_err(CliError::Msg)?;
                            let f = crate::pin_fetch::tool_digest(&crate::pin_fetch::Https, &catalog, n, release.as_deref().unwrap_or_default(), arch)
                                .map_err(CliError::Msg)?;
                            eprintln!("note: {n} {}: {} checked against the catalog's checksum (download {}), extracted as the box does", release.as_deref().unwrap_or_default(), f.asset, &f.archive_sha256[..12]);
                            (n.clone(), f.sha256)
                        }
                        None if *on_box => {
                            let home = std::env::var("OZBOX_BOX_HOME")
                                .ok()
                                .map(std::path::PathBuf::from)
                                .unwrap_or_else(|| std::path::PathBuf::from(std::env::var("OZBOX_BOX_USER_HOME").unwrap_or_else(|_| "/work/home/ozbox".into())));
                            let paths = crate::runner_setup::Paths::system(home);
                            let catalog = ozbox_catalog::embedded().map_err(CliError::Msg)?;
                            (n.clone(), crate::runner_setup::installed_tool_digest(&paths, &catalog, n).map_err(CliError::Msg)?)
                        }
                        None => return Err(CliError::Msg(format!("--tool {n}: name the folder you extracted it to (--tool {n}=DIR), give --release VERSION to fetch the catalog's Linux release, or add --on-box to digest the box's own copy"))),
                    };
                    tools.push(json!({"name": name, "sha256": d}));
                }
                out.insert("tools".into(), json!(tools));
            }
            if !browser.is_empty() {
                let d = match browser_cache {
                    Some(c) => crate::runner_setup::browser_digests_in(c, browser).map_err(CliError::Msg)?,
                    None if !revision.is_empty() && !*on_box => {
                        // one revision per folder: chromium, its headless shell and ffmpeg are numbered separately
                        let mut revs = std::collections::BTreeMap::new();
                        for r in revision {
                            let (k, n) = r.split_once('=').ok_or_else(|| CliError::Msg(format!("--revision {r}: write it as KIND=N, for example chromium=1169 (each folder of a browser has its own number)")))?;
                            if revs.insert(k.to_string(), n.to_string()).is_some() {
                                return Err(CliError::Msg(format!("--revision {k} is given twice")));
                            }
                        }
                        let mut need: Vec<&str> = browser.iter().flat_map(|b| crate::workload_policy::implied_kinds(b)).collect();
                        need.sort_unstable();
                        need.dedup();
                        if let Some(k) = need.iter().find(|k| !revs.contains_key(**k)) {
                            return Err(CliError::Msg(format!("--browser needs a revision for each of its folders ({}): add --revision {k}=N", need.join(", "))));
                        }
                        if let Some(k) = revs.keys().find(|k| !need.contains(&k.as_str())) {
                            return Err(CliError::Msg(format!("--revision {k}: no browser named with --browser needs that folder")));
                        }
                        let mut all = std::collections::BTreeMap::new();
                        for (k, rev) in &revs {
                            let (m, archive) = crate::pin_fetch::browser_digest(&crate::pin_fetch::Https, k, rev, arch).map_err(CliError::Msg)?;
                            eprintln!("note: {k} {rev}: downloaded from Playwright's CDN over https (archive {}); Playwright publishes no checksum, so compare this with a second download", &archive[..12]);
                            all.extend(m);
                        }
                        all
                    }
                    None if *on_box => {
                        let home = std::env::var("OZBOX_BOX_HOME")
                            .ok()
                            .map(std::path::PathBuf::from)
                            .unwrap_or_else(|| std::path::PathBuf::from(std::env::var("OZBOX_BOX_USER_HOME").unwrap_or_else(|_| "/work/home/ozbox".into())));
                        crate::runner_setup::installed_browser_digests(&crate::runner_setup::Paths::system(home), browser).map_err(CliError::Msg)?
                    }
                    None => return Err(CliError::Msg("--browser needs --browser-cache DIR (a cache you downloaded yourself), --revision KIND=N (download Playwright's Linux build, one per folder), or --on-box".into())),
                };
                out.insert("browser_digests".into(), json!(d));
            }
            println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
            Ok(())
        }
        PolicyCommand::Show { project } => {
            let store = open_from_env().map_err(fail)?;
            let p = crate::workload_policy::load(&store, project)
                .map_err(fail)?
                .ok_or_else(|| CliError::Msg(t("secrets.policy_none", &[])))?;
            println!("{}", serde_json::to_string_pretty(&p).unwrap_or_default());
            Ok(())
        }
    }
}

/// The launcher's socket, when this machine has one (a box that runs workload commands as a runner user).
#[cfg(unix)]
fn launcher_socket() -> Option<std::path::PathBuf> {
    let p = std::env::var("OZBOX_RUNNER_LAUNCH_SOCKET")
        .unwrap_or_else(|_| crate::runner::LAUNCH_SOCKET.to_string());
    let p = std::path::PathBuf::from(p);
    p.exists().then_some(p)
}

#[cfg(not(unix))]
fn launcher_socket() -> Option<std::path::PathBuf> {
    None
}

/// `NAME=value` words from the command line. The names are checked here only for shape; the box decides the rest.
fn parse_pass(words: &[String]) -> Result<Vec<(String, String)>, CliError> {
    words
        .iter()
        .map(|w| match w.split_once('=') {
            Some((k, v)) if !k.is_empty() => Ok((k.to_string(), v.to_string())),
            _ => Err(CliError::Msg(t("secrets.pass_shape", &[]))),
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn run_command(
    project: &str,
    env: &str,
    allow: &[String],
    vars: &[String],
    named: Option<&str>,
    argv: &[String],
    json: bool,
    action: &str,
    pass: &[(String, String)],
) -> Result<(), CliError> {
    if let Some(sock) = launcher_socket() {
        return run_on_box(
            &sock, project, env, allow, vars, named, argv, json, action, pass,
        );
    }
    if action != "run" || !pass.is_empty() {
        return Err(CliError::Msg(t("secrets.policy_box_only", &[])));
    }
    let store = open_from_env().map_err(fail)?;
    // a project that declared its commands is followed, not argued with
    let (allow, vars): (Vec<String>, Vec<String>) =
        match crate::workload_policy::load(&store, project).map_err(fail)? {
            Some(p) => {
                let name = named.ok_or_else(|| CliError::Msg(t("secrets.env_need_named", &[])))?;
                // plain variables, pins, services, renames, tools and browsers are a box's: a person's own computer has no
                // runner user to hold them, and running without them would be running something else
                if p.needs_v2() {
                    return Err(CliError::Msg(t("secrets.policy_box_only", &[])));
                }
                let c = p.command(name, argv).map_err(fail)?;
                (
                    c.allow.clone(),
                    c.env.iter().map(|e| e.name.clone()).collect(),
                )
            }
            None if named.is_some() => {
                return Err(CliError::Msg(t("secrets.policy_none", &[])));
            }
            None => (allow.to_vec(), vars.to_vec()),
        };
    let spec = crate::workload::RunSpec {
        project,
        env,
        allow: &allow,
        env_names: &vars,
        argv,
    };
    let r = crate::workload::run(&store, &spec).map_err(fail)?;
    // names only, never a value
    crate::workload::audit(
        store.path(),
        &format!(
            "env-run project={project} env={env} names={} exit={} redacted={}",
            r.resolved.join(","),
            r.code.map_or("none".to_string(), |c| c.to_string()),
            r.redactions
        ),
    );
    print_and_exit(r.code, &r.stdout, &r.stderr, r.redactions, json)
}

#[allow(clippy::too_many_arguments)]
#[cfg(unix)]
fn run_on_box(
    sock: &Path,
    project: &str,
    env: &str,
    allow: &[String],
    vars: &[String],
    named: Option<&str>,
    argv: &[String],
    json: bool,
    action: &str,
    pass: &[(String, String)],
) -> Result<(), CliError> {
    // On a box the project's declaration decides, so a list given here would only be a request to widen it.
    if !allow.is_empty() || !vars.is_empty() {
        return Err(CliError::Msg(t("secrets.env_flags_on_box", &[])));
    }
    let name = named.ok_or_else(|| CliError::Msg(t("secrets.env_need_named", &[])))?;
    let ask = || crate::runner::request_with(sock, project, env, name, argv, action, pass);
    let mut v = ask();
    if matches!(&v, Err(e) if e.contains("ensure-runner")) {
        // the runner user for a new project is made by the root helper, once
        let _ = std::process::Command::new("/usr/local/bin/ozbox-admin-request")
            .args(["ensure-runner", project])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        v = ask();
    }
    let v = v.map_err(CliError::Msg)?;
    if action != "run" {
        return print_service(&v, json);
    }
    print_and_exit(
        v["exit"].as_i64().and_then(|c| i32::try_from(c).ok()),
        v["stdout"].as_str().unwrap_or(""),
        v["stderr"].as_str().unwrap_or(""),
        usize::try_from(v["redactions"].as_u64().unwrap_or(0)).unwrap_or(0),
        json,
    )
}

#[allow(clippy::too_many_arguments)]
#[cfg(not(unix))]
fn run_on_box(
    _: &Path,
    _: &str,
    _: &str,
    _: &[String],
    _: &[String],
    _: Option<&str>,
    _: &[String],
    _: bool,
    _: &str,
    _: &[(String, String)],
) -> Result<(), CliError> {
    Err(CliError::Msg(t("secrets.serve_unix_only", &[])))
}

/// The answer to `--start`, `--stop`, `--status`: names and states, never a value.
fn print_service(v: &Value, json: bool) -> Result<(), CliError> {
    if json {
        println!("{v}");
        return Ok(());
    }
    let state = v["state"].as_str().unwrap_or("unknown");
    let port = v["port"].as_u64().unwrap_or(0).to_string();
    let healthy = v["healthy"].as_bool();
    let key = match (state, healthy) {
        ("running", _) => "secrets.service_running",
        ("stopped", _) => "secrets.service_stopped",
        ("active", Some(true)) => "secrets.service_healthy",
        ("active", _) => "secrets.service_unhealthy",
        _ => "secrets.service_inactive",
    };
    println!("{}", t(key, &[("port", &port)]));
    if let Some(log) = v["log"].as_str().filter(|l| !l.trim().is_empty()) {
        println!("{}", log.trim_end());
    }
    Ok(())
}

fn print_and_exit(
    code: Option<i32>,
    stdout: &str,
    stderr: &str,
    redactions: usize,
    json: bool,
) -> Result<(), CliError> {
    if json {
        println!(
            "{}",
            json!({"exit": code, "stdout": stdout, "stderr": stderr, "redactions": redactions})
        );
    } else {
        print!("{stdout}");
        eprint!("{stderr}");
    }
    std::process::exit(code.unwrap_or(1));
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::workload::parse_env;
    use ozbox_core::{Output, RecordingRunner};

    const SENTINEL: &str = "SENTINEL-import-0123456789abcdef";

    fn env_file(dir: &Path, body: &str) -> std::path::PathBuf {
        let p = dir.join(".env.staging");
        std::fs::write(&p, body).unwrap();
        p
    }

    fn live() -> String {
        format!("sk_{}_abcdef123456", "live")
    }

    /// G5 second review, N-M4: a file that says production is not imported under a staging name.
    #[test]
    fn a_file_that_says_production_is_not_imported_under_another_environment() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join(".env.production");
        std::fs::write(&f, "SERVICE_ROLE_KEY=value-1234567890\n").unwrap();
        let r = RecordingRunner::new();
        let args = ImportArgs {
            file: &f,
            project: "app",
            env: "staging",
            allow_live: &[],
            allow_live_all: false,
            public: &[],
            on_box: Some("dev"),
            approval: None,
        };
        let e = import(
            &args,
            &r,
            &mut std::io::empty(),
            false,
            true,
            false,
            &mut std::io::sink(),
        )
        .unwrap_err();
        assert!(e.to_string().contains("says production in its name"), "{e}");
        assert!(r.calls().is_empty(), "nothing was sent");
        // under the production environment the ordinary rules apply (held back unless named and confirmed)
        let args = ImportArgs {
            env: "production",
            ..args
        };
        assert!(import(
            &args,
            &r,
            &mut std::io::empty(),
            false,
            true,
            false,
            &mut std::io::sink()
        )
        .is_ok());
    }

    /// G5 second review, N-H2: a digest an owner will approve is computed off the box, at the commit the box reports, from a clean
    /// checkout.
    #[test]
    fn a_pin_is_computed_at_the_boxs_commit_from_a_clean_checkout() {
        let d = tempfile::tempdir().unwrap();
        let dir = std::fs::canonicalize(d.path()).unwrap();
        let git = |a: &[&str]| {
            assert!(
                std::process::Command::new("git")
                    .arg("-C")
                    .arg(&dir)
                    .args(a)
                    .output()
                    .unwrap()
                    .status
                    .success(),
                "{a:?}"
            );
        };
        git(&["init", "-q"]);
        std::fs::write(dir.join("m.mjs"), "x\n").unwrap();
        git(&["add", "."]);
        git(&[
            "-c",
            "user.email=a@b.c",
            "-c",
            "user.name=t",
            "commit",
            "-q",
            "-m",
            "m",
        ]);
        let head = String::from_utf8(
            std::process::Command::new("git")
                .arg("-C")
                .arg(&dir)
                .args(["rev-parse", "HEAD"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap();
        let head = head.trim();
        assert!(check_pin_origin(&dir, Some(head), false).is_ok());
        assert!(
            check_pin_origin(&dir, Some(&head[..8]), false).is_ok(),
            "a short commit is accepted"
        );
        let e = check_pin_origin(&dir, None, false).unwrap_err().to_string();
        assert!(e.contains("--commit"), "{e}");
        let e = check_pin_origin(&dir, Some("0123456789abcdef"), false)
            .unwrap_err()
            .to_string();
        assert!(e.contains("not at the box's commit"), "{e}");
        std::fs::write(dir.join("m.mjs"), "changed\n").unwrap();
        let e = check_pin_origin(&dir, Some(head), false)
            .unwrap_err()
            .to_string();
        assert!(e.contains("uncommitted"), "{e}");
    }

    #[test]
    fn a_laptops_file_goes_to_the_box_on_standard_input_and_a_production_key_stays_home() {
        let d = tempfile::tempdir().unwrap();
        let f = env_file(
            d.path(),
            &format!("API_KEY={SENTINEL}\nSTRIPE_KEY={}\nbad-name=1\n", live()),
        );
        crate::ingress_client::testing::install("dev");
        let r = RecordingRunner::new();
        r.reply(Output {
            status: Some(0),
            stdout: "{\"ok\":true,\"names\":[\"API_KEY\"],\"held\":[],\"invalid\":[]}\n".into(),
            stderr: String::new(),
        });
        let args = ImportArgs {
            file: &f,
            project: "app",
            env: "staging",
            allow_live: &[],
            allow_live_all: false,
            public: &[],
            on_box: Some("dev"),
            approval: None,
        };
        import(
            &args,
            &r,
            &mut std::io::empty(),
            false,
            true,
            true,
            &mut std::io::sink(),
        )
        .unwrap();
        let calls = r.calls();
        assert_eq!(calls.len(), 1);
        let c = &calls[0];
        assert_eq!(c.program, "ssh");
        // the ingress account, no command; nothing of the request on the command line
        assert_eq!(c.args, ["-T", "-o", "BatchMode=yes", "ozbox-dev-ingress"]);
        assert!(!c.args.join(" ").contains(SENTINEL));
        // what travels is ciphertext: the value is not in it
        let sent = String::from_utf8(c.stdin.clone().unwrap()).unwrap();
        assert!(!sent.contains(SENTINEL) && !sent.contains("API_KEY"));
        // the box's key opens it, and inside is the keys that were sent
        let inner =
            crate::ingress_client::testing::open_sent("dev", c.stdin.as_ref().unwrap()).to_string();
        assert!(inner.contains(SENTINEL) && inner.contains("API_KEY"));
        // the production-looking key and the invalid name never left this computer
        assert!(
            !inner.contains("STRIPE_KEY")
                && !inner.contains(&live())
                && !inner.contains("bad-name")
        );
    }

    /// What closes the route: the box user's `~/.bashrc` is read by bash when sshd runs `bash -c <command>`, and bash lets a
    /// function be named `/usr/local/bin/ozbox`, so a command route as the box user is capturable; the request goes to the
    /// ingress account instead, whose forced command reads none of the box user's files, and it is sealed.
    #[test]
    fn a_hostile_bashrc_can_capture_a_command_route_but_the_ingress_route_runs_none_of_its_files() {
        let d = tempfile::tempdir().unwrap();
        let rc = d.path().join("rc");
        let seen = d.path().join("seen");
        std::fs::write(
            &rc,
            format!(
                "function /usr/local/bin/ozbox {{ cat >> {}; }}\n",
                seen.display()
            ),
        )
        .unwrap();
        // the old shape: a command string given to bash, which reads the start-up file first (sshd's non-interactive bash
        // does the same with ~/.bashrc; BASH_ENV stands in for it here)
        let out = std::process::Command::new("bash")
            .args(["-c", "/usr/local/bin/ozbox secrets receive"])
            .env("BASH_ENV", &rc)
            .stdin(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut c| {
                use std::io::Write;
                c.stdin.take().unwrap().write_all(SENTINEL.as_bytes())?;
                c.wait()
            });
        assert!(out.is_ok());
        assert_eq!(
            std::fs::read_to_string(&seen).unwrap_or_default(),
            SENTINEL,
            "the class this closes: a command route is captured by a shell function"
        );
        // the new shape: the ingress account, whose forced command runs one program and reads no start-up file of the box
        // user's, and nothing of the request on the command line
        crate::ingress_client::testing::install("dev");
        let r = RecordingRunner::new();
        r.reply(Output {
            status: Some(0),
            stdout: "{\"ok\":true,\"names\":[]}\n".into(),
            stderr: String::new(),
        });
        ssh_receive(&r, "dev", &json!({"op": "approval_keys"})).unwrap();
        let args = r.calls()[0].args.clone();
        assert_eq!(args, ["-T", "-o", "BatchMode=yes", "ozbox-dev-ingress"]);
        // and an op the sealed route does not take is refused before anything is sent
        assert!(ssh_receive(&r, "dev", &json!({"op": "get", "name": "x"})).is_err());
        assert_eq!(r.calls().len(), 1);
    }

    #[test]
    fn a_blank_value_and_an_unclosed_quote_are_skipped_and_the_rest_go_including_values_with_spaces_and_json(
    ) {
        let d = tempfile::tempdir().unwrap();
        let f = env_file(
            d.path(),
            &format!(
                "EMPTY_A=\nEMPTY_B=\"\"\nQUOTED=\"{SENTINEL}\"\nORIGINS=\"https://a.example, https://b.example\"\nCONFIG={{\"k\":\"v\"}}\nAFTER=after-0123456789\nBROKEN=\"never closed\n"
            ),
        );
        crate::ingress_client::testing::install("dev");
        let r = RecordingRunner::new();
        r.reply(Output {
            status: Some(0),
            stdout: "{\"ok\":true,\"result\":{\"encoded_values\":true}}\n".into(),
            stderr: String::new(),
        });
        r.reply(Output {
            status: Some(0),
            stdout: "{\"ok\":true,\"names\":[\"QUOTED\",\"ORIGINS\",\"CONFIG\",\"AFTER\"],\"held\":[],\"invalid\":[]}\n".into(),
            stderr: String::new(),
        });
        let args = ImportArgs {
            file: &f,
            project: "app",
            env: "staging",
            allow_live: &[],
            allow_live_all: false,
            public: &[],
            on_box: Some("dev"),
            approval: None,
        };
        import(
            &args,
            &r,
            &mut std::io::empty(),
            false,
            true,
            true,
            &mut std::io::sink(),
        )
        .unwrap();
        // what travelled is sealed; the box's key opens it
        let sent =
            crate::ingress_client::testing::open_sent("dev", r.calls()[1].stdin.as_ref().unwrap())
                .to_string();
        for n in ["QUOTED", "ORIGINS", "CONFIG", "AFTER"] {
            assert!(sent.contains(n), "{n} must be sent");
        }
        // the quotes were removed before sending; a plain value goes as `value`, any other as base64
        assert!(sent.contains(&format!("\"value\":\"{SENTINEL}\"")));
        assert!(
            !sent.contains("a.example"),
            "an encoded value is not sent as text"
        );
        assert!(sent.contains(&crate::serve::auth::b64::encode_std(
            b"https://a.example, https://b.example"
        )));
        // nothing blank or unclosed left this computer
        for n in ["EMPTY_A", "EMPTY_B", "BROKEN", "never closed"] {
            assert!(!sent.contains(n), "{n} must not be sent");
        }
        // the words that say why name keys, never values
        let text = std::fs::read_to_string(&f).unwrap();
        let lines = parse_env(&text);
        let notes: Vec<String> = lines
            .iter()
            .zip(plan(&lines, "app", "staging"))
            .filter_map(|(l, r)| skippable(&r).map(|w| format!("{} {w}", l.name)))
            .collect();
        assert_eq!(notes.len(), 3);
        assert!(notes[0].starts_with("EMPTY_A skipped: the value is blank"));
        assert!(notes[2].starts_with("BROKEN cannot be stored: a quote is opened and never closed"));
        assert!(!notes.join(" ").contains("never closed\n"));
    }

    /// The real output of `import`, in both forms, with a sentinel in every kind of row: nothing of a value, or of a line
    /// that was read as a "name" from inside a value, may appear.
    #[test]
    fn what_import_prints_never_holds_a_value_or_a_piece_of_one() {
        let d = tempfile::tempdir().unwrap();
        let text = format!(
            "READY_ONE={SENTINEL}\nBLANK_ONE=\nUNCLOSED=\"VAL-UNCLOSED-0123456789\nINNER_NAME=VAL-INNER-0123456789\nPEM_PART_LINE_ABCDEFGH0123456789=VAL-PEM-0123456789\n"
        );
        let f = env_file(d.path(), &format!("-----BEGIN KEY-----\nPEMFRAGMENT0123456789abcdef=\nBAD-NAME=VAL-BAD-0123456789\n{text}"));
        let args = ImportArgs {
            file: &f,
            project: "app",
            env: "staging",
            allow_live: &[],
            allow_live_all: false,
            public: &[],
            on_box: None,
            approval: None,
        };
        for json in [false, true] {
            let mut out = Vec::new();
            let r = RecordingRunner::new();
            import(
                &args,
                &r,
                &mut std::io::empty(),
                false,
                json,
                false,
                &mut out,
            )
            .unwrap();
            let shown = String::from_utf8(out).unwrap();
            for needle in [
                "VAL-",
                "PEMFRAGMENT",
                "SENTINEL-workload",
                "INNER_NAME",
                "BAD-NAME",
            ] {
                assert!(
                    !shown.contains(needle),
                    "{needle} appeared (json={json}): {shown}"
                );
            }
            assert!(shown.contains("READY_ONE") && shown.contains("UNCLOSED"));
            assert!(
                shown.contains("line 2") || shown.contains("\"line\":2"),
                "{shown}"
            );
            assert!(r.calls().is_empty());
        }
    }

    /// Any value goes to the box as base64 in `value_b64` (plain ones as `value`), only after the box says it can read
    /// that; a box that cannot is sent the plain keys only and told which keys wait for an upgrade.
    #[test]
    fn an_encoded_value_goes_as_base64_to_a_box_that_can_read_it_and_is_listed_for_one_that_cannot()
    {
        let d = tempfile::tempdir().unwrap();
        let f = env_file(
            d.path(),
            "PEM=\"-----BEGIN KEY-----\nPEMLINE-0123456789abcdef=\n-----END KEY-----\"\nSPACED=\"two words here\"\nPLAIN=plain-0123456789\n",
        );
        let args = ImportArgs {
            file: &f,
            project: "app",
            env: "staging",
            allow_live: &[],
            allow_live_all: false,
            public: &[],
            on_box: Some("dev"),
            approval: None,
        };
        crate::ingress_client::testing::install("dev");
        let opened = |c: &ozbox_core::CommandSpec| {
            crate::ingress_client::testing::open_sent("dev", c.stdin.as_ref().unwrap())
        };
        // a box that can: capabilities first, then one import with both forms (each sealed; the box's key opens them)
        let r = RecordingRunner::new();
        r.reply(Output {
            status: Some(0),
            stdout: "{\"ok\":true,\"result\":{\"encoded_values\":true}}\n".into(),
            stderr: String::new(),
        });
        r.reply(Output { status: Some(0), stdout: "{\"ok\":true,\"names\":[\"PEM\",\"SPACED\",\"PLAIN\"],\"held\":[],\"invalid\":[]}\n".into(), stderr: String::new() });
        let mut out = Vec::new();
        import(
            &args,
            &r,
            &mut std::io::empty(),
            false,
            false,
            true,
            &mut out,
        )
        .unwrap();
        let calls = r.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(opened(&calls[0])["op"], "capabilities");
        let sent: Value = opened(&calls[1]);
        let rows = sent["lines"].as_array().unwrap();
        assert_eq!(
            rows[0]["value_b64"],
            crate::serve::auth::b64::encode_std(
                b"-----BEGIN KEY-----\nPEMLINE-0123456789abcdef=\n-----END KEY-----"
            )
        );
        assert!(rows[0].get("value").is_none());
        assert_eq!(rows[2]["value"], "plain-0123456789");
        let shown = String::from_utf8(out).unwrap();
        assert!(
            shown.contains("(stored encoded)")
                && !shown.contains("two words")
                && !shown.contains("PEMLINE")
        );
        // a box from before: the capability call is refused, so only the plain key goes, and the others are named
        let r = RecordingRunner::new();
        r.reply(Output {
            status: Some(0),
            stdout: "{\"ok\":false,\"error\":\"that is not allowed on this socket\"}\n".into(),
            stderr: String::new(),
        });
        r.reply(Output {
            status: Some(0),
            stdout: "{\"ok\":true,\"names\":[\"PLAIN\"],\"held\":[],\"invalid\":[]}\n".into(),
            stderr: String::new(),
        });
        let mut out = Vec::new();
        import(
            &args,
            &r,
            &mut std::io::empty(),
            false,
            false,
            true,
            &mut out,
        )
        .unwrap();
        let sent: Value = opened(&r.calls()[1]);
        assert_eq!(sent["lines"].as_array().unwrap().len(), 1);
        assert!(!opened(&r.calls()[1]).to_string().contains("two words"));
        let shown = String::from_utf8(out).unwrap();
        assert!(
            shown.contains("PEM, SPACED") && shown.contains("ozbox upgrade"),
            "{shown}"
        );
        // only plain keys: no capability call at all
        let f2 = env_file(d.path(), "PLAIN=plain-0123456789\n");
        let r = RecordingRunner::new();
        r.reply(Output {
            status: Some(0),
            stdout: "{\"ok\":true,\"names\":[\"PLAIN\"],\"held\":[],\"invalid\":[]}\n".into(),
            stderr: String::new(),
        });
        let a2 = ImportArgs { file: &f2, ..args };
        import(
            &a2,
            &r,
            &mut std::io::empty(),
            false,
            true,
            true,
            &mut std::io::sink(),
        )
        .unwrap();
        assert_eq!(r.calls().len(), 1);
    }

    /// The largest request this sends still fits the line the box reads once it is sealed (base64 plus the envelope), and
    /// a larger one is refused here, before anything is sent.
    #[test]
    fn a_request_at_the_cap_seals_into_a_line_the_box_reads_and_a_larger_one_is_not_sent() {
        let key = crate::ingress_client::testing::install("dev");
        let pad = |n: usize| json!({"op": "import", "project": "app", "env": "staging", "lines": [{"name": "K", "value": "x".repeat(n)}]});
        let base = pad(0).to_string().len();
        let at_cap = pad(MAX_RECEIVE_BYTES - base);
        assert_eq!(at_cap.to_string().len(), MAX_RECEIVE_BYTES);
        let pk = key.public();
        let sealed = crate::secrets_ingress::seal_request(
            &pk,
            "a123456789-123456789-123456789-12345678z",
            &key.fingerprint(),
            &at_cap,
            u64::MAX,
            &"f".repeat(32),
        )
        .unwrap()
        .to_string();
        assert!(
            (sealed.len() as u64) < crate::secrets_ingress::MAX_LINE_BYTES,
            "sealed line is {} bytes",
            sealed.len()
        );
        let r = RecordingRunner::new();
        assert!(ssh_receive(&r, "dev", &pad(MAX_RECEIVE_BYTES - base + 1)).is_err());
        assert!(r.calls().is_empty());
        // the check that matters is on the sealed line itself, so a path that skips the plain cap still never sends a line the
        // box would refuse
        assert!(crate::ingress_client::call(&r, "dev", &pad(900 * 1024)).is_err());
        assert!(r.calls().is_empty());
    }

    /// The plain cap, worked out by hand (base64, the tag, a generous envelope), seals under the box's line limit.
    #[test]
    fn the_plain_cap_seals_under_the_boxs_line_limit_by_arithmetic() {
        // base64 turns 3 bytes into 4, the tag adds 16, the envelope (labels, box name, 64 hex fingerprint) under 1 KiB
        let sealed_len = |plain: usize| (plain + 16).div_ceil(3) * 4 + 44 + 1024;
        assert!((sealed_len(MAX_RECEIVE_BYTES) as u64) < crate::secrets_ingress::MAX_LINE_BYTES);
    }

    #[test]
    fn naming_a_production_key_needs_a_word_typed_at_a_terminal() {
        let d = tempfile::tempdir().unwrap();
        let f = env_file(
            d.path(),
            &format!("API_KEY={SENTINEL}\nSTRIPE_KEY={}\n", live()),
        );
        let named = ["STRIPE_KEY".to_string()];
        let args = ImportArgs {
            file: &f,
            project: "app",
            env: "staging",
            allow_live: &named,
            allow_live_all: false,
            public: &[],
            on_box: Some("dev"),
            approval: None,
        };
        crate::ingress_client::testing::install("dev");
        // no terminal: refused, nothing sent, even with --yes
        let r = RecordingRunner::new();
        assert!(import(
            &args,
            &r,
            &mut std::io::empty(),
            false,
            true,
            true,
            &mut std::io::sink()
        )
        .is_err());
        // a terminal, the wrong word
        assert!(import(
            &args,
            &r,
            &mut "yes\n".as_bytes(),
            true,
            true,
            true,
            &mut std::io::sink()
        )
        .is_err());
        assert!(r.calls().is_empty());
        // the right word (the project's name)
        r.reply(Output {
            status: Some(0),
            stdout:
                "{\"ok\":true,\"names\":[\"API_KEY\",\"STRIPE_KEY\"],\"held\":[],\"invalid\":[]}\n"
                    .into(),
            stderr: String::new(),
        });
        import(
            &args,
            &r,
            &mut "app\n".as_bytes(),
            true,
            true,
            true,
            &mut std::io::sink(),
        )
        .unwrap();
        let sent =
            crate::ingress_client::testing::open_sent("dev", r.calls()[0].stdin.as_ref().unwrap())
                .to_string();
        assert!(sent.contains("STRIPE_KEY") && sent.contains("\"allowed\":[\"STRIPE_KEY\"]"));
    }

    #[test]
    fn without_yes_nothing_is_sent_and_a_failing_box_says_so_without_the_values() {
        let d = tempfile::tempdir().unwrap();
        let f = env_file(d.path(), &format!("API_KEY={SENTINEL}\n"));
        let args = ImportArgs {
            file: &f,
            project: "app",
            env: "staging",
            allow_live: &[],
            allow_live_all: false,
            public: &[],
            on_box: Some("dev"),
            approval: None,
        };
        let r = RecordingRunner::new();
        import(
            &args,
            &r,
            &mut std::io::empty(),
            false,
            false,
            false,
            &mut std::io::sink(),
        )
        .unwrap();
        assert!(r.calls().is_empty());
        r.reply(Output {
            status: Some(255),
            stdout: String::new(),
            stderr: String::new(),
        });
        let e = import(
            &args,
            &r,
            &mut std::io::empty(),
            false,
            false,
            true,
            &mut std::io::sink(),
        )
        .unwrap_err();
        assert!(!e.to_string().contains(SENTINEL));
    }

    #[test]
    fn the_unsealed_request_takes_an_import_or_a_policy_and_answers_names_and_the_import_socket_takes_neither(
    ) {
        let d = tempfile::tempdir().unwrap();
        // not an op it relays
        let v = serde_json::from_str::<Value>(r#"{"op":"get","name":"x"}"#).unwrap();
        assert!(!matches!(v["op"].as_str(), Some("import" | "policy")));
        // the service's import socket refuses reads and answers held keys by name
        let p: Arc<dyn crate::secrets_enc::KeyProvider> =
            Arc::new(crate::secrets_enc::LocalKekProvider::random("local").unwrap());
        let store =
            crate::secrets_enc::EncryptedSecrets::new(d.path().join("s.json"), "box-a", p).unwrap();
        let mac = crate::tokenmac::TokenMac::new(Arc::new(
            crate::secrets_enc::EncryptedSecrets::new(
                d.path().join("m.json"),
                "box-a",
                Arc::new(crate::secrets_enc::LocalKekProvider::random("local").unwrap()),
            )
            .unwrap(),
        ));
        let req = json!({"op":"import","project":"app","env":"staging","allowed":[],"text":"me",
            "lines":[{"name":"API_KEY","value":SENTINEL},{"name":"STRIPE_KEY","value":live()}]});
        let out = crate::secrets_service::handle(
            &store,
            &mac,
            crate::secrets_service::Policy::Unsealed,
            &req.to_string(),
        );
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["names"], json!(["API_KEY"]));
        assert_eq!(v["held"], json!(["STRIPE_KEY"]));
        assert!(!out.contains(SENTINEL) && !out.contains(&live()));
        // the import socket reads nothing back and cannot reach the box socket's other powers
        for r in [
            json!({"op":"get","name":"workload.app.staging.API_KEY"}),
            json!({"op":"names","prefix":""}),
            json!({"op":"set","name":"x","value":"y"}),
            json!({"op":"resolve","project":"app","env":"staging","text":"{{secret:API_KEY}}","allowed":["API_KEY"]}),
        ] {
            let o = crate::secrets_service::handle(
                &store,
                &mac,
                crate::secrets_service::Policy::Import,
                &r.to_string(),
            );
            assert!(o.contains("not allowed") && !o.contains(SENTINEL), "{r}");
        }
        // the box user's own import socket takes no keys, no declaration, no signer and no approval: those are the ingress
        // route's alone (they arrive sealed, as the opened request)
        for r in [
            req.clone(),
            json!({"op":"policy","project":"app","text":"{}"}),
            json!({"op":"approval_key_enroll","key_id":"x","public_key":"00"}),
            json!({"op":"approval_challenge","key_id":"x","scope":"import"}),
            json!({"op":"approval_redeem","key_id":"x","nonce":"n","signature":"s"}),
            json!({"op":"approval_keys"}),
        ] {
            let o = crate::secrets_service::handle(
                &store,
                &mac,
                crate::secrets_service::Policy::Import,
                &r.to_string(),
            );
            assert!(o.contains("not allowed") && !o.contains(SENTINEL), "{r}");
        }
        // a declaration arrives the same way and is checked before it is stored
        let ok = json!({"op":"policy","project":"app","text":r#"{"dir":"/work/projects/app","commands":{"test":{"allow":[],"argv":["npm","test"]}}}"#});
        let o = crate::secrets_service::handle(
            &store,
            &mac,
            crate::secrets_service::Policy::Unsealed,
            &ok.to_string(),
        );
        assert!(o.contains("\"ok\":true"), "{o}");
        assert!(crate::workload_policy::load(&store, "app")
            .unwrap()
            .is_some());
        let bad = json!({"op":"policy","project":"app","text":r#"{"dir":"/etc","commands":{}}"#});
        assert!(crate::secrets_service::handle(
            &store,
            &mac,
            crate::secrets_service::Policy::Unsealed,
            &bad.to_string()
        )
        .contains("\"ok\":false"));
    }

    use std::sync::Arc;

    #[test]
    fn the_service_flags_and_pass_values_parse_and_conflict_as_documented() {
        use crate::cli::Cli;
        use clap::Parser;
        let parse = |a: &[&str]| {
            let mut v = vec!["ozbox", "env", "run", "--project", "p", "--env", "e"];
            v.extend_from_slice(a);
            Cli::try_parse_from(v)
        };
        assert!(parse(&["--named", "s", "--start"]).is_ok());
        assert!(parse(&["--named", "s", "--status"]).is_ok());
        assert!(parse(&["--start"]).is_err(), "a service is named");
        assert!(parse(&["--named", "s", "--start", "--stop"]).is_err());
        assert!(parse(&["--named", "t", "--pass", "A=1", "--", "npm", "test"]).is_ok());
        assert!(parse(&["--named", "t"]).is_err(), "a run needs its command");
        assert_eq!(
            parse_pass(&["A=b=c".into()]).unwrap(),
            vec![("A".to_string(), "b=c".to_string())]
        );
        assert!(parse_pass(&["A".into()]).is_err() && parse_pass(&["=x".into()]).is_err());
    }

    #[test]
    fn a_new_format_declaration_is_not_sent_to_a_box_that_cannot_read_it() {
        crate::ingress_client::testing::install("dev");
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("p.json");
        std::fs::write(
            &f,
            r#"{"dir":"/work/projects/app","commands":{"a":{"allow":[],"vars":{"PORT":"3100"}}}}"#,
        )
        .unwrap();
        let set = |r: &RecordingRunner| {
            policy(
                &PolicyCommand::Set {
                    file: f.clone(),
                    project: "app".into(),
                    on_box: Some("dev".parse().unwrap()),
                    approval: None,
                },
                r,
                true,
            )
        };
        // a box from before the format answers capabilities without it: nothing else is sent
        let old = RecordingRunner::new();
        old.reply(Output {
            status: Some(0),
            stdout: "{\"ok\":true,\"result\":{\"encoded_values\":true}}\n".into(),
            stderr: String::new(),
        });
        assert!(set(&old).is_err());
        assert_eq!(old.calls().len(), 1, "only the capabilities question went");
        // a box that can read it gets the declaration
        let new = RecordingRunner::new();
        new.reply(Output {
            status: Some(0),
            stdout: "{\"ok\":true,\"result\":{\"declaration_v2\":true}}\n".into(),
            stderr: String::new(),
        });
        new.reply(Output {
            status: Some(0),
            stdout: "{\"ok\":true}\n".into(),
            stderr: String::new(),
        });
        assert!(set(&new).is_ok());
        assert_eq!(new.calls().len(), 2);
        // what went is sealed; the box's key opens it
        let sent = crate::ingress_client::testing::open_sent(
            "dev",
            new.calls()[1].stdin.as_ref().unwrap(),
        )
        .to_string();
        assert!(
            sent.contains("\"op\":\"policy\"") && sent.contains("PORT"),
            "{sent}"
        );
    }

    /// ADR 0029 Amendment 12: `--public` is the person's explicit mark. It is refused as a whole before anything is sent, only goes to a
    /// box that says it can read it, and rides on the line it marks.
    #[test]
    fn a_public_mark_is_checked_on_this_computer_asked_of_the_box_and_sent_on_its_own_line() {
        let d = tempfile::tempdir().unwrap();
        let b = |t: &str| {
            crate::serve::auth::b64::encode_url(t.as_bytes())
                .trim_end_matches('=')
                .to_string()
        };
        let jwt = |payload: &str| {
            format!(
                "{}.{}.{}",
                b("{\"alg\":\"HS256\"}"),
                b(payload),
                b("sig-0123456789")
            )
        };
        let anon = jwt(r#"{"role":"anon"}"#);
        let service = jwt(r#"{"role":"service_role"}"#);
        let go = |body: &str, public: &[String], r: &RecordingRunner| {
            let f = env_file(d.path(), body);
            let args = ImportArgs {
                file: &f,
                project: "app",
                env: "staging",
                allow_live: &[],
                allow_live_all: false,
                public,
                on_box: Some("dev"),
                approval: None,
            };
            import(
                &args,
                r,
                &mut std::io::empty(),
                false,
                false,
                true,
                &mut Vec::new(),
            )
        };
        crate::ingress_client::testing::install("dev");
        let opened = |c: &ozbox_core::CommandSpec| {
            crate::ingress_client::testing::open_sent("dev", c.stdin.as_ref().unwrap())
        };
        // a service-role key, a name that says secret, and a name the file does not hold: refused, nothing sent
        for (body, names) in [
            (
                format!("ANON={service}\nOTHER=plain-0123456789\n"),
                vec!["ANON"],
            ),
            (
                "API_TOKEN=plain-token-0123456789\n".to_string(),
                vec!["API_TOKEN"],
            ),
            ("A_B=1\n".to_string(), vec!["NOT_THERE"]),
        ] {
            let r = RecordingRunner::new();
            let names: Vec<String> = names.into_iter().map(String::from).collect();
            let e = go(&body, &names, &r).unwrap_err().to_string();
            assert!(e.contains("public"), "{e}");
            assert!(
                !e.contains(&service) && !e.contains("plain-token"),
                "never a value: {e}"
            );
            assert!(r.calls().is_empty(), "nothing was sent");
        }
        // a box that does not answer `public_values`: asked first, then told to upgrade, nothing imported
        let r = RecordingRunner::new();
        r.reply(Output {
            status: Some(0),
            stdout: "{\"ok\":true,\"result\":{\"encoded_values\":true}}\n".into(),
            stderr: String::new(),
        });
        let e = go(&format!("ANON={anon}\n"), &["ANON".to_string()], &r)
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("upgrade") && e.contains("Nothing was imported"),
            "{e}"
        );
        assert_eq!(r.calls().len(), 1);
        // a box that can: the mark is on the marked line only
        let r = RecordingRunner::new();
        r.reply(Output {
            status: Some(0),
            stdout: "{\"ok\":true,\"result\":{\"encoded_values\":true,\"public_values\":true}}\n"
                .into(),
            stderr: String::new(),
        });
        r.reply(Output {
            status: Some(0),
            stdout: "{\"ok\":true,\"names\":[\"ANON\",\"OTHER\"],\"held\":[],\"invalid\":[]}\n"
                .into(),
            stderr: String::new(),
        });
        go(
            &format!("ANON={anon}\nOTHER=plain-0123456789\n"),
            &["ANON".to_string()],
            &r,
        )
        .unwrap();
        let calls = r.calls();
        assert_eq!(opened(&calls[0])["op"], "capabilities");
        let sent = opened(&calls[1]);
        let rows = sent["lines"].as_array().unwrap();
        assert_eq!(rows[0]["name"], "ANON");
        assert_eq!(rows[0]["public"], true);
        assert!(
            rows[1].get("public").is_none(),
            "an unmarked line carries no mark"
        );
    }

    /// A file of `n` keys, all production-looking when imported under `production`.
    fn many_keys(n: usize) -> String {
        (0..n)
            .map(|i| format!("KEY_{i:02}=value-{i:02}-0123456789\n"))
            .collect()
    }

    fn args<'a>(f: &'a Path, env: &'a str, all: bool) -> ImportArgs<'a> {
        ImportArgs {
            file: f,
            project: "app",
            env,
            allow_live: &[],
            allow_live_all: all,
            public: &[],
            on_box: Some("dev"),
            approval: None,
        }
    }

    fn box_says(r: &RecordingRunner, names: &[&str], held: &[&str]) {
        r.reply(Output {
            status: Some(0),
            stdout: format!(
                "{{\"ok\":true,\"names\":{},\"held\":{},\"invalid\":[]}}\n",
                serde_json::json!(names),
                serde_json::json!(held)
            ),
            stderr: String::new(),
        });
    }

    #[test]
    fn allow_live_all_stores_every_production_looking_key_after_one_typed_confirmation_and_lists_them_first(
    ) {
        let d = tempfile::tempdir().unwrap();
        let f = env_file(d.path(), &many_keys(73));
        crate::ingress_client::testing::install("dev");
        let r = RecordingRunner::new();
        let names: Vec<String> = (0..73).map(|i| format!("KEY_{i:02}")).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        box_says(&r, &refs, &[]);
        let mut out = Vec::new();
        import(
            &args(&f, "production", true),
            &r,
            &mut "app\n".as_bytes(),
            true,
            false,
            true,
            &mut out,
        )
        .unwrap();
        let out = String::from_utf8(out).unwrap();
        // every name is sent as allowed (one flag, not 73)
        let sent =
            crate::ingress_client::testing::open_sent("dev", r.calls()[0].stdin.as_ref().unwrap())
                .to_string();
        assert!(sent.contains("\"KEY_00\"") && sent.contains("\"KEY_72\""));
        assert_eq!(sent.matches("\"allowed\":[").count(), 1);
        // the names are listed before anything else is said, and the count is the file's
        let listed = out.find("73 production-looking key(s)").unwrap();
        assert!(out[listed..].contains("KEY_00") && out[listed..].contains("KEY_72"));
        assert!(listed < out.find("Stored 73 keys").unwrap());
        assert!(out.contains("73 entries: 73 stored"), "{out}");
    }

    #[test]
    fn allow_live_all_from_a_script_is_refused_and_says_the_exact_command_to_run_in_a_terminal() {
        let d = tempfile::tempdir().unwrap();
        let f = env_file(d.path(), &many_keys(3));
        crate::ingress_client::testing::install("dev");
        let r = RecordingRunner::new();
        let mut out = Vec::new();
        let e = import(
            &args(&f, "production", true),
            &r,
            &mut std::io::empty(),
            false,
            false,
            true,
            &mut out,
        )
        .unwrap_err()
        .to_string();
        assert!(r.calls().is_empty(), "nothing was sent");
        assert!(
            e.contains("ozbox secrets import")
                && e.contains("--project app")
                && e.contains("--env production")
                && e.contains("--box dev")
                && e.contains("--allow-live-all")
                && e.contains("--yes"),
            "{e}"
        );
        // the person still learns which keys the confirmation would cover
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("KEY_00") && out.contains("KEY_02"), "{out}");
        // the wrong word at a terminal sends nothing either
        let mut out2 = Vec::new();
        assert!(import(
            &args(&f, "production", true),
            &r,
            &mut "yes\n".as_bytes(),
            true,
            false,
            true,
            &mut out2
        )
        .is_err());
        assert!(r.calls().is_empty());
    }

    #[test]
    fn a_named_key_refused_from_a_script_also_names_the_command_to_run() {
        let d = tempfile::tempdir().unwrap();
        let f = env_file(d.path(), &format!("STRIPE_KEY={}\n", live()));
        let named = ["STRIPE_KEY".to_string()];
        let a = ImportArgs {
            allow_live: &named,
            ..args(&f, "staging", false)
        };
        let e = import(
            &a,
            &RecordingRunner::new(),
            &mut std::io::empty(),
            false,
            false,
            true,
            &mut std::io::sink(),
        )
        .unwrap_err()
        .to_string();
        assert!(
            e.contains("--allow-live STRIPE_KEY") && e.contains("--yes"),
            "{e}"
        );
    }

    /// Seven entries: a duplicate (A_KEY twice), a blank, a quoted value with a comment, a name with a space, a line that is not
    /// NAME=value, and a production-looking key.
    fn messy() -> String {
        format!(
            "A_KEY=one-0123456789\nBLANK=\nexport Q1=\"quoted-0123456789\" # note\nA_KEY=three-0123456789\nbad name={SENTINEL}\nJUSTAWORD\nSTRIPE_KEY={}\n",
            live()
        )
    }

    #[test]
    fn the_preview_accounts_for_every_entry_and_the_counts_add_up() {
        let d = tempfile::tempdir().unwrap();
        let f = env_file(d.path(), &messy());
        let mut out = Vec::new();
        import(
            &args(&f, "staging", false),
            &RecordingRunner::new(),
            &mut std::io::empty(),
            false,
            false,
            false,
            &mut out,
        )
        .unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(
            out.contains("A_KEY  appears more than once: line 4 kept, line 1 ignored"),
            "{out}"
        );
        assert!(out.contains("line 6  not NAME=value"), "{out}");
        assert!(
            out.contains("line 5  ")
                && out.contains("not a valid variable name: the name contains a space"),
            "{out}"
        );
        assert!(out.contains("skipped: the value is blank"), "{out}");
        assert!(
            out.contains("7 entries: 2 ready to store, 1 held back (production-looking, not allowed), 3 skipped (reasons above), 1 duplicate (line 4 kept, line 1 ignored)"),
            "{out}"
        );
        // never a value, never the text of a line that is not a name
        assert!(
            !out.contains("SENTINEL") && !out.contains("one-0123") && !out.contains("three-0123")
        );
        assert!(!out.contains("bad name") && !out.contains("JUSTAWORD"));
    }

    #[test]
    fn the_json_result_carries_the_same_account() {
        let d = tempfile::tempdir().unwrap();
        let f = env_file(d.path(), &messy());
        crate::ingress_client::testing::install("dev");
        let r = RecordingRunner::new();
        box_says(&r, &["A_KEY", "Q1"], &[]);
        let mut out = Vec::new();
        import(
            &args(&f, "staging", false),
            &r,
            &mut std::io::empty(),
            false,
            true,
            true,
            &mut out,
        )
        .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(!text.contains("SENTINEL") && !text.contains("three-0123"));
        let v: Value = serde_json::from_str(text.trim()).unwrap();
        let s = &v["summary"];
        assert_eq!(s["entries"], 7);
        assert_eq!(s["stored"], 2);
        assert_eq!(s["held_back"], 1);
        assert_eq!(s["skipped"], 3);
        assert_eq!(s["duplicates"], 1);
        assert_eq!(s["unchanged"], 0);
        assert_eq!(s["adds_up"], true);
        assert_eq!(v["duplicates"][0]["name"], "A_KEY");
        assert_eq!(v["duplicates"][0]["kept_line"], 4);
        assert_eq!(v["duplicates"][0]["ignored_lines"], json!([1]));
        assert_eq!(v["rejected_lines"][0]["line"], 6);
        let outcomes: Vec<&str> = v["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| k["outcome"].as_str().unwrap())
            .collect();
        // file order, the kept line of a duplicated name where its LAST line was
        assert_eq!(
            outcomes,
            ["skipped", "stored", "stored", "skipped", "held_back"]
        );
    }

    #[test]
    fn a_key_the_box_did_not_report_stored_is_still_accounted_for() {
        let d = tempfile::tempdir().unwrap();
        let f = env_file(d.path(), "ONE_KEY=one-0123456789\nTWO_KEY=two-0123456789\n");
        crate::ingress_client::testing::install("dev");
        let r = RecordingRunner::new();
        box_says(&r, &["ONE_KEY"], &["TWO_KEY"]);
        let mut out = Vec::new();
        import(
            &args(&f, "staging", false),
            &r,
            &mut std::io::empty(),
            false,
            false,
            true,
            &mut out,
        )
        .unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("2 entries: 1 stored, 1 held back"), "{out}");
    }
}
