//! `ozbox ide <box>`, `ozbox desktop <box>` and `ozbox open <box> --in <editor>`.
//!
//! Plan, then apply (ADR 0002): what will change on the box is printed first, `--dry-run` stops there, and a change needs
//! confirmation or `--yes`. A request that is already satisfied plans to nothing on the box and goes straight to opening.

use std::io::BufRead;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ozbox_core::{BoxName, BoxState, CommandRunner, CommandSpec, Provider};
use serde_json::json;

use crate::code::editors::{Editor, Evidence};
use crate::code::local::{self, Login};
use crate::code::procs::Stop;
use crate::code::{self, BoxCode, Change, CodeSettings, Service};
use crate::messages::t;
use crate::run::CliError;
use crate::secrets::SecretStore;
use crate::serve::BoxAgent;
use crate::sshconfig::{self, RouteInputs};
use crate::tunnel::Kind;

pub struct Flags {
    pub yes: bool,
    pub dry_run: bool,
    pub json: bool,
}

/// Whether to stay in the foreground keeping the local connection open (the command), or return once it is open (tests).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Wait {
    UntilSignal,
    #[cfg_attr(not(test), allow(dead_code))]
    Return,
}

pub struct Deps<'a> {
    pub provider: &'a dyn Provider,
    pub agent: Arc<dyn BoxAgent>,
    pub secrets: Arc<dyn SecretStore>,
    /// Runs the program that opens a browser.
    pub runner: &'a dyn CommandRunner,
    pub settings_path: Option<PathBuf>,
    /// The dashboard's own host name, when it has one.
    pub dashboard_host: Option<String>,
    /// Is the dashboard set up for sign-in (the second lock needs it)?
    pub signin_ready: bool,
    pub input: &'a mut dyn BufRead,
    pub tty: bool,
    pub wait: Wait,
}

pub struct ServiceArgs {
    pub name: BoxName,
    pub service: Service,
    pub no_open: bool,
    pub port: Option<u16>,
    pub public_url: Option<String>,
    pub tunnel: Option<String>,
    pub off: bool,
    pub new_password: bool,
    pub remove_public: bool,
}

fn msg(s: String) -> CliError {
    CliError::Msg(s)
}

fn service_label(s: Service) -> &'static str {
    match s {
        Service::Ide => "web IDE",
        Service::Desktop => "desktop",
    }
}

/// Open an address in the person's browser.
pub fn open_url(runner: &dyn CommandRunner, url: &str) -> bool {
    let spec = if cfg!(target_os = "macos") {
        CommandSpec::new("open").arg(url)
    } else if cfg!(target_os = "windows") {
        CommandSpec::new("cmd").args(["/c", "start", ""]).arg(url)
    } else {
        CommandSpec::new("xdg-open").arg(url)
    };
    runner.run(&spec).is_ok_and(|o| o.status == Some(0))
}

fn confirm(d: &mut Deps, f: &Flags, name: &str) -> Result<(), CliError> {
    if f.yes {
        return Ok(());
    }
    if !d.tty {
        return Err(msg(t("code.err_confirm", &[("box", name)])));
    }
    eprint!("{}", t("code.prompt", &[]));
    let mut line = String::new();
    let _ = d.input.read_line(&mut line);
    if matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        Ok(())
    } else {
        Err(msg(t("code.aborted", &[])))
    }
}

fn running_box(d: &Deps, name: &BoxName) -> Result<ozbox_core::BoxRecord, CliError> {
    let rec = d
        .provider
        .get(name)?
        .ok_or_else(|| ozbox_core::Error::NotFound(name.to_string()))?;
    if rec.state != BoxState::Running {
        return Err(msg(t(
            "code.err_not_running",
            &[("box", name.as_str()), ("state", &rec.state.to_string())],
        )));
    }
    Ok(rec)
}

fn probe(d: &Deps, rec: &ozbox_core::BoxRecord, name: &BoxName) -> Result<BoxCode, CliError> {
    d.agent.code_status(rec).map_err(|e| {
        msg(t(
            "code.err_unreachable",
            &[("box", name.as_str()), ("why", &e.to_string())],
        ))
    })
}

fn load_settings(d: &Deps) -> Result<CodeSettings, CliError> {
    match &d.settings_path {
        Some(p) => CodeSettings::load(p).map_err(CliError::Msg),
        None => Ok(CodeSettings::default()),
    }
}

fn save_settings(d: &Deps, s: &CodeSettings) -> Result<(), CliError> {
    match &d.settings_path {
        Some(p) => s.save(p).map_err(CliError::Msg),
        None => Ok(()),
    }
}

/// What the box must do for this request, from what it says now.
pub fn needs_change(state: code::ServiceState, secret_set: bool, new_password: bool) -> bool {
    !(state.active && state.unit_current && secret_set) || new_password
}

#[derive(Default)]
struct Plan {
    steps: Vec<String>,
    change_box: bool,
    /// The IDE is set up, but the terminal settings on the box are from an older Oz Box: put the current ones there.
    refresh_terminals: bool,
}

pub fn run_service(d: &mut Deps, a: &ServiceArgs, f: &Flags) -> Result<(), CliError> {
    let name = a.name.as_str();
    let label = service_label(a.service);
    let rec = running_box(d, &a.name)?;
    let status = probe(d, &rec, &a.name)?;
    let state = status.of(a.service);
    let secret = a.service.secret_name(name);
    let secret_set = d.secrets.exists(&secret).unwrap_or(false);

    // The public address, checked before anything is shown or changed.
    let mut settings = load_settings(d)?;
    let mut public: Option<(String, Kind)> = None;
    if let Some(url) = &a.public_url {
        let tunnel = a
            .tunnel
            .as_deref()
            .ok_or_else(|| msg(t("code.err_tunnel_needed", &[])))?;
        let kind = Kind::parse(tunnel)
            .ok_or_else(|| msg(t("code.err_bad_tunnel", &[("tunnel", tunnel)])))?;
        if !d.signin_ready {
            return Err(msg(t("code.err_no_dashboard_signin", &[])));
        }
        let mut probe_settings = settings.clone();
        let host = probe_settings
            .set(
                name,
                a.service,
                url,
                d.dashboard_host.as_deref(),
                Some(kind),
            )
            .map_err(|k| msg(t(k, &[])))?;
        settings = probe_settings;
        public = Some((host, kind));
    } else if a.tunnel.is_some() {
        return Err(msg(t("code.err_tunnel_needed", &[])));
    }

    let mut plan = Plan::default();
    if a.off {
        if state.unit_current || state.active {
            plan.change_box = true;
            plan.steps
                .push(t("code.plan_disable", &[("service", label)]));
        }
    } else {
        if !state.program {
            return Err(msg(t(
                "code.err_no_program",
                &[("program", a.service.program())],
            )));
        }
        if needs_change(state, secret_set, a.new_password) {
            plan.change_box = true;
            plan.steps
                .push(t("code.plan_enable", &[("program", a.service.program())]));
            if a.service == Service::Ide {
                plan.steps.push(t("code.plan_terminals", &[]));
            }
            plan.steps.push(t("code.plan_password", &[]));
        } else if a.service == Service::Ide && !status.terminals {
            plan.refresh_terminals = true;
            plan.steps
                .push(t("code.plan_refresh_terminals", &[("box", name)]));
        }
        if let Some((host, kind)) = &public {
            plan.steps.push(t(
                "code.plan_public",
                &[
                    ("address", &format!("https://{host}")),
                    ("host", host),
                    ("tunnel", kind.id()),
                ],
            ));
        } else if !a.no_open || a.public_url.is_none() {
            plan.steps.push(t("code.plan_forward", &[]));
        }
    }
    if a.remove_public {
        plan.steps
            .push(format!("  stop serving the {label} on its own address"));
    }
    if !f.json {
        println!(
            "{}",
            t("code.plan_head", &[("box", name), ("service", label)])
        );
        if plan.steps.is_empty() {
            println!(
                "{}",
                t("code.plan_nothing", &[("box", name), ("service", label)])
            );
        }
        for s in &plan.steps {
            println!("{s}");
        }
    }
    if f.dry_run {
        if f.json {
            println!(
                "{}",
                json!({ "box": name, "service": a.service.id(), "state": state.label(), "changes_box": plan.change_box,
                        "steps": plan.steps, "dry_run": true })
            );
        } else {
            println!("{}", t("code.dry_run", &[]));
        }
        return Ok(());
    }
    if plan.change_box || plan.refresh_terminals || public.is_some() || a.remove_public {
        confirm(d, f, name)?;
    }
    if plan.refresh_terminals {
        d.agent
            .code_change(&rec, &Change::Terminals)
            .map_err(|e| msg(e.to_string()))?;
    }

    // Apply.
    if a.off {
        if plan.change_box {
            d.agent
                .code_change(&rec, &Change::Disable { service: a.service })
                .map_err(|e| msg(e.to_string()))?;
            let _ = d.secrets.delete(&secret);
        }
        let mut s = load_settings(d)?;
        if s.clear(name, a.service) {
            save_settings(d, &s)?;
        }
        if f.json {
            println!(
                "{}",
                json!({ "box": name, "service": a.service.id(), "applied": true, "off": true })
            );
        } else {
            println!(
                "{}",
                t("code.off_done", &[("box", name), ("service", label)])
            );
        }
        return Ok(());
    }
    let password = if plan.change_box {
        let (pw, fresh) = match (secret_set && !a.new_password, d.secrets.get(&secret)) {
            (true, Ok(Some(p))) => (p, false),
            _ => (code::new_password().map_err(CliError::Msg)?, true),
        };
        d.agent
            .code_change(
                &rec,
                &Change::Enable {
                    service: a.service,
                    password: pw.clone(),
                },
            )
            .map_err(|e| msg(e.to_string()))?;
        if fresh {
            d.secrets
                .set(&secret, &pw)
                .map_err(|e| msg(t("code.err_secret", &[("why", &e.to_string())])))?;
        }
        pw
    } else {
        d.secrets
            .get(&secret)
            .ok()
            .flatten()
            .ok_or_else(|| msg(t("code.err_no_password", &[])))?
    };
    if !f.json {
        println!("{}", t("code.done", &[("box", name), ("service", label)]));
    }
    if a.remove_public {
        let mut s = load_settings(d)?;
        if s.clear(name, a.service) {
            save_settings(d, &s)?;
        }
    }
    if let Some((host, kind)) = public {
        save_settings(d, &settings)?;
        if f.json {
            println!(
                "{}",
                json!({ "box": name, "service": a.service.id(), "applied": true, "public_host": host, "tunnel": kind.id() })
            );
        } else {
            println!(
                "{}",
                t(
                    "code.public_saved",
                    &[("host", &host), ("service", label), ("box", name)]
                )
            );
            let port = crate::code::proxy::DEFAULT_PORT.to_string();
            let key = match kind {
                Kind::Caddy => "code.public_guide_caddy",
                _ => "code.public_guide_cloudflare",
            };
            println!("{}", t(key, &[("host", &host), ("port", &port)]));
        }
        return Ok(());
    }
    local_session(d, a, &rec, &password, f)
}

fn local_session(
    d: &mut Deps,
    a: &ServiceArgs,
    rec: &ozbox_core::BoxRecord,
    password: &str,
    f: &Flags,
) -> Result<(), CliError> {
    let name = a.name.to_string();
    let svc = a.service;
    let (agent, rec2) = (Arc::clone(&d.agent), rec.clone());
    let dial: local::Dialer = Arc::new(move || {
        agent
            .connect_tcp(&rec2, svc.box_port())
            .map_err(|e| e.to_string())
    });
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce).map_err(|e| msg(e.to_string()))?;
    let nonce: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
    let quiet = f.json;
    let box_for_msg = name.clone();
    let login = match svc {
        Service::Ide => Login::Form {
            password: password.to_string(),
        },
        Service::Desktop => Login::Basic {
            user: Service::DESKTOP_USER.into(),
            password: password.to_string(),
        },
    };
    let seen = Arc::new(AtomicBool::new(false));
    let seen2 = Arc::clone(&seen);
    let l = local::start(
        dial,
        login,
        local::Options {
            port: a.port,
            nonce,
            warm_every: (d.wait == Wait::UntilSignal).then_some(Duration::from_secs(8)),
            on_state: Arc::new(move |up| {
                // the first answer is the connection coming up, not news
                if !seen2.swap(true, Ordering::SeqCst) && up {
                    return;
                }
                if !quiet {
                    let k = if up {
                        "code.forward_up"
                    } else {
                        "code.forward_down"
                    };
                    eprintln!("{}", t(k, &[("box", &box_for_msg)]));
                }
            }),
        },
    )
    .map_err(|e| msg(e.to_string()))?;
    let url = l.go_url();
    let opened = !a.no_open && open_url(d.runner, &url);
    if f.json {
        println!(
            "{}",
            json!({ "box": name, "service": svc.id(), "url": url, "local_url": l.base_url(), "opened": opened })
        );
    } else {
        println!("{}", t("code.open_at", &[("url", &url)]));
        if svc == Service::Ide {
            for k in [
                "code.browser_note_title",
                "code.browser_keys_mac",
                "code.browser_keys_other",
                "code.browser_tmux",
                "code.browser_chromium",
                "code.browser_firefox",
                "code.browser_safari",
            ] {
                println!("{}", t(k, &[]));
            }
        }
        if !a.no_open && !opened {
            println!("{}", t("code.err_open_failed", &[("url", &url)]));
        }
        if d.wait == Wait::UntilSignal {
            println!("{}", t("code.keep_running", &[]));
        }
    }
    if d.wait == Wait::UntilSignal {
        let stop = stop_flag();
        while !stop.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(200));
        }
    }
    drop(l);
    Ok(())
}

fn stop_flag() -> Arc<AtomicBool> {
    let flag = Arc::new(AtomicBool::new(false));
    #[cfg(unix)]
    for sig in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
        let _ = signal_hook::flag::register(sig, Arc::clone(&flag));
    }
    flag
}

pub struct OpenArgs {
    pub name: BoxName,
    pub editor: Editor,
    /// Print the link and do not open it.
    pub print: bool,
    pub folder: String,
}

/// `ozbox open <box> --in <editor>`: write or refresh the box's SSH entry (it follows the box's current machine), then
/// open the editor's link on the folder.
pub fn run_open(
    d: &mut Deps,
    a: &OpenArgs,
    inputs: &RouteInputs,
    ssh_dir: Option<PathBuf>,
    f: &Flags,
) -> Result<(), CliError> {
    let name = a.name.as_str();
    let rec = d
        .provider
        .get(&a.name)?
        .ok_or_else(|| ozbox_core::Error::NotFound(name.to_string()))?;
    let routes = sshconfig::routes(&rec, inputs);
    let route = routes
        .first()
        .ok_or_else(|| msg(t("code.err_no_ssh_entry", &[("box", name)])))?;
    let alias = sshconfig::host_alias(name);
    let mut plan = vec![format!(
        "  write or refresh the SSH entry {alias} (it points at {name}'s current machine)"
    )];
    let link = a.editor.url_for_box(name, &a.folder);
    match &link {
        Some(_) => plan.push(format!("  open {} on {}", a.editor.name(), a.folder)),
        None => plan.push(format!("  show the steps for {}", a.editor.name())),
    }
    // The editor's terminals should survive a disconnect: if the box lacks the helpers, they are put there (a change, so
    // it is planned and confirmed).
    let needs_terminals =
        rec.state == BoxState::Running && d.agent.code_status(&rec).is_ok_and(|s| !s.terminals);
    if needs_terminals {
        plan.push(t("code.plan_open_terminals", &[("box", name)]));
    }
    if !f.json {
        println!(
            "{}",
            t(
                "code.plan_head",
                &[("box", name), ("service", a.editor.name())]
            )
        );
        for s in &plan {
            println!("{s}");
        }
    }
    if f.dry_run {
        if f.json {
            println!(
                "{}",
                json!({ "box": name, "editor": a.editor.id(), "url": link.as_ref().map(|l| &l.0), "changes_box": needs_terminals, "dry_run": true })
            );
        } else {
            println!("{}", t("code.dry_run", &[]));
        }
        return Ok(());
    }
    if needs_terminals {
        confirm(d, f, name)?;
        d.agent
            .code_change(&rec, &Change::Terminals)
            .map_err(|e| msg(e.to_string()))?;
    }
    // The entry is only a file in the person's own ~/.ssh/ozbox/ and the dedicated key: no confirmation, as `connect --ssh --write`.
    let dir = ssh_dir.ok_or_else(|| msg("cannot find your SSH directory".into()))?;
    if let sshconfig::Route::AwsSsm { .. } = route {
        sshconfig::ensure_key(d.runner, &dir).map_err(CliError::Core)?;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |x| x.as_secs());
    let _ = sshconfig::ensure_named_key(d.runner, &dir, sshconfig::INGRESS_KEY_NAME);
    sshconfig::write_config(&dir, name, &sshconfig::block(name, route), now)
        .map_err(CliError::Core)?;
    let mut opened = false;
    if let Some((url, evidence)) = &link {
        if !a.print {
            opened = open_url(d.runner, url);
        }
        if f.json {
            println!(
                "{}",
                json!({ "box": name, "editor": a.editor.id(), "url": url, "documented": *evidence == Evidence::Documented,
                        "opened": opened, "ssh_host": alias })
            );
        } else {
            println!(
                "{}",
                t("code.ssh_written", &[("box", name), ("alias", &alias)])
            );
            println!("{url}");
            if *evidence == Evidence::Unverified {
                println!(
                    "{}",
                    t(
                        "code.editor_unverified",
                        &[
                            ("editor", a.editor.name()),
                            ("box", name),
                            ("alias", &alias)
                        ]
                    )
                );
            }
        }
    } else if f.json {
        println!(
            "{}",
            json!({ "box": name, "editor": a.editor.id(), "url": null, "documented": false, "ssh_host": alias, "opened": false })
        );
    } else {
        println!(
            "{}",
            t("code.ssh_written", &[("box", name), ("alias", &alias)])
        );
        println!(
            "{}",
            t(
                "code.editor_steps_jetbrains",
                &[("box", name), ("alias", &alias), ("path", &a.folder)]
            )
        );
    }
    if rec.state != BoxState::Running && !f.json {
        eprintln!(
            "note: {name} is {}; run `ozbox resume {name}` first.",
            rec.state
        );
    }
    Ok(())
}

fn age_text(s: u64) -> String {
    match s {
        0..=59 => format!("{s}s"),
        60..=3599 => format!("{}m", s / 60),
        3600..=86_399 => format!("{}h", s / 3600),
        _ => format!("{}d", s / 86_400),
    }
}

/// `ozbox ps <box>`: what is running, and (with a stop flag) stopping one thing, planned and confirmed.
pub fn run_ps(
    d: &mut Deps,
    name: &BoxName,
    stop_session: Option<&str>,
    stop_pid: Option<u32>,
    f: &Flags,
) -> Result<(), CliError> {
    let rec = running_box(d, name)?;
    let procs = d.agent.code_procs(&rec).map_err(|e| {
        msg(t(
            "code.err_unreachable",
            &[("box", name.as_str()), ("why", &e.to_string())],
        ))
    })?;
    let stop = match (stop_session, stop_pid) {
        (Some(n), None) => Some(Stop::session(n).map_err(CliError::Msg)?),
        (None, Some(p)) => Some(Stop::process(p).map_err(CliError::Msg)?),
        (None, None) => None,
        _ => return Err(msg(t("code.err_stop_both", &[]))),
    };
    let Some(stop) = stop else {
        if f.json {
            println!(
                "{}",
                serde_json::to_string(&json!({ "box": name.as_str(), "ps": procs }))
                    .unwrap_or_default()
            );
            return Ok(());
        }
        println!("{}", t("code.ps_head", &[("box", name.as_str())]));
        if !procs.tmux {
            println!("{}", t("code.ps_no_tmux", &[]));
        }
        if procs.sessions.is_empty() && procs.agents.is_empty() && procs.servers.is_empty() {
            println!("{}", t("code.ps_nothing", &[]));
        }
        if !procs.sessions.is_empty() {
            println!("{}", t("code.ps_sessions", &[]));
            let newest = procs
                .sessions
                .iter()
                .map(|s| s.activity_s)
                .max()
                .unwrap_or(0);
            for s in &procs.sessions {
                println!(
                    "{}",
                    t(
                        "code.ps_session",
                        &[
                            ("name", &s.name),
                            ("state", if s.attached { "attached" } else { "detached" }),
                            ("command", &s.command),
                            ("active", &age_text(newest.saturating_sub(s.activity_s))),
                        ]
                    )
                );
            }
        }
        if !procs.agents.is_empty() {
            println!("{}", t("code.ps_agents", &[]));
            for a in &procs.agents {
                println!(
                    "{}",
                    t(
                        "code.ps_agent",
                        &[
                            ("program", &a.program),
                            ("pid", &a.pid.to_string()),
                            ("age", &age_text(a.age_s))
                        ]
                    )
                );
            }
        }
        if !procs.servers.is_empty() {
            println!("{}", t("code.ps_servers", &[]));
            for s in &procs.servers {
                println!(
                    "{}",
                    t(
                        "code.ps_server",
                        &[
                            ("port", &s.port.to_string()),
                            ("program", &s.program),
                            ("pid", &s.pid.to_string())
                        ]
                    )
                );
            }
        }
        return Ok(());
    };
    // Only what the read showed can be stopped here.
    let known = match &stop {
        Stop::Session(n) => procs.sessions.iter().any(|s| &s.name == n),
        Stop::Process(p) => {
            procs.agents.iter().any(|a| a.pid == *p) || procs.servers.iter().any(|s| s.pid == *p)
        }
    };
    if !known {
        return Err(msg(t(
            "code.err_stop_failed",
            &[("why", "it is not in the list above, or is already gone")],
        )));
    }
    let step = match &stop {
        Stop::Session(n) => t("code.plan_stop_session", &[("name", n)]),
        Stop::Process(p) => t("code.plan_stop_process", &[("pid", &p.to_string())]),
    };
    if !f.json {
        println!(
            "{}",
            t(
                "code.plan_head",
                &[("box", name.as_str()), ("service", "processes")]
            )
        );
        println!("{step}");
    }
    if f.dry_run {
        if f.json {
            println!(
                "{}",
                json!({ "box": name.as_str(), "steps": [step], "dry_run": true })
            );
        } else {
            println!("{}", t("code.dry_run", &[]));
        }
        return Ok(());
    }
    confirm(d, f, name.as_str())?;
    d.agent
        .code_stop(&rec, &stop)
        .map_err(|e| msg(t("code.err_stop_failed", &[("why", &e.to_string())])))?;
    if f.json {
        println!("{}", json!({ "box": name.as_str(), "applied": true }));
    } else {
        println!("{}", t("code.stopped", &[]));
    }
    Ok(())
}

/// `ozbox tunnel setup cloudflare --on-box <box>`: run the Cloudflare tunnel's connector on the box as the box user's own
/// service. Plan, then apply. The token comes in on standard input and goes to the box on standard input; it is kept
/// there in a private file (0600) under the box user's home on /work, and appears in no argument, plan or answer.
pub fn run_connector_on(
    d: &mut Deps,
    name: &BoxName,
    provider: &str,
    public_url: &str,
    token_stdin: bool,
    rc: crate::tunnel_cli::ReplaceCheck<'_>,
    f: &Flags,
) -> Result<(), CliError> {
    if Kind::parse(provider) != Some(Kind::Cloudflare) {
        return Err(msg(t("code.conn_only_cloudflare", &[])));
    }
    let url = public_url.trim().trim_end_matches('/').to_string();
    crate::tunnel::public_host(&url).map_err(|k| msg(t(k, &[])))?;
    if !token_stdin {
        return Err(msg(t("code.conn_need_token_stdin", &[])));
    }
    let rec = running_box(d, name)?;
    let state = d
        .agent
        .code_status(&rec)
        .map_err(|e| msg(e.to_string()))?
        .connector;
    if !state.program {
        return Err(msg(t("code.conn_no_program", &[])));
    }
    let mut steps = vec![
        t("code.conn_step_token", &[]),
        t("code.conn_step_unit", &[]),
    ];
    let exists = state.unit_current || state.active;
    if exists {
        steps.push(t("code.conn_step_replace", &[]));
    }
    steps.push(t("code.conn_step_route", &[("address", &url)]));
    if !f.json {
        println!(
            "{}",
            t(
                "code.conn_head",
                &[("box", name.as_str()), ("address", &url)]
            )
        );
        for s in &steps {
            println!("{s}");
        }
    }
    if f.dry_run {
        if f.json {
            println!(
                "{}",
                json!({ "box": name.as_str(), "connector": "cloudflare", "changes_box": true, "steps": steps, "dry_run": true })
            );
        } else {
            println!("{}", t("code.dry_run", &[]));
        }
        return Ok(());
    }
    confirm(d, f, name.as_str())?;
    // a token already in place is never overwritten without the flag and a word typed at the terminal (not on standard
    // input, which carries the token)
    crate::tunnel_cli::confirm_replace(exists, "cloudflare", rc)?;
    // The token is read only now: a refused plan never reads it. One line, from standard input.
    let mut line = String::new();
    d.input
        .read_line(&mut line)
        .map_err(|_| msg(t("tunnel.token_unreadable", &[])))?;
    let token = line.trim().to_string();
    if !code::token_ok(&token) {
        return Err(msg(t("code.conn_bad_token", &[])));
    }
    d.agent
        .code_change(
            &rec,
            &Change::Connector {
                token: token.clone(),
            },
        )
        .map_err(|e| msg(e.to_string()))?;
    // Kept here, write-only, so an upgrade (which replaces the system disk the box's secrets service lives on) can put the
    // connector back. Best effort: without it the upgrade says the connector needs setting up again.
    let _ = d
        .secrets
        .set(&Service::connector_secret_name(name.as_str()), &token);
    if f.json {
        println!(
            "{}",
            json!({ "box": name.as_str(), "connector": "cloudflare", "applied": true })
        );
    } else {
        println!("{}", t("code.conn_done", &[("box", name.as_str())]));
    }
    Ok(())
}

/// `ozbox tunnel remove --on-box <box>`: stop the connector on the box and delete its token there.
pub fn run_connector_off(d: &mut Deps, name: &BoxName, f: &Flags) -> Result<(), CliError> {
    let rec = running_box(d, name)?;
    let state = d
        .agent
        .code_status(&rec)
        .map_err(|e| msg(e.to_string()))?
        .connector;
    let nothing = !(state.unit_current || state.active);
    if !f.json {
        println!("{}", t("code.conn_off_head", &[("box", name.as_str())]));
        if nothing {
            println!("{}", t("code.conn_off_nothing", &[("box", name.as_str())]));
        } else {
            println!("{}", t("code.conn_off_step", &[]));
        }
    }
    if f.dry_run {
        if f.json {
            println!(
                "{}",
                json!({ "box": name.as_str(), "connector": "cloudflare", "changes_box": !nothing, "dry_run": true })
            );
        } else {
            println!("{}", t("code.dry_run", &[]));
        }
        return Ok(());
    }
    if !nothing {
        confirm(d, f, name.as_str())?;
        d.agent
            .code_change(&rec, &Change::ConnectorOff)
            .map_err(|e| msg(e.to_string()))?;
    }
    let _ = d
        .secrets
        .delete(&Service::connector_secret_name(name.as_str()));
    if f.json {
        println!(
            "{}",
            json!({ "box": name.as_str(), "connector": "cloudflare", "applied": !nothing, "off": true })
        );
    } else {
        println!("{}", t("code.conn_off_done", &[("box", name.as_str())]));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::secrets::MemorySecrets;
    use crate::serve::agent::{AgentError, Conn};
    use ozbox_core::{BoxSpec, Operation, RecordingRunner, Size};
    use std::sync::Mutex;

    /// A box agent whose box is a table: the answer to a status probe, and every change it was asked for.
    struct FakeBox {
        status: Mutex<BoxCode>,
        changes: Mutex<Vec<Change>>,
        fail: Mutex<Option<String>>,
    }

    impl FakeBox {
        fn new(code: BoxCode) -> Arc<Self> {
            Arc::new(Self {
                status: Mutex::new(code),
                changes: Mutex::default(),
                fail: Mutex::default(),
            })
        }
    }

    impl BoxAgent for FakeBox {
        fn metrics_now(
            &self,
            _: &ozbox_core::BoxRecord,
            _: u64,
        ) -> Result<ozbox_core::MetricsSample, AgentError> {
            Err(AgentError::Unsupported("x".into()))
        }
        fn metrics_series(
            &self,
            _: &ozbox_core::BoxRecord,
            _: u64,
            _: u64,
            _: u64,
        ) -> Result<Vec<ozbox_core::MetricsSample>, AgentError> {
            Err(AgentError::Unsupported("x".into()))
        }
        fn selftest(
            &self,
            _: &ozbox_core::BoxRecord,
            _: u64,
        ) -> Result<crate::serve::agent::SelfTest, AgentError> {
            Err(AgentError::Unsupported("x".into()))
        }
        fn incidents(
            &self,
            _: &ozbox_core::BoxRecord,
            _: u64,
            _: u64,
        ) -> Result<Vec<crate::serve::agent::Incident>, AgentError> {
            Err(AgentError::Unsupported("x".into()))
        }
        fn code_status(&self, _: &ozbox_core::BoxRecord) -> Result<BoxCode, AgentError> {
            Ok(*self.status.lock().unwrap_or_else(|e| e.into_inner()))
        }
        fn code_change(&self, _: &ozbox_core::BoxRecord, c: &Change) -> Result<(), AgentError> {
            if let Some(m) = self.fail.lock().unwrap().clone() {
                return Err(AgentError::Unsupported(m));
            }
            self.changes.lock().unwrap().push(c.clone());
            Ok(())
        }
        fn connect_tcp(&self, _: &ozbox_core::BoxRecord, _: u16) -> Result<Conn, AgentError> {
            Err(AgentError::Unreachable("not in this test".into()))
        }
    }

    fn up(program: bool, unit: bool, active: bool) -> code::ServiceState {
        code::ServiceState {
            program,
            unit_current: unit,
            active,
        }
    }

    struct Rig {
        _dir: tempfile::TempDir,
        provider: Box<dyn Provider>,
        agent: Arc<FakeBox>,
        secrets: Arc<MemorySecrets>,
        runner: RecordingRunner,
        settings: PathBuf,
    }

    fn rig(ide: code::ServiceState) -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let provider: Box<dyn Provider> = Box::new(ozbox_provider_fake::open(dir.path()));
        let name = BoxName::new("dev").unwrap();
        let plan = provider
            .plan(&Operation::Create {
                spec: BoxSpec::new(name, Size::S),
            })
            .unwrap();
        provider.apply(&plan).unwrap();
        let agent = FakeBox::new(BoxCode {
            linger: true,
            tmux: true,
            terminals: true,
            ide,
            desktop: up(true, false, false),
            connector: Default::default(),
        });
        let settings = dir.path().join("code.toml");
        Rig {
            _dir: dir,
            provider,
            agent,
            secrets: Arc::new(MemorySecrets::default()),
            runner: RecordingRunner::new(),
            settings,
        }
    }

    fn args(service: Service) -> ServiceArgs {
        ServiceArgs {
            name: BoxName::new("dev").unwrap(),
            service,
            no_open: false,
            port: None,
            public_url: None,
            tunnel: None,
            off: false,
            new_password: false,
            remove_public: false,
        }
    }

    fn go(
        r: &Rig,
        a: &ServiceArgs,
        yes: bool,
        dry: bool,
        tty: bool,
        signin: bool,
    ) -> Result<(), CliError> {
        let mut empty = std::io::empty();
        let mut d = Deps {
            provider: r.provider.as_ref(),
            agent: r.agent.clone(),
            secrets: r.secrets.clone(),
            runner: &r.runner,
            settings_path: Some(r.settings.clone()),
            dashboard_host: Some("ozbox.example.com".into()),
            signin_ready: signin,
            input: &mut empty,
            tty,
            wait: Wait::Return,
        };
        run_service(
            &mut d,
            a,
            &Flags {
                yes,
                dry_run: dry,
                json: false,
            },
        )
    }

    #[test]
    fn a_set_up_service_plans_nothing_on_the_box_and_just_opens() {
        let r = rig(up(true, true, true));
        r.secrets
            .set("ide-password-dev", "abcdef0123456789abcdef0123456789")
            .unwrap();
        go(&r, &args(Service::Ide), true, false, false, false).unwrap();
        assert!(
            r.agent.changes.lock().unwrap().is_empty(),
            "the box was not touched"
        );
        let calls = r.runner.calls();
        assert_eq!(calls.len(), 1, "the browser was asked to open");
        assert!(calls[0]
            .args
            .iter()
            .any(|a| a.starts_with("http://localhost:") && a.contains("/__ozbox/go/")));
    }

    #[test]
    fn an_ide_set_up_by_an_older_version_gets_the_current_terminal_settings_and_keeps_its_password()
    {
        let r = rig(up(true, true, true));
        r.agent.status.lock().unwrap().terminals = false;
        r.secrets
            .set("ide-password-dev", "abcdef0123456789abcdef0123456789")
            .unwrap();
        // it is a change on the box: no terminal and no --yes is refused, and nothing is changed
        assert!(go(&r, &args(Service::Ide), false, false, false, false).is_err());
        assert!(r.agent.changes.lock().unwrap().is_empty());
        // a dry run changes nothing either
        go(&r, &args(Service::Ide), true, true, false, false).unwrap();
        assert!(r.agent.changes.lock().unwrap().is_empty());
        go(&r, &args(Service::Ide), true, false, false, false).unwrap();
        assert_eq!(*r.agent.changes.lock().unwrap(), vec![Change::Terminals]);
        assert_eq!(
            r.secrets.get("ide-password-dev").unwrap().as_deref(),
            Some("abcdef0123456789abcdef0123456789"),
            "the password is not changed"
        );
    }

    #[test]
    fn a_service_that_is_not_set_up_is_planned_confirmed_and_set_up_with_a_new_password_kept_write_only(
    ) {
        let r = rig(up(true, false, false));
        // no terminal and no --yes: refused, nothing changed
        let e = go(&r, &args(Service::Ide), false, false, false, false).unwrap_err();
        assert!(e.to_string().contains("without confirmation"), "{e}");
        assert!(r.agent.changes.lock().unwrap().is_empty());
        // a dry run changes nothing either
        go(&r, &args(Service::Ide), false, true, false, false).unwrap();
        assert!(r.agent.changes.lock().unwrap().is_empty());
        assert!(!r.secrets.exists("ide-password-dev").unwrap());
        go(&r, &args(Service::Ide), true, false, false, false).unwrap();
        let ch = r.agent.changes.lock().unwrap().clone();
        let [Change::Enable { service, password }] = ch.as_slice() else {
            panic!("{ch:?}")
        };
        assert_eq!(*service, Service::Ide);
        assert_eq!(
            r.secrets.get("ide-password-dev").unwrap().as_deref(),
            Some(password.as_str())
        );
        // the password is in no program's arguments
        for c in r.runner.calls() {
            assert!(
                c.args.iter().all(|a| !a.contains(password.as_str())),
                "{:?}",
                c.args
            );
        }
    }

    #[test]
    fn a_failed_setup_stores_no_password_and_a_box_without_the_program_is_refused_up_front() {
        let r = rig(up(true, false, false));
        *r.agent.fail.lock().unwrap() = Some("the box said no".into());
        assert!(go(&r, &args(Service::Ide), true, false, false, false).is_err());
        assert!(!r.secrets.exists("ide-password-dev").unwrap());
        let r = rig(up(false, false, false));
        let e = go(&r, &args(Service::Ide), true, false, false, false).unwrap_err();
        assert!(e.to_string().contains("code-server"), "{e}");
        assert!(r.agent.changes.lock().unwrap().is_empty());
    }

    #[test]
    fn off_removes_the_service_the_password_and_the_public_address() {
        let r = rig(up(true, true, true));
        r.secrets
            .set("ide-password-dev", "abcdef0123456789abcdef0123456789")
            .unwrap();
        let mut s = CodeSettings::default();
        s.set("dev", Service::Ide, "https://ide.example.com", None, None)
            .unwrap();
        s.save(&r.settings).unwrap();
        let mut a = args(Service::Ide);
        a.off = true;
        go(&r, &a, true, false, false, false).unwrap();
        assert_eq!(
            r.agent.changes.lock().unwrap().as_slice(),
            [Change::Disable {
                service: Service::Ide
            }]
        );
        assert!(!r.secrets.exists("ide-password-dev").unwrap());
        assert!(CodeSettings::load(&r.settings).unwrap().public.is_empty());
    }

    #[test]
    fn serving_on_your_own_address_needs_sign_in_a_tunnel_that_can_carry_it_and_saves_the_host() {
        let r = rig(up(true, true, true));
        r.secrets
            .set("ide-password-dev", "abcdef0123456789abcdef0123456789")
            .unwrap();
        let mut a = args(Service::Ide);
        a.public_url = Some("https://ide.example.com".into());
        // no tunnel named
        assert!(go(&r, &a, true, false, false, true)
            .unwrap_err()
            .to_string()
            .contains("--tunnel"));
        a.tunnel = Some("cloudflare".into());
        // the dashboard is not in sign-in mode
        assert!(go(&r, &a, true, false, false, false)
            .unwrap_err()
            .to_string()
            .contains("sign-in mode"));
        // a tunnel that serves one address
        a.tunnel = Some("tailscale-funnel".into());
        assert!(go(&r, &a, true, false, false, true)
            .unwrap_err()
            .to_string()
            .contains("one address"));
        // the dashboard's own name
        a.tunnel = Some("cloudflare".into());
        a.public_url = Some("https://ozbox.example.com".into());
        assert!(go(&r, &a, true, false, false, true).is_err());
        assert!(
            CodeSettings::load(&r.settings).unwrap().public.is_empty(),
            "nothing saved by a refusal"
        );
        a.public_url = Some("https://ide.example.com".into());
        go(&r, &a, true, false, false, true).unwrap();
        assert_eq!(
            CodeSettings::load(&r.settings)
                .unwrap()
                .host_of("dev", Service::Ide),
            Some("ide.example.com")
        );
        assert!(
            r.runner.calls().is_empty(),
            "serving on an address opens no local browser"
        );
    }

    #[test]
    fn a_stopped_or_missing_box_is_refused() {
        let r = rig(up(true, true, true));
        let mut a = args(Service::Ide);
        a.name = BoxName::new("nope").unwrap();
        assert!(go(&r, &a, true, false, false, false).is_err());
    }

    #[test]
    fn needs_change_follows_what_the_box_and_the_store_say() {
        assert!(!needs_change(up(true, true, true), true, false));
        assert!(needs_change(up(true, true, true), true, true));
        assert!(needs_change(up(true, true, true), false, false));
        assert!(needs_change(up(true, true, false), true, false));
        assert!(needs_change(up(true, false, true), true, false));
    }

    #[test]
    fn the_browser_is_opened_with_the_address_as_one_argument() {
        let r = RecordingRunner::new();
        assert!(open_url(&r, "http://localhost:5000/__ozbox/go/abc"));
        let c = r.calls();
        assert_eq!(
            c.last().unwrap().args.last().map(String::as_str),
            Some("http://localhost:5000/__ozbox/go/abc")
        );
    }

    #[test]
    fn open_writes_the_ssh_entry_and_builds_the_documented_link() {
        let r = rig(up(true, true, true));
        let dir = tempfile::tempdir().unwrap();
        let inputs = RouteInputs {
            domain: Some("example.com".into()),
            ..Default::default()
        };
        let mut empty = std::io::empty();
        let mut d = Deps {
            provider: r.provider.as_ref(),
            agent: r.agent.clone(),
            secrets: r.secrets.clone(),
            runner: &r.runner,
            settings_path: None,
            dashboard_host: None,
            signin_ready: false,
            input: &mut empty,
            tty: false,
            wait: Wait::Return,
        };
        let a = OpenArgs {
            name: BoxName::new("dev").unwrap(),
            editor: Editor::Vscode,
            print: false,
            folder: "/work/repos".into(),
        };
        let f = Flags {
            yes: true,
            dry_run: false,
            json: true,
        };
        run_open(&mut d, &a, &inputs, Some(dir.path().to_path_buf()), &f).unwrap();
        let cfg = std::fs::read_to_string(dir.path().join("ozbox/config")).unwrap();
        assert!(cfg.contains("Host ozbox-dev"), "{cfg}");
        let c = r.runner.calls();
        assert_eq!(
            c.last().unwrap().args.last().map(String::as_str),
            Some("vscode://vscode-remote/ssh-remote+ozbox-dev/work/repos")
        );
        // a dry run writes nothing
        let dir2 = tempfile::tempdir().unwrap();
        let f = Flags {
            yes: true,
            dry_run: true,
            json: true,
        };
        run_open(&mut d, &a, &inputs, Some(dir2.path().to_path_buf()), &f).unwrap();
        assert!(!dir2.path().join("ozbox/config").exists());
    }

    #[test]
    fn every_message_key_used_here_exists() {
        let keys = crate::messages::keys();
        for k in [
            "code.plan_head",
            "code.plan_nothing",
            "code.plan_enable",
            "code.plan_password",
            "code.plan_disable",
            "code.plan_forward",
            "code.plan_public",
            "code.done",
            "code.off_done",
            "code.open_at",
            "code.public_saved",
            "code.public_guide_cloudflare",
            "code.public_guide_caddy",
            "code.err_not_running",
            "code.err_confirm",
            "code.err_no_password",
            "code.ssh_written",
            "code.browser_note_title",
            "code.browser_keys_mac",
            "code.browser_keys_other",
            "code.browser_tmux",
            "code.browser_chromium",
            "code.browser_firefox",
            "code.browser_safari",
            "code.editor_unverified",
            "code.editor_steps_jetbrains",
            "code.forward_down",
            "code.forward_up",
            "code.keep_running",
        ] {
            assert!(keys.contains(&k), "{k}");
        }
    }

    fn connector_deps<'a>(r: &'a Rig, input: &'a mut dyn std::io::BufRead, tty: bool) -> Deps<'a> {
        Deps {
            provider: r.provider.as_ref(),
            agent: r.agent.clone(),
            secrets: r.secrets.clone(),
            runner: &r.runner,
            settings_path: Some(r.settings.clone()),
            dashboard_host: None,
            signin_ready: false,
            input,
            tty,
            wait: Wait::Return,
        }
    }

    const TOKEN: &str = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";

    #[test]
    fn the_tunnel_on_a_box_is_planned_confirmed_and_the_token_is_read_only_after_that() {
        let r = rig(up(true, false, false));
        r.agent.status.lock().unwrap().connector = up(true, false, false);
        let name = BoxName::new("dev").unwrap();
        let fl = |yes, dry| Flags {
            yes,
            dry_run: dry,
            json: false,
        };
        let url = "https://ide.example.com";
        // no terminal and no --yes: refused before the token is read
        let mut input = std::io::Cursor::new(format!("{TOKEN}\n").into_bytes());
        let e = run_connector_on(
            &mut connector_deps(&r, &mut input, false),
            &name,
            "cloudflare",
            url,
            true,
            crate::tunnel_cli::ReplaceCheck::none(),
            &fl(false, false),
        )
        .unwrap_err();
        assert!(e.to_string().contains("without confirmation"), "{e}");
        assert_eq!(input.position(), 0, "the token was not read");
        // a dry run reads nothing and changes nothing
        run_connector_on(
            &mut connector_deps(&r, &mut input, false),
            &name,
            "cloudflare",
            url,
            true,
            crate::tunnel_cli::ReplaceCheck::none(),
            &fl(true, true),
        )
        .unwrap();
        assert_eq!(input.position(), 0);
        assert!(r.agent.changes.lock().unwrap().is_empty());
        // applied
        run_connector_on(
            &mut connector_deps(&r, &mut input, false),
            &name,
            "cloudflare",
            url,
            true,
            crate::tunnel_cli::ReplaceCheck::none(),
            &fl(true, false),
        )
        .unwrap();
        assert_eq!(
            r.agent.changes.lock().unwrap().as_slice(),
            [Change::Connector {
                token: TOKEN.into()
            }]
        );
        // refusals: another provider, no --token-stdin, a token with odd characters, an image without the program
        let mut none = std::io::empty();
        assert!(run_connector_on(
            &mut connector_deps(&r, &mut none, false),
            &name,
            "ngrok",
            url,
            true,
            crate::tunnel_cli::ReplaceCheck::none(),
            &fl(true, false)
        )
        .is_err());
        assert!(run_connector_on(
            &mut connector_deps(&r, &mut none, false),
            &name,
            "cloudflare",
            url,
            false,
            crate::tunnel_cli::ReplaceCheck::none(),
            &fl(true, false)
        )
        .is_err());
        let mut bad = std::io::Cursor::new(b"abc'; rm -rf ~; echo \n".to_vec());
        assert!(run_connector_on(
            &mut connector_deps(&r, &mut bad, false),
            &name,
            "cloudflare",
            url,
            true,
            crate::tunnel_cli::ReplaceCheck::none(),
            &fl(true, false)
        )
        .is_err());
        r.agent.status.lock().unwrap().connector = up(false, false, false);
        let mut again = std::io::Cursor::new(format!("{TOKEN}\n").into_bytes());
        let e = run_connector_on(
            &mut connector_deps(&r, &mut again, false),
            &name,
            "cloudflare",
            url,
            true,
            crate::tunnel_cli::ReplaceCheck::none(),
            &fl(true, false),
        )
        .unwrap_err();
        assert!(e.to_string().contains("no cloudflared"), "{e}");
        assert_eq!(
            r.agent.changes.lock().unwrap().len(),
            1,
            "nothing else was sent"
        );
    }

    #[test]
    fn removing_the_tunnel_from_a_box_plans_nothing_when_none_is_there() {
        let r = rig(up(true, false, false));
        let name = BoxName::new("dev").unwrap();
        let fl = Flags {
            yes: true,
            dry_run: false,
            json: false,
        };
        let mut none = std::io::empty();
        run_connector_off(&mut connector_deps(&r, &mut none, false), &name, &fl).unwrap();
        assert!(r.agent.changes.lock().unwrap().is_empty());
        r.agent.status.lock().unwrap().connector = up(true, true, true);
        run_connector_off(&mut connector_deps(&r, &mut none, false), &name, &fl).unwrap();
        assert_eq!(
            r.agent.changes.lock().unwrap().as_slice(),
            [Change::ConnectorOff]
        );
    }
}
