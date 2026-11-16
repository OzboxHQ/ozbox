//! Running a parsed command: build the provider, plan, show, confirm, apply, report.

use std::fmt;
use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;

use ozbox_core::{
    BoxRecord, BoxSpec, CommandRunner, Operation, Plan, Provider, Risk, Size, SystemRunner,
};
use serde::Serialize;

use crate::cli::{Cli, Command, ProviderKind};
use crate::config::Config;
use crate::serve::BoxAgent;
use crate::settings::Settings;
use crate::sshconfig::{self, RouteInputs};
use crate::tools_cli;

mod admin;
mod adopt;
mod adopt_key;
mod backup;
mod box_guard;
mod box_secrets;
mod state;
pub(crate) mod upgrade;

/// What the CLI reports. Core errors print as they are; the rest are the CLI's own refusals.
#[derive(Debug)]
pub enum CliError {
    Core(ozbox_core::Error),
    Msg(String),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::Core(e) => write!(f, "{e}"),
            CliError::Msg(m) => f.write_str(m),
        }
    }
}

impl From<ozbox_core::Error> for CliError {
    fn from(e: ozbox_core::Error) -> Self {
        CliError::Core(e)
    }
}

type Result<T> = std::result::Result<T, CliError>;

/// Point OpenTofu at the plugin cache `ozbox init` filled, so creating a box does not download the plugin again (and
/// survives a GitHub outage). Set once, before anything else runs; a value the person set wins.
fn use_plugin_cache() {
    if std::env::var_os("TF_PLUGIN_CACHE_DIR").is_some() {
        return;
    }
    let dir = std::env::var_os("OZBOX_PLUGIN_CACHE_DIR")
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|h| h.join(".cache/ozbox/tofu-plugins")));
    if let Some(d) = dir.filter(|d| d.is_dir()) {
        std::env::set_var("TF_PLUGIN_CACHE_DIR", d);
    }
}

pub fn run(cli: Cli) -> Result<()> {
    use_plugin_cache();
    crate::infra_cli::set_dev_flag(cli.dev_modules);
    let (config, source) = Config::load_found()?;
    if let Some(w) = crate::config::both_files_warning(&Config::candidates()) {
        eprintln!("{w}");
    }
    let kind = match (cli.provider, config.provider_kind()?) {
        (Some(k), _) | (None, Some(k)) => k,
        (None, None) => ProviderKind::Fake,
    };
    // `[aws] profile` applies to every aws call, every tofu run and the ssh route (their `aws ssm` ProxyCommand), not
    // only to one command: they all inherit it from here. A profile the environment already chose wins.
    if let Some(p) =
        crate::config::aws_profile_to_export(&config, std::env::var("AWS_PROFILE").ok().as_deref())
    {
        std::env::set_var("AWS_PROFILE", p);
    }
    if let Some(n) = crate::config::ssh_timeout_to_export(
        &config,
        std::env::var("OZBOX_SSH_CONNECT_TIMEOUT").ok().as_deref(),
    ) {
        std::env::set_var("OZBOX_SSH_CONNECT_TIMEOUT", n);
    }
    let provider_configured = cli.provider.is_some() || config.provider.is_some();
    let json = cli.json;

    if let Command::Adopt { name } = &cli.command {
        return adopt::command(kind, &config, name, &flags(cli.yes, cli.dry_run, json));
    }
    if let Command::BrowserWorker = &cli.command {
        return crate::browse_cli::run_worker();
    }
    if let Command::AgentMcp { command } = &cli.command {
        return crate::agent_mcp_cli::run(command, json);
    }
    if let Command::BrowserLaunch = &cli.command {
        crate::browser_launch::serve_stdio();
        return Ok(());
    }
    if let Command::BrowserSetup { args } = &cli.command {
        return crate::browser_launch::run_setup(args);
    }
    if let Command::Capped { args } = &cli.command {
        match crate::capped::run(args) {
            Ok(code) => std::process::exit(code),
            Err(e) => return Err(CliError::Msg(e)),
        }
    }
    if let Command::HostGuard { words } = &cli.command {
        let o = crate::host_guard_cli::run(words, json);
        println!("{}", o.text);
        if !o.ok {
            std::process::exit(1);
        }
        return Ok(());
    }
    if let Command::State { command } = &cli.command {
        return state::command(kind, &config, command, &flags(cli.yes, cli.dry_run, json));
    }
    match &cli.command {
        Command::Sizes => return sizes(json),
        Command::Providers => return providers(json),
        Command::Infra => return infra_show(kind, &config, json),
        _ => {}
    }

    // Agent runs and approvals are local to this computer's task store; they need no provider.
    match &cli.command {
        Command::Run { command } => {
            let f = crate::runs_cli::Flags {
                json,
                dry_run: cli.dry_run,
                yes: cli.yes,
            };
            return crate::runs_cli::run(command, &f).map_err(|e| CliError::Msg(e.to_string()));
        }
        Command::Orch { command } => {
            let f = crate::runs_cli::Flags {
                json,
                dry_run: cli.dry_run,
                yes: cli.yes,
            };
            return crate::orch_cli::run(command, &f).map_err(|e| CliError::Msg(e.to_string()));
        }
        Command::Memory { command } => {
            return crate::memory_cli::run_memory(command, json);
        }
        Command::Skills { command } => {
            return crate::memory_cli::run_skills(command, json, cli.yes);
        }
        Command::Approvals { command } => {
            let f = crate::runs_cli::Flags {
                json,
                dry_run: cli.dry_run,
                yes: cli.yes,
            };
            return crate::runs_cli::approvals(command, &f)
                .map_err(|e| CliError::Msg(e.to_string()));
        }
        Command::Permissions { command } => {
            let f = crate::runs_cli::Flags {
                json,
                dry_run: cli.dry_run,
                yes: cli.yes,
            };
            return crate::perm_cli::permissions(command, &f)
                .map_err(|e| CliError::Msg(e.to_string()));
        }
        Command::Audit { command } => {
            let f = crate::runs_cli::Flags {
                json,
                dry_run: cli.dry_run,
                yes: cli.yes,
            };
            return crate::perm_cli::audit(command, &f).map_err(|e| CliError::Msg(e.to_string()));
        }
        _ => {}
    }

    if let Command::Init {
        profile,
        region,
        budget,
        alert_email,
        alert_from,
        two_factor,
        access,
        issuer_package,
        issuer_package_sha256,
    } = &cli.command
    {
        let explicit = cli.provider;
        return crate::init_cli::run_real(&crate::init_cli::Args {
            provider: explicit.map(|k| format!("{k:?}").to_lowercase()),
            profile: profile.clone(),
            region: region.clone(),
            budget: *budget,
            alert_email: alert_email.clone(),
            alert_from: alert_from.clone(),
            two_factor: *two_factor,
            access: access.clone(),
            issuer_package: issuer_package.clone(),
            issuer_package_sha256: issuer_package_sha256.clone(),
            yes: cli.yes,
            dry_run: cli.dry_run,
            json,
        })
        .map_err(CliError::Msg);
    }

    if let Command::Harden {
        profile,
        region,
        guardduty_runtime,
        session_logs,
        patching,
        retention_days,
        lock_mode,
    } = &cli.command
    {
        return crate::init_cli::run_harden_real(&crate::init_cli::HardenArgs {
            profile: profile.clone(),
            region: region.clone(),
            opts: crate::init::SecurityOpts {
                guardduty_runtime: *guardduty_runtime,
                session_logs: *session_logs,
                patching: *patching,
                retention_days: *retention_days,
                lock_mode: lock_mode.to_ascii_uppercase(),
            },
            yes: cli.yes,
            dry_run: cli.dry_run,
            json,
        })
        .map_err(CliError::Msg);
    }

    if let Command::Schedule { command } = &cli.command {
        let fl = crate::cli::ScheduleFlags {
            yes: cli.yes,
            dry_run: cli.dry_run,
            json,
        };
        return crate::sched_cli::run_schedule(command, &fl);
    }
    if let Command::Trigger { command } = &cli.command {
        let fl = crate::cli::ScheduleFlags {
            yes: cli.yes,
            dry_run: cli.dry_run,
            json,
        };
        return crate::sched_cli::run_trigger(command, &fl);
    }
    if let Command::Secrets { command } = &cli.command {
        return crate::secrets_cli::run(command, json, cli.yes, cli.dry_run);
    }
    if let Command::Env { command } = &cli.command {
        // `env run` starts a program and `env policy set` writes a declaration: neither has a dry run, so the flag is
        // refused rather than ignored
        if cli.dry_run {
            return Err(CliError::Msg(crate::messages::t("secrets.no_dry_run", &[])));
        }
        return crate::workload_cli::run_env(command, json);
    }
    if let Command::Guard { command } = &cli.command {
        return crate::guard_cli::run(command, json);
    }
    if let Command::Auth { command } = &cli.command {
        return crate::auth_cli::run(command, cli.yes);
    }
    if let Command::Tunnel { command } = &cli.command {
        // `--on-box` changes a box, so it needs the provider and the box agent: it is handled below with the other
        // box commands. Everything else here is local to this computer.
        if !matches!(
            command,
            crate::cli::TunnelCommand::Setup {
                on_box: Some(_),
                ..
            } | crate::cli::TunnelCommand::Remove { on_box: Some(_) }
        ) {
            return crate::tunnel_cli::run(command, json);
        }
    }
    if let Command::Models { command } = &cli.command {
        return crate::models_cli::run(command, cli.yes, cli.dry_run, json);
    }
    if let Command::Cost { command } = &cli.command {
        let f = crate::cost_cli::Flags {
            dry_run: cli.dry_run,
            json,
        };
        return crate::cost_cli::run(command, kind, &route_inputs(&config), &f);
    }
    if let Command::Plugin { command } = &cli.command {
        return crate::plugin_cli::run(command, cli.yes, cli.dry_run, json);
    }
    if let Command::Telemetry { command } = &cli.command {
        return crate::telemetry_cli::run(command, cli.yes, cli.dry_run, json);
    }
    if let Command::Dashboard { command } = &cli.command {
        return crate::dashboard_cli::run(command, cli.yes, cli.dry_run, json);
    }

    if let Command::Serve {
        bind,
        port,
        public_behind_tunnel,
        auth_config,
        public_url,
        tunnel,
        code_port,
    } = &cli.command
    {
        // Fail on a bad bind address before touching the provider.
        crate::serve::parse_bind(bind).map_err(CliError::Msg)?;
        // On a box with no provider configured the dashboard shows this box and never the simulated one.
        let choice = crate::this_box::choose(
            cli.provider,
            config.provider_kind()?,
            crate::this_box::on_a_box(),
        );
        if choice.is_demo() {
            warn_if_simulated(&source, provider_configured);
        }
        let provider = provider_for(choice, &config)?;
        let settings_path = Settings::path();
        let settings = match &settings_path {
            Some(p) => Settings::load_from(p)?,
            None => Settings::default(),
        };
        let setup = crate::serve::Setup {
            domain: config.domain.clone(),
            settings,
            settings_path,
            route_inputs: route_inputs(&config),
            init_paths: crate::init::InitPaths::detect(),
            public: crate::auth_cli::public_setup(
                *public_behind_tunnel || public_url.is_some(),
                auth_config.as_deref(),
                public_url.as_deref(),
            )
            .map_err(CliError::Msg)?,
            tunnel: crate::tunnel_cli::for_serve(tunnel.as_deref(), public_url.as_deref())
                .map_err(CliError::Msg)?,
            code_port: *code_port,
            rebuild: Some(std::sync::Arc::new(|| {
                let config = Config::load().map_err(|e| e.to_string())?;
                let choice = crate::this_box::choose(
                    None,
                    config.provider_kind().map_err(|e| e.to_string())?,
                    crate::this_box::on_a_box(),
                );
                let provider = provider_for(choice, &config).map_err(|e| e.to_string())?;
                let mut inputs = route_inputs(&config);
                inputs.domain = config.domain.clone().filter(|d| !d.is_empty());
                Ok(crate::serve::setup::Rebuilt {
                    provider,
                    simulated: choice.is_demo(),
                    inputs,
                    domain: config.domain.clone(),
                })
            })),
        };
        return crate::serve::serve(provider, choice.is_demo(), setup, bind, *port)
            .map_err(CliError::Msg);
    }

    warn_if_simulated(&source, provider_configured);
    // An upgrade of an AWS box with no pinned approver pins this computer's key in the new machine (the provider reads it
    // from here); every other command builds the provider as it always has.
    let provider = if matches!(cli.command, Command::Upgrade { .. }) && kind == ProviderKind::Aws {
        let mut cfg = aws_config(&config, false)?;
        if std::env::var("OZBOX_APPROVAL_PIN").as_deref() != Ok("off") {
            cfg.upgrade_pin = crate::approval_key_cli::pin_for_create(
                crate::approval_key_cli::keychain().as_ref(),
            )
            .ok()
            .flatten();
        }
        if matches!(
            cli.command,
            Command::Upgrade {
                use_fleet_key: true,
                ..
            }
        ) {
            if cfg.secrets_key_arn.as_deref().is_none_or(str::is_empty) {
                return Err(CliError::Msg(crate::messages::t(
                    "upgrade.no_fleet_key",
                    &[],
                )));
            }
            cfg.upgrade_use_fleet_key = true;
        }
        if let Some(dir) = ssh_dir() {
            cfg.upgrade_ingress_pin =
                crate::ingress_guard::label_for_create(&ozbox_core::SystemRunner, &dir)
                    .ok()
                    .flatten();
        }
        Box::new(ozbox_provider_aws::open(cfg)) as Box<dyn Provider>
    } else if matches!(cli.command, Command::Upgrade { .. }) && kind == ProviderKind::Hcloud {
        // The same for Hetzner, whose upgrade now replaces the server and so can deliver the pin in its new first boot.
        let mut cfg = hcloud_config(&config, false)?;
        if std::env::var("OZBOX_APPROVAL_PIN").as_deref() != Ok("off") {
            cfg.upgrade_pin = crate::approval_key_cli::pin_for_create(
                crate::approval_key_cli::keychain().as_ref(),
            )
            .ok()
            .flatten();
        }
        if let Some(dir) = ssh_dir() {
            cfg.upgrade_ingress_pin =
                crate::ingress_guard::label_for_create(&ozbox_core::SystemRunner, &dir)
                    .ok()
                    .flatten();
        }
        Box::new(ozbox_provider_hcloud::open(cfg)) as Box<dyn Provider>
    } else {
        build_provider(kind, &config)?
    };
    let p: &dyn Provider = provider.as_ref();
    let tf = tools_cli::Flags {
        yes: cli.yes,
        dry_run: cli.dry_run,
        json,
    };

    match cli.command {
        Command::Sizes
        | Command::Infra
        | Command::Providers
        | Command::Serve { .. }
        | Command::Auth { .. }
        | Command::Schedule { .. }
        | Command::Trigger { .. }
        | Command::Secrets { .. }
        | Command::Env { .. }
        | Command::Guard { .. }
        | Command::Dashboard { .. }
        | Command::Models { .. }
        | Command::Cost { .. }
        | Command::Run { .. }
        | Command::Orch { .. }
        | Command::Adopt { .. }
        | Command::State { .. }
        | Command::HostGuard { .. }
        | Command::Capped { .. }
        | Command::BrowserWorker
        | Command::AgentMcp { .. }
        | Command::BrowserLaunch
        | Command::BrowserSetup { .. }
        | Command::Memory { .. }
        | Command::Skills { .. }
        | Command::Approvals { .. }
        | Command::Permissions { .. }
        | Command::Audit { .. }
        | Command::Telemetry { .. }
        | Command::Plugin { .. }
        | Command::Init { .. }
        | Command::Harden { .. } => Ok(()),
        Command::Mesh { command } => {
            let boxes = p
                .list()?
                .into_iter()
                .map(|r| r.spec.name.to_string())
                .collect();
            crate::mesh_cli::run(
                &command,
                boxes,
                crate::mesh_cli::Flags {
                    yes: cli.yes,
                    dry_run: cli.dry_run,
                    json,
                },
            )
        }
        Command::Tunnel { command } => {
            let agent = crate::serve::agent_for(kind == ProviderKind::Fake, route_inputs(&config));
            let stdin = std::io::stdin();
            let mut lock = stdin.lock();
            let mut deps = code_deps(p, agent, &config, &mut lock, std::io::stdin().is_terminal());
            let fl = crate::code_cli::Flags {
                yes: cli.yes,
                dry_run: cli.dry_run,
                json,
            };
            match command {
                crate::cli::TunnelCommand::Setup {
                    tunnel_provider,
                    public_url,
                    token_stdin,
                    on_box: Some(name),
                    replace,
                    ..
                } => {
                    let mut tty = crate::tunnel_cli::tty_reader();
                    crate::code_cli::run_connector_on(
                        &mut deps,
                        &name,
                        &tunnel_provider,
                        &public_url,
                        token_stdin,
                        crate::tunnel_cli::ReplaceCheck::new(replace, tty.as_mut()),
                        &fl,
                    )
                }
                crate::cli::TunnelCommand::Remove { on_box: Some(name) } => {
                    crate::code_cli::run_connector_off(&mut deps, &name, &fl)
                }
                // handled before the provider was built
                _ => Ok(()),
            }
        }
        Command::Ide { name, code } => code_command(
            p,
            kind,
            &config,
            name,
            crate::code::Service::Ide,
            code,
            &flags(cli.yes, cli.dry_run, json),
        ),
        Command::Desktop { name, code } => code_command(
            p,
            kind,
            &config,
            name,
            crate::code::Service::Desktop,
            code,
            &flags(cli.yes, cli.dry_run, json),
        ),
        Command::Ps {
            name,
            stop_session,
            stop_pid,
        } => {
            let agent = crate::serve::agent_for(kind == ProviderKind::Fake, route_inputs(&config));
            let stdin = std::io::stdin();
            let mut lock = stdin.lock();
            let mut deps = code_deps(p, agent, &config, &mut lock, std::io::stdin().is_terminal());
            crate::code_cli::run_ps(
                &mut deps,
                &name,
                stop_session.as_deref(),
                stop_pid,
                &crate::code_cli::Flags {
                    yes: cli.yes,
                    dry_run: cli.dry_run,
                    json,
                },
            )
        }
        Command::Open {
            name,
            editor,
            print,
            folder,
        } => {
            let editor = crate::code::editors::Editor::parse(&editor).ok_or_else(|| {
                CliError::Msg(format!("{editor} is not an editor ozbox can open"))
            })?;
            let agent = crate::serve::agent_for(kind == ProviderKind::Fake, route_inputs(&config));
            let mut none = std::io::empty();
            let mut deps = code_deps(p, agent, &config, &mut none, false);
            crate::code_cli::run_open(
                &mut deps,
                &crate::code_cli::OpenArgs {
                    name,
                    editor,
                    print,
                    folder,
                },
                &route_inputs(&config),
                ssh_dir(),
                &crate::code_cli::Flags {
                    yes: cli.yes,
                    dry_run: cli.dry_run,
                    json,
                },
            )
        }
        Command::Backup { command } => backup::command(
            p,
            kind,
            &config,
            command,
            &flags(cli.yes, cli.dry_run, json),
        ),
        Command::Tools { command } => tools_command(p, kind, &config, command, &tf),
        Command::Profile { command } => profile_command(p, kind, &config, command, &tf),
        Command::List => list(p, json),
        Command::Show { name } => {
            let rec = p
                .get(&name)?
                .ok_or_else(|| ozbox_core::Error::NotFound(name.to_string()))?;
            if json {
                print_json(&rec)
            } else {
                print_record(&rec);
                Ok(())
            }
        }
        Command::Connect {
            name,
            desktop,
            shell,
            ssh,
            write,
            route,
            push_key,
            web: _,
        } => connect(
            p,
            &config,
            &name,
            &Mode {
                desktop,
                shell,
                ssh,
                write,
                route,
                push_key,
            },
            json,
        ),
        Command::Create {
            name,
            size,
            disk,
            region,
            image,
            labels,
            tools,
            profile,
            allow_first_boot_mismatch,
        } => {
            let settings = load_settings()?;
            let profile = match &profile {
                Some(n) => Some(tools_cli::profile_load(n)?),
                None => None,
            };
            let pbox = profile
                .as_ref()
                .map(|p| p.defaults.clone())
                .unwrap_or_default();
            let size = match (size, &pbox.size) {
                (Some(s), _) => s,
                (None, Some(s)) => s
                    .parse()
                    .map_err(|e: ozbox_core::Error| CliError::Msg(e.to_string()))?,
                (None, None) => settings.defaults.size,
            };
            let mut spec = BoxSpec::new(name.clone(), size);
            spec.work_disk_gb = disk
                .or(pbox.disk_gb)
                .unwrap_or(settings.defaults.work_disk_gb);
            spec.region = region;
            spec.image = image;
            spec.labels = pbox.labels.clone().into_iter().collect();
            if pbox.always_on == Some(true) {
                spec.labels.insert("ozbox-always-on".into(), "true".into());
            }
            spec.labels.extend(labels);
            // The box's first approver is this computer's key, pinned from here (never enrolled from inside the box).
            if kind != ProviderKind::Fake
                && !spec.labels.contains_key(crate::approval_key::PIN_LABEL)
            {
                match crate::approval_key_cli::pin_for_create(
                    crate::approval_key_cli::keychain().as_ref(),
                ) {
                    Ok(Some(v)) => {
                        spec.labels.insert(crate::approval_key::PIN_LABEL.into(), v);
                        if !json {
                            eprintln!(
                                "{}",
                                crate::messages::t(
                                    "approval_key.pinned",
                                    &[("id", crate::approval_key::PIN_ID)]
                                )
                            );
                        }
                    }
                    Ok(None) => {}
                    Err(why) => eprintln!(
                        "{}",
                        crate::messages::t("approval_key.not_pinned", &[("why", &why)])
                    ),
                }
            }
            // This computer's SSH key for the box's ingress account (the way it reaches the box's secrets service), pinned from
            // here so no process of the box user can add one.
            if kind != ProviderKind::Fake && !spec.labels.contains_key(ozbox_core::INGRESS_LABEL) {
                if let Some(dir) = ssh_dir() {
                    match crate::ingress_guard::label_for_create(&ozbox_core::SystemRunner, &dir) {
                        Ok(Some(v)) => {
                            spec.labels.insert(ozbox_core::INGRESS_LABEL.into(), v);
                        }
                        Ok(None) => {}
                        Err(why) => eprintln!(
                            "{}",
                            crate::messages::t("ingress.not_pinned", &[("why", &why)])
                        ),
                    }
                }
            }
            // Tools: what was named, plus the profile's; on a terminal with neither, a checklist per group.
            let mut wanted: Vec<String> = profile.map(|p| p.tools).unwrap_or_default();
            wanted.extend(tools);
            let interactive = wanted.is_empty()
                && !cli.yes
                && !cli.dry_run
                && !json
                && std::io::stdin().is_terminal();
            let ids = if interactive {
                tools_cli::choose_interactively()?
            } else {
                tools_cli::expand_ids_or_empty(&wanted)?
            };
            let f = flags(cli.yes, cli.dry_run, json);
            let created = !cli.dry_run;
            // The image and this program must render the same first boot (one version, ADR 0036): checked against the
            // image's signed release before anything is planned.
            let first_boot_notes = if kind == ProviderKind::Fake {
                Vec::new()
            } else {
                let section = match kind {
                    ProviderKind::Aws => config.aws.as_ref(),
                    ProviderKind::Hcloud => config.hcloud.as_ref(),
                    _ => None,
                };
                let image = spec
                    .image
                    .clone()
                    .or_else(|| section.and_then(|s| s.image.clone()));
                let region = spec
                    .region
                    .clone()
                    .or_else(|| section.and_then(|s| s.region.clone()));
                // No image named anywhere: on AWS the newest verified Oz image (the account's own, else the project's
                // public one). Nothing unverified is ever picked this way; naming an image is the way to take another.
                let image = match image {
                    None if kind == ProviderKind::Aws => {
                        let id = default_create_image(p, region.as_deref(), json)?;
                        spec.image = Some(id.clone());
                        Some(id)
                    }
                    other => other,
                };
                match image {
                    Some(image) => {
                        let info = p.image_info(&image, region.as_deref()).ok();
                        upgrade::first_boot_gate(
                            info.as_ref(),
                            &image,
                            &crate::infra_cli::effective_first_boot(),
                            allow_first_boot_mismatch,
                        )
                        .map_err(CliError::Msg)?
                    }
                    None => Vec::new(),
                }
            };
            mutate_with_notes(p, Operation::Create { spec }, &f, first_boot_notes)?;
            if created && !ids.is_empty() {
                tools_cli::after_create(
                    p,
                    kind == ProviderKind::Fake,
                    &route_inputs(&config),
                    &name,
                    ids,
                    cli.yes || interactive,
                    json,
                )?;
            }
            Ok(())
        }
        Command::Upgrade {
            name,
            image,
            allow_unverified_image,
            accept_new_secrets_store,
            no_pre_upgrade_snapshot,
            reprovision,
            allow_first_boot_mismatch,
            use_fleet_key,
            strict_checkpoint,
            legacy_checkpoint,
        } => {
            // On AWS the store's fate is read from the box's root, never from the box user's SSH answer
            let root_fn = |rec: &ozbox_core::BoxRecord| aws_root_facts(&config, rec);
            let root: Option<upgrade::RootFacts<'_>> =
                (kind == ProviderKind::Aws).then_some(&root_fn);
            upgrade::command(
                p,
                kind == ProviderKind::Fake,
                route_inputs(&config),
                name,
                image,
                allow_unverified_image,
                accept_new_secrets_store,
                no_pre_upgrade_snapshot,
                upgrade::FirstBootOpts {
                    ours: crate::infra_cli::effective_first_boot(),
                    reprovision,
                    allow_mismatch: allow_first_boot_mismatch,
                    // the sandbox's machines are simulated and have no first boot to look at, unless one is asked for
                    enabled: kind != ProviderKind::Fake || reprovision,
                },
                crate::quiesce::Mode {
                    strict: strict_checkpoint,
                    legacy: legacy_checkpoint,
                },
                use_fleet_key,
                root,
                &flags(cli.yes, cli.dry_run, json),
            )
        }
        Command::AdoptFleetKey { name, cancel } => {
            if kind != ProviderKind::Aws {
                return Err(CliError::Msg(crate::messages::t(
                    "adopt_key.err_aws_only",
                    &[],
                )));
            }
            let backend = std::sync::Arc::new(ozbox_provider_aws::AwsBackend::new(
                std::sync::Arc::new(SystemRunner),
                aws_config(&config, false)?,
            ));
            let agent = crate::serve::agent_for(false, route_inputs(&config));
            let configured = backend.configured_fleet_key();
            let deps = adopt_key::Deps {
                get: &|| {
                    p.get(&name)?
                        .ok_or_else(|| ozbox_core::Error::NotFound(name.to_string()).into())
                },
                configured,
                preview: &|rec, step| Ok(backend.plan_secrets_key_step(rec, step)?.summary.clone()),
                apply: &|rec, step| {
                    // planned again right before it is applied, so what is applied is what was just checked
                    let plan = backend.plan_secrets_key_step(rec, step)?;
                    backend.apply_secrets_key_step(&plan)?;
                    Ok(())
                },
                state: &|rec| agent.secrets_state(rec),
                // the box's ROOT, through Systems Manager: the facts Finish and Cancel rest on (the SSH answer above is the
                // box user's and can be forged)
                root: &|rec, which| backend.root_command(rec, which).map_err(|e| e.to_string()),
                // the cloud's own record of the box's tags: a read that worked and listed neither label (never a read that failed)
                tags_absent: &|rec| backend.secrets_tags_absent(rec).map_err(|e| e.to_string()),
                trigger: &|rec| match agent.admin(rec, "configure-box-secrets") {
                    Ok((true, _)) => Ok(()),
                    Ok((false, out)) => Err(out),
                    Err(e) => Err(e.to_string()),
                },
                pause: &|secs| std::thread::sleep(std::time::Duration::from_secs(secs)),
                ask: &admin::ask,
                ask_name: &admin::ask_name,
            };
            adopt_key::command(
                &deps,
                name.as_str(),
                cancel,
                &flags(cli.yes, cli.dry_run, json),
            )
        }
        Command::Admin { name, action } => {
            let agent = crate::serve::agent_for(kind == ProviderKind::Fake, route_inputs(&config));
            admin::command(
                p,
                agent.as_ref(),
                config
                    .aws
                    .as_ref()
                    .and_then(|a| a.release_repo.as_deref())
                    .unwrap_or(ozbox_core::DEFAULT_RELEASE_REPO),
                name,
                action,
                &flags(cli.yes, cli.dry_run, json),
            )
        }
        Command::BoxSecrets {
            name,
            backend,
            path,
            role,
            remove,
            vault_addr,
            mount,
            approval,
        } => {
            let agent = crate::serve::agent_for(kind == ProviderKind::Fake, route_inputs(&config));
            box_secrets::command(
                p,
                agent.as_ref(),
                &ozbox_core::SystemRunner,
                name,
                box_secrets::Change::from_flags(backend, path, role, remove),
                box_secrets::Extras {
                    vault_addr,
                    mount,
                    approval,
                },
                &flags(cli.yes, cli.dry_run, json),
            )
        }
        Command::BoxEgress {
            name,
            mode,
            presets,
            hosts,
            list_presets,
            skip_log_first,
            approval,
        } => {
            let agent = crate::serve::agent_for(kind == ProviderKind::Fake, route_inputs(&config));
            box_guard::egress(
                p,
                agent.as_ref(),
                config
                    .aws
                    .as_ref()
                    .and_then(|a| a.release_repo.as_deref())
                    .unwrap_or(ozbox_core::DEFAULT_RELEASE_REPO),
                name,
                box_guard::EgressArgs {
                    mode,
                    presets,
                    hosts,
                    list_presets,
                    skip_log_first,
                    approval,
                },
                &flags(cli.yes, cli.dry_run, json),
            )
        }
        Command::BoxPatch {
            name,
            rule,
            from,
            to,
            idle,
            approval,
        } => {
            let agent = crate::serve::agent_for(kind == ProviderKind::Fake, route_inputs(&config));
            box_guard::patch(
                p,
                agent.as_ref(),
                config
                    .aws
                    .as_ref()
                    .and_then(|a| a.release_repo.as_deref())
                    .unwrap_or(ozbox_core::DEFAULT_RELEASE_REPO),
                name,
                rule,
                from,
                to,
                idle,
                approval,
                &flags(cli.yes, cli.dry_run, json),
            )
        }
        Command::Pause { name } => mutate(
            p,
            Operation::Pause { name },
            &flags(cli.yes, cli.dry_run, json),
        ),
        Command::Resume { name } => mutate(
            p,
            Operation::Resume { name },
            &flags(cli.yes, cli.dry_run, json),
        ),
        Command::Resize {
            name,
            size,
            disk,
            strict_checkpoint,
            legacy_checkpoint,
        } => {
            let agent = crate::serve::agent_for(kind == ProviderKind::Fake, route_inputs(&config));
            mutate_quiesced(
                p,
                Operation::Resize {
                    name,
                    size,
                    work_disk_gb: disk,
                },
                &flags(cli.yes, cli.dry_run, json),
                agent.as_ref(),
                crate::quiesce::Mode {
                    strict: strict_checkpoint,
                    legacy: legacy_checkpoint,
                },
            )
        }
        Command::Snapshot { name } => mutate(
            p,
            Operation::Snapshot { name },
            &flags(cli.yes, cli.dry_run, json),
        ),
        Command::Clone { from, to } => mutate(
            p,
            Operation::Clone {
                from,
                to,
                snapshot: None,
            },
            &flags(cli.yes, cli.dry_run, json),
        ),
        Command::Destroy {
            name,
            no_final_snapshot,
            keep_old_system_disks,
        } => mutate(
            p,
            Operation::Destroy {
                name,
                final_snapshot: !no_final_snapshot,
                keep_old_system_disks,
            },
            &flags(cli.yes, cli.dry_run, json),
        ),
    }
}

struct Flags {
    yes: bool,
    dry_run: bool,
    json: bool,
}

fn tools_command(
    p: &dyn Provider,
    kind: ProviderKind,
    config: &Config,
    command: crate::cli::ToolsCommand,
    f: &tools_cli::Flags,
) -> Result<()> {
    use crate::cli::ToolsCommand as C;
    let agent = crate::serve::agent_for(kind == ProviderKind::Fake, route_inputs(config));
    let a = agent.as_ref();
    match command {
        C::List { name } => tools_cli::list(p, a, &name, f),
        C::Plan { name, ids, remove } => {
            let ids = tools_cli::expand_ids(&ids)?;
            let (i, r) = if remove { (vec![], ids) } else { (ids, vec![]) };
            tools_cli::change(p, a, &name, i, r, f, true)
        }
        C::Install { name, ids, pending } => {
            if pending {
                tools_cli::install_pending(p, a, &name, f)
            } else {
                tools_cli::change(p, a, &name, tools_cli::expand_ids(&ids)?, vec![], f, false)
            }
        }
        C::Remove { name, ids } => {
            tools_cli::change(p, a, &name, vec![], tools_cli::expand_ids(&ids)?, f, false)
        }
        C::Jobs { name } => tools_cli::jobs(p, a, &name, f),
        C::Requests { name } => tools_cli::requests(p, a, &name, f),
        C::Approve { name, id, always } => tools_cli::decide(
            p,
            a,
            &name,
            &id,
            if always {
                "approve_always"
            } else {
                "approve_once"
            },
            f,
        ),
        C::Deny { name, id } => tools_cli::decide(p, a, &name, &id, "deny", f),
    }
}

fn profile_command(
    p: &dyn Provider,
    kind: ProviderKind,
    config: &Config,
    command: crate::cli::ProfileCommand,
    f: &tools_cli::Flags,
) -> Result<()> {
    use crate::cli::ProfileCommand as C;
    match command {
        C::Save {
            name,
            profile,
            description,
            overwrite,
        } => {
            let agent = crate::serve::agent_for(kind == ProviderKind::Fake, route_inputs(config));
            tools_cli::profile_save(
                p,
                agent.as_ref(),
                &name,
                &profile,
                description,
                overwrite,
                f,
            )
        }
        C::List => tools_cli::profile_list(f),
        C::Show { profile } => tools_cli::profile_show(&profile, f),
        C::Delete { profile } => tools_cli::profile_delete(&profile, f),
    }
}

fn code_deps<'a>(
    p: &'a dyn Provider,
    agent: Box<dyn crate::serve::BoxAgent>,
    config: &Config,
    input: &'a mut dyn BufRead,
    tty: bool,
) -> crate::code_cli::Deps<'a> {
    let tunnel_file = crate::tunnel_cli::tunnel_path()
        .and_then(|p| crate::tunnel::TunnelFile::load(&p).ok().flatten());
    let _ = config;
    crate::code_cli::Deps {
        provider: p,
        agent: std::sync::Arc::from(agent),
        secrets: crate::serve::secret_store(),
        runner: &SystemRunner,
        settings_path: crate::code::settings_path(),
        dashboard_host: tunnel_file
            .as_ref()
            .and_then(|f| crate::tunnel::public_host(&f.public_url).ok()),
        signin_ready: crate::auth_cli::default_path().is_ok_and(|p| p.exists()),
        input,
        tty,
        wait: crate::code_cli::Wait::UntilSignal,
    }
}

fn code_command(
    p: &dyn Provider,
    kind: ProviderKind,
    config: &Config,
    name: ozbox_core::BoxName,
    service: crate::code::Service,
    code: crate::cli::CodeFlags,
    f: &Flags,
) -> Result<()> {
    let agent = crate::serve::agent_for(kind == ProviderKind::Fake, route_inputs(config));
    let stdin = std::io::stdin();
    let mut lock = stdin.lock();
    let mut deps = code_deps(p, agent, config, &mut lock, std::io::stdin().is_terminal());
    crate::code_cli::run_service(
        &mut deps,
        &crate::code_cli::ServiceArgs {
            name,
            service,
            no_open: code.no_open,
            port: code.port,
            public_url: code.public_url,
            tunnel: code.tunnel,
            off: code.off,
            new_password: code.new_password,
            remove_public: code.remove_public,
        },
        &crate::code_cli::Flags {
            yes: f.yes,
            dry_run: f.dry_run,
            json: f.json,
        },
    )
}

fn flags(yes: bool, dry_run: bool, json: bool) -> Flags {
    Flags { yes, dry_run, json }
}

/// Say so, on stderr, when the simulated provider is in use only because nothing was configured.
fn warn_if_simulated(source: &crate::config::Source, provider_configured: bool) {
    // A config file that exists but names no provider always warns. With no file at all the simulated provider is the
    // first-run demo, so the warning goes to a person at a terminal and not into a script's captured output.
    if source.found.is_none() && !std::io::stderr().is_terminal() {
        return;
    }
    if let Some(w) = crate::config::fallback_warning(source, provider_configured) {
        eprintln!("{w}");
    }
}

/// The provider `ozbox serve` runs on: this box alone, or what `build_provider` makes for the configured kind.
fn provider_for(choice: crate::this_box::Choice, config: &Config) -> Result<Box<dyn Provider>> {
    match choice {
        crate::this_box::Choice::ThisBox => {
            Ok(Box::new(crate::this_box::ThisBoxProvider::detect()))
        }
        c => build_provider(c.kind(), config),
    }
}

fn build_provider(kind: ProviderKind, config: &Config) -> Result<Box<dyn Provider>> {
    Ok(match kind {
        ProviderKind::Fake => {
            let dir = match std::env::var_os("OZBOX_STATE_DIR") {
                Some(d) => PathBuf::from(d),
                None => {
                    let home = dirs::home_dir().ok_or_else(|| {
                        CliError::Msg("cannot find your home directory; set OZBOX_STATE_DIR".into())
                    })?;
                    ozbox_provider_fake::default_state_dir(&home)
                }
            };
            Box::new(ozbox_provider_fake::open(dir))
        }
        ProviderKind::Hcloud => {
            Box::new(ozbox_provider_hcloud::open(hcloud_config(config, false)?))
        }
        ProviderKind::Aws => Box::new(ozbox_provider_aws::open(aws_config(config, false)?)),
        ProviderKind::Plugin => crate::plugin_cli::open_provider(config.plugin.as_deref())?,
    })
}

/// The Hetzner adapter's settings from the config file (and the default state directory for the boxes' OpenTofu state).
fn hcloud_config(config: &Config, force_s3: bool) -> Result<ozbox_provider_hcloud::HcloudConfig> {
    let mut cfg = ozbox_provider_hcloud::HcloudConfig::default();
    if let Some(s) = config.hcloud.as_ref() {
        cfg.region = s.region.clone();
        cfg.image = s.image.clone();
    }
    cfg.state_dir = ozbox_core::tofu::default_state_root(dirs::home_dir().as_deref());
    let modules = use_modules(
        "hcloud",
        "hcloud-box",
        config.hcloud.as_ref(),
        cfg.state_dir.clone(),
    )?;
    cfg.module_dir = modules.module_dir;
    cfg.first_boot_sha256 = Some(modules.first_boot);
    cfg.state_s3 = config.s3_state(ProviderKind::Hcloud, force_s3)?;
    Ok(cfg)
}

/// A box's root facts, read through Systems Manager (the one document the fleet's module makes) and parsed strictly. `Err` says
/// why not; nothing is ever decided from a partial answer.
pub(crate) fn aws_root_facts(
    config: &Config,
    rec: &ozbox_core::BoxRecord,
) -> std::result::Result<crate::secrets_adopt_facts::Facts, String> {
    let cfg = aws_config(config, false).map_err(|e| e.to_string())?;
    let backend = ozbox_provider_aws::AwsBackend::new(std::sync::Arc::new(SystemRunner), cfg);
    let out = backend
        .root_command(rec, ozbox_provider_aws::RootCommand::AdoptStatus)
        .map_err(|e| {
            // a box whose program does not know the check at all is OLDER, which is not a problem with this computer's policy
            if matches!(&e, ozbox_core::Error::Config(m) if m == ozbox_provider_aws::ROOT_PROGRAM_OLDER)
            {
                upgrade::ROOT_OLDER.to_string()
            } else {
                e.to_string()
            }
        })?;
    crate::secrets_adopt_facts::Facts::parse(&out).ok_or_else(|| upgrade::ROOT_OLDER.to_string())
}

/// [`aws_root_facts`] for a caller with no configuration at hand (the dashboard): the configuration is read now.
pub(crate) fn aws_root_facts_now(
    rec: &ozbox_core::BoxRecord,
) -> std::result::Result<crate::secrets_adopt_facts::Facts, String> {
    let config = Config::load().map_err(|e| e.to_string())?;
    aws_root_facts(&config, rec)
}

/// A default image is taken only when its signed release is verified (or the provider has no signed releases at all).
fn check_default_image(info: &ozbox_core::ImageInfo) -> std::result::Result<(), String> {
    if info.signature_applicable && !info.signature_verified {
        return Err(crate::messages::t(
            "create.err_unverified",
            &[
                ("id", &info.id),
                (
                    "why",
                    info.signature_detail
                        .as_deref()
                        .unwrap_or("it is not verified"),
                ),
            ],
        ));
    }
    Ok(())
}

/// A pre-release program that is booting a stable release newer than itself says so: it should be moved to that release.
fn newer_release_note(program: &str, release: &str) -> Option<String> {
    let newer = ozbox_provider_aws::public_images::version_order(release, program)
        == std::cmp::Ordering::Greater;
    (program.contains('-') && !release.contains('-') && newer).then(|| {
        crate::messages::t(
            "create.newer_release",
            &[("release", release), ("program", program)],
        )
    })
}

/// The image a `create` with no image named boots from: the newest Oz image for this account (see
/// `ozbox_provider_aws::public_images`), refused unless its signed release is verified.
fn default_create_image(
    p: &dyn ozbox_core::Provider,
    region: Option<&str>,
    json: bool,
) -> Result<String> {
    let info = p.latest_image(region)?;
    check_default_image(&info).map_err(CliError::Msg)?;
    if !json {
        let release = info.release.as_deref().unwrap_or("unknown");
        eprintln!(
            "{}",
            crate::messages::t(
                "create.image_default",
                &[("id", &info.id), ("release", release)]
            )
        );
        if let Some(note) = info
            .release
            .as_deref()
            .and_then(|r| newer_release_note(env!("CARGO_PKG_VERSION"), r))
        {
            eprintln!("{note}");
        }
    }
    Ok(info.id)
}

/// The AWS adapter's settings from the config file (and the default state directory for the boxes' OpenTofu state).
/// How many looks, one `interval` apart, make `minutes` of waiting for the copy of an old system disk (at least one).
fn snapshot_wait_polls(minutes: u32, interval: std::time::Duration) -> u32 {
    let every = interval.as_secs().max(1);
    u32::try_from(u64::from(minutes) * 60 / every)
        .unwrap_or(u32::MAX)
        .max(1)
}

fn aws_config(config: &Config, force_s3: bool) -> Result<ozbox_provider_aws::AwsConfig> {
    let mut cfg = ozbox_provider_aws::AwsConfig::default();
    if let Some(s) = config.aws.as_ref() {
        cfg.region = s.region.clone();
        cfg.image = s.image.clone();
        cfg.regions = s.regions.clone().unwrap_or_default();
        cfg.subnet_id = s.subnet_id.clone();
        cfg.kms_key_arn = s.kms_key_arn.clone();
        cfg.secrets_key_arn = s.secrets_key_arn.clone().filter(|k| !k.is_empty());
        cfg.fleet = s.fleet.clone().filter(|f| !f.is_empty());
        cfg.root_disk_gb = s.root_disk_gb;
        if let Some(m) = s.snapshot_wait_minutes.filter(|m| *m > 0) {
            cfg.snapshot_wait_polls = snapshot_wait_polls(m, cfg.poll_interval);
        }
        cfg.session_log_bucket = s.session_log_bucket.clone();
        cfg.patch_group = s.patch_group.clone();
        if let Some(r) = &s.release_repo {
            cfg.release_repo = r.clone();
        }
        if let Some(p) = s.image_publisher.as_deref().map(str::trim) {
            if p != ozbox_provider_aws::public_images::NO_PUBLISHER
                && !ozbox_provider_aws::public_images::is_account_id(p)
            {
                return Err(CliError::Msg(crate::messages::t(
                    "create.err_publisher",
                    &[],
                )));
            }
            cfg.image_publisher = Some(p.to_string());
        }
    }
    cfg.state_dir = ozbox_core::tofu::default_state_root(dirs::home_dir().as_deref());
    let modules = use_modules("aws", "aws-box", config.aws.as_ref(), cfg.state_dir.clone())?;
    cfg.module_dir = modules.module_dir;
    cfg.first_boot_sha256 = Some(modules.first_boot);
    cfg.state_s3 = config.s3_state(ProviderKind::Aws, force_s3)?;
    Ok(cfg)
}

/// `ozbox infra`: what this program renders at first boot, and from where. The image workflow records
/// `first_boot_sha256` in the signed manifest from this command's `--json`.
fn infra_show(kind: ProviderKind, config: &Config, json: bool) -> Result<()> {
    let own = crate::infra_cli::program_hashes();
    let (section, module, sec) = match kind {
        ProviderKind::Aws => ("aws", "aws-box", config.aws.as_ref()),
        ProviderKind::Hcloud => ("hcloud", "hcloud-box", config.hcloud.as_ref()),
        ProviderKind::Fake | ProviderKind::Plugin => ("", "", None),
    };
    let resolved = if module.is_empty() {
        None
    } else {
        let state = ozbox_core::tofu::default_state_root(dirs::home_dir().as_deref());
        Some(use_modules(section, module, sec, state)?)
    };
    let out = serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "first_boot_sha256": own.first_boot,
        "bundle_sha256": own.bundle,
        "module_dir": resolved.as_ref().map(|r| r.module_dir.display().to_string()),
        "rendered_first_boot_sha256": resolved.as_ref().map(|r| r.first_boot.clone()),
        "developer_modules": resolved.as_ref().is_some_and(|r| r.dev.is_some()),
    });
    if json {
        print_json(&out)?;
        return Ok(());
    }
    println!("ozbox {}", env!("CARGO_PKG_VERSION"));
    println!("first boot   {}", own.first_boot);
    println!("bundle       {}", own.bundle);
    if let Some(r) = &resolved {
        println!("{section:<12} {}", r.module_dir.display());
        if let Some(d) = &r.dev {
            println!(
                "             developer modules from {} (first boot {})",
                d.display(),
                r.first_boot
            );
        }
    }
    Ok(())
}

/// The box modules a provider renders: this program's own copy, or a developer folder (see `infra_cli`). Warnings are
/// printed once per process; the developer note is kept for every plan.
fn use_modules(
    section: &str,
    module: &str,
    sec: Option<&crate::config::ProviderSection>,
    state_root: Option<PathBuf>,
) -> Result<crate::infra_cli::Resolved> {
    let want = crate::infra_cli::Wanted {
        section,
        module,
        module_dir: sec.and_then(|s| s.module_dir.clone()),
        dev: crate::infra_cli::dev_flag() || sec.and_then(|s| s.dev_modules).unwrap_or(false),
        state_root,
    };
    let r = crate::infra_cli::resolve(&want).map_err(CliError::Msg)?;
    static WARNED: std::sync::Once = std::sync::Once::new();
    WARNED.call_once(|| {
        for w in &r.warnings {
            eprintln!("{w}");
        }
    });
    crate::infra_cli::set_plan_notes(r.plan_notes.clone());
    crate::infra_cli::set_effective_first_boot(&r.first_boot);
    Ok(r)
}

#[derive(Serialize)]
struct Outcome<'a> {
    plan: &'a Plan,
    applied: bool,
    dry_run: bool,
    result: Option<&'a BoxRecord>,
}

/// plan, print, (nothing to do | dry run | confirm), apply, report.
/// After a destroy: the box's SSH entry and its host key go too. A convenience for this computer; never fails the
/// destroy, which has already happened.
fn forget_ssh_entry(name: &str, json: bool) {
    let Some(dir) = ssh_dir() else { return };
    if let Ok(r) = sshconfig::remove_entry(&ozbox_core::SystemRunner, &dir, name) {
        if (r.rewritten || !r.forgotten.is_empty()) && !json {
            println!(
                "{}",
                crate::messages::t(
                    "destroy.ssh_removed",
                    &[("box", name), ("forgotten", &r.forgotten.len().to_string())]
                )
            );
        }
    }
}

fn ssh_dir() -> Option<PathBuf> {
    std::env::var_os("OZBOX_SSH_DIR")
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|h| h.join(".ssh")))
}

fn load_settings() -> Result<Settings> {
    Ok(match Settings::path() {
        Some(p) => Settings::load_from(&p)?,
        None => Settings::default(),
    })
}

fn route_inputs(config: &Config) -> RouteInputs {
    let aws = config.aws.as_ref();
    RouteInputs {
        aws_region: aws.and_then(|a| a.region.clone()),
        aws_profile: aws.and_then(|a| a.profile.clone()),
        domain: config.domain.clone().filter(|d| !d.is_empty()),
        mesh: crate::mesh_cli::route_setting(),
    }
}

/// Once setup has asked for it, a box that costs money needs a budget and an alert channel first.
fn guard_rails(p: &dyn Provider, op: &Operation) -> Result<()> {
    let Some(setup_path) = crate::init::InitPaths::setup_path() else {
        return Ok(());
    };
    let setup = crate::init::SetupFile::load(&setup_path);
    if !setup.require_guardrails {
        return Ok(());
    }
    let settings = load_settings()?;
    let chats = Settings::path()
        .map(|sp| {
            crate::state::ServerState::load(&sp.with_file_name("state.json"))
                .telegram
                .chats
                .len()
        })
        .unwrap_or(0);
    let secrets = crate::serve::secret_store();
    let g = crate::init::guardrails(&settings, secrets.as_ref(), chats);
    crate::init::require_guardrails(&setup, &g, p.id(), op)
        .map_err(|e| CliError::Msg(e.to_string()))
}

fn mutate(p: &dyn Provider, op: Operation, f: &Flags) -> Result<()> {
    mutate_with_notes(p, op, f, Vec::new())
}

/// [`mutate`], with lines the command adds to the plan.
fn mutate_with_notes(p: &dyn Provider, op: Operation, f: &Flags, notes: Vec<String>) -> Result<()> {
    mutate_inner(p, op, f, notes, None)
}

/// A change that may stop a running box: what will end is in the plan, and after the confirmation the box's agent is asked
/// to end its runs and snapshot uncommitted work first (see `quiesce`). `strict` refuses to go on unless it was all done.
fn mutate_quiesced(
    p: &dyn Provider,
    op: Operation,
    f: &Flags,
    agent: &dyn BoxAgent,
    mode: crate::quiesce::Mode,
) -> Result<()> {
    mutate_inner(p, op, f, Vec::new(), Some((agent, mode)))
}

fn mutate_inner(
    p: &dyn Provider,
    op: Operation,
    f: &Flags,
    notes: Vec<String>,
    quiesce: Option<(&dyn BoxAgent, crate::quiesce::Mode)>,
) -> Result<()> {
    guard_rails(p, &op)?;
    // The fleet cap and budget are checked before anything is planned, so a refusal costs nothing.
    crate::settings::enforce(&load_settings()?, p, &op)?;
    let mut plan = p.plan(&op)?;
    plan.notes.extend(notes);
    plan.notes.extend(crate::infra_cli::plan_notes());
    // Only a plan that stops a running machine is quiesced; what will end is read (never changed) before the plan shows.
    let stopping = match (&quiesce, p.get(plan.operation.box_name()).ok().flatten()) {
        (Some((agent, _)), Some(rec)) if crate::quiesce::needed(&plan, &rec) => {
            plan.notes
                .extend(crate::quiesce::preview(*agent, &rec).notes(rec.spec.name.as_str()));
            Some(rec)
        }
        _ => None,
    };
    if !f.json {
        print!("{plan}");
    }
    if plan.is_noop() {
        return finish(f, &plan, false, None);
    }
    if f.dry_run {
        if !f.json {
            println!("Dry run: nothing was changed.");
        }
        return finish(f, &plan, false, None);
    }
    confirm(&plan, f)?;
    // The box is asked to end its runs and save its work. From here until the change is applied, the hold on new runs is
    // lifted on every way out (a refusal, a declined question, a failed apply).
    let mut hold = None;
    if let (Some((agent, mode)), Some(rec)) = (quiesce, &stopping) {
        // Ctrl-C during the wait or the question lifts the hold before the process exits
        crate::quiesce::guard_interrupt(agent, rec, || -> Result<()> {
            let q = crate::quiesce::perform(
                agent,
                rec,
                &crate::quiesce::Opts::command(mode),
                &crate::quiesce::RealPace::new(),
            );
            hold = Some(crate::quiesce::Hold::new(agent, rec));
            if !f.json {
                println!("{}", q.step.detail);
            }
            let name = rec.spec.name.as_str();
            if !q.proceed {
                return Err(CliError::Msg(crate::quiesce::strict_refusal(
                    name, q.touched,
                )));
            }
            if q.reconfirm {
                confirm_unsaved(name, f)?;
            }
            Ok(())
        })?;
    }
    let result = p.apply(&plan)?;
    if let Some(h) = hold.as_mut() {
        h.disarm();
    }
    if !f.json {
        match &result {
            Some(r) => println!(
                "Done. {} is {} ({}).",
                r.spec.name,
                r.state,
                r.machine_type.as_deref().unwrap_or("-")
            ),
            None => println!("Done. {} is destroyed.", plan.operation.box_name()),
        }
    }
    if result.is_none() {
        if let Operation::Destroy { name, .. } = &plan.operation {
            forget_ssh_entry(name.as_str(), f.json);
        }
    }
    finish(f, &plan, true, result.as_ref())
}

/// `--json` output for a command with its own outcome shape (a superset of the plan, applied, dry_run, result shape).
fn finish_with(f: &Flags, outcome: &impl Serialize) -> Result<()> {
    if f.json {
        print_json(outcome)?;
    }
    Ok(())
}

fn finish(f: &Flags, plan: &Plan, applied: bool, result: Option<&BoxRecord>) -> Result<()> {
    if f.json {
        print_json(&Outcome {
            plan,
            applied,
            dry_run: f.dry_run,
            result,
        })?;
    }
    Ok(())
}

/// Low and medium risk: y/N. High risk (anything that cannot be undone): type the box name.
/// A prompt is only shown on a terminal; otherwise the mutation is refused rather than hanging.
fn confirm(plan: &Plan, f: &Flags) -> Result<()> {
    if f.yes {
        return Ok(());
    }
    let name = plan.operation.box_name();
    if !std::io::stdin().is_terminal() {
        return Err(CliError::Msg(format!(
            "refusing to {} {name} without confirmation: standard input is not a terminal. Review the plan, then pass --yes.",
            plan.operation.verb()
        )));
    }
    let mut err = std::io::stderr();
    let mut line = String::new();
    if plan.max_risk() == Some(Risk::High) {
        let _ = write!(
            err,
            "This cannot be undone. Type the box name ({name}) to confirm: "
        );
        let _ = err.flush();
        read_line(&mut line)?;
        if line.trim() != name.as_str() {
            return Err(CliError::Msg(
                "aborted: the name did not match; nothing was changed".into(),
            ));
        }
    } else {
        let _ = write!(err, "Proceed? [y/N] ");
        let _ = err.flush();
        read_line(&mut line)?;
        if !matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            return Err(CliError::Msg("aborted; nothing was changed".into()));
        }
    }
    Ok(())
}

/// The second question, when the box was not fully ready (its work not snapshotted, or its runs not asked to end): `--yes`
/// goes on; a terminal is asked; anything else refuses, and nothing has been stopped.
pub(in crate::run) fn confirm_unsaved(name: &str, f: &Flags) -> Result<()> {
    if f.yes {
        return Ok(());
    }
    if !std::io::stdin().is_terminal() {
        return Err(CliError::Msg(format!(
            "{} Standard input is not a terminal, so it was not asked: nothing was stopped. Pass --yes to go on without it.",
            crate::quiesce::declined(name)
        )));
    }
    let mut err = std::io::stderr();
    let _ = write!(err, "{} [y/N] ", crate::quiesce::reconfirm_question(name));
    let _ = err.flush();
    let mut line = String::new();
    read_line(&mut line)?;
    if matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        Ok(())
    } else {
        Err(CliError::Msg(crate::quiesce::declined(name)))
    }
}

fn read_line(buf: &mut String) -> Result<()> {
    std::io::stdin()
        .lock()
        .read_line(buf)
        .map(|_| ())
        .map_err(|e| CliError::Core(e.into()))
}

fn print_json<T: Serialize>(v: &T) -> Result<()> {
    let s = serde_json::to_string_pretty(v).map_err(|e| CliError::Core(e.into()))?;
    println!("{s}");
    Ok(())
}

fn list(p: &dyn Provider, json: bool) -> Result<()> {
    let recs = p.list()?;
    if let Some(paths) = crate::telemetry::Paths::detect() {
        crate::telemetry::note_boxes(&paths, recs.len(), p.id());
    }
    if json {
        return print_json(&recs);
    }
    if recs.is_empty() {
        println!("No boxes. Create one with `ozbox create <name> --size M`.");
        let searched = p.searched();
        if !searched.is_empty() {
            println!("Searched: {}", searched.join(", "));
        }
        return Ok(());
    }
    println!(
        "{:<24} {:<10} {:<6} {:>8}  {:<18} SNAPSHOTS",
        "NAME", "STATE", "SIZE", "DISK", "MACHINE"
    );
    for r in &recs {
        println!(
            "{:<24} {:<10} {:<6} {:>6}GB  {:<18} {}",
            r.spec.name,
            r.state.to_string(),
            r.spec.size.to_string(),
            r.spec.work_disk_gb,
            r.machine_type.as_deref().unwrap_or("-"),
            r.snapshots.len()
        );
    }
    for r in &recs {
        if r.state == ozbox_core::BoxState::InstanceMissing {
            println!(
                "\n{}",
                crate::messages::t("box.instance_missing", &[("box", r.spec.name.as_str())])
            );
        }
    }
    let searched = p.searched();
    if !searched.is_empty() {
        println!("\nSearched: {}", searched.join(", "));
    }
    Ok(())
}

fn print_record(r: &BoxRecord) {
    println!("name:       {}", r.spec.name);
    println!("state:      {}", r.state);
    if r.state == ozbox_core::BoxState::InstanceMissing {
        println!(
            "next:       {}",
            crate::messages::t("box.instance_missing", &[("box", r.spec.name.as_str())])
        );
    }
    println!("provider:   {}", r.provider);
    println!("size:       {}", r.spec.size);
    println!("machine:    {}", r.machine_type.as_deref().unwrap_or("-"));
    println!("work disk:  {} GB", r.spec.work_disk_gb);
    if let Some(i) = &r.spec.image {
        println!("image:      {i}");
    }
    if let Some(id) = &r.provider_id {
        println!("id:         {id}");
    }
    if let Some(c) = &r.created_at {
        println!("created:    {c}");
    }
    if !r.spec.labels.is_empty() {
        let l: Vec<String> = r
            .spec
            .labels
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        println!("labels:     {}", l.join(", "));
    }
    println!(
        "snapshots:  {}",
        if r.snapshots.is_empty() {
            "none".to_string()
        } else {
            r.snapshots.join(", ")
        }
    );
}

#[derive(Serialize)]
struct Connection<'a> {
    name: &'a str,
    mode: &'a str,
    /// `None` while no domain is configured: the box has no web address yet.
    url: Option<String>,
    /// The SSH config alias (`ozbox-<name>`), entry and route id; `None` while no route is known.
    ssh_host: Option<String>,
    ssh_config: Option<String>,
    ssh_route: Option<&'static str>,
    /// The dedicated key was pushed to the box (valid for 60 seconds).
    ssh_key_pushed: bool,
    state: String,
}

struct Mode {
    desktop: bool,
    shell: bool,
    ssh: bool,
    write: bool,
    route: Option<String>,
    push_key: bool,
}

/// Says how to connect. It never opens a port or a tunnel; `--ssh --write` only edits files under `~/.ssh`.
fn connect(
    p: &dyn Provider,
    config: &Config,
    name: &ozbox_core::BoxName,
    m: &Mode,
    json: bool,
) -> Result<()> {
    let rec = p
        .get(name)?
        .ok_or_else(|| ozbox_core::Error::NotFound(name.to_string()))?;
    let domain = config.domain.as_deref().filter(|d| !d.is_empty());
    let url = domain.map(|d| format!("https://{name}.{d}"));
    let routes = sshconfig::routes(&rec, &route_inputs(config));
    let chosen = match m.route.as_deref() {
        None => routes.first(),
        Some(id) => Some(routes.iter().find(|r| r.id() == id).ok_or_else(|| {
            CliError::Msg(format!(
                "{name} has no {id} route; available: {}",
                if routes.is_empty() {
                    "none".to_string()
                } else {
                    routes.iter().map(|r| r.id()).collect::<Vec<_>>().join(", ")
                }
            ))
        })?),
    };
    let ssh_block = chosen.map(|r| sshconfig::block(name.as_str(), r));
    let mode = if m.desktop {
        "desktop"
    } else if m.ssh {
        "ssh"
    } else if m.shell {
        "shell"
    } else {
        "web"
    };
    let written = if m.ssh && m.write {
        let (Some(block), Some(dir)) = (&ssh_block, ssh_dir()) else {
            return Err(CliError::Msg(format!(
                "{name} has no SSH route to write: an AWS box needs its instance id and a region, other boxes need a configured domain"
            )));
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        // the ingress account's entry (written with the box's) names its own key: make sure it exists
        let _ = sshconfig::ensure_named_key(&SystemRunner, &dir, sshconfig::INGRESS_KEY_NAME);
        Some(sshconfig::write_config(&dir, name.as_str(), block, now)?)
    } else {
        None
    };
    // AWS SSH uses a dedicated key. `--write` makes sure it exists; `--push-key` also sends it for 60 seconds.
    let mut key_created = false;
    let mut key_pushed = false;
    if m.ssh && (m.write || m.push_key) {
        if let Some(sshconfig::Route::AwsSsm {
            instance,
            region,
            profile,
        }) = chosen
        {
            let Some(dir) = ssh_dir() else {
                return Err(CliError::Msg("cannot find your SSH directory".into()));
            };
            let (public, created) = sshconfig::ensure_key(&SystemRunner, &dir)?;
            key_created = created;
            if m.push_key {
                SystemRunner.run_ok(&sshconfig::push_key_command(
                    instance,
                    region,
                    profile.as_deref(),
                    &public,
                ))?;
                key_pushed = true;
            }
        } else if m.push_key {
            return Err(CliError::Msg(format!(
                "{name} has no AWS route: only an AWS box takes a pushed key"
            )));
        }
    }
    if json {
        return print_json(&Connection {
            name: name.as_str(),
            mode,
            url,
            ssh_host: ssh_block
                .as_ref()
                .map(|_| sshconfig::host_alias(name.as_str())),
            ssh_config: ssh_block,
            ssh_route: chosen.map(sshconfig::Route::id),
            ssh_key_pushed: key_pushed,
            state: rec.state.to_string(),
        });
    }
    if m.ssh {
        match (chosen, &ssh_block) {
            (Some(route), Some(b)) => {
                let alias = sshconfig::host_alias(name.as_str());
                if let Some(w) = &written {
                    println!("Wrote {} ({}).", w.included_file.display(), route.label());
                    if w.include_added {
                        println!(
                            "Added one line to {}: {}",
                            w.main_config.display(),
                            sshconfig::INCLUDE_LINE
                        );
                        if let Some(bk) = &w.backup {
                            println!("The previous file was copied to {}.", bk.display());
                        }
                    }
                    println!("Connect with: ssh {alias}");
                } else {
                    println!(
                        "# {}. Add this to ~/.ssh/config, or run again with --write.",
                        route.label()
                    );
                    print!("{b}");
                    println!("# Connect with: ssh {alias}");
                }
                if key_created {
                    println!("Created your dedicated key ~/.ssh/{} (no passphrase; used only for Oz Box).", sshconfig::KEY_NAME);
                }
                if key_pushed {
                    println!("Sent your key to {name}: it is accepted for the next 60 seconds. Nothing is stored on the box.");
                }
                eprintln!("note: {}", route.requirements());
            }
            _ => {
                println!("{name} has no SSH route yet.");
                println!("An AWS box needs its instance id and a region (`region` in the [aws] section). Any other box needs `domain = \"...\"` and a tunnel.");
            }
        }
        if rec.state != ozbox_core::BoxState::Running {
            eprintln!(
                "note: {name} is {}; run `ozbox resume {name}` first.",
                rec.state
            );
        }
        return Ok(());
    }
    match &url {
        Some(u) => {
            if mode != "web" {
                println!("In v0.1 a box is reached through its web IDE, which includes the terminal and the desktop browser.");
            }
            println!("{u}");
        }
        None => {
            println!("{name} has no web address yet: no domain is configured.");
            println!(
                "Set `domain = \"...\"` in {}; boxes are then reached at https://{name}.<domain>.",
                Config::path().map_or_else(
                    || "the config file".to_string(),
                    |p| p.display().to_string()
                )
            );
            println!("Until then v0.1 has no other route to the terminal or desktop.");
        }
    }
    if rec.state != ozbox_core::BoxState::Running {
        eprintln!(
            "note: {name} is {}; run `ozbox resume {name}` first.",
            rec.state
        );
    }
    Ok(())
}

#[derive(Serialize)]
struct SizeRow {
    size: String,
    vcpus: u32,
    memory_gb: u32,
    gpus: u32,
    gpu_memory_gb: u32,
    fake: Option<String>,
    hcloud: Option<String>,
    aws: Option<String>,
}

fn sizes(json: bool) -> Result<()> {
    let all: Vec<Size> = Size::STANDARD
        .into_iter()
        .chain([
            Size::Gpu(ozbox_core::GpuKind::Small),
            Size::Gpu(ozbox_core::GpuKind::Large),
        ])
        .collect();
    let rows: Vec<SizeRow> = all
        .into_iter()
        .map(|s| {
            let sp = s.spec();
            SizeRow {
                size: s.to_string(),
                vcpus: sp.vcpus,
                memory_gb: sp.memory_gb,
                gpus: sp.gpus,
                gpu_memory_gb: sp.gpu_memory_gb,
                fake: Some(ozbox_provider_fake::machine_type_for(s)),
                hcloud: ozbox_provider_hcloud::machine_choice(s)
                    .ok()
                    .map(|c| c.machine_type),
                aws: ozbox_provider_aws::machine_choice(s)
                    .ok()
                    .map(|c| c.machine_type),
            }
        })
        .collect();
    if json {
        return print_json(&rows);
    }
    println!(
        "{:<6} {:>5} {:>7} {:<10} {:<22} {:<12} AWS",
        "SIZE", "VCPU", "MEM GB", "GPU", "FAKE", "HCLOUD"
    );
    for r in rows {
        let gpu = if r.gpus > 0 {
            format!("{}x {}GB", r.gpus, r.gpu_memory_gb)
        } else {
            "-".into()
        };
        println!(
            "{:<6} {:>5} {:>7} {:<10} {:<22} {:<12} {}",
            r.size,
            r.vcpus,
            r.memory_gb,
            gpu,
            r.fake.as_deref().unwrap_or("-"),
            r.hcloud.as_deref().unwrap_or("not offered"),
            r.aws.as_deref().unwrap_or("not offered")
        );
    }
    println!("\nA type can have more than a size promises (never less); `ozbox create --dry-run` shows a note when it does.");
    Ok(())
}

#[derive(Serialize)]
struct ProviderRow {
    id: &'static str,
    resize: String,
    online_disk_grow: bool,
    disk_shrink: bool,
    snapshots: bool,
    sizes: Vec<String>,
}

fn providers(json: bool) -> Result<()> {
    let rows: Vec<ProviderRow> = [
        ("fake", ozbox_provider_fake::capabilities()),
        ("hcloud", ozbox_provider_hcloud::capabilities()),
        ("aws", ozbox_provider_aws::capabilities()),
    ]
    .into_iter()
    .map(|(id, c)| ProviderRow {
        id,
        resize: format!("{:?}", c.resize),
        online_disk_grow: c.online_disk_grow,
        disk_shrink: c.disk_shrink,
        snapshots: c.snapshots,
        sizes: c.sizes.iter().map(ToString::to_string).collect(),
    })
    .collect();
    if json {
        return print_json(&rows);
    }
    println!("{:<8} {:<18} {:<12} SIZES", "ID", "RESIZE", "DISK GROW");
    for r in rows {
        println!(
            "{:<8} {:<18} {:<12} {}",
            r.id,
            r.resize,
            if r.online_disk_grow {
                "online"
            } else {
                "offline"
            },
            r.sizes.join(" ")
        );
    }
    println!("\nPick one with --provider, or `provider = \"...\"` in the config file. `fake` needs no account.");
    Ok(())
}

#[cfg(test)]
mod create_image_tests {
    use super::{check_default_image, newer_release_note};
    use ozbox_core::ImageInfo;

    fn info(verified: bool, applicable: bool) -> ImageInfo {
        ImageInfo {
            id: "ami-0abc".into(),
            release: Some("0.3.0".into()),
            created: None,
            signature_verified: verified,
            signature_detail: Some("the signed manifest does not list it".into()),
            signature_applicable: applicable,
            first_boot_sha256: None,
            upgrade: None,
        }
    }

    #[test]
    fn a_default_image_must_be_verified_unless_the_provider_has_no_signed_releases() {
        assert!(check_default_image(&info(true, true)).is_ok());
        assert!(check_default_image(&info(false, false)).is_ok());
        let e = check_default_image(&info(false, true))
            .err()
            .unwrap_or_default();
        assert!(!e.is_empty(), "an unverified default is refused");
        assert!(
            e.contains("ami-0abc") && e.contains("does not list it"),
            "{e}"
        );
        assert!(
            e.contains("--image") && e.contains("Nothing was created"),
            "{e}"
        );
    }

    #[test]
    fn a_beta_program_is_told_about_a_newer_stable_release_and_nobody_else_is() {
        let n = newer_release_note("0.2.0-beta.0", "0.2.0").unwrap_or_default();
        assert!(n.contains("0.2.0") && n.contains("ozbox upgrade"), "{n}");
        assert!(
            newer_release_note("0.2.0", "0.2.1").is_none(),
            "a stable program is not a beta"
        );
        assert!(newer_release_note("0.2.0-beta.1", "0.2.0-beta.0").is_none());
        assert!(
            newer_release_note("0.2.0-beta.1", "0.2.0-beta.2").is_none(),
            "not a stable release"
        );
    }
}

#[cfg(test)]
mod snapshot_wait_tests {
    use super::snapshot_wait_polls;
    use std::time::Duration;

    /// `snapshot_wait_minutes` under `[aws]` is minutes of waiting for the copy of an old system disk: the number of looks that
    /// make it, never none.
    #[test]
    fn minutes_of_waiting_become_the_looks_that_make_them() {
        let five = Duration::from_secs(5);
        assert_eq!(snapshot_wait_polls(30, five), 360);
        assert_eq!(snapshot_wait_polls(1, five), 12);
        assert_eq!(snapshot_wait_polls(10, Duration::from_secs(30)), 20);
        // a zero interval is looked at every second, and a wait is at least one look
        assert_eq!(snapshot_wait_polls(1, Duration::ZERO), 60);
        assert_eq!(snapshot_wait_polls(1, Duration::from_secs(600)), 1);
    }
}
