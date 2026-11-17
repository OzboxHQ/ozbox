//! `ozbox secrets status | rotate-kek | rotate-data-keys | rotate-hmac | serve | exec`.

use std::sync::Arc;

use serde_json::json;

use crate::cli::SecretsCommand;
use crate::messages::t;
use crate::run::CliError;
use crate::secrets_file::{open_from_env, provider_named};

fn fail(e: crate::secrets::SecretError) -> CliError {
    CliError::Msg(e.0)
}

pub fn run(command: &SecretsCommand, json: bool, yes: bool, dry_run: bool) -> Result<(), CliError> {
    if dry_run {
        if let Some(done) = dry_run_of(command, json) {
            return done;
        }
    }
    let yes = effective_yes(yes, dry_run);
    match command {
        SecretsCommand::Status => {
            let s = match open_from_env() {
                Ok(s) => s,
                // the box user has no store of its own: the service says whether it is up, and why not
                Err(e) => return status_of_service(&e.0, json),
            };
            let ages = s.ages().map_err(fail)?;
            if json {
                let rows: Vec<_> = ages
                    .iter()
                    .map(|(n, (c, r))| json!({"name": n, "created": c, "rotated": r}))
                    .collect();
                println!(
                    "{}",
                    json!({"secrets": rows, "encoded": s.encoded_count().map_err(fail)?,
                        "migrated": s.migration_record().map(|m| json!({"at": m.0, "count": m.1}))})
                );
            } else if ages.is_empty() {
                println!("{}", t("secrets.status_none", &[]));
            } else {
                for (n, (c, r)) in &ages {
                    println!(
                        "{}",
                        t(
                            "secrets.status_line",
                            &[
                                ("name", n),
                                ("created", &c.to_string()),
                                ("rotated", &r.to_string())
                            ]
                        )
                    );
                }
                if let Some((_, count)) = s.migration_record() {
                    println!(
                        "{}",
                        t("secrets.status_migrated", &[("count", &count.to_string())])
                    );
                }
                let encoded = s.encoded_count().map_err(fail)?;
                if encoded > 0 {
                    println!(
                        "{}",
                        t("secrets.status_encoded", &[("count", &encoded.to_string())])
                    );
                }
            }
            Ok(())
        }
        SecretsCommand::RotateKek { to } => {
            let s = open_from_env().map_err(fail)?;
            let new = provider_named(to, s.path()).map_err(fail)?;
            let n = s.rotate_kek(new, None).map_err(fail)?;
            println!("{}", t("secrets.rotated_kek", &[("count", &n.to_string())]));
            Ok(())
        }
        SecretsCommand::RotateDataKeys => {
            let n = open_from_env()
                .map_err(fail)?
                .rotate_all_data_keys()
                .map_err(fail)?;
            println!(
                "{}",
                t("secrets.rotated_data", &[("count", &n.to_string())])
            );
            Ok(())
        }
        SecretsCommand::RotateHmac { overlap_hours } => {
            let s = open_from_env().map_err(fail)?;
            let kid = crate::tokenmac::rotate(
                &s,
                crate::tokenmac::now_ms(),
                overlap_hours.saturating_mul(3_600_000),
            )
            .map_err(fail)?;
            println!(
                "{}",
                t(
                    "secrets.rotated_hmac",
                    &[("kid", &kid), ("hours", &overlap_hours.to_string())]
                )
            );
            Ok(())
        }
        SecretsCommand::Import {
            file,
            project,
            env,
            allow_live,
            allow_live_all,
            public,
            on_box,
            approval,
        } => crate::workload_cli::import(
            &crate::workload_cli::ImportArgs {
                file,
                project,
                env,
                allow_live,
                allow_live_all: *allow_live_all,
                public,
                on_box: on_box.as_ref().map(|b| b.as_str()),
                approval: approval.as_deref(),
            },
            &ozbox_core::SystemRunner,
            &mut std::io::stdin().lock(),
            std::io::IsTerminal::is_terminal(&std::io::stdin()),
            json,
            yes,
            &mut std::io::stdout(),
        ),
        SecretsCommand::Receive { socket } => crate::workload_cli::receive(socket.as_deref()),
        SecretsCommand::RunAs => crate::workload_cli::run_as(),
        SecretsCommand::ExecEnv { command } => crate::workload_cli::exec_env(command),
        SecretsCommand::ExecCred { command } => crate::workload_cli::exec_cred(command),
        SecretsCommand::EgressServe {
            port,
            uid,
            rules,
            tcp,
        } => crate::workload_cli::egress_serve(*port, *uid, rules, tcp),
        SecretsCommand::Put {
            name,
            socket,
            base64,
        } => admin_put(name, socket.as_deref(), true, *base64),
        SecretsCommand::Remove { name, socket } => admin_put(name, socket.as_deref(), false, false),
        SecretsCommand::Gate {
            scope,
            project,
            env,
            bind_token_stdin,
            socket,
        } => gate(scope, project, env, *bind_token_stdin, socket.as_deref()),
        SecretsCommand::ApprovalKey { command } => {
            use crate::cli::ApprovalKeyCommand as K;
            let runner = ozbox_core::SystemRunner;
            let keys = crate::approval_key_cli::keychain();
            match command {
                K::Enroll {
                    on_box,
                    key,
                    approval,
                } => crate::approval_key_cli::enroll(
                    &runner,
                    keys.as_ref(),
                    on_box,
                    key,
                    approval.as_deref(),
                    json,
                ),
                K::Revoke {
                    on_box,
                    key,
                    approval,
                } => {
                    crate::approval_key_cli::revoke(&runner, on_box, key, approval.as_deref(), json)
                }
                K::List { on_box } => crate::approval_key_cli::list(&runner, on_box, json),
            }
        }
        SecretsCommand::Ingress { command } => crate::ingress_cli::run(command, json),
        SecretsCommand::Approve {
            on_box,
            scope,
            project,
            env,
            key,
            token_stdin,
        } => {
            let bound;
            let env = if *token_stdin {
                if scope != "tunnel-token" || !env.is_empty() {
                    return Err(CliError::Msg(t("approval_key.token_stdin_scope", &[])));
                }
                let mut line = zeroize::Zeroizing::new(String::new());
                let _ = std::io::stdin().read_line(&mut line);
                if line.trim().is_empty() {
                    return Err(CliError::Msg(t("approval_key.token_stdin_empty", &[])));
                }
                bound = crate::secrets_approval::tunnel_token_binding(&line);
                &bound
            } else {
                env
            };
            crate::approval_key_cli::approve(
                &ozbox_core::SystemRunner,
                crate::approval_key_cli::keychain().as_ref(),
                on_box,
                key,
                scope,
                project,
                env,
                json,
                dry_run,
            )
        }
        SecretsCommand::Exec { env, command } => exec(env, command),
        SecretsCommand::Serve {
            box_socket,
            runner_socket,
            admin_socket,
            import_socket,
            ingress_socket,
            broker_socket,
            supervisor_socket,
            memory_store,
            audit_dir,
            audit_anchor_dir,
            persist_dir,
            passphrase_stdin,
        } => serve(
            box_socket,
            runner_socket.as_deref(),
            admin_socket.as_deref(),
            import_socket.as_deref(),
            ingress_socket.as_deref(),
            broker_socket.as_deref(),
            supervisor_socket.as_deref(),
            memory_store.as_deref(),
            audit_dir
                .as_deref()
                .map(|d| (d, audit_anchor_dir.as_deref())),
            persist_dir.as_deref(),
            *passphrase_stdin,
        ),
        SecretsCommand::SupervisorSetup { args } => supervisor_setup(args),
        SecretsCommand::IngressSetup { key } => {
            let g = crate::ingress_guard::Guard {
                runner: &ozbox_core::SystemRunner,
                paths: crate::ingress_guard::Paths::default(),
            };
            let said = g.install(key).map_err(CliError::Msg)?;
            println!("{said}");
            Ok(())
        }
        SecretsCommand::BoxSecretsAdmin { args } => run_embedded(BOX_SECRETS_ADMIN, args),
        SecretsCommand::ConfigureBox { env_file } => configure_box(env_file),
        SecretsCommand::AdoptKms => adopt_kms(),
        SecretsCommand::AdoptStatus => adopt_status(),
        SecretsCommand::AdoptCancel { from_copy } => adopt_cancel(*from_copy),
        SecretsCommand::AdoptArm => adopt_arm(),
        SecretsCommand::ProbeKms => probe_kms(),
        SecretsCommand::RunnerSetup { project, socket } => runner_setup(project, socket.as_deref()),
        SecretsCommand::LoadBox { socket } => load_box(socket.as_deref()),
        SecretsCommand::RecoverStore {
            challenge,
            nonce,
            expires,
            signature,
            console,
        } => recover_store(
            *challenge,
            nonce.as_deref().zip(*expires).zip(signature.as_deref()),
            *console,
        ),
    }
}

/// `import` with --dry-run is the preview, even with --yes: nothing is sent or stored.
fn effective_yes(yes: bool, dry_run: bool) -> bool {
    yes && !dry_run
}

/// What `--dry-run` does for each `secrets` command. `None` means the command is allowed to run as it is: it reads only,
/// or it already honours the flag itself (`import` stops at its preview, `approve` mints nothing). A command that changes
/// something says what it would do and stops; the plumbing that only the box's own helpers run has no dry run and refuses
/// the flag, so a person is never left thinking nothing changed when something did.
fn dry_run_of(command: &SecretsCommand, json: bool) -> Option<Result<(), CliError>> {
    use crate::cli::ApprovalKeyCommand as K;
    use crate::cli::IngressCommand as I;
    let would = |what: String| -> Option<Result<(), CliError>> {
        if json {
            println!("{}", json!({"dry_run": true, "would": what}));
        } else {
            println!("{}", t("secrets.dry_run", &[("what", &what)]));
        }
        Some(Ok(()))
    };
    match command {
        SecretsCommand::Status | SecretsCommand::Import { .. } | SecretsCommand::Approve { .. } => {
            None
        }
        SecretsCommand::ApprovalKey { command: K::List { .. } } => None,
        SecretsCommand::RotateKek { to } => would(format!("move the store to a new key-encryption key ({to})")),
        SecretsCommand::RotateDataKeys => would("give every secret a new data key".into()),
        SecretsCommand::RotateHmac { overlap_hours } => would(format!(
            "make a new key for internal tokens (the previous one keeps working for {overlap_hours} hours)"
        )),
        SecretsCommand::Put { name, .. } => would(format!("store the secret {name} from standard input")),
        SecretsCommand::Remove { name, .. } => would(format!("remove the secret {name}")),
        SecretsCommand::ApprovalKey { command: K::Enroll { on_box, key, .. } } => would(format!(
            "enrol this computer's key {key} on {}",
            on_box.as_str()
        )),
        SecretsCommand::ApprovalKey { command: K::Revoke { on_box, key, .. } } => would(format!(
            "revoke the key {key} on {}",
            on_box.as_str()
        )),
        SecretsCommand::Ingress { command: I::Pin { on_box, .. } } => would(format!(
            "pin (or check) the service key of {} on this computer",
            on_box.as_str()
        )),
        SecretsCommand::Ingress { command: I::Escrow { on_box } } => would(format!(
            "keep a copy of {}'s store key in this computer's keychain",
            on_box.as_str()
        )),
        SecretsCommand::Ingress { command: I::Requests { action, on_box } } => match action {
            crate::cli::RequestsAction::Approve { id, .. } => {
                would(format!("approve request {id} on {} with this computer's key", on_box.as_str()))
            }
            crate::cli::RequestsAction::Deny { id, .. } => {
                would(format!("deny (or revoke) request {id} on {}", on_box.as_str()))
            }
            // reading a request, or the keys, changes nothing
            _ => None,
        },
        SecretsCommand::Ingress { command: I::SetupCode { on_box } } => would(format!(
            "ask {} for the dashboard's first-time setup code",
            on_box.as_str()
        )),
        // plumbing run by the box's own helpers, or a program started for the person: no dry run
        SecretsCommand::Serve { .. }
        | SecretsCommand::IngressSetup { .. }
        | SecretsCommand::Receive { .. }
        | SecretsCommand::RunAs
        | SecretsCommand::ExecEnv { .. }
        | SecretsCommand::ExecCred { .. }
        | SecretsCommand::EgressServe { .. }
        | SecretsCommand::Gate { .. }
        | SecretsCommand::SupervisorSetup { .. }
        | SecretsCommand::BoxSecretsAdmin { .. }
        | SecretsCommand::RecoverStore { .. }
        | SecretsCommand::ConfigureBox { .. }
        | SecretsCommand::RunnerSetup { .. }
        | SecretsCommand::AdoptKms
        | SecretsCommand::AdoptStatus
        | SecretsCommand::AdoptCancel { .. }
        | SecretsCommand::AdoptArm
        | SecretsCommand::ProbeKms
        | SecretsCommand::LoadBox { .. }
        | SecretsCommand::Exec { .. } => Some(Err(CliError::Msg(t("secrets.no_dry_run", &[])))),
    }
}

/// `ozbox secrets runner-setup PROJECT` (root): see `runner_setup`. Prints what it did, by name and count; the tool digests are
/// printed so the owner can pin them in the declaration.
#[cfg(unix)]
fn runner_setup(project: &str, socket: Option<&std::path::Path>) -> Result<(), CliError> {
    use crate::secrets_service::SocketSecrets;
    if !crate::runner_setup::is_root() {
        return Err(CliError::Msg(t("secrets.runner_setup_root", &[])));
    }
    let name = crate::workload_policy::secret_name(project).map_err(fail)?;
    let sock = socket
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| std::path::PathBuf::from("/run/ozbox-secrets/admin/admin.sock"));
    let v = SocketSecrets::new(sock)
        .call(serde_json::json!({"op": "get", "name": name}))
        .map_err(fail)?;
    let policy = match v["value"].as_str() {
        Some(h) => Some(crate::workload_policy::Policy::from_stored(h).map_err(fail)?),
        None => None,
    };
    let home = std::env::var("OZBOX_BOX_HOME")
        .ok()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::PathBuf::from(
                std::env::var("OZBOX_BOX_USER_HOME").unwrap_or_else(|_| "/work/home/ozbox".into()),
            )
        });
    let catalog = ozbox_catalog::embedded().map_err(CliError::Msg)?;
    let paths = crate::runner_setup::Paths::system(home);
    let sum = crate::runner_setup::apply(
        &paths,
        &crate::runner_setup::SystemAcl,
        &catalog,
        project,
        policy.as_ref(),
    )
    .map_err(CliError::Msg)?;
    if sum.granted {
        println!(
            "{}",
            t("secrets.runner_setup_done", &[("project", project)])
        );
    } else if sum.revoked {
        println!(
            "{}",
            t("secrets.runner_setup_revoked", &[("project", project)])
        );
    }
    for user in &sum.runners {
        println!("{}", t("secrets.runner_setup_runner", &[("user", user)]));
    }
    for (tool, digest) in &sum.tools {
        match digest {
            Some(d) => println!(
                "{}",
                t(
                    "secrets.runner_setup_tool",
                    &[("tool", tool), ("digest", d)]
                )
            ),
            None => println!(
                "{}",
                t("secrets.runner_setup_tool_system", &[("tool", tool)])
            ),
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn runner_setup(_: &str, _: Option<&std::path::Path>) -> Result<(), CliError> {
    Err(CliError::Msg(t("secrets.serve_unix_only", &[])))
}

/// The root helper's way into the store: the admin socket, which only root and the secrets user can reach.
fn admin_put(
    name: &str,
    socket: Option<&std::path::Path>,
    set: bool,
    base64: bool,
) -> Result<(), CliError> {
    use crate::secrets::SecretStore;
    use serde_json::json;
    if !crate::secrets::valid_name(name) {
        return Err(CliError::Msg(t("secrets.bad_name", &[])));
    }
    let path = socket
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| std::path::PathBuf::from("/run/ozbox-secrets/admin/admin.sock"));
    let svc = crate::secrets_service::SocketSecrets::new(path);
    if set {
        let mut line = zeroize::Zeroizing::new(String::new());
        std::io::stdin()
            .read_line(&mut line)
            .map_err(|_| CliError::Msg(t("secrets.serve_pass", &[])))?;
        if base64 {
            // any value, exactly: the line is its base64, and the store decides what it can hold
            let value = crate::serve::auth::b64::decode_std(line.trim())
                .and_then(|b| String::from_utf8(b).ok())
                .map(zeroize::Zeroizing::new)
                .ok_or_else(|| CliError::Msg(t("secrets.bad_base64", &[])))?;
            svc.set_exact(name, &value).map_err(fail)?;
        } else {
            crate::secrets::check_value(line.trim_end()).map_err(fail)?;
            svc.call(json!({"op": "set", "name": name, "value": line.trim_end()}))
                .map_err(fail)?;
        }
    } else {
        svc.call(json!({"op": "delete", "name": name}))
            .map_err(fail)?;
    }
    Ok(())
}

/// Move the store from a file-kept key to the fleet's KMS key named by this box's instance tag. Run as root, as a unit of its
/// own, by `configure-box`; see `secrets_adopt`.
fn probe_kms() -> Result<(), CliError> {
    let scope = std::env::var("OZBOX_SECRET_SCOPE").unwrap_or_else(|_| "local".into());
    let p = provider_named("kms", std::path::Path::new("/")).map_err(fail)?;
    crate::secrets_enc::probe(p.as_ref(), &scope).map_err(fail)?;
    println!("the KMS key wraps and unwraps a key under this box's encryption context");
    Ok(())
}

fn adopt_kms() -> Result<(), CliError> {
    #[cfg(unix)]
    {
        let imds = crate::box_config::Imds::new("http://169.254.169.254");
        let paths = crate::secrets_recover::Paths::default();
        let machine = crate::secrets_adopt::SystemMachine {
            runner: &ozbox_core::SystemRunner,
            paths: &paths,
        };
        match crate::secrets_adopt::adopt_locked(&paths, &machine, &imds) {
            Ok(done) => {
                println!("{}", done.says());
                Ok(())
            }
            Err(why) => Err(CliError::Msg(format!(
                "the move to the fleet's KMS key did not happen: {why}"
            ))),
        }
    }
    #[cfg(not(unix))]
    {
        Err(CliError::Msg(t("secrets.serve_unix_only", &[])))
    }
}

/// The lines the laptop reads through the cloud's root channel (see `secrets_adopt_facts`).
fn adopt_status() -> Result<(), CliError> {
    #[cfg(unix)]
    {
        let imds = crate::box_config::Imds::new("http://169.254.169.254");
        let paths = crate::secrets_recover::Paths::default();
        let machine = crate::secrets_adopt::SystemMachine {
            runner: &ozbox_core::SystemRunner,
            paths: &paths,
        };
        print!(
            "{}",
            crate::secrets_adopt::facts(&paths, &machine, &imds).render()
        );
        Ok(())
    }
    #[cfg(not(unix))]
    {
        Err(CliError::Msg(t("secrets.serve_unix_only", &[])))
    }
}

/// Record the cancel and take a moved store back; prints `cancel=ok`, `cancel=busy` or `cancel=failed: <why>`, then the facts.
fn adopt_cancel(from_copy: bool) -> Result<(), CliError> {
    #[cfg(unix)]
    {
        let imds = crate::box_config::Imds::new("http://169.254.169.254");
        let paths = crate::secrets_recover::Paths::default();
        let machine = crate::secrets_adopt::SystemMachine {
            runner: &ozbox_core::SystemRunner,
            paths: &paths,
        };
        let done = if from_copy {
            crate::secrets_adopt::cancel_from_copy_locked(&paths, &machine, &imds)
        } else {
            crate::secrets_adopt::cancel_locked(&paths, &machine, &imds)
        };
        match done {
            Ok(crate::secrets_adopt::Outcome::Busy) => println!("cancel=busy"),
            Ok(_) => println!("cancel=ok"),
            Err(why) => {
                let one: String = why.chars().filter(|c| !c.is_control()).take(300).collect();
                println!("cancel=failed: {one}");
            }
        }
        print!(
            "{}",
            crate::secrets_adopt::facts(&paths, &machine, &imds).render()
        );
        Ok(())
    }
    #[cfg(not(unix))]
    {
        Err(CliError::Msg(t("secrets.serve_unix_only", &[])))
    }
}

fn adopt_arm() -> Result<(), CliError> {
    #[cfg(unix)]
    {
        let paths = crate::secrets_recover::Paths::default();
        match crate::secrets_adopt::arm_locked(&paths) {
            Ok(crate::secrets_adopt::Outcome::Busy) => println!("arm=busy"),
            Ok(_) => println!("arm=ok"),
            Err(why) => println!("arm=failed: {why}"),
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        Err(CliError::Msg(t("secrets.serve_unix_only", &[])))
    }
}

fn configure_box(env_file: &std::path::Path) -> Result<(), CliError> {
    use crate::box_config::{configure, Imds, Outcome};
    let imds = Imds::new("http://169.254.169.254");
    // A box whose person asked for its store to move to the fleet's KMS key says so in an instance tag (see `secrets_adopt`).
    // The move takes a minute or more and stops the secrets service, so it is NOT done here: this step is the box-secrets
    // unit's ExecStartPre, which systemd gives 90 seconds before it kills it, and a kill half way would leave the service
    // stopped. It runs as a unit of its own (`ozbox secrets adopt-kms`), started here without waiting, so nothing bounds it.
    #[cfg(unix)]
    {
        let paths = crate::secrets_recover::Paths::default();
        if crate::secrets_adopt::pending(&paths, &imds) {
            match crate::secrets_adopt::start_unit(&ozbox_core::SystemRunner) {
                Ok(()) => println!("the move of the secrets store to the fleet's KMS key was started (see `journalctl -u ozbox-adopt-fleet-key`)"),
                Err(why) => eprintln!("the move to the fleet's KMS key did not start: {why}"),
            }
        }
    }
    let o = configure(&imds, env_file).map_err(CliError::Msg)?;
    println!(
        "{}",
        match o {
            Outcome::NoMetadata => "no instance metadata here; nothing changed",
            Outcome::Written => "the box's secrets settings were written from its instance tags",
            Outcome::Unchanged => "the box's secrets settings already match its instance tags",
            Outcome::Removed =>
                "the instance tags are gone; the settings this step wrote were removed",
            Outcome::NothingDeclared => "this box declares no secrets of its own",
        }
    );
    Ok(())
}

/// The supervisor's setup script, carried in the program so the first-boot configuration does not have to carry it.
const SUPERVISOR_SETUP: &str =
    include_str!("../../../infra/cloud-init/scripts/ozbox-supervisor-setup.sh");

fn supervisor_setup(args: &[String]) -> Result<(), CliError> {
    run_embedded(SUPERVISOR_SETUP, args)
}

/// The box's secrets declaration and vault token script (Hetzner has no instance tags), carried here for the same reason.
const BOX_SECRETS_ADMIN: &str =
    include_str!("../../../infra/cloud-init/scripts/ozbox-box-secrets.sh");

fn run_embedded(script: &str, args: &[String]) -> Result<(), CliError> {
    use std::io::Write;
    let mut c = std::process::Command::new("bash")
        .arg("-s")
        .arg("--")
        .args(args)
        .stdin(std::process::Stdio::piped())
        .spawn()
        .map_err(|_| CliError::Msg("bash could not be started".into()))?;
    if let Some(mut i) = c.stdin.take() {
        let _ = i.write_all(script.as_bytes());
    }
    let st = c
        .wait()
        .map_err(|_| CliError::Msg("the setup did not finish".into()))?;
    std::process::exit(st.code().unwrap_or(1));
}

/// Pull the box's own secrets from the provider and give them to the service. Never prints a value or a path.
fn load_box(socket: Option<&std::path::Path>) -> Result<(), CliError> {
    use crate::box_secrets::{plan, root_for, AwsSsm, Backend, OpenBao};
    let env = |k: &str| std::env::var(k).unwrap_or_default();
    let (backend, prefix, role) = (
        env("OZBOX_BOX_SECRETS_BACKEND"),
        env("OZBOX_BOX_SECRETS_PATH"),
        env("OZBOX_BOX_ROLE"),
    );
    if backend.is_empty() {
        // nothing configured: a box that keeps no secrets of its own
        println!("no box secrets are configured");
        return Ok(());
    }
    let root = root_for(&prefix, &role).map_err(CliError::Msg)?;
    let runner = ozbox_core::SystemRunner;
    let params = match backend.as_str() {
        "aws-ssm" => AwsSsm::new(&env("OZBOX_BOX_SECRETS_REGION")).fetch(&root),
        "openbao" => OpenBao {
            runner: &runner,
            mount: std::env::var("OZBOX_BOX_SECRETS_MOUNT").unwrap_or_else(|_| "secret".into()),
        }
        .fetch(&root),
        _ => {
            return Err(CliError::Msg(
                "the box secrets backend must be aws-ssm or openbao".into(),
            ))
        }
    }
    .map_err(CliError::Msg)?;
    let (items, skipped) = plan(&root, params);
    let from = match backend.as_str() {
        "aws-ssm" => AwsSsm::new("").label(),
        _ => OpenBao {
            runner: &runner,
            mount: String::new(),
        }
        .label(),
    };
    let path = socket
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| std::path::PathBuf::from("/run/ozbox-secrets/admin/admin.sock"));
    let lines: Vec<_> = items
        .iter()
        .map(|i| json!({"project": i.project, "env": i.env, "name": i.name, "value": i.value.as_str()}))
        .collect();
    crate::secrets_service::SocketSecrets::new(path)
        .call(json!({"op": "box_load", "scope": role, "items": lines}))
        .map_err(fail)?;
    println!(
        "{} secrets loaded from {from} for role {role}; skipped {} malformed and {} production-looking",
        items.len(),
        skipped.malformed,
        skipped.production_looking
    );
    escrow_key(&runner);
    Ok(())
}

/// Set aside a store that cannot be opened, for a new one (see `secrets_recover` for exactly when that is allowed). Run as
/// root by the root helper; a challenge first, then its signature, or `--console` at the machine itself.
fn recover_store(
    challenge: bool,
    signed: Option<((&str, u64), &str)>,
    console: bool,
) -> Result<(), CliError> {
    use crate::secrets_recover as r;
    let paths = r::Paths::default();
    let facts = r::facts(&ozbox_core::SystemRunner);
    let now = crate::tokenmac::now_ms();
    let moved = if challenge {
        let c = r::challenge(&paths, &facts, now).map_err(CliError::Msg)?;
        println!("{}", c.words());
        return Ok(());
    } else if let Some(((nonce, expires), sig)) = signed {
        r::redeem(&paths, &facts, nonce, expires, sig, now).map_err(CliError::Msg)?
    } else if console {
        #[cfg(unix)]
        let root_at_a_terminal =
            running_as_root() && std::io::IsTerminal::is_terminal(&std::io::stdin());
        #[cfg(not(unix))]
        let root_at_a_terminal = false;
        if !root_at_a_terminal {
            return Err(CliError::Msg(
                "--console is for root at the machine's own console (a terminal); nothing was changed".into(),
            ));
        }
        r::console(&paths, &facts).map_err(CliError::Msg)?
    } else {
        return Err(CliError::Msg(
            "recovering a store needs the approval of the key pinned when this box was made: run `ozbox admin <box> -- recover-secrets` on your computer (it asks for a challenge and signs it); nothing was changed".into(),
        ));
    };
    println!(
        "set aside {moved} copies of the old store (renamed, never opened); start the secrets service to begin a new one. The box's own secrets come back from its vault; enter again anything that was kept only on the box"
    );
    Ok(())
}

/// Whether this process runs as root (the owner of /proc/self is the process's user; Linux, the only place this runs).
#[cfg(unix)]
fn running_as_root() -> bool {
    std::fs::metadata("/proc/self")
        .map(|m| std::os::unix::fs::MetadataExt::uid(&m) == 0)
        .unwrap_or(false)
}

/// A box that keeps its store's key in a file escrows it in its vault, so a replaced system disk can open the store again
/// (see `secrets_escrow`). Run by the loader, which holds the vault token. Says what it did; never the key.
fn escrow_key(runner: &dyn ozbox_core::CommandRunner) {
    if !crate::secrets_file::file_kek_selected() {
        return;
    }
    let Ok(store) = std::env::var("OZBOX_SECRET_FILE") else {
        return;
    };
    let scope = std::env::var("OZBOX_SECRET_SCOPE").unwrap_or_else(|_| "local".into());
    let Some(escrow) = crate::secrets_escrow::Escrow::from_env(&|k| std::env::var(k).ok(), &scope)
    else {
        println!("the store's key is kept in a file and this box has no vault escrow for it: an upgrade will start a new store");
        return;
    };
    let file = std::path::Path::new(&store).with_file_name(crate::secrets_persist::KEY_FILE);
    let Ok(kek) = std::fs::read_to_string(&file).map(zeroize::Zeroizing::new) else {
        return;
    };
    match escrow.place(runner, &kek) {
        Ok(true) => println!("the store's key was escrowed in the vault"),
        Ok(false) => {}
        Err(e) => eprintln!("{e}"),
    }
}

/// The root helper's check before a gated change: the code arrives on standard input, the answer is how it was allowed.
fn gate(
    scope: &str,
    project: &str,
    env: &str,
    bind_token_stdin: bool,
    socket: Option<&std::path::Path>,
) -> Result<(), CliError> {
    let path = socket
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| std::path::PathBuf::from("/run/ozbox-secrets/admin/admin.sock"));
    let mut line = zeroize::Zeroizing::new(String::new());
    let _ = std::io::stdin().read_line(&mut line);
    // The token being stored is read here, in root's own process, before the code is spent: the approval is for THAT token.
    // (A token the box user can swap in a file after the check is not a risk this way: the helper hands over the bytes it
    // already holds.)
    let bound;
    let env = if bind_token_stdin {
        let mut tok = zeroize::Zeroizing::new(String::new());
        let _ = std::io::stdin().read_line(&mut tok);
        if tok.trim().is_empty() {
            return Err(CliError::Msg(t("approval_key.token_stdin_empty", &[])));
        }
        bound = crate::secrets_approval::tunnel_token_binding(&tok);
        bound.as_str()
    } else {
        env
    };
    let v = crate::secrets_service::SocketSecrets::new(path)
        .call(
            json!({"op": "gate", "scope": scope, "project": project, "env": env,
            "approval": line.trim()}),
        )
        .map_err(fail)?;
    println!("{}", v["value"].as_str().unwrap_or("allowed"));
    Ok(())
}

fn exec(env: &[String], command: &[String]) -> Result<(), CliError> {
    let store = crate::secrets_file::select();
    let mut c = std::process::Command::new(&command[0]);
    c.args(&command[1..]);
    for pair in env {
        let (var, name) = pair
            .split_once('=')
            .filter(|(v, n)| {
                !v.is_empty()
                    && !n.is_empty()
                    && v.bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
            })
            .ok_or_else(|| CliError::Msg(t("secrets.exec_bad_env", &[])))?;
        let value = store
            .get(name)
            .map_err(fail)?
            .ok_or_else(|| CliError::Msg(t("secrets.exec_missing", &[("name", name)])))?;
        c.env(var, value);
    }
    let status = c
        .status()
        .map_err(|_| CliError::Msg(t("secrets.exec_failed", &[])))?;
    std::process::exit(status.code().unwrap_or(1));
}

/// The note a ready box with a file-kept, un-escrowed key carries, and what `ozbox upgrade` reads as "a new store".
pub const FILE_KEK_NOT_ESCROWED: &str = "the store's key is kept in a file on this box's system disk and is not escrowed in a vault, so a system-disk replacement (an upgrade) starts a new store; `ozbox upgrade` says so and asks first. Give the box a KMS key (AWS: [aws] secrets_key_arn), or box secrets on OpenBao with a token, to keep it";

/// Where the service says whether it is ready, for a user who cannot open the store (the box user).
pub const STATE_FILE: &str = "/run/ozbox-secrets/state";
const NOT_READY_EXIT: i32 = 78;

fn state_path() -> std::path::PathBuf {
    std::env::var_os("OZBOX_SECRETS_STATE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(STATE_FILE))
}

/// The service's state (see `secrets_state`). World readable: it names what is missing, never a value. Replaced whole.
#[cfg(unix)]
fn write_state(path: &std::path::Path, state: &crate::secrets_state::State) {
    use std::os::unix::fs::PermissionsExt;
    let tmp = path.with_extension("tmp");
    if std::fs::write(&tmp, state.render()).is_ok() {
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644));
        let _ = std::fs::rename(&tmp, path);
    }
}

/// What the state file says: ready, or why not (and, when the service wrote them, what protects the store).
fn interpret_state(text: &str, why: &str) -> (bool, String) {
    match crate::secrets_state::State::parse(text) {
        Some(s) => (s.ready, s.text),
        None => (
            false,
            format!(
                "the secrets service has not said anything ({why}). Is ozbox-secrets.service installed and started? `ozbox admin <box> -- collect-logs` shows its log"
            ),
        ),
    }
}

/// What `ozbox secrets status` says when this user has no store to open.
fn status_of_service(why: &str, json: bool) -> Result<(), CliError> {
    let state = std::fs::read_to_string(state_path()).ok();
    let (ready, reason) = interpret_state(state.as_deref().unwrap_or(""), why);
    let parsed = state
        .as_deref()
        .and_then(crate::secrets_state::State::parse);
    if json {
        // `key`, `escrow` and `code` are additive: what protects the store, whether a file-kept key has a copy off the
        // box, and why the service is not ready (see `secrets_state`). Absent when an older service wrote the state.
        let p = parsed.unwrap_or_default();
        println!(
            "{}",
            json!({"service": if ready {"ready"} else {"not_ready"}, "reason": reason,
                "key": p.kek, "escrow": p.escrow.map(|e| if e {"vault"} else {"none"}), "code": p.code})
        );
    } else if ready {
        println!(
            "The box's secrets service is running. This user cannot list or read what it holds."
        );
        if !reason.is_empty() {
            println!("{reason}");
        }
    }
    if ready {
        Ok(())
    } else {
        Err(CliError::Msg(format!(
            "The box's secrets service is not ready: {reason}"
        )))
    }
}

#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn serve(
    box_socket: &std::path::Path,
    runner: Option<&std::path::Path>,
    admin: Option<&std::path::Path>,
    import: Option<&std::path::Path>,
    ingress: Option<&std::path::Path>,
    broker_socket: Option<&std::path::Path>,
    supervisor: Option<&std::path::Path>,
    memory_store: Option<&std::path::Path>,
    audit: Option<(&std::path::Path, Option<&std::path::Path>)>,
    persist: Option<&std::path::Path>,
    passphrase_stdin: bool,
) -> Result<(), CliError> {
    let state = box_socket
        .parent()
        .and_then(std::path::Path::parent)
        .map(|d| d.join("state"))
        .unwrap_or_else(state_path);
    // A passphrase is read once from standard input: nothing to read it from again, so no retry in this process.
    let attempts = if passphrase_stdin {
        1
    } else {
        RETRIES_IN_PROCESS
    };
    let mut delay = std::time::Duration::from_secs(2);
    // What protects the store, and whether a file-kept key has a copy off the box: said in every state the service writes.
    let kek = if passphrase_stdin {
        Some("passphrase")
    } else {
        crate::secrets_file::kek_kind_with(
            &|k| std::env::var(k).ok(),
            crate::secrets_enc::TpmKek::available(),
        )
    };
    let scope = std::env::var("OZBOX_SECRET_SCOPE").unwrap_or_else(|_| "local".into());
    let escrow = (kek == Some("file")).then(|| {
        crate::secrets_escrow::Escrow::from_env(&|k| std::env::var(k).ok(), &scope).is_some()
    });
    // When this stopped being ready, kept across the unit's restarts so the self-test can tell a failure that lasts from one that
    // is only starting. Fixed at the first not-ready write; carried over from the file before when that was not ready too.
    let failing_since: std::cell::Cell<Option<u64>> = std::cell::Cell::new(
        std::fs::read_to_string(&state)
            .ok()
            .and_then(|t| crate::secrets_state::previous_failing_since(&t)),
    );
    let not_ready = |m: &str, code: &str| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let since = failing_since.get().map_or(now, |t| t.min(now));
        failing_since.set(Some(since));
        crate::secrets_state::State::not_ready(m, code, kek, escrow).with_failing_since(since)
    };
    for attempt in 1..=attempts {
        let failed = match serve_inner(
            box_socket,
            runner,
            admin,
            import,
            ingress,
            broker_socket,
            supervisor,
            memory_store,
            audit,
            persist,
            passphrase_stdin,
            &state,
        ) {
            Ok(()) => return Ok(()),
            Err(f) => f,
        };
        match failed {
            // Not configured is a state, not a crash: say why where the box user can read it, and exit with a code the
            // unit does not restart on (a restart every few seconds changes nothing and hides the reason).
            StartFailure::Config(m) => {
                write_state(&state, &not_ready(&m, "config"));
                eprintln!("the secrets service is not ready: {m}");
                std::process::exit(NOT_READY_EXIT);
            }
            // The store is there and its key is gone with no copy anywhere: the one state in which the store may be set
            // aside (`ozbox admin <box> -- recover-secrets`), so it has a code of its own.
            StartFailure::NoEscrow(m) => {
                write_state(&state, &not_ready(&m, crate::secrets_state::NO_ESCROW_CODE));
                eprintln!("the secrets service is not ready: {m}");
                std::process::exit(NOT_READY_EXIT);
            }
            // The store was sealed by a key kept in a file, this service is configured for another kind, and the file key is
            // gone with no copy: nothing on the box can open it. Also for good, and recorded as such (never as a restart), so the
            // store can be set aside for a new one.
            StartFailure::KindMismatch { message, stored } => {
                let st = not_ready(&message, crate::secrets_state::KIND_MISMATCH_CODE)
                    .with_store_kek(&stored);
                write_state(&state, &st);
                eprintln!("the secrets service is not ready: {message}");
                std::process::exit(NOT_READY_EXIT);
            }
            // The key service, the TPM, the vault or the disk did not answer: that passes. Try again here with a growing
            // wait, then exit with an ordinary failure so the unit starts it again (and reads its settings files again: a
            // vault token placed in the meantime is seen).
            StartFailure::Transient(m) => {
                if attempt == attempts {
                    write_state(
                        &state,
                        &not_ready(&format!("{m} (starting again)"), "transient"),
                    );
                    eprintln!("the secrets service could not start: {m}");
                    std::process::exit(1);
                }
                write_state(
                    &state,
                    &not_ready(
                        &format!("{m} (trying again in {} s)", delay.as_secs()),
                        "transient",
                    ),
                );
                eprintln!("the secrets service could not start, trying again: {m}");
                std::thread::sleep(delay);
                delay = next_delay(delay);
            }
        }
    }
    Ok(())
}

/// Why the service did not start. Only a configuration state stops it for good (exit 78); anything that can pass is retried.
#[derive(Debug, PartialEq, Eq)]
enum StartFailure {
    /// Nothing will change until a person changes the box's configuration: no key source, no store named.
    Config(String),
    /// The store is there, its file-kept key is not, and no escrow holds a copy. Also for good, and the only state in which
    /// the store may be set aside for a new one.
    NoEscrow(String),
    /// The store is sealed by a key kept in a file (`stored`), the service is configured for another kind, and the file key is
    /// gone with no copy. For good, like `NoEscrow`: the other state in which the store may be set aside.
    KindMismatch { message: String, stored: String },
    /// The key service, a TPM, the vault, the network or a disk failed: worth trying again.
    Transient(String),
}

/// How many times the service tries to start before it exits for the unit to start it again.
const RETRIES_IN_PROCESS: u32 = 6;
const MAX_RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(300);

fn next_delay(d: std::time::Duration) -> std::time::Duration {
    (d * 2).min(MAX_RETRY_DELAY)
}

/// Which kind of failure an error from choosing the store's key source is. Only the words this program writes for a
/// missing configuration are configuration; a key service or a TPM that failed to answer is transient.
fn classify_key_source(e: &crate::secrets::SecretError) -> StartFailure {
    let m = e.0.clone();
    let config = m == crate::secrets_file::NO_KEK
        || m == crate::secrets_file::KEY_FILE_MISSING
        || m.starts_with("OZBOX_SECRET_KEK")
        || m.contains("needs OZBOX_KMS_KEY_ID")
        || m.contains("settings are not valid")
        || m.contains("passphrase key is entered");
    if config {
        StartFailure::Config(m)
    } else {
        StartFailure::Transient(m)
    }
}

/// What a store sealed by a key of another kind than the one configured means. Only a store sealed by a file-kept key whose
/// key is gone (`key_file_present` false) with no copy anywhere (`escrow`) can never be opened; any other mismatch is left to
/// be retried as it always was (a key file that is there can still be moved with `ozbox adopt-fleet-key`).
fn classify_kind_mismatch(
    stored: &str,
    configured: &str,
    key_file_present: bool,
    escrow: Option<crate::secrets_escrow::Missing>,
) -> StartFailure {
    use crate::secrets_escrow::Missing;
    let plain = || StartFailure::Transient(crate::secrets_enc::KEK_KIND_MISMATCH.to_string());
    if stored != "file" || stored == configured || key_file_present {
        return plain();
    }
    match escrow {
        Some(Missing::NoEscrow(_)) => StartFailure::KindMismatch {
            message: format!(
                "the store was sealed by a key kept in a file, but this box is configured for {configured}, and that file key is not on this disk and no copy of it is held anywhere: the store cannot be opened"
            ),
            stored: stored.to_string(),
        },
        _ => plain(),
    }
}

/// A store sealed by another kind of key than the one configured never opens, however often it is tried. Say so, in a state of
/// its own, when the key it was sealed with is also gone (see `classify_kind_mismatch`); a store of the configured kind passes.
fn store_kind_gate(
    path: &std::path::Path,
    configured: &str,
    key_file: &std::path::Path,
    escrow: Option<&crate::secrets_escrow::Escrow>,
) -> Result<(), StartFailure> {
    let Some(stored) = crate::secrets_enc::EncryptedSecrets::stored_kek(path) else {
        return Ok(());
    };
    if stored == configured {
        return Ok(());
    }
    let copy = (stored == "file" && !key_file.exists()).then(|| {
        let declared = crate::secrets_escrow::Escrow::declared(&|k| std::env::var(k).ok());
        crate::secrets_escrow::recover_key(escrow, declared, &ozbox_core::SystemRunner, key_file)
    });
    Err(classify_kind_mismatch(
        &stored,
        configured,
        key_file.exists(),
        copy,
    ))
}

#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn serve_inner(
    box_socket: &std::path::Path,
    runner: Option<&std::path::Path>,
    admin: Option<&std::path::Path>,
    import: Option<&std::path::Path>,
    ingress: Option<&std::path::Path>,
    broker_socket: Option<&std::path::Path>,
    supervisor: Option<&std::path::Path>,
    memory_store: Option<&std::path::Path>,
    audit: Option<(&std::path::Path, Option<&std::path::Path>)>,
    persist: Option<&std::path::Path>,
    passphrase_stdin: bool,
    state: &std::path::Path,
) -> Result<(), StartFailure> {
    use crate::secrets_enc::{EncryptedSecrets, KeyProvider, LocalKekProvider};
    use crate::secrets_service::{listen, serve_gates, Policy};
    use StartFailure::{Config, Transient};
    let io = |e: std::io::Error| Transient(e.to_string());
    let path = std::path::PathBuf::from(
        std::env::var("OZBOX_SECRET_FILE")
            .map_err(|_| Config("OZBOX_SECRET_FILE must name the encrypted store".into()))?,
    );
    let scope = std::env::var("OZBOX_SECRET_SCOPE").unwrap_or_else(|_| "local".into());
    // A replaced system disk comes back with no store: put back the copy kept on the persistent disk, before anything opens it.
    if let Some(p) = persist {
        // The copy is on /work, which is mounted after the system starts. Starting without it would make a new store and
        // then overwrite the real copy, so wait for it (a couple of minutes), and if it never comes, say so and stop.
        if p.starts_with("/work") {
            let mut waited = 0;
            while !crate::secrets_persist::on_persistent_disk(p) {
                if waited >= 120 {
                    return Err(Transient(
                        "/work is not mounted yet, so the box's saved secrets cannot be put back"
                            .into(),
                    ));
                }
                std::thread::sleep(std::time::Duration::from_secs(2));
                waited += 2;
            }
        }
        let back = crate::secrets_persist::restore(&path, p, &scope);
        if let Some(theirs) = back.foreign {
            // a clone, or a disk restored from another box: that box's store is not this one's, and was removed
            eprintln!("the copy of the secrets store on /work belonged to another box ({theirs}) and was removed; this box starts its own");
        }
    }
    // A box that keeps its key in a file: the key never travels with /work, so a replaced system disk has the store but not
    // its key. It comes back from the vault's escrow; with no escrow nothing can bring it back (a configuration state).
    let file_kek = !passphrase_stdin && crate::secrets_file::file_kek_selected();
    let escrow = crate::secrets_escrow::Escrow::from_env(&|k| std::env::var(k).ok(), &scope);
    let key_file = path.with_file_name(crate::secrets_persist::KEY_FILE);
    // The owner's own copy of the key, put back through the ingress account while this service was down (`ozbox upgrade` does
    // it from the owner's keychain): used only if it really opens this store, and always removed.
    if crate::secrets_ingress::take_inbox(
        &crate::secrets_ingress::inbox_dir(),
        &key_file,
        file_kek && path.exists(),
        &|t| crate::secrets_ingress::kek_opens_store(&path, &scope, t),
    ) == crate::secrets_ingress::Inbox::Placed
    {
        eprintln!("the store's key was put back by its owner, through the ingress account");
    }
    if file_kek && path.exists() && !key_file.exists() {
        use crate::secrets_escrow::{recover_key, Missing};
        let declared = crate::secrets_escrow::Escrow::declared(&|k| std::env::var(k).ok());
        match recover_key(
            escrow.as_ref(),
            declared,
            &ozbox_core::SystemRunner,
            &key_file,
        ) {
            Missing::Recovered => eprintln!("the store's key came back from the vault's escrow"),
            Missing::NoEscrow(m) => return Err(StartFailure::NoEscrow(m)),
            Missing::Unavailable(m) => return Err(Transient(m)),
        }
    }
    let provider: Arc<dyn KeyProvider> = if passphrase_stdin {
        let mut line = zeroize::Zeroizing::new(String::new());
        std::io::stdin()
            .read_line(&mut line)
            .map_err(|_| Config(t("secrets.serve_pass", &[])))?;
        let salt = match EncryptedSecrets::stored_salt(&path) {
            Some(s) => s,
            None => {
                let mut s = vec![0u8; 16];
                getrandom::getrandom(&mut s)
                    .map_err(|_| Transient("no random numbers are available".into()))?;
                s
            }
        };
        Arc::new(
            LocalKekProvider::from_passphrase("passphrase", line.trim_end(), &salt)
                .map_err(|e| Config(e.0))?,
        )
    } else {
        crate::secrets_file::provider_from_env(&path).map_err(|e| classify_key_source(&e))?
    };
    store_kind_gate(&path, &provider.label(), &key_file, escrow.as_ref())?;
    // The box's own secrets: a second store on tmpfs, sealed under the same key and gone when the machine stops.
    let memory = match memory_store {
        Some(p) => Some(Arc::new(
            EncryptedSecrets::new(p.to_path_buf(), &scope, provider.clone())
                .map_err(|e| Transient(e.0))?,
        )),
        None => None,
    };
    let store = Arc::new(
        crate::secrets_file::open_encrypted(path, &scope, provider).map_err(|e| Transient(e.0))?,
    );
    // With a supervisor socket the box user's two sockets shrink (see `Policy::BoxLocked`, `Policy::BrokerLocked`).
    let locked = supervisor.is_some();
    let mut ls = vec![(
        listen(box_socket, 0o750).map_err(io)?,
        if locked {
            Policy::BoxLocked
        } else {
            Policy::Box
        },
    )];
    if let Some(p) = supervisor {
        ls.push((listen(p, 0o750).map_err(io)?, Policy::Supervisor));
    }
    if let Some(p) = runner {
        ls.push((listen(p, 0o750).map_err(io)?, Policy::Runner));
    }
    if let Some(p) = admin {
        ls.push((listen(p, 0o700).map_err(io)?, Policy::Admin));
    }
    if let Some(p) = import {
        ls.push((listen(p, 0o750).map_err(io)?, Policy::Import));
    }
    // The way a person's computer reaches this service: the folder belongs to the `ozbox-ingress` account's group (the
    // ingress setup made it), and what arrives there is a public-key request or a sealed one.
    if let Some(p) = ingress {
        ls.push((listen(p, 0o750).map_err(io)?, Policy::Ingress));
    }
    // The credential broker lives here: a model key is opened in this process and nowhere else (ADR 0017).
    let broker = match broker_socket {
        Some(p) => {
            ls.push((
                listen(p, 0o750).map_err(io)?,
                if locked {
                    Policy::BrokerLocked
                } else {
                    Policy::Broker
                },
            ));
            let pins = store.path().with_file_name("broker-pins.json");
            Some(
                crate::broker::Broker::start_with(
                    store.clone() as Arc<dyn crate::secrets::SecretStore>,
                    Arc::new(crate::broker::NetUpstream),
                    Some(pins),
                )
                .map_err(Transient)?,
            )
        }
        None => None,
    };
    // The audit chain (ADR 0028): its folder is readable by every user of the machine and written by this service alone;
    // the second copy of each checkpoint is in a folder only this user opens.
    let audit_cfg = match audit {
        Some((dir, anchor)) => {
            use std::os::unix::fs::PermissionsExt;
            let anchor_dir = anchor
                .map(std::path::Path::to_path_buf)
                .unwrap_or_else(|| store.path().with_file_name("audit-anchor"));
            std::fs::create_dir_all(dir).map_err(io)?;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).map_err(io)?;
            std::fs::create_dir_all(&anchor_dir).map_err(io)?;
            std::fs::set_permissions(&anchor_dir, std::fs::Permissions::from_mode(0o700))
                .map_err(io)?;
            Some(Arc::new(crate::audit_service::AuditCfg::new(
                dir, anchor_dir,
            )))
        }
        None => None,
    };
    let gates = crate::secrets_service::gates_for(memory, audit_cfg);
    if ingress.is_some() {
        let ing = crate::secrets_ingress::Ingress::load_or_create(store.as_ref(), &scope)
            .map_err(|e| Transient(e.0))?;
        let _ = gates.ingress.set(Arc::new(ing));
    }
    if file_kek {
        let _ = gates.kek_file.set(key_file.clone());
    }
    // The approval requests (ADR 0041): their journal beside the store, and the epoch, the spent ledger and the "has ever had
    // a key" markers in a directory of their own beside it, which replacing the store file does not reach. A journal that
    // cannot be opened is said in the log and leaves the request operations off, never the service down.
    {
        let dir = store.path().with_file_name("approval-requests");
        let state_dir = store.path().with_file_name("approval-state");
        match gates.enable_requests(&store, &dir, &state_dir, &scope, crate::tokenmac::now_ms()) {
            Ok(()) => {}
            Err(e) => {
                // the version's own protections stay on without the journal (phase 2 re-check NL1)
                let _ = gates.requests_failed.set(());
                eprintln!("the approval requests are off: {e}; the dashboard still makes no key enrolment code and a code enrolment still waits 24 hours");
            }
        }
    }
    // Two settings only root can change: whether scope-only codes are refused beside requests (on by default until
    // phase 3: root's off-switch file turns them off), and whether a verified attestation makes a presence key
    // (off until a real key has been proved on a box).
    let flag = |name: &str, path: &str| -> bool {
        let state = crate::approval_key::root_flag_state(std::path::Path::new(path));
        if state == crate::approval_key::FlagState::Untrusted {
            // an untrusted file is ignored, so the setting is the default: said loudly, never silently (phase 2 re-check NL9)
            eprintln!(
                "WARNING: {path} exists but is not a plain file owned by root that no one else can write, so it is IGNORED and {name} stays at its default; fix its owner and mode, then restart the secrets service"
            );
        }
        state == crate::approval_key::FlagState::On
    };
    let codes_off = flag(
        "approvals.legacy_codes_off",
        crate::approval_key::LEGACY_CODES_OFF_FLAG,
    );
    let presence = flag(
        "approvals.presence_keys",
        crate::approval_key::PRESENCE_KEYS_FLAG,
    );
    let _ = gates.legacy_codes_off.set(codes_off);
    let _ = gates.presence_keys.set(presence);
    // the settings read once, at start: a change to either file takes effect when the service restarts
    // what is in effect, not what root's file says: with no journal the codes stay on whatever the file says (RL1)
    eprintln!(
        "{}",
        approvals_start_line(codes_off, !gates.codes_allowed(), presence)
    );
    if let Some(p) = persist {
        let _ = gates.pin_record.set(p.to_path_buf());
    }
    // The first approver is the key pinned when the box was made (root wrote it at first boot), never one sent from the
    // box. A file that is not root's, or not in the right shape, is ignored and said so in the log.
    let pin_path = std::env::var_os("OZBOX_PINNED_APPROVERS")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(crate::approval_key::PIN_FILE));
    match crate::approval_key::read_pin(&pin_path)
        .and_then(|p| crate::approval_key::apply_pin(&store, &gates, p))
    {
        Ok(Some(id)) => {
            eprintln!("the approval key pinned when this box was made ({id}) is enrolled")
        }
        Ok(None) => {}
        Err(e) => eprintln!("{e}"),
    }
    eprintln!("{}", t("secrets.serve_running", &[]));
    let kind = if passphrase_stdin {
        "passphrase"
    } else {
        crate::secrets_file::kek_kind_with(
            &|k| std::env::var(k).ok(),
            crate::secrets_enc::TpmKek::available(),
        )
        .unwrap_or("file")
    };
    let mut ready = if file_kek && escrow.is_none() {
        crate::secrets_state::State::ready(FILE_KEK_NOT_ESCROWED, "file", Some(false))
    } else {
        crate::secrets_state::State::ready("", kind, file_kek.then_some(true))
    };
    // what a new store would lose: `ozbox upgrade --use-fleet-key` moves only a store that holds nothing
    if let Some(n) = crate::secrets_service::user_name_count(&store) {
        ready = ready.with_names(n);
    }
    write_state(state, &ready);
    if let Some(p) = persist {
        crate::secrets_persist::spawn_saver(
            store.path().to_path_buf(),
            p.to_path_buf(),
            p.starts_with("/work"),
        );
    }
    serve_gates(store, ls, broker, gates);
    Ok(())
}

#[cfg(not(unix))]
fn serve(
    _: &std::path::Path,
    _: Option<&std::path::Path>,
    _: Option<&std::path::Path>,
    _: Option<&std::path::Path>,
    _: Option<&std::path::Path>,
    _: Option<&std::path::Path>,
    _: Option<&std::path::Path>,
    _: Option<&std::path::Path>,
    _: Option<(&std::path::Path, Option<&std::path::Path>)>,
    _: Option<&std::path::Path>,
    _: bool,
) -> Result<(), CliError> {
    Err(CliError::Msg(t("secrets.serve_unix_only", &[])))
}

/// The start line for the two root-only approval settings: what is IN EFFECT, and, when root's off file is not, why (phase 2
/// RL1: with no request journal the service takes codes whatever the file says, so the line must not say they are off).
fn approvals_start_line(codes_off_flag: bool, codes_in_effect_off: bool, presence: bool) -> String {
    let override_note = if codes_off_flag && !codes_in_effect_off {
        " (root's off file is NOT in effect: the request journal did not open, so codes stay on)"
    } else {
        ""
    };
    format!(
        "approvals: scope-only codes {}{} and presence keys {} (root's files are read at start)",
        if codes_in_effect_off { "off" } else { "on" },
        override_note,
        if presence { "on" } else { "off" }
    )
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn the_approvals_start_line_says_what_is_in_effect_not_what_the_flag_says() {
        // root's file says off and the journal is open: off, no note
        let l = approvals_start_line(true, true, false);
        assert!(
            l.contains("scope-only codes off and presence keys off"),
            "{l}"
        );
        // root's file says off but the journal failed, so codes stay on: the line says on and names the override
        let l = approvals_start_line(true, false, true);
        assert!(
            l.contains("scope-only codes on (root's off file is NOT in effect"),
            "{l}"
        );
        assert!(l.contains("presence keys on"), "{l}");
        // no file: on, no note
        let l = approvals_start_line(false, false, false);
        assert!(
            l.contains("scope-only codes on and presence keys off"),
            "{l}"
        );
        assert!(!l.contains("NOT in effect"), "{l}");
    }

    #[test]
    fn the_box_user_is_told_why_the_store_is_not_ready_and_how_to_fix_it() {
        let (ok, _) = interpret_state("ready\n", "x");
        assert!(ok);
        let (ok, why) = interpret_state(
            &format!("not-ready: {}\n", crate::secrets_file::NO_KEK),
            "x",
        );
        assert!(!ok && why.contains("KMS key") && why.contains("OZBOX_SECRET_ALLOW_FILE_KEK=1"));
        // silence is a reason too, and it points at the log
        let (ok, why) = interpret_state("", "OZBOX_SECRET_FILE must name the encrypted store");
        assert!(!ok && why.contains("collect-logs"));
    }

    /// The finding this closes: a key service that failed for a moment at boot stopped the service for good (exit 78, never
    /// retried), and its sockets never came.
    #[test]
    fn only_a_missing_configuration_stops_the_service_and_a_failing_key_service_is_retried() {
        use crate::secrets::SecretError;
        for config in [
            crate::secrets_file::NO_KEK.to_string(),
            crate::secrets_file::KEY_FILE_MISSING.to_string(),
            "OZBOX_SECRET_KEK must be kms, tpm2, keychain or file".to_string(),
            "OZBOX_SECRET_KEK=kms needs OZBOX_KMS_KEY_ID to name the key".to_string(),
        ] {
            assert!(
                matches!(
                    classify_key_source(&SecretError(config.clone())),
                    StartFailure::Config(_)
                ),
                "{config}"
            );
        }
        for passing in [
            "the key service could not be reached",
            "the TPM is busy",
            "the store could not be read",
        ] {
            assert!(matches!(
                classify_key_source(&SecretError(passing.into())),
                StartFailure::Transient(_)
            ));
        }
        // the wait grows and is capped
        let mut d = std::time::Duration::from_secs(2);
        for _ in 0..20 {
            d = next_delay(d);
        }
        assert_eq!(d, MAX_RETRY_DELAY);
        // a ready state may carry a note, and is still ready
        let (ok, note) = interpret_state("ready: the store's key is not escrowed", "");
        assert!(ok && note.contains("not escrowed"));
    }

    #[test]
    fn a_state_file_is_world_readable_and_replaced_whole() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("state");
        write_state(
            &p,
            &crate::secrets_state::State::not_ready("no key", "config", Some("file"), None),
        );
        assert_eq!(
            std::fs::read_to_string(&p).unwrap(),
            "not-ready: no key\nkek=file\ncode=config\nadopt=kms\n"
        );
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o644
        );
        write_state(&p, &crate::secrets_state::State::ready("", "kms", None));
        assert_eq!(
            std::fs::read_to_string(&p).unwrap(),
            "ready\nkek=kms\nadopt=kms\n"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod dry_run_tests {
    use super::*;
    use crate::cli::{Cli, Command};
    use clap::Parser;

    /// Parse a real command line. The gate is asserted directly (`dry_run_of`), never by running the command: a
    /// regression must fail a test, not act on the developer's own store or keychain.
    fn gate(args: &[&str]) -> Option<Result<(), CliError>> {
        let mut argv = vec!["ozbox", "--dry-run", "--yes"];
        argv.extend_from_slice(args);
        let cli = Cli::try_parse_from(argv).unwrap();
        assert!(cli.dry_run && cli.yes);
        let Command::Secrets { command } = &cli.command else {
            panic!("not a secrets command");
        };
        dry_run_of(command, true)
    }

    #[test]
    fn dry_run_stops_every_secrets_command_that_changes_something() {
        for args in [
            vec!["secrets", "rotate-kek", "--to", "keychain"],
            vec!["secrets", "rotate-data-keys"],
            vec!["secrets", "rotate-hmac"],
            vec!["secrets", "put", "--name", "a-secret"],
            vec!["secrets", "remove", "--name", "a-secret"],
            vec!["secrets", "approval-key", "enroll", "--box", "dev"],
            vec!["secrets", "approval-key", "revoke", "--box", "dev"],
        ] {
            assert!(
                matches!(gate(&args), Some(Ok(()))),
                "{args:?} was not stopped by --dry-run"
            );
        }
        // import --yes with --dry-run: the command goes on to its preview, with yes taken away (nothing sent or stored)
        for args in [
            vec![
                "secrets",
                "import",
                ".env",
                "--project",
                "app",
                "--env",
                "staging",
            ],
            vec![
                "secrets",
                "import",
                ".env",
                "--project",
                "app",
                "--env",
                "staging",
                "--box",
                "dev",
            ],
        ] {
            assert!(gate(&args).is_none());
        }
        assert!(
            !effective_yes(true, true)
                && effective_yes(true, false)
                && !effective_yes(false, false)
        );
    }

    #[test]
    fn the_plumbing_refuses_the_flag_instead_of_ignoring_it() {
        for args in [
            vec!["secrets", "exec", "--env", "A=b", "--", "true"],
            vec!["secrets", "gate", "--scope", "import"],
            vec!["secrets", "run-as"],
        ] {
            let Some(Err(e)) = gate(&args) else {
                panic!("{args:?} must refuse --dry-run");
            };
            assert!(e.to_string().contains("no dry run"), "{args:?}: {e}");
        }
    }

    /// A store sealed by a file-kept key, found by a service configured for the fleet's KMS key, with the file key gone and no
    /// copy anywhere: recorded as `kind-mismatch` (for good, exit 78), never as a restart.
    #[test]
    fn a_file_sealed_store_under_a_kms_configuration_with_no_key_is_recorded_as_unopenable() {
        use crate::secrets::SecretStore;
        use crate::secrets_enc::{EncryptedSecrets, KeyProvider, LocalKekProvider};
        let d = tempfile::tempdir().unwrap();
        let store = d.path().join("secrets.json");
        let key_file = d.path().join(crate::secrets_persist::KEY_FILE);
        // no store yet: nothing to say
        assert!(store_kind_gate(&store, "kms", &key_file, None).is_ok());
        let kek = LocalKekProvider::random("file").unwrap();
        let s = EncryptedSecrets::new(
            store.clone(),
            "dev",
            std::sync::Arc::new(kek) as std::sync::Arc<dyn KeyProvider>,
        )
        .unwrap();
        s.set("projects/app/X", "v").unwrap();
        // the kinds match: the gate says nothing
        assert!(store_kind_gate(&store, "file", &key_file, None).is_ok());
        // kms configured, a file-sealed store, no key file, no escrow: unopenable, and what sealed it is named
        match store_kind_gate(&store, "kms", &key_file, None) {
            Err(StartFailure::KindMismatch { stored, .. }) => assert_eq!(stored, "file"),
            other => panic!("{other:?}"),
        }
        // the key file is there: the store can still be moved (`ozbox adopt-fleet-key`), so it is the old retry, not a loss
        std::fs::write(&key_file, "k").unwrap();
        assert!(matches!(
            store_kind_gate(&store, "kms", &key_file, None),
            Err(StartFailure::Transient(m)) if m == crate::secrets_enc::KEK_KIND_MISMATCH
        ));
        // a store sealed by something else than a file key is never called lost on this evidence
        assert!(matches!(
            classify_kind_mismatch("tpm2", "kms", false, None),
            StartFailure::Transient(_)
        ));
    }
}
