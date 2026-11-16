//! Commands that need a project's secrets run as a user of their own (ADR 0018, item 8). The agent and the box user never
//! share a uid with the process that holds the values: `/proc/<pid>/environ` and a ptrace attach both refuse across
//! uids, and Yama refuses the attach even from a parent.
//!
//! The pieces: the agent runs `ozbox env run --named test -- npm test`. That connects to a launcher socket (the box user
//! may connect, nobody else may). The launcher is a root program started by a socket-activated unit, one process per
//! request. It reads the project's declaration, asks the secrets service for the values the command may receive (a
//! production key is refused there), and starts the command with `systemd-run` as `ozbox-run-<project>`, in the project
//! folder, with the project's build folders as the only writable place. The values travel as ONE JSON line on the unit's
//! standard input, to a small step inside the unit (`ozbox secrets exec-env`, [`exec_env_command`]) that sets each variable
//! directly in the environment of the command it then starts. Never through an argument list, never through a file, and
//! never through text another program parses: the service manager's `EnvironmentFile=` unquotes, unescapes and splits on
//! newlines, so a value with a newline would add a variable (`PATH=` or `LD_PRELOAD=` among them) that beats the sandbox's
//! own. What comes back to the agent is the command's output with every known value of the project removed.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::workload::{collect, redact};
use crate::workload_policy::Policy;

pub const LAUNCH_SOCKET: &str = "/run/ozbox-runner/launch.sock";
/// The step inside the unit that takes the environment from standard input and starts the command.
pub const EXEC_ENV: [&str; 4] = ["/usr/local/bin/ozbox", "secrets", "exec-env", "--"];
/// The step inside a service's unit that turns its credentials into environment variables (`credential_env`).
pub const EXEC_CRED: [&str; 4] = ["/usr/local/bin/ozbox", "secrets", "exec-cred", "--"];
/// Where the launcher puts a service's secrets for the moment systemd takes to load them (root's, mode 0700, a folder per unit).
pub const CRED_ROOT: &str = "/run/ozbox-cred";
/// The most the environment line may hold (a value is at most 96 KB, and a command has a handful).
const MAX_ENV_LINE: u64 = 4 << 20;
pub const RUN_HOME: &str = "/var/lib/ozbox-run";
/// Root-owned copies of what the commands run: the tools (`bin/` holds the links), the browsers, and the verified pinned files.
pub const TOOLS_ROOT: &str = "/opt/ozbox-run-tools";
pub const BROWSERS_ROOT: &str = "/opt/ozbox-run-browsers";
/// The work area a secret command sees only through a private view.
pub const WORK_ROOT: &str = "/work";
pub const PINS_ROOT: &str = "/var/lib/ozbox-run/.pins";
/// A service stops by itself after this long if nobody stopped it.
pub(crate) const SERVICE_MAX_SECS: u32 = 4 * 3600;
/// The longest one run of a declared command may take.
const RUN_MAX_SECS: u32 = 30 * 60;
/// How long `--start` waits for the health check, and how often it asks.
const HEALTH_WAIT_MS: u64 = 60_000;
const HEALTH_POLL_MS: u64 = 250;
const MAX_REQUEST: u64 = 64 * 1024;
const MAX_ARGS: usize = 64;

/// The project's own runner user: its plain commands and its services.
pub fn runner_user(project: &str) -> String {
    format!("ozbox-run-{project}")
}

/// The runner user of one command that is GIVEN A SECRET: a user of its own, so no service, browser or other command ever shares
/// a uid with the process that holds the value (`/proc/<pid>/environ` of a process is readable by any process of the same uid,
/// and `PR_SET_DUMPABLE` does not survive the `execve` that starts the command). A short name made from the project and the
/// command (a Linux user name is at most 32 characters, and a command name alone is up to 32): `ozrc-` and the FULL first 128 bits of
/// the SHA-256 of `project NUL command`, in lowercase base32 (26 characters, 31 in all). Nobody can pick a project and command that
/// land on another's name; and `runner_setup::ensure_user` refuses to reuse a user it did not make for exactly this pair.
pub fn secret_runner_user(project: &str, command: &str) -> String {
    let d = ring::digest::digest(
        &ring::digest::SHA256,
        format!("{project}\0{command}").as_bytes(),
    );
    format!(
        "ozrc-{}",
        crate::serve::auth::b64::encode_base32(&d.as_ref()[..16]).to_ascii_lowercase()
    )
}

/// The user a command runs as.
pub fn runner_user_for(
    project: &str,
    command: &str,
    cp: &crate::workload_policy::CommandPolicy,
) -> String {
    if cp.bears_secrets() {
        secret_runner_user(project, command)
    } else {
        runner_user(project)
    }
}

/// Every runner user a declaration needs: the project's, then one per command that receives a secret.
pub fn runner_users(project: &str, policy: &Policy) -> Vec<String> {
    let mut v = vec![runner_user(project)];
    v.extend(
        policy
            .commands
            .iter()
            .filter(|(_, c)| c.bears_secrets())
            .map(|(n, _)| secret_runner_user(project, n)),
    );
    v
}

/// A runner user's home: the project runner's is `RUN_HOME/<project>`, a command's `RUN_HOME/<its user>`.
fn runner_home(project: &str, user: &str) -> String {
    if user == runner_user(project) {
        format!("{RUN_HOME}/{project}")
    } else {
        format!("{RUN_HOME}/{user}")
    }
}

fn seg_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The PATH a command runs with: this project's tools (a root-owned copy named by its content) first, then the system's. Without
/// tools declared it is the system's alone, as before.
pub fn run_path(project: &str, policy: &Policy) -> String {
    if policy.tools.is_empty() {
        "/usr/local/bin:/usr/bin:/bin".to_string()
    } else {
        format!("{TOOLS_ROOT}/bin/{project}:/usr/local/bin:/usr/bin:/bin")
    }
}

/// The first systemd that has `PrivatePIDs=` (a unit of its own PID namespace: it cannot see another unit's processes at all, even
/// of its own uid). Not assumed: a box asks `systemctl --version`, and a systemd without it simply goes without.
pub const MIN_SYSTEMD_PRIVATE_PIDS: u32 = 257;

/// What a unit's hardening depends on that differs between boxes.
#[derive(Debug, Clone, Copy, Default)]
pub struct Host {
    pub private_pids: bool,
}

/// The unit's properties every run and every service shares: who it is, what it may see and where it may go. Pure, so a test
/// can read it. `user` is the runner user the unit runs as (it decides the home).
fn sandbox_props(
    project: &str,
    user: &str,
    policy: &Policy,
    browser: bool,
    mounts: &[crate::runner_pins::Mount],
    host: Host,
    private: bool,
) -> Vec<String> {
    let home = runner_home(project, user);
    let mut rw = vec![format!("-{home}")];
    let dir = policy.dir.trim_end_matches('/');
    for w in &policy.writable {
        rw.push(format!("-{dir}/{w}"));
    }
    let mut props = vec![
        format!("Environment=HOME={home}"),
        format!("Environment=PATH={}", run_path(project, policy)),
    ];
    // only a command that drives a browser is told where the browsers are (never one that receives a secret)
    if browser && !policy.browsers.is_empty() {
        props.push(format!(
            "Environment=PLAYWRIGHT_BROWSERS_PATH={BROWSERS_ROOT}/{project}"
        ));
    }
    props.extend(
        [
            "NoNewPrivileges=yes",
            "PrivateTmp=yes",
            "PrivateDevices=yes",
            "ProtectSystem=strict",
            "ProtectHome=yes",
            // other users' processes are hidden from /proc (a command that receives a secret is another UID than everything
            // else that runs: see `secret_runner_user`)
            "ProtectProc=invisible",
            "ProcSubset=pid",
            "ProtectKernelTunables=yes",
            "ProtectControlGroups=yes",
            "RestrictSUIDSGID=yes",
            "LockPersonality=yes",
            // a secret does not go to swap, and a crash does not write the environment to a core file
            "MemorySwapMax=0",
            "LimitCORE=0",
            // The command's network is this machine's loopback and nothing else: no name server, no other host (ADR 0023).
            // What it may reach beyond is the egress proxy, which listens there.
            "IPAddressDeny=any",
            "IPAddressAllow=127.0.0.1 ::1",
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
        ]
        .map(String::from),
    );
    if host.private_pids {
        props.push("PrivatePIDs=yes".into());
    }
    props.push(format!("ReadWritePaths={}", rw.join(" ")));
    // A command that receives a secret gets a PRIVATE VIEW of the whole work area (G5 third round, NV-H1): `/work` is an empty,
    // read-only tmpfs in the unit's own mount namespace, and only what was verified is put back in it, at its own path: the pinned
    // files and folders (root-owned copies, bound read-only) and the declared writable folders (bound from the live folder, which
    // the launcher has checked is a real folder). Node looks for a `package.json` and a `node_modules` ABOVE the script too, so a
    // view that starts at the project folder still shows the agent's files one level up; rooted at `/work`, no folder above the
    // project and no other project exists in the unit, and every folder on the way to the project is a root-owned directory of the
    // tmpfs (so a swap of a folder on the live path, NV-M1, is never looked at: the unit never opens it).
    if private {
        props.push(format!("TemporaryFileSystem={WORK_ROOT}:ro"));
        for w in &policy.writable {
            props.push(format!("BindPaths={dir}/{w}:{dir}/{w}"));
        }
    }
    // the service's own files and sockets are not in the command's view, whoever it runs as. `/run/ozbox-cred` (where a service's
    // secrets are staged for systemd) is hidden too, in depth: it is root-only already, and systemd reads `LoadCredential=` files in
    // the manager, as root, BEFORE it builds the unit's mount namespace (credentials are set up in the unit's exec setup and only
    // then is the namespace entered), so hiding it from the unit does not stop the credential from loading. The leading `-` means a
    // missing folder is not an error.
    props.push(
        "InaccessiblePaths=-/run/ozbox-runner -/run/ozbox-secrets -/run/ozbox-admin -/etc/ozbox -/var/lib/ozbox-secrets -/run/ozbox-cred"
            .to_string(),
    );
    // pinned files and folders: the verified copy is what the command opens
    for m in mounts {
        props.push(m.property());
    }
    props
}

/// Every writable folder a secret command is given must be a real folder, not a link and not missing: the launcher looks at each
/// once before the unit starts (`BindPaths=` of a missing source would otherwise be skipped, and the command would meet a read-only
/// tmpfs with no word of why; a link would be followed to somewhere the declaration did not name).
pub fn check_writable(dir: &Path, writable: &[String]) -> Result<(), String> {
    for w in writable {
        let p = dir.join(w);
        match std::fs::symlink_metadata(&p) {
            Ok(m) if m.is_dir() => {}
            Ok(m) if m.file_type().is_symlink() => {
                return Err(format!("the writable folder {w} is a link: it is not started with a link in place of a folder the declaration named"));
            }
            Ok(_) => return Err(format!("the writable folder {w} is not a folder")),
            Err(_) => {
                return Err(format!(
                    "the writable folder {w} is missing: create it (as the box user) and run again, a command that receives a secret needs it in place"
                ));
            }
        }
    }
    Ok(())
}

fn push_props(v: &mut Vec<String>, props: Vec<String>) {
    for p in props {
        v.push("-p".into());
        v.push(p);
    }
}

/// The exact argument list of the `systemd-run` call. Pure, so a test can read it: it holds no secret value (those are on
/// the unit's standard input) and it is the whole of the sandbox the command runs in.
#[cfg(test)]
pub fn systemd_run_argv(project: &str, id: &str, policy: &Policy, argv: &[String]) -> Vec<String> {
    let cp = crate::workload_policy::CommandPolicy::default();
    systemd_run_argv_with(
        project,
        &runner_user(project),
        id,
        policy,
        &cp,
        argv,
        &[],
        Host::default(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn systemd_run_argv_with(
    project: &str,
    user: &str,
    id: &str,
    policy: &Policy,
    cp: &crate::workload_policy::CommandPolicy,
    argv: &[String],
    mounts: &[crate::runner_pins::Mount],
    host: Host,
) -> Vec<String> {
    let mut v: Vec<String> = ["systemd-run", "--quiet", "--pipe", "--wait", "--collect"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    v.push(format!("--unit=ozbox-run-{project}-{id}"));
    v.push(format!("--uid={user}"));
    v.push(format!("--gid={user}"));
    v.push(format!("--working-directory={}", policy.dir));
    let mut props = sandbox_props(
        project,
        user,
        policy,
        cp.browser,
        mounts,
        host,
        cp.bears_secrets(),
    );
    // 30 minutes: `RuntimeMaxSec` is the systemd property for it (`TimeoutRunSec` is not one: systemd-run refuses the whole unit)
    props.push(format!("RuntimeMaxSec={RUN_MAX_SECS}"));
    push_props(&mut v, props);
    v.push("--".into());
    v.extend(EXEC_ENV.iter().map(|s| s.to_string()));
    v.extend(argv.iter().cloned());
    v
}

/// A service's unit. The project and the command are joined by `_`, which neither can contain ([`seg_ok`] allows only
/// `[a-z0-9-]`), so two different (project, command) pairs never make one name: `a-b` + `c` and `a` + `b-c` were the same unit
/// under the hyphen name (env-run review round 3, E5).
pub fn service_unit(project: &str, command: &str) -> String {
    format!("ozbox-svc-{project}_{command}")
}

/// The name an earlier release gave the same service (`ozbox-svc-<project>-<command>`). Still looked for by `--stop`, `--status`
/// and `--start` so a service that was running when the box was upgraded is found, stopped and never started twice.
pub fn legacy_service_unit(project: &str, command: &str) -> String {
    format!("ozbox-svc-{project}-{command}")
}

/// Whether a `systemctl is-active` answer means "nothing of this unit is running or on its way in or out".
fn unit_idle(state: &str) -> bool {
    matches!(state.trim(), "" | "inactive" | "failed" | "unknown")
}

/// The unit a service is running under right now: the new name, or the earlier release's when that is the one that is up. The new
/// name when neither is.
fn live_service_unit(be: &dyn Backend, project: &str, command: &str) -> String {
    let new = service_unit(project, command);
    if !unit_idle(&be.unit_state(&new)) {
        return new;
    }
    let old = legacy_service_unit(project, command);
    if !unit_idle(&be.unit_state(&old)) {
        return old;
    }
    new
}

/// What a service is given besides its plain variables: where its credentials are staged (names only: a value is never in an
/// argument) and the public values it receives as plain environment.
#[derive(Default)]
pub struct ServiceInputs<'a> {
    /// The names of the credentials staged for this unit (see [`credential_path`]).
    pub credentials: &'a [String],
    /// This start's own staging folder name (a nonce), returned by [`Backend::stage_credentials`]; two starts never share one.
    pub stage: &'a str,
    /// Public values, already checked ([`crate::workload_policy::public_value_ok`]).
    pub public: &'a [(String, String)],
    /// The service's route out (ADR 0029 Amendment 12): its proxy unit and the ports the environment names. `None` for a service
    /// that declares nothing to reach.
    pub route: Option<&'a crate::runner_egress::Route>,
}

/// Where the credential `name` of `unit` is staged for systemd to read, in this start's own folder (`stage`, see
/// [`stage_credentials_in`]).
pub fn credential_path(unit: &str, stage: &str, name: &str) -> String {
    format!("{CRED_ROOT}/{unit}/{stage}/{name}")
}

/// A service is a unit of its own that outlives the launcher: no `--pipe`, no `--wait`, no 30-minute limit (it has its own,
/// longer one) and no standard input (there is none to carry a secret on). Its plain variables are properties, which is why
/// their values are limited to characters that need no quoting. A secret is never a property: it is a systemd credential
/// (`LoadCredential=NAME:PATH`, a path and never a value), which the unit reads from `$CREDENTIALS_DIRECTORY` (ADR 0029
/// Amendment 12). With credentials the unit is `Type=exec` and the call is not `--no-block`, so it returns once systemd has run
/// the program, which is when the staged files may be deleted. `env` runs it with the unit's PATH and nothing else of the
/// launcher's; `credential_env` runs it through `ozbox secrets exec-cred`, which sets each credential as a variable.
pub fn systemd_run_service_argv(
    project: &str,
    command: &str,
    policy: &Policy,
    cp: &crate::workload_policy::CommandPolicy,
    mounts: &[crate::runner_pins::Mount],
    host: Host,
    inputs: &ServiceInputs<'_>,
) -> Vec<String> {
    // a command that receives a secret runs as the user only it uses; any other as the project's own runner
    let user = runner_user_for(project, command, cp);
    let unit = service_unit(project, command);
    let with_credentials = !inputs.credentials.is_empty();
    let mut v: Vec<String> = ["systemd-run", "--quiet", "--collect"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    if !with_credentials {
        v.push("--no-block".into());
    }
    v.push(format!("--unit={unit}"));
    v.push(format!("--uid={user}"));
    v.push(format!("--gid={user}"));
    v.push(format!("--working-directory={}", policy.dir));
    let mut props = sandbox_props(
        project,
        &user,
        policy,
        cp.browser,
        mounts,
        host,
        cp.bears_secrets(),
    );
    props.push(format!("RuntimeMaxSec={SERVICE_MAX_SECS}"));
    props.push("Restart=no".into());
    props.push("StandardInput=null".into());
    if with_credentials {
        props.push("Type=exec".into());
        for n in inputs.credentials {
            props.push(format!(
                "LoadCredential={n}:{}",
                credential_path(&unit, inputs.stage, n)
            ));
        }
    }
    for (k, val) in &cp.vars {
        props.push(format!("Environment={k}={val}"));
    }
    for (k, val) in inputs.public {
        props.push(format!("Environment={k}={val}"));
    }
    if let Some(route) = inputs.route {
        props.extend(crate::runner_egress::route_props(route));
    }
    push_props(&mut v, props);
    v.push("--".into());
    if cp.credential_env && with_credentials {
        v.extend(EXEC_CRED.iter().map(|s| s.to_string()));
    } else {
        v.push("/usr/bin/env".into());
        v.push("--".into());
    }
    v.extend(cp.argv.iter().cloned());
    v
}

/// Put a service's secrets where systemd will read them: a folder of this unit under `root` (mode 0700), and in it a folder of THIS
/// start (a random name, mode 0700, returned), one file per credential (mode 0400). Two starts of one service therefore never
/// share or remove each other's files, and a failure part-way removes what this start wrote. The launcher is root, so root owns all
/// of it; a test runs it as itself.
pub fn stage_credentials_in(
    root: &Path,
    unit: &str,
    pairs: &[(String, Zeroizing<String>)],
) -> Result<String, String> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
    let bad = || "the service's secrets could not be put in place".to_string();
    // the unit's name is the folder's: only what `service_unit` makes
    let rest = unit.strip_prefix("ozbox-svc-").unwrap_or("");
    if rest.is_empty()
        || rest.len() > 80
        || !rest
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    {
        return Err(bad());
    }
    let mut raw = [0u8; 8];
    getrandom::getrandom(&mut raw).map_err(|_| bad())?;
    let stage: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(root)
        .map_err(|_| bad())?;
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).map_err(|_| bad())?;
    let unit_dir = root.join(unit);
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&unit_dir)
        .map_err(|_| bad())?;
    let dir = unit_dir.join(&stage);
    let result = (|| -> Result<(), String> {
        // `create` (not recursive): a folder that already exists is a failure, never shared
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .map_err(|_| bad())?;
        for (name, value) in pairs {
            let name_ok = !name.is_empty()
                && name.len() <= 64
                && !name.as_bytes()[0].is_ascii_digit()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
            if !name_ok || value.contains('\0') {
                return Err(bad());
            }
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o400)
                .open(dir.join(name))
                .map_err(|_| bad())?;
            f.write_all(value.as_bytes()).map_err(|_| bad())?;
        }
        Ok(())
    })();
    match result {
        Ok(()) => Ok(stage),
        Err(e) => {
            let _ = std::fs::remove_dir_all(&dir);
            Err(e)
        }
    }
}

/// Remove staged secrets: one start's folder (`Some(stage)`, after the start, whatever its outcome), or every one of the unit
/// (`None`, a stop).
pub fn clear_credentials_in(root: &Path, unit: &str, stage: Option<&str>) {
    match stage {
        // a nonce is hex; anything else would be a path, and is never joined
        Some(st) if !st.is_empty() && st.bytes().all(|b| b.is_ascii_hexdigit()) => {
            let _ = std::fs::remove_dir_all(root.join(unit).join(st));
        }
        Some(_) => {}
        None => {
            let _ = std::fs::remove_dir_all(root.join(unit));
        }
    }
}

/// How old a staging folder must be before a sweep takes it: a start needs a few seconds (`UNIT_WAIT`), so a folder this old was
/// left by a launcher that was killed between staging and clearing.
pub const CRED_STALE_SECS: u64 = 120;

/// Remove staged secrets nobody is going to clear: every start folder older than `older_than_secs`, or, with `project`, every
/// folder of that project's services whatever its age (setup stops those services first, so none is being started). Returns
/// how many folders went. Never follows a link; a folder that cannot be read is left alone.
pub fn sweep_credentials_in(root: &Path, project: Option<&str>, older_than_secs: u64) -> usize {
    let mut n = 0;
    let Ok(units) = std::fs::read_dir(root) else {
        return 0;
    };
    let now = std::time::SystemTime::now();
    for u in units.flatten() {
        let name = u.file_name().to_string_lossy().to_string();
        let Ok(meta) = std::fs::symlink_metadata(u.path()) else {
            continue;
        };
        if !meta.is_dir() {
            // nothing but unit folders belongs here; a stray file is not a staged secret of ours, but it is not kept either
            if std::fs::remove_file(u.path()).is_ok() {
                n += 1;
            }
            continue;
        }
        if let Some(p) = project {
            // a service of this project: `ozbox-svc-<project>_<command>`, or an earlier release's `ozbox-svc-<project>-<command>`
            // (a hyphen name has no `_`, so a project `app-two`'s new name is never taken for `app`'s)
            let mine = name.starts_with(&format!("ozbox-svc-{p}_"))
                || (name.starts_with(&format!("ozbox-svc-{p}-")) && !name.contains('_'));
            if !mine {
                continue;
            }
            if std::fs::remove_dir_all(u.path()).is_ok() {
                n += 1;
            }
            continue;
        }
        let Ok(stages) = std::fs::read_dir(u.path()) else {
            continue;
        };
        for st in stages.flatten() {
            let old = std::fs::symlink_metadata(st.path())
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| now.duration_since(t).ok())
                .is_some_and(|d| d.as_secs() >= older_than_secs);
            if old && std::fs::remove_dir_all(st.path()).is_ok() {
                n += 1;
            }
        }
    }
    n
}

/// The step inside a service's unit with `credential_env`: every file of `dir` (systemd's `$CREDENTIALS_DIRECTORY`) becomes a
/// variable of the same name, and the program is started with its standard input closed. A name that is not a variable name, a
/// file that is a link or a folder, or a value that is not text without a NUL byte refuses the start.
pub fn exec_cred_command(dir: &Path, argv: &[String]) -> Result<Command, String> {
    let bad = || "the credentials are not valid".to_string();
    let (prog, args) = argv.split_first().ok_or_else(bad)?;
    let mut c = Command::new(prog);
    c.args(args).stdin(Stdio::null());
    let mut names: Vec<String> = Vec::new();
    for e in std::fs::read_dir(dir).map_err(|_| bad())? {
        let e = e.map_err(|_| bad())?;
        let name = e.file_name().into_string().map_err(|_| bad())?;
        let name_ok = !name.is_empty()
            && name.len() <= 256
            && !name.as_bytes()[0].is_ascii_digit()
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
        let meta = std::fs::symlink_metadata(e.path()).map_err(|_| bad())?;
        // a credential is never allowed to become a variable that decides how a program starts or loads code, whatever the
        // declaration or the folder says (the same list that refuses a declared `vars` name)
        if name_ok && crate::workload_policy::reserved_name(&name, &[]).is_some() {
            return Err(format!(
                "the credential {name} cannot be set as a variable: it decides how a program starts"
            ));
        }
        if !name_ok || !meta.is_file() {
            return Err(bad());
        }
        names.push(name);
    }
    names.sort();
    for name in names {
        let bytes = Zeroizing::new(std::fs::read(dir.join(&name)).map_err(|_| bad())?);
        let val = std::str::from_utf8(&bytes).map_err(|_| bad())?;
        if val.contains('\0') {
            return Err(bad());
        }
        c.env(&name, val);
    }
    Ok(c)
}

/// The effective user of this process.
#[cfg(unix)]
fn current_euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// Whether `dir` is a credentials folder the shim may read: a real directory (no link anywhere on its path) directly under `root`
/// (`/run/credentials/`, which only root can create folders in), owned by one of `owners` (root, which is how systemd makes it;
/// or the unit's own user, which is how it hands the folder over on a file system with no ACLs), and writable by nobody else. A
/// `CREDENTIALS_DIRECTORY` that a declaration redirected to a folder the agent can write fails here.
#[cfg(unix)]
pub fn credentials_dir_ok(dir: &Path, root: &Path, owners: &[u32]) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let bad = || "this unit's credentials folder is not the one systemd made".to_string();
    // directly under the root, as the comment says: `/run/credentials/<unit>`, not a folder further down
    if dir.parent() != Some(root) {
        return Err(bad());
    }
    // no `..`, no link: the path is its own canonical form
    if std::fs::canonicalize(dir).map_err(|_| bad())? != dir {
        return Err(bad());
    }
    let m = std::fs::symlink_metadata(dir).map_err(|_| bad())?;
    if !m.is_dir() || !owners.contains(&m.uid()) || m.permissions().mode() & 0o022 != 0 {
        return Err(bad());
    }
    Ok(())
}

/// The unit's side of `credential_env`: read `$CREDENTIALS_DIRECTORY`, set the variables, become the program.
#[cfg(unix)]
pub fn exec_cred_main(argv: &[String]) -> Result<(), String> {
    use std::os::unix::process::CommandExt;
    let dir = std::env::var_os("CREDENTIALS_DIRECTORY")
        .map(PathBuf::from)
        .filter(|d| d.is_absolute())
        .ok_or_else(|| "this unit has no credentials".to_string())?;
    // systemd's own folder, and nothing a declaration or the agent could point it at
    credentials_dir_ok(&dir, Path::new("/run/credentials"), &[0, current_euid()])?;
    harden_self();
    let mut c = exec_cred_command(&dir, argv)?;
    // only returns when the program could not be started
    let e = c.exec();
    Err(format!("the program could not be started ({})", e.kind()))
}

/// The step inside the unit: `line` is the one JSON line the launcher wrote (`{"env":[["NAME","value"],...]}`), `argv` the
/// command. Returns the command with every variable set directly in its environment and its standard input closed. The
/// values are data here: no shell, no file, no parser but JSON. A name that is not a variable name, or a value with a NUL
/// byte, refuses the whole run.
pub fn exec_env_command(line: &str, argv: &[String]) -> Result<Command, String> {
    let bad = || "that request is not valid".to_string();
    let v: Value = serde_json::from_str(line.trim_end()).map_err(|_| bad())?;
    let pairs = v["env"].as_array().ok_or_else(bad)?;
    let (prog, args) = argv.split_first().ok_or_else(bad)?;
    let mut c = Command::new(prog);
    c.args(args).stdin(Stdio::null());
    for p in pairs {
        let (k, val) = match (p[0].as_str(), p[1].as_str()) {
            (Some(k), Some(val)) => (k, val),
            _ => return Err(bad()),
        };
        let name_ok = !k.is_empty()
            && k.len() <= 256
            && !k.as_bytes()[0].is_ascii_digit()
            && k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
        if !name_ok || val.contains('\0') {
            return Err(bad());
        }
        c.env(k, val);
    }
    Ok(c)
}

/// What the launcher feeds a run: the pairs as the one line [`exec_env_command`] reads.
fn env_line(pairs: &[(String, Zeroizing<String>)]) -> Zeroizing<String> {
    let list: Vec<[&str; 2]> = pairs
        .iter()
        .map(|(k, v)| [k.as_str(), v.as_str()])
        .collect();
    Zeroizing::new(format!("{}\n", json!({ "env": list })))
}

/// Make this process non-dumpable while it holds the environment line (`PR_SET_DUMPABLE=0`): no other process of its uid can read
/// its memory or `environ`, and it leaves no core file. **This is NOT what protects the command.** The kernel resets the flag to
/// dumpable on the `execve` that starts the command (the new program has a new memory image), so once the command runs, only a
/// uid of its own (`secret_runner_user`) and a unit that cannot see other units (`PrivatePIDs`) keep another process out of
/// `/proc/<pid>/environ`. Linux only; elsewhere there is nothing to set.
#[cfg(target_os = "linux")]
fn harden_self() {
    let _ = rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable);
}

#[cfg(not(target_os = "linux"))]
fn harden_self() {}

/// The unit's side of [`env_line`]: read the line from standard input, set the variables, become the command.
#[cfg(unix)]
pub fn exec_env_main(argv: &[String]) -> Result<(), String> {
    use std::os::unix::process::CommandExt;
    let mut line = Zeroizing::new(String::new());
    BufReader::new(std::io::stdin().take(MAX_ENV_LINE))
        .read_line(&mut line)
        .map_err(|_| "that request is not valid".to_string())?;
    harden_self();
    let mut c = exec_env_command(&line, argv)?;
    drop(line);
    // only returns when the command could not be started
    let e = c.exec();
    Err(format!("the command could not be started ({})", e.kind()))
}

/// What the launcher needs from the machine: the store (through the secrets service), the service manager, the clock.
/// Exit code, standard output, standard error.
pub type Collected = (Option<i32>, Vec<u8>, Vec<u8>);

/// A held per-service lock (a kernel `flock`, which frees itself when its holder dies). Released on drop.
pub struct ServiceLock(#[allow(dead_code)] Option<std::fs::File>);

pub trait Backend {
    fn policy(&self, project: &str) -> Result<Option<Policy>, String>;
    /// One value, for a name on the allow-list; refuses a production key.
    fn resolve(
        &self,
        project: &str,
        env: &str,
        name: &str,
        allowed: &[String],
    ) -> Result<Zeroizing<String>, String>;
    /// One value marked PUBLIC at import (`ozbox secrets import --public`), for a name the command declares in `public`. Refused
    /// when the stored entry carries no mark, or is production. A backend that holds no store has none.
    fn resolve_public(
        &self,
        _project: &str,
        _env: &str,
        _name: &str,
        _declared: &[String],
    ) -> Result<Zeroizing<String>, String> {
        Err("public values are not available here".to_string())
    }
    /// Put a service's secrets where systemd reads them, one file per credential name, in a folder of this start's own (see
    /// [`stage_credentials_in`]); returns that folder's name.
    fn stage_credentials(
        &self,
        _unit: &str,
        _pairs: &[(String, Zeroizing<String>)],
    ) -> Result<String, String> {
        Err("this machine cannot give a service a secret".to_string())
    }
    /// Remove what [`Backend::stage_credentials`] put there: one start's folder (`Some`, on every outcome of that start), or all of
    /// the unit's (`None`, on a stop).
    fn clear_credentials(&self, _unit: &str, _stage: Option<&str>) {}
    /// Remove staged secrets that an earlier launcher left behind (see [`sweep_credentials_in`]). Called before a service starts.
    fn sweep_credentials(&self) {}
    /// The numeric uid of a runner user: what the kernel rule that limits a service's proxy names. `None` when it does not exist.
    fn user_uid(&self, user: &str) -> Option<u32> {
        let (_, so, _) = self
            .exec(&["id".into(), "-u".into(), user.into()], b"")
            .ok()?;
        String::from_utf8_lossy(&so).trim().parse().ok()
    }
    /// `n` distinct free loopback ports, for a service's proxy and its tunnels, none of them in `not` (the service's own port).
    fn free_ports(&self, n: usize, not: &[u16]) -> Result<Vec<u16>, String> {
        let err = || "no free port is available for the service's route".to_string();
        let mut held: Vec<std::net::TcpListener> = Vec::new();
        let mut ports = Vec::new();
        // a port in `not` is skipped (and held while the next is tried, so it is not handed out again)
        for _ in 0..n + not.len() + 8 {
            let l = std::net::TcpListener::bind(("127.0.0.1", 0)).map_err(|_| err())?;
            let p = l.local_addr().map_err(|_| err())?.port();
            held.push(l);
            if !not.contains(&p) {
                ports.push(p);
                if ports.len() == n {
                    return Ok(ports);
                }
            }
        }
        Err(err())
    }
    /// Put a route's firewall rules where the privileged `ExecStartPre=` of its socket reads them; returns the path. One file
    /// per start, never reused.
    fn write_egress_rules(&self, _unit: &str, _text: &str) -> Result<String, String> {
        Err("this machine cannot limit a service's route".to_string())
    }
    /// Remove what [`Backend::write_egress_rules`] wrote for this unit.
    fn clear_egress_rules(&self, _unit: &str) {}
    /// Remove rules files that an earlier launcher left behind (see [`sweep_egress_rules_in`]). Called before a route starts.
    fn sweep_egress_rules(&self) {}
    /// The route units this machine knows (the part of a name before `.socket` / `.service`).
    fn route_units(&self) -> Vec<String> {
        match self.exec(
            &[
                "systemctl".into(),
                "list-units".into(),
                "--plain".into(),
                "--no-legend".into(),
                "--all".into(),
                "ozbox-egress-*".into(),
            ],
            b"",
        ) {
            Ok((_, so, _)) => parse_route_units(&String::from_utf8_lossy(&so)),
            Err(_) => Vec::new(),
        }
    }
    /// The route firewall tables that exist.
    fn egress_tables(&self) -> Vec<String> {
        match self.exec(
            &["/usr/sbin/nft".into(), "list".into(), "tables".into()],
            b"",
        ) {
            Ok((_, so, _)) => parse_egress_tables(&String::from_utf8_lossy(&so)),
            Err(_) => Vec::new(),
        }
    }
    /// Take the lock of one service's unit for the length of an action. `wait` false: `Ok(None)` when someone else holds it.
    fn lock_service(&self, _unit: &str, _wait: bool) -> Result<Option<ServiceLock>, String> {
        Ok(Some(ServiceLock(None)))
    }
    fn known(&self, project: &str) -> Result<Vec<Zeroizing<String>>, String>;
    /// Whether the runner USER (`runner_user_for`) exists on this machine.
    fn runner_ready(&self, user: &str) -> bool;
    /// What this machine's service manager supports (see [`Host`]).
    fn host(&self) -> Host {
        Host::default()
    }
    /// Whether what the declaration needs on this machine (the folder's access, the tools, the browsers) is in place for
    /// exactly this declaration. False sends the caller to the root helper's `ensure-runner`, which acts on the stored
    /// declaration and nothing from the request.
    fn setup_current(&self, _project: &str, _policy: &Policy) -> bool {
        true
    }
    /// Let go of whatever `setup_current` held (the box's launch lock). Called when a launch ends, however it ends.
    fn release_launch(&self) {}
    /// Whether every declared writable folder is a real folder right now (see [`check_writable`]). A fake with no disk says yes.
    fn writable_ready(&self, _policy: &Policy) -> Result<(), String> {
        Ok(())
    }
    /// Run `argv` with `stdin` on its standard input (the environment line), and collect what it printed.
    fn exec(&self, argv: &[String], stdin: &[u8]) -> Result<Collected, String>;
    fn audit(&self, line: &str);
    /// What turns a declared name into addresses for the egress proxy.
    fn resolver(&self) -> std::sync::Arc<dyn crate::egress::Resolver> {
        std::sync::Arc::new(crate::egress::SystemResolver)
    }
    /// Where verified copies of pinned files and the cache live (root-owned).
    fn pins(&self) -> crate::runner_pins::PinStore {
        crate::runner_pins::PinStore::new(PINS_ROOT)
    }
    /// `active`, `inactive`, `failed` ... for a unit; empty when it cannot be asked.
    fn unit_state(&self, unit: &str) -> String {
        match self.exec(&["systemctl".into(), "is-active".into(), unit.into()], b"") {
            Ok((_, so, _)) => String::from_utf8_lossy(&so).trim().to_string(),
            Err(_) => String::new(),
        }
    }
    /// Whether something already listens on this loopback port.
    fn port_open(&self, port: u16) -> bool {
        std::net::TcpStream::connect_timeout(
            &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
            std::time::Duration::from_millis(300),
        )
        .is_ok()
    }
    /// The status line's code of `GET path` on the loopback port, if it answered.
    fn http_status(&self, port: u16, path: &str) -> Option<u16> {
        use std::io::{Read, Write};
        let mut s = std::net::TcpStream::connect_timeout(
            &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
            std::time::Duration::from_millis(500),
        )
        .ok()?;
        let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(3)));
        let _ = s.set_write_timeout(Some(std::time::Duration::from_secs(3)));
        s.write_all(
            format!("GET {path} HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .ok()?;
        let mut head = [0u8; 16];
        let mut got = 0;
        while got < head.len() {
            match s.read(&mut head[got..]) {
                Ok(0) | Err(_) => break,
                Ok(n) => got += n,
            }
        }
        let line = std::str::from_utf8(&head[..got]).ok()?;
        line.split(' ').nth(1)?.parse().ok()
    }
    /// The tail of a unit's own output.
    fn unit_log(&self, unit: &str) -> String {
        match self.exec(
            &[
                "journalctl".into(),
                "-u".into(),
                unit.into(),
                "-n".into(),
                "40".into(),
                "--no-pager".into(),
                "-o".into(),
                "cat".into(),
            ],
            b"",
        ) {
            Ok((_, so, _)) => String::from_utf8_lossy(&so).to_string(),
            Err(_) => String::new(),
        }
    }
    fn sleep_ms(&self, ms: u64) {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }
}

fn fail(e: impl Into<String>) -> Value {
    json!({"ok": false, "error": e.into()})
}

/// What a request asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    Run,
    Start,
    Stop,
    Status,
}

fn read_action(r: &Value) -> Option<Action> {
    match r["action"].as_str().unwrap_or("run") {
        "run" => Some(Action::Run),
        "start" => Some(Action::Start),
        "stop" => Some(Action::Stop),
        "status" => Some(Action::Status),
        _ => None,
    }
}

/// The values a caller passed for the plain names the command declared, checked like a fixed value and never allowed to be (or
/// contain) a secret the project stores. Returns pairs in the order given.
fn checked_pass(
    r: &Value,
    cp: &crate::workload_policy::CommandPolicy,
    policy: &Policy,
    known: &[Zeroizing<String>],
) -> Result<Vec<(String, String)>, String> {
    let Some(obj) = r["pass"].as_object() else {
        return if r["pass"].is_null() {
            Ok(Vec::new())
        } else {
            Err("that request is not valid".into())
        };
    };
    let mut out = Vec::new();
    for (k, v) in obj {
        if !cp.pass.contains(k) {
            return Err(format!(
                "the command does not declare {k} as a value it takes"
            ));
        }
        let val = v
            .as_str()
            .ok_or_else(|| "that request is not valid".to_string())?;
        if let Some(why) = crate::workload_policy::reserved_name(k, &policy.tcp) {
            return Err(format!("{k} cannot be passed: {why}"));
        }
        crate::workload_policy::plain_value_ok(k, val)
            .map_err(|w| format!("the value of {k} {w}"))?;
        // what a command that holds a secret is told cannot steer where the secret goes (N-M3): no host name, address or URL
        if cp.bears_secrets()
            && !val
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b',' | b'='))
        {
            return Err(format!("the value of {k} may hold only letters, digits and _ - , = for a command that receives a secret: it cannot be a host name, an address or a URL"));
        }
        if policy.production_hit(val) {
            return Err(format!(
                "the value of {k} holds an identifier this project lists as production"
            ));
        }
        // a stored secret is not a plain value, even when it is passed by hand and looks harmless
        if known
            .iter()
            .any(|s| s.len() >= 4 && val.contains(s.as_str()))
        {
            return Err(format!("the value of {k} holds a stored secret: a command receives a secret only by its declared name"));
        }
        out.push((k.clone(), val.to_string()));
    }
    Ok(out)
}

/// How long a launch holds the shared setup lock waiting for its unit to exist.
const UNIT_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// Wait until systemd has made the transient unit `unit` (its `<unit>.service` file is in `dir`), or `gone` says the client that
/// asked for it has exited, or `limit` has passed. Returns whether the unit exists. A poll of a path every 2 ms, no process.
fn wait_until_unit_exists(
    dir: &Path,
    unit: &str,
    mut gone: impl FnMut() -> bool,
    limit: std::time::Duration,
) -> bool {
    let file = dir.join(format!("{unit}.service"));
    let start = std::time::Instant::now();
    loop {
        if file.exists() {
            return true;
        }
        if gone() || start.elapsed() >= limit {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
}

/// Keep `lock` in `slot` for the launch when the machine is set up for it. A poisoned mutex cannot hold it, and a launch that does
/// not hold the lock must not run: it answers "not set up" (G5 seventh round, NV6-I3).
fn hold_launch_lock(
    slot: &std::sync::Mutex<Option<std::fs::File>>,
    ok: bool,
    lock: Option<std::fs::File>,
) -> bool {
    match slot.lock() {
        Ok(mut g) => {
            *g = if ok { lock } else { None };
            ok
        }
        Err(_) => false,
    }
}

/// A launch whose unit file never appeared while its client is still running has an unknown start pending: it must not let go.
fn must_abort(existed: bool, client_exited: bool) -> bool {
    !existed && !client_exited
}

/// Answer one request.
pub fn launch(be: &dyn Backend, id: &str, line: &str) -> Value {
    let v = launch_inner(be, id, line);
    be.release_launch();
    v
}

fn launch_inner(be: &dyn Backend, id: &str, line: &str) -> Value {
    let Ok(r) = serde_json::from_str::<Value>(line) else {
        return fail("that request is not valid");
    };
    let s = |k: &str| r[k].as_str().unwrap_or("").to_string();
    let (project, env, command) = (s("project"), s("env"), s("command"));
    let Some(action) = read_action(&r) else {
        return fail("that request is not valid");
    };
    let argv: Vec<String> = r["argv"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    if !(seg_ok(&project) && seg_ok(&env) && seg_ok(&command)) {
        return fail("that request is not valid");
    }
    if action == Action::Run && argv.is_empty()
        || argv.len() > MAX_ARGS
        || argv.iter().any(|a| a.len() > 4096 || a.contains('\0'))
    {
        return fail("that request is not valid");
    }
    if argv.iter().any(|a| a.contains("{{secret:")) {
        return fail("a secret is never put in an argument: declare its name for the command, and read it from the environment");
    }
    let policy = match be.policy(&project) {
        Ok(Some(p)) => p,
        Ok(None) => {
            return fail("this project has not declared which secrets its commands may receive")
        }
        Err(e) => return fail(e),
    };
    if policy.dir.is_empty() {
        return fail("this project has not declared its folder");
    }
    // a service is started and stopped, never run; a plain command is never started
    let cp = if action == Action::Run {
        match policy.command(&command, &argv) {
            Ok(c) if c.service => {
                return fail(format!(
                    "{command} is a service: start it with --start, stop it with --stop"
                ))
            }
            Ok(c) => c,
            Err(e) => return fail(e.0),
        }
    } else {
        match policy.commands.get(&command) {
            Some(c) if c.service => c,
            Some(_) => return fail(format!("{command} is not a service")),
            None => {
                return fail(format!(
                    "this project does not declare a command named {command}"
                ))
            }
        }
    };
    let user = runner_user_for(&project, &command, cp);
    // A command that receives a secret meets every rule a declaration is held to now: a declaration stored by an earlier version still
    // LOADS, but its secret commands do not run until it is brought up to them (G5 second review, N-M5).
    // A service that receives a secret meets the same rules as a command that does: until now every one of them sat behind "run",
    // so a service would have skipped them (ADR 0029 Amendment 12).
    if matches!(action, Action::Run | Action::Start) && cp.bears_secrets() {
        if let Err(e) = policy
            .validate_at_launch()
            .and_then(|()| policy.secret_rules(Some(&command)))
        {
            return fail(format!(
                "{command} cannot be given a secret until its declaration is updated: {}",
                e.0
            ));
        }
        if !cp.envs.contains(&env) {
            return fail(format!(
                "{command} may take its secrets from {} only, not {env}",
                cp.envs.join(", ")
            ));
        }
    }
    // a public value comes from the environment the declaration lists too, so the caller cannot steer it at another one
    if matches!(action, Action::Run | Action::Start)
        && !cp.public.is_empty()
        && !cp.envs.contains(&env)
    {
        return fail(format!(
            "{command} may take its public values from {} only, not {env}",
            cp.envs.join(", ")
        ));
    }
    if action == Action::Run && cp.bears_secrets() {
        // the owner approved exactly these words: no flag, script or option of the caller's own (`--import`, `-r`, `--env-file`, `-e`)
        if argv != cp.argv {
            return fail(format!(
                "{command} receives a secret, so it runs exactly the words approved: {}",
                cp.argv.join(" ")
            ));
        }
    }
    if !be.runner_ready(&user) || !be.setup_current(&project, &policy) {
        return fail("the runner for this project is not set up yet: ask the box's admin helper for ensure-runner");
    }
    let known = match be.known(&project) {
        Ok(k) => k,
        Err(e) => return fail(e),
    };
    if action != Action::Run {
        return service(be, action, &project, &env, &command, &policy, cp, &known);
    }
    let pass = match checked_pass(&r, cp, &policy, &known) {
        Ok(p) => p,
        Err(e) => return fail(e),
    };
    // Pinned files are read, checked and copied BEFORE a secret is looked up: a change stops the run here, naming the file,
    // and nothing is resolved for, or delivered to, a script that is not the approved one.
    let checked = match be.pins().check(
        &project,
        Path::new(&policy.dir),
        &cp.pin,
        &cp.pin_tree,
        cp.bears_secrets(),
    ) {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    // A command that receives a secret and runs a script: everything the script loads must be pinned too, read from the VERIFIED
    // bytes (see `runner_imports`). Refused before a secret is looked up.
    if cp.bears_secrets() {
        if let Err(e) = be
            .pins()
            .check_code(Path::new(&policy.dir), &argv, &checked)
        {
            return fail(e);
        }
    }
    // a writable folder is bound into the private view from the live folder: one that is missing or is a link is refused here, by
    // name, never skipped (G5 third round, NV-L1)
    if cp.bears_secrets() {
        if let Err(e) = be.writable_ready(&policy) {
            return fail(e);
        }
    }
    let mut pairs: Vec<(String, Zeroizing<String>)> = Vec::new();
    let mut names: Vec<String> = Vec::new();
    for e in &cp.env {
        match be.resolve(&project, &env, &e.name, &cp.allow) {
            Ok(v) if policy.production_hit(&v) => {
                return fail(format!("{} holds an identifier this project lists as production, so it is not given to a command", e.name));
            }
            Ok(v) => {
                pairs.push((e.target().to_string(), v));
                names.push(match &e.rename {
                    Some(t) => format!("{}->{t}", e.name),
                    None => e.name.clone(),
                });
            }
            Err(err) => return fail(err),
        }
    }
    // public values (marked at import, declared by name): plain environment, checked for production like any other value
    let publics = match resolve_publics(be, &project, &env, cp, &policy) {
        Ok(p) => p,
        Err(e) => return fail(e),
    };
    // The egress proxy lives as long as this command. With nothing declared there is none, and the command's network is
    // its own loopback only.
    let rules = match crate::egress::parse_rules(&policy.egress) {
        Ok(r) => r,
        Err(e) => return fail(e),
    };
    let proxy = if rules.is_empty() {
        None
    } else {
        match crate::egress::start(rules, be.resolver()) {
            Ok(p) => Some(p),
            Err(e) => return fail(e),
        }
    };
    // one loopback listener per declared tcp destination, for the length of the command
    if let Err(e) = crate::egress::validate_tcp(&policy.tcp) {
        return fail(e);
    }
    let mut tunnels = Vec::new();
    for d in &policy.tcp {
        match crate::egress::start_tunnel(
            d.host.clone(),
            d.port,
            be.resolver(),
            crate::netguard::ip_is_public,
        ) {
            Ok(t) => tunnels.push((d.clone(), t)),
            Err(e) => return fail(e),
        }
    }
    // everything the command is given, as one line for the unit's standard input: nothing is written to disk
    let mut child_env: Vec<(String, Zeroizing<String>)> = pairs.clone();
    // plain variables: the declared fixed ones, then what the caller passed. None of them is a secret.
    for (k, v) in &cp.vars {
        child_env.push((k.clone(), Zeroizing::new(v.clone())));
    }
    for (k, v) in &publics {
        child_env.push((k.clone(), v.clone()));
    }
    for (k, v) in &pass {
        child_env.push((k.clone(), Zeroizing::new(v.clone())));
    }
    if let Some(p) = &proxy {
        // the password is in the command's own environment and nowhere the agent can read
        let url = Zeroizing::new(p.url());
        for k in [
            "HTTPS_PROXY",
            "https_proxy",
            "HTTP_PROXY",
            "http_proxy",
            "ALL_PROXY",
        ] {
            child_env.push((k.to_string(), url.clone()));
        }
        for k in ["NO_PROXY", "no_proxy"] {
            child_env.push((
                k.to_string(),
                Zeroizing::new("localhost,127.0.0.1,::1".into()),
            ));
        }
    }
    for (d, t) in &tunnels {
        for (k, v) in crate::egress::tunnel_env(d, t.port) {
            child_env.push((k, Zeroizing::new(v)));
        }
    }
    let stdin = env_line(&child_env);
    let run = systemd_run_argv_with(
        &project,
        &user,
        id,
        &policy,
        cp,
        &argv,
        &checked.mounts,
        be.host(),
    );
    let out = be.exec(&run, stdin.as_bytes());
    let Ok((code, so, se)) = out else {
        return fail("the command could not be started");
    };
    let (stdout, a) = redact(&String::from_utf8_lossy(&so), &known);
    let (stderr, b) = redact(&String::from_utf8_lossy(&se), &known);
    drop(proxy);
    drop(tunnels);
    be.audit(&format!(
        "env-run project={project} env={env} command={command} names={} public={} vars={} pins={} egress={} tcp={} exit={} redacted={}",
        names.join(","),
        publics.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>().join(","),
        cp.vars
            .keys()
            .cloned()
            .chain(pass.iter().map(|(k, _)| k.clone()))
            .collect::<Vec<_>>()
            .join(","),
        cp.pin.len(),
        policy.egress.join(","),
        policy
            .tcp
            .iter()
            .map(|d| format!("{}:{}", d.host, d.port))
            .collect::<Vec<_>>()
            .join(","),
        code.map_or("none".to_string(), |c| c.to_string()),
        a + b
    ));
    json!({"ok": true, "exit": code, "stdout": stdout, "stderr": stderr, "redactions": a + b, "resolved": names})
}

/// The values a command declares in `public`, each resolved from the store only if it carries the public mark, and held to the
/// production list like any other value.
fn resolve_publics(
    be: &dyn Backend,
    project: &str,
    env: &str,
    cp: &crate::workload_policy::CommandPolicy,
    policy: &Policy,
) -> Result<Vec<(String, Zeroizing<String>)>, String> {
    let mut out = Vec::new();
    for name in &cp.public {
        let v = be.resolve_public(project, env, name, &cp.public)?;
        crate::workload_policy::public_value_ok(&v)
            .map_err(|w| format!("the value of {name} {w}"))?;
        // checked again here: a mark is only honoured for a value that is still plainly public
        if let Some(why) =
            crate::workload_policy::public_mark_refusal(name, &v, policy.production_hit(&v))
        {
            return Err(format!(
                "{name} is marked public but is not given as a public value: {why}"
            ));
        }
        if policy.production_hit(&v) {
            return Err(format!(
                "{name} holds an identifier this project lists as production, so it is not given to a command"
            ));
        }
        out.push((name.clone(), v));
    }
    Ok(out)
}

/// `--start`, `--stop` and `--status` of a declared service. The service is a unit of its own (see
/// [`systemd_run_service_argv`]); the answer is its state, and what it printed with every stored value of the project removed.
#[allow(clippy::too_many_arguments)]
fn service(
    be: &dyn Backend,
    action: Action,
    project: &str,
    env: &str,
    command: &str,
    policy: &Policy,
    cp: &crate::workload_policy::CommandPolicy,
    known: &[Zeroizing<String>],
) -> Value {
    let unit = service_unit(project, command);
    let port = cp.port.unwrap_or(0);
    let path = cp.health.clone().unwrap_or_else(|| "/".to_string());
    let tail = |be: &dyn Backend| redact(&be.unit_log(&unit), known).0;
    // A start or a stop of one service at a time, for the whole action (E3): two starts raced on one unit name and a "leftover"
    // stop of one killed the other's live proxy. A status does not wait for it. (`exec` lets go of the launch lock after every
    // call, so this is a lock of its own.)
    let _service_lock = if action == Action::Status {
        None
    } else {
        match be.lock_service(&unit, true) {
            Ok(Some(l)) => Some(l),
            _ => {
                return fail(format!(
                    "another start or stop of {command} could not be waited for: try again"
                ))
            }
        }
    };
    match action {
        Action::Start => {
            // running, starting or stopping under either name: never started a second time on top of it
            if !unit_idle(&be.unit_state(&unit))
                || !unit_idle(&be.unit_state(&legacy_service_unit(project, command)))
            {
                return fail(format!("{command} is already running on port {port}"));
            }
            if be.port_open(port) {
                return fail(format!("port {port} is already in use on this machine"));
            }
            let checked = match be.pins().check(
                project,
                Path::new(&policy.dir),
                &cp.pin,
                &cp.pin_tree,
                cp.bears_secrets(),
            ) {
                Ok(c) => c,
                Err(e) => return fail(e),
            };
            // A service that receives a secret: everything its program loads is pinned too, and its folders are real, BEFORE a
            // secret is looked up (the same order as a run)
            if cp.bears_secrets() {
                if let Err(e) = be
                    .pins()
                    .check_code(Path::new(&policy.dir), &cp.argv, &checked)
                {
                    return fail(e);
                }
                if let Err(e) = be.writable_ready(policy) {
                    return fail(e);
                }
            }
            let mut secrets: Vec<(String, Zeroizing<String>)> = Vec::new();
            let mut names: Vec<String> = Vec::new();
            for e in &cp.env {
                match be.resolve(project, env, &e.name, &cp.allow) {
                    Ok(v) if policy.production_hit(&v) => {
                        return fail(format!("{} holds an identifier this project lists as production, so it is not given to a command", e.name));
                    }
                    Ok(v) => {
                        secrets.push((e.target().to_string(), v));
                        names.push(e.target().to_string());
                    }
                    Err(err) => return fail(err),
                }
            }
            let publics = match resolve_publics(be, project, env, cp, policy) {
                Ok(p) => p,
                Err(e) => return fail(e),
            };
            let public_plain: Vec<(String, String)> = publics
                .iter()
                .map(|(k, v)| (k.clone(), v.to_string()))
                .collect();
            let cred_names: Vec<String> = secrets.iter().map(|(k, _)| k.clone()).collect();
            // The route out (ADR 0029 Amendment 12). The ports are held and guarded before any service process exists and let go
            // only after the last one is dead: the socket (PID 1 holds the ports, the firewall table is loaded first), then the
            // proxy (started explicitly, so this waits for its READY), then the service. The service is not started without the
            // route its declaration names, and a failure at any step takes down what was made, the service first.
            let declared = route_declared(policy, cp);
            if declared {
                // every route this machine holds that no service is using (a launcher that was killed part-way, a setup that
                // changed the declaration), then this route's own: the service is not running (checked above, under this
                // service's lock), so a proxy or a socket of its name is a leftover and stopping it frees its ports
                sweep_routes(be, &crate::runner_egress::egress_unit(project, command));
                stop_route_units(be, &crate::runner_egress::egress_unit(project, command));
            }
            let route = match plan_route(be, project, command, policy, cp) {
                Ok(r) => r,
                Err(e) => return fail(e),
            };
            let stop_route = |be: &dyn Backend| {
                if let Some(r) = &route {
                    stop_route_units(be, &r.unit);
                }
            };
            let stop_service = |be: &dyn Backend| {
                let _ = be.exec(&["systemctl".into(), "stop".into(), unit.clone()], b"");
            };
            if let Some(r) = &route {
                let Some(uid) = be.user_uid(&runner_user_for(project, command, cp)) else {
                    return fail(
                        "the service's user could not be looked up, so its route is not started",
                    );
                };
                let file = match be
                    .write_egress_rules(&r.unit, &crate::runner_egress::render_nft(r, uid))
                {
                    Ok(f) => f,
                    Err(e) => return fail(e),
                };
                // the socket: PID 1 binds every port of the route (a port someone took since it was chosen fails the start)
                let up = be.exec(
                    &crate::runner_egress::systemd_run_route_argv(
                        &unit,
                        r,
                        uid,
                        &policy.egress,
                        &file,
                    ),
                    b"",
                );
                be.clear_egress_rules(&r.unit);
                if !matches!(up, Ok((Some(0), _, _))) {
                    stop_route(be);
                    return fail(
                        "the service's route could not be started, so the service was not started",
                    );
                }
                // the proxy: `Type=notify`, so this returns once it listens, never before
                let proxy_up = be.exec(&["systemctl".into(), "start".into(), r.proxy()], b"");
                if !matches!(proxy_up, Ok((Some(0), _, _))) {
                    stop_route(be);
                    return fail(
                        "the service's route could not be started, so the service was not started",
                    );
                }
                // the route's own start let go of setup's lock: take it again, so a declaration applied in between is seen and the
                // service never starts under the old one
                if !be.setup_current(project, policy) {
                    stop_route(be);
                    return fail("the runner for this project is not set up yet: ask the box's admin helper for ensure-runner");
                }
            }
            let mut stage = String::new();
            if !secrets.is_empty() {
                be.sweep_credentials();
                match be.stage_credentials(&unit, &secrets) {
                    Ok(st) => stage = st,
                    // the staging step removes what it wrote; nothing of this start is left to clear
                    Err(e) => {
                        stop_route(be);
                        return fail(e);
                    }
                }
            }
            let run = systemd_run_service_argv(
                project,
                command,
                policy,
                cp,
                &checked.mounts,
                be.host(),
                &ServiceInputs {
                    credentials: &cred_names,
                    stage: &stage,
                    public: &public_plain,
                    route: route.as_ref(),
                },
            );
            let started = be.exec(&run, b"");
            // gone on every outcome: systemd has loaded the credentials by the time `systemd-run` returns, and a failed start
            // never will
            if !secrets.is_empty() {
                be.clear_credentials(&unit, Some(&stage));
            }
            drop(secrets);
            match started {
                Ok((Some(0), _, _)) => {}
                _ => {
                    // the service may exist part-made: it goes first, then its route
                    stop_service(be);
                    stop_route(be);
                    return fail("the service could not be started");
                }
            }
            let mut waited = 0;
            let ready = loop {
                if be.http_status(port, &path).is_some_and(|c| c < 500) {
                    break true;
                }
                if !matches!(be.unit_state(&unit).as_str(), "active" | "activating") {
                    break false;
                }
                if waited >= HEALTH_WAIT_MS {
                    break false;
                }
                be.sleep_ms(HEALTH_POLL_MS);
                waited += HEALTH_POLL_MS;
            };
            if !ready {
                stop_service(be);
                stop_route(be);
                be.audit(&format!(
                    "env-service project={project} command={command} start=unhealthy port={port}"
                ));
                let log = tail(be);
                return fail(format!(
                    "{command} did not answer its health check on port {port} and was stopped{}",
                    if log.trim().is_empty() {
                        String::new()
                    } else {
                        format!("\n{}", log.trim_end())
                    }
                ));
            }
            // what the service can actually reach: the declared hosts and raw destinations, only when a route was started for them
            let (egress, tcp) = match &route {
                Some(_) => (
                    policy.egress.join(","),
                    policy
                        .tcp
                        .iter()
                        .map(|d| format!("{}:{}", d.host, d.port))
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                None => (String::new(), String::new()),
            };
            be.audit(&format!(
                "env-service project={project} env={env} command={command} start=ok port={port} pins={} secrets={} public={} egress={egress} tcp={tcp}",
                cp.pin.len(),
                names.join(","),
                publics.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>().join(",")
            ));
            json!({"ok": true, "state": "running", "port": port, "unit": unit})
        }
        Action::Stop => {
            let _ = be.exec(&["systemctl".into(), "stop".into(), unit.clone()], b"");
            // a service an earlier release started under its old name is stopped too (exact name: a hyphen name cannot be globbed
            // without reaching another project's)
            let _ = be.exec(
                &[
                    "systemctl".into(),
                    "stop".into(),
                    legacy_service_unit(project, command),
                ],
                b"",
            );
            // its route goes with it, after it: the service above has been stopped (blocking), so none of its processes is left, and
            // only now are the proxy and the socket (the ports) let go. The service's own end queues the same stops; this one waits
            // for them, so a `--start` right after never meets a route that is still going.
            if cp.bears_secrets() {
                stop_route_units(be, &crate::runner_egress::egress_unit(project, command));
            }
            be.clear_credentials(&unit, None);
            be.audit(&format!(
                "env-service project={project} command={command} stop"
            ));
            json!({"ok": true, "state": "stopped", "port": port, "unit": unit})
        }
        _ => {
            let unit = live_service_unit(be, project, command);
            let state = be.unit_state(&unit);
            let state = if state.is_empty() {
                "inactive".to_string()
            } else {
                state
            };
            let healthy = state == "active" && be.http_status(port, &path).is_some_and(|c| c < 500);
            json!({"ok": true, "state": state, "healthy": healthy, "port": port, "unit": unit, "log": tail(be)})
        }
    }
}

/// Where the per-service locks live (root's, mode 0700).
pub const SERVICE_LOCK_ROOT: &str = "/run/ozbox-service-locks";
/// A rules file older than this is one nobody is going to load: the launcher that wrote it died.
pub const EGRESS_RULES_STALE_SECS: u64 = 60;

fn route_unit_name_ok(unit: &str) -> bool {
    let rest = unit
        .strip_prefix(crate::runner_egress::UNIT_PREFIX)
        .unwrap_or("");
    !rest.is_empty()
        && rest.len() <= 80
        && rest
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

fn private_dir(root: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(root)?;
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))
}

/// Write one start's ruleset for a route: a file of its own (`<unit>.<16 hex>.nft`, created new, so a file or a link that is
/// already there is never followed or reused) under `root` (mode 0700), mode 0600. The launcher is root; so is the `+` step of the
/// socket unit that loads it, and nobody else needs to read it. Only a name `egress_unit` makes is accepted. Two starts never share
/// a file (E2): one start's socket can only load its own rules.
pub fn write_egress_rules_in(root: &Path, unit: &str, text: &str) -> Result<String, String> {
    use std::os::unix::fs::OpenOptionsExt;
    let bad = || "the service's route could not be put in place".to_string();
    if !route_unit_name_ok(unit) {
        return Err(bad());
    }
    private_dir(root).map_err(|_| bad())?;
    let mut raw = [0u8; 8];
    getrandom::getrandom(&mut raw).map_err(|_| bad())?;
    let nonce: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    let path = root.join(format!("{unit}.{nonce}.nft"));
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|_| bad())?;
    if f.write_all(text.as_bytes()).is_err() {
        let _ = std::fs::remove_file(&path);
        return Err(bad());
    }
    Ok(path.to_string_lossy().to_string())
}

/// Remove every rules file of this unit (the one a start wrote, and any an earlier start left).
pub fn clear_egress_rules_in(root: &Path, unit: &str) {
    if !route_unit_name_ok(unit) {
        return;
    }
    let Ok(rd) = std::fs::read_dir(root) else {
        return;
    };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if name.starts_with(&format!("{unit}.")) && name.ends_with(".nft") {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

/// Remove rules files older than `older_than_secs` (a launcher killed between writing one and clearing it). Returns how many went.
/// Never follows a link; anything that is not a plain `.nft` file is left alone.
pub fn sweep_egress_rules_in(root: &Path, older_than_secs: u64) -> usize {
    let Ok(rd) = std::fs::read_dir(root) else {
        return 0;
    };
    let now = std::time::SystemTime::now();
    let mut n = 0;
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if !name.ends_with(".nft") {
            continue;
        }
        let old = std::fs::symlink_metadata(e.path())
            .ok()
            .filter(|m| m.is_file())
            .and_then(|m| m.modified().ok())
            .and_then(|t| now.duration_since(t).ok())
            .is_some_and(|d| d.as_secs() >= older_than_secs);
        if old && std::fs::remove_file(e.path()).is_ok() {
            n += 1;
        }
    }
    n
}

/// Take the lock of one service's unit: `wait` blocks until it is free, otherwise `Ok(None)` says someone holds it. A kernel
/// `flock`, so a holder that dies frees it. The lock is a file under `root`, named by the unit.
pub fn lock_service_in(root: &Path, unit: &str, wait: bool) -> Result<Option<ServiceLock>, String> {
    use rustix::fs::{flock, FlockOperation};
    use std::os::unix::fs::OpenOptionsExt;
    let bad = || "the service's lock could not be taken".to_string();
    let rest = unit.strip_prefix("ozbox-svc-").unwrap_or("");
    if rest.is_empty()
        || rest.len() > 80
        || !rest
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    {
        return Err(bad());
    }
    private_dir(root).map_err(|_| bad())?;
    let f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(root.join(format!("{unit}.lock")))
        .map_err(|_| bad())?;
    let op = if wait {
        FlockOperation::LockExclusive
    } else {
        FlockOperation::NonBlockingLockExclusive
    };
    loop {
        match flock(&f, op) {
            Ok(()) => return Ok(Some(ServiceLock(Some(f)))),
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) if !wait && e == rustix::io::Errno::WOULDBLOCK => return Ok(None),
            Err(_) => return Err(bad()),
        }
    }
}

/// Whether a service has a route at all: it receives a secret and the project declares somewhere to reach.
fn route_declared(policy: &Policy, cp: &crate::workload_policy::CommandPolicy) -> bool {
    cp.bears_secrets() && (!policy.egress.is_empty() || !policy.tcp.is_empty())
}

/// What a project that declares `tcp` is told when a service that receives secrets is started.
const TCP_HELD: &str = "this project declares tcp destinations, and a service that receives secrets is not given them yet: its route's ports are not proven safe from another user on a real box. Remove the tcp declaration for this project, or run the command without secrets. (A one-shot `ozbox env run` still gets its tunnels.)";

/// Decide a service's route: none unless it receives a secret and the project declares somewhere to reach. Everything that can
/// refuse (the rules, the user, the ports) is looked at here, before anything is started.
fn plan_route(
    be: &dyn Backend,
    project: &str,
    command: &str,
    policy: &Policy,
    cp: &crate::workload_policy::CommandPolicy,
) -> Result<Option<crate::runner_egress::Route>, String> {
    if !route_declared(policy, cp) {
        return Ok(None);
    }
    if !policy.tcp.is_empty() && !crate::runner_egress::SERVICE_TCP_TUNNELS {
        return Err(TCP_HELD.to_string());
    }
    let rules = crate::egress::parse_rules(&policy.egress).map_err(|e| e.to_string())?;
    crate::egress::validate_tcp(&policy.tcp).map_err(|e| e.to_string())?;
    if rules.is_empty() && policy.tcp.is_empty() {
        return Ok(None);
    }
    // never the service's own port: the socket would hold it and the service could not bind it (E9)
    let ports = be.free_ports(1 + policy.tcp.len(), &[cp.port.unwrap_or(0)])?;
    if ports.len() != 1 + policy.tcp.len() {
        return Err("no free port is available for the service's route".into());
    }
    Ok(Some(crate::runner_egress::Route {
        unit: crate::runner_egress::egress_unit(project, command),
        port: ports[0],
        tunnels: policy
            .tcp
            .iter()
            .cloned()
            .zip(ports[1..].iter().copied())
            .collect(),
    }))
}

/// Stop a route's proxy and its socket (one call: systemd's ordering stops the proxy first and the socket, which holds the ports,
/// last), then remove any rules file it left. Blocking. The service is NOT stopped here: whoever calls it stops the service first,
/// or knows there is none, because the route's ports must be let go only after the service's last process is dead.
fn stop_route_units(be: &dyn Backend, route_unit: &str) {
    let _ = be.exec(
        &[
            "systemctl".into(),
            "stop".into(),
            format!("{route_unit}.service"),
            format!("{route_unit}.socket"),
        ],
        b"",
    );
    be.clear_egress_rules(route_unit);
}

/// The route units of this machine that belong to a service which is not running, and the firewall tables of such routes, are
/// stopped and removed (E6): a launcher killed between the socket and the service leaves a socket that holds ports for nothing,
/// and a table for a port that is later reused would refuse its new owner. A service that is being started or stopped right now
/// holds its lock, and is skipped. `ours` is the route the caller handles itself.
fn sweep_routes(be: &dyn Backend, ours: &str) {
    for base in be.route_units() {
        if base == ours {
            continue;
        }
        let Some(svc) = crate::runner_egress::service_of_route_unit(&base) else {
            continue;
        };
        let Ok(Some(_busy)) = be.lock_service(&svc, false) else {
            continue;
        };
        if unit_idle(&be.unit_state(&svc)) {
            stop_route_units(be, &base);
        }
    }
    for table in be.egress_tables() {
        let Some(base) = crate::runner_egress::unit_of_table(&table) else {
            continue;
        };
        if base == ours {
            continue;
        }
        let Some(svc) = crate::runner_egress::service_of_route_unit(&base) else {
            continue;
        };
        let Ok(Some(_busy)) = be.lock_service(&svc, false) else {
            continue;
        };
        if unit_idle(&be.unit_state(&svc)) && unit_idle(&be.unit_state(&format!("{base}.socket"))) {
            let _ = be.exec(
                &[
                    "/usr/sbin/nft".into(),
                    "delete".into(),
                    "table".into(),
                    "inet".into(),
                    table,
                ],
                b"",
            );
        }
    }
    be.sweep_egress_rules();
}

/// The unit names (without the `.socket` / `.service` suffix, each once) that `systemctl list-units` printed for the route units.
pub fn parse_route_units(listing: &str) -> Vec<String> {
    let mut out: Vec<String> = listing
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .map(|n| n.trim_start_matches('●'))
        .filter_map(|n| {
            n.strip_suffix(".socket")
                .or_else(|| n.strip_suffix(".service"))
        })
        .filter(|n| {
            crate::runner_egress::service_of_route_unit(n).is_some()
                && n.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        })
        .map(str::to_string)
        .collect();
    out.sort();
    out.dedup();
    out
}

/// The firewall tables `nft list tables` printed that are a route's (`table inet ozbox_egress_...`), by name.
pub fn parse_egress_tables(listing: &str) -> Vec<String> {
    listing
        .lines()
        .filter_map(|l| {
            let mut w = l.split_whitespace();
            (w.next() == Some("table") && w.next() == Some("inet")).then(|| w.next())?
        })
        .filter(|n| crate::runner_egress::unit_of_table(n).is_some())
        .map(str::to_string)
        .collect()
}

/// The launcher's entry: one request on standard input, one answer on standard output (the socket unit connects both).
pub fn serve_stdio(be: &dyn Backend) {
    let mut line = String::new();
    let mut rd = BufReader::new(std::io::stdin().take(MAX_REQUEST));
    if rd.read_line(&mut line).is_err() || line.is_empty() {
        return;
    }
    let mut raw = [0u8; 8];
    let _ = getrandom::getrandom(&mut raw);
    let id: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    let out = launch(be, &id, line.trim_end());
    let mut so = std::io::stdout();
    let _ = writeln!(so, "{out}");
    let _ = so.flush();
}

/// The real machine: the secrets service's admin and runner sockets, and `systemd-run`.
pub struct SystemBackend {
    pub admin: crate::secrets_service::SocketSecrets,
    pub resolver: crate::secrets_service::SocketSecrets,
    pub audit_log: PathBuf,
    /// Shared lock on the box's launch lock, held from "set up for this declaration" until the unit has been handed to `systemd-run`
    /// (G5 fourth round, NV3-L5): setup takes it exclusively, so it cannot finish its last kill between the two.
    pub launch_lock: std::sync::Mutex<Option<std::fs::File>>,
}

impl Backend for SystemBackend {
    fn policy(&self, project: &str) -> Result<Option<Policy>, String> {
        let name = crate::workload_policy::secret_name(project).map_err(|e| e.0)?;
        let v = self
            .admin
            .call(json!({"op": "get", "name": name}))
            .map_err(|e| e.0)?;
        match v["value"].as_str() {
            Some(h) => Policy::from_stored(h).map(Some).map_err(|e| e.0),
            None => Ok(None),
        }
    }
    fn resolve(
        &self,
        project: &str,
        env: &str,
        name: &str,
        allowed: &[String],
    ) -> Result<Zeroizing<String>, String> {
        let v = self
            .resolver
            .call(
                json!({"op": "resolve", "project": project, "env": env, "name": name, "exact": true,
                "text": format!("{{{{secret:{name}}}}}"), "allowed": allowed}),
            )
            .map_err(|e| e.0)?;
        Ok(Zeroizing::new(
            v["value"].as_str().unwrap_or("").to_string(),
        ))
    }
    fn resolve_public(
        &self,
        project: &str,
        env: &str,
        name: &str,
        declared: &[String],
    ) -> Result<Zeroizing<String>, String> {
        let v = self
            .resolver
            .call(
                json!({"op": "resolve", "project": project, "env": env, "name": name, "exact": true, "public": true,
                "text": "", "allowed": declared}),
            )
            .map_err(|e| e.0)?;
        Ok(Zeroizing::new(
            v["value"].as_str().unwrap_or("").to_string(),
        ))
    }
    fn stage_credentials(
        &self,
        unit: &str,
        pairs: &[(String, Zeroizing<String>)],
    ) -> Result<String, String> {
        stage_credentials_in(Path::new(CRED_ROOT), unit, pairs)
    }
    fn clear_credentials(&self, unit: &str, stage: Option<&str>) {
        clear_credentials_in(Path::new(CRED_ROOT), unit, stage);
    }
    fn sweep_credentials(&self) {
        sweep_credentials_in(Path::new(CRED_ROOT), None, CRED_STALE_SECS);
    }
    fn write_egress_rules(&self, unit: &str, text: &str) -> Result<String, String> {
        write_egress_rules_in(Path::new(crate::runner_egress::RULES_ROOT), unit, text)
    }
    fn clear_egress_rules(&self, unit: &str) {
        clear_egress_rules_in(Path::new(crate::runner_egress::RULES_ROOT), unit);
    }
    fn sweep_egress_rules(&self) {
        sweep_egress_rules_in(
            Path::new(crate::runner_egress::RULES_ROOT),
            EGRESS_RULES_STALE_SECS,
        );
    }
    fn lock_service(&self, unit: &str, wait: bool) -> Result<Option<ServiceLock>, String> {
        lock_service_in(Path::new(SERVICE_LOCK_ROOT), unit, wait)
    }
    fn known(&self, project: &str) -> Result<Vec<Zeroizing<String>>, String> {
        let names = self
            .admin
            .call(json!({"op": "names", "prefix": format!("workload.{project}.")}))
            .map_err(|e| e.0)?;
        let mut out = Vec::new();
        for n in names["names"].as_array().cloned().unwrap_or_default() {
            let v = self
                .admin
                .call(json!({"op": "get", "name": n}))
                .map_err(|e| e.0)?;
            if let Some(s) = v["value"].as_str() {
                out.push(Zeroizing::new(s.to_string()));
            }
        }
        Ok(out)
    }
    fn host(&self) -> Host {
        static HOST: std::sync::OnceLock<Host> = std::sync::OnceLock::new();
        *HOST.get_or_init(|| {
            let out = Command::new("systemctl")
                .arg("--version")
                .stdin(Stdio::null())
                .stderr(Stdio::null())
                .output();
            let version = out
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .and_then(|t| {
                    t.split_whitespace()
                        .nth(1)
                        .and_then(|v| v.parse::<u32>().ok())
                })
                .unwrap_or(0);
            Host {
                private_pids: version >= MIN_SYSTEMD_PRIVATE_PIDS,
            }
        })
    }
    fn runner_ready(&self, user: &str) -> bool {
        Command::new("id")
            .args(["-u", user])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }
    fn writable_ready(&self, policy: &Policy) -> Result<(), String> {
        check_writable(Path::new(&policy.dir), &policy.writable)
    }
    fn setup_current(&self, project: &str, policy: &Policy) -> bool {
        let home = std::env::var("OZBOX_BOX_HOME").unwrap_or_else(|_| "/work/home/ozbox".into());
        let paths = crate::runner_setup::Paths::system(PathBuf::from(home));
        // the lock first, then the question: a setup in progress is waited for, and the answer is then about what it left
        let Ok(lock) = crate::runner_setup::lock_file(&paths, false) else {
            // a lock that cannot be taken is a refusal, never a launch without it
            return false;
        };
        let ok = crate::runner_setup::current(&paths, project, policy);
        hold_launch_lock(&self.launch_lock, ok, lock)
    }
    fn release_launch(&self) {
        if let Ok(mut g) = self.launch_lock.lock() {
            *g = None;
        }
    }
    fn exec(&self, argv: &[String], stdin: &[u8]) -> Result<Collected, String> {
        let spawned = Command::new(&argv[0])
            .args(&argv[1..])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();
        let mut child = match spawned {
            Ok(c) => c,
            Err(_) => {
                self.release_launch();
                return Err("the command could not be started".to_string());
            }
        };
        // Handed over once the unit EXISTS, not once `systemd-run` was spawned: setup's last `systemctl kill` on the unit glob must find
        // what this launch started (G5 fifth round, NV3-L5). systemd writes a transient unit's file before it starts it; if the
        // client has gone first (it ran and finished, or failed), there is nothing left to find. A deadline keeps a stuck systemd
        // from holding setup forever.
        // Whether a unit was seen to exist. The environment line is written only when it was (or there is no unit to wait for): a
        // client that has already exited with no unit seen gets no line, so a late unit could never read it (G5 seventh round, NV6-I2).
        let mut unit_seen = true;
        if let Some(unit) = argv
            .iter()
            .find_map(|a| a.strip_prefix("--unit="))
            .filter(|_| argv[0] == "systemd-run")
        {
            let existed = wait_until_unit_exists(
                Path::new("/run/systemd/transient"),
                unit,
                || child.try_wait().map_or(true, |s| s.is_some()),
                UNIT_WAIT,
            );
            let exited = child.try_wait().map_or(true, |s| s.is_some());
            unit_seen = existed;
            if must_abort(existed, exited) {
                // The unit may still be created and started, under the declaration this launch read: stop the client, then stop
                // the unit, and only then let go of the lock (G5 sixth round, NV5-L1). The client and `systemctl` are two connections
                // to PID 1, so the ORDER of the two is not guaranteed, and a stop of a unit that is not loaded yet fails and is
                // ignored. What makes the run fail closed is that NO secret line is written: the client is dropped, the pipe the
                // unit would read closes, and a late unit's exec-env step reads end-of-file and never runs the command (NV6-I1).
                let _ = child.kill();
                let _ = child.wait();
                let _ = Command::new("systemctl")
                    .args(["stop", &format!("{unit}.service")])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
                self.release_launch();
                return Err("the command could not be started in time".to_string());
            }
        }
        self.release_launch();
        if !unit_seen {
            // no unit was seen and the client has gone: no line is written. Its own output (systemd-run's error) is returned, and a
            // client that reports success with no unit seen is still a failed start.
            drop(child.stdin.take());
            let out = collect(child);
            return if out.0 == Some(0) {
                Err("the command could not be started".to_string())
            } else {
                Ok(out)
            };
        }
        // written on a thread: the line can be larger than a pipe holds, and the unit reads it only once it has started
        let writer = child.stdin.take().map(|mut si| {
            let bytes = Zeroizing::new(stdin.to_vec());
            std::thread::spawn(move || {
                let _ = si.write_all(&bytes);
            })
        });
        let out = collect(child);
        if let Some(w) = writer {
            let _ = w.join();
        }
        Ok(out)
    }
    fn audit(&self, line: &str) {
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.audit_log)
            .and_then(|mut f| writeln!(f, "{} {line}", crate::tokenmac::now_ms()));
    }
}

/// The agent's side: ask the launcher to run one declared command (or start, stop or ask after a service) and return its
/// answer. `pass` holds the plain values the caller supplies; they are checked by the launcher against the declaration.
#[cfg(test)]
pub fn request(
    socket: &Path,
    project: &str,
    env: &str,
    command: &str,
    argv: &[String],
) -> Result<Value, String> {
    request_with(socket, project, env, command, argv, "run", &[])
}

pub fn request_with(
    socket: &Path,
    project: &str,
    env: &str,
    command: &str,
    argv: &[String],
    action: &str,
    pass: &[(String, String)],
) -> Result<Value, String> {
    let down = || "the box's command runner is not reachable".to_string();
    let mut s = UnixStream::connect(socket).map_err(|_| down())?;
    let pass: serde_json::Map<String, Value> =
        pass.iter().map(|(k, v)| (k.clone(), json!(v))).collect();
    let mut req = json!({"project": project, "env": env, "command": command, "argv": argv});
    if action != "run" {
        req["action"] = json!(action);
    }
    if !pass.is_empty() {
        req["pass"] = Value::Object(pass);
    }
    s.write_all(format!("{req}\n").as_bytes())
        .map_err(|_| down())?;
    let mut line = String::new();
    BufReader::new(&s)
        .read_line(&mut line)
        .map_err(|_| down())?;
    let v: Value = serde_json::from_str(&line).map_err(|_| down())?;
    if v["ok"].as_bool() == Some(true) {
        Ok(v)
    } else {
        Err(v["error"]
            .as_str()
            .unwrap_or("the request was refused")
            .to_string())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    const SENTINEL: &str = "SENTINEL-runner-0123456789abcdef";

    /// G5 fifth round, NV3-L5: the launch holds the setup lock until the unit exists.
    #[test]
    fn a_launch_waits_for_its_unit_to_exist_before_it_lets_setup_in() {
        use std::time::Duration;
        let d = tempfile::tempdir().unwrap();
        let unit = "ozbox-run-app-0123456789abcdef";
        // the unit appears while we wait
        let path = d.path().join(format!("{unit}.service"));
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(40));
            std::fs::write(path, b"").unwrap();
        });
        let t0 = std::time::Instant::now();
        assert!(wait_until_unit_exists(
            d.path(),
            unit,
            || false,
            Duration::from_secs(5)
        ));
        assert!(
            t0.elapsed() >= Duration::from_millis(30),
            "it did not wait for the unit"
        );
        t.join().unwrap();
        // the client exited first (it ran and finished): nothing to wait for
        assert!(!wait_until_unit_exists(
            d.path(),
            "ozbox-run-app-ffffffffffffffff",
            || true,
            Duration::from_secs(5)
        ));
        // a stuck systemd: the deadline ends the wait
        let t0 = std::time::Instant::now();
        assert!(!wait_until_unit_exists(
            d.path(),
            "ozbox-run-app-eeeeeeeeeeeeeeee",
            || false,
            Duration::from_millis(60)
        ));
        // a timeout with the client still running aborts and stops the unit; a client that has exited does not (NV5-L1)
        // NV6-I3: a poisoned mutex does not hold the lock, and the launch is refused
        let slot = std::sync::Mutex::new(None);
        assert!(hold_launch_lock(&slot, true, None));
        assert!(!hold_launch_lock(&slot, false, None));
        let slot = std::sync::Arc::new(std::sync::Mutex::new(None::<std::fs::File>));
        let s2 = slot.clone();
        let _ = std::thread::spawn(move || {
            let _g = s2.lock().unwrap();
            panic!("poison");
        })
        .join();
        assert!(
            !hold_launch_lock(&slot, true, None),
            "a poisoned lock slot fails closed"
        );
        assert!(must_abort(false, false));
        assert!(!must_abort(false, true));
        assert!(!must_abort(true, false));
        assert!(t0.elapsed() < Duration::from_secs(2));
    }

    /// What the pinned program of the fixture holds: no import, so the closure check has nothing more to ask for.
    const SCRIPT: &str = "console.log('mint')\n";

    const FAKE_STAGE: &str = "00ff00ff00ff00ff";

    struct Fake {
        pins_dir: tempfile::TempDir,
        policy: Option<Policy>,
        ready: bool,
        seen: RefCell<Vec<Vec<String>>>,
        stdin: RefCell<Option<String>>,
        output: String,
        audit: RefCell<Vec<String>>,
        /// (unit, name, value) staged and not yet cleared; and what stood staged each time a unit was started
        staged: RefCell<Vec<(String, String, String)>>,
        staged_at_start: RefCell<Vec<(String, String, String)>>,
        cleared: RefCell<Vec<String>>,
        /// stored values carrying the public mark: (name, value)
        marked_public: Vec<(String, String)>,
        /// what the `systemd-run` of a service answers
        service_exit: Option<i32>,
        started: std::cell::Cell<bool>,
        /// a service of an earlier release is running under its old (hyphen) name
        legacy_active: bool,
        /// what the `systemd-run` of a service's proxy answers, and the rulesets written for it: (unit, text)
        egress_exit: Option<i32>,
        rules_written: RefCell<Vec<(String, String)>>,
        rules_cleared: RefCell<Vec<String>>,
        /// how many times setup's lock was asked for again, and from which of those on setup no longer matches (1-based; 0: never)
        setup_checks: std::cell::Cell<u32>,
        setup_changes_at: u32,
        /// what `systemctl start` of the route's proxy answers
        proxy_start_exit: Option<i32>,
        /// every call of the launcher in the order it was made: "lock <unit> wait|try", "write-rules", "clear-rules", and each
        /// `exec` as its words
        order: RefCell<Vec<String>>,
        /// what the machine lists as route units and route tables, and which services' locks someone else holds
        listed_units: String,
        listed_tables: String,
        locked_elsewhere: Vec<String>,
        /// the answer of a service's health check
        health: Option<u16>,
    }

    /// A command that receives a secret, written the way a declaration must be: a pinned program, exactly the words approved, an
    /// environment it may draw from. Its copy is already in the pin store (a root-owned, content-named file), as it is after a first run.
    fn policy() -> Policy {
        Policy::parse(&format!(
            r#"{{"dir":"/work/projects/app","writable":[".next"],"commands":{{
                "test":{{"allow":["API_KEY","OTHER"],"env":["API_KEY"],"argv":["node","t.mjs"],"envs":["staging"],
                "pin":[{{"file":"t.mjs","sha256":"{}"}}]}}}}}}"#,
            crate::runner_pins::sha256_hex(SCRIPT.as_bytes())
        ))
        .unwrap()
    }

    fn fake(output: &str) -> Fake {
        let pins_dir = tempfile::tempdir().unwrap();
        let store = crate::runner_pins::PinStore::new(pins_dir.path());
        store.seed_blob_for_test(SCRIPT.as_bytes());
        Fake {
            pins_dir,
            policy: Some(policy()),
            ready: true,
            seen: RefCell::default(),
            stdin: RefCell::default(),
            output: output.to_string(),
            audit: RefCell::default(),
            staged: RefCell::default(),
            staged_at_start: RefCell::default(),
            cleared: RefCell::default(),
            marked_public: Vec::new(),
            service_exit: Some(0),
            started: std::cell::Cell::new(false),
            legacy_active: false,
            egress_exit: Some(0),
            rules_written: RefCell::default(),
            rules_cleared: RefCell::default(),
            setup_checks: std::cell::Cell::new(0),
            setup_changes_at: 0,
            proxy_start_exit: Some(0),
            order: RefCell::default(),
            listed_units: String::new(),
            listed_tables: String::new(),
            locked_elsewhere: Vec::new(),
            health: Some(200),
        }
    }

    impl Backend for Fake {
        fn policy(&self, _: &str) -> Result<Option<Policy>, String> {
            Ok(self.policy.clone())
        }
        fn resolve(
            &self,
            _: &str,
            _: &str,
            name: &str,
            allowed: &[String],
        ) -> Result<Zeroizing<String>, String> {
            if !allowed.iter().any(|a| a == name) {
                return Err(format!("{name} is not allowed for this command"));
            }
            Ok(Zeroizing::new(SENTINEL.to_string()))
        }
        fn known(&self, _: &str) -> Result<Vec<Zeroizing<String>>, String> {
            Ok(vec![Zeroizing::new(SENTINEL.to_string())])
        }
        fn runner_ready(&self, _: &str) -> bool {
            self.ready
        }
        fn pins(&self) -> crate::runner_pins::PinStore {
            crate::runner_pins::PinStore::new(self.pins_dir.path())
        }
        fn resolve_public(
            &self,
            _: &str,
            _: &str,
            name: &str,
            declared: &[String],
        ) -> Result<Zeroizing<String>, String> {
            if !declared.iter().any(|a| a == name) {
                return Err(format!("{name} is not declared public for this command"));
            }
            match self.marked_public.iter().find(|(n, _)| n == name) {
                Some((_, v)) => Ok(Zeroizing::new(v.clone())),
                None => Err(format!("{name} is not marked public")),
            }
        }
        fn stage_credentials(
            &self,
            unit: &str,
            pairs: &[(String, Zeroizing<String>)],
        ) -> Result<String, String> {
            for (n, v) in pairs {
                self.staged
                    .borrow_mut()
                    .push((unit.to_string(), n.clone(), v.to_string()));
            }
            Ok(FAKE_STAGE.to_string())
        }
        fn clear_credentials(&self, unit: &str, _stage: Option<&str>) {
            self.staged.borrow_mut().retain(|(u, _, _)| u != unit);
            self.cleared.borrow_mut().push(unit.to_string());
        }
        fn user_uid(&self, _: &str) -> Option<u32> {
            Some(61234)
        }
        fn write_egress_rules(&self, unit: &str, text: &str) -> Result<String, String> {
            self.order.borrow_mut().push("write-rules".into());
            self.rules_written
                .borrow_mut()
                .push((unit.to_string(), text.to_string()));
            Ok(format!(
                "/run/ozbox-egress-rules/{unit}.0123456789abcdef.nft"
            ))
        }
        fn clear_egress_rules(&self, unit: &str) {
            self.order.borrow_mut().push("clear-rules".into());
            self.rules_cleared.borrow_mut().push(unit.to_string());
        }
        fn setup_current(&self, _: &str, _: &Policy) -> bool {
            self.setup_checks.set(self.setup_checks.get() + 1);
            self.setup_changes_at == 0 || self.setup_checks.get() < self.setup_changes_at
        }
        fn lock_service(&self, unit: &str, wait: bool) -> Result<Option<ServiceLock>, String> {
            self.order
                .borrow_mut()
                .push(format!("lock {unit} {}", if wait { "wait" } else { "try" }));
            if self.locked_elsewhere.iter().any(|u| u == unit) {
                return if wait { Err("busy".into()) } else { Ok(None) };
            }
            Ok(Some(ServiceLock(None)))
        }
        fn unit_state(&self, unit: &str) -> String {
            if unit == "ozbox-svc-app-web" {
                return if self.legacy_active {
                    "active"
                } else {
                    "inactive"
                }
                .into();
            }
            if self.started.get() {
                "active"
            } else {
                "inactive"
            }
            .into()
        }
        fn port_open(&self, _: u16) -> bool {
            false
        }
        fn http_status(&self, _: u16, _: &str) -> Option<u16> {
            self.health
        }
        fn sleep_ms(&self, _: u64) {}
        fn exec(&self, argv: &[String], stdin: &[u8]) -> Result<Collected, String> {
            self.seen.borrow_mut().push(argv.to_vec());
            self.order.borrow_mut().push(argv.join(" "));
            *self.stdin.borrow_mut() = Some(String::from_utf8(stdin.to_vec()).unwrap());
            if argv.len() >= 2 && argv[..2] == ["systemctl", "list-units"] {
                return Ok((Some(0), self.listed_units.clone().into_bytes(), Vec::new()));
            }
            if argv[0] == "/usr/sbin/nft" && argv.get(1).map(String::as_str) == Some("list") {
                return Ok((Some(0), self.listed_tables.clone().into_bytes(), Vec::new()));
            }
            if argv.len() == 3
                && argv[..2] == ["systemctl", "start"]
                && argv[2].starts_with("ozbox-egress-")
            {
                return Ok((self.proxy_start_exit, Vec::new(), Vec::new()));
            }
            if argv.len() == 3
                && argv[..2] == ["systemctl", "stop"]
                && argv[2].starts_with("ozbox-svc-")
            {
                self.started.set(false);
                return Ok((Some(0), Vec::new(), Vec::new()));
            }
            if argv[0] == "systemd-run"
                && argv.iter().any(|a| a.starts_with("--unit=ozbox-egress-"))
            {
                return Ok((self.egress_exit, Vec::new(), Vec::new()));
            }
            if argv[0] == "systemd-run" && argv.iter().any(|a| a.starts_with("--unit=ozbox-svc-")) {
                *self.staged_at_start.borrow_mut() = self.staged.borrow().clone();
                self.started.set(self.service_exit == Some(0));
                return Ok((self.service_exit, Vec::new(), Vec::new()));
            }
            Ok((Some(3), self.output.clone().into_bytes(), b"err\n".to_vec()))
        }
        fn audit(&self, line: &str) {
            self.audit.borrow_mut().push(line.to_string());
        }
    }

    /// (the folder is what these tests used to look in for the environment file: nothing is written there any more)
    fn ask(f: &Fake, _dir: &Path, req: Value) -> Value {
        launch(f, "abcd1234", &req.to_string())
    }

    impl Fake {
        /// The environment the unit was given on standard input, as `NAME=value` lines (values here have no newline).
        fn env_text(&self) -> String {
            let line = self.stdin.borrow().clone().unwrap();
            assert_eq!(line.matches('\n').count(), 1, "one line");
            let v: Value = serde_json::from_str(line.trim_end()).unwrap();
            v["env"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| format!("{}={}\n", p[0].as_str().unwrap(), p[1].as_str().unwrap()))
                .collect()
        }
    }

    fn req(argv: &[&str]) -> Value {
        json!({"project":"app","env":"staging","command":"test","argv":argv})
    }

    #[test]
    fn the_command_starts_as_the_runner_with_the_values_on_standard_input_and_never_in_an_argument_or_a_file(
    ) {
        let d = tempfile::tempdir().unwrap();
        let f = fake(&format!("hello {SENTINEL} and {SENTINEL}\n"));
        let r = ask(&f, d.path(), req(&["node", "t.mjs"]));
        assert_eq!(r["ok"], true, "{r}");
        assert_eq!(r["exit"], 3);
        // what comes back has the value removed, and says how many
        assert!(!r.to_string().contains(SENTINEL));
        assert_eq!(r["redactions"], 2);
        assert_eq!(r["resolved"], json!(["API_KEY"]));
        // the exact start-up: the runner's uid and gid, the project folder, a read-only system, a private /tmp, the
        // environment step, and the command after it
        let argv = f.seen.borrow()[0].clone();
        assert_eq!(argv[0], "systemd-run");
        // the command receives API_KEY, so it is a user of its own, never the project's runner
        let rc = secret_runner_user("app", "test");
        for want in [
            format!("--uid={rc}"),
            format!("--gid={rc}"),
            "--working-directory=/work/projects/app".to_string(),
            "--unit=ozbox-run-app-abcd1234".to_string(),
            "--pipe".to_string(),
            "--wait".to_string(),
        ] {
            assert!(argv.contains(&want), "{want}");
        }
        let has = |p: &str| argv.iter().any(|a| a == p);
        for p in [
            "NoNewPrivileges=yes".to_string(),
            "PrivateTmp=yes".to_string(),
            "ProtectSystem=strict".to_string(),
            "ProtectProc=invisible".to_string(),
            "MemorySwapMax=0".to_string(),
            format!("ReadWritePaths=-/var/lib/ozbox-run/{rc} -/work/projects/app/.next"),
        ] {
            assert!(has(&p), "{p}");
        }
        assert!(argv.iter().any(|a| a.starts_with("InaccessiblePaths=")
            && a.contains("/run/ozbox-runner")
            && a.contains("/run/ozbox-secrets")));
        let dash = argv.iter().position(|a| a == "--").unwrap();
        assert_eq!(
            &argv[dash + 1..],
            [
                "/usr/local/bin/ozbox",
                "secrets",
                "exec-env",
                "--",
                "node",
                "t.mjs"
            ]
        );
        // no value in the argument list; no secret anywhere in what the launcher itself ran; and no service-manager
        // environment file or credential, which would parse or store the value
        assert!(!argv.join(" ").contains(SENTINEL));
        assert!(!argv
            .iter()
            .any(|a| a.starts_with("EnvironmentFile=") || a.starts_with("LoadCredential")));
        // the value went on the unit's standard input, as data
        assert_eq!(f.env_text(), format!("API_KEY={SENTINEL}\n"));
        assert!(std::fs::read_dir(d.path()).unwrap().next().is_none());
        // the audit line names names, not values
        let a = f.audit.borrow().join("\n");
        assert!(a.contains("names=API_KEY") && a.contains("exit=3") && !a.contains(SENTINEL));
    }

    #[test]
    fn what_the_declaration_does_not_allow_is_refused_before_anything_starts() {
        let d = tempfile::tempdir().unwrap();
        let mut f = fake("");
        // a program that does not start as declared
        let r = ask(&f, d.path(), req(&["sh", "-c", "env"]));
        assert_eq!(r["ok"], false);
        // an undeclared command
        let r = ask(
            &f,
            d.path(),
            json!({"project":"app","env":"staging","command":"deploy","argv":["node","t.mjs"]}),
        );
        assert_eq!(r["ok"], false);
        // a secret reference in an argument (its value would show in the process list)
        let r = ask(&f, d.path(), req(&["node", "t.mjs", "{{secret:API_KEY}}"]));
        assert!(r["error"].as_str().unwrap().contains("argument"));
        // a name that is not shaped like a project, environment or command
        for bad in [
            json!({"project":"../x","env":"staging","command":"test","argv":["node","t.mjs"]}),
            json!({"project":"app","env":"","command":"test","argv":["node","t.mjs"]}),
            json!({"project":"app","env":"staging","command":"te st","argv":["node","t.mjs"]}),
            json!({"project":"app","env":"staging","command":"test","argv":[]}),
            json!("not an object"),
        ] {
            assert_eq!(ask(&f, d.path(), bad)["ok"], false);
        }
        // no declaration, no runner
        f.policy = None;
        assert_eq!(ask(&f, d.path(), req(&["node", "t.mjs"]))["ok"], false);
        f.policy = Some(policy());
        f.ready = false;
        assert!(ask(&f, d.path(), req(&["node", "t.mjs"]))["error"]
            .as_str()
            .unwrap()
            .contains("ensure-runner"));
        assert!(f.seen.borrow().is_empty(), "nothing was started");
        assert!(std::fs::read_dir(d.path()).unwrap().next().is_none());
    }

    #[test]
    fn a_name_the_command_may_not_receive_stops_the_run() {
        let d = tempfile::tempdir().unwrap();
        let mut f = fake("");
        let mut p = policy();
        // declare an environment name that the allow-list does not hold: the backend refuses it
        p.commands.get_mut("test").unwrap().allow = vec!["OTHER".into()];
        p.commands.get_mut("test").unwrap().env =
            vec![crate::workload_policy::EnvEntry::plain("API_KEY")];
        f.policy = Some(p);
        let r = ask(&f, d.path(), req(&["node", "t.mjs"]));
        assert_eq!(r["ok"], false);
        assert!(r["error"].as_str().unwrap().contains("allowed"), "{r}");
        assert!(f.seen.borrow().is_empty());
    }

    #[test]
    fn nothing_the_agent_can_run_reads_the_runners_environment_or_its_file() {
        // The file and the unit are the whole story, so they are asserted rather than assumed. Switching uid needs root,
        // so what is checked here is what makes the kernel refuse: a different uid than the box user's, a file that
        // only root can open, and a sandbox that does not show the service's directories.
        let argv = systemd_run_argv("app", "id01", &policy(), &["npm".into(), "test".into()]);
        let uid = argv.iter().find(|a| a.starts_with("--uid=")).unwrap();
        assert_ne!(uid, "--uid=ozbox", "never the box user");
        assert_eq!(uid, "--uid=ozbox-run-app");
        assert!(argv.iter().any(|a| a == "ProtectProc=invisible"));
        assert!(argv.iter().any(|a| a == "LimitCORE=0"));
        assert!(!argv
            .iter()
            .any(|a| a.starts_with("--setenv") || a == "-E" || a.starts_with("Environment=API")));
        // there is no file at all: the values are only ever on a pipe
        let d = tempfile::tempdir().unwrap();
        let f = fake("x");
        ask(&f, d.path(), req(&["node", "t.mjs"]));
        assert!(f.stdin.borrow().is_some());
        assert!(std::fs::read_dir(d.path()).unwrap().next().is_none());
    }

    /// The step inside the unit, run here for real with every hostile value: it gets the exact bytes, its PATH is the one
    /// it was started with, and nothing inside a value runs. (What systemd does around it needs a real box.)
    #[cfg(unix)]
    #[test]
    fn the_environment_step_hands_over_any_value_exactly_and_runs_nothing() {
        let d = tempfile::tempdir().unwrap();
        let marker = d.path().join("MARKER-RAN");
        let vals: Vec<String> = crate::secrets_enc::hostile::values()
            .into_iter()
            .map(|v| v.replace("MARKER", &marker.display().to_string()))
            .collect();
        for (i, v) in vals.iter().enumerate() {
            let out = d.path().join(format!("o{i}"));
            let pth = d.path().join(format!("p{i}"));
            let line = env_line(&[("HV".to_string(), Zeroizing::new(v.clone()))]);
            let argv = vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                format!(
                    "printf %s \"$HV\" > '{}'; printf %s \"$PATH\" > '{}'",
                    out.display(),
                    pth.display()
                ),
            ];
            let st = exec_env_command(&line, &argv).unwrap().status().unwrap();
            assert!(st.success(), "{i}");
            assert_eq!(std::fs::read(&out).unwrap(), v.as_bytes(), "{i}");
            assert_eq!(
                std::fs::read_to_string(&pth).unwrap(),
                std::env::var("PATH").unwrap()
            );
        }
        assert!(!marker.exists(), "nothing inside a value ran");
        // a newline in a value cannot add a variable: this is the whole reason there is no environment file
        let line = env_line(&[(
            "A".to_string(),
            Zeroizing::new("x\nPATH=/tmp/evil".to_string()),
        )]);
        let out = exec_env_command(
            &line,
            &[
                "/bin/sh".into(),
                "-c".into(),
                "printf '%s|%s' \"$A\" \"${PATH}\"".into(),
            ],
        )
        .unwrap()
        .output()
        .unwrap();
        let text = String::from_utf8(out.stdout).unwrap();
        assert!(
            text.starts_with("x\nPATH=/tmp/evil|") && !text.ends_with("/tmp/evil"),
            "{text}"
        );
        // what the step refuses: a name that is not a variable name, a NUL byte, no command, a line that is not the shape
        for bad in [
            r#"{"env":[["A B","x"]]}"#,
            r#"{"env":[["1A","x"]]}"#,
            r#"{"env":[["A=B","x"]]}"#,
            r#"{"env":[["A","a\u0000b"]]}"#,
            r#"{"env":[["A"]]}"#,
            r#"{"nope":1}"#,
            "not json",
        ] {
            assert!(
                exec_env_command(bad, &["/bin/true".to_string()]).is_err(),
                "{bad}"
            );
        }
        assert!(exec_env_command(r#"{"env":[]}"#, &[]).is_err());
    }

    #[test]
    fn a_hostile_value_goes_to_the_unit_as_one_json_line_and_nowhere_else() {
        let d = tempfile::tempdir().unwrap();
        let f = fake("ok\n");
        // the fake's resolve hands back the sentinel; a hostile one goes through a second backend
        struct Hostile(String, Fake);
        impl Backend for Hostile {
            fn policy(&self, p: &str) -> Result<Option<Policy>, String> {
                self.1.policy(p)
            }
            fn resolve(
                &self,
                _: &str,
                _: &str,
                _: &str,
                _: &[String],
            ) -> Result<Zeroizing<String>, String> {
                Ok(Zeroizing::new(self.0.clone()))
            }
            fn known(&self, _: &str) -> Result<Vec<Zeroizing<String>>, String> {
                Ok(vec![Zeroizing::new(self.0.clone())])
            }
            fn runner_ready(&self, p: &str) -> bool {
                self.1.runner_ready(p)
            }
            fn pins(&self) -> crate::runner_pins::PinStore {
                self.1.pins()
            }
            fn exec(&self, argv: &[String], stdin: &[u8]) -> Result<Collected, String> {
                self.1.exec(argv, stdin)
            }
            fn audit(&self, l: &str) {
                self.1.audit(l)
            }
        }
        let evil = "a b\nPATH=/tmp/evil\nLD_PRELOAD=/tmp/x.so \"q\" $(id)".to_string();
        let h = Hostile(evil.clone(), f);
        let r = launch(&h, "abcd1234", &req(&["node", "t.mjs"]).to_string());
        assert_eq!(r["ok"], true, "{r}");
        let line = h.1.stdin.borrow().clone().unwrap();
        assert_eq!(
            line.matches('\n').count(),
            1,
            "one line, so a newline in a value cannot start another"
        );
        let v: Value = serde_json::from_str(line.trim_end()).unwrap();
        assert_eq!(v["env"][0], json!(["API_KEY", evil]));
        let argv = h.1.seen.borrow()[0].join(" ");
        assert!(!argv.contains("evil") && !argv.contains("LD_PRELOAD"));
        let _ = d;
    }

    #[test]
    fn the_agents_side_sends_names_and_words_only_and_reads_back_the_scrubbed_answer() {
        use std::os::unix::net::UnixListener;
        let d = tempfile::tempdir().unwrap();
        let sock = d.path().join("l.sock");
        let l = UnixListener::bind(&sock).unwrap();
        let t = std::thread::spawn(move || {
            let (c, _) = l.accept().unwrap();
            let mut line = String::new();
            BufReader::new(&c).read_line(&mut line).unwrap();
            let mut w = &c;
            w.write_all(
                b"{\"ok\":true,\"exit\":0,\"stdout\":\"fine\",\"stderr\":\"\",\"redactions\":0}\n",
            )
            .unwrap();
            line
        });
        let v = request(
            &sock,
            "app",
            "staging",
            "test",
            &["npm".into(), "test".into()],
        )
        .unwrap();
        assert_eq!(v["stdout"], "fine");
        let sent = t.join().unwrap();
        assert!(sent.contains("\"command\":\"test\"") && !sent.contains("allow"));
        assert!(request(&d.path().join("none.sock"), "a", "b", "c", &["x".into()]).is_err());
    }

    #[test]
    fn a_command_has_no_network_but_loopback_and_reaches_only_declared_hosts_through_the_proxy() {
        let d = tempfile::tempdir().unwrap();
        // nothing declared: the unit is closed, and the command is not even told about a proxy
        let f = fake("ok\n");
        let r = ask(
            &f,
            d.path(),
            json!({"project":"app","env":"staging","command":"test","argv":["node","t.mjs"]}),
        );
        assert_eq!(r["ok"], true, "{r}");
        let argv = f.seen.borrow()[0].join(" ");
        for p in [
            "IPAddressDeny=any",
            "IPAddressAllow=127.0.0.1 ::1",
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
        ] {
            assert!(argv.contains(p), "{p}");
        }
        assert!(!f.env_text().contains("PROXY"));

        // declared: the proxy variables are in the environment line, with a password that is nowhere else
        let mut f = fake("ok\n");
        let mut p = policy();
        p.egress = vec!["api.example.com".into(), "files.example.org:8443".into()];
        f.policy = Some(p);
        let r = ask(
            &f,
            d.path(),
            json!({"project":"app","env":"staging","command":"test","argv":["node","t.mjs"]}),
        );
        assert_eq!(r["ok"], true, "{r}");
        let body = f.env_text();
        assert!(body.contains("HTTPS_PROXY=http://run:") && body.contains("@127.0.0.1:"));
        assert!(body.contains("NO_PROXY=localhost,127.0.0.1,::1"));
        let pw = body
            .split("http://run:")
            .nth(1)
            .unwrap()
            .split('@')
            .next()
            .unwrap()
            .to_string();
        assert!(!f.seen.borrow()[0].join(" ").contains(&pw));
        assert!(!r.to_string().contains(&pw) && !r.to_string().contains(SENTINEL));
        assert!(f.audit.borrow()[0].contains("egress=api.example.com,files.example.org:8443"));
        assert!(!f.audit.borrow()[0].contains(&pw));
        // the proxy stops with the command
        let port: u16 = body
            .split("@127.0.0.1:")
            .nth(1)
            .unwrap()
            .split('\n')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_err());
    }

    #[test]
    fn a_declared_tcp_destination_is_a_loopback_listener_the_command_is_told_about() {
        let d = tempfile::tempdir().unwrap();
        let mut f = fake("ok\n");
        let mut p = policy();
        p.tcp = vec![crate::egress::TcpDest {
            host: "db.staging.example.com".into(),
            port: 5432,
            env: "DATABASE".into(),
        }];
        f.policy = Some(p);
        let r = ask(
            &f,
            d.path(),
            json!({"project":"app","env":"staging","command":"test","argv":["node","t.mjs"]}),
        );
        assert_eq!(r["ok"], true, "{r}");
        let body = f.env_text();
        let port: u16 = body
            .lines()
            .find_map(|l| l.strip_prefix("DATABASE_PORT="))
            .unwrap()
            .parse()
            .unwrap();
        assert!(body.contains("DATABASE_HOST=127.0.0.1\n"));
        assert!(body.contains(&format!("DATABASE_ADDR=127.0.0.1:{port}\n")));
        assert!(body.contains("DATABASE_REMOTE_HOST=db.staging.example.com\n"));
        // the unit is still closed to everything but loopback, and the audit line says where the command may go
        assert!(f.seen.borrow()[0].join(" ").contains("IPAddressDeny=any"));
        assert!(f.audit.borrow()[0].contains("tcp=db.staging.example.com:5432"));
        // it stops with the command
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_err());
        // an address as the host is refused before anything starts
        let mut f = fake("ok\n");
        let mut p = policy();
        p.tcp = vec![crate::egress::TcpDest {
            host: "10.0.0.5".into(),
            port: 5432,
            env: "DB".into(),
        }];
        f.policy = Some(p);
        let r = ask(
            &f,
            d.path(),
            json!({"project":"app","env":"staging","command":"test","argv":["node","t.mjs"]}),
        );
        assert_eq!(r["ok"], false);
        assert!(f.seen.borrow().is_empty());
    }

    /// a command that receives a secret has a user of its own, with a name Linux accepts, that no other command has.
    #[test]
    fn a_secret_receiving_command_has_a_short_stable_user_of_its_own() {
        let a = secret_runner_user("app", "e2e-mint");
        assert_eq!(a, secret_runner_user("app", "e2e-mint"), "stable");
        assert!(a.starts_with("ozrc-") && a.len() <= 32, "{a}");
        // the whole 128 bits are in the name (26 base32 characters), so no one can search for a collision
        assert_eq!(a.len(), 5 + 26, "{a}");
        // the longest project and command names still fit, and nothing collides
        let long = secret_runner_user(&"p".repeat(20), &"c".repeat(32));
        assert!(
            long.len() <= 32
                && long
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
            "{long}"
        );
        assert_ne!(a, secret_runner_user("app", "e2e-mint2"));
        assert_ne!(a, secret_runner_user("app2", "e2e-mint"));
        assert_ne!(
            secret_runner_user("ab", "c"),
            secret_runner_user("a", "bc"),
            "the separator keeps names apart"
        );
        let p = Policy::parse(
            r#"{"dir":"/work/projects/app","commands":{"mint":{"allow":["K"],"env":["K"]},"web":{"allow":[]},"run":{"allow":[]}}}"#,
        )
        .unwrap();
        let users = runner_users("app", &p);
        assert_eq!(
            users.len(),
            2,
            "the project's runner, and one for the one command with a secret: {users:?}"
        );
        assert_eq!(users[0], "ozbox-run-app");
        for (name, c) in &p.commands {
            let u = runner_user_for("app", name, c);
            assert_eq!(u == "ozbox-run-app", !c.bears_secrets(), "{name}");
        }
    }

    /// the hardening is on every unit, and a unit gets its own PID namespace only where systemd has it.
    #[test]
    fn every_unit_has_no_swap_and_no_core_and_its_own_pid_space_where_the_system_can() {
        let none = systemd_run_argv("app", "id01", &policy(), &["x".into()]);
        for p in [
            "MemorySwapMax=0",
            "LimitCORE=0",
            "ProtectProc=invisible",
            "ProcSubset=pid",
        ] {
            assert!(none.iter().any(|a| a == p), "{p}");
        }
        assert!(
            !none.iter().any(|a| a == "PrivatePIDs=yes"),
            "never assumed: an older systemd would refuse the property"
        );
        let cp = crate::workload_policy::CommandPolicy::default();
        let on = systemd_run_argv_with(
            "app",
            "ozbox-run-app",
            "id01",
            &policy(),
            &cp,
            &["x".into()],
            &[],
            Host { private_pids: true },
        );
        assert!(on.iter().any(|a| a == "PrivatePIDs=yes"));
        let svc = systemd_run_service_argv(
            "app",
            "web",
            &policy(),
            &crate::workload_policy::CommandPolicy {
                service: true,
                port: Some(3100),
                argv: vec!["x".into()],
                ..Default::default()
            },
            &[],
            Host { private_pids: true },
            &ServiceInputs::default(),
        );
        for p in ["MemorySwapMax=0", "PrivatePIDs=yes", "--uid=ozbox-run-app"] {
            assert!(svc.iter().any(|a| a == p), "{p}");
        }
    }

    /// The step inside the unit makes itself non-dumpable. (Linux; it cannot be observed from a unit test on another system, and
    /// it does not outlive the exec: see `harden_self`.)
    #[cfg(target_os = "linux")]
    #[test]
    fn the_exec_step_marks_itself_non_dumpable_and_says_it_does_not_survive_the_exec() {
        harden_self();
        let st = std::fs::read_to_string("/proc/self/status").unwrap();
        let _ = st; // the flag is read through prctl, which rustix exposes as a getter
        assert_eq!(
            rustix::process::dumpable_behavior().unwrap(),
            rustix::process::DumpableBehavior::NotDumpable
        );
    }
    /// G5 second review, N-H3: a command that receives a secret sees a private view of the project: the folder is an empty tmpfs,
    /// and only the verified copies and the declared writable folders are put back. A plain command keeps the live folder.
    #[test]
    fn a_secret_command_runs_in_a_private_view_of_the_project_and_a_plain_one_does_not() {
        let d = tempfile::tempdir().unwrap();
        let f = fake("ok\n");
        assert_eq!(ask(&f, d.path(), req(&["node", "t.mjs"]))["ok"], true);
        let argv = f.seen.borrow()[0].clone();
        let has = |p: &str| argv.iter().any(|a| a == p);
        // G5 third round, NV-H1: the view is the whole work area, so no folder above the project and no other project exists in it
        assert!(has("TemporaryFileSystem=/work:ro"), "{argv:?}");
        assert!(
            !argv
                .iter()
                .any(|a| a.starts_with("TemporaryFileSystem=")
                    && a != "TemporaryFileSystem=/work:ro"),
            "{argv:?}"
        );
        // a declared writable folder is bound from the live folder, and never with a "skip it if missing" dash (NV-L1)
        assert!(
            has("BindPaths=/work/projects/app/.next:/work/projects/app/.next"),
            "{argv:?}"
        );
        assert!(
            !argv.iter().any(|a| a.starts_with("BindPaths=-")),
            "{argv:?}"
        );
        // the pinned program is the verified root-owned copy, bound read-only at its own path inside the view
        assert!(
            argv.iter()
                .any(|a| a.starts_with("BindReadOnlyPaths=")
                    && a.ends_with(":/work/projects/app/t.mjs")),
            "{argv:?}"
        );
        // nothing else of the live folder is bound: no package.json, no node_modules, no optional peer, no .npmrc
        let binds: Vec<&String> = argv
            .iter()
            .filter(|a| a.starts_with("BindPaths=") || a.starts_with("BindReadOnlyPaths="))
            .collect();
        assert_eq!(binds.len(), 2, "{binds:?}");
        for absent in ["package.json", "node_modules", ".npmrc", "bufferutil"] {
            assert!(
                !binds.iter().any(|b| b.contains(absent)),
                "{absent} must not exist in the view: {binds:?}"
            );
        }
        // the working directory is a path inside the view
        assert!(has("--working-directory=/work/projects/app"));
        // a plain command has no private view (it needs no pin and no walk)
        let plain = systemd_run_argv("app", "id02", &policy(), &["npm".into(), "test".into()]);
        assert!(
            !plain.iter().any(|a| a.starts_with("TemporaryFileSystem=")),
            "{plain:?}"
        );
    }

    /// What the unit sees of a `/work` that is `live`, made on disk from the start-up arguments themselves, the way the service
    /// manager reads them (G5 fourth round): every folder of the live `/work` is there, then the path named by `TemporaryFileSystem=`
    /// is emptied, then the binds are put back. Nothing here knows what the launcher means to hide: change the root the launcher
    /// names and what Node finds changes with it.
    fn build_view(argv: &[String], live: &Path, view: &Path) {
        let cp = |from: &Path, to: &Path| {
            std::fs::create_dir_all(to.parent().unwrap()).unwrap();
            assert!(Command::new("cp")
                .arg("-R")
                .arg(from)
                .arg(to)
                .status()
                .unwrap()
                .success());
        };
        let map = |p: &str| live.join(p.trim_start_matches('/'));
        cp(&map("/work"), &view.join("work"));
        for a in argv {
            if let Some(t) = a.strip_prefix("TemporaryFileSystem=") {
                let root = view.join(t.trim_end_matches(":ro").trim_start_matches('/'));
                std::fs::remove_dir_all(&root).unwrap();
                std::fs::create_dir_all(&root).unwrap();
            }
        }
        for a in argv {
            if let Some(b) = a
                .strip_prefix("BindPaths=")
                .or_else(|| a.strip_prefix("BindReadOnlyPaths="))
            {
                let (src, dest) = b.split_once(':').unwrap();
                let src = if src.starts_with("/work") {
                    map(src)
                } else {
                    PathBuf::from(src)
                };
                cp(&src, &view.join(dest.trim_start_matches('/')));
            }
        }
    }

    fn node_run(cwd: &Path, entry: &str) -> String {
        let o = Command::new("node")
            .arg(entry)
            .current_dir(cwd)
            .output()
            .unwrap();
        format!(
            "{}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        )
    }

    /// G5 third round, NV-H1 (the second verification's Node probe): an agent writes `package.json` and `node_modules` ABOVE the
    /// project folder, where Node looks after the folder itself (the package-scope lookup and a self-reference by name first, an
    /// optional peer second). In the view the unit gets, none of it exists; in the previous shape (only the project folder
    /// replaced) both ran with the secret in the environment.
    #[test]
    fn nothing_above_the_project_folder_exists_in_a_secret_commands_view_and_node_finds_none_of_it()
    {
        if Command::new("node").arg("--version").output().is_err() {
            return;
        }
        let t = tempfile::tempdir().unwrap();
        let live = t.path().join("live");
        let wr = |p: &str, c: &str| {
            let f = live.join(p);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(f, c).unwrap();
        };
        // above the project folder: the agent's files
        wr(
            "work/projects/package.json",
            r#"{"name":"pkg","exports":"./evil.mjs"}"#,
        );
        wr(
            "work/projects/evil.mjs",
            "console.log('EVIL-SELFREF loaded')",
        );
        wr(
            "work/projects/node_modules/absent/index.js",
            "console.log('EVIL-PARENT-NODE_MODULES loaded')",
        );
        std::fs::create_dir_all(live.join("work/projects/app/.next")).unwrap();
        // the pinned parts, as the pin store holds them
        let blobs = t.path().join("blobs");
        std::fs::create_dir_all(blobs.join("pkg")).unwrap();
        std::fs::write(blobs.join("m.mjs"), "import 'pkg'; console.log('mint ran')").unwrap();
        std::fs::write(
            blobs.join("pkg/index.js"),
            "try{require('absent')}catch(e){console.log('absent not found')}; module.exports=1",
        )
        .unwrap();
        std::fs::write(
            blobs.join("pkg/package.json"),
            r#"{"name":"pkg","main":"index.js"}"#,
        )
        .unwrap();
        let mounts = vec![
            crate::runner_pins::Mount {
                blob: blobs.join("m.mjs"),
                dest: "/work/projects/app/tests/m.mjs".into(),
            },
            crate::runner_pins::Mount {
                blob: blobs.join("pkg"),
                dest: "/work/projects/app/node_modules/pkg".into(),
            },
        ];
        let pol = policy();
        let cmd = &pol.commands["test"];
        let argv = systemd_run_argv_with(
            "app",
            "ozrc-x",
            "id01",
            &pol,
            cmd,
            &["node".into(), "tests/m.mjs".into()],
            &mounts,
            Host::default(),
        );
        let good = t.path().join("good");
        build_view(&argv, &live, &good);
        let out = node_run(&good.join("work/projects/app"), "tests/m.mjs");
        assert!(
            out.contains("mint ran") && out.contains("absent not found"),
            "{out}"
        );
        assert!(
            !out.contains("EVIL"),
            "the agent's files above the project folder were loaded: {out}"
        );
        assert!(
            !good.join("work/projects/package.json").exists()
                && !good.join("work/projects/node_modules").exists()
        );
        assert!(!good.join("work/projects/evil.mjs").exists());
        // the control: the same start-up arguments with the root put back to the project folder (the shape of c4f2321): the files
        // above it are loaded
        let old = t.path().join("old");
        let older: Vec<String> = argv
            .iter()
            .map(|a| {
                if a.starts_with("TemporaryFileSystem=/work:") {
                    "TemporaryFileSystem=/work/projects/app:ro".to_string()
                } else {
                    a.clone()
                }
            })
            .collect();
        assert_ne!(older, argv, "the launcher names the root /work");
        build_view(&older, &live, &old);
        let out = node_run(&old.join("work/projects/app"), "tests/m.mjs");
        assert!(
            out.contains("EVIL"),
            "the probe must show the old shape was open: {out}"
        );
    }

    /// NV-L1, at the launch: a backend that finds a writable folder missing stops a secret command before any secret is resolved.
    #[test]
    fn a_missing_writable_folder_stops_a_secret_command_before_a_secret_is_looked_up() {
        struct Missing(Fake);
        impl Backend for Missing {
            fn policy(&self, p: &str) -> Result<Option<Policy>, String> {
                self.0.policy(p)
            }
            fn resolve(
                &self,
                _: &str,
                _: &str,
                _: &str,
                _: &[String],
            ) -> Result<Zeroizing<String>, String> {
                panic!("a secret was looked up")
            }
            fn known(&self, _: &str) -> Result<Vec<Zeroizing<String>>, String> {
                Ok(Vec::new())
            }
            fn runner_ready(&self, p: &str) -> bool {
                self.0.runner_ready(p)
            }
            fn pins(&self) -> crate::runner_pins::PinStore {
                self.0.pins()
            }
            fn writable_ready(&self, p: &Policy) -> Result<(), String> {
                check_writable(Path::new("/nonexistent-ozbox-test"), &p.writable)
            }
            fn exec(&self, a: &[String], s: &[u8]) -> Result<Collected, String> {
                self.0.exec(a, s)
            }
            fn audit(&self, l: &str) {
                self.0.audit(l)
            }
        }
        let f = Missing(fake("ok\n"));
        let r = launch(&f, "abcd1234", &req(&["node", "t.mjs"]).to_string());
        assert_eq!(r["ok"], false, "{r}");
        assert!(
            r.to_string().contains(".next") && r.to_string().contains("missing"),
            "{r}"
        );
        assert!(f.0.seen.borrow().is_empty());
    }

    /// NV-L1: a writable folder that is missing or is a link refuses the run with a sentence naming it; nothing is skipped.
    #[test]
    fn a_writable_folder_that_is_missing_or_a_link_is_refused_by_name() {
        let t = tempfile::tempdir().unwrap();
        std::fs::create_dir(t.path().join(".next")).unwrap();
        assert!(check_writable(t.path(), &[".next".into()]).is_ok());
        let e = check_writable(t.path(), &[".next".into(), ".auth".into()]).unwrap_err();
        assert!(e.contains(".auth") && e.contains("missing"), "{e}");
        std::os::unix::fs::symlink("/etc", t.path().join(".auth")).unwrap();
        let e = check_writable(t.path(), &[".auth".into()]).unwrap_err();
        assert!(e.contains(".auth") && e.contains("link"), "{e}");
        std::fs::write(t.path().join("f"), "x").unwrap();
        assert!(check_writable(t.path(), &["f".into()])
            .unwrap_err()
            .contains("not a folder"));
    }

    /// The copy is what runs: once it exists, the live folder is not read, so a change to it (or a swap of a folder above it for a
    /// link) is not even looked at, and an unchanged run does no walk.
    #[test]
    fn with_a_copy_in_place_the_live_folder_is_never_read() {
        let d = tempfile::tempdir().unwrap();
        let f = fake("ok\n");
        // /work/projects/app does not exist on this machine at all: a check that opened it would fail
        assert!(!Path::new("/work/projects/app").exists());
        assert_eq!(ask(&f, d.path(), req(&["node", "t.mjs"]))["ok"], true);
    }

    /// G5 second review, N-H1: the caller cannot add a loader flag, a script or an option to a secret command.
    #[test]
    fn a_secret_command_takes_no_flag_script_or_option_the_owner_did_not_approve() {
        let d = tempfile::tempdir().unwrap();
        let f = fake("ok\n");
        for argv in [
            vec!["node", "--import=./hook.mjs", "t.mjs"],
            vec!["node", "-r", "dotenv/config", "t.mjs"],
            vec!["node", "--env-file=.env", "t.mjs"],
            vec!["node", "-e", "console.log(process.env)"],
            vec!["node", "--require", "./x.js", "t.mjs"],
            vec!["node", "--loader", "./l.mjs", "t.mjs"],
            vec!["node", "t.mjs", "--extra"],
            vec!["node"],
        ] {
            let r = ask(&f, d.path(), req(&argv));
            assert_eq!(r["ok"], false, "{argv:?}: {r}");
        }
        assert!(
            f.seen.borrow().is_empty(),
            "nothing started and no secret was looked up"
        );
    }

    /// N-M3 and N-C1's resolve side: the environment is one the declaration names; a passed value cannot be a host or URL; a value that
    /// holds an identifier the owner listed as production is refused.
    #[test]
    fn what_the_caller_chooses_cannot_steer_where_a_secret_goes_or_reach_production() {
        let d = tempfile::tempdir().unwrap();
        let mut f = fake("ok\n");
        let r = ask(
            &f,
            d.path(),
            json!({"project":"app","env":"other","command":"test","argv":["node","t.mjs"]}),
        );
        assert!(r["error"].as_str().unwrap().contains("staging only"), "{r}");
        let mut p = policy();
        p.commands.get_mut("test").unwrap().pass = vec!["TARGET".into()];
        f.policy = Some(p.clone());
        for v in [
            "https://evil.example.net",
            "evil.example.net",
            "10.0.0.5",
            "a@b",
            "x/y",
        ] {
            let r = ask(
                &f,
                d.path(),
                json!({"project":"app","env":"staging","command":"test","argv":["node","t.mjs"],"pass":{"TARGET":v}}),
            );
            assert_eq!(r["ok"], false, "{v}: {r}");
        }
        assert!(f.seen.borrow().is_empty());
        assert_eq!(
            ask(
                &f,
                d.path(),
                json!({"project":"app","env":"staging","command":"test","argv":["node","t.mjs"],"pass":{"TARGET":"staging-2"}})
            )["ok"],
            true
        );
        // the key the store holds names the owner's production project: refused, whatever environment it was stored under
        let mut p = policy();
        p.production_ids = vec!["abcdprodref".into()];
        f.policy = Some(p);
        let jwt_payload =
            crate::serve::auth::b64::encode_url(br#"{"ref":"abcdprodref","role":"service_role"}"#);
        struct Jwt(Fake, String);
        impl Backend for Jwt {
            fn policy(&self, p: &str) -> Result<Option<Policy>, String> {
                self.0.policy(p)
            }
            fn resolve(
                &self,
                _: &str,
                _: &str,
                _: &str,
                _: &[String],
            ) -> Result<Zeroizing<String>, String> {
                Ok(Zeroizing::new(self.1.clone()))
            }
            fn known(&self, _: &str) -> Result<Vec<Zeroizing<String>>, String> {
                Ok(Vec::new())
            }
            fn runner_ready(&self, p: &str) -> bool {
                self.0.runner_ready(p)
            }
            fn pins(&self) -> crate::runner_pins::PinStore {
                self.0.pins()
            }
            fn exec(&self, a: &[String], s: &[u8]) -> Result<Collected, String> {
                self.0.exec(a, s)
            }
            fn audit(&self, l: &str) {
                self.0.audit(l)
            }
        }
        let j = Jwt(f, format!("eyJhbGciOiJIUzI1NiJ9.{jwt_payload}.sig"));
        j.0.seen.borrow_mut().clear();
        let r = launch(&j, "abcd1234", &req(&["node", "t.mjs"]).to_string());
        assert_eq!(r["ok"], false, "{r}");
        assert!(r["error"].as_str().unwrap().contains("production"), "{r}");
        assert!(j.0.seen.borrow().is_empty());
    }

    /// N-M5: a declaration stored before the rules loads, and its secret command says what to change instead of failing to load.
    #[test]
    fn a_stored_declaration_that_no_longer_meets_the_rules_is_refused_for_its_secret_command_only()
    {
        let d = tempfile::tempdir().unwrap();
        let mut f = fake("ok\n");
        let old = r#"{"dir":"/work/projects/app","commands":{"test":{"allow":["API_KEY"],"env":["API_KEY"],"argv":["npm","test"]}}}"#;
        let hex: String = old.bytes().map(|b| format!("{b:02x}")).collect();
        f.policy = Some(Policy::from_hex(&hex).unwrap());
        let r = ask(
            &f,
            d.path(),
            json!({"project":"app","env":"staging","command":"test","argv":["npm","test"]}),
        );
        assert_eq!(r["ok"], false);
        assert!(
            r["error"]
                .as_str()
                .unwrap()
                .contains("until its declaration is updated"),
            "{r}"
        );
        assert!(f.seen.borrow().is_empty());
    }

    // ---- ADR 0029 Amendment 12: a service that receives a secret, and public values -----------------------------------------

    /// A service declared the way a secret command must be: a pinned program, exactly the words, an environment it may draw from.
    fn service_policy(extra: &str) -> Policy {
        Policy::parse(&format!(
            r#"{{"dir":"/work/projects/app","writable":[".next"],"commands":{{
                "web":{{"allow":["API_KEY"],"env":["API_KEY"],"service":true,"port":3100,"health":"/","argv":["node","t.mjs"],"envs":["staging"],
                "pin":[{{"file":"t.mjs","sha256":"{}"}}]{extra}}}}}}}"#,
            crate::runner_pins::sha256_hex(SCRIPT.as_bytes())
        ))
        .unwrap()
    }

    fn start_web(f: &Fake, env: &str) -> Value {
        launch(
            f,
            "abcd1234",
            &json!({"project":"app","env":env,"command":"web","action":"start"}).to_string(),
        )
    }

    const WEB_UNIT: &str = "ozbox-svc-app_web";

    fn after_dashes(argv: &[String]) -> &[String] {
        let i = argv.iter().position(|a| a == "--").unwrap();
        &argv[i + 1..]
    }

    #[test]
    fn a_service_receives_its_secret_as_a_credential_and_never_as_a_property_an_argument_or_standard_input(
    ) {
        let mut f = fake("ok\n");
        f.policy = Some(service_policy(""));
        let r = start_web(&f, "staging");
        assert_eq!(r["ok"], true, "{r}");
        let argv = f.seen.borrow()[0].clone();
        let has = |p: &str| argv.iter().any(|a| a == p);
        // systemd is told where to read it, and the property holds a path
        assert!(
            has(&format!(
                "LoadCredential=API_KEY:{CRED_ROOT}/{WEB_UNIT}/{FAKE_STAGE}/API_KEY"
            )),
            "{argv:?}"
        );
        // started only once systemd has run the program (the files may then go), with the unit's own user and private view
        assert!(has("Type=exec") && !has("--no-block"), "{argv:?}");
        assert!(
            has(&format!("--uid={}", secret_runner_user("app", "web"))),
            "{argv:?}"
        );
        assert!(has("TemporaryFileSystem=/work:ro"), "{argv:?}");
        // nothing of the value in any argument, and no standard input carried it
        assert!(!argv.iter().any(|a| a.contains(SENTINEL)), "{argv:?}");
        assert_eq!(f.stdin.borrow().clone().unwrap(), "");
        assert!(
            !argv.iter().any(|a| a.starts_with("Environment=API_KEY")),
            "{argv:?}"
        );
        // the file stood there while the unit started, and is gone after, on this outcome and on every other
        assert_eq!(
            *f.staged_at_start.borrow(),
            vec![(
                WEB_UNIT.to_string(),
                "API_KEY".to_string(),
                SENTINEL.to_string()
            )]
        );
        assert!(f.staged.borrow().is_empty());
        assert_eq!(*f.cleared.borrow(), [WEB_UNIT]);
        // by default the program reads `$CREDENTIALS_DIRECTORY` itself: `env`, not the shim
        assert_eq!(after_dashes(&argv)[0], "/usr/bin/env");
        let audit = f.audit.borrow().join("\n");
        assert!(
            audit.contains("secrets=API_KEY") && !audit.contains(SENTINEL),
            "{audit}"
        );
        // the same program starting with `credential_env` goes through the shim
        f.policy = Some(service_policy(r#","credential_env":true"#));
        f.seen.borrow_mut().clear();
        f.started.set(false);
        assert_eq!(start_web(&f, "staging")["ok"], true);
        let argv = f.seen.borrow()[0].clone();
        assert_eq!(after_dashes(&argv)[..4], EXEC_CRED.map(String::from)[..]);
    }

    #[test]
    fn a_service_start_meets_every_rule_a_run_meets_before_any_secret_is_looked_up() {
        // an environment the declaration does not list
        let mut f = fake("ok\n");
        f.policy = Some(service_policy(""));
        let r = start_web(&f, "production");
        assert_eq!(r["ok"], false);
        assert!(r["error"].as_str().unwrap().contains("staging only"), "{r}");
        assert!(
            f.seen.borrow().is_empty()
                && f.staged.borrow().is_empty()
                && f.cleared.borrow().is_empty()
        );
        // a declaration that no longer meets the rules (no pin) loads and refuses its secret service by name
        let old = r#"{"dir":"/work/projects/app","commands":{"web":{"allow":["API_KEY"],"env":["API_KEY"],"service":true,"port":3100,"argv":["npm","start"],"envs":["staging"]}}}"#;
        let hex: String = old.bytes().map(|b| format!("{b:02x}")).collect();
        f.policy = Some(Policy::from_hex(&hex).unwrap());
        let r = start_web(&f, "staging");
        assert_eq!(r["ok"], false);
        assert!(
            r["error"]
                .as_str()
                .unwrap()
                .contains("until its declaration is updated"),
            "{r}"
        );
        assert!(f.seen.borrow().is_empty() && f.cleared.borrow().is_empty());
        // a plain service still starts as before: no credential, `--no-block`, the project's own runner
        let mut f = fake("ok\n");
        f.policy = Some(
            Policy::parse(
                r#"{"dir":"/work/projects/app","commands":{"web":{"allow":[],"service":true,"port":3100,"argv":["npm","start"]}}}"#,
            )
            .unwrap(),
        );
        assert_eq!(start_web(&f, "staging")["ok"], true);
        let argv = f.seen.borrow()[0].clone();
        assert!(
            argv.iter().any(|a| a == "--no-block")
                && !argv.iter().any(|a| a.starts_with("LoadCredential="))
        );
        assert!(argv
            .iter()
            .any(|a| a == &format!("--uid={}", runner_user("app"))));
        assert!(f.cleared.borrow().is_empty());
    }

    #[test]
    fn a_service_that_fails_to_start_leaves_no_secret_behind() {
        let mut f = fake("ok\n");
        f.policy = Some(service_policy(""));
        f.service_exit = Some(1);
        let r = start_web(&f, "staging");
        assert_eq!(r["ok"], false, "{r}");
        assert!(!r.to_string().contains(SENTINEL));
        assert!(
            f.staged.borrow().is_empty(),
            "the file is removed whatever the outcome"
        );
        assert_eq!(*f.cleared.borrow(), [WEB_UNIT]);
        // stopping clears too
        let stop = json!({"project":"app","env":"staging","command":"web","action":"stop"});
        launch(&f, "abcd1234", &stop.to_string());
        assert_eq!(f.cleared.borrow().len(), 2);
    }

    // ---- ADR 0029 Amendment 12: a service's route out ----------------------------------------------------------------------

    const PROXY_UNIT: &str = "ozbox-egress-app_web";

    /// The same service, in a project that declares somewhere to reach (hosts only: raw tcp is held back from services).
    fn route_policy() -> Policy {
        let p = service_policy("");
        let mut v = serde_json::to_value(&p).unwrap();
        v["egress"] = json!(["api.stripe.com", "files.example.org:8443"]);
        v["production_ids"] = json!(["prodref123456"]);
        Policy::parse(&v.to_string()).unwrap()
    }

    fn seen_units(f: &Fake) -> Vec<String> {
        f.seen
            .borrow()
            .iter()
            .filter(|a| a[0] == "systemd-run")
            .map(|a| a.iter().find(|x| x.starts_with("--unit=")).unwrap().clone())
            .collect()
    }

    /// The launcher's calls about one route, in the order they were made, each as one short tag. Sweeps of other routes (the
    /// listings) are left out: they are asserted on their own.
    fn tags(f: &Fake) -> Vec<String> {
        f.order
            .borrow()
            .iter()
            .filter_map(|c| {
                let w: Vec<&str> = c.split(' ').collect();
                Some(match w.as_slice() {
                    ["lock", u, mode] => format!("lock {u} {mode}"),
                    ["write-rules"] => "write-rules".into(),
                    ["clear-rules"] => "clear-rules".into(),
                    ["systemd-run", ..] if c.contains("--unit=ozbox-egress-app_web") => {
                        "socket-up".into()
                    }
                    ["systemd-run", ..] if c.contains("--unit=ozbox-svc-app_web") => {
                        "service-up".into()
                    }
                    ["systemctl", "start", u] if *u == format!("{PROXY_UNIT}.service") => {
                        "proxy-start".into()
                    }
                    ["systemctl", "stop", u] if *u == WEB_UNIT => "stop-service".into(),
                    ["systemctl", "stop", u] if *u == "ozbox-svc-app-web" => {
                        "stop-service-legacy".into()
                    }
                    ["systemctl", "stop", p, s]
                        if *p == format!("{PROXY_UNIT}.service")
                            && *s == format!("{PROXY_UNIT}.socket") =>
                    {
                        "stop-route".into()
                    }
                    _ => return None,
                })
            })
            .collect()
    }

    fn at(t: &[String], what: &str) -> usize {
        t.iter()
            .position(|x| x == what)
            .unwrap_or_else(|| panic!("{what} is not in {t:?}"))
    }

    fn stop_web(f: &Fake) -> Value {
        let stop = json!({"project":"app","env":"staging","command":"web","action":"stop"});
        launch(f, "abcd1234", &stop.to_string())
    }

    #[test]
    fn a_service_with_declared_hosts_gets_its_socket_then_its_proxy_then_the_service_and_a_route_to_it(
    ) {
        let mut f = fake("ok\n");
        f.policy = Some(route_policy());
        let r = start_web(&f, "staging");
        assert_eq!(r["ok"], true, "{r}");
        // the socket's unit (PID 1 holds the ports), then the service; the proxy is started by `systemctl start`, between
        assert_eq!(
            seen_units(&f),
            [format!("--unit={PROXY_UNIT}"), format!("--unit={WEB_UNIT}")]
        );
        let seen = f.seen.borrow().clone();
        let route = seen
            .iter()
            .find(|a| a.contains(&format!("--unit={PROXY_UNIT}")))
            .unwrap();
        let after = after_dashes(route);
        assert!(
            after.contains(&"api.stripe.com".to_string())
                && after.contains(&"files.example.org:8443".to_string())
        );
        assert!(after.contains(&"--uid".to_string()) && after.contains(&"61234".to_string()));
        // the firewall rule names the service's own user id and every port of the route, and is written before the socket starts
        let (unit, text) = f.rules_written.borrow()[0].clone();
        assert_eq!(unit, PROXY_UNIT);
        assert!(text.contains("meta skuid != 61234"), "{text}");
        assert!(text.contains("table inet ozbox_egress_app_sweb"), "{text}");
        // the launcher sets the environment of the service, as properties
        let svc = seen
            .iter()
            .find(|a| a.contains(&format!("--unit={WEB_UNIT}")))
            .unwrap();
        assert!(svc
            .iter()
            .any(|a| a == &format!("BindsTo={PROXY_UNIT}.service {PROXY_UNIT}.socket")));
        assert!(svc
            .iter()
            .any(|a| a == &format!("After={PROXY_UNIT}.service {PROXY_UNIT}.socket")));
        let proxy_env = svc
            .iter()
            .find(|a| a.starts_with("Environment=HTTPS_PROXY=http://127.0.0.1:"))
            .unwrap();
        assert!(!proxy_env.contains('@'), "no password in a property");
        assert!(
            text.contains(proxy_env.rsplit(':').next().unwrap()),
            "the rule covers the proxy's port"
        );
        // a service's route is never given a plain-http variable or the catch-all one
        for k in ["http_proxy", "HTTP_PROXY", "ALL_PROXY", "all_proxy"] {
            assert!(
                !svc.iter()
                    .any(|a| a.starts_with(&format!("Environment={k}="))),
                "{k}"
            );
        }
        // setup's lock was taken again before the service started; the audit line says what the service can reach
        assert_eq!(f.setup_checks.get(), 2);
        let audit = f.audit.borrow().join("\n");
        assert!(
            audit.contains("egress=api.stripe.com,files.example.org:8443 tcp="),
            "{audit}"
        );
    }

    #[test]
    fn start_order_the_lock_first_a_leftover_cleared_the_ports_held_then_the_proxy_ready_then_the_service(
    ) {
        let mut f = fake("ok\n");
        f.policy = Some(route_policy());
        assert_eq!(start_web(&f, "staging")["ok"], true);
        let t = tags(&f);
        assert_eq!(
            t,
            [
                "lock ozbox-svc-app_web wait",
                // a leftover route of this name (none here) is cleared before anything is made
                "stop-route",
                "clear-rules",
                "write-rules",
                "socket-up",
                "clear-rules",
                "proxy-start",
                "service-up",
            ],
            "{t:?}"
        );
        // the invariant, as order: the ports are held and guarded (socket-up) and the proxy is ready (proxy-start returns only on
        // READY) before any service process exists (service-up)
        assert!(
            at(&t, "socket-up") < at(&t, "proxy-start")
                && at(&t, "proxy-start") < at(&t, "service-up")
        );
        // the lock is taken before the first call that changes anything
        assert_eq!(at(&t, "lock ozbox-svc-app_web wait"), 0);
        // the rules file is cleared once the socket is up, and nothing is left behind
        assert_eq!(f.rules_cleared.borrow().last().unwrap(), PROXY_UNIT);
    }

    #[test]
    fn a_socket_that_will_not_start_means_no_proxy_and_no_service() {
        let mut f = fake("ok\n");
        f.policy = Some(route_policy());
        f.egress_exit = Some(1);
        let r = start_web(&f, "staging");
        assert_eq!(r["ok"], false, "{r}");
        assert!(r["error"]
            .as_str()
            .unwrap()
            .contains("route could not be started"));
        let t = tags(&f);
        assert!(
            !t.contains(&"proxy-start".to_string()) && !t.contains(&"service-up".to_string()),
            "{t:?}"
        );
        assert!(at(&t, "socket-up") < t.iter().rposition(|x| x == "stop-route").unwrap());
        // nothing was staged for a service that never started
        assert!(f.staged.borrow().is_empty() && f.staged_at_start.borrow().is_empty());
    }

    #[test]
    fn a_proxy_that_will_not_get_ready_means_no_service_and_the_socket_is_let_go_after_it() {
        let mut f = fake("ok\n");
        f.policy = Some(route_policy());
        f.proxy_start_exit = Some(1);
        let r = start_web(&f, "staging");
        assert_eq!(r["ok"], false, "{r}");
        let t = tags(&f);
        assert!(!t.contains(&"service-up".to_string()), "{t:?}");
        assert!(at(&t, "proxy-start") < t.iter().rposition(|x| x == "stop-route").unwrap());
        assert!(f.staged.borrow().is_empty() && f.staged_at_start.borrow().is_empty());
    }

    #[test]
    fn a_setup_applied_while_the_route_started_stops_the_route_and_never_starts_the_service() {
        let mut f = fake("ok\n");
        f.policy = Some(route_policy());
        f.setup_changes_at = 2;
        let r = start_web(&f, "staging");
        assert_eq!(r["ok"], false, "{r}");
        let t = tags(&f);
        assert!(!t.contains(&"service-up".to_string()), "{t:?}");
        assert!(at(&t, "proxy-start") < t.iter().rposition(|x| x == "stop-route").unwrap());
        assert!(f.staged.borrow().is_empty() && f.staged_at_start.borrow().is_empty());
    }

    #[test]
    fn a_service_that_does_not_start_is_stopped_first_and_then_its_route() {
        let mut f = fake("ok\n");
        f.policy = Some(route_policy());
        f.service_exit = Some(1);
        assert_eq!(start_web(&f, "staging")["ok"], false);
        let t = tags(&f);
        let up = at(&t, "service-up");
        let stop_service = t.iter().rposition(|x| x == "stop-service").unwrap();
        let stop_route = t.iter().rposition(|x| x == "stop-route").unwrap();
        // the route's ports are let go only after the service (which may exist part-made) is stopped
        assert!(up < stop_service && stop_service < stop_route, "{t:?}");
    }

    #[test]
    fn a_service_that_fails_its_health_check_is_stopped_first_and_then_its_route() {
        let mut f = fake("ok\n");
        f.policy = Some(route_policy());
        f.health = None;
        let r = start_web(&f, "staging");
        assert_eq!(r["ok"], false, "{r}");
        let t = tags(&f);
        let up = at(&t, "service-up");
        let stop_service = t.iter().rposition(|x| x == "stop-service").unwrap();
        let stop_route = t.iter().rposition(|x| x == "stop-route").unwrap();
        assert!(up < stop_service && stop_service < stop_route, "{t:?}");
    }

    #[test]
    fn stop_ends_the_service_first_waiting_for_it_and_only_then_lets_go_of_the_ports() {
        let mut f = fake("ok\n");
        f.policy = Some(route_policy());
        assert_eq!(start_web(&f, "staging")["ok"], true);
        f.order.borrow_mut().clear();
        assert_eq!(stop_web(&f)["ok"], true);
        let t = tags(&f);
        assert_eq!(
            t,
            [
                "lock ozbox-svc-app_web wait",
                "stop-service",
                "stop-service-legacy",
                "stop-route",
                "clear-rules"
            ],
            "{t:?}"
        );
        // blocking: neither stop is `--no-block`, so `--stop` returns when everything is gone
        assert!(!f
            .seen
            .borrow()
            .iter()
            .any(|a| a.iter().any(|x| x == "--no-block")
                && a.iter().any(|x| x.starts_with("ozbox-egress-"))));
    }

    #[test]
    fn a_quick_restart_stops_everything_before_it_and_starts_the_new_route_from_nothing() {
        let mut f = fake("ok\n");
        f.policy = Some(route_policy());
        assert_eq!(start_web(&f, "staging")["ok"], true);
        assert_eq!(stop_web(&f)["ok"], true);
        f.order.borrow_mut().clear();
        assert_eq!(start_web(&f, "staging")["ok"], true);
        let t = tags(&f);
        // the new start clears any route of the name first (the old service's queued stops, waited for), then builds its own
        assert!(at(&t, "stop-route") < at(&t, "socket-up"), "{t:?}");
        assert!(
            at(&t, "socket-up") < at(&t, "proxy-start")
                && at(&t, "proxy-start") < at(&t, "service-up")
        );
        // and the proxy it starts is its own: the old one is never "stopped after" the new one is up
        assert_eq!(t.iter().filter(|x| *x == "stop-route").count(), 1, "{t:?}");
    }

    #[test]
    fn a_second_start_of_a_running_service_changes_nothing_and_a_busy_lock_is_a_refusal() {
        let mut f = fake("ok\n");
        f.policy = Some(route_policy());
        assert_eq!(start_web(&f, "staging")["ok"], true);
        f.order.borrow_mut().clear();
        // the service is up: a second start is refused before it touches the route (a leftover stop must never kill a live proxy)
        let r = start_web(&f, "staging");
        assert_eq!(r["ok"], false, "{r}");
        assert!(r["error"].as_str().unwrap().contains("already running"));
        assert_eq!(tags(&f), ["lock ozbox-svc-app_web wait"], "{:?}", tags(&f));
        // another start or stop holds the lock: this one is refused and touches nothing
        let mut g = fake("ok\n");
        g.policy = Some(route_policy());
        g.locked_elsewhere = vec![WEB_UNIT.to_string()];
        assert_eq!(start_web(&g, "staging")["ok"], false);
        assert_eq!(stop_web(&g)["ok"], false);
        assert!(g.seen.borrow().is_empty());
        // a status never waits for the lock
        let locks = |f: &Fake| tags(f).iter().filter(|x| x.starts_with("lock")).count();
        let before = locks(&g);
        let status = json!({"project":"app","env":"staging","command":"web","action":"status"});
        launch(&g, "abcd1234", &status.to_string());
        assert_eq!(locks(&g), before);
    }

    #[test]
    fn a_service_that_declares_raw_tcp_is_refused_with_a_clear_message_before_anything_starts() {
        let mut f = fake("ok\n");
        let mut v = serde_json::to_value(route_policy()).unwrap();
        v["tcp"] = json!([{"host":"db.example.com","port":5432,"env":"DATABASE"}]);
        f.policy = Some(Policy::parse(&v.to_string()).unwrap());
        let r = start_web(&f, "staging");
        assert_eq!(r["ok"], false, "{r}");
        let e = r["error"].as_str().unwrap();
        assert!(
            e.contains("tcp") && e.contains("not given them yet") && e.contains("ozbox env run"),
            "{e}"
        );
        assert!(seen_units(&f).is_empty() && f.rules_written.borrow().is_empty());
        assert!(f.staged.borrow().is_empty());
    }

    #[test]
    fn a_leftover_route_of_a_service_that_is_not_running_is_swept_and_a_busy_one_is_left_alone() {
        let mut f = fake("ok\n");
        f.policy = Some(route_policy());
        // a launcher that died after the socket (idle service) and one whose start is in progress right now (lock held)
        f.listed_units = "ozbox-egress-gone_web.socket loaded active listening x\nozbox-egress-gone_web.service loaded inactive dead x\nozbox-egress-busy_web.socket loaded active listening x\n".into();
        f.locked_elsewhere = vec!["ozbox-svc-busy_web".into()];
        f.listed_tables = "table inet ozbox_egress_gone_sweb\ntable inet ozbox_egress_busy_sweb\ntable inet filter\ntable ip nat\n".into();
        assert_eq!(start_web(&f, "staging")["ok"], true);
        let order = f.order.borrow().clone();
        let has = |w: &str| order.iter().any(|c| c == w);
        assert!(
            has("systemctl stop ozbox-egress-gone_web.service ozbox-egress-gone_web.socket"),
            "{order:?}"
        );
        assert!(
            !has("systemctl stop ozbox-egress-busy_web.service ozbox-egress-busy_web.socket"),
            "{order:?}"
        );
        // the stale table of the dead route goes; the one of the route being started right now, and any that is not ours, stay
        assert!(
            has("/usr/sbin/nft delete table inet ozbox_egress_gone_sweb"),
            "{order:?}"
        );
        assert!(
            !order
                .iter()
                .any(|c| c.contains("delete table inet ozbox_egress_busy")),
            "{order:?}"
        );
        assert!(!order
            .iter()
            .any(|c| c.contains("inet filter") && c.contains("delete")));
        // the sweep comes before this route's own socket
        let sweep = order
            .iter()
            .position(|c| c.starts_with("systemctl list-units"))
            .unwrap();
        let socket = order
            .iter()
            .position(|c| c.contains("--unit=ozbox-egress-app_web"))
            .unwrap();
        assert!(sweep < socket);
    }

    #[test]
    fn what_systemctl_and_nft_list_is_read_for_route_units_and_tables_only() {
        let l = "ozbox-egress-app_web.service loaded active running\n● ozbox-egress-app_web.socket loaded failed failed\nozbox-egress-a-b_c.socket loaded active listening\nozbox-egress-would-block.service x\nozbox-egress-.socket x\nozbox-egress-A_b.socket x\nssh.service x\n";
        assert_eq!(
            parse_route_units(l),
            ["ozbox-egress-a-b_c", "ozbox-egress-app_web"]
        );
        let n = "table inet filter\ntable inet ozbox_egress_app_sweb\ntable ip ozbox_egress_app_sweb\ntable inet ozbox_egress_X\ntable inet ozbox_egress_a_hb_sc\n";
        assert_eq!(
            parse_egress_tables(n),
            ["ozbox_egress_app_sweb", "ozbox_egress_a_hb_sc"]
        );
    }

    #[test]
    fn every_way_a_service_ends_ends_its_route_after_it() {
        // The ends systemd itself drives (the service's RuntimeMaxSec, the program exiting, the proxy dying and BindsTo= stopping
        // the service) are not calls of the launcher, so they are read off the properties that make them happen.
        let mut f = fake("ok\n");
        f.policy = Some(route_policy());
        assert_eq!(start_web(&f, "staging")["ok"], true);
        let seen = f.seen.borrow().clone();
        let svc = seen
            .iter()
            .find(|a| a.contains(&format!("--unit={WEB_UNIT}")))
            .unwrap();
        let route = seen
            .iter()
            .find(|a| a.contains(&format!("--unit={PROXY_UNIT}")))
            .unwrap();
        let has = |v: &Vec<String>, p: &str| v.iter().any(|a| a == p);
        // service: its limit (RuntimeMaxSec) is what ends a run, and every end of it queues the proxy's stop and then the socket's
        assert!(has(svc, "RuntimeMaxSec=14400"));
        let stops: Vec<&String> = svc
            .iter()
            .filter(|a| a.starts_with("ExecStopPost="))
            .collect();
        assert_eq!(stops.len(), 2);
        assert!(
            stops[0].ends_with(&format!("{PROXY_UNIT}.service"))
                && stops[1].ends_with(&format!("{PROXY_UNIT}.socket"))
        );
        // the service dies with its proxy and its socket (BindsTo), and starts after them (After): never before
        assert!(svc
            .iter()
            .any(|a| a.starts_with("BindsTo=") && a.contains(".service") && a.contains(".socket")));
        // the proxy and the socket outlive the service's own limit by five minutes, so only a route left behind meets theirs
        assert!(has(route, "RuntimeMaxSec=14700"));
        // the proxy is bound to the socket: it never runs without the ports held
        assert!(
            has(route, &format!("BindsTo={PROXY_UNIT}.socket"))
                && has(route, &format!("After={PROXY_UNIT}.socket"))
        );
        // and ends with its service
        assert!(has(route, &format!("PartOf={WEB_UNIT}.service")));
    }

    #[test]
    fn a_production_value_never_starts_a_route_and_a_service_that_bears_no_secret_has_none() {
        // the resolved value is a production identifier: refused before anything of the route exists
        let mut f = fake("ok\n");
        let mut v = serde_json::to_value(route_policy()).unwrap();
        v["production_ids"] = json!([SENTINEL]);
        f.policy = Some(Policy::parse(&v.to_string()).unwrap());
        let r = start_web(&f, "staging");
        assert_eq!(r["ok"], false, "{r}");
        assert!(r["error"].as_str().unwrap().contains("production"), "{r}");
        assert!(f.seen.borrow().is_empty() && f.rules_written.borrow().is_empty());
        // production as an environment is refused too
        let f2 = {
            let mut f = fake("ok\n");
            f.policy = Some(route_policy());
            f
        };
        assert_eq!(start_web(&f2, "production")["ok"], false);
        assert!(f2.seen.borrow().is_empty());
        // a service that receives no secret keeps its network closed: no proxy, no rule
        let mut f3 = fake("ok\n");
        let mut v = serde_json::to_value(
            Policy::parse(
                r#"{"dir":"/work/projects/app","commands":{"web":{"allow":[],"service":true,"port":3100,"argv":["npm","start"]}}}"#,
            )
            .unwrap(),
        )
        .unwrap();
        v["egress"] = json!(["api.stripe.com"]);
        f3.policy = Some(Policy::parse(&v.to_string()).unwrap());
        assert_eq!(start_web(&f3, "staging")["ok"], true);
        assert_eq!(seen_units(&f3), [format!("--unit={WEB_UNIT}")]);
        assert!(f3.rules_written.borrow().is_empty());
    }

    #[test]
    fn the_route_is_not_a_declaration_the_service_can_set() {
        // the names the launcher sets stay reserved for a declaration
        for n in [
            "HTTPS_PROXY",
            "http_proxy",
            "ALL_PROXY",
            "NODE_EXTRA_CA_CERTS",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
        ] {
            assert!(
                crate::workload_policy::reserved_name(n, &[]).is_some(),
                "{n}"
            );
        }
    }

    #[test]
    fn a_route_is_never_given_the_services_own_port() {
        let f = fake("ok\n");
        // whatever port the machine hands out first is the "service's own": asked to avoid it, the route never gets it
        let first = f.free_ports(1, &[]).unwrap()[0];
        for _ in 0..5 {
            let ports = f.free_ports(3, &[first]).unwrap();
            assert_eq!(ports.len(), 3);
            assert!(!ports.contains(&first), "{ports:?}");
            let mut d = ports.clone();
            d.sort();
            d.dedup();
            assert_eq!(d.len(), 3, "distinct");
        }
    }

    #[test]
    fn two_projects_whose_names_run_together_get_different_units() {
        // `a-b` + `c` and `a` + `b-c` were one unit under the hyphen name (E5)
        assert_ne!(service_unit("a-b", "c"), service_unit("a", "b-c"));
        assert_ne!(
            crate::runner_egress::egress_unit("a-b", "c"),
            crate::runner_egress::egress_unit("a", "b-c")
        );
        assert_eq!(service_unit("app", "web"), "ozbox-svc-app_web");
        assert_eq!(legacy_service_unit("app", "web"), "ozbox-svc-app-web");
        // the one-segment rule that makes `_` safe as the joint
        assert!(!seg_ok("a_b"));
    }

    #[test]
    fn a_service_an_earlier_release_started_under_its_old_name_is_found_stopped_and_never_started_twice(
    ) {
        let stop = json!({"project":"app","env":"staging","command":"web","action":"stop"});
        let status = json!({"project":"app","env":"staging","command":"web","action":"status"});
        let mut f = fake("ok\n");
        f.policy = Some(service_policy(""));
        f.legacy_active = true;
        // not started on top of it
        let r = start_web(&f, "staging");
        assert_eq!(r["ok"], false, "{r}");
        assert!(r["error"].as_str().unwrap().contains("already running"));
        assert!(seen_units(&f).is_empty());
        // reported as running, under the name that is up
        let r = launch(&f, "abcd1234", &status.to_string());
        assert_eq!(r["state"], "active", "{r}");
        assert_eq!(r["unit"], "ozbox-svc-app-web");
        // stopped by its exact old name, as well as the new
        launch(&f, "abcd1234", &stop.to_string());
        let calls: Vec<String> = f.seen.borrow().iter().map(|a| a.join(" ")).collect();
        assert!(
            calls.contains(&"systemctl stop ozbox-svc-app_web".to_string()),
            "{calls:?}"
        );
        assert!(
            calls.contains(&"systemctl stop ozbox-svc-app-web".to_string()),
            "{calls:?}"
        );
    }

    #[test]
    fn staged_secrets_are_swept_under_both_names_and_never_across_projects() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path();
        let pairs = [("K".to_string(), Zeroizing::new("v".to_string()))];
        for u in [
            "ozbox-svc-app_web",
            "ozbox-svc-app-web",
            "ozbox-svc-app-two_web",
        ] {
            stage_credentials_in(root, u, &pairs).unwrap();
        }
        sweep_credentials_in(root, Some("app"), 0);
        assert!(!root.join("ozbox-svc-app_web").exists());
        assert!(
            !root.join("ozbox-svc-app-web").exists(),
            "an earlier release's name"
        );
        assert!(
            root.join("ozbox-svc-app-two_web").exists(),
            "another project's new name is never taken for this project's"
        );
    }

    #[test]
    fn a_ruleset_file_is_private_to_the_launcher_one_per_start_and_only_for_a_unit_of_ours() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("rules");
        let p = write_egress_rules_in(&root, PROXY_UNIT, "table\n").unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "table\n");
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let name = Path::new(&p)
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();
        assert!(
            name.starts_with("ozbox-egress-app_web.") && name.ends_with(".nft"),
            "{name}"
        );
        // written again: a file of its own, never the first one's (two starts cannot load each other's rules)
        let p2 = write_egress_rules_in(&root, PROXY_UNIT, "again\n").unwrap();
        assert_ne!(p, p2);
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "table\n");
        assert_eq!(std::fs::read_to_string(&p2).unwrap(), "again\n");
        for bad in [
            "ozbox-svc-app-web",
            "ozbox-egress-",
            "ozbox-egress-../x",
            "ozbox-egress-A",
        ] {
            assert!(write_egress_rules_in(&root, bad, "x").is_err(), "{bad}");
        }
        // an existing link at the name is never followed: the file is created new or the write is refused
        let other = write_egress_rules_in(&root, "ozbox-egress-app_other", "o\n").unwrap();
        // clearing removes this unit's files and no other's
        clear_egress_rules_in(&root, PROXY_UNIT);
        assert!(!Path::new(&p).exists() && !Path::new(&p2).exists());
        assert!(Path::new(&other).exists());
        // a sweep removes only plain .nft files that are old
        assert_eq!(sweep_egress_rules_in(&root, 3600), 0);
        assert_eq!(sweep_egress_rules_in(&root, 0), 1);
        assert!(!Path::new(&other).exists());
    }

    #[test]
    fn one_service_is_started_or_stopped_at_a_time_and_a_try_is_refused_while_it_is_held() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("locks");
        let first = lock_service_in(&root, WEB_UNIT, true).unwrap().unwrap();
        // held: a try says so, and another unit's lock is free
        assert!(lock_service_in(&root, WEB_UNIT, false).unwrap().is_none());
        assert!(lock_service_in(&root, "ozbox-svc-app_other", false)
            .unwrap()
            .is_some());
        drop(first);
        assert!(lock_service_in(&root, WEB_UNIT, false).unwrap().is_some());
        for bad in [
            "ozbox-egress-app_web",
            "ozbox-svc-",
            "ozbox-svc-../x",
            "ozbox-svc-A",
        ] {
            assert!(lock_service_in(&root, bad, true).is_err(), "{bad}");
        }
    }

    /// A JWT-shaped value built at run time: a public anonymous key looks like a secret and is not one.
    fn anon_key() -> String {
        format!(
            "{}.{}.{}",
            "eyJhbGciOiJIUzI1NiJ9", "eyJyb2xlIjoiYW5vbiJ9", "c2lnbmF0dXJlLWJ5dGVz"
        )
    }

    #[test]
    fn public_values_reach_a_run_as_plain_environment_and_a_service_as_a_property_and_only_when_marked_and_declared(
    ) {
        let anon = anon_key();
        let url = "https://staging.example.com";
        // a one-shot command: the values ride the unit's standard input like any plain variable, never an argument
        let mut f = fake("ok\n");
        let mut p = policy();
        p.commands.get_mut("test").unwrap().public = vec![
            "NEXT_PUBLIC_SUPABASE_ANON_KEY".into(),
            "NEXT_PUBLIC_APP_URL".into(),
        ];
        f.policy = Some(p);
        f.marked_public = vec![
            ("NEXT_PUBLIC_SUPABASE_ANON_KEY".into(), anon.clone()),
            ("NEXT_PUBLIC_APP_URL".into(), url.into()),
        ];
        let d = tempfile::tempdir().unwrap();
        assert_eq!(ask(&f, d.path(), req(&["node", "t.mjs"]))["ok"], true);
        let env = f.env_text();
        assert!(
            env.contains(&format!("NEXT_PUBLIC_SUPABASE_ANON_KEY={anon}\n"))
                && env.contains(&format!("NEXT_PUBLIC_APP_URL={url}\n")),
            "{env}"
        );
        assert!(!f.seen.borrow()[0].iter().any(|a| a.contains(&anon)));
        assert!(
            f.audit.borrow()[0]
                .contains("public=NEXT_PUBLIC_SUPABASE_ANON_KEY,NEXT_PUBLIC_APP_URL"),
            "names only"
        );
        assert!(!f.audit.borrow()[0].contains(&anon));
        // a name whose stored value is not marked public is refused, whatever the value looks like: nothing starts
        f.marked_public.clear();
        f.seen.borrow_mut().clear();
        let r = ask(&f, d.path(), req(&["node", "t.mjs"]));
        assert_eq!(r["ok"], false);
        assert!(
            r["error"].as_str().unwrap().contains("not marked public"),
            "{r}"
        );
        assert!(f.seen.borrow().is_empty());
        // an environment the declaration does not list gets no public value either
        f.marked_public = vec![("NEXT_PUBLIC_APP_URL".into(), url.into())];
        let r = ask(
            &f,
            d.path(),
            json!({"project":"app","env":"production","command":"test","argv":["node","t.mjs"]}),
        );
        assert_eq!(r["ok"], false);
        assert!(f.seen.borrow().is_empty());
        // a service: a plain `Environment=` property (public by design, so `systemctl show` may show it), no credential
        let mut f = fake("ok\n");
        f.policy = Some(
            Policy::parse(
                r#"{"dir":"/work/projects/app","commands":{"web":{"allow":[],"service":true,"port":3100,"argv":["npm","start"],"public":["NEXT_PUBLIC_SUPABASE_ANON_KEY"],"envs":["staging"]}}}"#,
            )
            .unwrap(),
        );
        f.marked_public = vec![("NEXT_PUBLIC_SUPABASE_ANON_KEY".into(), anon.clone())];
        assert_eq!(start_web(&f, "staging")["ok"], true);
        let argv = f.seen.borrow()[0].clone();
        assert!(
            argv.iter()
                .any(|a| a == &format!("Environment=NEXT_PUBLIC_SUPABASE_ANON_KEY={anon}")),
            "{argv:?}"
        );
        assert!(!argv.iter().any(|a| a.starts_with("LoadCredential=")));
        // a stored value that is not plain text is refused before it can become a second variable
        f.marked_public = vec![("NEXT_PUBLIC_SUPABASE_ANON_KEY".into(), "a b".into())];
        f.seen.borrow_mut().clear();
        f.started.set(false);
        assert_eq!(start_web(&f, "staging")["ok"], false);
        assert!(f.seen.borrow().is_empty());
    }

    #[test]
    fn the_staging_folder_is_private_holds_one_file_per_secret_and_is_removed() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("cred");
        let pairs = vec![
            (
                "API_KEY".to_string(),
                Zeroizing::new("value-one".to_string()),
            ),
            (
                "OTHER".to_string(),
                Zeroizing::new("two\nlines".to_string()),
            ),
        ];
        let st = stage_credentials_in(&root, "ozbox-svc-app-web", &pairs).unwrap();
        assert_eq!(st.len(), 16);
        assert!(st.bytes().all(|b| b.is_ascii_hexdigit()));
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let dir = root.join("ozbox-svc-app-web").join(&st);
        assert_eq!(mode(&root), 0o700);
        assert_eq!(mode(&root.join("ozbox-svc-app-web")), 0o700);
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&dir.join("API_KEY")), 0o400);
        assert_eq!(
            std::fs::read_to_string(dir.join("OTHER")).unwrap(),
            "two\nlines"
        );
        // L2: a second start has a folder of its own and leaves the first's files alone, so two starts never share one
        let st2 = stage_credentials_in(&root, "ozbox-svc-app-web", &pairs[..1]).unwrap();
        assert_ne!(st, st2);
        assert!(
            dir.join("OTHER").exists(),
            "the first start's files are untouched"
        );
        assert!(!root
            .join("ozbox-svc-app-web")
            .join(&st2)
            .join("OTHER")
            .exists());
        // clearing one start removes only its folder
        clear_credentials_in(&root, "ozbox-svc-app-web", Some(&st2));
        assert!(dir.exists() && !root.join("ozbox-svc-app-web").join(&st2).exists());
        // a stop removes every one of the unit's
        clear_credentials_in(&root, "ozbox-svc-app-web", None);
        assert!(!root.join("ozbox-svc-app-web").exists());
        // a stage that is not a nonce is never joined as a path
        let keep = stage_credentials_in(&root, "ozbox-svc-app-web", &pairs).unwrap();
        clear_credentials_in(&root, "ozbox-svc-app-web", Some("../.."));
        clear_credentials_in(&root, "ozbox-svc-app-web", Some(""));
        assert!(root.join("ozbox-svc-app-web").join(&keep).exists());
        clear_credentials_in(&root, "ozbox-svc-app-web", None);
        // a unit name that is not one of ours, a name that is not a variable name and a NUL are refused, and nothing is left
        for (u, n, v) in [
            ("../x", "A", "v"),
            ("ozbox-svc-a-b", "../A", "v"),
            ("ozbox-svc-a-b", "a", "v"),
            ("ozbox-svc-a-b", "A", "v\0"),
        ] {
            let bad = vec![(n.to_string(), Zeroizing::new(v.to_string()))];
            assert!(stage_credentials_in(&root, u, &bad).is_err(), "{u} {n}");
        }
        assert!(!root.join("x").exists());
        let left = std::fs::read_dir(root.join("ozbox-svc-a-b")).map_or(0, |r| r.count());
        assert_eq!(left, 0, "a refused start leaves no folder of its own");
        // the path systemd is told about is the one staged
        assert_eq!(
            credential_path("ozbox-svc-app-web", "00ff00ff00ff00ff", "API_KEY"),
            format!("{CRED_ROOT}/ozbox-svc-app-web/00ff00ff00ff00ff/API_KEY")
        );
    }

    #[test]
    fn a_sweep_takes_stale_start_folders_and_a_project_sweep_takes_all_of_its_services() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("cred");
        let pairs = vec![("K".to_string(), Zeroizing::new("v".to_string()))];
        let web = stage_credentials_in(&root, "ozbox-svc-app-web", &pairs).unwrap();
        let other = stage_credentials_in(&root, "ozbox-svc-other-web", &pairs).unwrap();
        // fresh folders are a start in progress: an age sweep leaves them
        assert_eq!(sweep_credentials_in(&root, None, CRED_STALE_SECS), 0);
        assert!(root.join("ozbox-svc-app-web").join(&web).exists());
        // with no age limit every start folder is stale
        assert_eq!(sweep_credentials_in(&root, None, 0), 2);
        assert!(!root.join("ozbox-svc-app-web").join(&web).exists());
        assert!(!root.join("ozbox-svc-other-web").join(&other).exists());
        // a project sweep removes that project's services whatever their age, and nobody else's
        let web = stage_credentials_in(&root, "ozbox-svc-app-web", &pairs).unwrap();
        let other = stage_credentials_in(&root, "ozbox-svc-other-web", &pairs).unwrap();
        assert_eq!(sweep_credentials_in(&root, Some("app"), CRED_STALE_SECS), 1);
        assert!(!root.join("ozbox-svc-app-web").join(&web).exists());
        assert!(root.join("ozbox-svc-other-web").join(&other).exists());
        // a project name that is a prefix of another's is not the other
        let a2 = stage_credentials_in(&root, "ozbox-svc-app2-web", &pairs).unwrap();
        assert_eq!(sweep_credentials_in(&root, Some("app"), CRED_STALE_SECS), 0);
        assert!(root.join("ozbox-svc-app2-web").join(&a2).exists());
        // a missing root is nothing to do
        assert_eq!(sweep_credentials_in(&d.path().join("none"), None, 0), 0);
    }

    #[test]
    fn the_shim_turns_each_credential_into_a_variable_and_refuses_what_is_not_one() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("API_KEY"), "value-one").unwrap();
        std::fs::write(d.path().join("OTHER_1"), "two words").unwrap();
        let argv = ["node".to_string(), "server.mjs".to_string()];
        let c = exec_cred_command(d.path(), &argv).unwrap();
        let envs: std::collections::BTreeMap<String, String> = c
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into(),
                    v.unwrap().to_string_lossy().into(),
                )
            })
            .collect();
        assert_eq!(envs["API_KEY"], "value-one");
        assert_eq!(envs["OTHER_1"], "two words");
        assert_eq!(c.get_program(), "node");
        // no credentials directory entry may be a link, a folder or a name that is not a variable name
        for (name, link) in [
            ("bad-name", false),
            ("1X", false),
            ("LINKED", true),
            ("DIR", false),
        ] {
            let d2 = tempfile::tempdir().unwrap();
            let p = d2.path().join(name);
            if link {
                std::os::unix::fs::symlink("/etc/hostname", &p).unwrap();
            } else if name == "DIR" {
                std::fs::create_dir(&p).unwrap();
            } else {
                std::fs::write(&p, "v").unwrap();
            }
            assert!(exec_cred_command(d2.path(), &argv).is_err(), "{name}");
        }
        let d3 = tempfile::tempdir().unwrap();
        std::fs::write(d3.path().join("NUL"), b"a\0b").unwrap();
        assert!(exec_cred_command(d3.path(), &argv).is_err());
        assert!(exec_cred_command(d.path(), &[]).is_err());
        assert!(exec_cred_command(Path::new("/nonexistent-cred-dir"), &argv).is_err());
    }

    #[test]
    fn the_shim_never_exports_a_name_that_decides_how_a_program_starts() {
        let argv = ["node".to_string(), "server.mjs".to_string()];
        for name in [
            "NODE_OPTIONS",
            "LD_PRELOAD",
            "PATH",
            "CREDENTIALS_DIRECTORY",
            "INVOCATION_ID",
            "LISTEN_FDS",
            "HTTPS_PROXY",
            "path",
        ] {
            let d = tempfile::tempdir().unwrap();
            std::fs::write(d.path().join(name), "v").unwrap();
            let e = exec_cred_command(d.path(), &argv).unwrap_err();
            assert!(e.contains("cannot be set"), "{name}: {e}");
            assert!(!e.contains("v\n"));
        }
    }

    #[test]
    fn the_shim_reads_only_a_folder_systemd_made_under_run_credentials() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let root = d.path().canonicalize().unwrap().join("credentials");
        std::fs::create_dir(&root).unwrap();
        let me = current_euid();
        let unit = root.join("app.service");
        std::fs::create_dir(&unit).unwrap();
        std::fs::set_permissions(&unit, std::fs::Permissions::from_mode(0o700)).unwrap();
        // the right place, the right owner, nobody else can write
        assert!(credentials_dir_ok(&unit, &root, &[me]).is_ok());
        // "directly under" the root, as the comment says: a folder further down is not systemd's (E14)
        let deeper = unit.join("sub");
        std::fs::create_dir(&deeper).unwrap();
        std::fs::set_permissions(&deeper, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(credentials_dir_ok(&deeper, &root, &[me]).is_err());
        // owned by someone else (here: nobody in the list owns it), as a folder the agent made would be
        assert!(credentials_dir_ok(&unit, &root, &[me.wrapping_add(1)]).is_err());
        // writable by group or others
        std::fs::set_permissions(&unit, std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(credentials_dir_ok(&unit, &root, &[me]).is_err());
        std::fs::set_permissions(&unit, std::fs::Permissions::from_mode(0o702)).unwrap();
        assert!(credentials_dir_ok(&unit, &root, &[me]).is_err());
        std::fs::set_permissions(&unit, std::fs::Permissions::from_mode(0o700)).unwrap();
        // outside the root, the root itself, a relative path and a `..` out of it
        let outside = d.path().join("elsewhere");
        std::fs::create_dir(&outside).unwrap();
        assert!(credentials_dir_ok(&outside, &root, &[me]).is_err());
        assert!(credentials_dir_ok(&root, &root, &[me]).is_err());
        assert!(credentials_dir_ok(Path::new("app.service"), &root, &[me]).is_err());
        assert!(credentials_dir_ok(&unit.join("../../elsewhere"), &root, &[me]).is_err());
        // a link, to a folder that would pass
        let link = root.join("linked");
        std::os::unix::fs::symlink(&unit, &link).unwrap();
        assert!(credentials_dir_ok(&link, &root, &[me]).is_err());
        // a regular file and a missing folder
        std::fs::write(root.join("file"), "x").unwrap();
        assert!(credentials_dir_ok(&root.join("file"), &root, &[me]).is_err());
        assert!(credentials_dir_ok(&root.join("none"), &root, &[me]).is_err());
        // and the real shim refuses a folder an agent could write, whatever CREDENTIALS_DIRECTORY says
        let real_root = Path::new("/run/credentials");
        assert!(credentials_dir_ok(&outside, real_root, &[0]).is_err());
    }

    /// `"tools": ["node"]` is enough: the program is found on the unit's PATH, in the folder the setup fills with that project's
    /// root-owned copy, ahead of the system's. No absolute path is written anywhere.
    #[test]
    fn a_declared_tool_is_first_on_the_units_path_in_the_folder_the_setup_fills() {
        let p = Policy::parse(
            r#"{"dir":"/work/projects/app","tools":["node"],"commands":{"build":{"allow":[],"argv":["node","build.mjs"]}}}"#,
        )
        .unwrap();
        let path = run_path("app", &p);
        let first = path.split(':').next().unwrap();
        let setup = crate::runner_setup::Paths::system(PathBuf::from("/work/home/ozbox"));
        assert_eq!(
            Path::new(first),
            setup.tools.join("bin").join("app"),
            "the unit looks where setup links `node`"
        );
        assert_eq!(path, format!("{first}:/usr/local/bin:/usr/bin:/bin"));
        let argv = systemd_run_argv(
            "app",
            "id1",
            &p,
            &["node".to_string(), "build.mjs".to_string()],
        );
        assert!(
            argv.iter()
                .any(|a| a == &format!("Environment=PATH={path}")),
            "{argv:?}"
        );
        // the program is not given as a path: it is the word the declaration wrote
        assert_eq!(after_dashes(&argv).last().unwrap(), "build.mjs");
        assert!(after_dashes(&argv).iter().any(|a| a == "node"));
        // another project's tools are another folder, and no tools keeps the system's PATH alone
        assert_ne!(run_path("other", &p), path);
        let none =
            Policy::parse(r#"{"dir":"/work/projects/app","commands":{"a":{"allow":[]}}}"#).unwrap();
        assert_eq!(run_path("app", &none), "/usr/local/bin:/usr/bin:/bin");
    }
}
