//! Self-test: after boot, resize and upgrade, check that the box can actually work. Each check passes, or fails with
//! the step named and a reason a person can act on.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use ozbox_core::{CommandRunner, CommandSpec};
use serde::Serialize;

use crate::growfs;
use crate::host::HostSource;
use crate::metrics::parse;

/// Whether runs are units of the box user's manager now (they outlive a daemon restart), and why not when they are not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunBackendNow {
    pub units: bool,
    pub why: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SelfTestConfig {
    pub work_dir: PathBuf,
    /// Require `work_dir` to be its own mount point (the persistent disk).
    pub require_mount: bool,
    pub min_free_bytes: u64,
    pub tools: Vec<String>,
    /// What the provider module declared about /work encryption: `true`, `false` or `unknown`. A cloud volume's
    /// encryption is invisible from inside the box, so a declaration alone is reported as unverified.
    pub work_encrypted: String,
    /// systemd units that carry the outbound tunnels; each must be `active`.
    pub tunnel_units: Vec<String>,
    /// Where the writability probe goes: the daemon's own state directory on /work. /work itself is root-owned by
    /// design and the daemon runs as the box user, so probing /work's top level fails on a healthy box.
    pub probe_dir: PathBuf,
    /// Where the box user's enabled `systemd --user` units are linked (`default.target.wants`, on /work). Each must be
    /// active: a user manager that reached its target before /work was mounted starts none of them, and nothing else
    /// would say so.
    pub user_wants_dir: PathBuf,
    /// The secrets service's sockets this user (the box user) must be able to connect to: the box socket, the broker
    /// socket and the import socket. A socket that exists but refuses this user means the service cannot be used at all.
    /// Empty off a box; a socket whose directory does not exist is a box without the service, and is skipped.
    pub secrets_sockets: Vec<PathBuf>,
    /// What the secrets service says about itself (`/run/ozbox-secrets/state`). When it says the service is not ready, the
    /// self-test fails and names the key that protects the store, so a box whose key cannot be used is never reported well.
    /// `None` off a box; a missing file is a box without the service, and is skipped.
    pub secrets_state_file: Option<PathBuf>,
    /// Root's approval setting files (`approvals-legacy-codes-off`, `approvals-presence-keys`). A file that is there but not
    /// root's, or that others can write, is ignored by the secrets service, so root's setting does not hold: that fails the
    /// test (phase 2 re-check NL9). Empty off a box; absent files are fine (the setting is its default).
    pub approval_flag_files: Vec<PathBuf>,
    /// The dashboard user's socket to this daemon, set only on a box that has a dashboard user.
    pub dashboard_socket: Option<DashboardSocket>,
    /// The cgroup root (`/sys/fs/cgroup`) to look for the box user's manager under, to check it has the memory and cpu
    /// controllers delegated (runs are units of that manager, ADR 0038, and their limits only hold with them). `None` off
    /// a box, and for a box whose runs are cgroup scopes under the daemon.
    pub user_cgroup_root: Option<PathBuf>,
    /// The way runs go now, when this daemon can have them survive its own restart (set per self-test from the backend
    /// switch). `None` off a box.
    pub run_backend: Option<RunBackendNow>,
    /// The box user's home on /work: its owner is the box user, whose manager is looked for.
    pub user_home: PathBuf,
}

/// What the self-test needs to say whether the dashboard's own socket is there.
#[derive(Debug, Clone)]
pub struct DashboardSocket {
    pub path: PathBuf,
    /// Did systemd hand this daemon the descriptor? Without it the daemon serves nothing on that socket, whatever the file says.
    pub handed_over: bool,
    /// Is the socket's systemd unit installed? Only the box's `ozbox` program writes it. A new daemon beside an older program
    /// has none, and its old dashboard still reaches it through the box group, so that is not a failure (G1 F3).
    pub unit_present: bool,
}

/// Where the socket unit is written.
pub const DASHBOARD_SOCKET_UNIT: &str = "/etc/systemd/system/ozboxd-supervisor.socket";

/// Where systemd binds the dashboard user's socket.
pub const DASHBOARD_SOCKET_PATH: &str = "/run/ozbox-supervisor-api/daemon.sock";

/// The dashboard's socket is up: handed to this daemon and present. The box user cannot connect to it (that is the point), so
/// this checks the descriptor the daemon holds and the file's presence, never a connection.
pub fn dashboard_socket_check(d: &DashboardSocket) -> Check {
    if !d.handed_over && !d.unit_present {
        return Check {
            name: "dashboard_socket".into(),
            outcome: Outcome::Unknown {
                reason: "this box's `ozbox` program predates the dashboard's socket, so no socket unit was made; upgrade the program from your computer (ozbox upgrade)".into(),
            },
        };
    }
    if !d.handed_over {
        return fail(
            "dashboard_socket",
            "socket activation",
            "the dashboard's socket unit is installed, but systemd did not hand the daemon its socket, so the dashboard cannot reach the daemon. Run: ozbox admin <box> -- ensure-supervisor (it stops the daemon, starts the socket, then starts the daemon)",
        );
    }
    if !d.path.exists() {
        return fail(
            "dashboard_socket",
            "socket file",
            format!(
                "the dashboard's socket {} is missing; run: ozbox admin <box> -- ensure-supervisor",
                d.path.display()
            ),
        );
    }
    pass("dashboard_socket")
}

/// Where root's approval setting files are on a box.
pub const APPROVAL_FLAG_FILES: &[&str] = &[
    "/etc/ozbox/approvals-legacy-codes-off",
    "/etc/ozbox/approvals-presence-keys",
];

/// Where the secrets service writes its state.
pub const SECRETS_STATE_FILE: &str = "/run/ozbox-secrets/state";

/// What the service writes at the end of its state's first line when it has used up its tries in this round and exits to be
/// started again (`ozbox-cli`'s `secrets_cli`), against `(trying again in N s)` while it is still retrying.
const SERVICE_GAVE_UP: &str = "(starting again)";

/// How long a box set up for KMS may stay not ready before the self-test calls it failed, counted from the `failing_since` line
/// the service keeps across its restarts. The service says `(starting again)` only for the few seconds between giving up and
/// the unit starting it, so the phrase alone would read as unknown nearly all of a long outage. Not a figure to tune lightly:
/// a key service that is only slow to answer must not fail a box.
pub const PERSISTENT_FAILURE_SECS: u64 = 180;

/// Whether a not-ready KMS service has failed for good: for `PERSISTENT_FAILURE_SECS` when it says since when, else (an older
/// service) when it has just given up its tries.
fn kms_failure_has_lasted(first: &str, failing_since: Option<u64>, now_ms: u64) -> bool {
    match failing_since {
        Some(since) => (now_ms / 1000).saturating_sub(since) >= PERSISTENT_FAILURE_SECS,
        None => first.ends_with(SERVICE_GAVE_UP),
    }
}

/// Whether the secrets service can use the key that protects its store, from the state file it writes (the first line is for a
/// person, `kek=` names the key's kind, `code=` says why not).
///
/// * Ready passes.
/// * Not ready for good (`code=` config, no-escrow or kind-mismatch) fails, and says what to do about THAT: a lost or
///   mismatched store is mended with `recover-secrets` or `adopt-fleet-key`, never by looking at IAM or the network.
/// * Not ready on a KMS key because the key service did not answer fails only once the service has used up its tries
///   (`(starting again)`) or, when it says since when (`failing_since=`, kept across its restarts), has been failing for
///   `PERSISTENT_FAILURE_SECS`; sooner than that (`(trying again in N s)`) it is `unknown`, as is any other kind of key that is
///   not ready. An older service that writes no `failing_since` is judged by the phrase alone.
/// * No state file: `None` on a box with no secrets service (its folder is absent); `unknown` when the folder is there but the
///   file is not (the service has not written one yet, or could not be read), never skipped.
fn secrets_key_check(host: &dyn HostSource, path: &Path, now_ms: u64) -> Option<Check> {
    const NAME: &str = "secrets_key_usable";
    let text = match host.read(&path.to_string_lossy()) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if !path.parent().is_some_and(Path::exists) {
                return None;
            }
            return Some(unknown(
                NAME,
                "the secrets service has not written its state yet (it may still be starting), so whether it can use its key is not known. If this stays, restart ozbox-secrets.service; `ozbox admin <box> -- collect-logs` shows more",
            ));
        }
        Err(_) => {
            return Some(unknown(
                NAME,
                "the secrets service's state could not be read, so whether it can use its key is not known",
            ))
        }
    };
    let first = text.lines().next().unwrap_or("").trim();
    let field = |name: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(name))
            .map(str::trim)
    };
    let kek =
        field("kek=").filter(|k| matches!(*k, "kms" | "tpm2" | "keychain" | "passphrase" | "file"));
    let code = field("code=");
    let failing_since = field("failing_since=").and_then(|v| v.parse::<u64>().ok());
    if first == "ready" || first.starts_with("ready:") {
        return Some(pass(NAME));
    }
    // the first line is the service's own fixed sentence; keep it short and on one line
    let why: String = first.chars().take(300).collect();
    Some(match (code, kek) {
        (Some("no-escrow" | "kind-mismatch"), _) => fail(
            NAME,
            "the secrets service's state",
            format!(
                "the secrets service cannot open its store, and nothing on this box can: it was sealed by a key that is gone. The service says: {why}. This is not a role or network problem. Put the key back if you still have a copy, then run `ozbox adopt-fleet-key <box>` on your computer; if there is no copy, `ozbox admin <box> -- recover-secrets` sets the store aside for a new one (the old secrets are lost)"
            ),
        ),
        (Some("config"), _) => fail(
            NAME,
            "the secrets service's state",
            format!(
                "the secrets service is not configured, so no secret can be read or saved. The service says: {why}. Check `/etc/ozbox/secrets.env` names the key, then restart ozbox-secrets.service"
            ),
        ),
        (_, Some("kms")) if kms_failure_has_lasted(first, failing_since, now_ms) => fail(
            NAME,
            "the secrets service's state",
            format!(
                "this box is set up for the fleet's KMS key and the secrets service cannot use it, so no secret can be read or saved. The service says: {why}. Check that the box's role may use the key (the key service refuses a role whose tag or policy does not match), that the key service is reachable from the box, and the box's `/etc/ozbox/secrets.env` names the right key; then restart ozbox-secrets.service. `ozbox admin <box> -- collect-logs` shows more"
            ),
        ),
        (_, other) => Check {
            name: NAME.into(),
            outcome: Outcome::Unknown {
                reason: format!(
                    "the secrets service is not ready yet and is still trying (key kind: {}): {why}. If this stays, check the box's role and the key service, and `ozbox admin <box> -- collect-logs`",
                    other.unwrap_or("not said")
                ),
            },
        },
    })
}

/// Where the box user's secrets-service sockets are on a box.
pub const BOX_USER_SECRETS_SOCKETS: &[&str] = &[
    "/run/ozbox-secrets/box/box.sock",
    "/run/ozbox-secrets/broker/broker.sock",
    "/run/ozbox-secrets/import/import.sock",
];

impl SelfTestConfig {
    pub fn new(work_dir: impl Into<PathBuf>) -> Self {
        let work_dir: PathBuf = work_dir.into();
        Self {
            probe_dir: work_dir.join(".ozbox"),
            user_wants_dir: work_dir.join("home/ozbox/.config/systemd/user/default.target.wants"),
            require_mount: true,
            min_free_bytes: 1 << 30,
            tools: vec!["git".into(), "sh".into(), "sync".into()],
            work_encrypted: "unknown".into(),
            tunnel_units: Vec::new(),
            secrets_sockets: Vec::new(),
            secrets_state_file: None,
            approval_flag_files: Vec::new(),
            dashboard_socket: None,
            user_cgroup_root: None,
            run_backend: None,
            user_home: work_dir.join("home/ozbox"),
            work_dir,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Outcome {
    Pass,
    Fail {
        step: String,
        reason: String,
    },
    /// Could not be verified from inside the box. Never reported as a pass.
    Unknown {
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Check {
    pub name: String,
    #[serde(flatten)]
    pub outcome: Outcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SelfTestResult {
    pub ts_ms: u64,
    /// No check failed.
    pub ok: bool,
    /// Every check was positively verified (no `unknown`).
    pub all_verified: bool,
    pub checks: Vec<Check>,
}

fn pass(name: &str) -> Check {
    Check {
        name: name.into(),
        outcome: Outcome::Pass,
    }
}

fn fail(name: &str, step: &str, reason: impl Into<String>) -> Check {
    Check {
        name: name.into(),
        outcome: Outcome::Fail {
            step: step.into(),
            reason: reason.into(),
        },
    }
}

fn unknown(name: &str, reason: impl Into<String>) -> Check {
    Check {
        name: name.into(),
        outcome: Outcome::Unknown {
            reason: reason.into(),
        },
    }
}

fn find_tool(name: &str, path_env: &str) -> bool {
    if name.contains('/') {
        return false;
    }
    std::env::split_paths(path_env).any(|d| is_executable(&d.join(name)))
}

#[cfg(unix)]
fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(p)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(p: &Path) -> bool {
    p.is_file()
}

/// Whether an enabled unit that is not `active` is nevertheless healthy: a `Type=oneshot` that ran and exited successfully
/// (`Result=success`, exit status 0), or a unit whose start condition was not met (`ConditionResult=no`, with no failure
/// recorded). The properties come from one `systemctl --user show -p …` of the box user's own manager. Anything else, a
/// long-running service that is not running, a failed run, or an answer that cannot be read, is not healthy.
fn finished_or_skipped(unit: &str, uid: Option<u32>, runner: &dyn CommandRunner) -> bool {
    let mut spec = CommandSpec::new("systemctl").args([
        "--user",
        "show",
        "-p",
        "Type,Result,ActiveState,SubState,ConditionResult,ExecMainStatus",
        "--",
        unit,
    ]);
    if let Some(uid) = uid {
        let run = format!("/run/user/{uid}");
        spec = spec
            .env("XDG_RUNTIME_DIR", run.clone())
            .env("DBUS_SESSION_BUS_ADDRESS", format!("unix:path={run}/bus"));
    }
    let Ok(out) = runner.run(&spec) else {
        return false;
    };
    let prop = |key: &str| -> Option<&str> {
        out.stdout
            .lines()
            .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
            .map(str::trim)
    };
    // a unit that is up, or on its way, or failed, is not "finished"
    if prop("ActiveState") != Some("inactive") || prop("Result") != Some("success") {
        return false;
    }
    let ran_ok = prop("Type") == Some("oneshot") && prop("ExecMainStatus") == Some("0");
    ran_ok || prop("ConditionResult") == Some("no")
}

/// The units enabled for the box user (names in `default.target.wants`) that are not active. A unit that is enabled and
/// not running is the symptom of a user manager that started before its home was mounted.
///
/// A pass means each unit was asked about, by name, of the box user's own manager, and each answered `active`. The
/// daemon is a system service with no session, so the manager is reached explicitly at `/run/user/<uid>` (the uid is the
/// owner of the folder the units are enabled in: that user's manager is the one that starts them). A folder that cannot
/// be read is `unknown`, never a pass; a manager that cannot be reached at all fails with that said plainly.
fn user_services_check(wants: &Path, runner: &dyn CommandRunner) -> Check {
    const NAME: &str = "user_services_active";
    let rd = match fs::read_dir(wants) {
        Ok(rd) => rd,
        // nothing enabled for the box user: nothing to check
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return pass(NAME),
        Err(e) => {
            return unknown(
                NAME,
                format!(
                    "the box user's enabled services could not be listed ({}): {}",
                    wants.display(),
                    e.kind()
                ),
            )
        }
    };
    let mut units: Vec<(String, bool)> = rd
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let unit =
                name.ends_with(".service") || name.ends_with(".path") || name.ends_with(".timer");
            // a link whose unit file is gone can never start
            unit.then(|| (name, fs::metadata(e.path()).is_ok()))
        })
        .collect();
    units.sort();
    if units.is_empty() {
        return pass(NAME);
    }
    let broken: Vec<&str> = units
        .iter()
        .filter(|(_, ok)| !ok)
        .map(|(n, _)| n.as_str())
        .collect();
    let names: Vec<&str> = units.iter().map(|(n, _)| n.as_str()).collect();
    let mut spec = CommandSpec::new("systemctl")
        .args(["--user", "is-active", "--"])
        .args(names.iter().copied());
    if let Some(uid) = owner_uid(wants) {
        let run = format!("/run/user/{uid}");
        spec = spec
            .env("XDG_RUNTIME_DIR", run.clone())
            .env("DBUS_SESSION_BUS_ADDRESS", format!("unix:path={run}/bus"));
    }
    let answer = runner.run(&spec).ok();
    let states: Vec<String> = answer
        .as_ref()
        .map(|o| o.stdout.lines().map(|l| l.trim().to_string()).collect())
        .unwrap_or_default();
    if states.len() != names.len() {
        // no line per unit: the manager did not answer (not running, or its bus is not there)
        return fail(
            NAME,
            "systemctl --user is-active",
            format!(
                "the box user's service manager did not answer, so none of its enabled services can be running ({}). It may have started before /work was mounted, or not at all: run `ozbox admin <box> -- enable-linger`, which starts it once with its home",
                names.join(", ")
            ),
        );
    }
    // A unit that is not active is asked about once more, for the properties that say WHY. Inactive is the right state for a
    // one-time service that ran and finished, or whose start condition was not met (nothing to do): never read from `status` text.
    let down: Vec<String> = names
        .iter()
        .zip(&states)
        .filter(|(_, s)| s.as_str() != "active")
        .filter(|(n, _)| !finished_or_skipped(n, owner_uid(wants), runner))
        .map(|(n, s)| format!("{n} ({s})"))
        .collect();
    if down.is_empty() && broken.is_empty() {
        return pass(NAME);
    }
    let mut why = Vec::new();
    if !down.is_empty() {
        why.push(format!("enabled but not running: {}", down.join(", ")));
    }
    if !broken.is_empty() {
        why.push(format!(
            "enabled, but the unit file is missing: {}",
            broken.join(", ")
        ));
    }
    fail(
        NAME,
        "systemctl --user is-active",
        format!(
            "{}. If the box user's manager started before /work was mounted it starts none of them: run `ozbox admin <box> -- enable-linger` once, and check that user@.service waits for /work",
            why.join("; ")
        ),
    )
}

/// Whether the box user's own manager has the controllers runs need (memory and cpu) delegated to it. A run's `MemoryMax`
/// and `CPUWeight` are properties of a unit of that manager, and a controller it was not given silently does nothing: a
/// run with a memory cap would have none. Read from the manager's cgroup (`cgroup.controllers`), which is what the
/// kernel says it can hand to its units, not from what a drop-in asked for.
fn user_manager_delegation_check(root: &Path, home: &Path) -> Check {
    const NAME: &str = "user_manager_delegation";
    let Some(uid) = owner_uid(home) else {
        return unknown(
            NAME,
            format!(
                "the box user could not be identified from {}, so its manager's controllers were not looked at",
                home.display()
            ),
        );
    };
    // what the kernel hands the units themselves: the cgroup they land in (`app.slice`), or the manager's own until it exists
    let manager = crate::runs::user_manager_cgroup(root, uid);
    let read = fs::read_to_string(manager.join("app.slice/cgroup.controllers")).or_else(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            fs::read_to_string(manager.join("cgroup.controllers"))
        } else {
            Err(e)
        }
    });
    match read {
        Ok(text) => {
            let missing = crate::runs::missing_run_controllers(&text);
            if missing.is_empty() {
                return pass(NAME);
            }
            fail(
                NAME,
                "read the box user's manager's cgroup.controllers",
                format!(
                    "the box user's service manager does not have {} delegated, so the memory and cpu limits of a run in a unit would not hold and runs use cgroup scopes, which end when the daemon restarts. The memory guard's drop-in /etc/systemd/system/user@.service.d/10-ozbox-memory.conf (Delegate=pids memory cpu) is missing or not loaded yet: run `ozbox admin <box> -- host-guard memory install`, and restart the box when it is idle (restarting user@{uid}.service alone would stop the box user's own services, such as the web IDE and its terminals)",
                    missing.join(" and ")
                ),
            )
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => fail(
            NAME,
            "read the box user's manager's cgroup.controllers",
            format!(
                "the box user's service manager is not running (no cgroup for user@{uid}.service), so runs have nowhere to live: run `ozbox admin <box> -- enable-linger`"
            ),
        ),
        Err(e) => unknown(
            NAME,
            format!(
                "the box user's manager's controllers could not be read: {}",
                e.kind()
            ),
        ),
    }
}

/// The way runs go now. A box whose runs are cgroup scopes is working, so this is never a failure, but it is never a pass
/// either: a person about to restart the daemon (a live update does) must see that the runs would end with it.
fn run_backend_check(now: &RunBackendNow) -> Check {
    const NAME: &str = "run_backend";
    if now.units {
        return pass(NAME);
    }
    unknown(
        NAME,
        format!(
            "runs are cgroup scopes under the daemon, so restarting the daemon ends every run that is going ({}). Runs that start after the box user's manager is ready use units, which outlive a restart",
            now.why.as_deref().unwrap_or("no reason was given")
        ),
    )
}

#[cfg(unix)]
fn owner_uid(p: &Path) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(p).ok().map(|m| m.uid())
}

#[cfg(not(unix))]
fn owner_uid(_: &Path) -> Option<u32> {
    None
}

/// `None` when no setting file is there (every setting is at its default); a pass when each one is a plain file owned by root
/// that no one else can write; a failure naming the file otherwise, because the service ignores it.
#[cfg(unix)]
fn approval_flags_check(files: &[PathBuf]) -> Option<Check> {
    use std::os::unix::fs::MetadataExt;
    let mut any = false;
    let mut bad = Vec::new();
    for f in files {
        if let Ok(m) = fs::symlink_metadata(f) {
            any = true;
            if !(m.is_file() && m.uid() == 0 && m.mode() & 0o022 == 0) {
                bad.push(f.display().to_string());
            }
        }
    }
    if !any {
        return None;
    }
    Some(if bad.is_empty() {
        pass("approval_settings_trusted")
    } else {
        fail(
            "approval_settings_trusted",
            "owner and mode of root's approval setting files",
            format!(
                "ignored by the secrets service until fixed (they must be plain files owned by root that no one else can write): {}",
                bad.join(", ")
            ),
        )
    })
}

#[cfg(not(unix))]
fn approval_flags_check(_: &[PathBuf]) -> Option<Check> {
    None
}

/// Whether this user can connect to each of the secrets service's sockets. A connection is opened and closed; nothing is
/// sent. Refused, or not there while its directory is, fails the check, naming the socket.
#[cfg(unix)]
fn secrets_sockets_check(sockets: &[PathBuf]) -> Option<Check> {
    use std::os::unix::net::UnixStream;
    let present: Vec<&PathBuf> = sockets
        .iter()
        .filter(|s| s.parent().is_some_and(Path::exists))
        .collect();
    if present.is_empty() {
        return None;
    }
    let bad: Vec<String> = present
        .iter()
        .filter_map(|s| match UnixStream::connect(s) {
            Ok(_) => None,
            Err(e) => Some(format!("{} ({})", s.display(), e.kind())),
        })
        .collect();
    Some(if bad.is_empty() {
        pass("secrets_sockets_reachable")
    } else {
        fail(
            "secrets_sockets_reachable",
            "connect as the box user",
            format!(
                "cannot connect: {}. Each socket must be in its directory's group with mode 0660; restart ozbox-secrets.service, and if this stays, `ozbox admin <box> -- collect-logs` shows why",
                bad.join(", ")
            ),
        )
    })
}

#[cfg(not(unix))]
fn secrets_sockets_check(_: &[PathBuf]) -> Option<Check> {
    None
}

/// The memory guard (ADR 0045), from `/proc/swaps` and `/proc/pressure/memory`. A swap on a disk FAILS: a page of the secrets
/// service could reach it. No compressed swap is `unknown` (a box not yet upgraded, or a kernel without zram), never a pass.
/// Sustained stalls (a 60-second average over the failing line) fail it: the box works, but is starved. `None` off a machine
/// that exposes neither file.
fn memory_guard_check(host: &dyn HostSource) -> Option<Check> {
    use ozbox_core::memory_plan::{psi_value, swap_devices, PSI_SOME_AVG60_FAIL};
    const NAME: &str = "memory_guard";
    let swaps = host.read("/proc/swaps").ok()?;
    let (zram, other) = swap_devices(&swaps);
    if !other.is_empty() {
        return Some(fail(
            NAME,
            "read /proc/swaps",
            format!(
                "swap is on a disk ({}): a page of the secrets service could reach it. Turn it off with swapoff and remove it; this box's swap is compressed RAM only",
                other.join(", ")
            ),
        ));
    }
    if let Some(p) = host
        .read("/proc/pressure/memory")
        .ok()
        .and_then(|t| psi_value(&t, "some", "avg60"))
    {
        if p >= PSI_SOME_AVG60_FAIL {
            return Some(fail(
                NAME,
                "read /proc/pressure/memory",
                format!(
                    "the box has been stalling on memory ({p:.0}% of the last minute): stop a heavy job, run it with `ozbox capped -- <command>`, or use a bigger size"
                ),
            ));
        }
    }
    if zram.is_empty() {
        return Some(unknown(
            NAME,
            "no compressed swap: the memory guard is not on this box yet (`ozbox upgrade` puts it there, with nothing restarted), or its kernel has no zram module. Without it, a job that fills the memory makes the kernel kill a terminal",
        ));
    }
    Some(pass(NAME))
}

/// Run every check. `sample_run` starts a trivial run in a cgroup and reports whether it worked.
pub fn run(
    cfg: &SelfTestConfig,
    host: &dyn HostSource,
    runner: &dyn CommandRunner,
    path_env: &str,
    sample_run: &dyn Fn() -> Result<(), String>,
    now_ms: u64,
) -> SelfTestResult {
    let mut checks = Vec::new();

    // work mounted
    if cfg.require_mount {
        let want = cfg.work_dir.to_string_lossy();
        checks.push(match host.read("/proc/mounts") {
            Ok(t)
                if parse::parse_mounts(&t)
                    .iter()
                    .any(|(mp, _)| mp.as_str() == want) =>
            {
                pass("work_mounted")
            }
            Ok(_) => fail(
                "work_mounted",
                "mount",
                format!("{want} is not a mount point"),
            ),
            Err(e) => fail("work_mounted", "read mounts", e.kind().to_string()),
        });
    }

    // work writable (probe file, written, fsynced, read back, removed). The probe goes in the daemon's own state
    // directory on /work: /work itself is root-owned by design, and the daemon runs as the box user.
    let probe = cfg
        .probe_dir
        .join(format!(".ozbox-selftest-{}", std::process::id()));
    let wrote = (|| -> std::io::Result<()> {
        let mut f = fs::File::create(&probe)?;
        f.write_all(b"ok")?;
        f.sync_all()?;
        if fs::read(&probe)? != b"ok" {
            return Err(std::io::Error::other("read-back differs"));
        }
        Ok(())
    })();
    let _ = fs::remove_file(&probe);
    checks.push(match wrote {
        Ok(()) => pass("work_writable"),
        Err(e) => fail("work_writable", "probe file", e.to_string()),
    });

    // disk headroom
    checks.push(match host.disk_space(&cfg.work_dir) {
        Ok(d) if d.free_bytes >= cfg.min_free_bytes => pass("disk_headroom"),
        Ok(d) => fail(
            "disk_headroom",
            "free space",
            format!(
                "{} MiB free, need {} MiB",
                d.free_bytes >> 20,
                cfg.min_free_bytes >> 20
            ),
        ),
        Err(e) => fail("disk_headroom", "statvfs", e.kind().to_string()),
    });

    // the filesystem fills its disk (a grown disk is followed by a filesystem grow within a minute)
    checks.push(match growfs::observe(host, &cfg.work_dir) {
        Ok(o) if growfs::fills_disk(&o) => pass("filesystem_fills_disk"),
        Ok(o) => fail(
            "filesystem_fills_disk",
            "filesystem grow",
            format!(
                "the disk is {} MiB but the filesystem only {} MiB; it grows by itself within a minute of a disk resize, \
                 so check the ozbox-growfs service if this stays",
                o.device_bytes >> 20,
                o.fs_bytes >> 20
            ),
        ),
        Err(e) => unknown("filesystem_fills_disk", e.to_string()),
    });

    // tools
    let missing: Vec<&str> = cfg
        .tools
        .iter()
        .map(String::as_str)
        .filter(|t| !find_tool(t, path_env))
        .collect();
    checks.push(if missing.is_empty() {
        pass("tools_present")
    } else {
        fail(
            "tools_present",
            "PATH lookup",
            format!("missing: {}", missing.join(", ")),
        )
    });

    // /work encrypted: verified only when the device sits on a dm-crypt layer; otherwise report what is known.
    let mounts = host.read("/proc/mounts").unwrap_or_default();
    let work = cfg.work_dir.to_string_lossy();
    let verified_crypt = parse::parse_mount_source(&mounts, &work)
        .filter(|d| d.starts_with('/'))
        .and_then(|dev| {
            runner
                .run_ok(&CommandSpec::new("lsblk").args(["-s", "-n", "-o", "TYPE", dev.as_str()]))
                .ok()
        })
        .is_some_and(|o| o.stdout.lines().any(|l| l.trim() == "crypt"));
    checks.push(if verified_crypt {
        pass("work_encrypted")
    } else {
        match cfg.work_encrypted.as_str() {
            "true" => unknown(
                "work_encrypted",
                "the provider module declares the volume encrypted; this cannot be verified from inside the box",
            ),
            "false" => unknown("work_encrypted", "the provider module declares the volume is not encrypted"),
            _ => unknown("work_encrypted", "encryption of the work volume is not known"),
        }
    });

    // tunnels up
    checks.push(if cfg.tunnel_units.is_empty() {
        unknown("tunnels_up", "no tunnel units are configured")
    } else {
        let down: Vec<&str> = cfg
            .tunnel_units
            .iter()
            .map(String::as_str)
            .filter(|u| {
                !runner
                    .run(&CommandSpec::new("systemctl").args(["is-active", u]))
                    .map(|o| o.status == Some(0) && o.stdout.trim() == "active")
                    .unwrap_or(false)
            })
            .collect();
        if down.is_empty() {
            pass("tunnels_up")
        } else {
            fail(
                "tunnels_up",
                "systemctl is-active",
                format!("not active: {}", down.join(", ")),
            )
        }
    });

    // the box user's own services are up (the user manager can come up before /work is mounted and then start none)
    checks.push(user_services_check(&cfg.user_wants_dir, runner));

    // the box user's manager can hold a run's limits (runs are units of it)
    if let Some(root) = &cfg.user_cgroup_root {
        checks.push(user_manager_delegation_check(root, &cfg.user_home));
    }

    if let Some(now) = &cfg.run_backend {
        checks.push(run_backend_check(now));
    }

    // the secrets service's sockets answer this user (a socket in the wrong group answers nobody)
    if let Some(d) = &cfg.dashboard_socket {
        checks.push(dashboard_socket_check(d));
    }
    if let Some(c) = secrets_sockets_check(&cfg.secrets_sockets) {
        checks.push(c);
    }
    // ... and the key that protects the store can be used (a KMS key the box cannot reach leaves the service down)
    if let Some(c) = cfg
        .secrets_state_file
        .as_deref()
        .and_then(|p| secrets_key_check(host, p, now_ms))
    {
        checks.push(c);
    }

    // root's approval setting files, when there are any, are ones the service trusts
    if let Some(c) = approval_flags_check(&cfg.approval_flag_files) {
        checks.push(c);
    }

    // swap is compressed RAM and never a disk, and the box is not starving (ADR 0045)
    if let Some(c) = memory_guard_check(host) {
        checks.push(c);
    }

    // a sample run starts
    checks.push(match sample_run() {
        Ok(()) => pass("sample_run"),
        Err(e) => fail("sample_run", "start a run in a cgroup", e),
    });

    SelfTestResult {
        ts_ms: now_ms,
        ok: !checks
            .iter()
            .any(|c| matches!(c.outcome, Outcome::Fail { .. })),
        all_verified: checks.iter().all(|c| c.outcome == Outcome::Pass),
        checks,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::FakeHost;
    use ozbox_core::{Output, RecordingRunner};

    fn setup(dir: &Path) -> (SelfTestConfig, FakeHost) {
        let mut cfg = SelfTestConfig::new(dir);
        fs::create_dir_all(&cfg.probe_dir).unwrap();
        cfg.min_free_bytes = 100;
        cfg.tools = vec!["sh".into()];
        let h = FakeHost::default();
        h.set(
            "/proc/mounts",
            &format!("/dev/x {} ext4 rw 0 0\n", dir.display()),
        );
        h.set_disk(1000, 500);
        (cfg, h)
    }

    #[test]
    fn the_memory_guard_check_fails_on_a_swap_on_a_disk_and_on_a_starved_box_and_is_unknown_without_zram(
    ) {
        let d = tempfile::tempdir().unwrap();
        let (cfg, h) = setup(d.path());
        let by = |h: &FakeHost| {
            run(&cfg, h, &RecordingRunner::new(), "/bin", &|| Ok(()), 7)
                .checks
                .into_iter()
                .find(|c| c.name == "memory_guard")
                .map(|c| c.outcome)
        };
        // a machine that exposes no swap file: no check
        assert_eq!(by(&h), None);
        let head = "Filename\tType\tSize\tUsed\tPriority\n";
        h.set("/proc/swaps", head);
        assert!(
            matches!(by(&h), Some(Outcome::Unknown { reason }) if reason.contains("ozbox upgrade"))
        );
        h.set(
            "/proc/swaps",
            &format!("{head}/dev/zram0 partition 4194300 0 100\n"),
        );
        assert_eq!(by(&h), Some(Outcome::Pass));
        h.set("/proc/pressure/memory", "some avg10=1.00 avg60=2.00 avg300=1.00 total=1\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n");
        assert_eq!(by(&h), Some(Outcome::Pass));
        // starved for most of the last minute
        h.set(
            "/proc/pressure/memory",
            "some avg10=80.00 avg60=40.00 avg300=1.00 total=1\n",
        );
        assert!(
            matches!(by(&h), Some(Outcome::Fail { reason, .. }) if reason.contains("ozbox capped"))
        );
        // a swap on a disk is the worst finding, whatever else is true
        h.set(
            "/proc/pressure/memory",
            "some avg10=0.00 avg60=0.00 avg300=0.00 total=1\n",
        );
        h.set(
            "/proc/swaps",
            &format!("{head}/dev/zram0 partition 1 0 100\n/swapfile file 1024 0 -2\n"),
        );
        assert!(
            matches!(by(&h), Some(Outcome::Fail { reason, .. }) if reason.contains("/swapfile") && reason.contains("secrets service"))
        );
    }

    /// a box with a dashboard user whose daemon was not handed the dashboard's socket is not healthy, and the
    /// self-test says so (it cannot connect to it itself: the box user is not allowed to).
    #[test]
    fn a_box_with_a_dashboard_user_must_have_its_socket_handed_to_the_daemon() {
        let d = tempfile::tempdir().unwrap();
        let (mut cfg, h) = setup(d.path());
        let sock = d.path().join("daemon.sock");
        fs::write(&sock, "").unwrap();
        let find = |cfg: &SelfTestConfig| {
            run(
                cfg,
                &h,
                &RecordingRunner::new(),
                "/bin:/usr/bin",
                &|| Ok(()),
                1,
            )
            .checks
            .into_iter()
            .find(|c| c.name == "dashboard_socket")
        };
        // no dashboard user: no check at all
        assert!(find(&cfg).is_none());
        cfg.dashboard_socket = Some(DashboardSocket {
            path: sock.clone(),
            handed_over: true,
            unit_present: true,
        });
        assert_eq!(find(&cfg).map(|c| c.outcome), Some(Outcome::Pass));
        cfg.dashboard_socket = Some(DashboardSocket {
            path: sock.clone(),
            handed_over: false,
            unit_present: true,
        });
        assert!(
            matches!(find(&cfg).map(|c| c.outcome), Some(Outcome::Fail { reason, .. }) if reason.contains("ensure-supervisor"))
        );
        // F3: no socket unit (an older program beside this daemon) is a warning that says to upgrade, never a failure
        cfg.dashboard_socket = Some(DashboardSocket {
            path: sock.clone(),
            handed_over: false,
            unit_present: false,
        });
        assert!(
            matches!(find(&cfg).map(|c| c.outcome), Some(Outcome::Unknown { reason }) if reason.contains("predates"))
        );
        cfg.dashboard_socket = Some(DashboardSocket {
            path: d.path().join("gone.sock"),
            handed_over: true,
            unit_present: true,
        });
        assert!(
            matches!(find(&cfg).map(|c| c.outcome), Some(Outcome::Fail { reason, .. }) if reason.contains("missing"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_root_approval_setting_file_the_service_would_ignore_fails_the_test() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let (mut cfg, h) = setup(d.path());
        let f = d.path().join("approvals-legacy-codes-off");
        let find = |cfg: &SelfTestConfig| {
            run(
                cfg,
                &h,
                &RecordingRunner::new(),
                "/bin:/usr/bin",
                &|| Ok(()),
                1,
            )
            .checks
            .into_iter()
            .find(|c| c.name == "approval_settings_trusted")
        };
        cfg.approval_flag_files = vec![f.clone()];
        // no file: the setting is its default, and there is nothing to check
        assert!(find(&cfg).is_none());
        // a file others can write is ignored by the service: the test fails and names it
        fs::write(&f, "").unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o666)).unwrap();
        match find(&cfg).map(|c| c.outcome) {
            Some(Outcome::Fail { reason, .. }) => {
                assert!(reason.contains("approvals-legacy-codes-off"), "{reason}")
            }
            o => panic!("{o:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn the_box_user_must_be_able_to_reach_each_secrets_socket() {
        let d = tempfile::tempdir().unwrap();
        let (mut cfg, h) = setup(d.path());
        let ok = d.path().join("box/box.sock");
        fs::create_dir_all(ok.parent().unwrap()).unwrap();
        let _l = std::os::unix::net::UnixListener::bind(&ok).unwrap();
        // a directory with no socket: the service is not answering there
        let gone = d.path().join("import/import.sock");
        fs::create_dir_all(gone.parent().unwrap()).unwrap();
        // no directory at all: a box without the service, skipped
        let absent = d.path().join("nope/broker.sock");
        let check = |socks: Vec<PathBuf>, cfg: &mut SelfTestConfig| {
            cfg.secrets_sockets = socks;
            run(
                cfg,
                &h,
                &RecordingRunner::new(),
                "/bin:/usr/bin",
                &|| Ok(()),
                1,
            )
            .checks
            .into_iter()
            .find(|c| c.name == "secrets_sockets_reachable")
        };
        assert_eq!(
            check(vec![ok.clone(), absent.clone()], &mut cfg).map(|c| c.outcome),
            Some(Outcome::Pass)
        );
        match check(vec![ok, gone.clone()], &mut cfg).map(|c| c.outcome) {
            Some(Outcome::Fail { reason, .. }) => {
                assert!(reason.contains(&gone.display().to_string()), "{reason}")
            }
            o => panic!("{o:?}"),
        }
        assert!(check(vec![absent], &mut cfg).is_none());
    }

    #[test]
    fn a_missing_state_file_is_unknown_where_the_service_has_a_folder_and_skipped_where_it_has_none(
    ) {
        let d = tempfile::tempdir().unwrap();
        let (_, h) = setup(d.path());
        // the service's runtime folder is there, its state file is not: not verified, never skipped
        match secrets_key_check(&h, &d.path().join("state"), 7).map(|c| c.outcome) {
            Some(Outcome::Unknown { reason }) => {
                assert!(reason.contains("not written"), "{reason}")
            }
            o => panic!("{o:?}"),
        }
        // no folder: a box without the service
        assert!(secrets_key_check(&h, &d.path().join("absent/state"), 7).is_none());
    }

    #[test]
    fn a_kms_box_whose_key_cannot_be_used_fails_the_self_test_in_words_to_act_on() {
        let d = tempfile::tempdir().unwrap();
        let (mut cfg, h) = setup(d.path());
        cfg.secrets_state_file = Some(PathBuf::from(SECRETS_STATE_FILE));
        let by = |h: &FakeHost| {
            run(&cfg, h, &RecordingRunner::new(), "/bin", &|| Ok(()), 7)
                .checks
                .into_iter()
                .find(|c| c.name == "secrets_key_usable")
                .map(|c| c.outcome)
        };
        // no state file: a box without the service
        assert_eq!(by(&h), None);
        h.set(SECRETS_STATE_FILE, "ready\nkek=kms\n");
        assert_eq!(by(&h), Some(Outcome::Pass));
        // still retrying (the service's own "(trying again in N s)"): unknown, never a fail and never a pass
        h.set(
            SECRETS_STATE_FILE,
            "not-ready: the key service could not be reached (trying again in 2 s)\nkek=kms\ncode=transient\n",
        );
        assert!(
            matches!(by(&h), Some(Outcome::Unknown { reason }) if reason.contains("still trying"))
        );
        // the service has used up its tries: now it fails, in words to act on
        h.set(
            SECRETS_STATE_FILE,
            "not-ready: the key that protects this machine's secrets is not available, so nothing was read or changed (check the key service or the keychain, then try again) (starting again)\nkek=kms\ncode=transient\n",
        );
        match by(&h) {
            Some(Outcome::Fail { reason, .. }) => {
                assert!(
                    reason.contains("KMS key") && reason.contains("not available"),
                    "{reason}"
                );
                assert!(
                    reason.contains("secrets.env") && reason.contains("collect-logs"),
                    "{reason}"
                );
            }
            o => panic!("{o:?}"),
        }
        // a store that cannot be opened for good points at the repair, not at IAM or the network
        for code in ["kind-mismatch", "no-escrow"] {
            h.set(
                SECRETS_STATE_FILE,
                &format!(
                    "not-ready: sealed by a key that is gone\nkek=kms\ncode={code}\nstore=file\n"
                ),
            );
            match by(&h) {
                Some(Outcome::Fail { reason, .. }) => {
                    assert!(
                        reason.contains("recover-secrets") && reason.contains("adopt-fleet-key"),
                        "{reason}"
                    );
                    assert!(
                        !reason.contains("role may use") && !reason.contains("reachable"),
                        "{reason}"
                    );
                }
                o => panic!("{o:?}"),
            }
        }
        h.set(
            SECRETS_STATE_FILE,
            "not-ready: no key\nkek=kms\ncode=config\n",
        );
        assert!(
            matches!(by(&h), Some(Outcome::Fail { reason, .. }) if reason.contains("secrets.env"))
        );
        // another kind of key that is not ready may only be starting: unknown, never a pass
        h.set(
            SECRETS_STATE_FILE,
            "not-ready: starting\nkek=file\ncode=transient\n",
        );
        assert!(matches!(by(&h), Some(Outcome::Unknown { reason }) if reason.contains("file")));
    }

    #[test]
    fn a_kms_failure_that_lasts_fails_across_restarts_whatever_phrase_the_state_is_in() {
        let d = tempfile::tempdir().unwrap();
        let (mut cfg, h) = setup(d.path());
        cfg.secrets_state_file = Some(PathBuf::from(SECRETS_STATE_FILE));
        let at = |h: &FakeHost, now_s: u64| {
            run(
                &cfg,
                h,
                &RecordingRunner::new(),
                "/bin",
                &|| Ok(()),
                now_s * 1000,
            )
            .checks
            .into_iter()
            .find(|c| c.name == "secrets_key_usable")
            .map(|c| c.outcome)
        };
        let since = 1_000_000u64;
        let state = |phrase: &str| {
            format!("not-ready: the key service could not be reached ({phrase})\nkek=kms\ncode=transient\nfailing_since={since}\n")
        };
        // under the threshold, in either phrase: unknown, never a fail
        for phrase in ["trying again in 2 s", "starting again"] {
            h.set(SECRETS_STATE_FILE, &state(phrase));
            assert!(
                matches!(
                    at(&h, since + PERSISTENT_FAILURE_SECS - 1),
                    Some(Outcome::Unknown { .. })
                ),
                "{phrase}"
            );
        }
        // past it, the unit alternating between its two phrases still fails (most of the time the phrase is "trying again")
        for phrase in [
            "trying again in 2 s",
            "trying again in 16 s",
            "starting again",
        ] {
            h.set(SECRETS_STATE_FILE, &state(phrase));
            match at(&h, since + PERSISTENT_FAILURE_SECS) {
                Some(Outcome::Fail { reason, .. }) => {
                    assert!(reason.contains("KMS key"), "{reason}")
                }
                o => panic!("{phrase}: {o:?}"),
            }
        }
        // ready clears it (the service leaves the line out)
        h.set(SECRETS_STATE_FILE, "ready\nkek=kms\n");
        assert_eq!(at(&h, since + 10_000), Some(Outcome::Pass));
        // an older service writes no failing_since: the phrase alone decides, as it always did
        h.set(
            SECRETS_STATE_FILE,
            "not-ready: x (trying again in 2 s)\nkek=kms\ncode=transient\n",
        );
        assert!(matches!(
            at(&h, since + 10_000),
            Some(Outcome::Unknown { .. })
        ));
        h.set(
            SECRETS_STATE_FILE,
            "not-ready: x (starting again)\nkek=kms\ncode=transient\n",
        );
        assert!(matches!(at(&h, 7), Some(Outcome::Fail { .. })));
        // a time in the future (a clock set back) is not a lasting failure
        h.set(SECRETS_STATE_FILE, &state("trying again in 2 s"));
        assert!(matches!(at(&h, since - 500), Some(Outcome::Unknown { .. })));
    }

    #[test]
    fn the_recovery_advice_names_the_real_adopt_command() {
        let d = tempfile::tempdir().unwrap();
        let (_, h) = setup(d.path());
        h.set(
            &d.path().join("state").to_string_lossy(),
            "not-ready: gone\nkek=kms\ncode=no-escrow\n",
        );
        match secrets_key_check(&h, &d.path().join("state"), 7).map(|c| c.outcome) {
            Some(Outcome::Fail { reason, .. }) => {
                assert!(reason.contains("`ozbox adopt-fleet-key <box>`"), "{reason}");
                assert!(
                    !reason.contains("admin <box> -- adopt-fleet-key"),
                    "{reason}"
                );
            }
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn all_pass() {
        let d = tempfile::tempdir().unwrap();
        let (cfg, h) = setup(d.path());
        let r = run(
            &cfg,
            &h,
            &RecordingRunner::new(),
            "/bin:/usr/bin",
            &|| Ok(()),
            7,
        );
        assert!(r.ok, "{r:?}");
        assert_eq!(r.checks.len(), 9);
        // encryption and tunnels cannot be verified with nothing configured: unknown, never pass
        assert!(!r.all_verified);
        let by = |n: &str| {
            r.checks
                .iter()
                .find(|c| c.name == n)
                .map(|c| c.outcome.clone())
        };
        assert!(matches!(
            by("work_encrypted"),
            Some(Outcome::Unknown { .. })
        ));
        assert!(matches!(by("tunnels_up"), Some(Outcome::Unknown { .. })));
        assert!(!d
            .path()
            .join(format!(".ozbox-selftest-{}", std::process::id()))
            .exists());
    }

    #[test]
    fn an_enabled_user_unit_that_is_not_running_fails_the_self_test_naming_it() {
        let d = tempfile::tempdir().unwrap();
        let (cfg, h) = setup(d.path());
        fs::create_dir_all(&cfg.user_wants_dir).unwrap();
        fs::write(cfg.user_wants_dir.join("ozbox-dashboard.service"), "").unwrap();
        let by = |r: &SelfTestResult| {
            r.checks
                .iter()
                .find(|c| c.name == "user_services_active")
                .map(|c| c.outcome.clone())
        };
        // the user manager reached its target before /work was mounted: nothing is active
        let down = run(&cfg, &h, &RecordingRunner::new(), "/bin", &|| Ok(()), 7);
        assert!(!down.ok);
        assert!(
            matches!(by(&down), Some(Outcome::Fail { reason, .. }) if reason.contains("ozbox-dashboard.service") && reason.contains("/work"))
        );
        // started: it passes
        let r = RecordingRunner::new();
        // the first command is the encryption check's lsblk
        r.reply(Output {
            status: Some(0),
            stdout: "disk\n".into(),
            stderr: String::new(),
        });
        r.reply(Output {
            status: Some(0),
            stdout: "active\n".into(),
            stderr: String::new(),
        });
        let up = run(&cfg, &h, &r, "/bin", &|| Ok(()), 7);
        assert_eq!(by(&up), Some(Outcome::Pass));
        // no enabled units at all is nothing to check
        fs::remove_dir_all(&cfg.user_wants_dir).unwrap();
        assert_eq!(
            by(&run(
                &cfg,
                &h,
                &RecordingRunner::new(),
                "/bin",
                &|| Ok(()),
                7
            )),
            Some(Outcome::Pass)
        );
    }

    /// What `systemctl --user show` says about a unit, as the self-test asks for it.
    fn shown(ty: &str, result: &str, active: &str, cond: &str, status: &str) -> String {
        format!("Type={ty}\nResult={result}\nActiveState={active}\nSubState=dead\nConditionResult={cond}\nExecMainStatus={status}\n")
    }

    #[test]
    fn an_enabled_unit_that_is_inactive_is_healthy_only_when_it_finished_or_had_nothing_to_do() {
        let d = tempfile::tempdir().unwrap();
        let (cfg, _h) = setup(d.path());
        let wants = &cfg.user_wants_dir;
        fs::create_dir_all(wants).unwrap();
        fs::write(wants.join("ozbox-session-resume.service"), "").unwrap();
        let check = |is_active: &str, show: &str| {
            let r = RecordingRunner::new();
            reply(&r, 3, is_active);
            reply(&r, 0, show);
            (user_services_check(wants, &r), r)
        };
        let name = "user_services_active";
        // active: no second question
        let (c, r) = check("active\n", "");
        assert_eq!(c, pass(name));
        assert_eq!(r.calls().len(), 1);
        // a one-time service that ran and exited 0 stays inactive; so does one whose condition was not met
        let (c, r) = check(
            "inactive\n",
            &shown("oneshot", "success", "inactive", "yes", "0"),
        );
        assert_eq!(c, pass(name), "{c:?}");
        let call = r.calls().pop().unwrap();
        assert_eq!(&call.args[..3], ["--user", "show", "-p"]);
        assert_eq!(
            call.args.last().map(String::as_str),
            Some("ozbox-session-resume.service")
        );
        let (c, _) = check(
            "inactive\n",
            &shown("oneshot", "success", "inactive", "no", "0"),
        );
        assert_eq!(c, pass(name), "{c:?}");
        let (c, _) = check(
            "inactive\n",
            &shown("simple", "success", "inactive", "no", "0"),
        );
        assert_eq!(c, pass(name), "{c:?}");
        // a failed run, a long-running service that is not running, and an answer that says nothing are failures
        for (why, show) in [
            (
                "exit-code",
                shown("oneshot", "exit-code", "inactive", "yes", "1"),
            ),
            (
                "failed active",
                shown("oneshot", "success", "failed", "yes", "0"),
            ),
            (
                "simple not running",
                shown("simple", "success", "inactive", "yes", "0"),
            ),
            (
                "condition but failed",
                shown("oneshot", "exit-code", "inactive", "no", "1"),
            ),
            (
                "oneshot status",
                shown("oneshot", "success", "inactive", "yes", "2"),
            ),
            ("empty", String::new()),
        ] {
            let (c, _) = check("inactive\n", &show);
            assert!(
                matches!(&c.outcome, Outcome::Fail { reason, .. } if reason.contains("ozbox-session-resume.service (inactive)") && reason.contains("enable-linger")),
                "{why}: {c:?}"
            );
        }
    }

    #[test]
    fn user_services_pass_only_when_the_box_users_own_manager_says_each_is_active() {
        let d = tempfile::tempdir().unwrap();
        let (cfg, _h) = setup(d.path());
        let wants = &cfg.user_wants_dir;
        fs::create_dir_all(wants).unwrap();
        for u in ["oz-cloudflared.service", "oz-code-server.service"] {
            fs::write(wants.join(u), "").unwrap();
        }
        // not a unit: ignored
        fs::write(wants.join("README"), "").unwrap();
        let r = RecordingRunner::new();
        reply(&r, 0, "active\nactive\n");
        assert_eq!(user_services_check(wants, &r), pass("user_services_active"));
        // the manager is asked by name, at the box user's own runtime folder (the daemon has no session of its own)
        let call = r.calls().pop().unwrap();
        assert_eq!(
            call.args,
            [
                "--user",
                "is-active",
                "--",
                "oz-cloudflared.service",
                "oz-code-server.service"
            ]
        );
        #[cfg(unix)]
        {
            let uid = owner_uid(wants).unwrap();
            assert_eq!(
                call.env.get("XDG_RUNTIME_DIR").map(String::as_str),
                Some(format!("/run/user/{uid}").as_str())
            );
        }
        // one is not running: it is named, with what the manager said
        let r = RecordingRunner::new();
        reply(&r, 3, "active\ninactive\n");
        let c = user_services_check(wants, &r);
        assert!(
            matches!(&c.outcome, Outcome::Fail { reason, .. } if reason.contains("oz-code-server.service (inactive)") && !reason.contains("oz-cloudflared.service (")),
            "{c:?}"
        );
        // the manager did not answer at all (not running, or started without its home and stopped)
        let r = RecordingRunner::new();
        r.reply(Output {
            status: Some(1),
            stdout: String::new(),
            stderr: "Failed to connect to bus: No such file or directory".into(),
        });
        let c = user_services_check(wants, &r);
        assert!(
            matches!(&c.outcome, Outcome::Fail { reason, .. } if reason.contains("did not answer") && reason.contains("enable-linger")),
            "{c:?}"
        );
        // a link to a unit file that is gone
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(d.path().join("gone.service"), wants.join("gone.service"))
                .unwrap();
            let r = RecordingRunner::new();
            reply(&r, 3, "active\ninactive\nactive\n");
            let c = user_services_check(wants, &r);
            assert!(
                matches!(&c.outcome, Outcome::Fail { reason, .. } if reason.contains("unit file is missing: gone.service")),
                "{c:?}"
            );
        }
    }

    #[cfg(unix)]
    /// A fake cgroup tree with the box user's manager at `user.slice/user-<uid>.slice/user@<uid>.service`.
    #[cfg(unix)]
    fn manager_cgroup(root: &Path, home: &Path, controllers: Option<&str>) {
        let uid = owner_uid(home).unwrap();
        let dir = crate::runs::user_manager_cgroup(root, uid);
        fs::create_dir_all(&dir).unwrap();
        if let Some(c) = controllers {
            fs::write(dir.join("cgroup.controllers"), c).unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn the_box_users_manager_must_have_memory_and_cpu_delegated_for_a_runs_limits_to_hold() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("cgroup");
        let home = d.path().join("home");
        fs::create_dir_all(&home).unwrap();
        const N: &str = "user_manager_delegation";
        // not running at all: there is no cgroup for it
        fs::create_dir_all(&root).unwrap();
        let c = user_manager_delegation_check(&root, &home);
        assert!(
            matches!(&c.outcome, Outcome::Fail { reason, .. } if reason.contains("not running") && reason.contains("enable-linger")),
            "{c:?}"
        );
        // running, with the controllers
        manager_cgroup(&root, &home, Some("cpuset cpu io memory pids\n"));
        assert_eq!(user_manager_delegation_check(&root, &home), pass(N));
        // running, without cpu (the stock default on an older systemd): fails and names the missing one and the fix
        manager_cgroup(&root, &home, Some("memory pids\n"));
        let c = user_manager_delegation_check(&root, &home);
        assert!(
            matches!(&c.outcome, Outcome::Fail { reason, .. } if reason.contains("does not have cpu delegated") && reason.contains("10-ozbox-memory.conf") && reason.contains("stop the box user's own services") && !reason.contains("have memory")),
            "{c:?}"
        );
        manager_cgroup(&root, &home, Some("pids\n"));
        let c = user_manager_delegation_check(&root, &home);
        assert!(
            matches!(&c.outcome, Outcome::Fail { reason, .. } if reason.contains("have memory and cpu")),
            "{c:?}"
        );
        // the box user cannot be identified: unknown, never a pass
        let c = user_manager_delegation_check(&root, &d.path().join("no-such-home"));
        assert!(matches!(c.outcome, Outcome::Unknown { .. }), "{c:?}");
        // the controllers file cannot be read (a folder where it should be): unknown
        let uid = owner_uid(&home).unwrap();
        let f = crate::runs::user_manager_cgroup(&root, uid).join("cgroup.controllers");
        fs::remove_file(&f).unwrap();
        fs::create_dir(&f).unwrap();
        assert!(matches!(
            user_manager_delegation_check(&root, &home).outcome,
            Outcome::Unknown { .. }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn the_delegation_check_reads_the_cgroup_the_units_land_in_before_the_managers_own() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("cgroup");
        let home = d.path().join("home");
        fs::create_dir_all(&home).unwrap();
        manager_cgroup(&root, &home, Some("cpu memory\n"));
        let uid = owner_uid(&home).unwrap();
        let slice = crate::runs::user_manager_cgroup(&root, uid).join("app.slice");
        fs::create_dir_all(&slice).unwrap();
        fs::write(slice.join("cgroup.controllers"), "cpu\n").unwrap();
        let c = user_manager_delegation_check(&root, &home);
        assert!(
            matches!(&c.outcome, Outcome::Fail { reason, .. } if reason.contains("does not have memory delegated")),
            "{c:?}"
        );
    }

    #[test]
    fn the_way_runs_go_is_reported_and_a_scope_fallback_is_never_a_pass_or_a_failure() {
        let up = run_backend_check(&RunBackendNow {
            units: true,
            why: None,
        });
        assert_eq!(up, pass("run_backend"));
        let down = run_backend_check(&RunBackendNow {
            units: false,
            why: Some("the box user's service manager is not running".into()),
        });
        assert!(
            matches!(&down.outcome, Outcome::Unknown { reason } if reason.contains("restarting the daemon ends every run") && reason.contains("not running")),
            "{down:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_delegation_check_is_part_of_the_self_test_only_when_asked_for() {
        let d = tempfile::tempdir().unwrap();
        let (mut cfg, h) = setup(d.path());
        let names =
            |r: &SelfTestResult| r.checks.iter().map(|c| c.name.clone()).collect::<Vec<_>>();
        let r = run(
            &cfg,
            &h,
            &RecordingRunner::new(),
            "/bin:/usr/bin",
            &|| Ok(()),
            7,
        );
        assert!(!names(&r).contains(&"user_manager_delegation".to_string()));
        let root = d.path().join("cgroup");
        fs::create_dir_all(&cfg.user_home).unwrap();
        manager_cgroup(&root, &cfg.user_home, Some("memory\n"));
        cfg.user_cgroup_root = Some(root);
        let r = run(
            &cfg,
            &h,
            &RecordingRunner::new(),
            "/bin:/usr/bin",
            &|| Ok(()),
            7,
        );
        assert!(!r.ok);
        let c = r
            .checks
            .iter()
            .find(|c| c.name == "user_manager_delegation")
            .unwrap();
        assert!(matches!(c.outcome, Outcome::Fail { .. }));
    }

    #[test]
    fn an_unreadable_list_of_user_services_is_unknown_never_a_pass() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let wants = d.path().join("wants");
        fs::create_dir_all(&wants).unwrap();
        fs::write(wants.join("a.service"), "").unwrap();
        fs::set_permissions(&wants, fs::Permissions::from_mode(0o000)).unwrap();
        let c = user_services_check(&wants, &RecordingRunner::new());
        fs::set_permissions(&wants, fs::Permissions::from_mode(0o755)).unwrap();
        // root reads it anyway (some CI containers), so only an ordinary user sees the refusal
        if !running_as_root() {
            assert!(matches!(c.outcome, Outcome::Unknown { .. }), "{c:?}");
        }
    }

    #[cfg(unix)]
    fn running_as_root() -> bool {
        std::process::Command::new("id")
            .arg("-u")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
            .unwrap_or(false)
    }

    #[test]
    fn each_failure_names_its_step() {
        let d = tempfile::tempdir().unwrap();
        let (mut cfg, h) = setup(d.path());
        h.set("/proc/mounts", "tmpfs /run tmpfs rw 0 0\n");
        h.set_disk(1000, 10);
        cfg.tools = vec!["definitely-not-a-tool".into()];
        let r = run(
            &cfg,
            &h,
            &RecordingRunner::new(),
            "/bin",
            &|| Err("cgroup not delegated".into()),
            7,
        );
        assert!(!r.ok);
        let by = |n: &str| {
            r.checks
                .iter()
                .find(|c| c.name == n)
                .map(|c| c.outcome.clone())
        };
        assert!(matches!(by("work_mounted"), Some(Outcome::Fail { step, .. }) if step == "mount"));
        assert!(
            matches!(by("disk_headroom"), Some(Outcome::Fail { reason, .. }) if reason.contains("need"))
        );
        assert!(
            matches!(by("tools_present"), Some(Outcome::Fail { reason, .. }) if reason.contains("definitely-not-a-tool"))
        );
        assert!(
            matches!(by("sample_run"), Some(Outcome::Fail { reason, .. }) if reason == "cgroup not delegated")
        );
        assert_eq!(by("work_writable"), Some(Outcome::Pass));
    }

    #[test]
    fn filesystem_must_fill_its_disk() {
        let d = tempfile::tempdir().unwrap();
        let (cfg, h) = setup(d.path());
        let find = |r: &SelfTestResult| {
            r.checks
                .iter()
                .find(|c| c.name == "filesystem_fills_disk")
                .map(|c| c.outcome.clone())
        };
        // nothing to read the disk size from: unknown, never a pass
        let r = run(&cfg, &h, &RecordingRunner::new(), "/bin", &|| Ok(()), 7);
        assert!(matches!(find(&r), Some(Outcome::Unknown { .. })));
        let gib: u64 = 1 << 30;
        h.set(
            "/proc/mounts",
            &format!("/dev/nvme1n1 {} ext4 rw 0 0\n", d.path().display()),
        );
        h.set(
            "/sys/class/block/nvme1n1/size",
            &format!("{}\n", 30 * gib / 512),
        );
        h.set_disk(19 * gib, gib);
        let r = run(&cfg, &h, &RecordingRunner::new(), "/bin", &|| Ok(()), 7);
        assert!(
            matches!(find(&r), Some(Outcome::Fail { reason, .. }) if reason.contains("grows by itself"))
        );
        assert!(!r.ok);
        h.set_disk(29 * gib, gib);
        let r = run(&cfg, &h, &RecordingRunner::new(), "/bin", &|| Ok(()), 7);
        assert_eq!(find(&r), Some(Outcome::Pass));
    }

    #[test]
    fn unwritable_work_dir_fails() {
        let d = tempfile::tempdir().unwrap();
        let (mut cfg, h) = setup(d.path());
        cfg.work_dir = d.path().join("does-not-exist");
        cfg.probe_dir = cfg.work_dir.join(".ozbox");
        cfg.require_mount = false;
        let r = run(&cfg, &h, &RecordingRunner::new(), "/bin", &|| Ok(()), 7);
        assert!(r
            .checks
            .iter()
            .any(|c| c.name == "work_writable" && matches!(c.outcome, Outcome::Fail { .. })));
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"outcome\":\"fail\"") && json.contains("\"step\""));
    }

    #[cfg(unix)]
    #[test]
    fn a_root_owned_work_top_level_still_passes_when_the_state_dir_is_writable() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let (mut cfg, h) = setup(d.path());
        let state = d.path().join(".ozbox");
        fs::create_dir_all(&state).unwrap();
        cfg.probe_dir = state.clone();
        // the top of /work is not writable by the daemon (root-owned on a real box)
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o555)).unwrap();
        let r = run(&cfg, &h, &RecordingRunner::new(), "/bin", &|| Ok(()), 7);
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let by = |n: &str| {
            r.checks
                .iter()
                .find(|c| c.name == n)
                .map(|c| c.outcome.clone())
        };
        assert_eq!(by("work_writable"), Some(Outcome::Pass));
    }

    fn reply(r: &RecordingRunner, status: i32, stdout: &str) {
        r.reply(Output {
            status: Some(status),
            stdout: stdout.into(),
            stderr: String::new(),
        });
    }

    #[test]
    fn encryption_is_pass_only_when_verified() {
        let d = tempfile::tempdir().unwrap();
        let (mut cfg, h) = setup(d.path());
        cfg.work_encrypted = "true".into();
        // declared only: unknown, and the reason says why
        let r = run(&cfg, &h, &RecordingRunner::new(), "/bin", &|| Ok(()), 7);
        let enc = r
            .checks
            .iter()
            .find(|c| c.name == "work_encrypted")
            .unwrap();
        assert!(
            matches!(&enc.outcome, Outcome::Unknown { reason } if reason.contains("cannot be verified"))
        );
        // a dm-crypt layer under the mount is verified
        let rec = RecordingRunner::new();
        reply(&rec, 0, "part\ncrypt\n");
        let r = run(&cfg, &h, &rec, "/bin", &|| Ok(()), 7);
        assert!(r
            .checks
            .iter()
            .any(|c| c.name == "work_encrypted" && c.outcome == Outcome::Pass));
        assert_eq!(rec.calls()[0].args, ["-s", "-n", "-o", "TYPE", "/dev/x"]);
        // declared unencrypted is reported, not hidden
        cfg.work_encrypted = "false".into();
        let r = run(&cfg, &h, &RecordingRunner::new(), "/bin", &|| Ok(()), 7);
        let enc = r
            .checks
            .iter()
            .find(|c| c.name == "work_encrypted")
            .unwrap();
        assert!(
            matches!(&enc.outcome, Outcome::Unknown { reason } if reason.contains("not encrypted"))
        );
    }

    #[test]
    fn tunnels_must_be_active() {
        let d = tempfile::tempdir().unwrap();
        let (mut cfg, h) = setup(d.path());
        cfg.tunnel_units = vec!["tunnel-a.service".into(), "tunnel-b.service".into()];
        let rec = RecordingRunner::new();
        reply(&rec, 0, "disk\n"); // lsblk: no crypt
        reply(&rec, 0, "active\n");
        reply(&rec, 3, "inactive\n");
        let r = run(&cfg, &h, &rec, "/bin", &|| Ok(()), 7);
        let t = r.checks.iter().find(|c| c.name == "tunnels_up").unwrap();
        assert!(
            matches!(&t.outcome, Outcome::Fail { reason, .. } if reason == "not active: tunnel-b.service"),
            "{t:?}"
        );
        assert!(!r.ok);
        let calls = rec.calls();
        assert!(calls
            .iter()
            .any(|c| c.program == "systemctl" && c.args == ["is-active", "tunnel-b.service"]));
    }
}
