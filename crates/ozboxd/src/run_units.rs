//! Runs as units of the box user's own manager (ADR 0038 section 4).
//!
//! A run used to be a cgroup scope under the daemon's own service, with its pipes held by the daemon: restarting the
//! daemon ended every run. Now a run is a transient service of the box user's manager, `ozbox-run-<id>.service`, started
//! with an argv array (`systemd-run --user`) and the limits the daemon applied before (`MemoryMax`, `MemoryHigh`,
//! `CPUWeight`, `RuntimeMaxSec`), and its program is `ozboxd run-shim` (see [`crate::run_shim`]), which owns the run's
//! output, standard input and exit status.
//!
//! Each run has a record on `/work` (`<runs dir>/<id>/run.json`) with no argument and no value in it, so a daemon that
//! starts again lists the units, reads and verifies each record and carries on with the run it describes. A record that
//! does not verify is reported, never adopted and never touched.
//!
//! Everything that talks to systemd goes through [`UserUnits`], so the lot is tested on any OS with fakes.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ozbox_core::{CommandRunner, CommandSpec};
use serde::{Deserialize, Serialize};

use crate::run_shim::{
    self, Fault, Reply, Request, EXIT, LOG, RECORD, SOCK, STARTED, SUPPORTED_PROTOS,
};
use crate::runs::{
    hex, unhex32, AdoptReport, AdoptedRun, ChildHandle, RunInfo, RunRequest, RunState, Spawner,
};
use crate::timeutil::Clock;

pub const RECORD_VERSION: u32 = 1;
pub const UNIT_PREFIX: &str = "ozbox-run-";
/// A run's status when its shim is gone with none written: it was killed with the machine (128 + SIGKILL).
pub const KILLED_STATUS: i32 = 137;
/// The newest record version this daemon can still read, one ahead of the one it writes: a daemon one patch back (a rollback)
/// reads the fields it knows of a newer record and ignores the rest, instead of losing the run from its list.
pub const MAX_READABLE_RECORD_VERSION: u32 = RECORD_VERSION + 1;
/// A unit's own run-time limit is only the backstop behind the daemon's deadline (which does not count the time a run is
/// frozen), so it is set this far past the run's limit: a freeze shorter than this never ends a run as a kill.
pub const RUNTIME_MAX_MARGIN_S: u64 = 24 * 60 * 60;
/// The most a record may be; one is a few hundred bytes.
const MAX_RECORD_BYTES: u64 = 64 * 1024;

/// A run id is what the manager made (lower-case hex) or something as plain; it becomes a directory and a unit name.
pub fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 32 && id.bytes().all(|b| b.is_ascii_alphanumeric())
}

pub fn unit_name(id: &str) -> String {
    format!("{UNIT_PREFIX}{id}.service")
}

/// The id a run unit's name carries, if it is one of ours.
pub fn id_of_unit(unit: &str) -> Option<&str> {
    unit.strip_prefix(UNIT_PREFIX)
        .and_then(|r| r.strip_suffix(".service"))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref())
}

/// What is kept of a run on disk. Never an argument, never an environment value, never a capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunRecord {
    pub v: u32,
    /// The shim protocol the run's shim speaks, so a daemon of another patch drives it right.
    pub shim_proto: u32,
    pub id: String,
    pub unit: String,
    pub program: String,
    pub labels: BTreeMap<String, String>,
    pub memory_request_bytes: u64,
    pub memory_max_bytes: Option<u64>,
    pub cpu_weight: Option<u32>,
    pub max_runtime_s: Option<u64>,
    pub queued_ms: u64,
    pub started_ms: u64,
    pub keep_stdin_open: bool,
    pub log_max_bytes: u64,
    /// The SHA-256 (hex) of a controlled run's capability (ADR 0037).
    pub cap_sha256: Option<String>,
    /// The daemon's own service cgroup (`/system.slice/ozboxd.service`): the only place a process may talk to the run's shim
    /// from. `None` when the daemon could not tell.
    #[serde(default)]
    pub daemon_cgroup: Option<String>,
}

/// Every field a record of the current version has.
const RECORD_FIELDS: &[&str] = &[
    "v",
    "shim_proto",
    "id",
    "unit",
    "program",
    "labels",
    "memory_request_bytes",
    "memory_max_bytes",
    "cpu_weight",
    "max_runtime_s",
    "queued_ms",
    "started_ms",
    "keep_stdin_open",
    "log_max_bytes",
    "cap_sha256",
    "daemon_cgroup",
];

impl RunRecord {
    /// Parse and check a record's bytes: a version this code knows, only the fields it knows, and values that make sense.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let mut v: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|_| "the record is not readable".to_string())?;
        match v.get("v").and_then(serde_json::Value::as_u64) {
            Some(n) if n == u64::from(RECORD_VERSION) => {}
            // one version ahead: read what is known, ignore the rest (the unit's hash still binds every byte)
            Some(n) if n == u64::from(MAX_READABLE_RECORD_VERSION) => {
                if let Some(o) = v.as_object_mut() {
                    o.retain(|k, _| RECORD_FIELDS.contains(&k.as_str()));
                    o.insert("v".into(), RECORD_VERSION.into());
                }
            }
            Some(_) => return Err("the record is of a version this daemon does not know".into()),
            None => return Err("the record has no version".into()),
        }
        let r: Self = serde_json::from_value(v)
            .map_err(|_| "the record has fields this daemon does not know".to_string())?;
        r.check()?;
        Ok(r)
    }

    fn check(&self) -> Result<(), String> {
        let bad = |m: &str| Err(format!("the record is not valid: {m}"));
        if !valid_id(&self.id) {
            return bad("id");
        }
        if self.unit != unit_name(&self.id) {
            return bad("it names a unit that is not this run's");
        }
        if self.program.is_empty() || self.program.len() > 256 || self.program.contains('/') {
            return bad("program");
        }
        if self.labels.len() > crate::runs::MAX_LABELS
            || self
                .labels
                .iter()
                .any(|(k, v)| k.len() > 64 || v.len() > 64)
        {
            return bad("labels");
        }
        if self.cpu_weight.is_some_and(|w| !(1..=10_000).contains(&w))
            || self.memory_max_bytes == Some(0)
            || self.log_max_bytes == 0
        {
            return bad("limits");
        }
        if self
            .cap_sha256
            .as_deref()
            .is_some_and(|h| unhex32(h).is_none())
        {
            return bad("capability hash");
        }
        if self
            .daemon_cgroup
            .as_deref()
            .is_some_and(|c| !c.starts_with('/') || c.contains("..") || c.len() > 256)
        {
            return bad("daemon cgroup");
        }
        Ok(())
    }

    fn info(&self) -> RunInfo {
        RunInfo {
            id: self.id.clone(),
            state: RunState::Running,
            program: self.program.clone(),
            labels: self.labels.clone(),
            memory_request_bytes: self.memory_request_bytes,
            memory_max_bytes: self.memory_max_bytes,
            queued_ms: self.queued_ms,
            started_ms: Some(self.started_ms),
            ended_ms: None,
            exit_code: None,
            timed_out: false,
        }
    }
}

/// Read a run's record from its folder, refusing anything that is not what the daemon wrote: a folder or file that is a
/// link, a file that is not plain, one that another user owns or that others may write, an oversized one, a record that
/// names another run. Returns the record and the exact bytes (their hash is what the unit was started with).
pub fn read_record(runs_dir: &Path, id: &str) -> Result<(RunRecord, Vec<u8>), String> {
    if !valid_id(id) {
        return Err("not a run id".into());
    }
    let dir = runs_dir.join(id);
    let root = fs::metadata(runs_dir).map_err(|e| format!("the runs folder: {}", e.kind()))?;
    let dm = fs::symlink_metadata(&dir).map_err(|e| match e.kind() {
        io::ErrorKind::NotFound => "there is no record for it".to_string(),
        k => format!("the run's folder: {k}"),
    })?;
    if !dm.is_dir() {
        return Err("the run's folder is not a folder".into());
    }
    let path = dir.join(RECORD);
    let fm = fs::symlink_metadata(&path).map_err(|e| format!("the record: {}", e.kind()))?;
    if !fm.is_file() {
        return Err("the record is not a plain file".into());
    }
    if fm.len() > MAX_RECORD_BYTES {
        return Err("the record is too large".into());
    }
    // the folder and the file belong to whoever owns the runs folder, and nobody else may write either
    if dm.uid() != root.uid() || fm.uid() != root.uid() {
        return Err("the record belongs to another user".into());
    }
    if dm.mode() & 0o022 != 0 || fm.mode() & 0o022 != 0 {
        return Err("the record can be written by others".into());
    }
    let bytes = fs::read(&path).map_err(|e| format!("the record: {}", e.kind()))?;
    let rec = RunRecord::parse(&bytes)?;
    if rec.id != id {
        return Err("the record names another run".into());
    }
    Ok((rec, bytes))
}

/// Whether a unit's command line is the shim started for exactly this record: `<...>/ozboxd run-shim <id> <sha256 of the
/// record> <runs dir>`. A record edited after its run started, a record copied from another run, or a unit that is
/// something else entirely fails this.
pub fn check_binding(
    argv: &[String],
    id: &str,
    record: &[u8],
    runs_dir: &Path,
) -> Result<(), String> {
    let [exe, sub, unit_id, hash, dir] = argv else {
        return Err("the unit is not a run shim".into());
    };
    if Path::new(exe).file_name().is_none_or(|n| n != "ozboxd") || sub != "run-shim" {
        return Err("the unit is not a run shim".into());
    }
    if unit_id != id {
        return Err("the unit belongs to another run".into());
    }
    if Path::new(dir) != runs_dir {
        return Err("the unit works in another folder".into());
    }
    if *hash != sha256_hex(record) {
        return Err("the record is not the one the run was started with (it changed since)".into());
    }
    Ok(())
}

// ---- the box user's manager --------------------------------------------------------------------------------

/// What `systemd-run --user` is asked to start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitStart {
    pub unit: String,
    pub exe: PathBuf,
    pub args: Vec<String>,
    /// The run's one memory plan (cap, throttle, swap bound, group kill, OOM score), as the manager computed it for both
    /// backends: nothing here is worked out again by the unit spawner.
    pub memory_max: Option<u64>,
    pub memory_high: Option<u64>,
    pub memory_swap_max: Option<u64>,
    /// `OOMPolicy=kill`: systemd turns on `memory.oom.group` for the unit, so the kernel kills the whole run or none of it.
    pub oom_group: bool,
    /// `OOMScoreAdjust=`: a unit of the box user's manager may only raise its score, which is what a run wants.
    pub oom_score_adj: i32,
    pub cpu_weight: u32,
    /// The unit's own run-time limit: the run's limit plus [`RUNTIME_MAX_MARGIN_S`].
    pub runtime_max_s: Option<u64>,
    pub sandbox: Sandbox,
}

/// How much of the daemon's own sandbox a run keeps. A run used to be a child of `ozboxd.service` and inherited
/// its hardening; a unit of the box user's manager inherits none, so it is asked for here.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Sandbox {
    /// Also a private `/dev`, a read-only system and a read-only home, with `read_write_paths` writable. These need a mount
    /// namespace, which a user manager can only make with a user namespace: not yet proven on the image, so off by default.
    pub strict: bool,
    pub read_write_paths: Vec<PathBuf>,
}

/// The box user's own service manager, as far as runs need it.
pub trait UserUnits: Send + Sync {
    fn start(&self, spec: &UnitStart) -> io::Result<()>;
    /// SIGKILL to every process of the unit.
    fn kill(&self, unit: &str) -> io::Result<()>;
    fn freeze(&self, unit: &str) -> io::Result<()>;
    fn thaw(&self, unit: &str) -> io::Result<()>;
    /// The run units that exist now (any state), by name.
    fn list(&self) -> io::Result<BTreeSet<String>>;
    /// The command line a unit was started with; `None` when there is no such unit.
    fn command_line(&self, unit: &str) -> io::Result<Option<Vec<String>>>;
    /// The pid of the unit's main process (its shim); `Ok(None)` when the manager cannot say, `Ok(Some(0))` when there is none
    /// yet. Used to check that the process answering on a run's socket is the one the manager started: both mean "not yet",
    /// and a caller never treats either as permission.
    fn main_pid(&self, _unit: &str) -> io::Result<Option<u32>> {
        Ok(None)
    }
    /// Whether the unit's processes are frozen now.
    fn frozen(&self, _unit: &str) -> bool {
        false
    }
}

/// `systemctl --user` / `systemd-run --user`, reached explicitly at `/run/user/<uid>`: the daemon is a system service with
/// no session. Every call is an argv array.
pub struct SystemdUserUnits {
    runner: Arc<dyn CommandRunner>,
    uid: u32,
}

impl SystemdUserUnits {
    pub fn new(runner: Arc<dyn CommandRunner>, uid: u32) -> Self {
        Self { runner, uid }
    }

    fn spec(&self, program: &str) -> CommandSpec {
        let run = format!("/run/user/{}", self.uid);
        CommandSpec::new(program)
            .env("XDG_RUNTIME_DIR", run.clone())
            .env("DBUS_SESSION_BUS_ADDRESS", format!("unix:path={run}/bus"))
    }

    fn ctl(&self, args: &[&str]) -> io::Result<ozbox_core::Output> {
        let spec = self
            .spec("systemctl")
            .arg("--user")
            .args(args.iter().copied());
        self.runner
            .run(&spec)
            .map_err(|_| io::Error::other("systemctl could not run"))
    }

    fn ctl_ok(&self, args: &[&str]) -> io::Result<()> {
        let out = self.ctl(args)?;
        if out.status == Some(0) {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "the manager refused or the unit is not there",
            ))
        }
    }
}

/// The `systemd-run` argument list for a start: an argv array, the limits as properties, the program after `--`.
pub fn systemd_run_args(s: &UnitStart) -> Vec<String> {
    let mut a: Vec<String> = vec![
        "--user".into(),
        "--quiet".into(),
        // return when the start is queued rather than when the unit is up: the daemon waits for the shim's socket instead
        "--no-block".into(),
        // a unit that ended (or failed) leaves nothing behind for the manager to list
        "--collect".into(),
        format!("--unit={}", s.unit),
        "--property=KillMode=control-group".into(),
        "--property=TimeoutStopSec=10".into(),
    ];
    if let Some(m) = s.memory_max {
        a.push(format!("--property=MemoryMax={m}"));
    }
    if let Some(m) = s.memory_high {
        a.push(format!("--property=MemoryHigh={m}"));
    }
    if let Some(m) = s.memory_swap_max {
        a.push(format!("--property=MemorySwapMax={m}"));
    }
    // the box owner's choice either way: one kill for the whole run, or only the process the kernel chose. A unit left to the
    // manager's default would be stopped whole by a single kill (`DefaultOOMPolicy=stop`), which a scope run never is (Z22).
    a.push(
        if s.oom_group {
            "--property=OOMPolicy=kill"
        } else {
            "--property=OOMPolicy=continue"
        }
        .into(),
    );
    a.push(format!("--property=OOMScoreAdjust={}", s.oom_score_adj));
    a.push(format!("--property=CPUWeight={}", s.cpu_weight));
    // what a run had under the daemon (ozboxd.service): no new privileges, no setuid or setgid files, no personality change
    for p in [
        "NoNewPrivileges=yes",
        "RestrictSUIDSGID=yes",
        "LockPersonality=yes",
    ] {
        a.push(format!("--property={p}"));
    }
    if s.sandbox.strict {
        for p in [
            "PrivateDevices=yes",
            "ProtectSystem=strict",
            "ProtectHome=read-only",
        ] {
            a.push(format!("--property={p}"));
        }
        if !s.sandbox.read_write_paths.is_empty() {
            let paths: Vec<String> = s
                .sandbox
                .read_write_paths
                .iter()
                .map(|p| p.to_string_lossy().into_owned())
                .collect();
            a.push(format!("--property=ReadWritePaths={}", paths.join(" ")));
        }
    }
    if let Some(t) = s.runtime_max_s {
        a.push(format!("--property=RuntimeMaxSec={t}"));
    }
    a.push("--".into());
    a.push(s.exe.to_string_lossy().into_owned());
    a.extend(s.args.iter().cloned());
    a
}

/// The words of a unit's `ExecStart` as `systemctl show` prints it: `{ path=… ; argv[]=a b c ; ignore_errors=no ; … }`.
pub fn parse_exec_start(text: &str) -> Option<Vec<String>> {
    let rest = text.split("argv[]=").nth(1)?;
    let argv = rest.split(" ; ").next()?;
    let words: Vec<String> = argv.split_whitespace().map(str::to_string).collect();
    (!words.is_empty()).then_some(words)
}

impl UserUnits for SystemdUserUnits {
    fn start(&self, s: &UnitStart) -> io::Result<()> {
        let spec = self.spec("systemd-run").args(systemd_run_args(s));
        let out = self
            .runner
            .run(&spec)
            .map_err(|_| io::Error::other("systemd-run could not run"))?;
        if out.status == Some(0) {
            Ok(())
        } else {
            Err(io::Error::other("the manager did not accept the run"))
        }
    }
    fn kill(&self, unit: &str) -> io::Result<()> {
        self.ctl_ok(&["kill", "--signal=SIGKILL", "--kill-whom=all", "--", unit])
    }
    fn freeze(&self, unit: &str) -> io::Result<()> {
        self.ctl_ok(&["freeze", "--", unit])
    }
    fn thaw(&self, unit: &str) -> io::Result<()> {
        self.ctl_ok(&["thaw", "--", unit])
    }
    fn list(&self) -> io::Result<BTreeSet<String>> {
        let pattern = format!("{UNIT_PREFIX}*.service");
        let out = self.ctl(&[
            "list-units",
            "--all",
            "--plain",
            "--no-legend",
            "--no-pager",
            "--full",
            "--",
            &pattern,
        ])?;
        if out.status != Some(0) {
            return Err(io::Error::other("the box user's manager did not answer"));
        }
        Ok(out
            .stdout
            .lines()
            .filter_map(|l| l.split_whitespace().next())
            .filter(|u| id_of_unit(u).is_some())
            .map(str::to_string)
            .collect())
    }
    fn main_pid(&self, unit: &str) -> io::Result<Option<u32>> {
        let out = self.ctl(&["show", "--property=MainPID", "--value", "--", unit])?;
        if out.status != Some(0) {
            return Err(io::Error::other("the box user's manager did not answer"));
        }
        Ok(out.stdout.trim().parse().ok())
    }
    fn command_line(&self, unit: &str) -> io::Result<Option<Vec<String>>> {
        let out = self.ctl(&["show", "--property=ExecStart", "--value", "--", unit])?;
        if out.status != Some(0) {
            return Err(io::Error::other("the box user's manager did not answer"));
        }
        Ok(parse_exec_start(&out.stdout))
    }
    fn frozen(&self, unit: &str) -> bool {
        self.ctl(&["show", "--property=FreezerState", "--value", "--", unit])
            .is_ok_and(|o| o.stdout.trim() == "frozen")
    }
}

// ---- the spawner ----------------------------------------------------------------------------------------------

pub struct UnitSpawnerConfig {
    /// `<state dir>/runs`, on /work.
    pub runs_dir: PathBuf,
    /// The program of the unit: this daemon's own binary (`ozboxd`), whose `run-shim` subcommand is the shim.
    pub shim_exe: PathBuf,
    /// Per-run cap on the output file.
    pub log_max_bytes: u64,
    /// Applied to runs that set no limit of their own.
    pub default_max_runtime_s: Option<u64>,
    /// How long a run's shim has to answer after its unit was started.
    pub start_timeout: Duration,
    /// How long one status or input request may wait on a shim (a frozen shim does not answer).
    pub call_timeout: Duration,
    /// The daemon's own service cgroup, written into each record so a shim talks only to processes in it.
    pub daemon_cgroup: Option<String>,
    pub sandbox: Sandbox,
}

impl UnitSpawnerConfig {
    pub fn new(runs_dir: impl Into<PathBuf>, shim_exe: impl Into<PathBuf>) -> Self {
        Self {
            runs_dir: runs_dir.into(),
            shim_exe: shim_exe.into(),
            log_max_bytes: 10 * 1024 * 1024,
            default_max_runtime_s: None,
            start_timeout: Duration::from_secs(10),
            call_timeout: Duration::from_millis(500),
            daemon_cgroup: None,
            sandbox: Sandbox::default(),
        }
    }
}

pub struct UnitSpawner {
    cfg: UnitSpawnerConfig,
    units: Arc<dyn UserUnits>,
    clock: Arc<dyn Clock>,
}

impl UnitSpawner {
    pub fn new(cfg: UnitSpawnerConfig, units: Arc<dyn UserUnits>, clock: Arc<dyn Clock>) -> Self {
        Self { cfg, units, clock }
    }

    pub fn runs_dir(&self) -> &Path {
        &self.cfg.runs_dir
    }

    /// Make the runs folder (private to the box user) if it is not there.
    pub fn prepare(&self) -> io::Result<()> {
        // the manager prints a unit's command line as words separated by spaces, which is how a run's unit is checked later:
        // a folder name with whitespace in it could never be told from two arguments, so no run would ever be adopted
        if self
            .cfg
            .runs_dir
            .to_string_lossy()
            .chars()
            .any(char::is_whitespace)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the runs folder's path has whitespace in it",
            ));
        }
        if !self.cfg.runs_dir.exists() {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&self.cfg.runs_dir)?;
        }
        Ok(())
    }

    fn dir(&self, id: &str) -> io::Result<PathBuf> {
        if !valid_id(id) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad run id"));
        }
        Ok(self.cfg.runs_dir.join(id))
    }

    fn child(&self, id: &str, pid: u32, proto: u32, shim_pid: Option<u32>) -> UnitChild {
        UnitChild {
            shim_pid: Mutex::new(shim_pid),
            dir: self.cfg.runs_dir.join(id),
            unit: unit_name(id),
            units: self.units.clone(),
            pid,
            proto,
            call_timeout: self.cfg.call_timeout,
            exit: None,
        }
    }

    /// Wait for a run's shim to answer its first request: the socket appears when the unit has started. Before anything is
    /// sent (the request carries the argv, the environment and the first input) the process on the socket is checked to be
    /// the unit's own main process, so a process of the box user that bound the socket first gets nothing. Returns the answer
    /// and the shim's pid as the kernel reported it.
    fn send_start(
        &self,
        dir: &Path,
        unit: &str,
        req: &RunRequest,
    ) -> io::Result<(Reply, Option<u32>)> {
        let msg = Request::Start {
            proto: run_shim::PROTO,
            argv: req.argv.clone(),
            cwd: req.cwd.clone(),
            env: req.env.clone(),
            stdin: req.stdin.clone(),
        };
        let sock = dir.join(SOCK);
        let begin = Instant::now();
        let mut wait = Duration::from_millis(1);
        let verify = |peer: Option<u32>| self.check_peer(unit, peer);
        loop {
            match run_shim::call_checked(&sock, &msg, self.cfg.start_timeout, &verify) {
                Ok(r) => return Ok(r),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::NotFound
                            | io::ErrorKind::ConnectionRefused
                            | io::ErrorKind::NotConnected
                    ) && begin.elapsed() < self.cfg.start_timeout =>
                {
                    std::thread::sleep(wait);
                    wait = (wait * 2).min(Duration::from_millis(20));
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// The process on a run's socket must be the unit's main process. `NotConnected` means the manager has no main process
    /// for the unit yet (the caller tries again); `PermissionDenied` means somebody else is answering.
    fn check_peer(&self, unit: &str, peer: Option<u32>) -> io::Result<()> {
        let Some(peer) = peer else { return Ok(()) };
        match self.units.main_pid(unit)? {
            // the manager cannot say, or has no main process yet: nothing is sent until it can (never "no answer, so allowed")
            None | Some(0) => Err(io::Error::from(io::ErrorKind::NotConnected)),
            Some(main) if main == peer => Ok(()),
            Some(_) => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the process answering on the run's socket is not the run's unit",
            )),
        }
    }
}

impl Spawner for UnitSpawner {
    fn applies_limits(&self, _id: &str) -> bool {
        true
    }

    fn cgroup_name(&self, id: &str) -> String {
        unit_name(id)
    }

    fn spawn(
        &self,
        id: &str,
        req: &RunRequest,
        limits: &ozbox_core::memory_plan::RunLimits,
    ) -> io::Result<Box<dyn ChildHandle>> {
        let dir = self.dir(id)?;
        self.prepare()?;
        fs::DirBuilder::new().mode(0o700).create(&dir)?;
        let cleanup = |units: &dyn UserUnits, started: bool| {
            if started {
                let _ = units.kill(&unit_name(id));
            }
            let _ = fs::remove_dir_all(&dir);
        };
        let now = self.clock.now_ms();
        let record = RunRecord {
            v: RECORD_VERSION,
            shim_proto: run_shim::PROTO,
            id: id.to_string(),
            unit: unit_name(id),
            program: req.program(),
            labels: req.labels.clone(),
            memory_request_bytes: req.memory_request_bytes,
            memory_max_bytes: limits.memory_max,
            cpu_weight: req.cpu_weight,
            max_runtime_s: req.max_runtime_s,
            queued_ms: now,
            started_ms: now,
            keep_stdin_open: req.keep_stdin_open,
            log_max_bytes: self.cfg.log_max_bytes,
            cap_sha256: req.cap_sha256.clone(),
            daemon_cgroup: self.cfg.daemon_cgroup.clone(),
        };
        let bytes = serde_json::to_vec_pretty(&record).map_err(io::Error::other)?;
        // whole and durable (temporary file, flush, rename, flush the folder): a crash leaves no half record
        let written = run_shim::write_atomic(&dir, RECORD, &bytes, 0o600);
        if let Err(e) = written {
            cleanup(self.units.as_ref(), false);
            return Err(e);
        }
        // "starting" before anything is handed to the manager: if this cannot be written the run does not begin, and if the
        // daemon stops from here on, a run that left no status and no unit is one that never ran (Z23)
        if let Err(e) = run_shim::write_atomic(&dir, STARTED, MARK_STARTING, 0o600) {
            cleanup(self.units.as_ref(), false);
            return Err(e);
        }
        let hash = sha256_hex(&bytes);
        let start = UnitStart {
            unit: unit_name(id),
            exe: self.cfg.shim_exe.clone(),
            args: vec![
                "run-shim".into(),
                id.to_string(),
                hash,
                self.cfg.runs_dir.to_string_lossy().into_owned(),
            ],
            memory_max: limits.memory_max,
            memory_high: limits.memory_high,
            memory_swap_max: limits.memory_swap_max,
            oom_group: limits.oom_group,
            oom_score_adj: limits.oom_score_adj,
            cpu_weight: req.cpu_weight.unwrap_or(100),
            // the daemon's deadline is the one that counts frozen time; the unit's is only a backstop behind it
            runtime_max_s: req
                .max_runtime_s
                .or(self.cfg.default_max_runtime_s)
                .map(|t| t + RUNTIME_MAX_MARGIN_S),
            sandbox: self.cfg.sandbox.clone(),
        };
        if let Err(e) = self.units.start(&start) {
            cleanup(self.units.as_ref(), false);
            return Err(e);
        }
        match self.send_start(&dir, &unit_name(id), req) {
            Ok((r, shim)) if r.ok => {
                // the shim answered: from here a run with no status was killed, not "never started"
                let _ = run_shim::write_atomic(&dir, STARTED, MARK_STARTED, 0o600);
                Ok(Box::new(self.child(id, r.pid.unwrap_or(0), r.proto, shim)))
            }
            // the program could not be started: the run exists and ended with 127, as it would under a shell
            Ok((r, shim)) if r.fault == Some(Fault::StartFailed) => {
                let _ = run_shim::write_atomic(&dir, STARTED, MARK_STARTED, 0o600);
                Ok(Box::new(self.child(id, 0, r.proto, shim)))
            }
            Ok(_) => {
                cleanup(self.units.as_ref(), true);
                Err(io::Error::other("the run's shim refused the start"))
            }
            Err(e) => {
                cleanup(self.units.as_ref(), true);
                Err(e)
            }
        }
    }

    fn read_log(&self, id: &str, from: u64, max: usize) -> io::Result<Option<Vec<u8>>> {
        use std::io::{Read, Seek, SeekFrom};
        let mut f = match fs::File::open(self.dir(id)?.join(LOG)) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        f.seek(SeekFrom::Start(from))?;
        let mut buf = Vec::new();
        f.take(max as u64).read_to_end(&mut buf)?;
        Ok(Some(buf))
    }

    fn forget(&self, id: &str) {
        if let Ok(dir) = self.dir(id) {
            let _ = fs::remove_dir_all(dir);
        }
    }

    fn freeze(&self, id: &str) -> io::Result<()> {
        self.units.freeze(&unit_name(id))
    }

    fn thaw(&self, id: &str) -> io::Result<()> {
        self.units.thaw(&unit_name(id))
    }

    fn adopt(&self) -> AdoptReport {
        let mut report = AdoptReport::default();
        let units = match self.units.list() {
            Ok(u) => u,
            Err(_) => {
                // nothing can be verified without the manager: say so once, adopt nothing
                report.refused.push((
                    "*".into(),
                    "the box user's service manager did not answer, so no run was taken over"
                        .into(),
                ));
                return report;
            }
        };
        let mut ids: BTreeSet<String> = units
            .iter()
            .filter_map(|u| id_of_unit(u).map(str::to_string))
            .collect();
        if let Ok(rd) = fs::read_dir(&self.cfg.runs_dir) {
            for e in rd.flatten() {
                if let Ok(n) = e.file_name().into_string() {
                    ids.insert(n);
                }
            }
        }
        for id in ids {
            let has_unit = units.contains(&unit_name(&id));
            match self.adopt_one(&id, has_unit) {
                Ok(Some(run)) => report.runs.push(run),
                Ok(None) => {}
                Err(why) => report.refused.push((id, why)),
            }
        }
        report
    }
}

/// What the marker file says before the manager has been handed the unit, and once the shim has answered.
const MARK_STARTING: &[u8] = b"starting";
const MARK_STARTED: &[u8] = b"started";

/// Whether a run's marker says it got as far as running. A file of an earlier daemon (any other content) counts as started.
fn marked_started(dir: &Path) -> bool {
    fs::read(dir.join(STARTED)).is_ok_and(|b| b != MARK_STARTING)
}

impl UnitSpawner {
    fn adopt_one(&self, id: &str, has_unit: bool) -> Result<Option<AdoptedRun>, String> {
        let dir = self.cfg.runs_dir.join(id);
        let (rec, bytes) = read_record(&self.cfg.runs_dir, id)?;
        let deadline = |r: &RunRecord| {
            r.max_runtime_s
                .or(self.cfg.default_max_runtime_s)
                .map(|s| r.started_ms + s * 1000)
        };
        let cap = rec.cap_sha256.as_deref().and_then(unhex32);
        if !has_unit {
            // no unit: the run ended while no daemon was looking. Its status is the shim's, or the machine's end of it.
            let status = run_shim::read_exit(&dir);
            // no status and no marker: the daemon stopped before the unit was ever started. That run did not run, so it is
            // not shown as killed.
            let never_started = status.is_none() && !marked_started(&dir);
            let code = status.unwrap_or(KILLED_STATUS);
            let ended_ms = fs::metadata(dir.join(EXIT))
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(self.clock.now_ms(), |d| d.as_millis() as u64);
            let mut info = rec.info();
            info.state = RunState::Exited;
            info.ended_ms = Some(ended_ms.max(rec.started_ms));
            info.exit_code = Some(code);
            if never_started {
                info.state = RunState::Cancelled;
                info.exit_code = None;
            }
            return Ok(Some(AdoptedRun {
                info,
                request_bytes: rec.memory_request_bytes,
                deadline_ms: None,
                cap_sha256: cap,
                child: None,
                frozen: false,
            }));
        }
        // a unit: it must be the shim started for exactly this record
        let argv = self
            .units
            .command_line(&unit_name(id))
            .map_err(|_| "the box user's manager did not answer".to_string())?
            .ok_or_else(|| "the unit is gone".to_string())?;
        check_binding(&argv, id, &bytes, &self.cfg.runs_dir)?;
        let frozen = self.units.frozen(&unit_name(id));
        // the process answering must be the unit's own main process (it is asked once, here; the handle then holds its pid)
        let main = self.units.main_pid(&unit_name(id)).ok().flatten();
        let verify = |peer: Option<u32>| match (main, peer) {
            (Some(m), Some(p)) if m != 0 && m != p => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "not the run's unit",
            )),
            // the manager did not say which process is the run's: whoever answers is not checked, so nobody is believed
            // (a frozen run is the exception below: its shim does not answer, and its pid is pinned on its first answer)
            (None | Some(0), Some(_)) => Err(io::Error::from(io::ErrorKind::NotConnected)),
            _ => Ok(()),
        };
        let (pid, proto, shim) = match run_shim::call_checked(
            &dir.join(SOCK),
            &Request::Status,
            self.cfg.call_timeout,
            &verify,
        ) {
            Ok((r, shim)) => {
                if !SUPPORTED_PROTOS.contains(&r.proto) {
                    return Err(format!(
                        "its shim speaks protocol {}, which this daemon does not",
                        r.proto
                    ));
                }
                (r.pid.unwrap_or(0), r.proto, shim)
            }
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                return Err("the process answering on its socket is not the run's unit".into())
            }
            Err(e) if e.kind() == io::ErrorKind::NotConnected && !frozen => return Err(
                "the manager did not say which process is the run's, so its shim cannot be checked"
                    .into(),
            ),
            // a frozen shim does not answer; the run is still there
            Err(e)
                if frozen
                    || e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::TimedOut =>
            {
                (0, rec.shim_proto, None)
            }
            Err(_) => return Err("its shim does not answer".into()),
        };
        if !marked_started(&dir) {
            // the daemon stopped between the shim's answer and the marker: the unit is there, so the run did start
            let _ = run_shim::write_atomic(&dir, STARTED, MARK_STARTED, 0o600);
        }
        Ok(Some(AdoptedRun {
            info: rec.info(),
            request_bytes: rec.memory_request_bytes,
            deadline_ms: deadline(&rec),
            cap_sha256: cap,
            child: Some(Box::new(self.child(id, pid, proto, shim))),
            frozen,
        }))
    }
}

/// The handle of a run that lives in a unit. It holds no connection: each call goes to the run's shim by path.
struct UnitChild {
    /// The shim's own pid as the kernel reported it when it was first talked to: every later request checks the process on
    /// the socket is still that one, so a socket replaced by another process of the box user gets none of the input.
    shim_pid: Mutex<Option<u32>>,
    dir: PathBuf,
    unit: String,
    units: Arc<dyn UserUnits>,
    pid: u32,
    proto: u32,
    call_timeout: Duration,
    exit: Option<i32>,
}

impl UnitChild {
    fn ask(&self, req: &Request) -> io::Result<Reply> {
        if !SUPPORTED_PROTOS.contains(&self.proto) {
            return Err(io::Error::from(io::ErrorKind::Unsupported));
        }
        let expected = self.shim_pid.lock().ok().and_then(|p| *p);
        let verify = |peer: Option<u32>| match (expected, peer) {
            (Some(e), Some(p)) if e != p => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the process on the run's socket is not its shim",
            )),
            // a run taken over while frozen has no pinned shim yet: the first process to answer must be the unit's main
            // process as the manager says it now, and is then the one every later request checks (Z21)
            (None, Some(p)) => match self.units.main_pid(&self.unit) {
                Ok(Some(m)) if m != 0 && m == p => Ok(()),
                Ok(Some(m)) if m != 0 => Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "the process on the run's socket is not the run's unit",
                )),
                _ => Err(io::Error::from(io::ErrorKind::NotConnected)),
            },
            _ => Ok(()),
        };
        let (reply, shim) =
            run_shim::call_checked(&self.dir.join(SOCK), req, self.call_timeout, &verify)?;
        if let (None, Some(shim)) = (expected, shim) {
            if let Ok(mut p) = self.shim_pid.lock() {
                p.get_or_insert(shim);
            }
        }
        Ok(reply)
    }
}

impl ChildHandle for UnitChild {
    fn pid(&self) -> u32 {
        self.pid
    }

    fn release(&mut self) -> io::Result<()> {
        Ok(()) // the shim started the program inside the unit's limits already
    }

    fn try_wait(&mut self) -> io::Result<Option<i32>> {
        if let Some(c) = self.exit {
            return Ok(Some(c));
        }
        if let Some(c) = run_shim::read_exit(&self.dir) {
            self.exit = Some(c);
            return Ok(Some(c));
        }
        match self.ask(&Request::Status) {
            Ok(r) => {
                self.exit = r.exited;
                Ok(r.exited)
            }
            // not answering now (frozen, busy): it is still going
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::PermissionDenied
                        // the manager has not said which process is the shim (yet): the run is not over for that
                        | io::ErrorKind::NotConnected
                ) =>
            {
                // (a process that is not its shim on the socket is not an end either: the run is still the manager's)
                Ok(None)
            }
            // the shim is gone: its status, if it got to write it, else killed with the machine or by the manager
            Err(_) => {
                let code = run_shim::read_exit(&self.dir).unwrap_or(KILLED_STATUS);
                self.exit = Some(code);
                Ok(Some(code))
            }
        }
    }

    fn kill(&mut self) -> io::Result<()> {
        self.units.kill(&self.unit)
    }

    fn send_stdin(&mut self, bytes: &[u8]) -> io::Result<()> {
        let text = String::from_utf8_lossy(bytes).into_owned();
        let r = self.ask(&Request::Stdin { text })?;
        if r.ok {
            return Ok(());
        }
        Err(io::Error::from(match r.fault {
            Some(Fault::WouldBlock) => io::ErrorKind::WouldBlock,
            _ => io::ErrorKind::BrokenPipe,
        }))
    }

    fn close_stdin(&mut self) {
        let _ = self.ask(&Request::CloseStdin);
    }
}
