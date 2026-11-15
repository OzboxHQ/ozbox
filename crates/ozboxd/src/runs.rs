//! Runs: agent runs, tool commands and test jobs, each in its own cgroup v2 scope with a memory cap, plus a FIFO
//! admission queue.
//!
//! Safety rules: a run is an **argv array** (never a shell string); its environment is secret - it is never logged,
//! serialized or shown in a `Debug` print; and the run list shows only the program's base name, never arguments.
//!
//! The cgroup filesystem, the memory probe and the process spawner are traits, so admission and queueing are tested
//! on any OS with fakes. A started child waits on a gate (a one-line `read` in a tiny wrapper that then `exec`s the
//! real argv) until its pid is inside the cgroup, so it never runs a single instruction outside its limits.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ozbox_core::RunUsage;
use serde::{Deserialize, Serialize};

use crate::metrics::parse;
use crate::timeutil::Clock;

pub const MAX_ARGS: usize = 256;
pub const MAX_ARG_LEN: usize = 4096;
pub const MAX_ENV: usize = 128;
pub const MAX_LABELS: usize = 16;

/// A request to start a run. Deliberately not `Serialize` (it carries secret env values) and `Debug` hides them.
#[derive(Clone, Deserialize)]
pub struct RunRequest {
    pub argv: Vec<String>,
    #[serde(default)]
    pub cwd: Option<PathBuf>,
    /// Secret values: never logged or serialized.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Memory the run needs. It waits in the queue while less than this is free.
    #[serde(default)]
    pub memory_request_bytes: u64,
    /// Hard cap (`memory.max`). `memory.high` is set to 90% of it.
    #[serde(default)]
    pub memory_max_bytes: Option<u64>,
    /// `cpu.weight`, 1..=10000 (default 100).
    #[serde(default)]
    pub cpu_weight: Option<u32>,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    /// Wall-clock limit in seconds (1 s to 7 days); the whole scope is killed on expiry. Falls back to the
    /// daemon's default, if any.
    #[serde(default)]
    pub max_runtime_s: Option<u64>,
    /// Text fed to the program's standard input, then end-of-file (an agent's prompt). It reaches the program through a
    /// pipe: never an argument, never a file. Secret like the environment: never logged, serialized or shown by `Debug`.
    #[serde(default)]
    pub stdin: Option<String>,
    /// Keep the standard input open after `stdin` has been written, so more text can be appended with
    /// `POST /v1/runs/<id>/stdin` (an interactive agent session, or a prompt longer than one request). It closes when
    /// the caller says so or the run ends.
    #[serde(default)]
    pub keep_stdin_open: bool,
    /// A controlled run: the daemon answers with a capability (once), and the run's input, output and stop then need it.
    /// For a run that holds something the box user must not drive or read, such as a browser session (ADR 0037).
    #[serde(default)]
    pub require_capability: bool,
    /// Set by [`RunManager::start_controlled`] only (never read from a request): the SHA-256 of the capability, in hex, for
    /// the run's record on disk, so a restarted daemon can keep checking it. Never the capability itself.
    #[serde(skip)]
    pub cap_sha256: Option<String>,
}

/// The SHA-256 of a capability: all the daemon keeps of it.
fn cap_hash(cap: &str) -> [u8; 32] {
    let d = ring::digest::digest(&ring::digest::SHA256, cap.as_bytes());
    let mut h = [0u8; 32];
    h.copy_from_slice(d.as_ref());
    h
}

/// Lower-case hex of a digest.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A digest from its hex text.
pub fn unhex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn same(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The most text a run's standard input may carry in one request.
pub const MAX_STDIN: usize = 48 * 1024;
/// The most text that may be waiting to be read by one run's program. More than this means it is not reading.
pub const MAX_STDIN_PENDING: usize = 1024 * 1024;

impl fmt::Debug for RunRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunRequest")
            .field("program", &self.program())
            .field("args", &self.argv.len().saturating_sub(1))
            .field("env_keys", &self.env.len())
            .field("stdin_bytes", &self.stdin.as_ref().map(String::len))
            .field("memory_request_bytes", &self.memory_request_bytes)
            .finish()
    }
}

impl RunRequest {
    pub fn new(argv: Vec<String>) -> Self {
        Self {
            argv,
            cwd: None,
            env: BTreeMap::new(),
            memory_request_bytes: 0,
            memory_max_bytes: None,
            cpu_weight: None,
            labels: BTreeMap::new(),
            max_runtime_s: None,
            stdin: None,
            keep_stdin_open: false,
            require_capability: false,
            cap_sha256: None,
        }
    }

    /// Base name of the program only, for lists and logs.
    pub fn program(&self) -> String {
        self.argv
            .first()
            .map(|p| p.rsplit('/').next().unwrap_or(p).to_string())
            .unwrap_or_default()
    }

    pub fn validate(&self) -> Result<(), RunError> {
        let bad = |m: &str| Err(RunError::Invalid(m.to_string()));
        if self.argv.is_empty() || self.argv[0].is_empty() {
            return bad("argv must name a program");
        }
        if self.argv.len() > MAX_ARGS
            || self
                .argv
                .iter()
                .any(|a| a.len() > MAX_ARG_LEN || a.contains('\0'))
        {
            return bad("argv has too many or too long arguments");
        }
        if self.stdin.as_ref().is_some_and(|t| t.len() > MAX_STDIN) {
            return bad("the standard input text is too long");
        }
        if self.keep_stdin_open && self.stdin.is_none() {
            return bad("keep_stdin_open needs a first text on standard input");
        }
        if self.stdin.as_ref().is_some_and(|t| t.contains('\0')) {
            return bad("the standard input text is not allowed");
        }
        if self.env.len() > MAX_ENV {
            return bad("too many environment variables");
        }
        let valid_key = |k: &str| {
            !k.is_empty()
                && !k.starts_with(|c: char| c.is_ascii_digit())
                && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        };
        if self
            .env
            .iter()
            .any(|(k, v)| !valid_key(k) || v.contains('\0') || v.len() > MAX_ARG_LEN)
        {
            return bad("an environment variable name or value is not allowed");
        }
        if self.labels.len() > MAX_LABELS
            || self
                .labels
                .iter()
                .any(|(k, v)| k.len() > 64 || v.len() > 64)
        {
            return bad("too many or too long labels");
        }
        if self.cwd.as_ref().is_some_and(|c| !c.is_absolute()) {
            return bad("cwd must be an absolute path");
        }
        if self.cpu_weight.is_some_and(|w| !(1..=10_000).contains(&w)) {
            return bad("cpu_weight must be 1 to 10000");
        }
        if self
            .max_runtime_s
            .is_some_and(|s| !(1..=7 * 86_400).contains(&s))
        {
            return bad("max_runtime_s must be 1 second to 7 days");
        }
        if let Some(max) = self.memory_max_bytes {
            if max == 0 || max < self.memory_request_bytes {
                return bad("memory_max_bytes must be positive and at least the request");
            }
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RunError {
    #[error("invalid run request: {0}")]
    Invalid(String),
    #[error("the run queue is full")]
    QueueFull,
    #[error("the requested memory exceeds the box's total memory")]
    TooLarge,
    #[error("no such run")]
    NotFound,
    #[error("could not start the run: {0}")]
    Start(String),
    #[error("{0}")]
    Input(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    Queued,
    Running,
    Exited,
    Cancelled,
}

/// The label the browser tool puts on its worker's run: such a run is only ever reached with its capability.
pub const BROWSER_LABEL: &str = "ozbox.browser";

fn is_browser(r: &RunInfo) -> bool {
    r.labels.contains_key(BROWSER_LABEL)
}

/// What [`RunManager::pause`] did.
#[derive(Debug, Clone, PartialEq)]
pub struct PauseReport {
    pub kind: PauseKind,
    pub frozen: Vec<String>,
    pub failed: Vec<(String, String)>,
    /// The runs going when the pause began.
    pub running: Vec<RunInfo>,
}

/// What [`RunManager::adopt_existing`] found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdoptSummary {
    pub adopted: usize,
    pub ended: usize,
    /// `(run id, why)`; ids and reasons only, never a record's contents.
    pub refused: Vec<(String, String)>,
}

/// What the API shows about a run: no arguments, no environment.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RunInfo {
    pub id: String,
    pub state: RunState,
    pub program: String,
    pub labels: BTreeMap<String, String>,
    pub memory_request_bytes: u64,
    pub memory_max_bytes: Option<u64>,
    pub queued_ms: u64,
    pub started_ms: Option<u64>,
    pub ended_ms: Option<u64>,
    pub exit_code: Option<i32>,
    /// Killed because it reached its wall-clock limit.
    pub timed_out: bool,
}

/// The most output one log read returns.
pub const LOG_CHUNK: usize = 48 * 1024;
/// How long after a program exits its last output is given to reach the log file.
const LOG_SETTLE_MS: u64 = 300;

/// One read of a run's output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LogChunk {
    pub text: String,
    /// Where the next read starts.
    pub next: u64,
    pub state: RunState,
    /// Set only once the run has ended and every byte of its output has been returned.
    pub exit_code: Option<i32>,
}

/// How much of `bytes` to return: all of it when `all` (the run is over), else up to the last newline, else (a very long
/// line) everything up to the last complete character.
fn whole_text_len(bytes: &[u8], all: bool) -> usize {
    if all {
        return bytes.len();
    }
    if let Some(i) = bytes.iter().rposition(|b| *b == b'\n') {
        return i + 1;
    }
    if bytes.len() < LOG_CHUNK {
        return 0;
    }
    match std::str::from_utf8(bytes) {
        Ok(_) => bytes.len(),
        Err(e) => e.valid_up_to(),
    }
}

// ---- seams ----------------------------------------------------------------------------------------------------

/// The cgroup v2 tree under the configured parent. `name` is `run-<id>.scope`.
pub trait CgroupFs: Send + Sync {
    fn create(&self, name: &str) -> io::Result<()>;
    fn write(&self, name: &str, file: &str, value: &str) -> io::Result<()>;
    fn read(&self, name: &str, file: &str) -> io::Result<String>;
    fn remove(&self, name: &str) -> io::Result<()>;
}

/// Free-memory source for admission.
pub trait MemoryProbe: Send + Sync {
    fn total_bytes(&self) -> u64;
    fn available_bytes(&self) -> u64;
}

pub trait ChildHandle: Send {
    fn pid(&self) -> u32;
    /// Let the gated child go (it is already inside its cgroup).
    fn release(&mut self) -> io::Result<()>;
    fn try_wait(&mut self) -> io::Result<Option<i32>>;
    fn kill(&mut self) -> io::Result<()>;
    /// Ask these processes (the run's own, found in its scope) to end: SIGTERM, never SIGKILL. The caller waits and then
    /// kills the whole scope. The default cannot signal, and the caller then goes straight to the kill.
    fn terminate_pids(&mut self, _pids: &[u32]) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
    /// Append text to the program's standard input (only for a run started with `keep_stdin_open`). Never waits for the
    /// program: a program that is not reading makes this fail instead.
    fn send_stdin(&mut self, _bytes: &[u8]) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
    /// End of file on the program's standard input.
    fn close_stdin(&mut self) {}
}

pub trait Spawner: Send + Sync {
    /// Start a run. `limits` is the run's one memory plan (see [`ozbox_core::memory_plan::run_limits`]): a spawner that
    /// starts a unit must apply all of it as the unit's properties, because the manager then writes none of it to a
    /// cgroup; one that does not must still put the run's OOM score at `limits.oom_score_adj`.
    fn spawn(
        &self,
        id: &str,
        req: &RunRequest,
        limits: &ozbox_core::memory_plan::RunLimits,
    ) -> io::Result<Box<dyn ChildHandle>>;
    /// A run has left the history: drop anything kept for it (its log).
    fn forget(&self, _id: &str) {}
    /// Up to `max` bytes of a run's output from byte `from`; `None` when no output is kept for it.
    fn read_log(&self, _id: &str, _from: u64, _max: usize) -> io::Result<Option<Vec<u8>>> {
        Ok(None)
    }
    /// The name of a run's cgroup under the [`CgroupFs`] parent (what usage and OOM events are read from).
    fn cgroup_name(&self, id: &str) -> String {
        scope_name(id)
    }
    /// Whether the spawner puts the run inside its limits itself (a transient unit with properties), so the manager makes
    /// no cgroup of its own, writes no limits and moves no pid. False: the manager does all of that (a cgroup scope).
    fn applies_limits(&self, _id: &str) -> bool {
        false
    }
    /// Decide where this run will live, once, before anything is made for it. A spawner with more than one way of running
    /// things (see `run_backend::BackendSwitch`) picks and remembers it here; everything else is fixed.
    fn place(&self, _id: &str) {}
    /// Things worth telling the operator that the spawner noticed (its way of running things changed), once each.
    fn notes(&self) -> Vec<String> {
        Vec::new()
    }
    /// Stop a run's processes in place (the cgroup freezer) and let them go again. Unsupported unless the spawner says so.
    fn freeze(&self, _id: &str) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
    fn thaw(&self, _id: &str) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
    /// Runs that outlived the previous daemon, found again from their records. Nothing for a spawner whose runs die with
    /// the daemon.
    fn adopt(&self) -> AdoptReport {
        AdoptReport::default()
    }
}

/// A run found again after the daemon restarted.
pub struct AdoptedRun {
    pub info: RunInfo,
    pub request_bytes: u64,
    /// Absolute wall-clock deadline, from the run's own start time and limit.
    pub deadline_ms: Option<u64>,
    /// The SHA-256 of a controlled run's capability, from its verified record.
    pub cap_sha256: Option<[u8; 32]>,
    /// The handle of a run still going; `None` for one that has ended (it goes to the history).
    pub child: Option<Box<dyn ChildHandle>>,
    pub frozen: bool,
}

/// What a restarted daemon found: runs to carry on with, runs that ended meanwhile, and records it would not trust.
#[derive(Default)]
pub struct AdoptReport {
    pub runs: Vec<AdoptedRun>,
    /// `(run id, why)`: a record that did not verify, or a unit with no record. Reported, never adopted, never touched.
    pub refused: Vec<(String, String)>,
}

/// The real cgroup tree, as plain files under `parent` (default `/sys/fs/cgroup/ozbox.slice`).
#[derive(Debug, Clone)]
pub struct FsCgroup {
    parent: PathBuf,
}

impl FsCgroup {
    pub fn new(parent: impl Into<PathBuf>) -> Self {
        Self {
            parent: parent.into(),
        }
    }

    /// Use the cgroup this service was delegated (`Delegate=yes`), found from `/proc/self/cgroup`.
    ///
    /// cgroup v2 forbids a cgroup from both holding processes and delegating controllers to children, so the
    /// daemon first moves itself into a leaf `daemon` child (unless systemd already put it in one), then enables
    /// `memory` and `cpu` for the service cgroup, whose children are the run scopes.
    pub fn delegated(root: &Path, self_cgroup: &str, pid: u32) -> io::Result<Self> {
        let rel = parse_self_cgroup(self_cgroup).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "no cgroup v2 entry in /proc/self/cgroup",
            )
        })?;
        let own = root.join(rel.trim_start_matches('/'));
        let service = if own.file_name().is_some_and(|n| n == "daemon") {
            own.parent().map(Path::to_path_buf).unwrap_or(own.clone())
        } else {
            let leaf = own.join("daemon");
            std::fs::create_dir_all(&leaf)?;
            std::fs::write(leaf.join("cgroup.procs"), pid.to_string())?;
            own
        };
        std::fs::write(service.join("cgroup.subtree_control"), "+memory +cpu")?;
        Ok(Self { parent: service })
    }

    pub fn parent(&self) -> &Path {
        &self.parent
    }

    /// Make sure the parent exists and delegates the controllers runs need. Best effort: on a host without the
    /// controllers delegated the per-run writes fail with a clear error instead.
    pub fn prepare(&self) -> io::Result<()> {
        std::fs::create_dir_all(&self.parent)?;
        let _ = std::fs::write(self.parent.join("cgroup.subtree_control"), "+memory +cpu");
        Ok(())
    }

    fn path(&self, name: &str) -> io::Result<PathBuf> {
        if name.is_empty() || name.contains('/') || name.contains("..") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "bad cgroup name",
            ));
        }
        Ok(self.parent.join(name))
    }
}

impl CgroupFs for FsCgroup {
    fn create(&self, name: &str) -> io::Result<()> {
        std::fs::create_dir(self.path(name)?)
    }
    fn write(&self, name: &str, file: &str, value: &str) -> io::Result<()> {
        std::fs::write(self.path(name)?.join(file), value)
    }
    fn read(&self, name: &str, file: &str) -> io::Result<String> {
        std::fs::read_to_string(self.path(name)?.join(file))
    }
    fn remove(&self, name: &str) -> io::Result<()> {
        std::fs::remove_dir(self.path(name)?)
    }
}

/// The cgroup of a user's own service manager (`user@<uid>.service`) under the cgroup root.
pub fn user_manager_cgroup(root: &Path, uid: u32) -> PathBuf {
    root.join(format!("user.slice/user-{uid}.slice/user@{uid}.service"))
}

/// Which of the controllers runs need (`memory`, `cpu`) a cgroup does not have, from its `cgroup.controllers`. A transient
/// unit's `MemoryMax` and `CPUWeight` only hold if the box user's manager has them delegated.
pub fn missing_run_controllers(controllers: &str) -> Vec<&'static str> {
    ["memory", "cpu"]
        .into_iter()
        .filter(|c| !controllers.split_whitespace().any(|x| x == *c))
        .collect()
}

/// The cgroup v2 path from `/proc/self/cgroup` (the `0::<path>` line).
pub fn parse_self_cgroup(text: &str) -> Option<String> {
    text.lines()
        .find_map(|l| l.strip_prefix("0::"))
        .map(|p| p.trim().to_string())
        .filter(|p| p.starts_with('/') && !p.contains(".."))
}

/// Memory numbers from `/proc/meminfo` through a [`crate::host::HostSource`].
pub struct HostMemory(pub Arc<dyn crate::host::HostSource>);

impl HostMemory {
    fn info(&self) -> parse::Meminfo {
        self.0
            .read("/proc/meminfo")
            .ok()
            .and_then(|t| parse::parse_meminfo(&t).ok())
            .unwrap_or_default()
    }
}

impl MemoryProbe for HostMemory {
    fn total_bytes(&self) -> u64 {
        self.info().total
    }
    fn available_bytes(&self) -> u64 {
        self.info().available
    }
}

/// Spawns real processes. The child starts as `sh -c 'read _; exec "$@"' sh <argv...>` with a piped stdin: the
/// argv reaches `exec` as separate words (no shell parsing of user text), and the child blocks on the `read` until
/// [`ChildHandle::release`] writes the newline - after the parent has moved its pid into the cgroup.
#[cfg(unix)]
pub struct StdSpawner {
    /// When set, stdout and stderr are appended to `<log_dir>/<id>.log`; otherwise they are discarded.
    pub log_dir: Option<PathBuf>,
    /// Per-run cap on the log file; output past it is dropped with a marker line.
    pub log_max_bytes: u64,
}

#[cfg(unix)]
struct StdChild {
    child: std::process::Child,
    gate: Option<std::process::ChildStdin>,
    /// The run's standard input, written after the gate opens.
    input: Option<Vec<u8>>,
    keep_open: bool,
    /// Text waiting for the writer thread of a run whose input stays open, and how many bytes of it there are.
    feed: Option<(
        std::sync::mpsc::Sender<Vec<u8>>,
        Arc<std::sync::atomic::AtomicUsize>,
    )>,
}

#[cfg(unix)]
impl ChildHandle for StdChild {
    fn pid(&self) -> u32 {
        self.child.id()
    }
    fn release(&mut self) -> io::Result<()> {
        use std::io::Write;
        if let Some(mut g) = self.gate.take() {
            g.write_all(b"\n")?;
            if let Some(input) = self.input.take() {
                // A pipe holds about 64 KiB: write on a thread so this call (made under the manager's lock) never waits
                // for the program to read. Dropping the pipe at the end is the program's end-of-file.
                let keep = if self.keep_open {
                    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
                    let pending = Arc::new(std::sync::atomic::AtomicUsize::new(0));
                    self.feed = Some((tx, pending.clone()));
                    Some((rx, pending))
                } else {
                    None
                };
                std::thread::Builder::new()
                    .name("ozboxd-stdin".into())
                    .spawn(move || {
                        if g.write_all(&input).is_err() {
                            return;
                        }
                        if let Some((rx, pending)) = keep {
                            // ends when the sender is dropped (close, or the run leaving the daemon's list)
                            while let Ok(more) = rx.recv() {
                                let n = more.len();
                                let ok = g.write_all(&more).and_then(|_| g.flush()).is_ok();
                                pending.fetch_sub(n, std::sync::atomic::Ordering::SeqCst);
                                if !ok {
                                    return;
                                }
                            }
                        }
                    })?;
            }
        }
        Ok(())
    }
    fn try_wait(&mut self) -> io::Result<Option<i32>> {
        use std::os::unix::process::ExitStatusExt;
        Ok(self
            .child
            .try_wait()?
            .map(|s| s.code().unwrap_or_else(|| 128 + s.signal().unwrap_or(0))))
    }
    fn kill(&mut self) -> io::Result<()> {
        self.feed = None;
        self.child.kill()
    }
    fn terminate_pids(&mut self, pids: &[u32]) -> io::Result<()> {
        // `unsafe` is forbidden in this crate, so the signal is sent by `kill`, with numbers only (a pid is read from the
        // run's own scope and is never below 2, so no pid of the system and no process group is ever named).
        let list: Vec<String> = pids
            .iter()
            .filter(|p| **p > 1 && **p <= i32::MAX as u32)
            .map(u32::to_string)
            .collect();
        if list.is_empty() {
            return Err(io::Error::from(io::ErrorKind::NotFound));
        }
        let st = std::process::Command::new("kill")
            .arg("-TERM")
            .arg("--")
            .args(&list)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()?;
        if st.success() {
            Ok(())
        } else {
            Err(io::Error::other("kill failed"))
        }
    }
    fn send_stdin(&mut self, bytes: &[u8]) -> io::Result<()> {
        use std::sync::atomic::Ordering;
        let Some((tx, pending)) = &self.feed else {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe));
        };
        if pending.load(Ordering::SeqCst) + bytes.len() > MAX_STDIN_PENDING {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        pending.fetch_add(bytes.len(), Ordering::SeqCst);
        tx.send(bytes.to_vec()).map_err(|_| {
            pending.fetch_sub(bytes.len(), Ordering::SeqCst);
            io::Error::from(io::ErrorKind::BrokenPipe)
        })
    }
    fn close_stdin(&mut self) {
        self.feed = None;
    }
}

#[cfg(unix)]
impl Spawner for StdSpawner {
    fn spawn(
        &self,
        id: &str,
        req: &RunRequest,
        limits: &ozbox_core::memory_plan::RunLimits,
    ) -> io::Result<Box<dyn ChildHandle>> {
        use std::process::{Command, Stdio};
        let mut c = Command::new("sh");
        // After the gate, stdin is /dev/null, unless the run was given text: then it is the same pipe, carrying that text
        // and then end-of-file. Either way a run never waits on input nobody will send.
        // The daemon is protected from the OOM killer (ADR 0045), and a child inherits its score: a run puts its own back UP before
        // it does anything (a process may raise its score, never lower it), so a run is never protected by the daemon's.
        let raise = ozbox_core::memory_plan::raise_score_snippet(limits.oom_score_adj);
        let script = if req.stdin.is_some() {
            format!("{raise}; read _gate; exec \"$@\"")
        } else {
            format!("{raise}; read _gate; exec \"$@\" </dev/null")
        };
        c.arg("-c").arg(&script).arg("sh").args(&req.argv);
        if let Some(d) = &req.cwd {
            c.current_dir(d);
        }
        c.envs(&req.env);
        c.stdin(Stdio::piped());
        let log = match &self.log_dir {
            Some(dir) => {
                c.stdout(Stdio::piped()).stderr(Stdio::piped());
                let f = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(dir.join(format!("{id}.log")))?;
                Some(Arc::new(std::sync::Mutex::new(CappedLog::new(
                    f,
                    self.log_max_bytes,
                ))))
            }
            None => {
                c.stdout(Stdio::null()).stderr(Stdio::null());
                None
            }
        };
        let mut child = c.spawn()?;
        if let Some(log) = log {
            if let Some(o) = child.stdout.take() {
                pump(o, log.clone());
            }
            if let Some(e) = child.stderr.take() {
                pump(e, log);
            }
        }
        let gate = child.stdin.take();
        Ok(Box::new(StdChild {
            child,
            gate,
            input: req.stdin.as_ref().map(|t| t.as_bytes().to_vec()),
            keep_open: req.keep_stdin_open,
            feed: None,
        }))
    }

    fn read_log(&self, id: &str, from: u64, max: usize) -> io::Result<Option<Vec<u8>>> {
        use std::io::{Read, Seek, SeekFrom};
        let Some(dir) = &self.log_dir else {
            return Ok(None);
        };
        let mut f = match std::fs::File::open(dir.join(format!("{id}.log"))) {
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
        if let Some(dir) = &self.log_dir {
            let _ = std::fs::remove_file(dir.join(format!("{id}.log")));
        }
    }
}

/// Copy a child's pipe into a size-capped log. Once the cap is hit the output is drained and dropped so the child
/// never blocks on a full pipe.
#[cfg(unix)]
pub(crate) fn pump<R: io::Read + Send + 'static>(
    mut src: R,
    log: Arc<std::sync::Mutex<CappedLog>>,
) {
    let _ = std::thread::Builder::new()
        .name("ozboxd-log".into())
        .spawn(move || {
            let mut buf = [0u8; 8192];
            while let Ok(n) = src.read(&mut buf) {
                if n == 0 {
                    break;
                }
                if let Ok(mut l) = log.lock() {
                    l.write(&buf[..n]);
                }
            }
        });
}

/// A log file with a hard size cap: the cap is never exceeded by output, and truncation leaves one marker line.
pub struct CappedLog {
    file: std::fs::File,
    cap: u64,
    written: u64,
    truncated: bool,
}

impl CappedLog {
    pub fn new(file: std::fs::File, cap: u64) -> Self {
        let written = file.metadata().map(|m| m.len()).unwrap_or(0);
        Self {
            file,
            cap,
            written,
            truncated: false,
        }
    }

    pub fn write(&mut self, data: &[u8]) {
        use std::io::Write;
        if self.truncated {
            return;
        }
        let room = self.cap.saturating_sub(self.written) as usize;
        let take = data.len().min(room);
        if take > 0 && self.file.write_all(&data[..take]).is_ok() {
            self.written += take as u64;
        }
        if take < data.len() {
            self.truncated = true;
            let _ = self.file.write_all(
                format!("\n[ozbox: output truncated at {} bytes]\n", self.cap).as_bytes(),
            );
        }
    }
}

// ---- manager --------------------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct RunConfig {
    pub max_queue: usize,
    pub max_active: usize,
    pub history: usize,
    /// Applied to runs that do not set `max_runtime_s`. `None` = no limit.
    pub default_max_runtime_s: Option<u64>,
    /// A run that sets no `memory_max_bytes` gets the box's default cap, derived from its RAM (ADR 0045): everything but the
    /// box's own reserve, throttled at 90 %, with a bounded share of the compressed swap, and killed as one group if it passes
    /// it. Never divided by the number of runs: admission already shares memory by what each asks for. `false` only for a
    /// box whose owner chose to run uncapped.
    pub default_memory_cap: bool,
}

impl Default for RunConfig {
    fn default() -> Self {
        Self {
            max_queue: 32,
            max_active: 64,
            history: 100,
            default_max_runtime_s: None,
            default_memory_cap: true,
        }
    }
}

struct Active {
    info: RunInfo,
    child: Box<dyn ChildHandle>,
    request_bytes: u64,
    prev_cpu: Option<(u64, u64)>, // (usage_usec, ts_ms)
    deadline_ms: Option<u64>,
    timed_out: bool,
    /// When the run was frozen (live update), while it is. Its wall-clock limit does not run while it is frozen.
    frozen_since_ms: Option<u64>,
}

/// Things the daemon should record as incidents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunEvent {
    TimedOut(String),
    /// The spawner's way of running things changed (for example, the box user's manager became ready, or went away).
    Backend(String),
}

struct Queued {
    info: RunInfo,
    req: RunRequest,
}

pub struct RunManager {
    cfg: RunConfig,
    cg: Arc<dyn CgroupFs>,
    mem: Arc<dyn MemoryProbe>,
    spawner: Arc<dyn Spawner>,
    clock: Arc<dyn Clock>,
    active: Vec<Active>,
    queue: VecDeque<Queued>,
    done: VecDeque<RunInfo>,
    events: Vec<RunEvent>,
    seq: u32,
    /// Controlled runs: the hash of each one's capability, by run id. Dropped with the run's history.
    caps: BTreeMap<String, [u8; 32]>,
    /// While set, no queued run is started (a live update has the runs frozen, or a replace is about to move the box).
    paused: Option<PauseKind>,
    /// When to look for runs a previous daemon left going again, and how many times that has been tried: the first look found
    /// the box user's manager not answering.
    adopt_retry: Option<(u64, u32)>,
    /// While set and in the future, no new run starts: the box is about to be stopped for a resize or an upgrade. It
    /// expires by itself, because the change can fail before the stop and a box must not refuse work for ever.
    hold_until_ms: Option<u64>,
}

/// How often, and how many times, a daemon that could not reach the box user's manager looks again for runs it left going.
const ADOPT_RETRY_EVERY_MS: u64 = 5_000;
const ADOPT_RETRIES: u32 = 24;

/// Why runs are paused, which decides what happens to them (ADR 0038 section 4, item 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PauseKind {
    /// A live update: the machine stays, so each running run is frozen in place with the cgroup freezer and thawed after.
    Freeze,
    /// A replace: a frozen process cannot move to another machine, so nothing is frozen. New runs wait, and the runs that
    /// are going are listed for the caller, whose engine checkpoints, stops and resumes them on the new machine.
    Replace,
}

/// How long a hold on new runs lasts at most.
pub const HOLD_MAX_MS: u64 = 10 * 60 * 1000;

/// Kill every process in a run's scope (`cgroup.kill`, Linux 5.14+), and the direct child as a fallback.
/// Returns false only if neither worked.
fn kill_scope(cg: &dyn CgroupFs, name: &str, child: &mut dyn ChildHandle) -> bool {
    let scope_ok = cg.write(name, "cgroup.kill", "1").is_ok();
    child.kill().is_ok() || scope_ok
}

pub fn scope_name(id: &str) -> String {
    format!("run-{id}.scope")
}

impl RunManager {
    pub fn new(
        cfg: RunConfig,
        cg: Arc<dyn CgroupFs>,
        mem: Arc<dyn MemoryProbe>,
        spawner: Arc<dyn Spawner>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            cfg,
            cg,
            mem,
            spawner,
            clock,
            active: Vec::new(),
            queue: VecDeque::new(),
            done: VecDeque::new(),
            events: Vec::new(),
            seq: 0,
            caps: BTreeMap::new(),
            paused: None,
            adopt_retry: None,
            hold_until_ms: None,
        }
    }

    /// A daemon that started before the box user's manager was up could not take its runs over; it looks again, so a run that
    /// outlived the previous daemon is listed, counted in admission and reaped as soon as the manager answers.
    fn retry_adoption(&mut self, now: u64) {
        let Some((at, tries)) = self.adopt_retry else {
            return;
        };
        if now < at {
            return;
        }
        let summary = self.adopt_existing();
        let still = summary.refused.iter().any(|(id, _)| id == "*");
        self.adopt_retry =
            (still && tries < ADOPT_RETRIES).then_some((now + ADOPT_RETRY_EVERY_MS, tries + 1));
        for (id, why) in &summary.refused {
            if id != "*" {
                self.events.push(RunEvent::Backend(format!(
                    "run {id} was not taken over: {why}"
                )));
            }
        }
        if summary.adopted + summary.ended > 0 {
            self.events.push(RunEvent::Backend(format!(
                "took over {} run(s) still going and {} that ended meanwhile, once the box user's manager answered",
                summary.adopted, summary.ended
            )));
        }
    }

    fn new_id(&mut self) -> String {
        self.seq = self.seq.wrapping_add(1);
        format!("{:x}{:04x}", self.clock.now_ms() / 1000, self.seq & 0xffff)
    }

    /// Memory free for a new run: available, minus what already-admitted runs are still entitled to grow into.
    fn free_bytes(&self) -> u64 {
        let reserved: u64 = self
            .active
            .iter()
            .map(|a| {
                let cur = self
                    .cg
                    .read(&self.spawner.cgroup_name(&a.info.id), "memory.current")
                    .ok()
                    .and_then(|t| parse::parse_cgroup_u64(&t).ok())
                    .unwrap_or(0);
                a.request_bytes.saturating_sub(cur)
            })
            .sum();
        self.mem.available_bytes().saturating_sub(reserved)
    }

    /// Start a run now, or queue it (FIFO). Returns its id and whether it is running or queued.
    pub fn start(&mut self, req: RunRequest) -> Result<(String, RunState), RunError> {
        req.validate()?;
        let total = self.mem.total_bytes();
        if total > 0 && req.memory_request_bytes > total {
            return Err(RunError::TooLarge);
        }
        let now = self.clock.now_ms();
        if self.hold_until_ms.is_some_and(|t| now < t) {
            return Err(RunError::Input(
                "new runs are paused: a resize or an upgrade asked this box to get ready to stop. Start the run after it is back. If the box is not being stopped, a DELETE of /v1/quiesce lifts this, and it ends by itself after 10 minutes",
            ));
        }
        let id = self.new_id();
        let info = RunInfo {
            id: id.clone(),
            state: RunState::Queued,
            program: req.program(),
            labels: req.labels.clone(),
            memory_request_bytes: req.memory_request_bytes,
            memory_max_bytes: req.memory_max_bytes,
            queued_ms: now,
            started_ms: None,
            ended_ms: None,
            exit_code: None,
            timed_out: false,
        };
        let can_start_now = self.queue.is_empty()
            && self.paused.is_none()
            && self.active.len() < self.cfg.max_active
            && req.memory_request_bytes <= self.free_bytes();
        if can_start_now {
            self.launch(info, &req)?;
            return Ok((id, RunState::Running));
        }
        if self.queue.len() >= self.cfg.max_queue {
            return Err(RunError::QueueFull);
        }
        self.queue.push_back(Queued { info, req });
        Ok((id, RunState::Queued))
    }

    fn launch(&mut self, mut info: RunInfo, req: &RunRequest) -> Result<(), RunError> {
        // A spawner that starts a unit sets the limits as the unit's properties: there is no cgroup of ours to make.
        // The way is decided first: the name of a run's cgroup depends on it.
        self.spawner.place(&info.id);
        let name = self.spawner.cgroup_name(&info.id);
        let own_cgroup = !self.spawner.applies_limits(&info.id);
        let fail = |cg: &Arc<dyn CgroupFs>, e: io::Error, what: &str| {
            if own_cgroup {
                let _ = cg.remove(&name);
            }
            // a spawner's own words ("the box user's manager does not delegate: memory") are kept; any other error is its kind
            let why = if e.kind() == io::ErrorKind::Other {
                e.to_string()
            } else {
                e.kind().to_string()
            };
            RunError::Start(format!("{what}: {why}"))
        };
        // ONE memory plan per run (cap, throttle, swap bound, group kill, OOM score), computed here before the backend branch
        // and read by BOTH spawners: the cgroup this manager makes below, and the unit a spawner starts. Neither backend
        // may compute its own, or one of them quietly runs without the guard (ADR 0045, ADR 0038 amendment 1).
        let limits = ozbox_core::memory_plan::run_limits(
            self.mem.total_bytes(),
            self.cfg.default_memory_cap,
            req.memory_max_bytes,
            req.memory_request_bytes,
        );
        info.memory_max_bytes = limits.memory_max;
        if own_cgroup {
            self.cg
                .create(&name)
                .map_err(|e| RunError::Start(format!("cgroup create: {}", e.kind())))?;
            if let (Some(max), Some(high)) = (limits.memory_max, limits.memory_high) {
                self.cg
                    .write(&name, "memory.max", &max.to_string())
                    .map_err(|e| fail(&self.cg, e, "memory.max"))?;
                self.cg
                    .write(&name, "memory.high", &high.to_string())
                    .map_err(|e| fail(&self.cg, e, "memory.high"))?;
                // A bounded share of the compressed swap, and one kill for the whole run (a half-killed build left running is
                // worse than a dead one). Best effort: a kernel without swap accounting has neither file.
                if let Some(swap) = limits.memory_swap_max {
                    let _ = self.cg.write(&name, "memory.swap.max", &swap.to_string());
                }
                if limits.oom_group {
                    let _ = self.cg.write(&name, "memory.oom.group", "1");
                }
            }
            self.cg
                .write(
                    &name,
                    "cpu.weight",
                    &req.cpu_weight.unwrap_or(100).to_string(),
                )
                .map_err(|e| fail(&self.cg, e, "cpu.weight"))?;
        }
        let mut child = self
            .spawner
            .spawn(&info.id, req, &limits)
            .map_err(|e| fail(&self.cg, e, "spawn"))?;
        if own_cgroup {
            if let Err(e) = self
                .cg
                .write(&name, "cgroup.procs", &child.pid().to_string())
            {
                let _ = child.kill();
                return Err(fail(&self.cg, e, "move pid into cgroup"));
            }
        }
        if let Err(e) = child.release() {
            let _ = child.kill();
            return Err(fail(&self.cg, e, "release"));
        }
        info.state = RunState::Running;
        info.started_ms = Some(self.clock.now_ms());
        self.active.push(Active {
            info,
            child,
            request_bytes: req.memory_request_bytes,
            prev_cpu: None,
            deadline_ms: req
                .max_runtime_s
                .or(self.cfg.default_max_runtime_s)
                .map(|s| self.clock.now_ms() + s * 1000),
            timed_out: false,
            frozen_since_ms: None,
        });
        Ok(())
    }

    /// Reap finished runs, then admit queued ones in order while the head fits. Returns ids that finished.
    pub fn tick(&mut self) -> Vec<String> {
        let mut finished = Vec::new();
        let now = self.clock.now_ms();
        for note in self.spawner.notes() {
            self.events.push(RunEvent::Backend(note));
        }
        self.retry_adoption(now);
        for a in &mut self.active {
            if !a.timed_out
                && a.frozen_since_ms.is_none()
                && a.deadline_ms.is_some_and(|d| now >= d)
            {
                a.timed_out = true;
                a.info.timed_out = true;
                kill_scope(
                    self.cg.as_ref(),
                    &self.spawner.cgroup_name(&a.info.id),
                    a.child.as_mut(),
                );
                self.events.push(RunEvent::TimedOut(a.info.id.clone()));
            }
        }
        let mut i = 0;
        while i < self.active.len() {
            // a frozen run answers nothing and cannot end; it is looked at again after it is thawed
            if self.active[i].frozen_since_ms.is_some() {
                i += 1;
                continue;
            }
            let code = self.active[i].child.try_wait().ok().flatten();
            if let Some(code) = code {
                let mut a = self.active.remove(i);
                if !self.spawner.applies_limits(&a.info.id) {
                    let _ = self.cg.remove(&self.spawner.cgroup_name(&a.info.id));
                }
                a.info.state = RunState::Exited;
                a.info.ended_ms = Some(now);
                a.info.exit_code = Some(code);
                finished.push(a.info.id.clone());
                self.remember(a.info);
            } else {
                i += 1;
            }
        }
        while let Some(head) = self.queue.front() {
            if self.paused.is_some()
                || self.active.len() >= self.cfg.max_active
                || head.req.memory_request_bytes > self.free_bytes()
            {
                break;
            }
            let Some(q) = self.queue.pop_front() else {
                break;
            };
            if let Err(e) = self.launch(q.info.clone(), &q.req) {
                let mut info = q.info;
                info.state = RunState::Cancelled;
                info.ended_ms = Some(now);
                let _ = e; // the reason is in the incident log kept by the caller
                finished.push(info.id.clone());
                self.remember(info);
            }
        }
        finished
    }

    fn remember(&mut self, info: RunInfo) {
        self.done.push_back(info);
        while self.done.len() > self.cfg.history {
            if let Some(old) = self.done.pop_front() {
                self.spawner.forget(&old.id);
                self.caps.remove(&old.id);
            }
        }
    }

    /// Start a controlled run (see [`RunRequest::require_capability`]): as [`RunManager::start`], and the capability its
    /// starter must show from now on. It is made and bound in the same step, so no request can reach the run before it.
    pub fn start_controlled(
        &mut self,
        mut req: RunRequest,
    ) -> Result<(String, RunState, String), RunError> {
        use ring::rand::SecureRandom;
        let mut raw = [0u8; 32];
        ring::rand::SystemRandom::new()
            .fill(&mut raw)
            .map_err(|_| RunError::Start("no random numbers".into()))?;
        let cap: String = std::iter::once("ozc_".to_string())
            .chain(raw.iter().map(|b| format!("{b:02x}")))
            .collect();
        req.require_capability = true;
        req.cap_sha256 = Some(hex(&cap_hash(&cap)));
        let (id, state) = self.start(req)?;
        self.caps.insert(id.clone(), cap_hash(&cap));
        Ok((id, state, cap))
    }

    /// Whether a request may touch this run: any request for an ordinary run; for a controlled one, only one that shows its
    /// capability (compared as hashes, in constant time). A browser worker's run is controlled by what it is (its
    /// `ozbox.browser` label), not only by a capability this process still remembers: one whose capability is not known here
    /// (the service started again while the run went on) is refused, never treated as an ordinary run.
    pub fn authorized(&self, id: &str, presented: Option<&str>) -> bool {
        match self.caps.get(id) {
            Some(h) => presented.is_some_and(|p| same(h, &cap_hash(p))),
            None => !self.list().iter().any(|r| r.id == id && is_browser(r)),
        }
    }

    /// Stop a run: kill it if running (it is reaped on the next tick), or drop it from the queue.
    pub fn stop(&mut self, id: &str) -> Result<RunState, RunError> {
        if let Some(a) = self.active.iter_mut().find(|a| a.info.id == id) {
            if !kill_scope(
                self.cg.as_ref(),
                &self.spawner.cgroup_name(&a.info.id),
                a.child.as_mut(),
            ) {
                return Err(RunError::Start("kill failed".into()));
            }
            return Ok(RunState::Running);
        }
        if let Some(pos) = self.queue.iter().position(|q| q.info.id == id) {
            if let Some(q) = self.queue.remove(pos) {
                let mut info = q.info;
                info.state = RunState::Cancelled;
                info.ended_ms = Some(self.clock.now_ms());
                self.remember(info);
            }
            return Ok(RunState::Cancelled);
        }
        Err(RunError::NotFound)
    }

    /// Refuse new runs for `for_ms` (at most [`HOLD_MAX_MS`]); a later call moves the end, and it ends by itself.
    pub fn hold_new_runs(&mut self, for_ms: u64) {
        self.hold_until_ms = Some(self.clock.now_ms().saturating_add(for_ms.min(HOLD_MAX_MS)));
    }

    /// End a hold at once (a quiesce that is being started again, or one that found nothing to wait for).
    pub fn release_hold(&mut self) {
        self.hold_until_ms = None;
    }

    /// Drop every queued run (they never started), and say which. Done before running ones are asked to end, so that a
    /// run that ends and frees memory cannot admit the next one.
    pub fn cancel_queued(&mut self) -> Vec<RunInfo> {
        let now = self.clock.now_ms();
        let mut out = Vec::new();
        while let Some(q) = self.queue.pop_front() {
            let mut info = q.info;
            info.state = RunState::Cancelled;
            info.ended_ms = Some(now);
            out.push(info.clone());
            self.remember(info);
        }
        out
    }

    /// The runs going now (not the queue, not the history).
    pub fn running(&self) -> Vec<RunInfo> {
        self.active.iter().map(|a| a.info.clone()).collect()
    }

    /// Ask a running run to end: SIGTERM to the processes in its scope (the direct child when the scope cannot be read).
    /// `Err(NotFound)` when it is not running; `Err(Start)` when nothing could be signalled (the caller kills instead).
    pub fn terminate(&mut self, id: &str) -> Result<(), RunError> {
        let Some(a) = self.active.iter_mut().find(|a| a.info.id == id) else {
            return Err(RunError::NotFound);
        };
        let mut pids: Vec<u32> = self
            .cg
            .read(&scope_name(id), "cgroup.procs")
            .map(|t| t.lines().filter_map(|l| l.trim().parse().ok()).collect())
            .unwrap_or_default();
        if pids.is_empty() {
            pids.push(a.child.pid());
        }
        a.child
            .terminate_pids(&pids)
            .map_err(|_| RunError::Start("could not signal the run".into()))
    }

    /// Append text to a running run's standard input (it must have been started with `keep_stdin_open`), or end its input.
    pub fn send_stdin(&mut self, id: &str, text: &str, close: bool) -> Result<(), RunError> {
        if text.len() > MAX_STDIN || text.contains('\0') {
            return Err(RunError::Invalid(
                "the text is too long or not allowed".into(),
            ));
        }
        let Some(a) = self.active.iter_mut().find(|a| a.info.id == id) else {
            return Err(if self.queue.iter().any(|q| q.info.id == id) {
                RunError::Input("the run has not started yet")
            } else {
                RunError::NotFound
            });
        };
        if !text.is_empty() {
            a.child.send_stdin(text.as_bytes()).map_err(|e| {
                RunError::Input(match e.kind() {
                    io::ErrorKind::WouldBlock => "the agent is not reading its input",
                    _ => "this run does not take more input",
                })
            })?;
        }
        if close {
            a.child.close_stdin();
        }
        Ok(())
    }

    /// Queued first (in order), then running, then recent history.
    pub fn list(&self) -> Vec<RunInfo> {
        self.queue
            .iter()
            .map(|q| q.info.clone())
            .chain(self.active.iter().map(|a| a.info.clone()))
            .chain(self.done.iter().cloned())
            .collect()
    }

    /// A run's output from byte `from`, as whole lines of text (see [`LogChunk`]). A run that is still going gives only
    /// complete lines, so a reader never sees half a line or half a character; a finished one gives everything left,
    /// once its output has had a moment to land after the program exited.
    pub fn read_log(&self, id: &str, from: u64) -> Result<LogChunk, RunError> {
        let info = self
            .list()
            .into_iter()
            .find(|i| i.id == id)
            .ok_or(RunError::NotFound)?;
        let finished = matches!(info.state, RunState::Exited | RunState::Cancelled);
        let settled = finished
            && info
                .ended_ms
                .is_some_and(|e| self.clock.now_ms().saturating_sub(e) >= LOG_SETTLE_MS);
        let bytes = self
            .spawner
            .read_log(id, from, LOG_CHUNK)
            .map_err(|e| RunError::Start(format!("log: {}", e.kind())))?
            .unwrap_or_default();
        let take = whole_text_len(&bytes, settled && bytes.len() < LOG_CHUNK);
        Ok(LogChunk {
            text: String::from_utf8_lossy(&bytes[..take]).into_owned(),
            next: from + take as u64,
            state: info.state,
            exit_code: if settled && take == bytes.len() {
                info.exit_code
            } else {
                None
            },
        })
    }

    /// Pause the runs (ADR 0038 section 4, item 5), and hold the queue back until [`RunManager::resume`].
    ///
    /// [`PauseKind::Freeze`] (a live update): every running run is frozen in place with the cgroup freezer, which needs no
    /// help from the program and costs it nothing but the time. A run that could not be frozen is named in `failed`; the
    /// pause stays in effect, and `resume` thaws what froze.
    /// [`PauseKind::Replace`]: nothing is frozen, because a frozen process cannot move to another machine. The runs that
    /// are going are listed in `running` for the caller's engine to checkpoint, stop and resume on the new machine.
    pub fn pause(&mut self, kind: PauseKind) -> PauseReport {
        let now = self.clock.now_ms();
        self.paused = Some(kind);
        let mut report = PauseReport {
            kind,
            frozen: Vec::new(),
            failed: Vec::new(),
            running: self.active.iter().map(|a| a.info.clone()).collect(),
        };
        if kind == PauseKind::Replace {
            return report;
        }
        for a in &mut self.active {
            if a.frozen_since_ms.is_some() {
                report.frozen.push(a.info.id.clone());
                continue;
            }
            match self.spawner.freeze(&a.info.id) {
                Ok(()) => {
                    a.frozen_since_ms = Some(now);
                    report.frozen.push(a.info.id.clone());
                }
                Err(e) => report
                    .failed
                    .push((a.info.id.clone(), format!("freeze: {}", e.kind()))),
            }
        }
        report
    }

    /// Undo [`RunManager::pause`]: thaw every frozen run (its wall-clock limit moves later by the time it was frozen) and
    /// let the queue go on. If some run cannot be thawed the pause stays, the others are thawed, and those are returned: a
    /// run is never left frozen with nothing saying so.
    pub fn resume(&mut self) -> Result<(), Vec<(String, String)>> {
        let now = self.clock.now_ms();
        let mut failed = Vec::new();
        for a in &mut self.active {
            let Some(since) = a.frozen_since_ms else {
                continue;
            };
            match self.spawner.thaw(&a.info.id) {
                Ok(()) => {
                    if let Some(d) = a.deadline_ms.as_mut() {
                        *d += now.saturating_sub(since);
                    }
                    a.frozen_since_ms = None;
                }
                Err(e) => failed.push((a.info.id.clone(), format!("thaw: {}", e.kind()))),
            }
        }
        if failed.is_empty() {
            self.paused = None;
            Ok(())
        } else {
            Err(failed)
        }
    }

    pub fn paused(&self) -> Option<PauseKind> {
        self.paused
    }

    pub fn is_frozen(&self, id: &str) -> bool {
        self.active
            .iter()
            .any(|a| a.info.id == id && a.frozen_since_ms.is_some())
    }

    /// Take over the runs a previous daemon left going, from their records (see [`Spawner::adopt`]), and the runs that ended
    /// meanwhile, which join the history with their output. A record that did not verify is returned, not adopted.
    pub fn adopt_existing(&mut self) -> AdoptSummary {
        let now = self.clock.now_ms();
        let report = self.spawner.adopt();
        // the box user's manager did not answer (it may simply not be up yet): try again soon, a bounded number of times
        if report.refused.iter().any(|(id, _)| id == "*") {
            self.adopt_retry = Some((now + ADOPT_RETRY_EVERY_MS, 1));
        } else {
            self.adopt_retry = None;
        }
        let mut summary = AdoptSummary {
            refused: report.refused,
            ..AdoptSummary::default()
        };
        let mut ended = Vec::new();
        for r in report.runs {
            if self.list().iter().any(|i| i.id == r.info.id) {
                continue;
            }
            if let Some(h) = r.cap_sha256 {
                self.caps.insert(r.info.id.clone(), h);
            }
            match r.child {
                Some(child) => {
                    summary.adopted += 1;
                    self.active.push(Active {
                        info: r.info,
                        child,
                        request_bytes: r.request_bytes,
                        prev_cpu: None,
                        deadline_ms: r.deadline_ms,
                        timed_out: false,
                        frozen_since_ms: r.frozen.then_some(now),
                    });
                }
                None => {
                    summary.ended += 1;
                    ended.push(r.info);
                }
            }
        }
        ended.sort_by_key(|i| i.started_ms.unwrap_or(i.queued_ms));
        for info in ended {
            self.remember(info);
        }
        summary
    }

    /// Drain pending incident-worthy events (timeouts).
    pub fn take_events(&mut self) -> Vec<RunEvent> {
        std::mem::take(&mut self.events)
    }

    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    pub fn queued_count(&self) -> usize {
        self.queue.len()
    }

    /// Ids of live cgroups, for the OOM watcher.
    pub fn active_scopes(&self) -> Vec<(String, String)> {
        self.active
            .iter()
            .map(|a| (a.info.id.clone(), self.spawner.cgroup_name(&a.info.id)))
            .collect()
    }

    pub fn read_cgroup(&self, scope: &str, file: &str) -> io::Result<String> {
        self.cg.read(scope, file)
    }

    /// Per-run usage from each run's cgroup. CPU is the delta since the previous call (100 = one core).
    pub fn usage(&mut self) -> Vec<RunUsage> {
        let now = self.clock.now_ms();
        let mut out = Vec::new();
        for a in &mut self.active {
            let name = self.spawner.cgroup_name(&a.info.id);
            let mem = self
                .cg
                .read(&name, "memory.current")
                .ok()
                .and_then(|t| parse::parse_cgroup_u64(&t).ok())
                .unwrap_or(0);
            let max = self
                .cg
                .read(&name, "memory.max")
                .ok()
                .and_then(|t| parse::parse_cgroup_limit(&t).ok())
                .flatten();
            let usec = self
                .cg
                .read(&name, "cpu.stat")
                .ok()
                .and_then(|t| parse::parse_cgroup_cpu_usage_usec(&t).ok());
            let mut cpu = 0.0;
            if let Some(u) = usec {
                if let Some((pu, pt)) = a.prev_cpu {
                    let dt_us = now.saturating_sub(pt) * 1000;
                    if dt_us > 0 {
                        cpu = u.saturating_sub(pu) as f64 / dt_us as f64 * 100.0;
                    }
                }
                a.prev_cpu = Some((u, now));
            }
            out.push(RunUsage {
                id: a.info.id.clone(),
                cpu_pct: cpu,
                mem_bytes: mem,
                mem_max_bytes: max,
            });
        }
        out
    }
}

/// Fakes for tests (also used by the API tests).
pub mod testing {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    #[derive(Default)]
    pub struct FakeCgroup {
        pub files: Mutex<BTreeMap<(String, String), String>>,
        pub scopes: Mutex<Vec<String>>,
    }

    impl FakeCgroup {
        pub fn set(&self, name: &str, file: &str, v: &str) {
            if let Ok(mut f) = self.files.lock() {
                f.insert((name.into(), file.into()), v.into());
            }
        }
        pub fn get(&self, name: &str, file: &str) -> Option<String> {
            self.files
                .lock()
                .ok()?
                .get(&(name.to_string(), file.to_string()))
                .cloned()
        }
        pub fn scope_count(&self) -> usize {
            self.scopes.lock().map(|s| s.len()).unwrap_or(0)
        }
    }

    impl CgroupFs for FakeCgroup {
        fn create(&self, name: &str) -> io::Result<()> {
            if let Ok(mut s) = self.scopes.lock() {
                s.push(name.to_string());
            }
            Ok(())
        }
        fn write(&self, name: &str, file: &str, value: &str) -> io::Result<()> {
            self.set(name, file, value);
            Ok(())
        }
        fn read(&self, name: &str, file: &str) -> io::Result<String> {
            self.get(name, file)
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unset"))
        }
        fn remove(&self, name: &str) -> io::Result<()> {
            if let Ok(mut s) = self.scopes.lock() {
                s.retain(|n| n != name);
            }
            Ok(())
        }
    }

    pub struct FakeMemory {
        pub total: Mutex<u64>,
        pub available: Mutex<u64>,
    }

    impl FakeMemory {
        pub fn new(total: u64, available: u64) -> Self {
            Self {
                total: Mutex::new(total),
                available: Mutex::new(available),
            }
        }
        pub fn set_available(&self, v: u64) {
            if let Ok(mut a) = self.available.lock() {
                *a = v;
            }
        }
    }

    impl MemoryProbe for FakeMemory {
        fn total_bytes(&self) -> u64 {
            self.total.lock().map(|v| *v).unwrap_or(0)
        }
        fn available_bytes(&self) -> u64 {
            self.available.lock().map(|v| *v).unwrap_or(0)
        }
    }

    /// The signals asked of children: (pid, pids named).
    pub type Terms = Arc<Mutex<Vec<(u32, Vec<u32>)>>>;

    /// Children that exit when the test says so. `exits` maps pid -> exit code.
    #[derive(Default)]
    pub struct FakeSpawner {
        pub exits: Arc<Mutex<BTreeMap<u32, i32>>>,
        pub next_pid: Mutex<u32>,
        pub spawned: Mutex<Vec<String>>,
        /// Text appended to the standard input of runs kept open, as (pid, text).
        pub writes: Arc<Mutex<Vec<(u32, String)>>>,
        /// Run ids frozen now (see `freeze`/`thaw`), and ids whose freeze or thaw is to fail.
        pub frozen: Mutex<std::collections::BTreeSet<String>>,
        pub fail_freeze: Mutex<std::collections::BTreeSet<String>>,
        /// What `adopt` hands over, once.
        pub to_adopt: Mutex<Option<AdoptReport>>,
        /// Behave like a unit spawner: it sets the limits itself and names the cgroup like a unit.
        pub unit_like: std::sync::atomic::AtomicBool,
        /// The memory plan each spawn was handed, by run id.
        pub limits_seen: Mutex<Vec<(String, ozbox_core::memory_plan::RunLimits)>>,
        /// The signals asked of children, as (pid, pids named).
        pub terms: Terms,
        /// Whether a child ends (code 143) when asked to, as a program that handles SIGTERM does.
        pub obeys_term: Arc<std::sync::atomic::AtomicBool>,
        /// Whether a kill takes time: the child is not gone until the test says it exits (a scope emptied late).
        pub slow_kill: Arc<std::sync::atomic::AtomicBool>,
    }

    impl FakeSpawner {
        pub fn exit(&self, pid: u32, code: i32) {
            if let Ok(mut e) = self.exits.lock() {
                e.insert(pid, code);
            }
        }
    }

    struct FakeChild {
        pid: u32,
        exits: Arc<Mutex<BTreeMap<u32, i32>>>,
        released: bool,
        writes: Arc<Mutex<Vec<(u32, String)>>>,
        keep: bool,
        terms: Terms,
        obeys_term: bool,
        slow_kill: bool,
    }

    impl ChildHandle for FakeChild {
        fn pid(&self) -> u32 {
            self.pid
        }
        fn release(&mut self) -> io::Result<()> {
            self.released = true;
            Ok(())
        }
        fn try_wait(&mut self) -> io::Result<Option<i32>> {
            Ok(self
                .exits
                .lock()
                .ok()
                .and_then(|e| e.get(&self.pid).copied()))
        }
        fn kill(&mut self) -> io::Result<()> {
            if self.slow_kill {
                return Ok(());
            }
            if let Ok(mut e) = self.exits.lock() {
                e.insert(self.pid, 137);
            }
            Ok(())
        }
        fn terminate_pids(&mut self, pids: &[u32]) -> io::Result<()> {
            if let Ok(mut t) = self.terms.lock() {
                t.push((self.pid, pids.to_vec()));
            }
            if self.obeys_term {
                if let Ok(mut e) = self.exits.lock() {
                    e.insert(self.pid, 143);
                }
            }
            Ok(())
        }
        fn send_stdin(&mut self, bytes: &[u8]) -> io::Result<()> {
            if !self.keep {
                return Err(io::Error::from(io::ErrorKind::BrokenPipe));
            }
            if let Ok(mut w) = self.writes.lock() {
                w.push((self.pid, String::from_utf8_lossy(bytes).into_owned()));
            }
            Ok(())
        }
        fn close_stdin(&mut self) {
            self.keep = false;
        }
    }

    impl Spawner for FakeSpawner {
        fn applies_limits(&self, _id: &str) -> bool {
            self.unit_like.load(std::sync::atomic::Ordering::SeqCst)
        }
        fn cgroup_name(&self, id: &str) -> String {
            if self.applies_limits(id) {
                format!("ozbox-run-{id}.service")
            } else {
                scope_name(id)
            }
        }
        fn freeze(&self, id: &str) -> io::Result<()> {
            if self.fail_freeze.lock().is_ok_and(|f| f.contains(id)) {
                return Err(io::Error::other("freezer"));
            }
            if let Ok(mut f) = self.frozen.lock() {
                f.insert(id.to_string());
            }
            Ok(())
        }
        fn thaw(&self, id: &str) -> io::Result<()> {
            if self.fail_freeze.lock().is_ok_and(|f| f.contains(id)) {
                return Err(io::Error::other("freezer"));
            }
            if let Ok(mut f) = self.frozen.lock() {
                f.remove(id);
            }
            Ok(())
        }
        fn adopt(&self) -> AdoptReport {
            self.to_adopt
                .lock()
                .ok()
                .and_then(|mut a| a.take())
                .unwrap_or_default()
        }
        fn spawn(
            &self,
            id: &str,
            req: &RunRequest,
            limits: &ozbox_core::memory_plan::RunLimits,
        ) -> io::Result<Box<dyn ChildHandle>> {
            if let Ok(mut l) = self.limits_seen.lock() {
                l.push((id.to_string(), *limits));
            }
            let pid = {
                let mut n = self
                    .next_pid
                    .lock()
                    .map_err(|_| io::Error::other("poisoned"))?;
                *n += 1;
                1000 + *n
            };
            if let Ok(mut s) = self.spawned.lock() {
                s.push(id.to_string());
            }
            Ok(Box::new(FakeChild {
                pid,
                exits: self.exits.clone(),
                released: false,
                writes: self.writes.clone(),
                keep: req.keep_stdin_open,
                terms: self.terms.clone(),
                obeys_term: self.obeys_term.load(std::sync::atomic::Ordering::SeqCst),
                slow_kill: self.slow_kill.load(std::sync::atomic::Ordering::SeqCst),
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use crate::timeutil::FakeClock;

    const GIB: u64 = 1 << 30;

    struct Rig {
        m: RunManager,
        cg: Arc<FakeCgroup>,
        mem: Arc<FakeMemory>,
        sp: Arc<FakeSpawner>,
        clock: Arc<FakeClock>,
    }

    fn rig(avail: u64, cfg: RunConfig) -> Rig {
        let cg = Arc::new(FakeCgroup::default());
        let mem = Arc::new(FakeMemory::new(16 * GIB, avail));
        let sp = Arc::new(FakeSpawner::default());
        let clock = Arc::new(FakeClock::new(1_794_182_400_000));
        let m = RunManager::new(cfg, cg.clone(), mem.clone(), sp.clone(), clock.clone());
        Rig {
            m,
            cg,
            mem,
            sp,
            clock,
        }
    }

    fn req(gib: u64) -> RunRequest {
        let mut r = RunRequest::new(vec!["/usr/bin/true".into(), "--secret-arg".into()]);
        r.memory_request_bytes = gib * GIB;
        r.memory_max_bytes = Some(gib.max(1) * GIB);
        r
    }

    /// A security review (2026-11-11): a capability lived only in this process's memory and `authorized` let any request
    /// through for a run it had none for. A browser worker's run is now refused without its capability even when the
    /// capability is not known here (as after a restart of the service while the run went on); an ordinary run is not.
    #[test]
    fn a_browser_workers_run_is_never_reached_without_its_capability() {
        let mut r = rig(8 * GIB, RunConfig::default());
        let mut browser = req(1);
        browser.labels.insert(BROWSER_LABEL.into(), "1".into());
        let (id, _, cap) = r.m.start_controlled(browser.clone()).unwrap();
        assert!(r.m.authorized(&id, Some(&cap)));
        assert!(!r.m.authorized(&id, None));
        assert!(!r.m.authorized(&id, Some("ozc_wrong")));
        // the capability is forgotten (a restarted service): the run is still refused, never an ordinary run
        r.m.caps.clear();
        assert!(!r.m.authorized(&id, None));
        assert!(!r.m.authorized(&id, Some(&cap)));
        // a browser-labelled run started without a capability at all is not reachable either
        let (plain_browser, _) = r.m.start(browser).unwrap();
        assert!(!r.m.authorized(&plain_browser, None));
        // an ordinary run is reached as before
        let (ordinary, _) = r.m.start(req(1)).unwrap();
        assert!(r.m.authorized(&ordinary, None));
    }

    #[test]
    fn starts_in_its_own_cgroup_with_limits() {
        let mut r = rig(8 * GIB, RunConfig::default());
        let (id, st) = r.m.start(req(2)).unwrap();
        assert_eq!(st, RunState::Running);
        let n = scope_name(&id);
        assert_eq!(r.cg.get(&n, "memory.max").unwrap(), (2 * GIB).to_string());
        assert_eq!(
            r.cg.get(&n, "memory.high").unwrap(),
            ozbox_core::memory_plan::high_for(2 * GIB).to_string()
        );
        assert_eq!(r.cg.get(&n, "cpu.weight").unwrap(), "100");
        assert_eq!(r.cg.get(&n, "cgroup.procs").unwrap(), "1001");
    }

    #[test]
    fn waits_when_memory_is_short_then_admits_fifo() {
        let mut r = rig(4 * GIB, RunConfig::default());
        let (a, sa) = r.m.start(req(3)).unwrap();
        assert_eq!(sa, RunState::Running);
        // Run `a` has not touched its memory yet, so its 3 GiB stays reserved: only 1 GiB is free.
        let (b, sb) = r.m.start(req(2)).unwrap();
        assert_eq!(sb, RunState::Queued);
        // A small run must not jump the queue (strict FIFO).
        let (c, sc) = r.m.start(req(0)).unwrap();
        assert_eq!(sc, RunState::Queued);
        assert!(r.m.tick().is_empty());
        assert_eq!(r.m.queued_count(), 2);
        // `a` ends; memory is free again.
        r.sp.exit(1001, 0);
        r.mem.set_available(8 * GIB);
        let fin = r.m.tick();
        assert_eq!(fin, vec![a]);
        let ids: Vec<_> =
            r.m.list()
                .into_iter()
                .filter(|i| i.state == RunState::Running)
                .map(|i| i.id)
                .collect();
        assert_eq!(ids, vec![b, c]);
    }

    #[test]
    fn queue_is_bounded_and_oversize_refused() {
        let mut r = rig(
            GIB,
            RunConfig {
                max_queue: 2,
                ..RunConfig::default()
            },
        );
        r.m.start(req(1)).unwrap(); // runs, reserves 1 GiB
        r.m.start(req(1)).unwrap();
        r.m.start(req(1)).unwrap();
        assert_eq!(r.m.start(req(1)), Err(RunError::QueueFull));
        assert_eq!(r.m.start(req(17)), Err(RunError::TooLarge));
    }

    #[test]
    fn stop_kills_running_and_cancels_queued() {
        let mut r = rig(GIB, RunConfig::default());
        let (a, _) = r.m.start(req(1)).unwrap();
        let (b, sb) = r.m.start(req(1)).unwrap();
        assert_eq!(sb, RunState::Queued);
        assert_eq!(r.m.stop(&b), Ok(RunState::Cancelled));
        assert_eq!(r.m.stop("nope"), Err(RunError::NotFound));
        r.m.stop(&a).unwrap();
        assert_eq!(r.m.tick(), vec![a.clone()]);
        let info = r.m.list().into_iter().find(|i| i.id == a).unwrap();
        assert_eq!((info.state, info.exit_code), (RunState::Exited, Some(137)));
        assert_eq!(r.cg.scope_count(), 0);
    }

    #[test]
    fn terminate_signals_the_scope_processes_and_never_kills() {
        let mut r = rig(16 * GIB, RunConfig::default());
        let (a, _) = r.m.start(req(1)).unwrap();
        r.cg.set(&scope_name(&a), "cgroup.procs", "4001\n4002\nnot-a-pid\n");
        r.sp.obeys_term
            .store(true, std::sync::atomic::Ordering::SeqCst);
        // the child was made before the switch: it does not obey, which is the case after a grace
        assert_eq!(r.m.terminate(&a), Ok(()));
        let terms = r.sp.terms.lock().unwrap().clone();
        assert_eq!(terms.len(), 1);
        assert_eq!(
            terms[0].1,
            vec![4001, 4002],
            "the scope's own processes, nothing else"
        );
        assert_eq!(
            r.cg.get(&scope_name(&a), "cgroup.kill"),
            None,
            "terminate never kills the scope"
        );
        assert!(
            r.m.tick().is_empty(),
            "a program that has not ended is still running"
        );
        assert_eq!(r.m.terminate("nope"), Err(RunError::NotFound));
    }

    #[test]
    fn terminate_falls_back_to_the_child_when_the_scope_cannot_be_read() {
        let mut r = rig(16 * GIB, RunConfig::default());
        let (a, _) = r.m.start(req(1)).unwrap();
        r.m.terminate(&a).unwrap();
        let terms = r.sp.terms.lock().unwrap().clone();
        assert_eq!(terms[0].1, vec![terms[0].0], "the direct child");
    }

    #[test]
    fn cancel_queued_runs_before_stopping_so_none_is_admitted() {
        let mut r = rig(GIB, RunConfig::default());
        let (a, _) = r.m.start(req(1)).unwrap();
        let (b, sb) = r.m.start(req(1)).unwrap();
        assert_eq!(sb, RunState::Queued);
        let cancelled = r.m.cancel_queued();
        assert_eq!(
            cancelled.iter().map(|i| i.id.clone()).collect::<Vec<_>>(),
            vec![b.clone()]
        );
        r.m.stop(&a).unwrap();
        r.m.tick();
        assert!(
            r.m.running().is_empty(),
            "the freed memory admitted nothing"
        );
        let info = r.m.list().into_iter().find(|i| i.id == b).unwrap();
        assert_eq!(info.state, RunState::Cancelled);
    }

    #[test]
    fn a_hold_refuses_new_runs_and_ends_by_itself() {
        let mut r = rig(16 * GIB, RunConfig::default());
        r.m.hold_new_runs(60_000);
        assert!(matches!(r.m.start(req(1)), Err(RunError::Input(_))));
        r.clock.advance(59_000);
        assert!(r.m.start(req(1)).is_err());
        r.clock.advance(2_000);
        assert!(
            r.m.start(req(1)).is_ok(),
            "the hold expired without anyone releasing it"
        );
        // never longer than the cap, whatever is asked
        r.m.hold_new_runs(u64::MAX);
        r.clock.advance(HOLD_MAX_MS + 1);
        assert!(r.m.start(req(1)).is_ok());
        r.m.hold_new_runs(60_000);
        r.m.release_hold();
        assert!(r.m.start(req(1)).is_ok());
    }

    #[test]
    fn validation_and_secrecy() {
        let mut r = rig(8 * GIB, RunConfig::default());
        assert!(matches!(
            r.m.start(RunRequest::new(vec![])),
            Err(RunError::Invalid(_))
        ));
        let mut bad = RunRequest::new(vec!["x".into()]);
        bad.env.insert("1BAD".into(), "v".into());
        assert!(matches!(r.m.start(bad), Err(RunError::Invalid(_))));
        let mut rel = RunRequest::new(vec!["x".into()]);
        rel.cwd = Some("relative".into());
        assert!(rel.validate().is_err());

        let mut q = req(1);
        q.env.insert("API_TOKEN".into(), "s3cr3t-value".into());
        assert!(!format!("{q:?}").contains("s3cr3t-value"));
        assert!(!format!("{q:?}").contains("--secret-arg"));
        let (id, _) = r.m.start(q).unwrap();
        let shown = serde_json::to_string(&r.m.list()).unwrap();
        assert!(
            !shown.contains("s3cr3t-value") && !shown.contains("--secret-arg"),
            "{shown}"
        );
        assert!(shown.contains("\"program\":\"true\"") && shown.contains(&id));
    }

    #[test]
    fn usage_reads_the_run_cgroup() {
        let mut r = rig(8 * GIB, RunConfig::default());
        let (id, _) = r.m.start(req(1)).unwrap();
        let n = scope_name(&id);
        r.cg.set(&n, "memory.current", "123456");
        r.cg.set(&n, "cpu.stat", "usage_usec 1000000\n");
        let u = r.m.usage();
        assert_eq!((u[0].mem_bytes, u[0].cpu_pct), (123_456, 0.0));
        assert_eq!(u[0].mem_max_bytes, Some(GIB));
    }

    #[cfg(unix)]
    #[test]
    fn real_spawner_gates_then_runs_argv_without_a_shell() {
        let cg = Arc::new(FakeCgroup::default());
        let mem = Arc::new(FakeMemory::new(16 * GIB, 8 * GIB));
        let sp = Arc::new(StdSpawner {
            log_dir: None,
            log_max_bytes: 1 << 20,
        });
        let mut m = RunManager::new(
            RunConfig::default(),
            cg,
            mem,
            sp,
            Arc::new(crate::timeutil::SystemClock),
        );
        // `$(echo hi)` stays a literal argument: exit 3 only if it was not interpreted.
        let mut rq = RunRequest::new(vec![
            "sh".into(),
            "-c".into(),
            "[ \"$1\" = '$(echo hi)' ] && exit 3; exit 4".into(),
            "sh".into(),
            "$(echo hi)".into(),
        ]);
        rq.env.insert("OZBOX_TEST_ENV".into(), "1".into());
        let (id, st) = m.start(rq).unwrap();
        assert_eq!(st, RunState::Running);
        let mut code = None;
        for _ in 0..200 {
            if !m.tick().is_empty() {
                code = m
                    .list()
                    .into_iter()
                    .find(|i| i.id == id)
                    .and_then(|i| i.exit_code);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        assert_eq!(code, Some(3));
    }

    #[test]
    fn the_default_cap_is_never_lower_than_what_the_run_itself_asked_for() {
        use ozbox_core::memory_plan::{sizing, GIB as G};
        let default = sizing(16 * G).run_max_bytes;
        let mut r = rig(16 * GIB, RunConfig::default());
        let mut rq = req(15);
        rq.memory_max_bytes = None;
        assert!(rq.memory_request_bytes > default);
        let (id, st) = r.m.start(rq).unwrap();
        assert_eq!(st, RunState::Running);
        assert_eq!(
            r.cg.get(&scope_name(&id), "memory.max").unwrap(),
            (15 * GIB).to_string()
        );
    }

    #[test]
    fn a_run_with_no_limit_of_its_own_gets_the_default_cap_from_the_boxs_ram() {
        use ozbox_core::memory_plan::{sizing, GIB as G};
        let want = sizing(16 * G);
        let mut r = rig(8 * GIB, RunConfig::default());
        let mut rq = req(1);
        rq.memory_max_bytes = None;
        let (id, st) = r.m.start(rq).unwrap();
        assert_eq!(st, RunState::Running);
        let n = scope_name(&id);
        // everything but the box's reserve, throttled at 90 %, a bounded share of the compressed swap, killed as one group
        assert_eq!(
            r.cg.get(&n, "memory.max").unwrap(),
            want.run_max_bytes.to_string()
        );
        assert_eq!(
            r.cg.get(&n, "memory.high").unwrap(),
            want.run_high_bytes.to_string()
        );
        assert_eq!(
            r.cg.get(&n, "memory.swap.max").unwrap(),
            want.run_swap_max_bytes.to_string()
        );
        assert_eq!(r.cg.get(&n, "memory.oom.group").unwrap(), "1");
        assert!(r
            .m
            .list()
            .iter()
            .any(|i| i.id == id && i.memory_max_bytes == Some(want.run_max_bytes)));
        // not divided by the number of runs: two runs each get the same cap, admission shares what is free
        let mut rq = req(1);
        rq.memory_max_bytes = None;
        let (id2, _) = r.m.start(rq).unwrap();
        assert_eq!(
            r.cg.get(&scope_name(&id2), "memory.max").unwrap(),
            want.run_max_bytes.to_string()
        );
        // a request's own limit is kept, and the swap share never exceeds it
        let (id3, _) = r.m.start(req(2)).unwrap();
        assert_eq!(
            r.cg.get(&scope_name(&id3), "memory.max").unwrap(),
            (2 * GIB).to_string()
        );
        assert_eq!(
            r.cg.get(&scope_name(&id3), "memory.swap.max").unwrap(),
            (2 * GIB).to_string()
        );
        // a box whose owner chose to run uncapped
        let mut off = rig(
            8 * GIB,
            RunConfig {
                default_memory_cap: false,
                ..RunConfig::default()
            },
        );
        let mut rq = req(1);
        rq.memory_max_bytes = None;
        let (id4, _) = off.m.start(rq).unwrap();
        assert!(off.cg.get(&scope_name(&id4), "memory.max").is_none());
    }

    /// The daemon is protected from the OOM killer and a child inherits its score: a run puts its own back up first.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_real_run_raises_its_own_oom_score_so_the_daemons_protection_is_never_inherited() {
        let d = tempfile::tempdir().unwrap();
        let sp = Arc::new(StdSpawner {
            log_dir: Some(d.path().to_path_buf()),
            log_max_bytes: 1 << 20,
        });
        let mut m = RunManager::new(
            RunConfig::default(),
            Arc::new(FakeCgroup::default()),
            Arc::new(FakeMemory::new(16 * GIB, 8 * GIB)),
            sp,
            Arc::new(crate::timeutil::SystemClock),
        );
        let mut rq = RunRequest::new(vec!["cat".into(), "/proc/self/oom_score_adj".into()]);
        rq.memory_max_bytes = Some(GIB);
        let (id, _) = m.start(rq).unwrap();
        for _ in 0..200 {
            if !m.tick().is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        let log = std::fs::read_to_string(d.path().join(format!("{id}.log"))).unwrap_or_default();
        assert_eq!(log.trim(), "500", "{log}");
    }

    #[test]
    fn a_daemon_that_could_not_reach_the_manager_looks_again_for_the_runs_it_left_going() {
        let mut r = rig(8 * GIB, RunConfig::default());
        *r.sp.to_adopt.lock().unwrap() = Some(AdoptReport {
            runs: vec![],
            refused: vec![(
                "*".into(),
                "the box user's service manager did not answer".into(),
            )],
        });
        let first = r.m.adopt_existing();
        assert!(first.refused.iter().any(|(id, _)| id == "*"));
        // the manager comes up, and a run the previous daemon left is there to be found
        let info = RunInfo {
            id: "old1".into(),
            state: RunState::Exited,
            program: "x".into(),
            labels: BTreeMap::new(),
            memory_request_bytes: 0,
            memory_max_bytes: None,
            queued_ms: 0,
            started_ms: Some(0),
            ended_ms: Some(1),
            exit_code: Some(0),
            timed_out: false,
        };
        *r.sp.to_adopt.lock().unwrap() = Some(AdoptReport {
            runs: vec![AdoptedRun {
                info,
                request_bytes: 0,
                deadline_ms: None,
                cap_sha256: None,
                child: None,
                frozen: false,
            }],
            refused: vec![],
        });
        // not before the retry is due
        r.m.tick();
        assert!(r.m.list().is_empty());
        r.clock.advance(ADOPT_RETRY_EVERY_MS);
        r.m.tick();
        assert!(r.m.list().iter().any(|i| i.id == "old1"));
        assert!(r
            .m
            .take_events()
            .iter()
            .any(|e| matches!(e, RunEvent::Backend(t) if t.contains("took over"))));
        // and it stops looking once it has been answered
        assert!(r.m.adopt_retry.is_none());
    }

    #[test]
    fn fs_cgroup_rejects_path_tricks() {
        let d = tempfile::tempdir().unwrap();
        let cg = FsCgroup::new(d.path());
        assert!(cg.create("../escape").is_err());
        assert!(cg.create("run-abc.scope").is_ok());
        cg.write("run-abc.scope", "memory.max", "5").unwrap();
        assert_eq!(cg.read("run-abc.scope", "memory.max").unwrap(), "5");
    }

    #[test]
    fn wall_clock_limit_kills_the_scope_and_raises_an_event() {
        let mut r = rig(8 * GIB, RunConfig::default());
        let mut q = req(1);
        q.max_runtime_s = Some(60);
        let (id, _) = r.m.start(q).unwrap();
        r.clock.advance(59_000);
        assert!(r.m.tick().is_empty() && r.m.take_events().is_empty());
        r.clock.advance(2_000);
        assert_eq!(r.m.tick(), vec![id.clone()]);
        assert_eq!(r.m.take_events(), vec![RunEvent::TimedOut(id.clone())]);
        assert!(r.m.take_events().is_empty());
        assert_eq!(
            r.cg.get(&scope_name(&id), "cgroup.kill").as_deref(),
            Some("1")
        );
        let info = r.m.list().into_iter().find(|i| i.id == id).unwrap();
        assert!(info.timed_out && info.state == RunState::Exited);
        let mut bad = req(1);
        bad.max_runtime_s = Some(0);
        assert!(bad.validate().is_err());
    }

    #[test]
    fn default_limit_applies_when_the_request_has_none() {
        let cfg = RunConfig {
            default_max_runtime_s: Some(10),
            ..RunConfig::default()
        };
        let mut r = rig(8 * GIB, cfg);
        let (id, _) = r.m.start(req(1)).unwrap();
        r.clock.advance(11_000);
        assert_eq!(r.m.tick(), vec![id]);
    }

    #[test]
    fn stop_writes_cgroup_kill() {
        let mut r = rig(8 * GIB, RunConfig::default());
        let (id, _) = r.m.start(req(1)).unwrap();
        r.m.stop(&id).unwrap();
        assert_eq!(
            r.cg.get(&scope_name(&id), "cgroup.kill").as_deref(),
            Some("1")
        );
    }

    #[test]
    fn self_cgroup_and_delegation() {
        assert_eq!(
            parse_self_cgroup("0::/system.slice/ozboxd.service\n").as_deref(),
            Some("/system.slice/ozboxd.service")
        );
        assert_eq!(parse_self_cgroup("12:memory:/x\n"), None);
        assert_eq!(parse_self_cgroup("0::/a/../b"), None);

        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("system.slice/ozboxd.service")).unwrap();
        let cg = FsCgroup::delegated(d.path(), "0::/system.slice/ozboxd.service\n", 4242).unwrap();
        // the daemon moved into a leaf; controllers were enabled on the service cgroup; runs are its children
        let svc = d.path().join("system.slice/ozboxd.service");
        assert_eq!(
            std::fs::read_to_string(svc.join("daemon/cgroup.procs")).unwrap(),
            "4242"
        );
        assert_eq!(
            std::fs::read_to_string(svc.join("cgroup.subtree_control")).unwrap(),
            "+memory +cpu"
        );
        assert_eq!(cg.parent(), svc);
        // already in a leaf (systemd DelegateSubgroup): the parent is the service cgroup, no second leaf
        let d2 = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d2.path().join("system.slice/ozboxd.service/daemon")).unwrap();
        let cg2 =
            FsCgroup::delegated(d2.path(), "0::/system.slice/ozboxd.service/daemon\n", 1).unwrap();
        assert_eq!(cg2.parent(), d2.path().join("system.slice/ozboxd.service"));
        assert!(FsCgroup::delegated(d.path(), "nonsense", 1).is_err());
    }

    #[test]
    fn capped_log_truncates_with_one_marker() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("l.log");
        let f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&p)
            .unwrap();
        let mut l = CappedLog::new(f, 10);
        l.write(b"12345");
        l.write(b"6789012345"); // crosses the cap
        l.write(b"more");
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(
            text.starts_with("1234567890\n[ozbox: output truncated at 10 bytes]"),
            "{text}"
        );
        assert_eq!(text.matches("truncated").count(), 1);
        assert!(!text.contains("more"));
    }

    #[cfg(unix)]
    #[test]
    fn real_spawner_caps_logs_nulls_stdin_and_forgets() {
        let d = tempfile::tempdir().unwrap();
        let sp = Arc::new(StdSpawner {
            log_dir: Some(d.path().to_path_buf()),
            log_max_bytes: 100,
        });
        let cg = Arc::new(FakeCgroup::default());
        let mem = Arc::new(FakeMemory::new(16 * GIB, 8 * GIB));
        let mut m = RunManager::new(
            RunConfig {
                history: 1,
                ..RunConfig::default()
            },
            cg,
            mem,
            sp.clone(),
            Arc::new(crate::timeutil::SystemClock),
        );
        // 1 KiB of output, then reads stdin: it must see EOF immediately (/dev/null), not hang.
        let script = "head -c 1024 /dev/zero | tr '\\0' x; cat >/dev/null; exit 7";
        let (id, _) = m
            .start(RunRequest::new(vec![
                "sh".into(),
                "-c".into(),
                script.into(),
            ]))
            .unwrap();
        let mut code = None;
        for _ in 0..200 {
            if !m.tick().is_empty() {
                code = m
                    .list()
                    .into_iter()
                    .find(|i| i.id == id)
                    .and_then(|i| i.exit_code);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        assert_eq!(code, Some(7));
        std::thread::sleep(std::time::Duration::from_millis(100));
        let log = std::fs::read_to_string(d.path().join(format!("{id}.log"))).unwrap();
        assert!(
            log.len() < 200 && log.contains("output truncated at 100 bytes"),
            "{}",
            log.len()
        );
        // a second finished run pushes the first out of the 1-deep history: its log goes too
        let (id2, _) = m.start(RunRequest::new(vec!["true".into()])).unwrap();
        for _ in 0..200 {
            if !m.tick().is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        let _ = id2;
        assert!(!d.path().join(format!("{id}.log")).exists());
    }
    #[test]
    fn whole_text_never_returns_half_a_line_or_half_a_character() {
        assert_eq!(whole_text_len(b"one\ntw", false), 4);
        assert_eq!(whole_text_len(b"one\ntw", true), 6);
        assert_eq!(whole_text_len(b"no newline yet", false), 0);
        assert_eq!(whole_text_len(b"", false), 0);
        // a full chunk with no newline is cut at the last whole character
        let mut long = "\u{e9}".repeat(LOG_CHUNK / 2).into_bytes();
        long.push(0xc3);
        long.truncate(LOG_CHUNK);
        let cut = whole_text_len(&long, false);
        assert!(std::str::from_utf8(&long[..cut]).is_ok() && cut >= LOG_CHUNK - 1);
    }

    #[cfg(unix)]
    #[test]
    fn a_run_is_fed_its_text_on_standard_input_and_its_output_is_read_back_in_whole_lines() {
        let d = tempfile::tempdir().unwrap();
        let sp = Arc::new(StdSpawner {
            log_dir: Some(d.path().to_path_buf()),
            log_max_bytes: 1 << 20,
        });
        let clock = Arc::new(FakeClock::new(1_794_182_400_000));
        let mut m = RunManager::new(
            RunConfig::default(),
            Arc::new(FakeCgroup::default()),
            Arc::new(FakeMemory::new(16 * GIB, 8 * GIB)),
            sp,
            clock.clone(),
        );
        // the text is on standard input, not in the arguments: the program prints what it read, then exits 6
        let mut rq = RunRequest::new(vec![
            "sh".into(),
            "-c".into(),
            "cat; echo; echo done; exit 6".into(),
        ]);
        rq.stdin = Some("first line\nsecond line".into());
        assert!(!format!("{rq:?}").contains("first line"));
        let (id, _) = m.start(rq).unwrap();
        let mut finished = false;
        for _ in 0..200 {
            if !m.tick().is_empty() {
                finished = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        assert!(finished);
        // just after it exits the output may still be landing: no end is reported yet
        let early = m.read_log(&id, 0).unwrap();
        assert_eq!(early.exit_code, None);
        clock.advance(1000);
        std::thread::sleep(std::time::Duration::from_millis(100));
        let all = m.read_log(&id, 0).unwrap();
        assert_eq!(all.text, "first line\nsecond line\ndone\n");
        assert_eq!(all.exit_code, Some(6));
        assert_eq!(all.next, all.text.len() as u64);
        // reading on from where it stopped gives nothing more, and an unknown run is refused
        let rest = m.read_log(&id, all.next).unwrap();
        assert!(rest.text.is_empty() && rest.exit_code == Some(6));
        assert_eq!(m.read_log("nope", 0), Err(RunError::NotFound));
    }

    #[test]
    fn a_stdin_text_that_is_too_long_is_refused() {
        let mut rq = RunRequest::new(vec!["true".into()]);
        rq.stdin = Some("x".repeat(MAX_STDIN + 1));
        assert!(matches!(rq.validate(), Err(RunError::Invalid(_))));
        rq.stdin = Some("x".repeat(MAX_STDIN));
        assert!(rq.validate().is_ok());
    }

    #[test]
    fn a_kept_open_run_takes_more_input_and_a_closed_or_plain_one_refuses_it() {
        let mut r = rig(8 * GIB, RunConfig::default());
        let mut rq = req(1);
        rq.stdin = Some("first".into());
        rq.keep_stdin_open = true;
        let (id, _) = r.m.start(rq).unwrap();
        r.m.send_stdin(&id, "second\n", false).unwrap();
        assert_eq!(r.sp.writes.lock().unwrap().len(), 1);
        assert_eq!(r.m.send_stdin("nope", "x", false), Err(RunError::NotFound));
        assert!(matches!(
            r.m.send_stdin(&id, &"x".repeat(MAX_STDIN + 1), false),
            Err(RunError::Invalid(_))
        ));
        r.m.send_stdin(&id, "", true).unwrap();
        assert!(matches!(
            r.m.send_stdin(&id, "late", false),
            Err(RunError::Input(_))
        ));
        // a run that was not kept open never takes input
        let mut plain = req(1);
        plain.stdin = Some("p".into());
        let (pid, _) = r.m.start(plain).unwrap();
        assert!(matches!(
            r.m.send_stdin(&pid, "x", false),
            Err(RunError::Input(_))
        ));
        // keeping the input open needs a first text
        let mut bad = req(1);
        bad.keep_stdin_open = true;
        assert!(matches!(bad.validate(), Err(RunError::Invalid(_))));
    }

    #[cfg(unix)]
    #[test]
    fn a_real_kept_open_run_reads_lines_sent_later_and_sees_end_of_file_when_closed() {
        let d = tempfile::tempdir().unwrap();
        let sp = Arc::new(StdSpawner {
            log_dir: Some(d.path().to_path_buf()),
            log_max_bytes: 1 << 20,
        });
        let clock = Arc::new(FakeClock::new(1_794_182_400_000));
        let mut m = RunManager::new(
            RunConfig::default(),
            Arc::new(FakeCgroup::default()),
            Arc::new(FakeMemory::new(16 * GIB, 8 * GIB)),
            sp,
            clock.clone(),
        );
        let mut rq = RunRequest::new(vec![
            "sh".into(),
            "-c".into(),
            "while read l; do echo got:$l; done; echo eof".into(),
        ]);
        rq.stdin = Some("one\n".into());
        rq.keep_stdin_open = true;
        let (id, _) = m.start(rq).unwrap();
        m.send_stdin(&id, "two\n", false).unwrap();
        m.send_stdin(&id, "-n -e three\n", true).unwrap();
        for _ in 0..200 {
            if !m.tick().is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        clock.advance(1000);
        std::thread::sleep(std::time::Duration::from_millis(100));
        let all = m.read_log(&id, 0).unwrap();
        assert_eq!(all.text, "got:one\ngot:two\ngot:-n -e three\neof\n");
    }
}
