//! A box's own daemon, as the dashboard sees it: live and historical usage, the self-test and the incident history.
//!
//! The dashboard never talks to a box. It talks to this trait. A real provider's boxes are reached by
//! [`super::transport::SshAgent`], which forwards the daemon's Unix socket over the provider's SSH route; the demo
//! provider answers from [`SimulatedAgent`]. The shapes mirror what the daemon returns.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ozboxd::files::{FilesConfig, FilesService};
use ozboxd::timeutil::SystemClock;

use ozbox_core::{BoxRecord, MetricsSample};
use serde::{Deserialize, Serialize};

use super::metrics_sim;

pub use ozboxd::files::{Body as FileBody, Input as FileInput, Reply as FileReply};

/// A byte stream to a loopback port on a box (the IDE or the desktop), split into its two halves so a relay can move
/// each way on its own thread. `keep` is held for as long as the stream lives.
pub struct Conn {
    pub read: Box<dyn std::io::Read + Send>,
    pub write: Box<dyn std::io::Write + Send>,
    pub keep: Option<Box<dyn Send>>,
}

impl Conn {
    pub fn from_tcp(s: std::net::TcpStream) -> std::io::Result<Self> {
        let r = s.try_clone()?;
        Ok(Self {
            read: Box::new(r),
            write: Box::new(s),
            keep: None,
        })
    }

    #[cfg(unix)]
    pub fn from_unix(
        s: std::os::unix::net::UnixStream,
        keep: Option<Box<dyn Send>>,
    ) -> std::io::Result<Self> {
        let r = s.try_clone()?;
        Ok(Self {
            read: Box::new(r),
            write: Box::new(s),
            keep,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Outcome {
    Pass,
    Fail {
        step: String,
        reason: String,
    },
    /// Could not be verified from inside the box. Never shown as a pass.
    Unknown {
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Check {
    pub name: String,
    #[serde(flatten)]
    pub outcome: Outcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelfTest {
    pub ts_ms: u64,
    pub ok: bool,
    pub all_verified: bool,
    pub checks: Vec<Check>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Incident {
    pub ts_ms: u64,
    pub kind: String,
    pub detail: String,
}

/// What the box's daemon says after saving work in progress (`POST /v1/checkpoint`): counts and per-repo failures only,
/// never file names or contents.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CheckpointOutcome {
    #[serde(default)]
    pub repos_scanned: usize,
    #[serde(default)]
    pub errors: Vec<String>,
    /// The `wip/` branch written in each repository that had unsaved work (names only).
    #[serde(default)]
    pub branches: Vec<CheckpointBranch>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointBranch {
    /// The repository's path relative to the box's repositories folder.
    pub repo: String,
    pub branch: String,
}

/// What a box's own files say about its image, read over SSH without the daemon: the marker the image build writes
/// (`/etc/ozbox/image-release`) and whether `/usr/local/bin/ozboxd` is there. Lets `ozbox upgrade` say "this image has no
/// agent" at once instead of waiting for an agent that cannot exist.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ImageAgent {
    /// The image wrote its marker: this machine came from an Oz image.
    pub from_image: bool,
    pub image_version: Option<String>,
    /// The agent program is installed.
    pub agent_present: bool,
    /// The machine's architecture as the release names it (`amd64` or `arm64`), when it said.
    pub arch: Option<String>,
    /// What the machine says it recorded at its first boot (`/etc/ozbox/first-boot`, root-owned). A cross-check only: the
    /// answer travels through the box user's shell, so it is never trusted to say a box is current (see `run::upgrade`).
    pub first_boot: BoxFirstBoot,
}

/// The box's own answer about its first boot.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum BoxFirstBoot {
    /// No record (a machine made before the record existed, a first boot cut short, or none given).
    #[default]
    Unrecorded,
    /// Exactly one well-formed record.
    Recorded(String),
    /// More than one record line, or one that is not a hash: the answer cannot be taken at its word.
    Malformed,
}

/// The remote command that reads it: fixed text, no input from anywhere. The `sh` it starts has an empty environment and
/// absolute paths, but the command still travels through the box user's own shell (whose rc files live on /work), and
/// that shell can print around it, or even replace the whole answer. So the answer is never an authority: the parser treats
/// more than one record line as malformed, and the provider's record decides (the box can only ask for a repair).
pub const IMAGE_AGENT_COMMAND: &str = "exec /usr/bin/env -i PATH=/usr/bin:/bin /bin/sh -c 'cat /etc/ozbox/image-release 2>/dev/null; cat /etc/ozbox/first-boot 2>/dev/null; if [ -x /usr/local/bin/ozboxd ]; then echo ozboxd=present; else echo ozboxd=absent; fi; echo arch=$(uname -m)'";

/// Read the answer of [`IMAGE_AGENT_COMMAND`]. `None` when it holds no `ozboxd=` line (so nothing can be said).
pub fn parse_image_agent(output: &str) -> Option<ImageAgent> {
    let mut out = ImageAgent::default();
    let mut verdict = None;
    let mut records = 0usize;
    for line in output.lines() {
        match line.trim().split_once('=') {
            Some(("ozboxd", v)) => verdict = Some(v == "present"),
            Some(("image_version", v)) => {
                out.from_image = true;
                out.image_version = Some(v.chars().filter(|c| !c.is_control()).take(40).collect());
            }
            Some(("ozboxd_sha256", _)) => out.from_image = true,
            Some(("first_boot_sha256", v)) => {
                records += 1;
                out.first_boot = match (records, v.trim()) {
                    (1, "") => BoxFirstBoot::Unrecorded,
                    (1, h) if ozbox_core::infra::is_sha256(h) => {
                        BoxFirstBoot::Recorded(h.to_string())
                    }
                    _ => BoxFirstBoot::Malformed,
                };
            }
            Some(("arch", v)) => {
                out.arch = match v {
                    "x86_64" | "amd64" => Some("amd64".into()),
                    "aarch64" | "arm64" => Some("arm64".into()),
                    _ => None,
                }
            }
            _ => {}
        }
    }
    // the shared reader of the image's record (the dashboard installer reads it the same way): a one-line record from the
    // first images, or a record that only names hashes, still says the machine is from an image
    let record = ozbox_core::release::parse_image_release(output);
    out.from_image |= record.present;
    if out.image_version.is_none() {
        out.image_version = record.version;
    }
    out.agent_present = verdict?;
    Some(out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentError {
    /// The box's daemon cannot be reached from here. The text says why and is safe to show.
    Unreachable(String),
    /// This kind of server cannot reach a daemon at all (no transport on this system).
    Unsupported(String),
}

/// What a request that was already written to the box's socket says when it then fails. Anything else (the socket missing, a
/// refused connection, a write that failed) means nothing was sent.
pub const SENT_THEN_FAILED: &[&str] = &[
    "the box's agent did not answer in time",
    "the box's agent answered with too much data",
    "the box's agent answered with something that is not HTTP",
    "the box's agent answered with data that is not understood",
];

impl AgentError {
    /// The request may have reached the box before this failure (it was sent and the answer was lost or unreadable).
    pub fn may_have_been_sent(&self) -> bool {
        matches!(self, AgentError::Unreachable(m) if SENT_THEN_FAILED.contains(&m.as_str()))
    }
}

impl std::fmt::Display for AgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (Self::Unreachable(m) | Self::Unsupported(m)) = self;
        f.write_str(m)
    }
}

impl std::error::Error for AgentError {}

pub trait BoxAgent: Send + Sync {
    /// The latest sample.
    fn metrics_now(&self, rec: &BoxRecord, now_ms: u64) -> Result<MetricsSample, AgentError>;
    /// Samples from `from_ms` to `to_ms` at `step_ms` spacing, oldest first.
    fn metrics_series(
        &self,
        rec: &BoxRecord,
        from_ms: u64,
        to_ms: u64,
        step_ms: u64,
    ) -> Result<Vec<MetricsSample>, AgentError>;
    /// Run the self-test now.
    fn selftest(&self, rec: &BoxRecord, now_ms: u64) -> Result<SelfTest, AgentError>;
    /// Ask the box to save its work in progress (git checkpoint branches) now. Used before a box is stopped on purpose.
    fn checkpoint(&self, _rec: &BoxRecord) -> Result<CheckpointOutcome, AgentError> {
        Err(AgentError::Unsupported(NoTransport::REASON.into()))
    }
    /// A run's pause: the same, but the local `wip/` branch the resume needs is never pushed unless the box was set up to push
    /// on stop. An agent with no such distinction answers as [`Self::checkpoint`].
    fn checkpoint_for_run(&self, rec: &BoxRecord) -> Result<CheckpointOutcome, AgentError> {
        self.checkpoint(rec)
    }
    /// One call to the box daemon's quiesce service (`/v1/quiesce`): `POST` starts getting the box ready for a stop that is
    /// coming on purpose (runs end cleanly, uncommitted work is snapshotted), `GET` reads where it is, `DELETE` ends the
    /// hold on new runs. The daemon's answer, whatever its status (an agent that predates it answers 404); only a box that
    /// cannot be reached is an error.
    fn quiesce_call(
        &self,
        _rec: &BoxRecord,
        _method: &str,
        _body: &[u8],
    ) -> Result<(u16, serde_json::Value), AgentError> {
        Err(AgentError::Unsupported(NoTransport::REASON.into()))
    }
    /// What the box's files say about its image and agent program, without the daemon (see [`ImageAgent`]).
    fn image_agent(&self, _rec: &BoxRecord) -> Result<ImageAgent, AgentError> {
        Err(AgentError::Unsupported(NoTransport::REASON.into()))
    }
    /// What the box's secrets service last said about itself (`/run/ozbox-secrets/state`, see `secrets_state`), and whether
    /// its unit is active, over the same route as [`BoxAgent::image_agent`]. `Ok((None, _))`: the service has written no
    /// state (an older box, or one whose service never ran).
    fn secrets_state(
        &self,
        _rec: &BoxRecord,
    ) -> Result<(Option<crate::secrets_state::State>, bool), AgentError> {
        Err(AgentError::Unsupported(NoTransport::REASON.into()))
    }
    /// Ask the box's root helper for one allow-listed action (`ozbox-admin-request`), no daemon needed. `request` is the
    /// action and its arguments as plain words. Returns whether it succeeded and what the helper printed.
    fn admin(&self, _rec: &BoxRecord, _request: &str) -> Result<(bool, String), AgentError> {
        Err(AgentError::Unsupported(NoTransport::REASON.into()))
    }
    /// The last self-test result, without running one (used by the alert loop). `None` = none yet.
    fn selftest_last(&self, rec: &BoxRecord, now_ms: u64) -> Result<Option<SelfTest>, AgentError> {
        self.selftest(rec, now_ms).map(Some)
    }
    fn incidents(
        &self,
        rec: &BoxRecord,
        since_ms: u64,
        now_ms: u64,
    ) -> Result<Vec<Incident>, AgentError>;
    /// Called every second or so by the server loop: close what is idle.
    fn housekeeping(&self, _now_ms: u64) {}
    /// One call to the box's tool installer (`/v1/tools/<segments>`). Returns the daemon's status and JSON answer, whatever
    /// the status; only a box that cannot be reached is an error.
    fn tools(
        &self,
        _rec: &BoxRecord,
        _method: &str,
        _segments: &[&str],
        _body: &[u8],
    ) -> Result<(u16, serde_json::Value), AgentError> {
        Err(AgentError::Unsupported(NoTransport::REASON.into()))
    }
    /// One request to the box's local-AI service (`action` `list` or `pull`, with `runtime` and `model`): the models an
    /// Ollama or vLLM server on the box holds, or pulling one onto `/work`. The daemon's JSON answer.
    fn local_ai(
        &self,
        _rec: &BoxRecord,
        _request: &serde_json::Value,
    ) -> Result<serde_json::Value, AgentError> {
        Err(AgentError::Unsupported(
            "this box's daemon does not manage local models yet".into(),
        ))
    }
    /// One call to the box daemon's run API: `sub` is what follows `/v1/runs` (empty to start a run or list them,
    /// `/<id>` to stop one, `/<id>/log?from=<byte>` to read its output). The daemon's answer, whatever its status; only a
    /// box that cannot be reached is an error. The body may carry a run's environment: it is never logged or kept.
    fn runs(
        &self,
        _rec: &BoxRecord,
        _method: &str,
        _sub: &str,
        _body: &[u8],
    ) -> Result<(u16, serde_json::Value), AgentError> {
        Err(AgentError::Unsupported(NoTransport::REASON.into()))
    }
    /// As [`BoxAgent::runs`], for a controlled run: the call shows the run's capability, which the daemon asks for before it
    /// gives the run input, its output or a stop. The capability travels in a header, never in a path or a log. A
    /// connection that cannot carry it refuses, so a controlled run is never driven without it.
    fn runs_controlled(
        &self,
        _rec: &BoxRecord,
        _method: &str,
        _sub: &str,
        _body: &[u8],
        _capability: &str,
    ) -> Result<(u16, serde_json::Value), AgentError> {
        Err(AgentError::Unsupported(
            "this connection to the box cannot drive a controlled run".into(),
        ))
    }
    /// One call to the box's coding-agent routes: `/v1/agent-sessions...` (the agents running in the person's terminals) or
    /// `/v1/agent-events...` (what agents report). The daemon's answer, whatever its status; only a box that cannot be
    /// reached is an error.
    fn agent_call(
        &self,
        _rec: &BoxRecord,
        _method: &str,
        _path: &str,
        _body: &[u8],
    ) -> Result<(u16, serde_json::Value), AgentError> {
        Err(AgentError::Unsupported(NoTransport::REASON.into()))
    }
    /// Make `port` on this computer's loopback address reachable on the box's own loopback address, at the same number,
    /// through the connection that is already open to the box (a reverse forward). It opens no port on the box that
    /// anything but the box itself can reach (ADR 0005). Fails if the box's port is already taken.
    fn reverse_forward(&self, _rec: &BoxRecord, _port: u16) -> Result<(), AgentError> {
        Err(AgentError::Unsupported(NoTransport::REASON.into()))
    }
    /// One call to the box's backup API (`sub` is the path after `/v1/backup`, for example `/status`). The daemon's
    /// answer, whatever its status; only a box that cannot be reached is an error.
    fn restic(
        &self,
        _rec: &BoxRecord,
        _method: &str,
        _sub: &str,
        _body: &[u8],
    ) -> Result<(u16, serde_json::Value), AgentError> {
        Err(AgentError::Unsupported(NoTransport::REASON.into()))
    }
    /// One call to the box's file API (`path` is `/v1/files/...`). The shape is the daemon's, whichever transport.
    fn files(
        &self,
        _rec: &BoxRecord,
        _method: &str,
        _path: &str,
        _query: &BTreeMap<String, String>,
        _input: FileInput<'_>,
    ) -> Result<FileReply, AgentError> {
        Err(AgentError::Unsupported(NoTransport::REASON.into()))
    }
    /// The demo box's private folder (its `home` and `state`), so a test can do to it what the box user could.
    #[cfg(test)]
    fn demo_box_dir(&self, _box_name: &str) -> Option<PathBuf> {
        None
    }
    /// Can this dashboard put a skill on a box's disk, or take one off? Only a dashboard that runs on the box has the socket
    /// that carries it; any other reaches the box socket, which refuses both. The page says so before it offers the choice.
    fn skill_writes(&self) -> bool {
        false
    }
    /// One call to the box's skills API (`sub` is what follows `/v1/skills`: empty to list, `/<name>` to put or take away one).
    /// The daemon's answer, whatever its status; only a box that cannot be reached is an error. A daemon from before this
    /// existed answers `501` with the code `agent_too_old`.
    fn skills(
        &self,
        _rec: &BoxRecord,
        _method: &str,
        _sub: &str,
        _body: &[u8],
    ) -> Result<(u16, serde_json::Value), AgentError> {
        Err(AgentError::Unsupported(NoTransport::REASON.into()))
    }
    /// A stream to a loopback `port` on the box, over the same outbound route as everything else. A forward that has
    /// dropped is rebuilt here, so the next call works.
    fn connect_tcp(&self, _rec: &BoxRecord, _port: u16) -> Result<Conn, AgentError> {
        Err(AgentError::Unsupported(NoTransport::REASON.into()))
    }
    /// What the box's IDE and desktop services are doing (`ozbox ide`, `ozbox desktop`).
    fn code_status(&self, _rec: &BoxRecord) -> Result<crate::code::BoxCode, AgentError> {
        Err(AgentError::Unsupported(NoTransport::REASON.into()))
    }
    /// What a person has running on the box: tmux sessions, coding agents, dev servers (`ozbox ps`).
    fn code_procs(&self, _rec: &BoxRecord) -> Result<crate::code::procs::Procs, AgentError> {
        Err(AgentError::Unsupported(NoTransport::REASON.into()))
    }
    /// Stop one session or one agent or server process of the box user's.
    fn code_stop(
        &self,
        _rec: &BoxRecord,
        _stop: &crate::code::procs::Stop,
    ) -> Result<(), AgentError> {
        Err(AgentError::Unsupported(NoTransport::REASON.into()))
    }
    /// Set a service up and start it, or stop it and take it away. The error text is safe to show.
    fn code_change(
        &self,
        _rec: &BoxRecord,
        _change: &crate::code::Change,
    ) -> Result<(), AgentError> {
        Err(AgentError::Unsupported(NoTransport::REASON.into()))
    }
    /// A connection to the box's terminal endpoint, past the upgrade (see `ozboxd::terminal` for the frames).
    #[cfg(unix)]
    fn terminal(
        &self,
        _rec: &BoxRecord,
        _cols: u16,
        _rows: u16,
        _session: Option<&str>,
    ) -> Result<super::terminal::Conn, AgentError> {
        Err(AgentError::Unsupported(NoTransport::REASON.into()))
    }
}

/// What a server gets where no transport exists.
pub struct NoTransport;

impl NoTransport {
    pub const REASON: &'static str =
        "Reaching a box's agent needs SSH forwarding, which is not available on this system.";
}

impl BoxAgent for NoTransport {
    fn metrics_now(&self, _: &BoxRecord, _: u64) -> Result<MetricsSample, AgentError> {
        Err(AgentError::Unsupported(Self::REASON.into()))
    }
    fn metrics_series(
        &self,
        _: &BoxRecord,
        _: u64,
        _: u64,
        _: u64,
    ) -> Result<Vec<MetricsSample>, AgentError> {
        Err(AgentError::Unsupported(Self::REASON.into()))
    }
    fn selftest(&self, _: &BoxRecord, _: u64) -> Result<SelfTest, AgentError> {
        Err(AgentError::Unsupported(Self::REASON.into()))
    }
    fn incidents(&self, _: &BoxRecord, _: u64, _: u64) -> Result<Vec<Incident>, AgentError> {
        Err(AgentError::Unsupported(Self::REASON.into()))
    }
}

const CHECKS: [&str; 6] = [
    "work disk mounted",
    "work disk writable",
    "disk headroom",
    "tools present",
    "tunnels up",
    "sample run starts",
];

/// Deterministic demo answers. Label `sim_profile`: `failing` fails the tunnel check, `unverified` reports one check
/// as unknown; anything else passes. Incidents are a fixed short history for the box.
pub struct SimulatedAgent {
    /// This computer is a box. Then the demo must not touch it: a terminal, files or a stand-in server would be real
    /// programs and real folders on the box, labelled as demo (see `serve/no_simulation.rs`).
    host_is_box: bool,
    base: PathBuf,
    files: Mutex<HashMap<String, Arc<FilesService>>>,
    /// The demo's own folder is made once, by this process, private to its user (mode 0700); `Err` says why it could not be.
    base_made: std::sync::OnceLock<Result<(), String>>,
    /// Each demo box's skills service, over a private home folder: the real code over a pretend disk.
    skills: Mutex<HashMap<String, Arc<ozboxd::skills::SkillsService>>>,
    tools: Mutex<HashMap<String, super::tools::SimTools>>,
    /// The demo repository every demo box backs up to, and each box's service in front of it.
    repo: super::sim_restic::SimRepo,
    restic: Mutex<HashMap<String, Arc<ozboxd::backup_service::BackupService>>>,
    #[cfg(unix)]
    terminals: Mutex<HashMap<String, Arc<ozboxd::terminal::TerminalService>>>,
    /// The demo's tmux sessions, agents and servers, per box.
    procs: Mutex<HashMap<String, crate::code::procs::Procs>>,
    /// Which demo services are set up and running, per box.
    code: Mutex<HashMap<(String, crate::code::Service), bool>>,
    /// Boxes whose Cloudflare connector the demo has "started".
    connector: Mutex<std::collections::HashSet<String>>,
    /// The stand-in IDE and desktop servers, started when first reached.
    code_upstream: Mutex<HashMap<crate::code::Service, std::net::SocketAddr>>,
    /// The demo boxes' local models, per box.
    local_ai: Mutex<HashMap<String, crate::local_ai::SimLocal>>,
    /// What was typed into each demo terminal session (`box:pane`), in order.
    typed: Mutex<HashMap<String, Vec<String>>>,
}

impl Default for SimulatedAgent {
    /// Detects whether this computer is a box, so no construction site can forget to ask.
    fn default() -> Self {
        Self::with_host_is_box(crate::this_box::on_a_box())
    }
}

impl SimulatedAgent {
    pub fn with_host_is_box(host_is_box: bool) -> Self {
        let mut rnd = [0u8; 6];
        let _ = getrandom::getrandom(&mut rnd);
        let id: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
        Self {
            host_is_box,
            base: std::env::temp_dir().join(format!("ozbox-demo-{id}")),
            files: Mutex::new(HashMap::new()),
            base_made: std::sync::OnceLock::new(),
            skills: Mutex::new(HashMap::new()),
            tools: Mutex::new(HashMap::new()),
            repo: super::sim_restic::SimRepo::default(),
            restic: Mutex::new(HashMap::new()),
            #[cfg(unix)]
            terminals: Mutex::new(HashMap::new()),
            procs: Mutex::new(HashMap::new()),
            code: Mutex::new(HashMap::new()),
            connector: Mutex::new(std::collections::HashSet::new()),
            code_upstream: Mutex::new(HashMap::new()),
            local_ai: Mutex::new(HashMap::new()),
            typed: Mutex::new(HashMap::new()),
        }
    }
}

impl Drop for SimulatedAgent {
    fn drop(&mut self) {
        // only a folder this process made: never one that was already there
        if matches!(self.base_made.get(), Some(Ok(()))) {
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }
}

/// A 1x1 PNG and a one-page PDF, so previews have something to show.
const DEMO_PNG: &[u8] = &[
    137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0,
    0, 0, 31, 21, 196, 137, 0, 0, 0, 13, 73, 68, 65, 84, 120, 218, 99, 100, 96, 248, 95, 15, 0, 2,
    135, 1, 128, 235, 71, 186, 146, 0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130,
];
const DEMO_PDF: &[u8] = b"%PDF-1.1\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 200 100]>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n";

impl SimulatedAgent {
    /// The refusal when this computer is a box (X2): a demo shell, folder or server must never run on one.
    fn refuse_on_a_box(&self, what: &str) -> Result<(), AgentError> {
        if self.host_is_box {
            return Err(AgentError::Unsupported(super::no_simulation::refusal(what)));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn demo_folder_exists(&self) -> bool {
        self.base.exists()
    }

    /// The demo's folder under the system's shared temp folder, made private: created here (never reused if something is
    /// already there), mode 0700, so no other user of a shared machine can read or plant files in a demo box's home.
    fn private_base(&self) -> Result<&Path, AgentError> {
        self.base_made
            .get_or_init(|| {
                let mut b = std::fs::DirBuilder::new();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    b.mode(0o700);
                }
                b.create(&self.base).map_err(|e| {
                    if e.kind() == std::io::ErrorKind::AlreadyExists {
                        "the demo's folder already exists, so it is not used".to_string()
                    } else {
                        "the demo's folder could not be made".to_string()
                    }
                })
            })
            .as_ref()
            .map(|()| self.base.as_path())
            .map_err(|e| AgentError::Unreachable(e.clone()))
    }

    /// The same skills service a real box runs, over a private home folder for this box.
    fn skills_for(&self, name: &str) -> Result<Arc<ozboxd::skills::SkillsService>, AgentError> {
        self.refuse_on_a_box("skills")?;
        let mut map = self
            .skills
            .lock()
            .map_err(|_| AgentError::Unreachable("the demo skills are unavailable".into()))?;
        if let Some(s) = map.get(name) {
            return Ok(Arc::clone(s));
        }
        let root = self.private_base()?.join(name);
        let svc = Arc::new(ozboxd::skills::SkillsService::new(
            root.join("home"),
            root.join("state"),
            Arc::new(SystemClock),
        ));
        map.insert(name.to_string(), Arc::clone(&svc));
        Ok(svc)
    }

    /// The same file API a real box runs, over a private folder of sample files for this box.
    fn files_for(&self, name: &str) -> Result<Arc<FilesService>, AgentError> {
        self.refuse_on_a_box("files")?;
        let mut map = self
            .files
            .lock()
            .map_err(|_| AgentError::Unreachable("the demo files are unavailable".into()))?;
        if let Some(s) = map.get(name) {
            return Ok(Arc::clone(s));
        }
        let root = self.private_base()?.join(name).join("work");
        let seed = || -> std::io::Result<()> {
            std::fs::create_dir_all(root.join("exchange"))?;
            std::fs::create_dir_all(root.join("projects/demo/src"))?;
            std::fs::write(
                root.join("exchange/welcome.txt"),
                "Hello from a demo box.\nFiles here are sample data.\n",
            )?;
            std::fs::write(root.join("exchange/report.csv"), "day,runs\nmon,3\ntue,5\n")?;
            std::fs::write(root.join("exchange/logo.png"), DEMO_PNG)?;
            std::fs::write(root.join("exchange/brief.pdf"), DEMO_PDF)?;
            std::fs::write(
                root.join("projects/demo/README.md"),
                "# Demo project\n\nEdit me.\n",
            )?;
            std::fs::write(
                root.join("projects/demo/src/main.ts"),
                "export const answer = 42;\n",
            )?;
            std::fs::write(
                root.join("projects/demo/.env"),
                "DEMO_KEY=not-a-real-secret\n",
            )?;
            std::fs::write(root.join("projects/demo/.env.example"), "DEMO_KEY=\n")?;
            Ok(())
        };
        seed()
            .map_err(|_| AgentError::Unreachable("the demo files could not be created".into()))?;
        let svc = FilesService::new(FilesConfig::new(vec![root]), Arc::new(SystemClock))
            .map_err(|_| AgentError::Unreachable("the demo files could not be opened".into()))?;
        let svc = Arc::new(svc);
        map.insert(name.to_string(), Arc::clone(&svc));
        Ok(svc)
    }
}

/// What the demo says a demo agent may do without asking: the Claude Code one asks (plain); nothing else reports a mode.
fn demo_authority(engine: &str) -> &'static str {
    if engine == "claude-code" {
        "plain"
    } else {
        "unknown"
    }
}

impl BoxAgent for SimulatedAgent {
    /// Three demo coding agents in terminals, one for each level of integration: Claude Code at its prompt (hooks), Codex
    /// busy (notify) and OpenCode (terminal). What is typed into one is echoed back by its screen.
    fn agent_call(
        &self,
        rec: &BoxRecord,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> Result<(u16, serde_json::Value), AgentError> {
        use serde_json::json;
        let name = rec.spec.name.to_string();
        let demo = [
            ("%3", "claude-code", "web", "fix/parser", "hooks", "waiting"),
            ("%5", "codex", "api", "main", "notify", "busy"),
            ("%7", "opencode", "lib", "main", "terminal", "unknown"),
        ];
        if path == "/v1/agent-sessions" && method == "GET" {
            let rows: Vec<_> = demo
                .iter()
                .map(|(id, e, r, b, l, s)| json!({ "id": id, "engine": e, "repo": r, "branch": b, "level": l, "state": s, "tmux_session": "work", "authority": demo_authority(e) }))
                .collect();
            return Ok((200, json!({ "tmux": true, "sessions": rows })));
        }
        let Some(rest) = path.strip_prefix("/v1/agent-sessions/") else {
            return Ok((404, json!({ "error": "not found" })));
        };
        let (pane, action) = rest
            .split_once('/')
            .map(|(p, a)| (p, a.split('?').next().unwrap_or("")))
            .unwrap_or((rest, ""));
        let Some(row) = demo.iter().find(|d| d.0 == pane) else {
            return Ok((
                404,
                json!({ "error": "that terminal session is not running, or it is not a coding agent in a repository" }),
            ));
        };
        let key = format!("{name}:{pane}");
        let mut typed = self
            .typed
            .lock()
            .map_err(|_| AgentError::Unreachable("the demo state is unavailable".into()))?;
        match (method, action) {
            ("POST", "send") => {
                let v: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
                let force = v["force"].as_bool().unwrap_or(false);
                // as the daemon answers a chat app: only a plain session takes a line from one, and not a line the agent would
                // act on itself. A caller that does not say it is the dashboard is a chat app.
                let from_app = v["from_app"].as_bool().unwrap_or(true);
                if from_app
                    && ozbox_core::agent_line::starts_with_agent_command(
                        v["text"].as_str().unwrap_or(""),
                    )
                {
                    return Ok((
                        403,
                        json!({ "error": "a chat app may not type a line that starts with ! # & or /", "code": "line_not_allowed" }),
                    ));
                }
                if from_app && demo_authority(row.1) != "plain" {
                    return Ok((
                        403,
                        json!({ "error": "what that agent may do without asking could not be established", "code": "unknown" }),
                    ));
                }
                if row.5 != "waiting" && !force {
                    return Ok((
                        409,
                        json!({ "error": "the agent is not waiting for input", "code": "not_waiting" }),
                    ));
                }
                typed
                    .entry(key)
                    .or_default()
                    .push(v["text"].as_str().unwrap_or("").chars().take(200).collect());
                Ok((200, json!({ "id": pane, "sent": true })))
            }
            ("GET", "capture") => {
                let lines: Vec<String> = std::iter::once(format!("{} ready", row.1))
                    .chain(
                        typed
                            .get(&key)
                            .into_iter()
                            .flatten()
                            .flat_map(|t| [format!("> {t}"), format!("Done: {t}")]),
                    )
                    .collect();
                Ok((200, json!({ "id": pane, "text": lines.join("\n") })))
            }
            _ => Ok((405, json!({ "error": "method not allowed" }))),
        }
    }
    fn code_procs(&self, rec: &BoxRecord) -> Result<crate::code::procs::Procs, AgentError> {
        use crate::code::procs::{Agent, Procs, Server, Session};
        let mut m = self
            .procs
            .lock()
            .map_err(|_| AgentError::Unreachable("the demo state is unavailable".into()))?;
        Ok(m.entry(rec.spec.name.to_string())
            .or_insert_with(|| Procs {
                tmux: true,
                sessions: vec![
                    Session {
                        name: "term-1".into(),
                        created_s: 1_700_000_000,
                        activity_s: 1_700_000_900,
                        attached: false,
                        command: "claude".into(),
                    },
                    Session {
                        name: "term-2".into(),
                        created_s: 1_700_000_100,
                        activity_s: 1_700_000_950,
                        attached: true,
                        command: "bash".into(),
                    },
                ],
                agents: vec![Agent {
                    pid: 4242,
                    program: "claude".into(),
                    age_s: 5400,
                }],
                servers: vec![Server {
                    port: 3000,
                    pid: 777,
                    program: "node".into(),
                }],
            })
            .clone())
    }

    fn code_stop(
        &self,
        rec: &BoxRecord,
        stop: &crate::code::procs::Stop,
    ) -> Result<(), AgentError> {
        use crate::code::procs::Stop;
        self.code_procs(rec)?;
        let mut m = self
            .procs
            .lock()
            .map_err(|_| AgentError::Unreachable("the demo state is unavailable".into()))?;
        if let Some(p) = m.get_mut(rec.spec.name.as_str()) {
            match stop {
                Stop::Session(n) => p.sessions.retain(|s| &s.name != n),
                Stop::Process(pid) => {
                    p.agents.retain(|a| a.pid != *pid);
                    p.servers.retain(|s| s.pid != *pid);
                }
            }
        }
        Ok(())
    }

    fn code_status(&self, rec: &BoxRecord) -> Result<crate::code::BoxCode, AgentError> {
        let map = self
            .code
            .lock()
            .map_err(|_| AgentError::Unreachable("the demo state is unavailable".into()))?;
        let state = |s: crate::code::Service| {
            let on = map.get(&(rec.spec.name.to_string(), s)).copied();
            crate::code::ServiceState {
                program: true,
                unit_current: on.is_some(),
                active: on == Some(true),
            }
        };
        Ok(crate::code::BoxCode {
            linger: true,
            tmux: true,
            terminals: true,
            ide: state(crate::code::Service::Ide),
            desktop: state(crate::code::Service::Desktop),
            connector: {
                let on = self
                    .connector
                    .lock()
                    .map(|c| c.contains(rec.spec.name.as_str()))
                    .unwrap_or(false);
                crate::code::ServiceState {
                    program: true,
                    unit_current: on,
                    active: on,
                }
            },
        })
    }

    fn code_change(&self, rec: &BoxRecord, change: &crate::code::Change) -> Result<(), AgentError> {
        let mut map = self
            .code
            .lock()
            .map_err(|_| AgentError::Unreachable("the demo state is unavailable".into()))?;
        if matches!(change, crate::code::Change::Terminals) {
            return Ok(());
        }
        if let Some(on) = match change {
            crate::code::Change::Connector { .. } => Some(true),
            crate::code::Change::ConnectorOff => Some(false),
            _ => None,
        } {
            // the demo keeps the connector as a third entry beside the two services
            let mut c = self
                .connector
                .lock()
                .map_err(|_| AgentError::Unreachable("the demo state is unavailable".into()))?;
            if on {
                c.insert(rec.spec.name.to_string());
            } else {
                c.remove(rec.spec.name.as_str());
            }
            return Ok(());
        }
        let key = (rec.spec.name.to_string(), change.service());
        match change {
            crate::code::Change::Enable { .. } => {
                map.insert(key, true);
            }
            crate::code::Change::Disable { .. } => {
                map.remove(&key);
            }
            crate::code::Change::Terminals
            | crate::code::Change::Connector { .. }
            | crate::code::Change::ConnectorOff => {}
        }
        Ok(())
    }

    fn connect_tcp(&self, rec: &BoxRecord, port: u16) -> Result<Conn, AgentError> {
        self.refuse_on_a_box("server")?;
        let svc = crate::code::ALL
            .into_iter()
            .find(|s| s.box_port() == port)
            .ok_or_else(|| {
                AgentError::Unsupported("nothing listens on that port in the demo".into())
            })?;
        let running = self
            .code
            .lock()
            .map(|m| m.get(&(rec.spec.name.to_string(), svc)) == Some(&true))
            .unwrap_or(false);
        if !running {
            return Err(AgentError::Unreachable(
                "the service is not running on this box".into(),
            ));
        }
        let addr = {
            let mut up = self
                .code_upstream
                .lock()
                .map_err(|_| AgentError::Unreachable("the demo state is unavailable".into()))?;
            match up.get(&svc) {
                Some(a) => *a,
                None => {
                    let a = super::sim_code::start(match svc {
                        crate::code::Service::Ide => "Simulated web IDE",
                        crate::code::Service::Desktop => "Simulated desktop",
                    })
                    .map_err(|_| {
                        AgentError::Unreachable("the demo server could not start".into())
                    })?;
                    up.insert(svc, a);
                    a
                }
            }
        };
        let s = std::net::TcpStream::connect(addr)
            .map_err(|_| AgentError::Unreachable("the demo server did not answer".into()))?;
        Conn::from_tcp(s)
            .map_err(|_| AgentError::Unreachable("the demo server did not answer".into()))
    }

    /// The demo box's terminal is a real shell on this computer, in a private folder (never tmux, never the user's
    /// home): the same daemon code a real box runs, so the demo exercises the real protocol.
    #[cfg(unix)]
    fn terminal(
        &self,
        rec: &BoxRecord,
        cols: u16,
        rows: u16,
        _session: Option<&str>,
    ) -> Result<super::terminal::Conn, AgentError> {
        use std::os::unix::net::UnixStream;
        self.refuse_on_a_box("terminal")?;
        let name = rec.spec.name.as_str();
        let svc = {
            let mut map = self
                .terminals
                .lock()
                .map_err(|_| AgentError::Unreachable("the demo terminal is unavailable".into()))?;
            if !map.contains_key(name) {
                let dir = self.private_base()?.join(name).join("work");
                let _ = std::fs::create_dir_all(&dir);
                let cfg = ozboxd::config::TerminalSection {
                    tmux: false,
                    command: vec!["/bin/sh".into()],
                    max_sessions: 8,
                    ..Default::default()
                };
                map.insert(
                    name.to_string(),
                    Arc::new(ozboxd::terminal::TerminalService::new(cfg, dir, None)),
                );
            }
            map.get(name)
                .cloned()
                .ok_or_else(|| AgentError::Unreachable("the demo terminal is unavailable".into()))?
        };
        let (mut a, b) = UnixStream::pair()
            .map_err(|_| AgentError::Unreachable("the demo terminal could not start".into()))?;
        let head = ozboxd::http::Head {
            method: "GET".into(),
            path: "/v1/terminal".into(),
            query: BTreeMap::from([
                ("cols".to_string(), cols.to_string()),
                ("rows".to_string(), rows.to_string()),
            ]),
            content_length: 0,
            length_given: false,
            early: Vec::new(),
            capability: None,
        };
        std::thread::spawn(move || svc.handle(b, &head));
        super::terminal::handshake(&mut a)?;
        Ok(super::terminal::Conn {
            stream: a,
            hold: None,
        })
    }

    fn restic(
        &self,
        rec: &BoxRecord,
        method: &str,
        sub: &str,
        body: &[u8],
    ) -> Result<(u16, serde_json::Value), AgentError> {
        let name = rec.spec.name.as_str();
        let dir = self.private_base()?.join(name).join("restic");
        let svc =
            {
                let mut map = self.restic.lock().map_err(|_| {
                    AgentError::Unreachable("the demo backups are unavailable".into())
                })?;
                Arc::clone(map.entry(name.to_string()).or_insert_with(|| {
                    super::sim_restic::service_for(dir.clone(), name, &self.repo)
                }))
            };
        let parsed: serde_json::Value = if body.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(body).map_err(|_| {
                AgentError::Unreachable("the demo backups got a body that is not JSON".into())
            })?
        };
        let now = ozboxd::timeutil::Clock::now_ms(&ozboxd::timeutil::SystemClock);
        let provision = super::sim_restic::provision(&dir);
        Ok(svc.handle(method, sub, &parsed, &provision, now))
    }

    fn tools(
        &self,
        rec: &BoxRecord,
        method: &str,
        segments: &[&str],
        body: &[u8],
    ) -> Result<(u16, serde_json::Value), AgentError> {
        let name = rec.spec.name.as_str();
        let mut map = self
            .tools
            .lock()
            .map_err(|_| AgentError::Unreachable("the demo tools are unavailable".into()))?;
        if !map.contains_key(name) {
            let catalog = ozbox_catalog::embedded().map_err(AgentError::Unreachable)?;
            let fail = rec.spec.labels.get("sim_profile").map(String::as_str) == Some("failing");
            let path = std::env::var_os("OZBOX_STATE_DIR")
                .map(|d| PathBuf::from(d).join(format!("sim-tools-{name}.json")));
            map.insert(
                name.to_string(),
                super::tools::SimTools::new(catalog, fail, path),
            );
        }
        let sim = map
            .get_mut(name)
            .ok_or_else(|| AgentError::Unreachable("no demo tools".into()))?;
        Ok(sim.call(method, segments, body))
    }

    fn local_ai(
        &self,
        rec: &BoxRecord,
        request: &serde_json::Value,
    ) -> Result<serde_json::Value, AgentError> {
        let mut map = self
            .local_ai
            .lock()
            .map_err(|_| AgentError::Unreachable("the demo local models are unavailable".into()))?;
        Ok(map
            .entry(rec.spec.name.to_string())
            .or_default()
            .call(request))
    }

    #[cfg(test)]
    fn demo_box_dir(&self, box_name: &str) -> Option<PathBuf> {
        self.private_base().ok().map(|b| b.join(box_name))
    }

    /// The demo stands in for a dashboard that runs on the box, so its writes go through.
    fn skill_writes(&self) -> bool {
        true
    }

    fn skills(
        &self,
        rec: &BoxRecord,
        method: &str,
        sub: &str,
        body: &[u8],
    ) -> Result<(u16, serde_json::Value), AgentError> {
        Ok(self
            .skills_for(rec.spec.name.as_str())?
            .route(method, sub, body, true))
    }

    fn files(
        &self,
        rec: &BoxRecord,
        method: &str,
        path: &str,
        query: &BTreeMap<String, String>,
        input: FileInput<'_>,
    ) -> Result<FileReply, AgentError> {
        Ok(self
            .files_for(rec.spec.name.as_str())?
            .call(method, path, query, input))
    }

    fn metrics_now(&self, rec: &BoxRecord, now_ms: u64) -> Result<MetricsSample, AgentError> {
        Ok(metrics_sim::sample(rec, metrics_sim::bucket(now_ms, 5_000)))
    }

    fn metrics_series(
        &self,
        rec: &BoxRecord,
        from_ms: u64,
        to_ms: u64,
        step_ms: u64,
    ) -> Result<Vec<MetricsSample>, AgentError> {
        let start = from_ms.div_ceil(step_ms) * step_ms;
        Ok((0..)
            .map(|i| start + i * step_ms)
            .take_while(|t| *t <= to_ms)
            .map(|t| metrics_sim::sample(rec, t))
            .collect())
    }

    fn checkpoint(&self, _rec: &BoxRecord) -> Result<CheckpointOutcome, AgentError> {
        Ok(CheckpointOutcome::default())
    }

    /// The demo box has no supervised runs to list.
    fn runs(
        &self,
        _rec: &BoxRecord,
        method: &str,
        sub: &str,
        _body: &[u8],
    ) -> Result<(u16, serde_json::Value), AgentError> {
        if method == "GET" && sub.is_empty() {
            return Ok((200, serde_json::json!({ "runs": [] })));
        }
        Err(AgentError::Unsupported(
            "the demo box does not run programs".into(),
        ))
    }

    /// The demo box has no runs to end and no repositories: it answers like a daemon that finished at once.
    fn quiesce_call(
        &self,
        _rec: &BoxRecord,
        method: &str,
        _body: &[u8],
    ) -> Result<(u16, serde_json::Value), AgentError> {
        use serde_json::json;
        let done = json!({
            "state": "done", "job": 1, "started_ms": 0,
            "report": {
                "runs": { "runs": [], "not_stopped": 0 },
                "checkpoint": { "repos_scanned": 0, "branches": [], "errors": [], "pruned": 0 }
            }
        });
        match method {
            "GET" | "DELETE" => Ok((200, done)),
            "POST" => Ok((
                202,
                json!({ "state": "running", "job": 1, "started_ms": 0 }),
            )),
            _ => Err(AgentError::Unsupported(
                "that quiesce request is not valid".into(),
            )),
        }
    }

    fn selftest(&self, rec: &BoxRecord, now_ms: u64) -> Result<SelfTest, AgentError> {
        let profile = rec
            .spec
            .labels
            .get("sim_profile")
            .map(String::as_str)
            .unwrap_or("");
        let checks: Vec<Check> = CHECKS
            .iter()
            .map(|n| Check {
                name: (*n).to_string(),
                outcome: match (profile, *n) {
                    ("failing", "tunnels up") => Outcome::Fail {
                        step: "tunnels up".into(),
                        reason: "the tunnel service is not running".into(),
                    },
                    ("unverified", "work disk mounted") => Outcome::Unknown {
                        reason: "the encryption state is not visible from inside the box".into(),
                    },
                    _ => Outcome::Pass,
                },
            })
            .collect();
        Ok(SelfTest {
            ts_ms: now_ms,
            ok: !checks
                .iter()
                .any(|c| matches!(c.outcome, Outcome::Fail { .. })),
            all_verified: !checks
                .iter()
                .any(|c| matches!(c.outcome, Outcome::Unknown { .. })),
            checks,
        })
    }

    fn incidents(
        &self,
        rec: &BoxRecord,
        since_ms: u64,
        now_ms: u64,
    ) -> Result<Vec<Incident>, AgentError> {
        let failing = rec.spec.labels.get("sim_profile").map(String::as_str) == Some("failing");
        let mut v = vec![Incident {
            ts_ms: now_ms.saturating_sub(26 * 3_600_000),
            kind: "restart".into(),
            detail: "the box agent restarted after an update".into(),
        }];
        if failing {
            v.push(Incident {
                ts_ms: now_ms.saturating_sub(40 * 60_000),
                kind: "self_test_failed".into(),
                detail: "step: tunnels up".into(),
            });
        }
        v.retain(|i| i.ts_ms >= since_ms);
        Ok(v)
    }
}

/// A scripted agent for tests.
#[cfg(test)]
#[derive(Default)]
pub struct FakeAgent {
    pub selftests: BTreeMap<String, SelfTest>,
    pub incidents: BTreeMap<String, Vec<Incident>>,
    pub now: BTreeMap<String, MetricsSample>,
}

#[cfg(test)]
impl BoxAgent for FakeAgent {
    fn metrics_now(&self, rec: &BoxRecord, _: u64) -> Result<MetricsSample, AgentError> {
        self.now
            .get(rec.spec.name.as_str())
            .cloned()
            .ok_or_else(|| AgentError::Unreachable("no daemon answered".into()))
    }
    fn metrics_series(
        &self,
        rec: &BoxRecord,
        from_ms: u64,
        to_ms: u64,
        step_ms: u64,
    ) -> Result<Vec<MetricsSample>, AgentError> {
        let s = self.metrics_now(rec, 0)?;
        let start = from_ms.div_ceil(step_ms) * step_ms;
        Ok((0..)
            .map(|i| start + i * step_ms)
            .take_while(|t| *t <= to_ms)
            .map(|t| MetricsSample {
                ts_ms: t,
                ..s.clone()
            })
            .collect())
    }
    fn selftest(&self, rec: &BoxRecord, _: u64) -> Result<SelfTest, AgentError> {
        self.selftests
            .get(rec.spec.name.as_str())
            .cloned()
            .ok_or_else(|| AgentError::Unreachable("no daemon answered".into()))
    }
    fn incidents(
        &self,
        rec: &BoxRecord,
        since_ms: u64,
        _: u64,
    ) -> Result<Vec<Incident>, AgentError> {
        let mut v = self
            .incidents
            .get(rec.spec.name.as_str())
            .cloned()
            .ok_or_else(|| AgentError::Unreachable("no daemon answered".into()))?;
        v.retain(|i| i.ts_ms >= since_ms);
        Ok(v)
    }
}

#[cfg(test)]
mod image_agent_tests {
    use super::*;

    #[test]
    fn the_marker_and_the_presence_of_the_agent_are_read_from_the_answer() {
        let a = parse_image_agent(
            "image_version=2026.11.09\nozboxd_sha256=ab\nsource_commit=x\nozboxd=absent\n",
        );
        assert_eq!(
            a,
            Some(ImageAgent {
                from_image: true,
                image_version: Some("2026.11.09".into()),
                agent_present: false,
                arch: None,
                first_boot: BoxFirstBoot::Unrecorded,
            })
        );
        let stock = parse_image_agent("ozboxd=absent\n");
        assert_eq!(
            stock.map(|s| (s.from_image, s.agent_present)),
            Some((false, false))
        );
        assert!(parse_image_agent("ozboxd=present").is_some_and(|a| a.agent_present));
        assert_eq!(parse_image_agent("Connection refused"), None);
    }

    #[test]
    fn upgrade_reads_the_record_of_every_image_the_way_the_installer_does() {
        let b = "b".repeat(64);
        // today's record, with the browser's lines
        let a = parse_image_agent(&format!(
            "image_version=0.1.1-alpha.0\nozboxd_sha256={b}\nozbox_sha256={b}\nsource_commit=339e501\nchrome_version=none\nchrome_deb_sha256=none\nozboxd=present\narch=x86_64\n"
        ));
        assert_eq!(
            a.map(|a| (a.from_image, a.agent_present, a.image_version)),
            Some((true, true, Some("0.1.1-alpha.0".to_string())))
        );
        // the first images' one-line record
        let old = parse_image_agent("2026.11.09\nozboxd=present\n");
        assert_eq!(
            old.map(|a| (a.from_image, a.image_version)),
            Some((true, Some("2026.11.09".to_string())))
        );
    }

    #[test]
    fn the_first_boot_record_is_read_when_the_box_has_one() {
        let h = "c".repeat(64);
        let a = parse_image_agent(&format!(
            "image_version=0.1.1\nfirst_boot_sha256={h}\nozboxd=present\n"
        ));
        assert_eq!(
            a.map(|a| a.first_boot),
            Some(BoxFirstBoot::Recorded(h.clone()))
        );
        // a box made before the record existed, or with no hash given
        let old = parse_image_agent("image_version=0.1.0\nozboxd=present\n");
        assert_eq!(old.map(|a| a.first_boot), Some(BoxFirstBoot::Unrecorded));
        let empty = parse_image_agent("first_boot_sha256=\nozboxd=present\n");
        assert_eq!(empty.map(|a| a.first_boot), Some(BoxFirstBoot::Unrecorded));
        assert!(IMAGE_AGENT_COMMAND.contains("/etc/ozbox/first-boot"));
    }

    /// The answer passes through the box user's shell, whose rc files are on /work: a line printed before (or after) the
    /// real record makes the answer malformed, never "the one I wanted".
    #[test]
    fn an_injected_record_line_makes_the_answer_malformed() {
        let (ours, real) = ("a".repeat(64), "b".repeat(64));
        for forged in [
            format!("first_boot_sha256={ours}\nfirst_boot_sha256={real}\nozboxd=present\n"),
            format!("first_boot_sha256={real}\nozboxd=present\nfirst_boot_sha256={ours}\n"),
            format!("first_boot_sha256={ours}\nfirst_boot_sha256=\nozboxd=present\n"),
            "first_boot_sha256=NOT-A-HASH\nozboxd=present\n".to_string(),
        ] {
            assert_eq!(
                parse_image_agent(&forged).map(|a| a.first_boot),
                Some(BoxFirstBoot::Malformed),
                "{forged}"
            );
        }
        // the command does not run in the user's login shell environment
        assert!(
            IMAGE_AGENT_COMMAND.starts_with("exec /usr/bin/env -i PATH=/usr/bin:/bin /bin/sh -c '")
        );
        assert!(IMAGE_AGENT_COMMAND.ends_with('\''));
        assert_eq!(
            IMAGE_AGENT_COMMAND.matches('\'').count(),
            2,
            "no quote inside the inner command"
        );
    }
}
