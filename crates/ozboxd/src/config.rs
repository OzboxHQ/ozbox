//! Configuration from `/etc/ozbox/ozboxd.toml`. Every field has a default, so an absent or empty file is valid.
//! Secrets never live here: the backup repository and password come from a separate env file (see `backup`).

use std::path::PathBuf;

use serde::Deserialize;

pub const DEFAULT_CONFIG_PATH: &str = "/etc/ozbox/ozboxd.toml";

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Defaults to the hostname when it is a valid box name, else `box`.
    pub box_name: Option<String>,
    /// The `ozbox-always-on=true` label: never idle-stop.
    pub always_on: bool,
    /// Which provider this box runs on (`aws`, `hcloud`, ...). Enables provider-specific watchers.
    pub provider: String,
    pub socket_path: PathBuf,
    /// Octal, e.g. "0660".
    pub socket_mode: String,
    /// The one user the dashboard's socket answers (ADR 0040, decision 3), checked with the kernel's peer credentials. The
    /// socket itself is not configured here: systemd (root) binds it in a folder root owns and hands it over (socket
    /// activation), so the daemon never creates, moves or changes the mode of it.
    pub supervisor_user: String,
    pub work_dir: PathBuf,
    pub repos_root: PathBuf,
    pub state_dir: PathBuf,
    /// Defaults to `<state_dir>/metrics`.
    pub metrics_dir: Option<PathBuf>,
    /// Cgroup that holds the run scopes. Absent = the cgroup systemd delegated to this service (`Delegate=yes`).
    pub cgroup_parent: Option<PathBuf>,
    /// Where run output is kept; absent = `<state_dir>/run-logs`.
    pub run_log_dir: Option<PathBuf>,
    pub release_file: PathBuf,
    pub sample_interval_s: u64,
    pub gpu: bool,
    pub idle: IdleSection,
    pub store: StoreSection,
    pub runs: RunsSection,
    pub checkpoint: CheckpointSection,
    pub selftest: SelfTestSection,
    pub backup: BackupSection,
    pub files: FilesSection,
    pub tools: ToolsSection,
    pub terminal: TerminalSection,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IdleSection {
    pub threshold_minutes: u64,
    pub cpu_threshold_pct: f64,
    pub check_interval_s: u64,
    pub session_ports: Vec<u16>,
    /// argv that asks the control side to stop this box, e.g. `["ozbox", "pause", "<box>"]`. Empty = record an
    /// incident instead of stopping.
    pub stop_command: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StoreSection {
    pub max_mb: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RunsSection {
    pub max_queue: usize,
    pub max_active: usize,
    /// Per-run log size cap, MiB.
    pub log_max_mb: u64,
    /// Wall-clock limit applied to runs that set none, seconds. 0 = none.
    pub default_max_runtime_s: u64,
    /// Cap every run that sets no memory limit of its own at what the box can spare (ADR 0045). Default on.
    pub default_memory_cap: bool,
    /// Where a run lives. `unit`: a transient service of the box user's manager, which keeps going when this daemon
    /// restarts (ADR 0038). `scope`: a cgroup under this daemon's own service, which ends with it. `auto` (the default):
    /// `unit` when the box user's manager is there and delegates the memory and cpu controllers, else `scope`, said once
    /// in the incident log.
    pub backend: String,
    /// How long, at start, the daemon waits for the box user's manager to be ready before it takes over the runs a previous
    /// daemon left going and starts its own (`auto` and `unit`). 0 = do not wait. Runs started later look again.
    pub manager_wait_s: u64,
    /// How much of the daemon's own sandbox a run in a unit keeps. `basic` (the default): no new privileges, no setuid or
    /// setgid files, no personality change. `strict`: also a private /dev and a read-only system and home with the work
    /// folder and /tmp writable, which needs the user manager to be able to make a mount namespace (not yet seen on an image).
    pub sandbox: String,
    /// Where runs keep their records, output and status (`unit` backend); absent = `<state_dir>/runs`.
    pub dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CheckpointSection {
    pub push_remote: Option<String>,
    pub max_depth: usize,
    /// Newest WIP branches kept per repo.
    pub keep_wip: usize,
    /// Off by default. When the daemon is stopped (a resize, an upgrade or a shutdown stops the machine), when the box stops
    /// itself for being idle, and when the cloud announces an interruption, it takes the same hidden snapshot a quiesce takes:
    /// nothing visible is written and nothing is pushed. A run's pause still writes the local branch `wip/<box>/<time>` that its
    /// resume needs, and does not push it. Set this to `true` to have those paths push as well, and the stop paths
    /// run the older checkpoint instead, which **writes a visible branch `wip/<box>/<time>` in every repository with changes
    /// and pushes it to `push_remote` when one is set**.
    pub push_wip_on_stop: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SelfTestSection {
    pub min_free_mb: u64,
    pub require_mount: bool,
    pub tools: Vec<String>,
    /// What the provider module declared: `true`, `false` or `unknown`.
    pub work_encrypted: String,
    /// systemd units carrying the outbound tunnels.
    pub tunnel_units: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BackupSection {
    pub enabled: bool,
    pub env_file: PathBuf,
    /// The secrets service's broker socket, where restic runs with credentials the daemon never sees.
    pub service_socket: Option<PathBuf>,
    pub paths: Vec<String>,
    pub excludes: Vec<String>,
    pub interval_hours: u64,
}

/// The tool installer.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ToolsSection {
    /// Memory cap for an install job, MiB.
    pub job_memory_mb: u64,
}

impl Default for ToolsSection {
    fn default() -> Self {
        Self {
            job_memory_mb: 1536,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            box_name: None,
            always_on: false,
            provider: String::new(),
            socket_path: PathBuf::from("/run/ozboxd/ozboxd.sock"),
            socket_mode: "0660".into(),
            supervisor_user: "ozbox-supervisor".into(),
            work_dir: PathBuf::from("/work"),
            repos_root: PathBuf::from("/work/repos"),
            state_dir: PathBuf::from("/work/.ozbox"),
            metrics_dir: None,
            cgroup_parent: None,
            run_log_dir: None,
            release_file: PathBuf::from("/etc/ozbox-release"),
            sample_interval_s: 5,
            gpu: true,
            idle: IdleSection::default(),
            store: StoreSection::default(),
            runs: RunsSection::default(),
            checkpoint: CheckpointSection::default(),
            selftest: SelfTestSection::default(),
            backup: BackupSection::default(),
            files: FilesSection::default(),
            tools: ToolsSection::default(),
            terminal: TerminalSection::default(),
        }
    }
}

impl Default for IdleSection {
    fn default() -> Self {
        Self {
            threshold_minutes: 90,
            cpu_threshold_pct: 5.0,
            check_interval_s: 30,
            session_ports: vec![8080, 6080],
            stop_command: Vec::new(),
        }
    }
}

impl Default for StoreSection {
    fn default() -> Self {
        Self { max_mb: 256 }
    }
}

impl Default for RunsSection {
    fn default() -> Self {
        Self {
            max_queue: 32,
            max_active: 64,
            log_max_mb: 10,
            default_max_runtime_s: 0,
            default_memory_cap: true,
            backend: "auto".into(),
            manager_wait_s: 20,
            sandbox: "basic".into(),
            dir: None,
        }
    }
}

impl Default for CheckpointSection {
    fn default() -> Self {
        Self {
            push_remote: None,
            max_depth: 3,
            keep_wip: 20,
            push_wip_on_stop: false,
        }
    }
}

impl Default for SelfTestSection {
    fn default() -> Self {
        Self {
            min_free_mb: 1024,
            require_mount: true,
            tools: vec!["git".into(), "sh".into(), "sync".into()],
            work_encrypted: "unknown".into(),
            tunnel_units: Vec::new(),
        }
    }
}

/// The file API's reach and limits. The work directory is always shared; add the owner's home here to share it too.
/// The browser terminal. Sessions attach to one shared tmux session by default, so they survive a dropped connection
/// and are the same shell an SSH or editor terminal shows.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TerminalSection {
    pub enabled: bool,
    pub max_sessions: usize,
    /// A session with no input and no output for this long is closed (a tmux session itself keeps running).
    pub idle_timeout_s: u64,
    /// argv to run instead of the box user's login shell (and instead of tmux). Empty = default.
    pub command: Vec<String>,
    pub tmux: bool,
    pub tmux_session: String,
    /// tmux scrollback, in lines.
    pub history_lines: u32,
}

impl Default for TerminalSection {
    fn default() -> Self {
        Self {
            enabled: true,
            max_sessions: 4,
            idle_timeout_s: 30 * 60,
            command: Vec::new(),
            tmux: true,
            tmux_session: "ozbox".into(),
            history_lines: 20_000,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FilesSection {
    pub extra_roots: Vec<PathBuf>,
    pub max_upload_mb: u64,
    pub max_bundle_mb: u64,
}

impl Default for FilesSection {
    fn default() -> Self {
        Self {
            extra_roots: Vec::new(),
            max_upload_mb: 2048,
            max_bundle_mb: 1024,
        }
    }
}

impl Default for BackupSection {
    fn default() -> Self {
        Self {
            enabled: false,
            env_file: PathBuf::from("/etc/ozbox/restic.env"),
            service_socket: None,
            paths: vec!["/work".into()],
            excludes: vec!["/work/.ozbox/metrics".into()],
            interval_hours: 24,
        }
    }
}

impl Config {
    pub fn from_toml(text: &str) -> Result<Self, String> {
        let c: Config = toml::from_str(text).map_err(|e| format!("bad config: {}", e.message()))?;
        c.validate()?;
        Ok(c)
    }

    pub fn validate(&self) -> Result<(), String> {
        if u32::from_str_radix(&self.socket_mode, 8).map_or(true, |m| m > 0o777) {
            return Err("socket_mode must be an octal mode such as \"0660\"".into());
        }
        if self.sample_interval_s == 0 || self.sample_interval_s > 3600 {
            return Err("sample_interval_s must be 1 to 3600".into());
        }
        if !matches!(
            self.selftest.work_encrypted.as_str(),
            "true" | "false" | "unknown"
        ) {
            return Err("selftest.work_encrypted must be true, false or unknown".into());
        }
        if !["auto", "unit", "scope"].contains(&self.runs.backend.as_str()) {
            return Err("runs.backend must be auto, unit or scope".into());
        }
        if self.checkpoint.keep_wip == 0 || self.runs.log_max_mb == 0 {
            return Err("checkpoint.keep_wip and runs.log_max_mb must be at least 1".into());
        }
        if self.idle.check_interval_s == 0 {
            return Err("idle.check_interval_s must be at least 1".into());
        }
        Ok(())
    }

    pub fn socket_mode_bits(&self) -> u32 {
        u32::from_str_radix(&self.socket_mode, 8).unwrap_or(0o660)
    }

    pub fn metrics_path(&self) -> PathBuf {
        self.metrics_dir
            .clone()
            .unwrap_or_else(|| self.state_dir.join("metrics"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_file_is_all_defaults() {
        let c = Config::from_toml("").unwrap();
        assert_eq!(c.socket_path, PathBuf::from("/run/ozboxd/ozboxd.sock"));
        assert_eq!(c.socket_mode_bits(), 0o660);
        assert_eq!(c.idle.threshold_minutes, 90);
        assert_eq!(c.metrics_path(), PathBuf::from("/work/.ozbox/metrics"));
        assert!(!c.backup.enabled && !c.always_on);
    }

    #[test]
    fn overrides_and_rejections() {
        let c = Config::from_toml("always_on = true\n[idle]\nthreshold_minutes = 30\nstop_command = [\"ozbox\", \"pause\", \"b\"]\n").unwrap();
        assert!(c.always_on);
        assert_eq!(
            (c.idle.threshold_minutes, c.idle.stop_command.len()),
            (30, 3)
        );
        assert_eq!(c.idle.cpu_threshold_pct, 5.0); // untouched fields keep defaults
        assert!(Config::from_toml("socket_mode = \"999\"").is_err());
        assert!(Config::from_toml("unknown_key = 1").is_err());
        assert!(Config::from_toml("[selftest]\nwork_encrypted = \"maybe\"").is_err());
        assert!(Config::from_toml("[checkpoint]\nkeep_wip = 0").is_err());
        assert!(Config::from_toml("sample_interval_s = 0").is_err());
        assert!(Config::from_toml("[[").is_err());
    }
}
