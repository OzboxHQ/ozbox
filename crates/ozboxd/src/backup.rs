//! Backups with restic.
//!
//! Who schedules: when the dashboard server owns the schedule it calls [`crate::backup_service`] through the API, and
//! the box's own `[backup] enabled` stays false (the first-boot file writes it explicitly, and a test holds that).
//! Both on would back the box up twice.
//!
//! The repository location and password reach restic only through **environment variables loaded from a file
//! outside the box config** (`RESTIC_REPOSITORY`, `RESTIC_PASSWORD_FILE`, cloud credentials). None of it is ever put
//! in argv, a log line or an error. Commands are argv arrays through a [`CommandRunner`].

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use ozbox_core::{CommandRunner, CommandSpec};

#[derive(Debug, Clone)]
pub struct BackupConfig {
    pub restic_bin: String,
    /// `KEY=VALUE` lines, owned by root and outside the box config (e.g. `/etc/ozbox/restic.env`).
    pub env_file: PathBuf,
    /// The box's secrets service (its broker socket). When set, restic runs there as the secrets user with the
    /// credentials it holds, and `env_file` is not used: the daemon never reads a credential.
    pub service_socket: Option<PathBuf>,
    pub paths: Vec<String>,
    pub excludes: Vec<String>,
    pub tag: String,
    /// The box's name. Every snapshot it makes also carries `ozbox-box=<name>`, so boxes that share one repository
    /// keep their own history and their own retention.
    pub box_name: Option<String>,
    pub keep_daily: u32,
    pub keep_weekly: u32,
    pub keep_monthly: u32,
    pub interval_hours: u64,
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            restic_bin: "restic".into(),
            env_file: PathBuf::from("/etc/ozbox/restic.env"),
            service_socket: None,
            paths: vec!["/work".into()],
            excludes: vec!["/work/.ozbox/metrics".into()],
            tag: "ozbox".into(),
            box_name: None,
            keep_daily: 7,
            keep_weekly: 4,
            keep_monthly: 6,
            interval_hours: 24,
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BackupError {
    #[error("backup environment is incomplete: {0} is not set")]
    MissingEnv(&'static str),
    /// The secrets service did not answer (it is not up yet): not the same as credentials that are missing.
    #[error("the box's secrets service is not ready")]
    ServiceUnavailable,
    #[error("invalid snapshot id")]
    BadSnapshot,
    #[error("restore target must be an absolute path")]
    BadTarget,
    #[error("restic {0} failed (exit {1:?})")]
    Failed(&'static str, Option<i32>),
}

/// Parse `KEY=VALUE` lines (comments and blank lines ignored, matching quotes stripped).
pub fn parse_env_file(text: &str) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    for l in text.lines() {
        let l = l.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let l = l.strip_prefix("export ").unwrap_or(l);
        let Some((k, v)) = l.split_once('=') else {
            continue;
        };
        let v = v.trim();
        let v = v
            .strip_prefix('"')
            .and_then(|x| x.strip_suffix('"'))
            .or_else(|| v.strip_prefix('\'').and_then(|x| x.strip_suffix('\'')))
            .unwrap_or(v);
        m.insert(k.trim().to_string(), v.to_string());
    }
    m
}

pub struct Restic {
    cfg: BackupConfig,
    env: BTreeMap<String, String>,
    runner: Arc<dyn CommandRunner>,
}

impl Restic {
    /// `env` is the parsed env file. Both the repository and a password source must be present.
    pub fn new(
        cfg: BackupConfig,
        env: BTreeMap<String, String>,
        runner: Arc<dyn CommandRunner>,
    ) -> Result<Self, BackupError> {
        if !env.contains_key("RESTIC_REPOSITORY") {
            return Err(BackupError::MissingEnv("RESTIC_REPOSITORY"));
        }
        if !env.contains_key("RESTIC_PASSWORD_FILE") && !env.contains_key("RESTIC_PASSWORD_COMMAND")
        {
            return Err(BackupError::MissingEnv("RESTIC_PASSWORD_FILE"));
        }
        Ok(Self { cfg, env, runner })
    }

    pub fn load(cfg: BackupConfig, runner: Arc<dyn CommandRunner>) -> Result<Self, BackupError> {
        if let Some(sock) = cfg.service_socket.clone() {
            // The credentials live with the secrets service; only whether they exist is asked here.
            let boxs = crate::secrets_link::box_socket_for(&sock);
            let has = |name: &str| {
                crate::secrets_link::exists_checked(&boxs, name)
                    .map_err(|_| BackupError::ServiceUnavailable)
            };
            if !has("restic-env")? {
                return Err(BackupError::MissingEnv("the backup credentials"));
            }
            if !has("restic-password")? {
                return Err(BackupError::MissingEnv("the backup password"));
            }
            let runner: Arc<dyn CommandRunner> =
                Arc::new(crate::secrets_link::ServiceRunner { socket: sock });
            return Ok(Self {
                cfg,
                env: BTreeMap::new(),
                runner,
            });
        }
        let text = std::fs::read_to_string(&cfg.env_file)
            .map_err(|_| BackupError::MissingEnv("the env file"))?;
        Self::new(cfg, parse_env_file(&text), runner)
    }

    fn base(&self) -> CommandSpec {
        let mut c = CommandSpec::new(self.cfg.restic_bin.clone());
        c.env = self.env.clone();
        c
    }

    /// The tags a snapshot of this box carries, and the filter that finds exactly them (all of them, comma-joined).
    fn box_tags(&self) -> Vec<String> {
        let mut t = vec![self.cfg.tag.clone()];
        if let Some(b) = &self.cfg.box_name {
            t.push(format!("ozbox-box={b}"));
        }
        t
    }

    pub fn backup_cmd(&self) -> CommandSpec {
        let mut c = self
            .base()
            .args(["backup", "--one-file-system", "--tag"])
            .arg(self.box_tags().join(","));
        for e in &self.cfg.excludes {
            c = c.arg("--exclude").arg(e.clone());
        }
        // whatever the settings say, the secrets service's private folder is never in a backup
        for e in ozbox_core::backup_scope::NEVER_BACKED_UP {
            if !self.cfg.excludes.iter().any(|x| x == e) {
                c = c.arg("--exclude").arg(*e);
            }
        }
        c.args(self.cfg.paths.iter().cloned())
    }

    pub fn forget_cmd(&self) -> CommandSpec {
        self.base()
            .args(["forget", "--prune", "--tag"])
            .arg(self.box_tags().join(","))
            .arg("--keep-daily")
            .arg(self.cfg.keep_daily.to_string())
            .arg("--keep-weekly")
            .arg(self.cfg.keep_weekly.to_string())
            .arg("--keep-monthly")
            .arg(self.cfg.keep_monthly.to_string())
    }

    pub fn restore_cmd(&self, snapshot: &str, target: &str) -> Result<CommandSpec, BackupError> {
        if snapshot != "latest" && !valid_snapshot_id(snapshot) {
            return Err(BackupError::BadSnapshot);
        }
        if !target.starts_with('/') || target.contains('\0') {
            return Err(BackupError::BadTarget);
        }
        let mut c = self.base().args(["restore", snapshot, "--target", target]);
        // nor is it, or the audit chain, ever put back (an older snapshot still holds the folder)
        for e in ozbox_core::backup_scope::NEVER_RESTORED {
            c = c.arg("--exclude").arg(*e);
        }
        Ok(c)
    }

    pub fn snapshots_cmd(&self) -> CommandSpec {
        self.base()
            .args(["snapshots", "--json", "--tag"])
            .arg(self.box_tags().join(","))
    }

    /// The snapshots this box made (tagged for it), oldest first.
    pub fn snapshots(&self) -> Result<Vec<ResticSnapshot>, BackupError> {
        self.snapshots_within(None)
    }

    /// As [`Self::snapshots`], with a limit on how long restic may take (a runner that can stops it at the limit, and the
    /// answer is then a failure, like a repository that does not answer).
    pub fn snapshots_within(
        &self,
        limit: Option<std::time::Duration>,
    ) -> Result<Vec<ResticSnapshot>, BackupError> {
        let mut cmd = self.snapshots_cmd();
        cmd.timeout_secs = limit.map(|d| d.as_secs().max(1));
        let out = match self.runner.run(&cmd) {
            Ok(o) if o.status == Some(0) => o,
            Ok(o) => return Err(BackupError::Failed("snapshots", o.status)),
            Err(_) => return Err(BackupError::Failed("snapshots", None)),
        };
        parse_snapshots(&out.stdout).ok_or(BackupError::Failed("snapshots", Some(0)))
    }

    /// Forget one snapshot, and prune what only it held. The id must be one of this box's own snapshots.
    pub fn forget_one_cmd(&self, id: &str) -> Result<CommandSpec, BackupError> {
        if !valid_snapshot_id(id) {
            return Err(BackupError::BadSnapshot);
        }
        Ok(self.base().args(["forget", "--prune"]).arg(id))
    }

    pub fn forget_one(&self, id: &str) -> Result<(), BackupError> {
        let id = id.to_string();
        // Never trust an id on its own: it must be in the list of this box's snapshots.
        let own = self.snapshots()?;
        if !own.iter().any(|s| s.id == id || s.id.starts_with(&id)) {
            return Err(BackupError::BadSnapshot);
        }
        self.run("forget", &self.forget_one_cmd(&id)?)
    }

    /// Put a snapshot back over `/work` (files in it replace the ones on disk; files made since stay).
    pub fn restore_in_place(&self, snapshot: &str) -> Result<(), BackupError> {
        self.run("restore", &self.restore_cmd(snapshot, "/")?)
    }

    fn run(&self, what: &'static str, cmd: &CommandSpec) -> Result<(), BackupError> {
        match self.runner.run(cmd) {
            Ok(o) if o.status == Some(0) => Ok(()),
            // Deliberately no stderr: it may echo the repository location.
            Ok(o) => Err(BackupError::Failed(what, o.status)),
            Err(_) => Err(BackupError::Failed(what, None)),
        }
    }

    /// Back up, then apply retention. A forget failure does not hide a successful backup, but is reported.
    pub fn backup_and_forget(&self) -> Result<(), BackupError> {
        self.run("backup", &self.backup_cmd())?;
        self.run("forget", &self.forget_cmd())
    }

    pub fn restore(&self, snapshot: &str, target: &str) -> Result<(), BackupError> {
        self.run("restore", &self.restore_cmd(snapshot, target)?)
    }
}

fn valid_snapshot_id(s: &str) -> bool {
    (8..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// One snapshot as restic lists it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ResticSnapshot {
    pub id: String,
    /// RFC 3339, as restic reports it.
    pub time: String,
    pub tags: Vec<String>,
    /// Bytes processed by the backup, when this restic version reports it.
    pub size_bytes: Option<u64>,
}

/// Parse `restic snapshots --json`. `None` when the text is not what restic prints.
pub fn parse_snapshots(text: &str) -> Option<Vec<ResticSnapshot>> {
    let v: serde_json::Value = serde_json::from_str(text.trim()).ok()?;
    let mut out: Vec<ResticSnapshot> = v
        .as_array()?
        .iter()
        .filter_map(|e| {
            let id = e.get("id")?.as_str()?.to_string();
            if !valid_snapshot_id(&id) {
                return None;
            }
            Some(ResticSnapshot {
                id,
                time: e.get("time")?.as_str()?.to_string(),
                tags: e
                    .get("tags")
                    .and_then(|t| t.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default(),
                size_bytes: e
                    .pointer("/summary/total_bytes_processed")
                    .and_then(serde_json::Value::as_u64),
            })
        })
        .collect();
    out.sort_by(|a, b| a.time.cmp(&b.time));
    Some(out)
}

/// A simple interval schedule: due when never run, or when the interval has passed.
#[derive(Debug)]
pub struct BackupSchedule {
    interval_ms: u64,
    last_ms: Option<u64>,
}

impl BackupSchedule {
    pub fn new(interval_hours: u64) -> Self {
        Self {
            interval_ms: interval_hours.max(1) * 3_600_000,
            last_ms: None,
        }
    }
    pub fn due(&self, now_ms: u64) -> bool {
        self.last_ms
            .is_none_or(|l| now_ms.saturating_sub(l) >= self.interval_ms)
    }
    pub fn mark(&mut self, now_ms: u64) {
        self.last_ms = Some(now_ms);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ozbox_core::{Output, RecordingRunner};

    fn env() -> BTreeMap<String, String> {
        parse_env_file(
            "# creds\nRESTIC_REPOSITORY=s3:https://objects.example.com/bucket\nexport RESTIC_PASSWORD_FILE=\"/etc/ozbox/restic.pass\"\nAWS_SECRET_ACCESS_KEY='sekrit-key'\n",
        )
    }

    fn restic(rec: Arc<RecordingRunner>) -> Restic {
        Restic::new(BackupConfig::default(), env(), rec).unwrap()
    }

    #[test]
    fn env_file_parses() {
        let e = env();
        assert_eq!(e["RESTIC_PASSWORD_FILE"], "/etc/ozbox/restic.pass");
        assert_eq!(e["AWS_SECRET_ACCESS_KEY"], "sekrit-key");
    }

    #[test]
    fn exact_argv_and_secrets_only_in_env() {
        let rec = Arc::new(RecordingRunner::new());
        let r = restic(rec.clone());
        r.backup_and_forget().unwrap();
        let calls = rec.calls();
        assert_eq!(calls[0].program, "restic");
        assert_eq!(
            calls[0].args,
            [
                "backup",
                "--one-file-system",
                "--tag",
                "ozbox",
                "--exclude",
                "/work/.ozbox/metrics",
                "--exclude",
                "/work/ozbox-secrets-private",
                "/work"
            ]
        );
        assert_eq!(
            calls[1].args,
            [
                "forget",
                "--prune",
                "--tag",
                "ozbox",
                "--keep-daily",
                "7",
                "--keep-weekly",
                "4",
                "--keep-monthly",
                "6"
            ]
        );
        for c in &calls {
            assert_eq!(c.env["RESTIC_PASSWORD_FILE"], "/etc/ozbox/restic.pass");
            let argv = c.args.join(" ");
            assert!(
                !argv.contains("sekrit-key")
                    && !argv.contains("objects.example.com")
                    && !argv.contains("restic.pass")
            );
            let ser = serde_json::to_string(c).unwrap();
            assert!(!ser.contains("sekrit-key"), "env must not serialize");
        }
    }

    #[test]
    fn restore_validates_inputs() {
        let r = restic(Arc::new(RecordingRunner::new()));
        let c = r.restore_cmd("latest", "/work/restore").unwrap();
        assert_eq!(
            c.args,
            [
                "restore",
                "latest",
                "--target",
                "/work/restore",
                "--exclude",
                "/work/ozbox-secrets-private",
                "--exclude",
                "/work/ozbox-audit",
                "--exclude",
                "/work/ozbox-backup"
            ]
        );
        // the record root keeps of the backup set-up is never put back from an old snapshot: the exclusion is the folder the
        // helper writes to, whatever it is called
        #[cfg(unix)]
        assert!(ozbox_core::backup_scope::NEVER_RESTORED.contains(
            &crate::backup_state::dir_for(std::path::Path::new("/work"))
                .to_str()
                .unwrap()
        ));
        assert!(r.restore_cmd("deadbeef01", "/x").is_ok());
        assert_eq!(
            r.restore_cmd("--include=/etc", "/x").unwrap_err(),
            BackupError::BadSnapshot
        );
        assert_eq!(
            r.restore_cmd("latest", "rel").unwrap_err(),
            BackupError::BadTarget
        );
    }

    #[test]
    fn failures_do_not_echo_stderr() {
        let rec = Arc::new(RecordingRunner::new());
        rec.reply(Output {
            status: Some(1),
            stdout: String::new(),
            stderr: "repo s3:https://objects.example.com key sekrit-key".into(),
        });
        let e = restic(rec).backup_and_forget().unwrap_err();
        let msg = e.to_string();
        assert_eq!(e, BackupError::Failed("backup", Some(1)));
        assert!(!msg.contains("sekrit") && !msg.contains("objects.example.com"));
    }

    #[test]
    fn requires_repository_and_password_source() {
        let rec: Arc<dyn CommandRunner> = Arc::new(RecordingRunner::new());
        let mut e = env();
        e.remove("RESTIC_PASSWORD_FILE");
        assert!(matches!(
            Restic::new(BackupConfig::default(), e, rec.clone()),
            Err(BackupError::MissingEnv("RESTIC_PASSWORD_FILE"))
        ));
        assert!(matches!(
            Restic::new(BackupConfig::default(), BTreeMap::new(), rec),
            Err(BackupError::MissingEnv("RESTIC_REPOSITORY"))
        ));
    }

    #[test]
    fn schedule_interval() {
        let mut s = BackupSchedule::new(24);
        assert!(s.due(0));
        s.mark(1000);
        assert!(!s.due(1000 + 23 * 3_600_000));
        assert!(s.due(1000 + 24 * 3_600_000));
    }
}
