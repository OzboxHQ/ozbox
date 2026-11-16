//! Backups to a restic repository, on request, through the daemon's API.
//!
//! The dashboard server owns the schedule and the policy; this is the part that lives on the box, next to the data:
//! run a backup (and prune to the retention the caller names), list this box's snapshots, forget one, restore one, and
//! take new repository credentials. A backup can take hours, so a request starts it and answers at once; `status`
//! says whether one is running and how the last one ended. One operation runs at a time.
//!
//! Nothing here puts a repository location, a key or restic's own error text in an answer: a failure is an operation
//! name and an exit code (see [`crate::backup`]).

use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

use serde::{Deserialize, Serialize};

use ozbox_core::CommandRunner;

use crate::backup::{BackupConfig, BackupError, Restic, ResticSnapshot};
use crate::timeutil::Clock;

/// How long to keep what, in snapshots per period.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Retention {
    pub keep_daily: u32,
    pub keep_weekly: u32,
    pub keep_monthly: u32,
}

impl Retention {
    pub const MAX: u32 = 3650;

    pub fn valid(&self) -> bool {
        self.keep_daily <= Self::MAX
            && self.keep_weekly <= Self::MAX
            && self.keep_monthly <= Self::MAX
            && self.keep_daily + self.keep_weekly + self.keep_monthly > 0
    }
}

/// Whether backups that were set up on this box work now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupHealth {
    /// Backups were never set up here (or were removed on purpose): nothing to check.
    NotExpected,
    /// They were set up, the credentials are here and the repository answered.
    Working,
    /// They were set up and the credentials are not on this box any more.
    CredentialsMissing,
    /// They were set up, the credentials are here and the repository did not answer.
    Unreachable,
    /// They were set up, but the secrets service did not answer, so whether the credentials are here is not known yet
    /// (a box that has just started). Not a failure, and not the same as credentials that are missing.
    ServiceNotReady,
    /// A backup, restore or forget is using the repository (a prune holds it exclusively), so it was not asked.
    Busy,
    /// The repository has not been checked yet: a check is running in the background (it can take a minute on a slow
    /// network), or none has run since the box started. Not a failure.
    Pending,
}

/// How long a repository check's answer is kept before the next self-test starts another.
const PROBE_TTL_MS: u64 = 10 * 60 * 1000;

/// What the box is doing about backups right now, and how the last operation ended.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct BackupStatus {
    /// Credentials for a repository are on this box.
    pub configured: bool,
    /// Backups were set up on this box (a record root keeps on `/work`, so it outlives an upgrade). `expected` with no
    /// `configured` is backups that stopped.
    #[serde(default)]
    pub expected: bool,
    /// `backup`, `forget` or `restore` while one runs.
    pub running: Option<String>,
    pub running_since_ms: Option<u64>,
    pub last: Option<LastOp>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastOp {
    pub op: String,
    pub started_ms: u64,
    pub finished_ms: u64,
    pub ok: bool,
    /// Safe to show: an operation name and an exit code, never restic's own text.
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StartError {
    #[error("this box has no backup repository set up")]
    NotConfigured,
    #[error("another backup operation is still running")]
    Busy,
    #[error("{0}")]
    Refused(String),
}

#[derive(Default)]
struct Inner {
    running: Option<(String, u64)>,
    last: Option<LastOp>,
    probe: Probe,
}

/// The background check of the repository: one at a time, and its last answer.
#[derive(Default)]
struct Probe {
    inflight: bool,
    /// The answer and when it was got.
    result: Option<(BackupHealth, u64)>,
    /// Bumped when the credentials change, so a check that began before does not store what it found with the old ones.
    epoch: u64,
}

pub struct BackupService {
    cfg: BackupConfig,
    runner: Arc<dyn CommandRunner>,
    clock: Arc<dyn Clock>,
    inner: Mutex<Inner>,
    /// Run operations on the calling thread (tests); the daemon starts a thread per operation.
    inline: bool,
    /// Where the record that backups were set up lives (root's folder on `/work`, see `backup_state`).
    state_dir: Option<(PathBuf, u32)>,
}

static GLOBAL: OnceLock<Arc<BackupService>> = OnceLock::new();

/// The daemon's backup service, once started. The API routes `/v1/backup/...` to it.
pub fn global() -> Option<&'static Arc<BackupService>> {
    GLOBAL.get()
}

pub fn install_global(s: Arc<BackupService>) {
    let _ = GLOBAL.set(s);
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl BackupService {
    pub fn new(cfg: BackupConfig, runner: Arc<dyn CommandRunner>, clock: Arc<dyn Clock>) -> Self {
        Self {
            cfg,
            runner,
            clock,
            inner: Mutex::new(Inner::default()),
            inline: false,
            state_dir: None,
        }
    }

    /// Read the record that backups were set up from `dir` (root's folder on `/work`).
    pub fn with_state_dir(self, dir: PathBuf) -> Self {
        self.with_state_dir_owned_by(dir, 0)
    }

    /// As [`Self::with_state_dir`], with the user that must own the record (root, 0, on a box; a test's own user).
    pub fn with_state_dir_owned_by(mut self, dir: PathBuf, uid: u32) -> Self {
        self.state_dir = Some((dir, uid));
        self
    }

    /// Whether backups were set up on this box, by the record root keeps on `/work`. False without a folder, and for a
    /// record that cannot be trusted (it is never obeyed).
    #[cfg(unix)]
    pub fn expected(&self) -> bool {
        self.state_dir
            .as_ref()
            .is_some_and(|(d, uid)| matches!(crate::backup_state::read(d, *uid), Ok(Some(_))))
    }

    #[cfg(not(unix))]
    pub fn expected(&self) -> bool {
        false
    }

    /// Whether backups that were set up are working. It never waits for the repository: restic runs in a background check
    /// (one at a time) and this reports its last answer, or `Pending` while there is none. What it does ask directly is
    /// cheap and local: whether backups were set up, whether the secrets service answers and holds the credentials, and
    /// whether an operation is using the repository. Never carries restic's text, the repository or a credential.
    pub fn health(self: &Arc<Self>) -> BackupHealth {
        if !self.expected() {
            return BackupHealth::NotExpected;
        }
        match self.restic() {
            Err(BackupError::ServiceUnavailable) => return BackupHealth::ServiceNotReady,
            Err(_) => return BackupHealth::CredentialsMissing,
            Ok(_) => {}
        }
        let now = self.clock.now_ms();
        {
            let g = lock(&self.inner);
            if g.running.is_some() {
                return BackupHealth::Busy;
            }
            if let Some((h, at)) = g.probe.result {
                if now.saturating_sub(at) < PROBE_TTL_MS {
                    return h;
                }
            }
        }
        self.start_probe();
        match lock(&self.inner).probe.result {
            Some((h, at)) if now.saturating_sub(at) < PROBE_TTL_MS => h,
            _ => BackupHealth::Pending,
        }
    }

    /// Ask the repository now (waits for it). The background check runs this; it is not called on a request.
    fn probe_repository(&self) -> BackupHealth {
        match self.restic() {
            Err(BackupError::ServiceUnavailable) => BackupHealth::ServiceNotReady,
            Err(_) => BackupHealth::CredentialsMissing,
            Ok(r) => match r.snapshots() {
                Ok(_) => BackupHealth::Working,
                Err(_) => BackupHealth::Unreachable,
            },
        }
    }

    /// Start the background check unless one is already running (a slow or dead repository must not pile up threads and
    /// restic children, one per self-test). Its answer is kept, except when an operation began meanwhile: a prune's
    /// exclusive lock would make a healthy repository look unreachable.
    pub fn start_probe(self: &Arc<Self>) {
        {
            let mut g = lock(&self.inner);
            if g.probe.inflight {
                return;
            }
            g.probe.inflight = true;
        }
        let me = Arc::clone(self);
        let epoch = lock(&self.inner).probe.epoch;
        let job = move || {
            let h = me.probe_repository();
            let now = me.clock.now_ms();
            let mut g = lock(&me.inner);
            g.probe.inflight = false;
            if g.running.is_none() && g.probe.epoch == epoch {
                g.probe.result = Some((h, now));
            }
        };
        if self.inline {
            job();
        } else if std::thread::Builder::new()
            .name("ozboxd-backup-probe".into())
            .spawn(job)
            .is_err()
        {
            lock(&self.inner).probe.inflight = false;
        }
    }

    /// Forget the last repository check (the credentials changed, so it no longer says anything).
    fn forget_probe(&self) {
        let mut g = lock(&self.inner);
        g.probe.result = None;
        g.probe.epoch += 1;
    }

    pub fn inline(mut self) -> Self {
        self.inline = true;
        self
    }

    pub fn env_file(&self) -> &PathBuf {
        &self.cfg.env_file
    }

    fn restic(&self) -> Result<Restic, BackupError> {
        self.restic_with(None)
    }

    fn restic_with(&self, keep: Option<Retention>) -> Result<Restic, BackupError> {
        let mut cfg = self.cfg.clone();
        if let Some(k) = keep {
            cfg.keep_daily = k.keep_daily;
            cfg.keep_weekly = k.keep_weekly;
            cfg.keep_monthly = k.keep_monthly;
        }
        Restic::load(cfg, self.runner.clone())
    }

    pub fn configured(&self) -> bool {
        self.restic().is_ok()
    }

    pub fn status(&self) -> BackupStatus {
        let g = lock(&self.inner);
        BackupStatus {
            configured: self.configured(),
            expected: self.expected(),
            running: g.running.as_ref().map(|r| r.0.clone()),
            running_since_ms: g.running.as_ref().map(|r| r.1),
            last: g.last.clone(),
        }
    }

    pub fn snapshots(&self) -> Result<Vec<ResticSnapshot>, BackupError> {
        self.restic()?.snapshots()
    }

    fn begin(&self, op: &str) -> Result<u64, StartError> {
        if !self.configured() {
            return Err(StartError::NotConfigured);
        }
        let mut g = lock(&self.inner);
        if g.running.is_some() {
            return Err(StartError::Busy);
        }
        let now = self.clock.now_ms();
        g.running = Some((op.to_string(), now));
        Ok(now)
    }

    fn finish(&self, op: &str, started: u64, res: Result<(), BackupError>) {
        let mut g = lock(&self.inner);
        g.running = None;
        g.last = Some(LastOp {
            op: op.to_string(),
            started_ms: started,
            finished_ms: self.clock.now_ms(),
            ok: res.is_ok(),
            error: res.err().map(|e| e.to_string()),
        });
    }

    fn spawn(
        self: &Arc<Self>,
        op: &'static str,
        started: u64,
        keep: Option<Retention>,
        work: impl FnOnce(&Restic) -> Result<(), BackupError> + Send + 'static,
    ) {
        let me = Arc::clone(self);
        let job = move || {
            let res = me.restic_with(keep).and_then(|r| work(&r));
            me.finish(op, started, res);
        };
        if self.inline {
            job();
        } else if std::thread::Builder::new()
            .name(format!("ozboxd-{op}"))
            .spawn(job)
            .is_err()
        {
            self.finish(
                op,
                started,
                Err(BackupError::Failed("the operation could not start", None)),
            );
        }
    }

    /// Back up `/work`, then prune to `keep`. Answers at once; `status` follows it. A prune that fails does not hide
    /// a backup that worked, but is reported as the operation's error.
    pub fn start_backup(self: &Arc<Self>, keep: Retention) -> Result<(), StartError> {
        if !keep.valid() {
            return Err(StartError::Refused(
                "the retention must keep at least one backup, and at most 3650 of each kind".into(),
            ));
        }
        let started = self.begin("backup")?;
        self.spawn("backup", started, Some(keep), |r| r.backup_and_forget());
        Ok(())
    }

    /// Forget one of this box's snapshots and prune what only it held.
    pub fn start_forget(self: &Arc<Self>, id: &str) -> Result<(), StartError> {
        if !is_id(id) {
            return Err(StartError::Refused("that is not a snapshot id".into()));
        }
        let started = self.begin("forget")?;
        let id = id.to_string();
        self.spawn("forget", started, None, move |r| r.forget_one(&id));
        Ok(())
    }

    /// Restore a snapshot: over `/work` (`in_place`), or into a folder beside the files, `/work/restored-<id>`.
    pub fn start_restore(self: &Arc<Self>, id: &str, in_place: bool) -> Result<(), StartError> {
        if !is_id(id) {
            return Err(StartError::Refused("that is not a snapshot id".into()));
        }
        let started = self.begin("restore")?;
        let id = id.to_string();
        self.spawn("restore", started, None, move |r| {
            if in_place {
                r.restore_in_place(&id)
            } else {
                let short: String = id.chars().take(8).collect();
                r.restore(&id, &format!("/work/restored-{short}"))
            }
        });
        Ok(())
    }
}

fn err(status: u16, code: &str, message: &str) -> (u16, serde_json::Value) {
    (
        status,
        serde_json::json!({ "error": message, "code": code }),
    )
}

impl BackupService {
    /// One request of the `/v1/backup/...` API, as `(status, JSON)`. `sub` is the path after `/v1/backup`. `provision`
    /// puts new credentials on the box (the daemon's way is the root helper; the sandbox writes a temporary folder).
    pub fn handle(
        self: &Arc<Self>,
        method: &str,
        sub: &str,
        body: &serde_json::Value,
        provision: &dyn Fn(&crate::backup_root::Request) -> Result<Option<String>, String>,
        now_ms: u64,
    ) -> (u16, serde_json::Value) {
        use crate::backup_root::{Action, Request as Provision};
        let started = |r: Result<(), StartError>| match r {
            Ok(()) => (202, serde_json::json!({ "started": true })),
            Err(StartError::NotConfigured) => err(
                409,
                "not_configured",
                &StartError::NotConfigured.to_string(),
            ),
            Err(StartError::Busy) => err(409, "busy", &StartError::Busy.to_string()),
            Err(StartError::Refused(m)) => err(400, "refused", &m),
        };
        let word = |k: &str| {
            body.get(k)
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
        };
        match (method, sub) {
            ("GET", "/status") => (200, serde_json::to_value(self.status()).unwrap_or_default()),
            ("GET", "/snapshots") => {
                // a prune or a restore holds the repository; listing it then fails for a reason that is not "unreachable"
                if lock(&self.inner).running.is_some() {
                    return err(
                        409,
                        "busy",
                        "a backup operation is using the repository right now; try again when it finishes",
                    );
                }
                match self.snapshots() {
                    Ok(items) => (200, serde_json::json!({ "items": items })),
                    Err(BackupError::MissingEnv(_)) => err(
                        409,
                        "not_configured",
                        "this box has no backup repository set up",
                    ),
                    Err(BackupError::ServiceUnavailable) => err(
                        503,
                        "secrets_not_ready",
                        "the box's secrets service is not ready yet; try again in a moment",
                    ),
                    Err(e) => err(502, "backup_failed", &e.to_string()),
                }
            }
            ("POST", "/run") => {
                let n = |k: &str, d: u32| {
                    body.get(k)
                        .and_then(serde_json::Value::as_u64)
                        .map_or(d, |v| u32::try_from(v).unwrap_or(u32::MAX))
                };
                started(self.start_backup(Retention {
                    keep_daily: n("keep_daily", 7),
                    keep_weekly: n("keep_weekly", 4),
                    keep_monthly: n("keep_monthly", 6),
                }))
            }
            ("POST", "/forget") => started(self.start_forget(word("snapshot"))),
            ("POST", "/restore") => started(self.start_restore(
                word("snapshot"),
                body.get("in_place").and_then(serde_json::Value::as_bool) == Some(true),
            )),
            ("PUT" | "DELETE", "/credentials") => {
                let env = body
                    .get("env")
                    .and_then(serde_json::Value::as_object)
                    .map(|o| {
                        o.iter()
                            .filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_string())))
                            .collect()
                    })
                    .unwrap_or_default();
                let req = Provision {
                    id: format!("c{now_ms}"),
                    action: if method == "PUT" {
                        Action::Set
                    } else {
                        Action::Clear
                    },
                    env,
                    password: word("password").to_string(),
                };
                let done = provision(&req);
                // whatever the answer, what the last check said about the old credentials no longer applies
                self.forget_probe();
                match done {
                    Ok(None) => (200, serde_json::json!({ "ok": true })),
                    // done, with something to know (a record that could not be kept): never a failure of the credentials
                    Ok(Some(w)) => (200, serde_json::json!({ "ok": true, "warning": w })),
                    Err(m) => err(422, "provision_failed", &m),
                }
            }
            (_, "/status" | "/snapshots" | "/run" | "/forget" | "/restore" | "/credentials") => {
                err(405, "method_not_allowed", "method not allowed")
            }
            _ => err(404, "not_found", "not found"),
        }
    }
}

fn is_id(s: &str) -> bool {
    (8..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timeutil::FakeClock;
    use ozbox_core::{Output, RecordingRunner};

    fn env_file(dir: &std::path::Path) -> PathBuf {
        let p = dir.join("restic.env");
        std::fs::write(
            &p,
            "RESTIC_REPOSITORY=s3:https://objects.example.com/bucket\nRESTIC_PASSWORD_FILE=/etc/ozbox/restic.pass\nAWS_SECRET_ACCESS_KEY=sekrit-key\n",
        )
        .unwrap();
        p
    }

    fn svc(dir: &std::path::Path, rec: Arc<RecordingRunner>) -> Arc<BackupService> {
        let cfg = BackupConfig {
            env_file: env_file(dir),
            box_name: Some("main".into()),
            ..BackupConfig::default()
        };
        Arc::new(BackupService::new(cfg, rec, Arc::new(FakeClock::new(1_000))).inline())
    }

    const KEEP: Retention = Retention {
        keep_daily: 7,
        keep_weekly: 4,
        keep_monthly: 3,
    };

    #[test]
    fn a_backup_is_tagged_for_the_box_and_pruned_to_the_asked_for_retention() {
        let dir = tempfile::tempdir().unwrap();
        let rec = Arc::new(RecordingRunner::new());
        let s = svc(dir.path(), rec.clone());
        s.start_backup(KEEP).unwrap();
        let calls = rec.calls();
        assert_eq!(calls[0].args[0], "backup");
        assert!(calls[0].args.contains(&"ozbox,ozbox-box=main".to_string()));
        assert_eq!(calls[1].args[0], "forget");
        let a = calls[1].args.join(" ");
        assert!(a.contains("--tag ozbox,ozbox-box=main"));
        assert!(
            a.contains("--keep-daily 7 --keep-weekly 4 --keep-monthly 3"),
            "{a}"
        );
        let st = s.status();
        assert!(st.configured && st.running.is_none());
        let last = st.last.unwrap();
        assert!(last.ok && last.op == "backup" && last.error.is_none());
    }

    #[test]
    fn a_failure_is_reported_without_restics_text_or_the_repository() {
        let dir = tempfile::tempdir().unwrap();
        let rec = Arc::new(RecordingRunner::new());
        rec.reply(Output {
            status: Some(1),
            stdout: String::new(),
            stderr: "Fatal: repository s3:https://objects.example.com/bucket key sekrit-key".into(),
        });
        let s = svc(dir.path(), rec);
        s.start_backup(KEEP).unwrap();
        let last = s.status().last.unwrap();
        assert!(!last.ok);
        let shown = serde_json::to_string(&s.status()).unwrap();
        assert!(
            !shown.contains("sekrit") && !shown.contains("objects.example.com"),
            "{shown}"
        );
        assert_eq!(
            last.error.as_deref(),
            Some("restic backup failed (exit Some(1))")
        );
    }

    #[test]
    fn without_credentials_nothing_runs() {
        let dir = tempfile::tempdir().unwrap();
        let rec = Arc::new(RecordingRunner::new());
        let cfg = BackupConfig {
            env_file: dir.path().join("absent.env"),
            ..BackupConfig::default()
        };
        let s =
            Arc::new(BackupService::new(cfg, rec.clone(), Arc::new(FakeClock::new(0))).inline());
        assert_eq!(s.start_backup(KEEP), Err(StartError::NotConfigured));
        assert!(!s.status().configured);
        assert!(rec.calls().is_empty());
    }

    #[test]
    fn a_retention_that_keeps_nothing_or_too_much_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let s = svc(dir.path(), Arc::new(RecordingRunner::new()));
        for bad in [
            Retention {
                keep_daily: 0,
                keep_weekly: 0,
                keep_monthly: 0,
            },
            Retention {
                keep_daily: 4000,
                keep_weekly: 0,
                keep_monthly: 0,
            },
        ] {
            assert!(matches!(s.start_backup(bad), Err(StartError::Refused(_))));
        }
    }

    #[test]
    fn only_a_snapshot_the_box_made_can_be_forgotten() {
        let dir = tempfile::tempdir().unwrap();
        let rec = Arc::new(RecordingRunner::new());
        rec.reply(Output {
            status: Some(0),
            stdout: r#"[{"id":"aaaaaaaa11111111","time":"2026-11-01T01:00:00Z","tags":["ozbox","ozbox-box=main"]}]"#.into(),
            stderr: String::new(),
        });
        let s = svc(dir.path(), rec.clone());
        s.start_forget("bbbbbbbb22222222").unwrap();
        let last = s.status().last.unwrap();
        assert!(!last.ok, "an id that is not in this box's list is refused");
        assert!(rec.calls().iter().all(|c| c.args[0] != "forget"));
        // a real one goes through
        let rec = Arc::new(RecordingRunner::new());
        rec.reply(Output {
            status: Some(0),
            stdout: r#"[{"id":"aaaaaaaa11111111","time":"2026-11-01T01:00:00Z","tags":["ozbox"]}]"#
                .into(),
            stderr: String::new(),
        });
        let s = svc(dir.path(), rec.clone());
        s.start_forget("aaaaaaaa11111111").unwrap();
        assert!(s.status().last.unwrap().ok);
        assert_eq!(
            rec.calls()[1].args,
            ["forget", "--prune", "aaaaaaaa11111111"]
        );
        assert!(matches!(
            s.start_forget("--keep-last=0"),
            Err(StartError::Refused(_))
        ));
    }

    #[test]
    fn restore_goes_to_a_folder_beside_the_files_or_over_work() {
        let dir = tempfile::tempdir().unwrap();
        let rec = Arc::new(RecordingRunner::new());
        let s = svc(dir.path(), rec.clone());
        s.start_restore("aaaaaaaa11111111", false).unwrap();
        s.start_restore("aaaaaaaa11111111", true).unwrap();
        let c = rec.calls();
        // never the secrets service's private folder or the audit chain, whichever the target
        let never = [
            "--exclude",
            "/work/ozbox-secrets-private",
            "--exclude",
            "/work/ozbox-audit",
            "--exclude",
            "/work/ozbox-backup",
        ];
        assert_eq!(
            c[0].args,
            [
                &[
                    "restore",
                    "aaaaaaaa11111111",
                    "--target",
                    "/work/restored-aaaaaaaa"
                ][..],
                &never[..]
            ]
            .concat()
        );
        assert_eq!(
            c[1].args,
            [
                &["restore", "aaaaaaaa11111111", "--target", "/"][..],
                &never[..]
            ]
            .concat()
        );
        assert!(matches!(
            s.start_restore("../x", true),
            Err(StartError::Refused(_))
        ));
    }

    #[test]
    fn a_second_operation_while_one_runs_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let s = svc(dir.path(), Arc::new(RecordingRunner::new()));
        // Simulate one in flight.
        lock(&s.inner).running = Some(("backup".into(), 5));
        assert_eq!(s.start_backup(KEEP), Err(StartError::Busy));
        let st = s.status();
        assert_eq!(st.running.as_deref(), Some("backup"));
        assert_eq!(st.running_since_ms, Some(5));
    }

    #[test]
    fn snapshots_are_parsed_oldest_first_with_their_size_when_restic_says() {
        let dir = tempfile::tempdir().unwrap();
        let rec = Arc::new(RecordingRunner::new());
        rec.reply(Output {
            status: Some(0),
            stdout: r#"[{"id":"bbbbbbbb22222222","time":"2026-11-02T01:00:00Z","tags":["ozbox"],"summary":{"total_bytes_processed":1048576}},{"id":"aaaaaaaa11111111","time":"2026-11-01T01:00:00Z","tags":["ozbox"]},{"id":"bad","time":"x"}]"#.into(),
            stderr: String::new(),
        });
        let list = svc(dir.path(), rec).snapshots().unwrap();
        assert_eq!(list.len(), 2, "an entry with a malformed id is dropped");
        assert_eq!(list[0].id, "aaaaaaaa11111111");
        assert_eq!(list[1].size_bytes, Some(1_048_576));
    }

    #[cfg(unix)]
    fn me() -> u32 {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(".").unwrap().uid()
    }

    #[cfg(unix)]
    #[test]
    fn backups_that_were_set_up_are_expected_and_health_says_whether_they_work() {
        use crate::backup_state::{merge, write};
        let dir = tempfile::tempdir().unwrap();
        let rec = Arc::new(RecordingRunner::new());
        let state = dir.path().join("ozbox-backup");
        let mk = |env: PathBuf, rec: Arc<RecordingRunner>| {
            Arc::new(
                BackupService::new(
                    BackupConfig {
                        env_file: env,
                        box_name: Some("main".into()),
                        ..BackupConfig::default()
                    },
                    rec,
                    Arc::new(FakeClock::new(1_000)),
                )
                .inline()
                .with_state_dir_owned_by(state.clone(), me()),
            )
        };
        // never set up: nothing to check, and the status says so
        let svc = mk(env_file(dir.path()), rec.clone());
        assert_eq!(svc.health(), BackupHealth::NotExpected);
        assert!(!svc.status().expected);
        // set up, credentials present, the repository answers
        write(
            &state,
            &merge(None, &crate::config::BackupSection::default()),
            me(),
        )
        .unwrap();
        rec.reply(Output {
            status: Some(0),
            stdout: "[]".into(),
            stderr: String::new(),
        });
        assert!(svc.status().expected && svc.status().configured);
        assert_eq!(svc.health(), BackupHealth::Working);
        // the answer is kept: a second ask does not run restic again
        let asked = rec.calls().len();
        assert_eq!(svc.health(), BackupHealth::Working);
        assert_eq!(rec.calls().len(), asked);
        // set up, credentials present, the repository does not answer (a later check)
        svc.forget_probe();
        rec.reply(Output {
            status: Some(1),
            stdout: String::new(),
            stderr: "Fatal: unable to open repository at s3:https://objects.example.com/b".into(),
        });
        assert_eq!(svc.health(), BackupHealth::Unreachable);
        // set up, and the credentials are gone (a new secrets store)
        let lost = mk(dir.path().join("absent.env"), rec.clone());
        assert_eq!(lost.health(), BackupHealth::CredentialsMissing);
        assert!(lost.status().expected && !lost.status().configured);
        // the health never carries restic's text or the repository
        assert!(!format!("{:?}", svc.health()).contains("objects"));
    }

    /// A restic that answers only when the test lets it (a slow network without a slow test), counting how often it is asked.
    struct GateRunner {
        asked: std::sync::atomic::AtomicUsize,
        release: Mutex<std::sync::mpsc::Receiver<()>>,
    }

    impl GateRunner {
        fn new() -> (Arc<Self>, std::sync::mpsc::Sender<()>) {
            let (tx, rx) = std::sync::mpsc::channel();
            (
                Arc::new(Self {
                    asked: Default::default(),
                    release: Mutex::new(rx),
                }),
                tx,
            )
        }
    }

    impl CommandRunner for GateRunner {
        fn run(&self, _cmd: &ozbox_core::CommandSpec) -> ozbox_core::Result<Output> {
            self.asked
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let _ = self.release.lock().unwrap().recv();
            Ok(Output {
                status: Some(0),
                stdout: "[]".into(),
                stderr: String::new(),
            })
        }
    }

    #[cfg(unix)]
    fn waiting_for(what: &str, ok: impl Fn() -> bool) {
        for _ in 0..400 {
            if ok() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        panic!("{what}");
    }

    /// A service for health tests: the daemon's own shape (a thread per check), with the record written.
    #[cfg(unix)]
    fn recorded(dir: &std::path::Path, runner: Arc<dyn CommandRunner>) -> Arc<BackupService> {
        let state = dir.join("ozbox-backup");
        crate::backup_state::write(
            &state,
            &crate::backup_state::merge(None, &crate::config::BackupSection::default()),
            me(),
        )
        .unwrap();
        Arc::new(
            BackupService::new(
                BackupConfig {
                    env_file: env_file(dir),
                    box_name: Some("main".into()),
                    ..BackupConfig::default()
                },
                runner,
                Arc::new(FakeClock::new(1_000)),
            )
            .with_state_dir_owned_by(state, me()),
        )
    }

    #[cfg(unix)]
    #[test]
    fn a_slow_repository_never_holds_the_health_check_and_never_piles_up_checks() {
        let dir = tempfile::tempdir().unwrap();
        let (gate, release) = GateRunner::new();
        let svc = recorded(dir.path(), gate.clone());
        // the repository is slow (it answers when released): the answer is at once, "not verified yet", never a failure
        let asks = |svc: &Arc<BackupService>| {
            let (tx, rx) = std::sync::mpsc::channel();
            let svc = Arc::clone(svc);
            std::thread::spawn(move || {
                let _ = tx.send(svc.health());
            });
            rx.recv_timeout(std::time::Duration::from_secs(2))
                .unwrap_or_else(|_| panic!("the health check waited for the repository"))
        };
        assert_eq!(asks(&svc), BackupHealth::Pending);
        for _ in 0..5 {
            assert_eq!(asks(&svc), BackupHealth::Pending);
        }
        // six asks, one restic: a dead network does not leave a thread and a child behind per self-test
        waiting_for("the check did not start", || {
            gate.asked.load(std::sync::atomic::Ordering::SeqCst) == 1
        });
        assert_eq!(gate.asked.load(std::sync::atomic::Ordering::SeqCst), 1);
        // when it answers, the next ask has the answer (and still only one restic ran)
        release.send(()).unwrap();
        waiting_for("the check did not finish", || {
            svc.health() == BackupHealth::Working
        });
        assert_eq!(gate.asked.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[cfg(unix)]
    #[test]
    fn while_an_operation_holds_the_repository_health_says_busy_and_snapshots_say_busy_not_unreachable() {
        let dir = tempfile::tempdir().unwrap();
        let rec = Arc::new(RecordingRunner::new());
        let svc = recorded(dir.path(), rec.clone());
        lock(&svc.inner).running = Some(("forget".into(), 1));
        assert_eq!(svc.health(), BackupHealth::Busy);
        assert!(rec.calls().is_empty(), "restic is not asked while one is running");
        let (status, v) = svc.handle("GET", "/snapshots", &serde_json::Value::Null, &|_| Ok(None), 1);
        assert_eq!((status, v["code"].as_str()), (409, Some("busy")));
        assert!(rec.calls().is_empty());
        // a check that finishes after an operation began is not kept: a prune's lock would make a good repository look dead
        lock(&svc.inner).running = None;
        let slow = {
            let (gate, release) = GateRunner::new();
            let s = recorded(dir.path(), gate.clone());
            assert_eq!(s.health(), BackupHealth::Pending);
            waiting_for("the check did not start", || {
                gate.asked.load(std::sync::atomic::Ordering::SeqCst) == 1
            });
            lock(&s.inner).running = Some(("backup".into(), 2));
            release.send(()).unwrap();
            waiting_for("the check did not end", || !lock(&s.inner).probe.inflight);
            s
        };
        lock(&slow.inner).running = None;
        assert!(lock(&slow.inner).probe.result.is_none());
    }

    /// A secrets service that answers `exists` with a fixed flag.
    #[cfg(unix)]
    fn fake_secrets(dir: &std::path::Path, flag: bool) -> PathBuf {
        use std::io::{BufRead, BufReader, Write};
        let broker = dir.join("run/broker/broker.sock");
        let boxs = dir.join("run/box/box.sock");
        std::fs::create_dir_all(boxs.parent().unwrap()).unwrap();
        let l = std::os::unix::net::UnixListener::bind(&boxs).unwrap();
        std::thread::spawn(move || {
            for c in l.incoming().flatten() {
                let mut line = String::new();
                BufReader::new(&c).read_line(&mut line).unwrap();
                let mut w = &c;
                w.write_all(format!("{{\"ok\":true,\"flag\":{flag}}}\n").as_bytes())
                    .unwrap();
            }
        });
        broker
    }

    #[cfg(unix)]
    #[test]
    fn a_secrets_service_that_is_not_up_is_not_called_missing_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let rec = Arc::new(RecordingRunner::new());
        let state = dir.path().join("ozbox-backup");
        crate::backup_state::write(
            &state,
            &crate::backup_state::merge(None, &crate::config::BackupSection::default()),
            me(),
        )
        .unwrap();
        let mk = |socket: PathBuf| {
            Arc::new(
                BackupService::new(
                    BackupConfig {
                        service_socket: Some(socket),
                        box_name: Some("main".into()),
                        ..BackupConfig::default()
                    },
                    rec.clone(),
                    Arc::new(FakeClock::new(1_000)),
                )
                .inline()
                .with_state_dir_owned_by(state.clone(), me()),
            )
        };
        // the service is not there yet (the box has just started): not verified, and not a stop
        let down = mk(dir.path().join("nothing/broker/broker.sock"));
        assert_eq!(down.health(), BackupHealth::ServiceNotReady);
        let (status, v) = down.handle("GET", "/snapshots", &serde_json::Value::Null, &|_| Ok(None), 1);
        assert_eq!((status, v["code"].as_str()), (503, Some("secrets_not_ready")));
        // the service answers and holds nothing: that one is a loss
        let empty = mk(fake_secrets(dir.path(), false));
        assert_eq!(empty.health(), BackupHealth::CredentialsMissing);
        let (status, v) = empty.handle("GET", "/snapshots", &serde_json::Value::Null, &|_| Ok(None), 1);
        assert_eq!((status, v["code"].as_str()), (409, Some("not_configured")));
        assert!(rec.calls().is_empty());
    }

    #[test]
    fn sending_credentials_forgets_the_last_check_and_a_warning_is_a_success_that_carries_it() {
        let dir = tempfile::tempdir().unwrap();
        let rec = Arc::new(RecordingRunner::new());
        let s = svc(dir.path(), rec);
        let body = serde_json::json!({"env": {}, "password": "x"});
        lock(&s.inner).probe.result = Some((BackupHealth::Unreachable, 1_000));
        let (status, v) = s.handle("PUT", "/credentials", &body, &|_| Ok(Some("note".into())), 5);
        assert_eq!(status, 200);
        assert_eq!((v["ok"].as_bool(), v["warning"].as_str()), (Some(true), Some("note")));
        assert!(lock(&s.inner).probe.result.is_none());
        let (status, v) = s.handle("PUT", "/credentials", &body, &|_| Ok(None), 6);
        assert_eq!(status, 200);
        assert!(v.get("warning").is_none());
        let (status, _) = s.handle("PUT", "/credentials", &body, &|_| Err("no".into()), 7);
        assert_eq!(status, 422);
    }
}
