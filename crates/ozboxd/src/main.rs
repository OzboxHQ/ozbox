#![cfg_attr(test, allow(clippy::unwrap_used))]
//! `ozboxd` - the Oz Box daemon. Threads: sampler (metrics + run reaping), idle loop, maintenance (self-test, health
//! refresh, backups) and the Unix-socket API. SIGTERM / SIGINT checkpoint and exit. Logs go to stderr (journald)
//! and carry ids and numbers only.

#[cfg(not(unix))]
fn main() {
    eprintln!("ozboxd runs on Linux only");
    std::process::exit(1);
}

#[cfg(unix)]
fn main() {
    if let Err(e) = daemon::run() {
        eprintln!("ozboxd: fatal: {e}");
        std::process::exit(1);
    }
}

#[cfg(unix)]
mod daemon {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::JoinHandle;
    use std::time::Duration;

    use ozbox_core::{BoxName, CommandRunner, SystemRunner};
    use ozboxd::api::{self, lock, AppState, HealthInfo};
    use ozboxd::backup::{BackupConfig, BackupSchedule, Restic};
    use ozboxd::checkpoint::{CheckpointConfig, Checkpointer};
    use ozboxd::config::{Config, DEFAULT_CONFIG_PATH};
    use ozboxd::health::{self, IncidentKind, IncidentLog, OomWatcher};
    use ozboxd::host::{FsHost, HostSource};
    use ozboxd::idle::{
        CombinedSessions, CommandStopRequester, IdleConfig, IdleLoop, StepOutcome, StopRequester,
        TunnelSessions, UnconfiguredStop, WhoSessions,
    };
    use ozboxd::interruption::InterruptionWatcher;
    use ozboxd::metrics::Sampler;
    use ozboxd::run_backend::{BackendMode, BackendSwitch};
    use ozboxd::run_units::{SystemdUserUnits, UnitSpawner, UnitSpawnerConfig};
    use ozboxd::runs::{
        FsCgroup, HostMemory, RunConfig, RunManager, RunRequest, Spawner, StdSpawner,
    };
    use ozboxd::selftest::{self, SelfTestConfig, SelfTestResult};
    use ozboxd::store::{Step, Store, StoreConfig};
    use ozboxd::timeutil::{Clock, SystemClock, MINUTE_MS};
    use signal_hook::consts::{SIGINT, SIGTERM};
    use signal_hook::iterator::Signals;

    fn log(msg: &str) {
        eprintln!("ozboxd: {msg}");
    }

    /// Sleep up to `total`, waking early when shutdown is set.
    fn sleep_unless(shutdown: &AtomicBool, total: Duration) {
        let mut left = total;
        let slice = Duration::from_millis(200);
        while !shutdown.load(Ordering::SeqCst) && !left.is_zero() {
            let d = left.min(slice);
            std::thread::sleep(d);
            left = left.saturating_sub(d);
        }
    }

    fn load_config() -> Result<Config, String> {
        let mut args = std::env::args().skip(1);
        let mut path = PathBuf::from(DEFAULT_CONFIG_PATH);
        while let Some(a) = args.next() {
            match a.as_str() {
                "--config" => path = PathBuf::from(args.next().ok_or("--config needs a path")?),
                // `ozboxd growfs` is handled by `run`; it takes the same --config.
                "growfs" => {}
                "--version" => {
                    println!("ozboxd {}", env!("CARGO_PKG_VERSION"));
                    std::process::exit(0);
                }
                _ => return Err("usage: ozboxd [growfs] [--config <path>] [--version]".into()),
            }
        }
        match std::fs::read_to_string(&path) {
            Ok(t) => Config::from_toml(&t),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(format!("cannot read config: {}", e.kind())),
        }
    }

    fn box_name(cfg: &Config) -> BoxName {
        let candidate = cfg.box_name.clone().or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_string())
        });
        candidate
            .and_then(|n| BoxName::new(n).ok())
            .or_else(|| BoxName::new("box").ok())
            .unwrap_or_else(unreachable_box_name)
    }

    // "box" is a valid name; this keeps the no-unwrap rule without a panic path in normal operation.
    fn unreachable_box_name() -> BoxName {
        BoxName::new("box").unwrap_or_else(|_| std::process::exit(1))
    }

    /// `ozboxd growfs`: the privileged one-shot. Run as root by `ozbox-growfs.service` on a timer; it does the one
    /// grow command and leaves a result file for the (unprivileged) daemon to report. Nothing else runs here.
    fn growfs_once(cfg: &Config) -> Result<(), String> {
        use ozboxd::growfs::{self, GrowRecord};
        let path = std::path::Path::new(growfs::RESULT_PATH);
        let previous: Option<GrowRecord> = std::fs::read_to_string(path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok());
        let rec = growfs::run_once(
            &FsHost,
            &SystemRunner,
            &cfg.work_dir,
            SystemClock.now_ms(),
            previous.as_ref(),
        );
        if let Some(rec) = rec {
            let body = serde_json::to_string(&rec).map_err(|e| e.to_string())?;
            let tmp = path.with_extension("tmp");
            std::fs::write(&tmp, body)
                .map_err(|e| format!("cannot write the result: {}", e.kind()))?;
            std::fs::rename(&tmp, path)
                .map_err(|e| format!("cannot write the result: {}", e.kind()))?;
            log(&rec.detail);
        }
        Ok(())
    }

    /// `ozboxd tools-exec <job dir>`: run one tool job as the box user (started by the daemon inside a capped cgroup).
    fn tools_exec(dir: &str) -> Result<(), String> {
        use ozboxd::tools::{job, root::FileBridge, sys::RealSys};
        let catalog = ozbox_catalog::embedded()?;
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or("HOME is not set")?;
        let bridge = FileBridge::new(ozboxd::tools::root::ROOT_DIR);
        let st = job::run_job(
            std::path::Path::new(dir),
            &catalog,
            &RealSys,
            &bridge,
            &home,
            &|| SystemClock.now_ms(),
        )?;
        if st.state == job::JobState::Succeeded {
            Ok(())
        } else {
            Err(st.error.unwrap_or_else(|| "the job failed".into()))
        }
    }

    /// `ozboxd tools-root`: the privileged helper, started by a systemd path unit when a request appears. It runs
    /// only catalog steps (see `tools::root`).
    fn tools_root() -> Result<(), String> {
        use ozboxd::tools::{exec::RootPaths, root, sys::RealSys};
        let catalog = ozbox_catalog::embedded()?;
        let arch =
            ozbox_catalog::Arch::host().ok_or("this machine's architecture is not supported")?;
        let n = root::serve_requests(
            std::path::Path::new(root::ROOT_DIR),
            &catalog,
            arch,
            &RealSys,
            &RootPaths::default(),
            ozboxd::tools::job::LOG_CAP,
        );
        log(&format!("tools helper: {n} request(s) handled"));
        Ok(())
    }

    /// `ozboxd run-shim <id> <record sha256> <runs dir>`: the program of a run's unit (see `run_shim`). It ends with the
    /// run's own exit status, which is the unit's.
    fn run_shim_main() -> Result<(), String> {
        let a: Vec<String> = std::env::args().skip(2).collect();
        let [id, hash, dir] = a.as_slice() else {
            return Err("usage: ozboxd run-shim <id> <record sha256> <runs dir>".into());
        };
        if !ozboxd::run_units::valid_id(id) {
            return Err("not a run id".into());
        }
        let code = ozboxd::run_shim::serve(&std::path::Path::new(dir).join(id), id, hash)?;
        std::process::exit(code);
    }

    /// The box user's numeric id (this daemon runs as that user).
    fn current_uid() -> Option<u32> {
        let t = std::fs::read_to_string("/proc/self/status").ok()?;
        t.lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|r| r.split_whitespace().next())
            .and_then(|n| n.parse().ok())
    }

    /// `ozboxd backup-root`: installs new backup credentials the daemon handed over (see `backup_root`).
    fn backup_root() -> Result<(), String> {
        use ozboxd::backup_root as br;
        let t = br::Target::default();
        // credentials an older version left in a file go into the secrets store first, and the file is removed
        match br::migrate(&t) {
            Ok(true) => log("backup credentials moved into the secrets store"),
            Ok(false) => {}
            Err(e) => log(&format!("backup credentials were not moved: {e}")),
        }
        let n = br::serve_requests(std::path::Path::new(br::ROOT_DIR), &t);
        log(&format!(
            "backup credentials helper: {n} request(s) handled"
        ));
        // every start: a box that held credentials before the record existed gets one, and a [backup] edit is kept
        match br::refresh_record(&t) {
            Ok((outcome, skipped)) => {
                log(&format!("backup record: {outcome}"));
                for why in skipped {
                    log(&format!("backup record: {why}"));
                }
            }
            Err(e) => log(&format!("backup record: {e}")),
        }
        Ok(())
    }

    /// `ozboxd interruption-watch`: run as the metadata user (the box user may not reach the metadata service), ask it for
    /// an interruption notice every five seconds, and leave the one in effect where the daemon reads it.
    fn interruption_watch() -> Result<(), String> {
        use ozboxd::interruption::{watch_once, InterruptionWatcher, NOTICE_FILE};
        let w = InterruptionWatcher::new(Arc::new(ozbox_core::SystemRunner));
        let path = std::path::Path::new(NOTICE_FILE);
        let mut said = false;
        loop {
            match watch_once(&w, path) {
                Ok(()) => said = false,
                Err(why) if !said => {
                    said = true;
                    log(&format!("interruption watcher: {why}"));
                }
                Err(_) => {}
            }
            std::thread::sleep(Duration::from_secs(5));
        }
    }

    pub fn run() -> Result<(), String> {
        // Before any thread or child exists: the socket systemd handed over (if it did) is made close-on-exec here, so no
        // run this daemon starts can inherit a listening socket.
        let inherited = ozbox_listenfd::take_unix_listener();
        match std::env::args().nth(1).as_deref() {
            Some("tools-exec") => {
                return tools_exec(
                    &std::env::args()
                        .nth(2)
                        .ok_or("usage: ozboxd tools-exec <job dir>")?,
                )
            }
            Some("tools-root") => return tools_root(),
            // the hooks coding agents run (see `agent_events`): they never need the daemon's config and must exit 0
            Some("hook") => {
                let rest: Vec<String> = std::env::args().skip(2).collect();
                std::process::exit(ozboxd::hook_cli::main_hook(&rest));
            }
            Some("hooks") => {
                let rest: Vec<String> = std::env::args().skip(2).collect();
                std::process::exit(ozboxd::hook_cli::main_hooks(&rest));
            }
            Some("run-shim") => return run_shim_main(),
            // what the box installs at every boot: the session record only, never an ask (see `session_resume`)
            Some("session-hook") => {
                let rest: Vec<String> = std::env::args().skip(2).collect();
                std::process::exit(ozboxd::hook_cli::main_session_hook(&rest));
            }
            // at every boot of the box user's manager: the record hooks, then the agents' sessions come back
            Some("session-resume") => {
                std::process::exit(ozboxd::session_resume::main_session_resume())
            }
            Some("backup-root") => return backup_root(),
            Some("interruption-watch") => return interruption_watch(),
            _ => {}
        }
        let mut cfg = load_config()?;
        // What an upgrade must not lose (see `backup_state`): settings root's /etc no longer holds because the system disk
        // was replaced. A record that cannot be trusted is ignored and said, never obeyed.
        let backup_state_dir = ozboxd::backup_state::dir_for(&cfg.work_dir);
        match ozboxd::backup_state::read(&backup_state_dir, 0) {
            Ok(Some(c)) => cfg.backup = ozboxd::backup_state::effective(cfg.backup, Some(&c)),
            Ok(None) => {}
            Err(why) => log(&why),
        }
        if std::env::args().nth(1).as_deref() == Some("growfs") {
            return growfs_once(&cfg);
        }
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let runner: Arc<dyn CommandRunner> = Arc::new(SystemRunner);
        let host: Arc<dyn HostSource> = Arc::new(FsHost);
        let name = box_name(&cfg);
        // Backups on request (the dashboard server schedules them); needs credentials on the box to do anything.
        ozboxd::backup_service::install_global(Arc::new(
            ozboxd::backup_service::BackupService::new(
                BackupConfig {
                    env_file: cfg.backup.env_file.clone(),
                    service_socket: cfg.backup.service_socket.clone(),
                    paths: cfg.backup.paths.clone(),
                    excludes: cfg.backup.excludes.clone(),
                    box_name: Some(name.to_string()),
                    ..BackupConfig::default()
                },
                runner.clone(),
                clock.clone(),
            )
            .with_state_dir(backup_state_dir.clone()),
        ));
        let shutdown = Arc::new(AtomicBool::new(false));

        let _ = std::fs::create_dir_all(&cfg.state_dir);
        let mut incidents = IncidentLog::open(cfg.state_dir.join("incidents.jsonl"));
        let restarts = health::bump_restart_count(&cfg.state_dir.join("state.json"));
        if restarts > 1 {
            incidents.record(
                clock.now_ms(),
                IncidentKind::Restart,
                format!("restart #{restarts}"),
            );
        }
        log(&format!("starting (restart #{restarts}), box {name}"));

        // Store: a failure degrades history, never the box.
        let mut scfg = StoreConfig::new(cfg.metrics_path());
        scfg.max_bytes = cfg.store.max_mb * 1024 * 1024;
        let store = match Store::open(scfg) {
            Ok(s) => s,
            Err(_) => {
                incidents.record(
                    clock.now_ms(),
                    IncidentKind::MetricsDegraded,
                    "metrics directory unavailable; using a temporary one",
                );
                let mut f = StoreConfig::new(std::env::temp_dir().join("ozboxd-metrics"));
                f.max_bytes = 16 * 1024 * 1024;
                Store::open(f).map_err(|e| format!("no usable metrics directory: {}", e.kind()))?
            }
        };

        // Runs: units of the box user's own manager when it can hold them (they outlive this daemon), else cgroup scopes
        // under this daemon's own service (they end with it). The way is chosen again for every run (see `run_backend`), so a
        // daemon that started a moment before the manager does not use scopes for its whole life.
        let uid = current_uid();
        let mode = BackendMode::parse(&cfg.runs.backend);
        let cgroup_root = std::path::PathBuf::from("/sys/fs/cgroup");
        let run_dir = cfg
            .runs
            .dir
            .clone()
            .unwrap_or_else(|| cfg.state_dir.join("runs"));
        let scope_cg = match &cfg.cgroup_parent {
            Some(p) => {
                let cg = FsCgroup::new(p.clone());
                cg.prepare().map(|_| cg)
            }
            None => std::fs::read_to_string("/proc/self/cgroup")
                .and_then(|t| FsCgroup::delegated(&cgroup_root, &t, std::process::id())),
        };
        let scope_cg = match scope_cg {
            Ok(cg) => cg,
            Err(e) => {
                if mode != BackendMode::Unit {
                    incidents.record(
                        clock.now_ms(),
                        IncidentKind::Unexpected,
                        format!(
                            "cgroup delegation unavailable ({}); runs that need a scope will fail to start",
                            e.kind()
                        ),
                    );
                }
                FsCgroup::new("/sys/fs/cgroup/ozbox.unavailable")
            }
        };
        let cg_parent = scope_cg.parent().to_path_buf();
        // Run output of the scope way is kept where the control side can read it back (`GET /v1/runs/<id>/log`): beside the
        // daemon's other state unless the configuration says otherwise.
        let run_log_dir = cfg
            .run_log_dir
            .clone()
            .unwrap_or_else(|| cfg.state_dir.join("run-logs"));
        let _ = std::fs::create_dir_all(&run_log_dir);
        let scope_spawner: Arc<dyn Spawner> = Arc::new(StdSpawner {
            log_max_bytes: cfg.runs.log_max_mb * 1024 * 1024,
            log_dir: Some(run_log_dir),
        });
        let mut switch: Option<Arc<BackendSwitch>> = None;
        let mut has_records = false;
        let (spawner, run_cg): (Arc<dyn Spawner>, Arc<dyn ozboxd::runs::CgroupFs>) = match uid {
            Some(uid) if mode != BackendMode::Scope || run_dir.exists() => {
                let exe =
                    std::env::current_exe().unwrap_or_else(|_| "/usr/local/bin/ozboxd".into());
                let mut ucfg = UnitSpawnerConfig::new(run_dir.clone(), exe);
                ucfg.log_max_bytes = cfg.runs.log_max_mb * 1024 * 1024;
                ucfg.default_max_runtime_s =
                    (cfg.runs.default_max_runtime_s > 0).then_some(cfg.runs.default_max_runtime_s);
                // the shim talks only to processes in this daemon's own service cgroup
                ucfg.daemon_cgroup = std::fs::read_to_string("/proc/self/cgroup")
                    .ok()
                    .and_then(|t| ozboxd::runs::parse_self_cgroup(&t))
                    .and_then(|c| ozboxd::run_shim::service_cgroup_of(&c));
                if cfg.runs.sandbox == "strict" {
                    ucfg.sandbox = ozboxd::run_units::Sandbox {
                        strict: true,
                        read_write_paths: vec![cfg.work_dir.clone(), "/tmp".into()],
                    };
                }
                let units = Arc::new(SystemdUserUnits::new(runner.clone(), uid));
                let sp = UnitSpawner::new(ucfg, units, clock.clone());
                if let Err(e) = sp.prepare() {
                    incidents.record(
                        clock.now_ms(),
                        IncidentKind::Unexpected,
                        format!(
                            "the runs folder could not be made ({}); runs in units will fail to start",
                            e.kind()
                        ),
                    );
                }
                has_records = std::fs::read_dir(&run_dir)
                    .map(|mut d| d.next().is_some())
                    .unwrap_or(false);
                let probe: ozboxd::run_backend::Probe = {
                    let root = cgroup_root.clone();
                    Arc::new(move || {
                        ozboxd::run_backend::probe_user_manager(
                            &root,
                            std::path::Path::new("/run/user"),
                            uid,
                        )
                    })
                };
                // Wait (bounded) for the box user's manager: the daemon is ordered after it, but a manager that is slow to
                // come up must not decide the way of every run for this daemon's life.
                if mode != BackendMode::Scope && cfg.runs.manager_wait_s > 0 {
                    let mut waited = 0;
                    // only a manager that has not started yet is worth waiting for: one that is up and does not delegate
                    // what a run needs will not start to (Z24)
                    while matches!(probe(), Err(ozboxd::run_backend::ProbeError::NotRunning))
                        && waited < cfg.runs.manager_wait_s
                    {
                        std::thread::sleep(Duration::from_secs(1));
                        waited += 1;
                    }
                    if waited > 0 {
                        log(&format!(
                            "waited {waited} s for the box user's manager before starting runs"
                        ));
                    }
                }
                let sw = Arc::new(BackendSwitch::new(mode, Arc::new(sp), scope_spawner, probe));
                switch = Some(sw.clone());
                let units_cg: Arc<dyn ozboxd::runs::CgroupFs> = Arc::new(FsCgroup::new(
                    ozboxd::run_backend::app_slice_cgroup(&cgroup_root, uid),
                ));
                (
                    sw,
                    Arc::new(ozboxd::run_backend::RoutedCgroup {
                        units: units_cg,
                        scopes: Arc::new(scope_cg),
                    }),
                )
            }
            _ => (scope_spawner, Arc::new(scope_cg)),
        };
        let runs = Arc::new(Mutex::new(RunManager::new(
            RunConfig {
                max_queue: cfg.runs.max_queue,
                max_active: cfg.runs.max_active,
                default_max_runtime_s: (cfg.runs.default_max_runtime_s > 0)
                    .then_some(cfg.runs.default_max_runtime_s),
                default_memory_cap: cfg.runs.default_memory_cap,
                ..RunConfig::default()
            },
            run_cg,
            Arc::new(HostMemory(host.clone())),
            spawner,
            clock.clone(),
        )));
        if let Some(sw) = &switch {
            // Runs a previous daemon left going are always carried on with, whichever way new runs go now; a record that
            // does not verify is reported. A box with no records and no manager has nothing to look for.
            if has_records || sw.status().units {
                let found = lock(&runs).adopt_existing();
                if found.adopted + found.ended > 0 {
                    log(&format!(
                        "took over {} run(s) still going and {} that ended meanwhile",
                        found.adopted, found.ended
                    ));
                }
                for (id, why) in found.refused {
                    if id == "*" && !has_records {
                        continue;
                    }
                    incidents.record(
                        clock.now_ms(),
                        IncidentKind::Unexpected,
                        format!("run {id} was not taken over: {why}"),
                    );
                }
            }
        }

        // Checkpoint
        let mut ccfg = CheckpointConfig::new(cfg.repos_root.clone());
        ccfg.max_depth = cfg.checkpoint.max_depth;
        ccfg.push_remote = cfg.checkpoint.push_remote.clone();
        ccfg.keep_wip = cfg.checkpoint.keep_wip;
        // the quiesce snapshot looks under all of /work (the box user's home included), not only the repos folder
        ccfg.snapshot_root = Some(cfg.work_dir.clone());
        // a repository that is the box user's home folder (a dotfiles repository) is never snapshotted
        ccfg.home_dir = std::env::var_os("HOME").map(PathBuf::from);
        let checkpointer = Arc::new(Checkpointer::new(
            ccfg,
            name.clone(),
            runner.clone(),
            clock.clone(),
        ));

        // Self-test
        let mut stcfg = SelfTestConfig::new(cfg.work_dir.clone());
        stcfg.probe_dir = cfg.state_dir.clone();
        stcfg.min_free_bytes = cfg.selftest.min_free_mb * 1024 * 1024;
        stcfg.require_mount = cfg.selftest.require_mount;
        stcfg.tools = cfg.selftest.tools.clone();
        stcfg.work_encrypted = cfg.selftest.work_encrypted.clone();
        stcfg.tunnel_units = cfg.selftest.tunnel_units.clone();
        if cfg.selftest.require_mount {
            stcfg.secrets_sockets = selftest::BOX_USER_SECRETS_SOCKETS
                .iter()
                .map(std::path::PathBuf::from)
                .collect();
        }
        if cfg.selftest.require_mount {
            stcfg.secrets_state_file = Some(std::path::PathBuf::from(selftest::SECRETS_STATE_FILE));
        }
        if cfg.selftest.require_mount {
            stcfg.box_secrets_declaration =
                Some(std::path::PathBuf::from(selftest::BOX_SECRETS_DECLARATION));
        }
        if cfg.selftest.require_mount {
            stcfg.approval_flag_files = selftest::APPROVAL_FLAG_FILES
                .iter()
                .map(std::path::PathBuf::from)
                .collect();
        }
        // a box with a dashboard user must have been handed the dashboard's socket (checked, not connected to)
        if cfg.selftest.require_mount
            && std::fs::read_to_string("/etc/passwd")
                .ok()
                .and_then(|t| ozbox_core::daemon_scope::passwd_ids(&t, &cfg.supervisor_user))
                .is_some()
        {
            stcfg.dashboard_socket = Some(selftest::DashboardSocket {
                path: std::path::PathBuf::from(selftest::DASHBOARD_SOCKET_PATH),
                handed_over: matches!(inherited, Some(Ok(_))),
                unit_present: std::path::Path::new(selftest::DASHBOARD_SOCKET_UNIT).exists(),
            });
        }
        // a dashboard that was installed must be running, and no tunnel of the box user's own may be left (the marker is root's; the
        // dashboard user's own folder is closed to this user)
        if cfg.selftest.require_mount {
            stcfg.dashboard_traces = Some(selftest::DashboardTraces {
                marker: std::path::PathBuf::from(selftest::DASHBOARD_MARKER),
                migrated: std::path::PathBuf::from(selftest::DASHBOARD_MIGRATED),
                old_home: std::path::PathBuf::from(selftest::DASHBOARD_OLD_HOME),
            });
            stcfg.legacy_tunnel_paths = selftest::legacy_tunnel_paths(&stcfg.user_home);
        }
        if cfg.selftest.require_mount && cfg.runs.backend != "scope" {
            stcfg.user_cgroup_root = Some(std::path::PathBuf::from("/sys/fs/cgroup"));
        }
        if cfg.backup.enabled {
            stcfg.tools.push("restic".into());
        }
        // backups that were set up on this box must still work after a boot, an upgrade or a restore: the check exists only
        // for a box that has the record, and fails when the credentials are gone or the repository does not answer
        if let Some(svc) = ozboxd::backup_service::global() {
            // the repository is asked in the background (one check at a time), never inside the self-test: a slow network
            // must not make the self-test, and the upgrade waiting on it, time out. Start the first check now.
            let first = svc.clone();
            std::thread::spawn(move || {
                let _ = first.health();
            });
            let svc = svc.clone();
            stcfg.backups = Some(selftest::BackupsProbe {
                box_name: name.to_string(),
                health: Arc::new(move || svc.health()),
            });
        }
        let selftest_fn: Arc<dyn Fn() -> SelfTestResult + Send + Sync> = {
            let (host, runs, clock, runner) =
                (host.clone(), runs.clone(), clock.clone(), runner.clone());
            let switch = switch.clone();
            Arc::new(move || {
                let mut stcfg = stcfg.clone();
                if let Some(sw) = &switch {
                    let now = sw.status();
                    stcfg.run_backend = Some(selftest::RunBackendNow {
                        units: now.units,
                        why: now.why,
                    });
                }
                let sample = || -> Result<(), String> {
                    let mut rq = RunRequest::new(vec!["true".into()]);
                    rq.memory_max_bytes = Some(64 * 1024 * 1024);
                    let (id, _) = lock(&runs).start(rq).map_err(|e| e.to_string())?;
                    for _ in 0..60 {
                        let mut m = lock(&runs);
                        m.tick();
                        if let Some(i) = m.list().into_iter().find(|i| i.id == id) {
                            if i.exit_code.is_some() {
                                return if i.exit_code == Some(0) {
                                    Ok(())
                                } else {
                                    Err("sample run exited non-zero".into())
                                };
                            }
                        }
                        drop(m);
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    Err("sample run did not finish in 3 s".into())
                };
                let path = std::env::var("PATH").unwrap_or_default();
                selftest::run(
                    &stcfg,
                    host.as_ref(),
                    runner.as_ref(),
                    &path,
                    &sample,
                    clock.now_ms(),
                )
            })
        };

        let state = Arc::new(AppState {
            version: env!("CARGO_PKG_VERSION").to_string(),
            started_ms: clock.now_ms(),
            clock: clock.clone(),
            latest: Mutex::new(None),
            store: Mutex::new(store),
            runs: runs.clone(),
            selftest_last: Mutex::new(None),
            selftest_fn: {
                let f = selftest_fn.clone();
                Box::new(move || f())
            },
            incidents: Mutex::new(incidents),
            checkpoint_fn: {
                let c = checkpointer.clone();
                let push_wip = cfg.checkpoint.push_wip_on_stop;
                Box::new(move |for_run| {
                    if for_run {
                        c.checkpoint_all_for_run(push_wip)
                    } else {
                        c.checkpoint_all()
                    }
                })
            },
            checkpoint_lock: Mutex::new(()),
            health: Mutex::new(HealthInfo {
                restarts,
                ..HealthInfo::default()
            }),
        });

        // Quiesce: ends runs cleanly and snapshots uncommitted work before a resize or an upgrade stops the machine. The
        // snapshot is the one that touches nothing of the person's and never pushes; it shares the checkpoint lock.
        {
            let st = state.clone();
            let cp = checkpointer.clone();
            ozboxd::quiesce::install(Arc::new(
                ozboxd::quiesce::Quiescer::new(
                    runs.clone(),
                    Arc::new(move |budget| {
                        let _one = lock(&st.checkpoint_lock);
                        cp.snapshot_all_hidden(&ozboxd::checkpoint::HiddenOpts {
                            total: budget,
                            ..ozboxd::checkpoint::HiddenOpts::default()
                        })
                    }),
                    clock.clone(),
                    Arc::new(std::thread::sleep),
                )
                .with_audit(Arc::new(|line| eprintln!("ozboxd: audit {line}"))),
            ));
        }

        let mut threads: Vec<JoinHandle<()>> = Vec::new();

        // API
        let listener = api::bind_socket(&cfg.socket_path, cfg.socket_mode_bits())
            .map_err(|e| format!("cannot bind the API socket: {}", e.kind()))?;
        // The tool installer: plans and applies catalog installs; its jobs run as capped runs.
        match (
            ozbox_catalog::embedded(),
            ozbox_catalog::Arch::host(),
            std::env::current_exe(),
            std::env::var_os("HOME"),
        ) {
            (Ok(catalog), Some(arch), Ok(exe), Some(home)) => {
                let svc = ozboxd::tools::ToolsService::new(
                    ozboxd::tools::ToolsConfig {
                        state: ozboxd::tools::state_dir(&cfg.state_dir),
                        home: PathBuf::from(home),
                        exe,
                        job_memory_bytes: cfg.tools.job_memory_mb.saturating_mul(1024 * 1024),
                        arch,
                    },
                    catalog,
                    runs.clone(),
                    Arc::new(ozboxd::tools::sys::RealSys),
                    runner.clone(),
                    clock.clone(),
                );
                svc.recover();
                ozboxd::tools::install_global(Arc::new(svc));
            }
            _ => log("the tool installer is off: this machine's architecture or home directory is unknown"),
        }
        // Local models: the runtime is a `systemd --user` service of the box user; the daemon only writes its unit and
        // talks to it over the loopback.
        #[cfg(unix)]
        if let Some(home) = std::env::var_os("HOME") {
            ozboxd::local_ai::install_global(Arc::new(ozboxd::local_ai::LocalAiService::new(
                Arc::new(ozboxd::local_ai::RealHost {
                    home: PathBuf::from(home),
                }),
                clock.clone(),
            )));
        }
        // Skills on the box's disk: the folders its coding agents read, under the box user's home.
        if let Some(home) = std::env::var_os("HOME") {
            ozboxd::skills::install_global(Arc::new(ozboxd::skills::SkillsService::new(
                PathBuf::from(home),
                cfg.state_dir.clone(),
                clock.clone(),
            )));
        }
        if cfg.terminal.enabled {
            ozboxd::terminal::install_global(Arc::new(ozboxd::terminal::TerminalService::new(
                cfg.terminal.clone(),
                cfg.work_dir.clone(),
                Some(cfg.state_dir.join("terminal-audit.jsonl")),
            )));
        }
        let files = {
            let mut roots = vec![cfg.work_dir.clone()];
            roots.extend(cfg.files.extra_roots.iter().cloned());
            let mut fc = ozboxd::files::FilesConfig::new(roots);
            fc.max_upload = cfg.files.max_upload_mb.saturating_mul(1024 * 1024);
            fc.max_zip = cfg.files.max_bundle_mb.saturating_mul(1024 * 1024);
            match ozboxd::files::FilesService::new(fc, clock.clone()) {
                Ok(f) => {
                    f.clean_tmp();
                    Some(Arc::new(f))
                }
                Err(_) => {
                    log("the file API is off: the shared folders could not be opened");
                    None
                }
            }
        };
        // The user unit that brings the agents' sessions back at every boot (ADR 0049) is written by this daemon, as the box
        // user, into the box user's own systemd folder; so a box made before this release gets it at its next start. A tmux
        // window closed while the box runs has its record removed within a minute (never while the system is stopping).
        {
            let (sd, runner) = (shutdown.clone(), runner.clone());
            threads.push(spawn("session-records", move || {
                let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
                // one off switch for all of it (ADR 0049): while the file is there, nothing is installed and nothing is swept
                let off = || {
                    home.as_deref()
                        .is_some_and(ozboxd::session_resume::resume_off)
                };
                if let Some(home) = home.as_deref().filter(|_| !off()) {
                    let bin = ozboxd::session_resume::binary_path();
                    match ozboxd::session_resume::install_user_unit(home, &bin) {
                        Ok(ozboxd::session_resume::UnitOutcome::Installed) => {
                            log("the boot unit that brings agent sessions back was installed")
                        }
                        Ok(_) => {}
                        Err(e) => log(&format!(
                            "the boot unit for agent sessions was not installed: {}",
                            e.kind()
                        )),
                    }
                    // the record hooks too, so sessions started from now on are recorded on a box that has not rebooted
                    for (engine, o) in ozboxd::hook_cli::install_at_boot(home, &bin) {
                        match o {
                            ozboxd::hook_cli::Outcome::Installed => {
                                log(&format!("session record hooks installed for {engine}"))
                            }
                            ozboxd::hook_cli::Outcome::LeftAlone(why) => log(&format!(
                                "session record hooks for {engine} not installed: {why}"
                            )),
                            _ => {}
                        }
                    }
                }
                let dir = ozboxd::session_resume::records_dir();
                let mut shelled = std::collections::BTreeMap::new();
                let mut skips = ozboxd::session_resume::SkipWatch::default();
                while !sd.load(Ordering::SeqCst) {
                    sleep_unless(&sd, Duration::from_secs(60));
                    // told to stop while asleep: no sweep, because that is exactly when the panes are dying
                    if sd.load(Ordering::SeqCst) {
                        break;
                    }
                    if let (Some(dir), false) = (dir.as_deref(), off()) {
                        // a sweep that keeps being skipped says so once, with the managers' answers
                        if let Some(line) =
                            skips.look(ozboxd::session_resume::stopping_answers(runner.as_ref()))
                        {
                            log(&line);
                        }
                        ozboxd::session_resume::sweep(
                            runner.as_ref(),
                            &ozboxd::session_resume::ProcFs,
                            dir,
                            ozboxd::session_resume::WORK_ROOT,
                            ozboxd::session_resume::SweepOptions {
                                now_ms: ozboxd::session_resume::now_ms(),
                                boot_secs: ozboxd::session_resume::boot_time_secs(),
                                watch_shells: Some(&mut shelled),
                                stop: &|| sd.load(Ordering::SeqCst),
                            },
                        );
                    }
                }
            })?);
        }
        {
            let (st, sd, fl) = (state.clone(), shutdown.clone(), files.clone());
            threads.push(spawn("api", move || {
                if api::serve_with(listener, st, fl, sd).is_err() {
                    log("API server stopped unexpectedly");
                }
            })?);
        }
        // The dashboard user's own socket (ADR 0040, decision 3). systemd binds it as root in a folder root owns
        // (`ozboxd-supervisor.socket`) and hands it over; this daemon never binds, moves or changes the mode of it, so
        // nothing the box user does to its own folders changes who may connect. It answers one user and the routes of
        // `daemon_scope` only. A host without the socket unit (an older one) simply has no such socket, and says so once.
        {
            let (st, sd, fl) = (state.clone(), shutdown.clone(), files.clone());
            let user = cfg.supervisor_user.clone();
            threads.push(spawn("api-supervisor", move || {
                supervisor_socket(inherited, &user, st, fl, sd)
            })?);
        }

        // Sampler
        {
            let (st, sd, host, runner, runs, clock) = (
                state.clone(),
                shutdown.clone(),
                host.clone(),
                runner.clone(),
                runs.clone(),
                clock.clone(),
            );
            let (work, gpu, interval) = (
                cfg.work_dir.clone(),
                cfg.gpu,
                Duration::from_secs(cfg.sample_interval_s),
            );
            // Kills are counted in two places: the daemon's own service (scope runs, and everything else under it) and the
            // box user's app slice, where a run in a unit lives and where its kill is the only trace left (Z20).
            let mut slices = vec![health::OomSlice {
                key: "slice".into(),
                path: cg_parent
                    .join("memory.events")
                    .to_string_lossy()
                    .into_owned(),
                label: "the box slice".into(),
                holds_units: false,
            }];
            if let Some(uid) = uid {
                slices.push(health::OomSlice {
                    key: "app-slice".into(),
                    path: ozboxd::run_backend::app_slice_cgroup(&cgroup_root, uid)
                        .join("memory.events")
                        .to_string_lossy()
                        .into_owned(),
                    label: "the box user's app slice".into(),
                    holds_units: true,
                });
            }
            threads.push(spawn("sampler", move || {
                let mut sampler = Sampler::new(host.clone(), runner, work, gpu);
                let mut oom = OomWatcher::default();
                health::prime_oom_slices(host.as_ref(), &mut oom, &slices);
                let mut last_degraded = 0u64;
                let mut pressure = ozboxd::pressure::Watch::default();
                while !sd.load(Ordering::SeqCst) {
                    let now = clock.now_ms();
                    // Early warning: memory stalls are said before anything is killed (ADR 0045).
                    if let Some((some, full)) = std::fs::read_to_string("/proc/pressure/memory")
                        .ok()
                        .and_then(|t| ozboxd::pressure::read(&t))
                    {
                        if let Some(detail) = pressure.observe(now, some, full) {
                            lock(&st.incidents).record(now, IncidentKind::MemoryPressure, detail);
                        }
                    }
                    let (usage, events) = {
                        let mut m = lock(&runs);
                        m.tick();
                        (m.usage(), m.take_events())
                    };
                    for ev in events {
                        match ev {
                            ozboxd::runs::RunEvent::TimedOut(id) => lock(&st.incidents).record(
                                now,
                                IncidentKind::RunTimedOut,
                                format!("run {id} reached its wall-clock limit and was killed"),
                            ),
                            ozboxd::runs::RunEvent::Backend(what) => {
                                lock(&st.incidents).record(now, IncidentKind::Unexpected, what)
                            }
                        }
                    }
                    match sampler.sample(now, usage) {
                        Ok(s) => {
                            if let Err(e) = lock(&st.store).push(&s) {
                                if now.saturating_sub(last_degraded) > 10 * MINUTE_MS {
                                    last_degraded = now;
                                    lock(&st.incidents).record(
                                        now,
                                        IncidentKind::MetricsDegraded,
                                        format!("store write failed: {}", e.kind()),
                                    );
                                }
                            }
                            *lock(&st.latest) = Some(s);
                        }
                        Err(e) => {
                            if now.saturating_sub(last_degraded) > 10 * MINUTE_MS {
                                last_degraded = now;
                                lock(&st.incidents).record(
                                    now,
                                    IncidentKind::MetricsDegraded,
                                    e.to_string(),
                                );
                            }
                        }
                    }
                    // OOM kills: each live run's cgroup, and the slices above (Z20).
                    let scopes = lock(&runs).active_scopes();
                    let step = health::oom_step(
                        host.as_ref(),
                        &mut oom,
                        &scopes,
                        &|name| lock(&runs).read_cgroup(name, "memory.events").ok(),
                        &slices,
                    );
                    for detail in step.incidents {
                        lock(&st.incidents).record(now, IncidentKind::OomKill, detail);
                    }
                    if step.kills > 0 {
                        lock(&st.health).oom_kills += step.kills;
                    }
                    sleep_unless(&sd, interval);
                }
            })?);
        }

        // Idle loop
        {
            let push_wip = cfg.checkpoint.push_wip_on_stop;
            let (st, sd, host, runner, runs, clock, cp) = (
                state.clone(),
                shutdown.clone(),
                host.clone(),
                runner.clone(),
                runs.clone(),
                clock.clone(),
                checkpointer.clone(),
            );
            let icfg = IdleConfig {
                threshold_minutes: cfg.idle.threshold_minutes,
                cpu_threshold_pct: cfg.idle.cpu_threshold_pct,
                always_on: cfg.always_on,
                session_ports: cfg.idle.session_ports.clone(),
                ..IdleConfig::default()
            };
            let stop: Box<dyn StopRequester> = if cfg.idle.stop_command.is_empty() {
                Box::new(UnconfiguredStop)
            } else {
                Box::new(CommandStopRequester {
                    runner: runner.clone(),
                    argv: cfg.idle.stop_command.clone(),
                })
            };
            let sessions = CombinedSessions(vec![
                Box::new(TunnelSessions {
                    host,
                    ports: icfg.session_ports.clone(),
                }),
                Box::new(WhoSessions { runner }),
            ]);
            let interval = Duration::from_secs(cfg.idle.check_interval_s);
            threads.push(spawn("idle", move || {
                let mut idle = IdleLoop::new(icfg, Box::new(sessions), stop);
                while !sd.load(Ordering::SeqCst) {
                    sleep_unless(&sd, interval);
                    if sd.load(Ordering::SeqCst) {
                        break;
                    }
                    let now = clock.now_ms();
                    let cpu = {
                        let pts =
                            lock(&st.store).query(now.saturating_sub(MINUTE_MS), now, Step::Raw5s);
                        if pts.is_empty() {
                            100.0 // no recent samples: unknown counts as busy
                        } else {
                            pts.iter()
                                .filter_map(|p| p.fields.get("cpu_pct"))
                                .map(|a| a.mean)
                                .sum::<f64>()
                                / pts.len() as f64
                        }
                    };
                    let active = {
                        let m = lock(&runs);
                        (m.active_count() + m.queued_count()) as u32
                    };
                    // an idle stop saves the hidden snapshot and pushes nothing, unless the box was set up to push
                    let guard_cp = || {
                        let _one = lock(&st.checkpoint_lock);
                        cp.on_idle(push_wip)
                    };
                    match idle.step(now, active, cpu, &guard_cp) {
                        StepOutcome::StopRequested(r) => log(&format!(
                            "idle: stop requested after checkpoint ({} branch(es))",
                            r.branches.len()
                        )),
                        StepOutcome::StopFailed(why, _) => {
                            log("idle: could not request a stop");
                            lock(&st.incidents).record(now, IncidentKind::StopRequestFailed, why);
                        }
                        StepOutcome::CheckpointFailed(errs) => {
                            lock(&st.incidents).record(
                                now,
                                IncidentKind::CheckpointFailed,
                                format!(
                                    "idle checkpoint: {} repo(s) failed; box left running",
                                    errs.len()
                                ),
                            );
                        }
                        StepOutcome::Busy(_)
                        | StepOutcome::CoolingDown
                        | StepOutcome::NoStopConfigured => {}
                    }
                }
            })?);
        }

        // Maintenance: self-test at boot, health refresh, backups
        {
            let (st, sd, runner, clock, f) = (
                state.clone(),
                shutdown.clone(),
                runner.clone(),
                clock.clone(),
                selftest_fn.clone(),
            );
            let release = cfg.release_file.clone();
            let bcfg = BackupConfig {
                env_file: cfg.backup.env_file.clone(),
                service_socket: cfg.backup.service_socket.clone(),
                paths: cfg.backup.paths.clone(),
                excludes: cfg.backup.excludes.clone(),
                interval_hours: cfg.backup.interval_hours,
                box_name: Some(name.to_string()),
                ..BackupConfig::default()
            };
            let backup_enabled = cfg.backup.enabled;
            threads.push(spawn("maintenance", move || {
                sleep_unless(&sd, Duration::from_secs(10));
                let r = f();
                if !r.ok {
                    lock(&st.incidents).record(
                        clock.now_ms(),
                        IncidentKind::SelfTestFailed,
                        "boot self-test failed; see /v1/selftest",
                    );
                }
                *lock(&st.selftest_last) = Some(r);
                let mut schedule = BackupSchedule::new(bcfg.interval_hours);
                let mut last_health = 0u64;
                let mut last_growfs = 0u64;
                let started = st.started_ms;
                while !sd.load(Ordering::SeqCst) {
                    let now = clock.now_ms();
                    // The privileged one-shot grows the filesystem after a disk resize; report what it did.
                    if let Some(rec) = std::fs::read_to_string(ozboxd::growfs::RESULT_PATH)
                        .ok()
                        .and_then(|t| serde_json::from_str::<ozboxd::growfs::GrowRecord>(&t).ok())
                    {
                        if ozboxd::growfs::should_report(&rec, last_growfs, started) {
                            last_growfs = rec.ts_ms;
                            let kind = if rec.action == ozboxd::growfs::Action::Grown {
                                IncidentKind::DiskGrown
                            } else {
                                IncidentKind::DiskGrowFailed
                            };
                            lock(&st.incidents).record(now, kind, rec.detail);
                        }
                    }
                    if now.saturating_sub(last_health) > 6 * 3_600_000 || last_health == 0 {
                        last_health = now;
                        let version = std::fs::read_to_string(&release)
                            .ok()
                            .and_then(|t| health::parse_release(&t));
                        let pending = health::pending_updates(&runner);
                        let mut h = lock(&st.health);
                        h.image_version = version;
                        h.pending_updates = pending;
                    }
                    if backup_enabled && schedule.due(now) {
                        schedule.mark(now); // a failed run waits a full interval; the incident says so
                        match Restic::load(bcfg.clone(), runner.clone())
                            .and_then(|r| r.backup_and_forget())
                        {
                            Ok(()) => log("backup finished"),
                            Err(e) => lock(&st.incidents).record(
                                now,
                                IncidentKind::BackupFailed,
                                e.to_string(),
                            ),
                        }
                    }
                    sleep_unless(&sd, Duration::from_secs(60));
                }
            })?);
        }

        // Interruption watcher (AWS only)
        if cfg.provider == "aws" {
            let push_wip = cfg.checkpoint.push_wip_on_stop;
            let (st, sd, runner, clock, cp) = (
                state.clone(),
                shutdown.clone(),
                runner.clone(),
                clock.clone(),
                checkpointer.clone(),
            );
            threads.push(spawn("interruption", move || {
                let mut w = InterruptionWatcher::new(runner);
                let mut unreachable_logged = false;
                // the watcher of its own leaves its notice here; a box made before it has none, and this asks itself
                let file = std::path::Path::new(ozboxd::interruption::NOTICE_FILE);
                while !sd.load(Ordering::SeqCst) {
                    let polled = if file.parent().is_some_and(std::path::Path::is_dir) {
                        w.poll_file(file)
                    } else {
                        w.poll()
                    };
                    match polled {
                        Ok(Some(n)) => {
                            unreachable_logged = false;
                            lock(&st.incidents).record(
                                clock.now_ms(),
                                IncidentKind::Interruption,
                                n.describe(),
                            );
                            log(&format!("{}: saving uncommitted work now", n.describe()));
                            let report = {
                                let _one = lock(&st.checkpoint_lock);
                                cp.on_interruption(push_wip)
                            };
                            if !report.errors.is_empty() {
                                lock(&st.incidents).record(
                                    clock.now_ms(),
                                    IncidentKind::CheckpointFailed,
                                    format!(
                                        "interruption checkpoint: {} repo(s) failed",
                                        report.errors.len()
                                    ),
                                );
                            }
                        }
                        Ok(None) => unreachable_logged = false,
                        Err(why) => {
                            // Once per outage: an unreachable metadata service is not a notice.
                            if !unreachable_logged {
                                unreachable_logged = true;
                                log(&format!("interruption watcher: {why}"));
                            }
                        }
                    }
                    sleep_unless(&sd, Duration::from_secs(5));
                }
            })?);
        }

        // Signals: checkpoint, then exit.
        let mut signals = Signals::new([SIGTERM, SIGINT])
            .map_err(|e| format!("cannot install signal handlers: {}", e.kind()))?;
        if let Some(sig) = signals.forever().next() {
            let push_wip = cfg.checkpoint.push_wip_on_stop;
            log(&format!(
                "signal {sig}: saving uncommitted work ({}) and exiting",
                if push_wip {
                    "the older checkpoint: a wip/<box>/<time> branch, pushed when a remote is set"
                } else {
                    "a hidden snapshot; nothing visible is written and nothing is pushed"
                }
            ));
            shutdown.store(true, Ordering::SeqCst);
            // A snapshot already running (a quiesce) is waited for only briefly: systemd ends the daemon after its stop timeout.
            let held = lock_within(&state.checkpoint_lock, Duration::from_secs(10));
            match held {
                Some(_one) => {
                    let report = checkpointer.on_stop(push_wip);
                    log(&format!(
                        "stop snapshot: {} saved, {} error(s)",
                        report.branches.len(),
                        report.errors.len()
                    ));
                }
                None => log(
                    "stop snapshot: another snapshot was still running; not taking a second one",
                ),
            }
        }
        for t in threads {
            let _ = t.join();
        }
        let _ = std::fs::remove_file(&cfg.socket_path);
        Ok(())
    }

    /// Take a lock for at most `wait`, polling; `None` when it stayed taken.
    fn lock_within(m: &Mutex<()>, wait: Duration) -> Option<std::sync::MutexGuard<'_, ()>> {
        let until = std::time::Instant::now() + wait;
        loop {
            match m.try_lock() {
                Ok(g) => return Some(g),
                Err(std::sync::TryLockError::Poisoned(e)) => return Some(e.into_inner()),
                Err(std::sync::TryLockError::WouldBlock) => {
                    if std::time::Instant::now() >= until {
                        return None;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }

    /// Serve the socket systemd handed over until shutdown. A serve error is logged (when the reason changes) and the
    /// same listener is served again after a pause, so a failure never leaves the dashboard without its socket.
    fn supervisor_socket(
        inherited: Option<std::io::Result<std::os::unix::net::UnixListener>>,
        user: &str,
        st: Arc<api::AppState>,
        fl: Option<Arc<ozboxd::files::FilesService>>,
        sd: Arc<AtomicBool>,
    ) {
        use ozbox_core::daemon_scope::passwd_ids;
        // A DEBUG build only: the browser tests of this repository have no systemd and no `ozbox-supervisor` user, so with
        // `OZBOXD_TEST_DASHBOARD_SOCKET=<path>` the daemon binds that path itself and serves it as the dashboard's socket (every
        // peer admitted). A release build has no such code. The transport's own debug hook (`OZBOX_DAEMON_SUPERVISOR_SOCKET`)
        // is the dashboard's half of the same arrangement.
        #[cfg(debug_assertions)]
        let (inherited, test_peer) = match std::env::var_os("OZBOXD_TEST_DASHBOARD_SOCKET") {
            Some(p) if inherited.is_none() => {
                let _ = std::fs::remove_file(&p);
                (Some(std::os::unix::net::UnixListener::bind(&p)), true)
            }
            _ => (inherited, false),
        };
        #[cfg(not(debug_assertions))]
        let test_peer = false;
        let listener = match inherited {
            Some(Ok(l)) => l,
            Some(Err(e)) => {
                log(&format!(
                    "the dashboard user's socket could not be taken from systemd ({}); it is off",
                    e.kind()
                ));
                return;
            }
            None => {
                log("no dashboard user's socket was handed over by systemd (ozboxd-supervisor.socket is not on this host); it is off");
                return;
            }
        };
        let ids = {
            let user = user.to_string();
            move || {
                std::fs::read_to_string("/etc/passwd")
                    .ok()
                    .and_then(|t| passwd_ids(&t, &user))
                    .map(|(uid, _)| uid)
            }
        };
        let gate = Arc::new(if test_peer {
            api::SupervisorGate::new(
                |_| Some(1),
                || Some(1),
                |line| eprintln!("ozboxd: audit {line}"),
            )
        } else {
            api::SupervisorGate::new(api::peer_uid, ids, |line| eprintln!("ozboxd: audit {line}"))
        });
        log(&format!(
            "the dashboard user's socket is up (from systemd, {})",
            ozbox_listenfd::DAEMON_MARKER
        ));
        // the held count of a refusal burst is written when its interval ends, not only at the next refusal
        {
            let gate = gate.clone();
            let sd = sd.clone();
            std::thread::spawn(move || {
                while !sd.load(Ordering::SeqCst) {
                    sleep_unless(&sd, Duration::from_secs(5));
                    gate.flush_due();
                }
            });
        }
        let mut last = String::new();
        while !sd.load(Ordering::SeqCst) {
            let served = listener.try_clone().and_then(|l| {
                api::serve_supervisor(l, st.clone(), fl.clone(), sd.clone(), gate.clone())
            });
            if let Err(e) = served {
                let why = e.kind().to_string();
                if why != last {
                    log(&format!(
                        "the dashboard user's socket stopped ({why}); serving it again in 5 s"
                    ));
                    last = why;
                }
                sleep_unless(&sd, Duration::from_secs(5));
            }
        }
    }

    fn spawn(name: &str, f: impl FnOnce() + Send + 'static) -> Result<JoinHandle<()>, String> {
        std::thread::Builder::new()
            .name(format!("ozboxd-{name}"))
            .spawn(f)
            .map_err(|e| format!("cannot start thread {name}: {}", e.kind()))
    }
}
