//! Where each run lives, decided per run (ADR 0038 section 4).
//!
//! A run is either a unit of the box user's own manager (it outlives the daemon) or a cgroup scope under the daemon's own
//! service (it ends with it). The way used to be chosen once, when the daemon started, and a daemon that won the race
//! against the box user's manager at boot then used scopes for its whole life, so the very restart a live update is
//! made of ended every run. Now:
//!
//! - the choice is made again for every run, from a cheap look at the manager ([`probe_user_manager`]), so one that came up
//!   a moment after the daemon is used as soon as it is there;
//! - runs a previous daemon left going are always taken over (the unit spawner's `adopt`), whichever way new runs go;
//! - every change of way is told once ([`Spawner::notes`]), and the self-test reports the way in use.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::runs::{AdoptReport, CgroupFs, ChildHandle, RunRequest, Spawner};
use ozbox_core::memory_plan::RunLimits;

/// `runs.backend`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendMode {
    /// Units when the box user's manager can hold them, else scopes (the default).
    Auto,
    /// Always units; a manager that is not there fails the run's start with its reason.
    Unit,
    /// Always scopes: runs end with the daemon.
    Scope,
}

impl BackendMode {
    pub fn parse(s: &str) -> Self {
        match s {
            "unit" => Self::Unit,
            "scope" => Self::Scope,
            _ => Self::Auto,
        }
    }
}

/// The cgroup the box user's units live in.
pub fn app_slice_cgroup(root: &Path, uid: u32) -> PathBuf {
    crate::runs::user_manager_cgroup(root, uid).join("app.slice")
}

/// Whether the box user's manager is up and can hold a run's limits: its runtime folder is there, and the controllers a
/// run needs (memory, cpu) are available in the cgroup its units land in (`app.slice`, which is what the kernel hands them;
/// the manager's own cgroup when `app.slice` has not been made yet). Pure on a cgroup tree, so it is tested on fixtures.
pub fn probe_user_manager(
    cgroup_root: &Path,
    runtime_root: &Path,
    uid: u32,
) -> Result<(), ProbeError> {
    if !runtime_root.join(format!("{uid}/systemd")).exists() {
        return Err(ProbeError::NotRunning);
    }
    let slice = app_slice_cgroup(cgroup_root, uid);
    let text = std::fs::read_to_string(slice.join("cgroup.controllers")).or_else(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            std::fs::read_to_string(
                crate::runs::user_manager_cgroup(cgroup_root, uid).join("cgroup.controllers"),
            )
        } else {
            Err(e)
        }
    });
    match text {
        Ok(t) => {
            let missing = crate::runs::missing_run_controllers(&t);
            if missing.is_empty() {
                Ok(())
            } else {
                Err(ProbeError::Unusable(format!(
                    "the box user's manager does not delegate: {}",
                    missing.join(", ")
                )))
            }
        }
        Err(e) => Err(ProbeError::Unusable(format!(
            "its controllers cannot be read ({})",
            e.kind()
        ))),
    }
}

/// Why the box user's manager cannot hold runs. Only [`ProbeError::NotRunning`] can change by waiting: a manager that is up
/// but does not hand out the controllers will not start to because a daemon is patient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeError {
    /// Its runtime folder is not there yet (it has not started).
    NotRunning,
    /// It is up and cannot do what a run needs; the text says what.
    Unusable(String),
}

impl std::fmt::Display for ProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotRunning => f.write_str("the box user's service manager is not running"),
            Self::Unusable(why) => f.write_str(why),
        }
    }
}

pub type Probe = Arc<dyn Fn() -> Result<(), ProbeError> + Send + Sync>;

/// The way runs go now, for the self-test and the operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendStatus {
    pub mode: BackendMode,
    /// True: runs are units of the box user's manager and survive a daemon restart.
    pub units: bool,
    /// Why not, when they are not.
    pub why: Option<String>,
}

#[derive(Default)]
struct State {
    /// Where each run was placed: true for a unit.
    placed: BTreeMap<String, bool>,
    last: Option<bool>,
    notes: Vec<String>,
}

pub struct BackendSwitch {
    mode: BackendMode,
    units: Arc<dyn Spawner>,
    scopes: Arc<dyn Spawner>,
    probe: Probe,
    state: Mutex<State>,
}

impl BackendSwitch {
    pub fn new(
        mode: BackendMode,
        units: Arc<dyn Spawner>,
        scopes: Arc<dyn Spawner>,
        probe: Probe,
    ) -> Self {
        Self {
            mode,
            units,
            scopes,
            probe,
            state: Mutex::new(State::default()),
        }
    }

    fn decide(&self) -> (bool, Option<String>) {
        match self.mode {
            BackendMode::Unit => (true, None),
            BackendMode::Scope => (false, Some("runs.backend is set to scope".into())),
            BackendMode::Auto => match (self.probe)() {
                Ok(()) => (true, None),
                Err(why) => (false, Some(why.to_string())),
            },
        }
    }

    /// The way runs would go if one started now.
    pub fn status(&self) -> BackendStatus {
        let (units, why) = self.decide();
        BackendStatus {
            mode: self.mode,
            units,
            why,
        }
    }

    fn is_unit(&self, id: &str) -> bool {
        self.state
            .lock()
            .ok()
            .and_then(|s| s.placed.get(id).copied())
            .unwrap_or(false)
    }

    fn pick(&self, id: &str) -> &Arc<dyn Spawner> {
        if self.is_unit(id) {
            &self.units
        } else {
            &self.scopes
        }
    }
}

impl Spawner for BackendSwitch {
    fn place(&self, id: &str) {
        let (unit, why) = self.decide();
        if let Ok(mut s) = self.state.lock() {
            s.placed.insert(id.to_string(), unit);
            if s.last != Some(unit) {
                // the first run of a daemon says nothing when units are in use: that is the expected way
                let note = match (unit, s.last) {
                    (true, None) => None,
                    (true, Some(_)) => Some("runs use units of the box user's manager again, so they outlive a restart of this daemon".to_string()),
                    (false, _) => Some(format!(
                        "runs use cgroup scopes under this daemon, so a restart of it ends them: {}",
                        why.unwrap_or_else(|| "unknown".into())
                    )),
                };
                s.notes.extend(note);
                s.last = Some(unit);
            }
        }
    }

    fn applies_limits(&self, id: &str) -> bool {
        self.is_unit(id)
    }

    fn cgroup_name(&self, id: &str) -> String {
        self.pick(id).cgroup_name(id)
    }

    fn spawn(
        &self,
        id: &str,
        req: &RunRequest,
        limits: &RunLimits,
    ) -> io::Result<Box<dyn ChildHandle>> {
        // `unit` mode never falls back, so it has to say why a run cannot be held rather than start it with caps the manager
        // would accept as properties and not enforce (Z22); the other modes decided at `place`.
        if self.mode == BackendMode::Unit && self.is_unit(id) {
            if let Err(why) = (self.probe)() {
                return Err(io::Error::other(why.to_string()));
            }
        }
        self.pick(id).spawn(id, req, limits)
    }

    fn read_log(&self, id: &str, from: u64, max: usize) -> io::Result<Option<Vec<u8>>> {
        self.pick(id).read_log(id, from, max)
    }

    fn forget(&self, id: &str) {
        self.pick(id).forget(id);
        if let Ok(mut s) = self.state.lock() {
            s.placed.remove(id);
        }
    }

    fn freeze(&self, id: &str) -> io::Result<()> {
        self.pick(id).freeze(id)
    }

    fn thaw(&self, id: &str) -> io::Result<()> {
        self.pick(id).thaw(id)
    }

    /// Always asks the unit spawner, whichever way new runs go now: a run a previous daemon left going in a unit must be
    /// listed, counted in admission and reaped.
    fn adopt(&self) -> AdoptReport {
        let report = self.units.adopt();
        if let Ok(mut s) = self.state.lock() {
            for r in &report.runs {
                s.placed.insert(r.info.id.clone(), true);
            }
        }
        report
    }

    fn notes(&self) -> Vec<String> {
        self.state
            .lock()
            .map(|mut s| std::mem::take(&mut s.notes))
            .unwrap_or_default()
    }
}

/// One cgroup tree for both kinds of run: a unit's cgroup is under the box user's manager, a scope's under the daemon's own
/// service, and a unit's name ends in `.service`.
pub struct RoutedCgroup {
    pub units: Arc<dyn CgroupFs>,
    pub scopes: Arc<dyn CgroupFs>,
}

impl RoutedCgroup {
    fn pick(&self, name: &str) -> &Arc<dyn CgroupFs> {
        if name.ends_with(".service") {
            &self.units
        } else {
            &self.scopes
        }
    }
}

impl CgroupFs for RoutedCgroup {
    fn create(&self, name: &str) -> io::Result<()> {
        self.pick(name).create(name)
    }
    fn write(&self, name: &str, file: &str, value: &str) -> io::Result<()> {
        self.pick(name).write(name, file, value)
    }
    fn read(&self, name: &str, file: &str) -> io::Result<String> {
        self.pick(name).read(name, file)
    }
    fn remove(&self, name: &str) -> io::Result<()> {
        self.pick(name).remove(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runs::testing::{FakeCgroup, FakeSpawner};
    use crate::runs::{AdoptedRun, RunInfo, RunState};
    use std::collections::BTreeMap as Map;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn tree(
        controllers: Option<&str>,
        app_slice: bool,
        running: bool,
    ) -> (tempfile::TempDir, PathBuf, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let (cg, rt) = (d.path().join("cg"), d.path().join("run-user"));
        let mgr = crate::runs::user_manager_cgroup(&cg, 1500);
        std::fs::create_dir_all(&mgr).unwrap();
        if running {
            std::fs::create_dir_all(rt.join("1500/systemd")).unwrap();
        }
        if let Some(c) = controllers {
            let target = if app_slice {
                std::fs::create_dir_all(mgr.join("app.slice")).unwrap();
                mgr.join("app.slice")
            } else {
                mgr.clone()
            };
            std::fs::write(target.join("cgroup.controllers"), c).unwrap();
        }
        (d, cg, rt)
    }

    #[test]
    fn the_probe_reads_the_cgroup_the_units_land_in_and_says_what_is_wrong() {
        let (_d, cg, rt) = tree(Some("cpuset cpu io memory pids"), true, true);
        assert!(probe_user_manager(&cg, &rt, 1500).is_ok());
        // the manager's own cgroup is not the truth when app.slice exists: it is what the units get that counts
        let (_d, cg, rt) = tree(Some("cpu pids"), true, true);
        let e = probe_user_manager(&cg, &rt, 1500).unwrap_err().to_string();
        assert!(e.contains("memory") && !e.contains("cpu,"), "{e}");
        // no app.slice yet: the manager's own controllers are all there is to read
        let (_d, cg, rt) = tree(Some("cpu memory"), false, true);
        assert!(probe_user_manager(&cg, &rt, 1500).is_ok());
        let (_d, cg, rt) = tree(Some("cpu memory"), true, false);
        assert_eq!(
            probe_user_manager(&cg, &rt, 1500).unwrap_err(),
            ProbeError::NotRunning
        );
        let (_d, cg, rt) = tree(None, false, true);
        assert!(probe_user_manager(&cg, &rt, 1500)
            .unwrap_err()
            .to_string()
            .contains("cannot be read"));
    }

    fn switch(
        mode: BackendMode,
        up: &Arc<AtomicBool>,
    ) -> (BackendSwitch, Arc<FakeSpawner>, Arc<FakeSpawner>) {
        let (units, scopes) = (
            Arc::new(FakeSpawner::default()),
            Arc::new(FakeSpawner::default()),
        );
        units.unit_like.store(true, Ordering::SeqCst);
        let up = up.clone();
        let sw = BackendSwitch::new(
            mode,
            units.clone(),
            scopes.clone(),
            Arc::new(move || {
                if up.load(Ordering::SeqCst) {
                    Ok(())
                } else {
                    Err(ProbeError::NotRunning)
                }
            }),
        );
        (sw, units, scopes)
    }

    fn limits() -> RunLimits {
        ozbox_core::memory_plan::run_limits(16 << 30, true, None, 0)
    }

    #[test]
    fn a_daemon_that_lost_the_race_uses_units_for_the_runs_that_start_after_the_manager_is_up() {
        let up = Arc::new(AtomicBool::new(false));
        let (sw, units, scopes) = switch(BackendMode::Auto, &up);
        let rq = RunRequest::new(vec!["true".into()]);
        // the manager is not up: this run is a scope, and the operator is told what that costs
        sw.place("a");
        assert!(!sw.applies_limits("a"));
        sw.spawn("a", &rq, &limits()).unwrap();
        let notes = sw.notes();
        assert_eq!(notes.len(), 1);
        assert!(notes[0].contains("a restart of it ends them") && notes[0].contains("not running"));
        // told once, not once a run
        sw.place("b");
        assert!(sw.notes().is_empty());
        // the manager comes up: the NEXT run is a unit, and that is told once too
        up.store(true, Ordering::SeqCst);
        sw.place("c");
        assert!(sw.applies_limits("c") && !sw.applies_limits("a"));
        sw.spawn("c", &rq, &limits()).unwrap();
        assert!(sw.notes()[0].contains("outlive a restart"));
        assert_eq!(units.spawned.lock().unwrap().as_slice(), ["c"]);
        assert_eq!(scopes.spawned.lock().unwrap().as_slice(), ["a"]);
        assert!(sw.cgroup_name("c").ends_with(".service"));
        assert!(sw.cgroup_name("a").ends_with(".scope"));
        // a daemon that starts straight into units says nothing: that is the expected way
        let (sw2, _, _) = switch(BackendMode::Auto, &Arc::new(AtomicBool::new(true)));
        sw2.place("x");
        assert!(sw2.notes().is_empty());
    }

    #[test]
    fn the_configured_mode_is_taken_as_asked() {
        let down = Arc::new(AtomicBool::new(false));
        let (sw, _, _) = switch(BackendMode::Unit, &down);
        sw.place("a");
        assert!(sw.applies_limits("a"));
        let up = Arc::new(AtomicBool::new(true));
        let (sw, _, _) = switch(BackendMode::Scope, &up);
        sw.place("a");
        assert!(!sw.applies_limits("a"));
        assert!(sw.status().why.unwrap().contains("scope"));
        assert_eq!(BackendMode::parse("nonsense"), BackendMode::Auto);
    }

    #[test]
    fn a_fallback_daemon_still_takes_over_runs_a_previous_daemon_left_going() {
        // even when new runs go to scopes (mode scope, manager not up at the probe), the units are asked about
        let up = Arc::new(AtomicBool::new(false));
        let (sw, units, _) = switch(BackendMode::Scope, &up);
        let info = RunInfo {
            id: "old1".into(),
            state: RunState::Running,
            program: "x".into(),
            labels: Map::new(),
            memory_request_bytes: 0,
            memory_max_bytes: None,
            queued_ms: 0,
            started_ms: Some(0),
            ended_ms: None,
            exit_code: None,
            timed_out: false,
        };
        *units.to_adopt.lock().unwrap() = Some(AdoptReport {
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
        let r = sw.adopt();
        assert_eq!(r.runs.len(), 1);
        // and the run is a unit as far as its cgroup, limits and log go
        assert!(sw.applies_limits("old1"));
        assert!(sw.cgroup_name("old1").ends_with(".service"));
    }

    #[test]
    fn a_units_cgroup_and_a_scopes_are_read_from_their_own_trees() {
        let (u, s) = (
            Arc::new(FakeCgroup::default()),
            Arc::new(FakeCgroup::default()),
        );
        let r = RoutedCgroup {
            units: u.clone(),
            scopes: s.clone(),
        };
        r.write("ozbox-run-a.service", "memory.max", "1").unwrap();
        r.write("run-b.scope", "memory.max", "2").unwrap();
        assert_eq!(
            u.get("ozbox-run-a.service", "memory.max").as_deref(),
            Some("1")
        );
        assert_eq!(s.get("run-b.scope", "memory.max").as_deref(), Some("2"));
        assert!(u.get("run-b.scope", "memory.max").is_none());
    }

    #[test]
    fn unit_mode_refuses_a_run_the_manager_cannot_hold_and_says_why() {
        let (units, scopes) = (
            Arc::new(FakeSpawner::default()),
            Arc::new(FakeSpawner::default()),
        );
        units.unit_like.store(true, Ordering::SeqCst);
        let sw = BackendSwitch::new(
            BackendMode::Unit,
            units.clone(),
            scopes,
            Arc::new(|| {
                Err(ProbeError::Unusable(
                    "the box user's manager does not delegate: memory".into(),
                ))
            }),
        );
        let rq = RunRequest::new(vec!["true".into()]);
        sw.place("a");
        let e = sw.spawn("a", &rq, &limits()).err().unwrap();
        assert!(e.to_string().contains("does not delegate: memory"), "{e}");
        // nothing was started
        assert!(units.spawned.lock().unwrap().is_empty());
    }
}
