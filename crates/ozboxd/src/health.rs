//! Health: incidents, restart count, OOM kills, image version and pending security updates.

use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ozbox_core::{CommandRunner, CommandSpec};

use crate::host::HostSource;
use serde::{Deserialize, Serialize};

pub const MAX_INCIDENTS: usize = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentKind {
    Restart,
    OomKill,
    StopRequestFailed,
    CheckpointFailed,
    SelfTestFailed,
    BackupFailed,
    RunStartFailed,
    RunTimedOut,
    Interruption,
    DiskGrown,
    DiskGrowFailed,
    MetricsDegraded,
    /// The box stalled on memory (`/proc/pressure/memory`): said before the kernel kills anything (ADR 0045).
    MemoryPressure,
    Unexpected,
}

/// Ids, counts and step names only - never paths of user files, arguments or contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Incident {
    pub ts_ms: u64,
    pub kind: IncidentKind,
    pub detail: String,
}

/// Bounded in-memory history, mirrored to a JSON-lines file when a path is given.
pub struct IncidentLog {
    items: VecDeque<Incident>,
    path: Option<PathBuf>,
}

impl IncidentLog {
    pub fn in_memory() -> Self {
        Self {
            items: VecDeque::new(),
            path: None,
        }
    }

    /// Load the last [`MAX_INCIDENTS`] lines (a torn line is skipped) and keep appending.
    pub fn open(path: PathBuf) -> Self {
        let mut items = VecDeque::new();
        if let Ok(text) = fs::read_to_string(&path) {
            for l in text.lines() {
                if let Ok(i) = serde_json::from_str::<Incident>(l) {
                    items.push_back(i);
                    if items.len() > MAX_INCIDENTS {
                        items.pop_front();
                    }
                }
            }
        }
        Self {
            items,
            path: Some(path),
        }
    }

    pub fn record(&mut self, ts_ms: u64, kind: IncidentKind, detail: impl Into<String>) {
        let mut detail: String = detail.into();
        detail.truncate(300);
        let inc = Incident {
            ts_ms,
            kind,
            detail,
        };
        if let Some(p) = &self.path {
            let line = serde_json::to_string(&inc).unwrap_or_default();
            if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(p) {
                let _ = writeln!(f, "{line}");
            }
        }
        self.items.push_back(inc);
        if self.items.len() > MAX_INCIDENTS {
            self.items.pop_front();
            // Keep the file bounded: rewrite it from memory once it has outgrown the cap by 2x.
            if let Some(p) = &self.path {
                if fs::metadata(p).map(|m| m.len()).unwrap_or(0) > (MAX_INCIDENTS as u64) * 2 * 400
                {
                    let body: String = self
                        .items
                        .iter()
                        .filter_map(|i| serde_json::to_string(i).ok())
                        .map(|l| l + "\n")
                        .collect();
                    let _ = fs::write(p, body);
                }
            }
        }
    }

    pub fn since(&self, since_ms: u64) -> Vec<Incident> {
        self.items
            .iter()
            .filter(|i| i.ts_ms >= since_ms)
            .cloned()
            .collect()
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct PersistedState {
    #[serde(default)]
    restarts: u64,
}

/// Increment and persist the restart counter (atomic replace); returns the new count. Unreadable state restarts at 1.
pub fn bump_restart_count(path: &Path) -> u64 {
    let mut st: PersistedState = fs::read_to_string(path)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default();
    st.restarts += 1;
    let tmp = path.with_extension("tmp");
    if let Ok(body) = serde_json::to_string(&st) {
        if let Ok(mut f) = fs::File::create(&tmp) {
            let ok = f.write_all(body.as_bytes()).is_ok() && f.sync_all().is_ok();
            if ok {
                let _ = fs::rename(&tmp, path);
            }
        }
    }
    st.restarts
}

/// Turns `memory.events` counters into "new OOM kills since last look".
#[derive(Debug, Default)]
pub struct OomWatcher {
    last: BTreeMap<String, u64>,
}

impl OomWatcher {
    /// Record a baseline so history from before this process started is not reported.
    pub fn prime(&mut self, key: &str, oom_kill: u64) {
        self.last.insert(key.to_string(), oom_kill);
    }

    /// New kills since the previous call. A key never seen counts from zero (a brand-new run cgroup).
    pub fn observe(&mut self, key: &str, oom_kill: u64) -> u64 {
        let prev = self.last.insert(key.to_string(), oom_kill).unwrap_or(0);
        oom_kill.saturating_sub(prev)
    }

    /// Whether a baseline exists for this key.
    pub fn has(&self, key: &str) -> bool {
        self.last.contains_key(key)
    }

    /// Forget cgroups that no longer exist.
    pub fn retain(&mut self, alive: &[String]) {
        self.last.retain(|k, _| alive.contains(k));
    }
}

/// A cgroup whose `memory.events` counts kills of every process below it, watched beside the runs' own cgroups: a run
/// that was killed whole has its cgroup removed before anyone reads it, and the kill is only left in the slice above.
#[derive(Debug, Clone)]
pub struct OomSlice {
    /// The key the baseline is kept under.
    pub key: String,
    /// The `memory.events` file.
    pub path: String,
    /// What the incident calls it ("the box slice").
    pub label: String,
    /// Which runs live below it: kills of those are already counted from their own cgroups when those can still be read.
    pub holds_units: bool,
}

/// What one pass of the OOM watch found.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct OomStep {
    /// New kills, each counted once.
    pub kills: u64,
    /// One text per new finding, for an `OomKill` incident.
    pub incidents: Vec<String>,
}

fn events_oom_kill(text: &str) -> Option<u64> {
    crate::metrics::parse::parse_memory_events(text)
        .ok()
        .map(|e| e.oom_kill)
}

/// Record the baseline of every slice that can be read now, so kills from before this process started are not reported.
pub fn prime_oom_slices(host: &dyn HostSource, watcher: &mut OomWatcher, slices: &[OomSlice]) {
    for s in slices {
        if let Some(n) = host.read(&s.path).ok().as_deref().and_then(events_oom_kill) {
            watcher.prime(&s.key, n);
        }
    }
}

/// One pass of the OOM watch: each live run's own `memory.events` (read by `read_run`, which says `None` when the cgroup
/// is already gone), then each slice. A slice that could not be read at start is baselined on its first good read and
/// reports nothing then; a missing file stays silent. A slice reports only what the runs it holds did not already
/// account for in the same pass, so a live run that was killed is one incident, not two.
pub fn oom_step(
    host: &dyn HostSource,
    watcher: &mut OomWatcher,
    runs: &[(String, String)],
    read_run: &dyn Fn(&str) -> Option<String>,
    slices: &[OomSlice],
) -> OomStep {
    let mut out = OomStep::default();
    let (mut unit_kills, mut scope_kills) = (0u64, 0u64);
    for (id, name) in runs {
        let Some(n) = read_run(name).as_deref().and_then(events_oom_kill) else {
            continue;
        };
        let n = watcher.observe(name, n);
        if n > 0 {
            out.kills += n;
            out.incidents
                .push(format!("run {id}: {n} process(es) killed for memory"));
            if name.ends_with(".service") {
                unit_kills += n;
            } else {
                scope_kills += n;
            }
        }
    }
    for s in slices {
        let Some(n) = host.read(&s.path).ok().as_deref().and_then(events_oom_kill) else {
            continue;
        };
        if !watcher.has(&s.key) {
            watcher.prime(&s.key, n);
            continue;
        }
        let n = watcher.observe(&s.key, n);
        let n = n.saturating_sub(if s.holds_units {
            unit_kills
        } else {
            scope_kills
        });
        if n > 0 {
            out.kills += n;
            out.incidents
                .push(format!("{n} process(es) killed under {}", s.label));
        }
    }
    let mut alive: Vec<String> = runs.iter().map(|(_, n)| n.clone()).collect();
    alive.extend(slices.iter().map(|s| s.key.clone()));
    watcher.retain(&alive);
    out
}

/// `/etc/ozbox-release`: `VERSION=` / `IMAGE_VERSION=` lines, else the first non-empty line.
pub fn parse_release(text: &str) -> Option<String> {
    let clean = |s: &str| s.trim().trim_matches('"').trim_matches('\'').to_string();
    for l in text.lines() {
        if let Some((k, v)) = l.split_once('=') {
            if matches!(k.trim(), "VERSION" | "IMAGE_VERSION") {
                let v = clean(v);
                if !v.is_empty() {
                    return Some(v);
                }
            }
        }
    }
    text.lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.contains('='))
        .map(clean)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PendingUpdates {
    pub total: u32,
    pub security: u32,
}

/// Count `Inst` lines of `apt-get -s upgrade`; those from a `-security` pocket are security updates.
pub fn parse_apt_simulation(text: &str) -> PendingUpdates {
    let mut p = PendingUpdates {
        total: 0,
        security: 0,
    };
    for l in text.lines().filter(|l| l.starts_with("Inst ")) {
        p.total += 1;
        if l.contains("-security") {
            p.security += 1;
        }
    }
    p
}

/// `None` when apt is unavailable or fails (optional signal).
pub fn pending_updates(runner: &Arc<dyn CommandRunner>) -> Option<PendingUpdates> {
    let out = runner
        .run_ok(&CommandSpec::new("apt-get").args(["-s", "upgrade"]))
        .ok()?;
    Some(parse_apt_simulation(&out.stdout))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ozbox_core::{Output, RecordingRunner};

    #[test]
    fn incidents_are_bounded_persisted_and_torn_tolerant() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("incidents.jsonl");
        {
            let mut l = IncidentLog::open(p.clone());
            l.record(10, IncidentKind::OomKill, "run abc oom_kill+1");
            l.record(20, IncidentKind::Restart, "restart 2");
        }
        fs::OpenOptions::new()
            .append(true)
            .open(&p)
            .unwrap()
            .write_all(b"{\"ts_ms\":3")
            .unwrap();
        let l = IncidentLog::open(p);
        assert_eq!(l.len(), 2);
        assert_eq!(l.since(15).len(), 1);
        let mut mem = IncidentLog::in_memory();
        for i in 0..(MAX_INCIDENTS + 10) {
            mem.record(i as u64, IncidentKind::Unexpected, "x");
        }
        assert_eq!(mem.len(), MAX_INCIDENTS);
        assert_eq!(mem.since(0)[0].ts_ms, 10);
    }

    #[test]
    fn restart_count_persists() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("state.json");
        assert_eq!(bump_restart_count(&p), 1);
        assert_eq!(bump_restart_count(&p), 2);
        fs::write(&p, "garbage").unwrap();
        assert_eq!(bump_restart_count(&p), 1);
    }

    #[test]
    fn oom_deltas() {
        let mut w = OomWatcher::default();
        w.prime("slice", 4);
        assert_eq!(w.observe("slice", 4), 0);
        assert_eq!(w.observe("slice", 6), 2);
        assert_eq!(w.observe("run-x", 1), 1); // new run cgroup counts from 0
        assert_eq!(w.observe("run-x", 1), 0);
        w.retain(&["slice".to_string()]);
        assert_eq!(w.observe("run-x", 1), 1);
    }

    #[test]
    fn release_and_apt() {
        assert_eq!(
            parse_release("VERSION=\"0.3.1\"\nBUILD=abc\n"),
            Some("0.3.1".into())
        );
        assert_eq!(parse_release("\n0.2.0\n"), Some("0.2.0".into()));
        assert_eq!(parse_release("BUILD=x"), None);
        let apt = "Reading package lists...\nInst libssl3 [3.0.1] (3.0.2 Ubuntu:24.04/noble-security [amd64])\nInst vim [1] (2 Ubuntu:24.04/noble-updates [amd64])\nConf vim\n";
        assert_eq!(
            parse_apt_simulation(apt),
            PendingUpdates {
                total: 2,
                security: 1
            }
        );
        let r: Arc<dyn CommandRunner> = Arc::new(RecordingRunner::new());
        assert_eq!(
            pending_updates(&r),
            Some(PendingUpdates {
                total: 0,
                security: 0
            })
        );
        let rr = Arc::new(RecordingRunner::new());
        rr.reply(Output {
            status: Some(100),
            ..Default::default()
        });
        let r2: Arc<dyn CommandRunner> = rr;
        assert_eq!(pending_updates(&r2), None);
    }
}
