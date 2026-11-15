//! Idle detection and the pause request.
//!
//! Idle = no interactive session (tunnel / IDE / shell), no active run, CPU below a threshold, for N minutes
//! (default 90). Then: checkpoint, then ask whoever controls the box to stop it. Never on an always-on box, and
//! never when the answer to "is anyone here" is unknown.

use std::sync::Arc;

use ozbox_core::{CommandRunner, CommandSpec};
use serde::Serialize;

use crate::checkpoint::CheckpointReport;
use crate::host::HostSource;
use crate::metrics::parse::{self, TCP_ESTABLISHED};
use crate::timeutil::MINUTE_MS;

#[derive(Debug, Clone)]
pub struct IdleConfig {
    pub threshold_minutes: u64,
    pub cpu_threshold_pct: f64,
    /// The `ozbox-always-on=true` label.
    pub always_on: bool,
    /// Loopback ports the IDE / desktop listen on; an established connection to one is a session.
    pub session_ports: Vec<u16>,
    /// After asking for a stop, wait this long before asking again.
    pub retry_minutes: u64,
}

impl Default for IdleConfig {
    fn default() -> Self {
        Self {
            threshold_minutes: 90,
            cpu_threshold_pct: 5.0,
            always_on: false,
            session_ports: vec![8080, 6080],
            retry_minutes: 10,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct IdleInput {
    /// `None` = the session count could not be read.
    pub sessions: Option<u32>,
    pub active_runs: u32,
    pub cpu_pct: f64,
    /// How long all of the above has been quiet.
    pub quiet_minutes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BusyReason {
    AlwaysOn,
    Unknown,
    Sessions,
    ActiveRuns,
    CpuAboveThreshold,
    NotQuietLongEnough,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "state", content = "reason", rename_all = "snake_case")]
pub enum Decision {
    Idle,
    Busy(BusyReason),
}

/// The decision itself, pure.
pub fn decide(input: &IdleInput, cfg: &IdleConfig) -> Decision {
    use BusyReason::*;
    if cfg.always_on {
        return Decision::Busy(AlwaysOn);
    }
    match input.sessions {
        None => return Decision::Busy(Unknown),
        Some(n) if n > 0 => return Decision::Busy(Sessions),
        Some(_) => {}
    }
    if input.active_runs > 0 {
        return Decision::Busy(ActiveRuns);
    }
    if input.cpu_pct >= cfg.cpu_threshold_pct {
        return Decision::Busy(CpuAboveThreshold);
    }
    if input.quiet_minutes < cfg.threshold_minutes {
        return Decision::Busy(NotQuietLongEnough);
    }
    Decision::Idle
}

/// Tracks how long the box has been quiet.
#[derive(Debug, Default)]
pub struct IdleTracker {
    quiet_since_ms: Option<u64>,
}

impl IdleTracker {
    pub fn observe(
        &mut self,
        now_ms: u64,
        sessions: Option<u32>,
        active_runs: u32,
        cpu_pct: f64,
        cfg: &IdleConfig,
    ) -> Decision {
        let active = sessions != Some(0) || active_runs > 0 || cpu_pct >= cfg.cpu_threshold_pct;
        if active {
            self.quiet_since_ms = None;
        } else if self.quiet_since_ms.is_none() {
            self.quiet_since_ms = Some(now_ms);
        }
        let quiet_minutes = self
            .quiet_since_ms
            .map(|s| now_ms.saturating_sub(s) / MINUTE_MS)
            .unwrap_or(0);
        decide(
            &IdleInput {
                sessions,
                active_runs,
                cpu_pct,
                quiet_minutes,
            },
            cfg,
        )
    }
}

// ---- sessions -------------------------------------------------------------------------------------------------

pub trait SessionSource: Send + Sync {
    fn count(&self) -> Result<u32, String>;
}

/// Established connections to the IDE / desktop ports, from `/proc/net/tcp{,6}`. Only the server side of a
/// loopback connection is counted (its local port is the IDE's), so each connection counts once.
pub struct TunnelSessions {
    pub host: Arc<dyn HostSource>,
    pub ports: Vec<u16>,
}

impl SessionSource for TunnelSessions {
    fn count(&self) -> Result<u32, String> {
        let mut n = 0;
        let mut any = false;
        for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
            // tcp6 may be absent on a box with IPv6 disabled; tcp must be readable.
            match self.host.read(path) {
                Ok(t) => {
                    any = true;
                    let entries = parse::parse_proc_net_tcp(&t).map_err(|e| e.to_string())?;
                    n += entries
                        .iter()
                        .filter(|e| {
                            e.state == TCP_ESTABLISHED
                                && e.local_loopback
                                && self.ports.contains(&e.local_port)
                        })
                        .count() as u32;
                }
                Err(e) if path.ends_with("tcp6") => {
                    let _ = e;
                }
                Err(e) => return Err(format!("{path}: {}", e.kind())),
            }
        }
        if any {
            Ok(n)
        } else {
            Err("no tcp table".into())
        }
    }
}

/// Logged-in shell sessions from `who` (utmp).
pub struct WhoSessions {
    pub runner: Arc<dyn CommandRunner>,
}

pub fn parse_who(text: &str) -> u32 {
    text.lines().filter(|l| !l.trim().is_empty()).count() as u32
}

impl SessionSource for WhoSessions {
    fn count(&self) -> Result<u32, String> {
        let out = self
            .runner
            .run_ok(&CommandSpec::new("who"))
            .map_err(|_| "who failed".to_string())?;
        Ok(parse_who(&out.stdout))
    }
}

/// Sum of several sources; unknown if any is unknown.
pub struct CombinedSessions(pub Vec<Box<dyn SessionSource>>);

impl SessionSource for CombinedSessions {
    fn count(&self) -> Result<u32, String> {
        self.0
            .iter()
            .try_fold(0u32, |a, s| s.count().map(|n| a + n))
    }
}

// ---- stopping -------------------------------------------------------------------------------------------------

pub trait StopRequester: Send + Sync {
    fn request_stop(&self) -> Result<(), String>;
    /// False when there is no way to stop the box at all (nothing configured), as opposed to a stop that was tried and
    /// failed. Nothing configured is a fact about the setup, so it is recorded once, not on every retry.
    fn configured(&self) -> bool {
        true
    }
}

/// What the daemon records when no stop command is set, with the way to set one.
pub const NO_STOP_COMMAND: &str = "no stop command configured, so this box will not pause itself when idle. To turn auto-pause on, set [idle] stop_command in /etc/ozbox/ozboxd.toml to a command that asks the machine that controls this box to pause it (the box has no cloud permission to stop itself, so the command must reach that machine, for example over SSH, and run `ozbox pause <box>` there); leave it empty to keep the box running. Idle checkpoints of your repositories still run every ten minutes";

/// Runs a configured argv, e.g. a command that asks a control host to pause this box.
pub struct CommandStopRequester {
    pub runner: Arc<dyn CommandRunner>,
    pub argv: Vec<String>,
}

impl StopRequester for CommandStopRequester {
    fn request_stop(&self) -> Result<(), String> {
        let Some((prog, args)) = self.argv.split_first() else {
            return Err(NO_STOP_COMMAND.into());
        };
        self.runner
            .run_ok(&CommandSpec::new(prog.clone()).args(args.iter().cloned()))
            .map(|_| ())
            .map_err(|_| "the stop command failed".to_string())
    }
}

/// Nothing configured: the caller records an incident instead of stopping.
pub struct UnconfiguredStop;

impl StopRequester for UnconfiguredStop {
    fn request_stop(&self) -> Result<(), String> {
        Err(NO_STOP_COMMAND.into())
    }
    fn configured(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepOutcome {
    Busy(BusyReason),
    /// Idle, but a stop was requested recently.
    CoolingDown,
    /// Idle, but the checkpoint reported errors: the box is left running rather than risk unsaved work.
    CheckpointFailed(Vec<String>),
    StopRequested(CheckpointReport),
    StopFailed(String, CheckpointReport),
    /// Idle, and there is no stop command, which was already recorded once: nothing more to say.
    NoStopConfigured,
}

pub struct IdleLoop {
    pub cfg: IdleConfig,
    tracker: IdleTracker,
    sessions: Box<dyn SessionSource>,
    stopper: Box<dyn StopRequester>,
    last_request_ms: Option<u64>,
    /// The missing stop command has been reported (once per daemon run).
    no_stop_reported: bool,
}

impl IdleLoop {
    pub fn new(
        cfg: IdleConfig,
        sessions: Box<dyn SessionSource>,
        stopper: Box<dyn StopRequester>,
    ) -> Self {
        Self {
            cfg,
            tracker: IdleTracker::default(),
            sessions,
            stopper,
            last_request_ms: None,
            no_stop_reported: false,
        }
    }

    pub fn step(
        &mut self,
        now_ms: u64,
        active_runs: u32,
        cpu_pct: f64,
        checkpoint: &dyn Fn() -> CheckpointReport,
    ) -> StepOutcome {
        let sessions = self.sessions.count().ok();
        match self
            .tracker
            .observe(now_ms, sessions, active_runs, cpu_pct, &self.cfg)
        {
            Decision::Busy(r) => StepOutcome::Busy(r),
            Decision::Idle => {
                if self
                    .last_request_ms
                    .is_some_and(|t| now_ms.saturating_sub(t) < self.cfg.retry_minutes * MINUTE_MS)
                {
                    return StepOutcome::CoolingDown;
                }
                // An idle box checkpoints its repositories on the retry cadence whether or not a stop command exists:
                // that never depended on being able to stop the box, and it still does not.
                let report = checkpoint();
                self.last_request_ms = Some(now_ms);
                if !report.errors.is_empty() {
                    return StepOutcome::CheckpointFailed(report.errors);
                }
                // Nothing to ask once it has been said that nothing is configured: no stop request, no incident.
                if self.no_stop_reported && !self.stopper.configured() {
                    return StepOutcome::NoStopConfigured;
                }
                match self.stopper.request_stop() {
                    Ok(()) => StepOutcome::StopRequested(report),
                    Err(e) => {
                        if !self.stopper.configured() {
                            self.no_stop_reported = true;
                        }
                        StepOutcome::StopFailed(e, report)
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::FakeHost;
    use ozbox_core::RecordingRunner;
    use std::sync::Mutex;

    fn input(sessions: Option<u32>, runs: u32, cpu: f64, quiet: u64) -> IdleInput {
        IdleInput {
            sessions,
            active_runs: runs,
            cpu_pct: cpu,
            quiet_minutes: quiet,
        }
    }

    #[test]
    fn decision_table() {
        let cfg = IdleConfig::default();
        use BusyReason::*;
        assert_eq!(decide(&input(Some(0), 0, 1.0, 90), &cfg), Decision::Idle);
        assert_eq!(decide(&input(Some(0), 0, 1.0, 500), &cfg), Decision::Idle);
        assert_eq!(
            decide(&input(Some(1), 0, 1.0, 500), &cfg),
            Decision::Busy(Sessions)
        );
        assert_eq!(
            decide(&input(Some(0), 1, 1.0, 500), &cfg),
            Decision::Busy(ActiveRuns)
        );
        assert_eq!(
            decide(&input(Some(0), 0, 5.0, 500), &cfg),
            Decision::Busy(CpuAboveThreshold)
        );
        assert_eq!(
            decide(&input(Some(0), 0, 1.0, 89), &cfg),
            Decision::Busy(NotQuietLongEnough)
        );
        assert_eq!(
            decide(&input(None, 0, 1.0, 500), &cfg),
            Decision::Busy(Unknown)
        );
        let always = IdleConfig {
            always_on: true,
            ..IdleConfig::default()
        };
        assert_eq!(
            decide(&input(Some(0), 0, 0.0, 99_999), &always),
            Decision::Busy(AlwaysOn)
        );
    }

    #[test]
    fn tracker_resets_on_activity() {
        let cfg = IdleConfig {
            threshold_minutes: 10,
            ..IdleConfig::default()
        };
        let mut t = IdleTracker::default();
        let m = MINUTE_MS;
        assert_eq!(
            t.observe(0, Some(0), 0, 0.0, &cfg),
            Decision::Busy(BusyReason::NotQuietLongEnough)
        );
        assert_eq!(
            t.observe(9 * m, Some(0), 0, 0.0, &cfg),
            Decision::Busy(BusyReason::NotQuietLongEnough)
        );
        assert_eq!(t.observe(10 * m, Some(0), 0, 0.0, &cfg), Decision::Idle);
        // someone connects: the clock restarts
        assert_eq!(
            t.observe(11 * m, Some(1), 0, 0.0, &cfg),
            Decision::Busy(BusyReason::Sessions)
        );
        assert_eq!(
            t.observe(12 * m, Some(0), 0, 0.0, &cfg),
            Decision::Busy(BusyReason::NotQuietLongEnough)
        );
        assert_eq!(t.observe(22 * m, Some(0), 0, 0.0, &cfg), Decision::Idle);
        // an unreadable session count is activity too
        assert_eq!(
            t.observe(23 * m, None, 0, 0.0, &cfg),
            Decision::Busy(BusyReason::Unknown)
        );
        assert_eq!(
            t.observe(24 * m, Some(0), 0, 0.0, &cfg),
            Decision::Busy(BusyReason::NotQuietLongEnough)
        );
    }

    #[test]
    fn counts_tunnel_sessions_once() {
        let host = Arc::new(FakeHost::default());
        let t4 = std::fs::read_to_string(format!(
            "{}/tests/fixtures/net_tcp.txt",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let t6 = std::fs::read_to_string(format!(
            "{}/tests/fixtures/net_tcp6.txt",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        host.set("/proc/net/tcp", &t4);
        let s = TunnelSessions {
            host: host.clone(),
            ports: vec![8080],
        };
        // fixture: one established loopback connection to 8080 (the listener and the client end are not counted)
        assert_eq!(s.count(), Ok(1));
        host.set("/proc/net/tcp6", &t6);
        let s2 = TunnelSessions {
            host: host.clone(),
            ports: vec![8080, 0x17B8],
        };
        assert_eq!(s2.count(), Ok(2));
        let missing = TunnelSessions {
            host: Arc::new(FakeHost::default()),
            ports: vec![8080],
        };
        assert!(missing.count().is_err());
    }

    #[test]
    fn who_lines() {
        assert_eq!(parse_who("ozbox pts/0 2026-11-09 10:00 (10.0.0.2)\n\n"), 1);
        assert_eq!(parse_who(""), 0);
    }

    struct Sessions0;
    impl SessionSource for Sessions0 {
        fn count(&self) -> Result<u32, String> {
            Ok(0)
        }
    }

    struct Spy(Arc<Mutex<u32>>, Result<(), String>);
    impl StopRequester for Spy {
        fn request_stop(&self) -> Result<(), String> {
            if let Ok(mut n) = self.0.lock() {
                *n += 1;
            }
            self.1.clone()
        }
    }

    fn ok_report() -> CheckpointReport {
        CheckpointReport::default()
    }

    #[test]
    fn checkpoints_before_stopping_and_cools_down() {
        let calls = Arc::new(Mutex::new(0));
        let order = Arc::new(Mutex::new(Vec::<&'static str>::new()));
        let cfg = IdleConfig {
            threshold_minutes: 0,
            ..IdleConfig::default()
        };
        let mut l = IdleLoop::new(
            cfg,
            Box::new(Sessions0),
            Box::new(Spy(calls.clone(), Ok(()))),
        );
        let o2 = order.clone();
        let cp = move || {
            if let Ok(mut o) = o2.lock() {
                o.push("checkpoint");
            }
            ok_report()
        };
        assert!(matches!(
            l.step(0, 0, 0.0, &cp),
            StepOutcome::StopRequested(_)
        ));
        assert_eq!(l.step(MINUTE_MS, 0, 0.0, &cp), StepOutcome::CoolingDown);
        assert_eq!(*calls.lock().unwrap(), 1);
        assert_eq!(order.lock().unwrap().len(), 1);
        assert!(matches!(
            l.step(11 * MINUTE_MS, 0, 0.0, &cp),
            StepOutcome::StopRequested(_)
        ));
        assert_eq!(*calls.lock().unwrap(), 2);
    }

    #[test]
    fn failed_checkpoint_keeps_the_box_running() {
        let calls = Arc::new(Mutex::new(0));
        let cfg = IdleConfig {
            threshold_minutes: 0,
            ..IdleConfig::default()
        };
        let mut l = IdleLoop::new(
            cfg,
            Box::new(Sessions0),
            Box::new(Spy(calls.clone(), Ok(()))),
        );
        let bad = || CheckpointReport {
            errors: vec!["p: git add failed".into()],
            ..Default::default()
        };
        assert!(matches!(
            l.step(0, 0, 0.0, &bad),
            StepOutcome::CheckpointFailed(_)
        ));
        assert_eq!(*calls.lock().unwrap(), 0);
    }

    #[test]
    fn always_on_never_checkpoints_or_stops() {
        let calls = Arc::new(Mutex::new(0));
        let cfg = IdleConfig {
            threshold_minutes: 0,
            always_on: true,
            ..IdleConfig::default()
        };
        let mut l = IdleLoop::new(
            cfg,
            Box::new(Sessions0),
            Box::new(Spy(calls.clone(), Ok(()))),
        );
        let never = || -> CheckpointReport { panic!("must not checkpoint") };
        assert_eq!(
            l.step(0, 0, 0.0, &never),
            StepOutcome::Busy(BusyReason::AlwaysOn)
        );
        assert_eq!(*calls.lock().unwrap(), 0);
    }

    #[test]
    fn a_missing_stop_command_is_reported_once_not_every_retry() {
        let mut l = IdleLoop::new(
            IdleConfig {
                threshold_minutes: 0,
                ..IdleConfig::default()
            },
            Box::new(Sessions0),
            Box::new(UnconfiguredStop),
        );
        let checkpoints = std::cell::Cell::new(0u32);
        let cp = || {
            checkpoints.set(checkpoints.get() + 1);
            ok_report()
        };
        let first = l.step(0, 0, 0.0, &cp);
        assert!(
            matches!(&first, StepOutcome::StopFailed(why, _) if why.contains("stop_command")),
            "the first time it says how to configure one: {first:?}"
        );
        // well past the retry window, still idle: nothing more is recorded
        for i in 1..=5u64 {
            assert_eq!(
                l.step(i * 20 * MINUTE_MS, 0, 0.0, &cp),
                StepOutcome::NoStopConfigured
            );
        }
        // the checkpoints went on at the retry cadence: the report only stopped the stop requests
        assert_eq!(checkpoints.get(), 6);
        // and inside the retry window it is still a cooldown, not another checkpoint
        assert_eq!(
            l.step(5 * 20 * MINUTE_MS + MINUTE_MS, 0, 0.0, &cp),
            StepOutcome::CoolingDown
        );
        assert_eq!(checkpoints.get(), 6);
    }

    #[test]
    fn stop_command_is_an_argv_and_unconfigured_fails() {
        let r = Arc::new(RecordingRunner::new());
        let s = CommandStopRequester {
            runner: r.clone(),
            argv: vec!["ozbox".into(), "pause".into(), "my-box".into()],
        };
        // RecordingRunner's default reply is status 0.
        r.reply(ozbox_core::Output {
            status: Some(0),
            ..Default::default()
        });
        assert!(s.request_stop().is_ok());
        assert_eq!(
            r.calls()[0].args,
            vec!["pause".to_string(), "my-box".to_string()]
        );
        assert!(UnconfiguredStop.request_stop().is_err());
        assert!(CommandStopRequester {
            runner: r,
            argv: vec![]
        }
        .request_stop()
        .is_err());
    }
}
