//! Restarting a box after patches, only by the owner's rule (ADR 0035). Patching installs updates and never restarts
//! (`RebootOption=NoReboot` on AWS, `Automatic-Reboot "false"` in unattended-upgrades). A restart that a kernel update
//! needs is done here, by one rule the owner sets: `never` (the default: the box says it needs one and waits), or
//! `when-idle` inside a window of the day (UTC), once nothing has used the box for a while. "In use" is a run an agent is
//! executing, a person logged in as the box user, or a hold file the owner placed. The decision is a pure function; the
//! root half reads the box's real signals, and also answers the patch window's pre-check on AWS.

use std::path::{Path, PathBuf};

use ozbox_core::{CommandRunner, CommandSpec};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RebootMode {
    Never,
    WhenIdle,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub mode: RebootMode,
    /// The window, in hours of the day (UTC): from (inclusive) to (exclusive). A window that crosses midnight is `from > to`.
    pub from_hour: u8,
    pub to_hour: u8,
    /// How long nothing may have used the box before it restarts.
    pub idle_minutes: u32,
}

impl Rule {
    pub fn never() -> Self {
        Self {
            mode: RebootMode::Never,
            from_hour: 0,
            to_hour: 0,
            idle_minutes: 30,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.from_hour > 23
            || self.to_hour > 24
            || (self.mode == RebootMode::WhenIdle && self.from_hour == self.to_hour)
        {
            return Err("the window is two different hours of the day, 0 to 23 (UTC)".into());
        }
        if !(5..=1440).contains(&self.idle_minutes) {
            return Err("the idle time is 5 to 1440 minutes".into());
        }
        Ok(())
    }

    /// `never` | `when-idle --from H --to H [--idle MIN]`.
    pub fn from_words(words: &[String]) -> Result<Self, String> {
        let (mode, rest) = words.split_first().ok_or("say never or when-idle")?;
        let mut r = Rule::never();
        r.mode = match mode.as_str() {
            "never" => RebootMode::Never,
            "when-idle" => RebootMode::WhenIdle,
            _ => return Err("the rule is never or when-idle".into()),
        };
        let mut it = rest.iter();
        while let Some(flag) = it.next() {
            let v: u32 = it
                .next()
                .and_then(|v| v.parse().ok())
                .ok_or_else(|| format!("{flag} needs a number"))?;
            match flag.as_str() {
                "--from" => r.from_hour = u8::try_from(v).map_err(|_| "the hour is 0 to 23")?,
                "--to" => r.to_hour = u8::try_from(v).map_err(|_| "the hour is 0 to 24")?,
                "--idle" => r.idle_minutes = v,
                other => return Err(format!("{other} is not an option of this action")),
            }
        }
        if r.mode == RebootMode::Never && !rest.is_empty() {
            return Err("never takes no options".into());
        }
        r.validate()?;
        Ok(r)
    }

    /// The words that carry it to the box (the inverse of [`from_words`](Self::from_words)).
    pub fn to_words(&self) -> Vec<String> {
        match self.mode {
            RebootMode::Never => vec!["never".into()],
            RebootMode::WhenIdle => vec![
                "when-idle".into(),
                "--from".into(),
                self.from_hour.to_string(),
                "--to".into(),
                self.to_hour.to_string(),
                "--idle".into(),
                self.idle_minutes.to_string(),
            ],
        }
    }

    pub fn in_window(&self, hour: u8) -> bool {
        if self.from_hour < self.to_hour {
            (self.from_hour..self.to_hour).contains(&hour)
        } else {
            hour >= self.from_hour || hour < self.to_hour
        }
    }
}

/// Whether a new rule lets the box restart itself where the current one did not: any `when-idle` rule that is not the
/// one in force. Such a change needs a fresh approval the box user cannot make (ADR 0035, amendment 1). `never` does not:
/// it only takes restarts away, and an agent can already hold a restart off with the hold file. Pure.
pub fn loosens(current: &Rule, new: &Rule) -> bool {
    new.mode == RebootMode::WhenIdle && new != current
}

/// What is using the box right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Use {
    pub runs: u32,
    pub sessions: u32,
    pub hold: bool,
}

impl Use {
    pub fn busy(&self) -> bool {
        self.runs > 0 || self.sessions > 0 || self.hold
    }
    pub fn describe(&self) -> String {
        if !self.busy() {
            return "idle".into();
        }
        let mut p = Vec::new();
        if self.runs > 0 {
            p.push(format!("{} agent run(s) executing", self.runs));
        }
        if self.sessions > 0 {
            p.push(format!("{} login session(s)", self.sessions));
        }
        if self.hold {
            p.push("a hold file the owner placed".into());
        }
        format!("in use: {}", p.join(", "))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// No restart is needed.
    Nothing,
    /// One is needed; not now, and why.
    Wait(&'static str),
    Reboot,
}

/// Whether to restart now. `idle_since` is the second the box was last seen starting to be idle (`None` while busy).
/// Pure.
pub fn decide(
    rule: &Rule,
    reboot_required: bool,
    u: &Use,
    hour_utc: u8,
    idle_since: Option<u64>,
    now: u64,
) -> Decision {
    if !reboot_required {
        return Decision::Nothing;
    }
    if rule.mode == RebootMode::Never {
        return Decision::Wait("the rule is never: the box waits for the owner to restart it");
    }
    if u.busy() {
        return Decision::Wait("the box is in use");
    }
    if !rule.in_window(hour_utc) {
        return Decision::Wait("outside the window");
    }
    match idle_since {
        Some(t) if now.saturating_sub(t) >= u64::from(rule.idle_minutes) * 60 => Decision::Reboot,
        _ => Decision::Wait("not idle for long enough yet"),
    }
}

#[derive(Debug, Clone)]
pub struct Paths {
    pub etc: PathBuf,
    pub var: PathBuf,
    pub units: PathBuf,
    pub reboot_required: PathBuf,
}

impl Default for Paths {
    fn default() -> Self {
        Self {
            etc: "/etc/ozbox".into(),
            var: "/var/lib/ozbox-patch".into(),
            units: "/etc/systemd/system".into(),
            reboot_required: "/var/run/reboot-required".into(),
        }
    }
}

const SERVICE: &str = "[Unit]\nDescription=Oz Box: restart after patches only by the owner's rule\n\n[Service]\nType=oneshot\nExecStart=/usr/local/bin/ozbox host-guard patch tick\n";
const TIMER: &str = "[Unit]\nDescription=Oz Box: look at the restart rule every five minutes\n\n[Timer]\nOnBootSec=10min\nOnUnitActiveSec=5min\n\n[Install]\nWantedBy=timers.target\n";

pub struct Guard<'a> {
    pub runner: &'a dyn CommandRunner,
    pub paths: Paths,
    pub now: u64,
}

fn write_atomic(path: &Path, text: &str) -> Result<(), String> {
    let io = |e: std::io::Error| format!("could not write {}: {e}", path.display());
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d).map_err(io)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, text).map_err(io)?;
    std::fs::rename(&tmp, path).map_err(io)
}

impl Guard<'_> {
    fn rule_file(&self) -> PathBuf {
        self.paths.etc.join("patch-rule.json")
    }
    fn idle_file(&self) -> PathBuf {
        self.paths.var.join("idle-since")
    }

    pub fn rule(&self) -> Rule {
        std::fs::read_to_string(self.rule_file())
            .ok()
            .and_then(|t| serde_json::from_str::<Rule>(&t).ok())
            .filter(|r| r.validate().is_ok())
            .unwrap_or_else(Rule::never)
    }

    pub fn set(&self, rule: &Rule) -> Result<String, String> {
        rule.validate()?;
        write_atomic(
            &self.rule_file(),
            &serde_json::to_string_pretty(rule).map_err(|e| e.to_string())?,
        )?;
        let sc = |a: &[&str]| {
            let _ = self
                .runner
                .run(&CommandSpec::new("systemctl").args(a.iter().copied()));
        };
        if rule.mode == RebootMode::WhenIdle {
            write_atomic(&self.paths.units.join("ozbox-patch.service"), SERVICE)?;
            write_atomic(&self.paths.units.join("ozbox-patch.timer"), TIMER)?;
            sc(&["daemon-reload"]);
            sc(&["enable", "--now", "ozbox-patch.timer"]);
            Ok(format!(
                "After patches the box restarts itself only between {:02}:00 and {:02}:00 UTC, once nothing has used it for {} minutes.",
                rule.from_hour, rule.to_hour, rule.idle_minutes
            ))
        } else {
            sc(&["disable", "--now", "ozbox-patch.timer"]);
            Ok("The box never restarts itself after patches; it says when it needs one.".into())
        }
    }

    /// What is using the box: runs are the transient units the runner starts, sessions are logins of the box user.
    pub fn usage(&self) -> Use {
        let count = |c: CommandSpec, keep: &dyn Fn(&str) -> bool| -> u32 {
            self.runner
                .run(&c)
                .ok()
                .filter(|o| o.status == Some(0))
                .map_or(0, |o| {
                    o.stdout
                        .lines()
                        .filter(|l| !l.trim().is_empty() && keep(l))
                        .count() as u32
                })
        };
        Use {
            runs: count(
                CommandSpec::new("systemctl").args([
                    "list-units",
                    "ozbox-run-*",
                    "--state=active",
                    "--no-legend",
                    "--plain",
                ]),
                &|_| true,
            ),
            sessions: count(
                CommandSpec::new("loginctl").args(["list-sessions", "--no-legend"]),
                &|l| l.split_whitespace().any(|w| w == "ozbox"),
            ),
            hold: self.paths.etc.join("patch-hold").exists(),
        }
    }

    /// The pre-check the AWS patch window runs: exit status 0 only when the box is idle.
    pub fn check(&self) -> (bool, String) {
        let u = self.usage();
        (!u.busy(), u.describe())
    }

    /// One look, from the timer: remember when the box became idle, and restart if the rule says so.
    pub fn tick(&self, hour_utc: u8) -> String {
        let rule = self.rule();
        let u = self.usage();
        let idle_since = if u.busy() {
            let _ = std::fs::remove_file(self.idle_file());
            None
        } else {
            let t = std::fs::read_to_string(self.idle_file())
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok());
            match t {
                Some(t) => Some(t),
                None => {
                    let _ = write_atomic(&self.idle_file(), &self.now.to_string());
                    Some(self.now)
                }
            }
        };
        match decide(
            &rule,
            self.paths.reboot_required.exists(),
            &u,
            hour_utc,
            idle_since,
            self.now,
        ) {
            Decision::Nothing => "No restart is needed.".into(),
            Decision::Wait(why) => format!("A restart is needed; not now: {why}."),
            Decision::Reboot => {
                let _ = self
                    .runner
                    .run(&CommandSpec::new("systemctl").arg("reboot"));
                "Restarting now, as the owner's rule allows.".into()
            }
        }
    }

    pub fn status(&self) -> String {
        let r = self.rule();
        let need = self.paths.reboot_required.exists();
        let rule = match r.mode {
            RebootMode::Never => "never (the box waits for the owner)".to_string(),
            RebootMode::WhenIdle => format!(
                "when idle, {:02}:00 to {:02}:00 UTC, after {} idle minutes",
                r.from_hour, r.to_hour, r.idle_minutes
            ),
        };
        format!(
            "Restart rule: {rule}. A restart is {}needed. Now: {}.",
            if need { "" } else { "not " },
            self.usage().describe()
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ozbox_core::{Output, RecordingRunner};

    fn w(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_string).collect()
    }

    #[test]
    fn the_rule_is_read_from_words_and_refuses_nonsense() {
        assert_eq!(
            Rule::from_words(&w("never")).unwrap().mode,
            RebootMode::Never
        );
        let r = Rule::from_words(&w("when-idle --from 2 --to 5 --idle 45")).unwrap();
        assert_eq!((r.from_hour, r.to_hour, r.idle_minutes), (2, 5, 45));
        for bad in [
            "sometimes",
            "when-idle",
            "when-idle --from 3 --to 3",
            "when-idle --from 25 --to 3",
            "when-idle --from 1 --to 2 --idle 1",
            "never --from 1",
            "when-idle --from x",
        ] {
            assert!(Rule::from_words(&w(bad)).is_err(), "{bad}");
        }
        assert!(Rule::from_words(&[]).is_err());
        for good in ["never", "when-idle --from 22 --to 4 --idle 30"] {
            let r = Rule::from_words(&w(good)).unwrap();
            assert_eq!(Rule::from_words(&r.to_words()).unwrap(), r);
        }
    }

    #[test]
    fn letting_the_box_restart_itself_loosens_and_never_does_not() {
        let r = |s: &str| Rule::from_words(&w(s)).unwrap();
        assert!(loosens(&r("never"), &r("when-idle --from 2 --to 5")));
        assert!(loosens(
            &r("when-idle --from 2 --to 5"),
            &r("when-idle --from 2 --to 6")
        ));
        assert!(loosens(
            &r("when-idle --from 2 --to 5 --idle 60"),
            &r("when-idle --from 2 --to 5 --idle 30")
        ));
        assert!(!loosens(&r("when-idle --from 2 --to 5"), &r("never")));
        assert!(!loosens(&r("never"), &r("never")));
        assert!(!loosens(
            &r("when-idle --from 2 --to 5"),
            &r("when-idle --from 2 --to 5")
        ));
    }

    #[test]
    fn the_window_may_cross_midnight() {
        let r = Rule::from_words(&w("when-idle --from 22 --to 4")).unwrap();
        assert!(r.in_window(23) && r.in_window(0) && r.in_window(3));
        assert!(!r.in_window(4) && !r.in_window(12) && !r.in_window(21));
    }

    #[test]
    fn a_box_in_use_is_never_restarted_whatever_the_window_says() {
        let r = Rule::from_words(&w("when-idle --from 0 --to 23 --idle 5")).unwrap();
        let idle = Use::default();
        for busy in [
            Use { runs: 1, ..idle },
            Use {
                sessions: 1,
                ..idle
            },
            Use { hold: true, ..idle },
        ] {
            assert!(matches!(
                decide(&r, true, &busy, 3, Some(0), 100_000),
                Decision::Wait("the box is in use")
            ));
        }
        assert_eq!(
            decide(&r, true, &idle, 3, Some(0), 100_000),
            Decision::Reboot
        );
    }

    #[test]
    fn the_default_rule_never_restarts_and_no_need_means_nothing() {
        let r = Rule::never();
        assert!(matches!(
            decide(&r, true, &Use::default(), 3, Some(0), 1_000_000),
            Decision::Wait(_)
        ));
        assert_eq!(
            decide(&r, false, &Use::default(), 3, Some(0), 1_000_000),
            Decision::Nothing
        );
        let w2 = Rule::from_words(&w("when-idle --from 2 --to 4 --idle 30")).unwrap();
        assert!(matches!(
            decide(&w2, true, &Use::default(), 12, Some(0), 1_000_000),
            Decision::Wait("outside the window")
        ));
        assert!(matches!(
            decide(&w2, true, &Use::default(), 3, Some(990), 1_000),
            Decision::Wait("not idle for long enough yet")
        ));
        assert!(matches!(
            decide(&w2, true, &Use::default(), 3, None, 1_000),
            Decision::Wait(_)
        ));
    }

    fn paths(d: &Path) -> Paths {
        Paths {
            etc: d.join("etc"),
            var: d.join("var"),
            units: d.join("units"),
            reboot_required: d.join("reboot-required"),
        }
    }

    #[test]
    fn the_timer_restarts_only_after_the_box_has_been_idle_long_enough_inside_the_window() {
        let d = tempfile::tempdir().unwrap();
        let r = RecordingRunner::new();
        let at = |now| Guard {
            runner: &r,
            paths: paths(d.path()),
            now,
        };
        at(0)
            .set(&Rule::from_words(&w("when-idle --from 2 --to 5 --idle 30")).unwrap())
            .unwrap();
        assert!(d.path().join("units/ozbox-patch.timer").is_file());
        std::fs::write(d.path().join("reboot-required"), "").unwrap();
        // first look: idle just began
        assert!(at(1_000).tick(3).contains("not idle for long enough"));
        assert!(!r
            .calls()
            .iter()
            .any(|c| c.args.contains(&"reboot".to_string())));
        // later, idle for 30 minutes: restart
        assert!(at(1_000 + 1_800).tick(3).contains("Restarting"));
        assert!(r
            .calls()
            .iter()
            .any(|c| c.program == "systemctl" && c.args == ["reboot"]));
    }

    #[test]
    fn a_run_in_progress_resets_the_idle_clock_and_is_what_the_pre_check_reports() {
        let d = tempfile::tempdir().unwrap();
        let r = RecordingRunner::new();
        let g = Guard {
            runner: &r,
            paths: paths(d.path()),
            now: 50,
        };
        g.set(&Rule::from_words(&w("when-idle --from 0 --to 23 --idle 5")).unwrap())
            .unwrap();
        std::fs::write(d.path().join("reboot-required"), "").unwrap();
        let _ = g.tick(3);
        assert!(d.path().join("var/idle-since").is_file());
        // a unit named ozbox-run-x is active
        r.reply(Output {
            status: Some(0),
            stdout: "ozbox-run-x.service loaded active running a run\n".into(),
            ..Output::default()
        });
        let (idle, why) = g.check();
        assert!(!idle && why.contains("1 agent run"), "{why}");
        r.reply(Output {
            status: Some(0),
            stdout: "ozbox-run-x.service loaded active running a run\n".into(),
            ..Output::default()
        });
        assert!(g.tick(3).contains("in use"));
        assert!(!d.path().join("var/idle-since").exists());
    }

    #[test]
    fn a_login_of_another_user_is_not_the_box_being_used() {
        let d = tempfile::tempdir().unwrap();
        let r = RecordingRunner::new();
        let g = Guard {
            runner: &r,
            paths: paths(d.path()),
            now: 1,
        };
        r.reply(Output::default());
        r.reply(Output {
            status: Some(0),
            stdout: "3 1000 root seat0\n4 1001 ozbox -\n".into(),
            ..Output::default()
        });
        assert_eq!(g.usage().sessions, 1);
    }
}
