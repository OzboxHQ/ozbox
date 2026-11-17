//! Quiesce, the command's side: before a resize, or an upgrade, that stops the machine, say what will end, ask the box's
//! agent to end its runs cleanly and snapshot uncommitted work, and report both. See `ozboxd::quiesce` for what the box does.
//!
//! Three rules. **The plan decides:** quiesce happens only when the plan stops a running machine (`instance.stop`), and only
//! after the person confirmed; a dry run, a refusal and a change that stops nothing never reach the box. **Fail closed in
//! what is said:** a box that could not be asked is "could not list", never "nothing running". **Nothing the box says
//! reaches the terminal as it came:** program names, folders and messages are cleaned of control characters and cut.

use std::time::{Duration, Instant};

use ozbox_core::{BoxRecord, BoxState, Plan};
use serde::Deserialize;
use serde_json::json;

use crate::messages::t;
use crate::run::upgrade::{checkpoint_before, Step, StepOutcome};
use crate::serve::agent::{AgentError, BoxAgent};

/// How long runs get to end by themselves before they are stopped.
pub const GRACE_S: u64 = 10;
/// What the daemon takes beyond the grace, at most (the settling after the kills, the snapshot and its flushes). The box
/// says its own bound in the answer to the first request and that is what is used when it is longer; this is for a box that
/// does not say. Mirrors `ozboxd::quiesce::bound_s`.
const DAEMON_BOUND_EXTRA_S: u64 = 138;
/// Waited on top of the daemon's own bound.
const WAIT_MARGIN_S: u64 = 30;
const MAX_LISTED: usize = 8;

/// Does this plan stop a running machine? Then the box is quiesced first.
pub fn needed(plan: &Plan, rec: &BoxRecord) -> bool {
    rec.state == BoxState::Running && plan.changes.iter().any(|c| c.kind == "instance.stop")
}

/// Text from a box, made safe to print: control characters (escape sequences, line breaks) become `?`, and it is cut.
pub fn clean(s: &str, max: usize) -> String {
    let mut out: String = s
        .chars()
        .map(|c| {
            if c.is_control() || is_format(c) {
                '?'
            } else {
                c
            }
        })
        .take(max)
        .collect();
    if s.chars().count() > max {
        out.push_str("...");
    }
    out
}

/// Characters that print as nothing or reorder what is around them (zero-width, bidirectional controls, the soft hyphen, the
/// byte-order mark): a program or folder name could use them to look like something else.
fn is_format(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{061C}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Service {
    Available,
    /// The agent answered, and has no quiesce service (it predates it).
    Older,
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preview {
    pub service: Service,
    /// Programs of the runs going or queued; `Err` is why they could not be listed.
    pub runs: Result<Vec<String>, String>,
    /// Engines of the coding-agent sessions; `Err` is why they could not be listed.
    pub sessions: Result<Vec<String>, String>,
}

#[derive(Deserialize, Default)]
struct RunsAnswer {
    #[serde(default)]
    runs: Vec<RunRow>,
}
#[derive(Deserialize)]
struct RunRow {
    #[serde(default)]
    state: String,
    #[serde(default)]
    program: String,
}
#[derive(Deserialize, Default)]
struct SessionsAnswer {
    #[serde(default)]
    sessions: Vec<SessionRow>,
}
#[derive(Deserialize)]
struct SessionRow {
    #[serde(default)]
    engine: String,
}

/// Read-only: what the box's agent says is running, and whether it can quiesce. Asks nothing to change.
pub fn preview(agent: &dyn BoxAgent, rec: &BoxRecord) -> Preview {
    let service = match agent.quiesce_call(rec, "GET", b"") {
        Ok((200, _)) => Service::Available,
        Ok((404 | 405, _)) => Service::Older,
        // the service is installed on every box with this release: 503 means it could not start, not that it is older
        Ok((503, _)) => Service::Unknown("it answered that the service is not available".into()),
        Ok((s, _)) => Service::Unknown(format!("it answered {s}")),
        Err(e) => Service::Unknown(clean(&e.to_string(), 200)),
    };
    let runs = match agent.runs(rec, "GET", "", b"") {
        Ok((200, v)) => serde_json::from_value::<RunsAnswer>(v)
            .map(|a| {
                a.runs
                    .into_iter()
                    .filter(|r| r.state == "running" || r.state == "queued")
                    .map(|r| clean(&r.program, 60))
                    .collect()
            })
            .map_err(|_| "its answer was not understood".to_string()),
        Ok((s, _)) => Err(format!("it answered {s}")),
        Err(e) => Err(clean(&e.to_string(), 200)),
    };
    let sessions = match agent.agent_call(rec, "GET", "/v1/agent-sessions", b"") {
        Ok((200, v)) => serde_json::from_value::<SessionsAnswer>(v)
            .map(|a| {
                a.sessions
                    .into_iter()
                    .map(|s| clean(&s.engine, 30))
                    .collect()
            })
            .map_err(|_| "its answer was not understood".to_string()),
        Ok((s, _)) => Err(format!("it answered {s}")),
        Err(e) => Err(clean(&e.to_string(), 200)),
    };
    Preview {
        service,
        runs,
        sessions,
    }
}

impl Preview {
    /// The lines the plan carries before anything is confirmed.
    pub fn notes(&self, box_name: &str) -> Vec<String> {
        let mut v = Vec::new();
        v.push(match &self.service {
            Service::Available => t("quiesce.head", &[]),
            Service::Older => t("quiesce.head_older", &[]),
            Service::Unknown(why) => t("quiesce.head_unknown", &[("box", box_name), ("why", why)]),
        });
        v.push(t("quiesce.ends", &[]));
        v.push(match &self.runs {
            Ok(r) if r.is_empty() => t("quiesce.runs_none", &[]),
            Ok(r) => {
                let mut list: Vec<String> = r.iter().take(MAX_LISTED).cloned().collect();
                if r.len() > MAX_LISTED {
                    list.push(format!("and {} more", r.len() - MAX_LISTED));
                }
                t(
                    "quiesce.runs",
                    &[
                        ("n", &r.len().to_string()),
                        ("list", &list.join(", ")),
                        ("grace", &GRACE_S.to_string()),
                    ],
                )
            }
            Err(why) => t("quiesce.runs_unknown", &[("why", why)]),
        });
        v.push(match &self.sessions {
            Ok(s) if s.is_empty() => t("quiesce.sessions_none", &[]),
            Ok(s) => {
                let claude = s.iter().filter(|e| *e == "claude-code").count();
                t(
                    "quiesce.sessions",
                    &[
                        ("n", &s.len().to_string()),
                        ("claude", &claude.to_string()),
                        ("other", &(s.len() - claude).to_string()),
                    ],
                )
            }
            Err(why) => t("quiesce.sessions_unknown", &[("why", why)]),
        });
        v.push(t("quiesce.other", &[]));
        v.push(match &self.service {
            Service::Available => t("quiesce.snapshot", &[]),
            Service::Older => t("quiesce.snapshot_older", &[("box", box_name)]),
            Service::Unknown(_) => t("quiesce.snapshot_unknown", &[]),
        });
        v
    }
}

/// Time, so a test does not wait.
pub trait Pace {
    fn sleep(&self, d: Duration);
    fn waited(&self) -> Duration;
}

pub struct RealPace(Instant);

impl RealPace {
    pub fn new() -> Self {
        Self(Instant::now())
    }
}

impl Pace for RealPace {
    fn sleep(&self, d: Duration) {
        std::thread::sleep(d);
    }
    fn waited(&self) -> Duration {
        self.0.elapsed()
    }
}

/// What the person asked for: `--strict-checkpoint`, `--legacy-checkpoint` and `--no-checkpoint`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Mode {
    /// Refuse to go on unless the box was fully ready.
    pub strict: bool,
    /// On a box whose agent is older, use its own (visible, possibly pushing) checkpoint instead of going on without one.
    pub legacy: bool,
    /// On a box whose agent is older, go on without any checkpoint: the person said so by name.
    pub none: bool,
}

/// A box whose agent is older can either use its own checkpoint (a visible branch that it may push) or go on with none.
/// Neither is chosen for the person (plan, then apply: what happens is decided before the confirmation, and `--yes` only
/// confirms what the plan said), so the command is refused before anything changes until one of the two is named. A dry
/// run is never refused: it shows the plan and the choice.
pub fn older_choice(
    service: &Service,
    mode: Mode,
    box_name: &str,
) -> Result<Option<String>, String> {
    if *service != Service::Older || mode.strict {
        return Ok(None);
    }
    if mode.legacy {
        return Ok(Some(t("quiesce.chosen_legacy", &[("box", box_name)])));
    }
    if mode.none {
        return Ok(Some(t("quiesce.chosen_none", &[("box", box_name)])));
    }
    Err(t("quiesce.choose_older", &[("box", box_name)]))
}

#[derive(Debug, Clone, Copy)]
pub struct Opts {
    pub mode: Mode,
    pub grace_s: u64,
    /// The longest to wait for the box, in seconds (at least this, and longer when the box's own bound is longer).
    pub max_wait_s: u64,
}

impl Opts {
    pub fn command(mode: Mode) -> Self {
        Self {
            mode,
            grace_s: GRACE_S,
            max_wait_s: GRACE_S + DAEMON_BOUND_EXTRA_S + WAIT_MARGIN_S,
        }
    }
    /// The dashboard waits as long: it does the waiting off its request loop, so no one else waits meanwhile.
    pub fn dashboard() -> Self {
        Self::command(Mode::default())
    }
}

/// Did the box end any run before it was told to stop?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Touched {
    No,
    Yes,
    /// Not known: the box was still working, or was lost, when the command stopped asking.
    Maybe,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quiesced {
    pub step: Step,
    /// May the change go on? Always, unless strict and the box was not fully ready.
    pub proceed: bool,
    /// The change may go on, but the box is not fully ready (work not snapshotted, or runs not asked to end): the person is
    /// asked again.
    pub reconfirm: bool,
    pub touched: Touched,
    /// The box's agent predates this feature (it answered 404 or 405).
    pub older: bool,
}

#[derive(Deserialize, Default)]
struct JobAnswer {
    #[serde(default)]
    state: String,
    #[serde(default)]
    job: u64,
    /// How long the box says the job can take at most.
    #[serde(default)]
    bound_s: u64,
    #[serde(default)]
    report: Option<ReportAnswer>,
}
#[derive(Deserialize, Default)]
struct ReportAnswer {
    #[serde(default)]
    runs: RunsPart,
    #[serde(default)]
    checkpoint: CpPart,
    #[serde(default)]
    runs_untouched: bool,
}
#[derive(Deserialize, Default)]
struct RunsPart {
    #[serde(default)]
    runs: Vec<EndedRow>,
    #[serde(default)]
    not_stopped: usize,
}
#[derive(Deserialize)]
struct EndedRow {
    #[serde(default)]
    program: String,
    #[serde(default)]
    how: String,
}
#[derive(Deserialize, Default)]
struct CpPart {
    #[serde(default)]
    repos_scanned: usize,
    #[serde(default)]
    branches: Vec<BranchRow>,
    #[serde(default)]
    errors: Vec<String>,
    /// What the snapshot left out by design (a home folder repository, files over the size cap): told, never an error.
    #[serde(default)]
    skipped: Vec<String>,
}
#[derive(Deserialize)]
struct BranchRow {
    #[serde(default)]
    repo: String,
    #[serde(default)]
    branch: String,
}

/// Only a ref this feature writes is ever printed as one.
fn plausible_ref(r: &str) -> bool {
    r.strip_prefix("refs/ozbox/wip/").is_some_and(|t| {
        !t.is_empty()
            && t.len() < 40
            && t.bytes()
                .all(|b| b.is_ascii_digit() || matches!(b, b'T' | b'Z' | b'-'))
    })
}

fn render(r: &ReportAnswer) -> (Vec<String>, bool) {
    let mut lines = Vec::new();
    for e in &r.runs.runs {
        let program = clean(&e.program, 60);
        let key = match e.how.as_str() {
            "ended" => "quiesce.run_ended",
            "finished" => "quiesce.run_finished",
            "killed" => "quiesce.run_killed",
            "cancelled" => "quiesce.run_cancelled",
            "exiting" => "quiesce.run_exiting",
            "not_stopped" => "quiesce.run_not_stopped",
            _ => continue,
        };
        lines.push(t(key, &[("program", &program)]));
    }
    // runs counted as not stopped that the list does not name (an agent that counted without listing)
    let named = r
        .runs
        .runs
        .iter()
        .filter(|e| matches!(e.how.as_str(), "exiting" | "not_stopped"))
        .count();
    if r.runs.not_stopped > named {
        lines.push(t(
            "quiesce.not_stopped",
            &[("n", &(r.runs.not_stopped - named).to_string())],
        ));
    }
    let mut any_ref = false;
    for b in &r.checkpoint.branches {
        any_ref = true;
        let name = if plausible_ref(&b.branch) {
            b.branch.clone()
        } else {
            "a snapshot".to_string()
        };
        lines.push(t(
            "quiesce.saved",
            &[("repo", &clean(&b.repo, 80)), ("ref", &name)],
        ));
    }
    if r.checkpoint.branches.is_empty()
        && r.checkpoint.errors.is_empty()
        && r.checkpoint.skipped.is_empty()
    {
        lines.push(t(
            "quiesce.nothing_to_save",
            &[("repos", &r.checkpoint.repos_scanned.to_string())],
        ));
    }
    for e in &r.checkpoint.skipped {
        lines.push(t("quiesce.skipped", &[("what", &clean(e, 160))]));
    }
    for e in &r.checkpoint.errors {
        lines.push(t("quiesce.save_failed", &[("what", &clean(e, 160))]));
    }
    if any_ref {
        lines.push(t("quiesce.restore", &[]));
    }
    let clean_run = r.checkpoint.errors.is_empty() && r.runs.not_stopped == 0;
    (lines, clean_run)
}

fn step(outcome: StepOutcome, head: String, lines: Vec<String>) -> Step {
    let mut detail = head;
    for l in lines {
        detail.push('\n');
        detail.push_str(&l);
    }
    Step::new(outcome, detail)
}

/// Do it: start the quiesce, wait for it (bounded), report. Never panics and never fails the change by itself; only
/// `strict` can make `proceed` false. A box that was not fully ready sets `reconfirm`, so the person is asked again.
pub fn perform(agent: &dyn BoxAgent, rec: &BoxRecord, o: &Opts, pace: &dyn Pace) -> Quiesced {
    let name = rec.spec.name.as_str().to_string();
    let strict = o.mode.strict;
    let not_ready = |outcome: StepOutcome, text: String, touched: Touched, older: bool| Quiesced {
        step: Step::new(outcome, text),
        proceed: !strict,
        reconfirm: true,
        touched,
        older,
    };
    let body = json!({ "grace_s": o.grace_s, "strict": strict }).to_string();
    let (job, mut bound) = match agent.quiesce_call(rec, "POST", body.as_bytes()) {
        Ok((200 | 202, v)) => match serde_json::from_value::<JobAnswer>(v) {
            Ok(a) if a.job > 0 => (a.job, a.bound_s),
            _ => {
                return not_ready(
                    StepOutcome::Failed,
                    t("quiesce.not_understood", &[("box", &name)]),
                    Touched::Maybe,
                    false,
                )
            }
        },
        // an agent that predates the service: its own checkpoint writes a visible branch and may push it, so it is used
        // only when the person asked for it by name, and never under strict (it cannot ask runs to end)
        Ok((404 | 405, _)) => {
            return if o.mode.legacy && !strict {
                legacy(agent, rec, &name)
            } else if o.mode.none && !strict {
                // the person chose no checkpoint by name (`--no-checkpoint`): told, never asked again
                Quiesced {
                    step: Step::new(
                        StepOutcome::Skipped,
                        t("quiesce.none_chosen", &[("box", &name)]),
                    ),
                    proceed: true,
                    reconfirm: false,
                    touched: Touched::No,
                    older: true,
                }
            } else {
                not_ready(
                    StepOutcome::Skipped,
                    t("quiesce.older_not_saved", &[("box", &name)]),
                    Touched::No,
                    true,
                )
            };
        }
        // a box of this release answers 503 when the service did not start: that is a failure, never "older"
        Ok((503, _)) => {
            return not_ready(
                StepOutcome::Failed,
                t("quiesce.not_started", &[("box", &name)]),
                Touched::No,
                false,
            )
        }
        Ok((429, v)) => {
            let retry = v
                .get("retry_after_s")
                .and_then(serde_json::Value::as_u64)
                .map(|n| format!(" (try again in {n} seconds)"))
                .unwrap_or_default();
            return not_ready(
                StepOutcome::Failed,
                t("quiesce.too_soon", &[("box", &name), ("retry", &retry)]),
                Touched::No,
                false,
            );
        }
        Ok((s, _)) => {
            return not_ready(
                StepOutcome::Failed,
                t(
                    "quiesce.refused",
                    &[("box", &name), ("status", &s.to_string())],
                ),
                Touched::No,
                false,
            )
        }
        Err(e) => {
            return not_ready(
                StepOutcome::Skipped,
                t(
                    "quiesce.unreachable",
                    &[("box", &name), ("why", &clean(&e.to_string(), 200))],
                ),
                Touched::No,
                false,
            )
        }
    };
    let mut limit = Duration::from_secs(o.max_wait_s.max(bound + WAIT_MARGIN_S));
    let mut bad = 0;
    loop {
        match agent.quiesce_call(rec, "GET", b"") {
            Ok((200, v)) => {
                bad = 0;
                if let Ok(a) = serde_json::from_value::<JobAnswer>(v) {
                    if a.bound_s > bound {
                        bound = a.bound_s;
                        limit = limit.max(Duration::from_secs(bound + WAIT_MARGIN_S));
                    }
                    if a.job != job || a.state == "idle" {
                        return not_ready(
                            StepOutcome::Failed,
                            t("quiesce.gone", &[]),
                            Touched::Maybe,
                            false,
                        );
                    }
                    if a.state == "done" {
                        return finished(a.report.unwrap_or_default(), strict);
                    }
                }
            }
            // A poll that fails (a dropped SSH connection) says nothing about the job, which keeps going on the box and is
            // bounded: keep asking until the time it is allowed to take, plus the margin, has passed. Giving up sooner and
            // stopping the machine could cut it in the middle of a git write.
            _ => bad += 1,
        }
        if pace.waited() >= limit {
            let key = if bad > 0 {
                "quiesce.lost"
            } else {
                "quiesce.timeout"
            };
            return not_ready(
                StepOutcome::Failed,
                t(
                    key,
                    &[("box", &name), ("secs", &limit.as_secs().to_string())],
                ),
                Touched::Maybe,
                false,
            );
        }
        pace.sleep(Duration::from_secs(1));
    }
}

fn finished(report: ReportAnswer, strict: bool) -> Quiesced {
    let untouched = report.runs_untouched;
    let touched = if untouched || (report.runs.runs.is_empty() && report.runs.not_stopped == 0) {
        Touched::No
    } else {
        Touched::Yes
    };
    let (lines, ok) = render(&report);
    // `killed` is the designed outcome for a program that ignores the request, so it is not "unclean"; a run that could not
    // be stopped, a snapshot that failed, and a job that stopped before it touched a run are.
    Quiesced {
        step: step(
            if ok {
                StepOutcome::Done
            } else {
                StepOutcome::Failed
            },
            t(
                if ok {
                    "quiesce.done"
                } else {
                    "quiesce.partial"
                },
                &[],
            ),
            lines,
        ),
        proceed: ok || !strict,
        reconfirm: !ok,
        touched,
        older: false,
    }
}

/// A box whose agent has no quiesce service, used only when the person asked: its own checkpoint (a visible branch, pushed if
/// that box was set up to push), and runs are not asked to end.
fn legacy(agent: &dyn BoxAgent, rec: &BoxRecord, name: &str) -> Quiesced {
    let cp = checkpoint_before(agent, rec);
    Quiesced {
        step: Step::new(
            cp.outcome,
            format!("{}\n{}", t("quiesce.legacy", &[("box", name)]), cp.detail),
        ),
        proceed: true,
        // the person asked for this path by name
        reconfirm: false,
        touched: Touched::No,
        older: true,
    }
}

/// What a refusal under `--strict-checkpoint` says, including what already happened.
pub fn strict_refusal(box_name: &str, touched: Touched) -> String {
    t(
        match touched {
            Touched::No => "quiesce.strict_stop_untouched",
            Touched::Yes => "quiesce.strict_stop_touched",
            Touched::Maybe => "quiesce.strict_stop_maybe",
        },
        &[("box", box_name)],
    )
}

/// What the person declining the second question hears.
pub fn declined(box_name: &str) -> String {
    t("quiesce.declined", &[("box", box_name)])
}

/// The question asked again when the box was not fully ready.
pub fn reconfirm_question(box_name: &str) -> String {
    t("quiesce.reconfirm", &[("box", box_name)])
}

/// Best effort after a change that did not go on: end the hold on new runs, so a box that did not stop does not keep
/// refusing them.
pub fn release(agent: &dyn BoxAgent, rec: &BoxRecord) {
    let _: Result<_, AgentError> = agent.quiesce_call(rec, "DELETE", b"");
}

/// Run `body` (the wait for the box to be ready, and the question that may follow) so that Ctrl-C does not leave the hold on
/// new runs behind: the hold is lifted (which also asks a job that is still running to stop) before the process exits with
/// status 130. Once `body` returns the signal does what it always does.
#[cfg(unix)]
pub fn guard_interrupt<T>(agent: &dyn BoxAgent, rec: &BoxRecord, body: impl FnOnce() -> T) -> T {
    use signal_hook::consts::SIGINT;
    use std::sync::atomic::AtomicBool;
    let hit = std::sync::Arc::new(AtomicBool::new(false));
    let done = std::sync::Arc::new(AtomicBool::new(false));
    // Registered in this order: while `done` is false the signal only sets `hit`; once it is true the default action runs.
    let _ = signal_hook::flag::register_conditional_default(SIGINT, std::sync::Arc::clone(&done));
    let _ = signal_hook::flag::register(SIGINT, std::sync::Arc::clone(&hit));
    watch_interrupt(agent, rec, &hit, &done, &|| std::process::exit(130), body)
}

#[cfg(not(unix))]
pub fn guard_interrupt<T>(_: &dyn BoxAgent, _: &BoxRecord, body: impl FnOnce() -> T) -> T {
    body()
}

/// The watcher behind [`guard_interrupt`], with the flag and the exit passed in so a test can drive it.
fn watch_interrupt<T>(
    agent: &dyn BoxAgent,
    rec: &BoxRecord,
    hit: &std::sync::atomic::AtomicBool,
    done: &std::sync::atomic::AtomicBool,
    exit: &(dyn Fn() + Sync),
    body: impl FnOnce() -> T,
) -> T {
    use std::sync::atomic::Ordering;
    std::thread::scope(|scope| {
        scope.spawn(|| {
            while !done.load(Ordering::SeqCst) {
                if hit.load(Ordering::SeqCst) {
                    release(agent, rec);
                    eprintln!(
                        "{}",
                        t("quiesce.interrupted", &[("box", rec.spec.name.as_str())])
                    );
                    exit();
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        });
        let out = body();
        done.store(true, Ordering::SeqCst);
        out
    })
}

/// The hold on new runs, lifted when this goes out of scope unless [`Hold::disarm`] was called (after the change was
/// applied and the box stopped). Covers a refusal, a declined question, a failed apply and every early return between.
pub struct Hold<'a> {
    agent: &'a dyn BoxAgent,
    rec: &'a BoxRecord,
    armed: bool,
}

impl<'a> Hold<'a> {
    pub fn new(agent: &'a dyn BoxAgent, rec: &'a BoxRecord) -> Self {
        Self {
            agent,
            rec,
            armed: true,
        }
    }
    pub fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for Hold<'_> {
    fn drop(&mut self) {
        if self.armed {
            release(self.agent, self.rec);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::serve::agent::{CheckpointOutcome, Incident, SelfTest};
    use ozbox_core::{BoxName, BoxSpec, MetricsSample, Operation, Provider, Size};
    use serde_json::{json, Value};
    use std::cell::Cell;
    use std::sync::Mutex;

    type Answer = Result<(u16, Value), AgentError>;
    type Script = Box<dyn Fn(&str, u32) -> Answer + Send + Sync>;

    struct Scripted {
        quiesce: Script,
        gets: Mutex<u32>,
        calls: Mutex<Vec<String>>,
        runs: Answer,
        sessions: Answer,
        checkpoint: Result<CheckpointOutcome, AgentError>,
    }

    impl Scripted {
        fn new(quiesce: Script) -> Self {
            Self {
                quiesce,
                gets: Mutex::new(0),
                calls: Mutex::new(Vec::new()),
                runs: Ok((200, json!({ "runs": [] }))),
                sessions: Ok((200, json!({ "tmux": true, "sessions": [] }))),
                checkpoint: Ok(CheckpointOutcome::default()),
            }
        }
    }

    impl BoxAgent for Scripted {
        fn metrics_now(&self, _: &BoxRecord, _: u64) -> Result<MetricsSample, AgentError> {
            Err(AgentError::Unsupported("x".into()))
        }
        fn metrics_series(
            &self,
            _: &BoxRecord,
            _: u64,
            _: u64,
            _: u64,
        ) -> Result<Vec<MetricsSample>, AgentError> {
            Ok(vec![])
        }
        fn selftest(&self, _: &BoxRecord, _: u64) -> Result<SelfTest, AgentError> {
            Err(AgentError::Unsupported("x".into()))
        }
        fn incidents(&self, _: &BoxRecord, _: u64, _: u64) -> Result<Vec<Incident>, AgentError> {
            Ok(vec![])
        }
        fn checkpoint(&self, _: &BoxRecord) -> Result<CheckpointOutcome, AgentError> {
            self.calls.lock().unwrap().push("checkpoint".into());
            self.checkpoint.clone()
        }
        fn runs(&self, _: &BoxRecord, _: &str, _: &str, _: &[u8]) -> Answer {
            self.runs.clone()
        }
        fn agent_call(&self, _: &BoxRecord, _: &str, _: &str, _: &[u8]) -> Answer {
            self.sessions.clone()
        }
        fn quiesce_call(&self, _: &BoxRecord, method: &str, _: &[u8]) -> Answer {
            self.calls.lock().unwrap().push(method.into());
            let mut g = self.gets.lock().unwrap();
            if method == "GET" {
                *g += 1;
            }
            (self.quiesce)(method, *g)
        }
    }

    struct FakePace(Cell<u64>);
    impl Pace for FakePace {
        fn sleep(&self, d: Duration) {
            self.0.set(self.0.get() + d.as_secs());
        }
        fn waited(&self) -> Duration {
            Duration::from_secs(self.0.get())
        }
    }

    fn rec_and_plan(dir: &std::path::Path, op_size: Size) -> (BoxRecord, Plan) {
        let p = ozbox_provider_fake::open(dir);
        let n = BoxName::new("main").unwrap();
        p.apply(
            &p.plan(&Operation::Create {
                spec: BoxSpec::new(n.clone(), Size::S),
            })
            .unwrap(),
        )
        .unwrap();
        let rec = p.get(&n).unwrap().unwrap();
        let plan = p
            .plan(&Operation::Resize {
                name: n,
                size: Some(op_size),
                work_disk_gb: None,
            })
            .unwrap();
        (rec, plan)
    }

    fn strict() -> Mode {
        Mode {
            strict: true,
            ..Mode::default()
        }
    }

    fn done_report(report: Value) -> Value {
        json!({ "state": "done", "job": 3, "report": report })
    }

    fn finishing(report: Value) -> Script {
        Box::new(move |m, gets| match (m, gets) {
            ("POST", _) => Ok((202, json!({ "state": "running", "job": 3 }))),
            ("GET", 1 | 2) => Ok((200, json!({ "state": "running", "job": 3 }))),
            ("GET", _) => Ok((200, done_report(report.clone()))),
            _ => Ok((200, json!({}))),
        })
    }

    fn rec() -> BoxRecord {
        let d = tempfile::tempdir().unwrap();
        rec_and_plan(d.path(), Size::M).0
    }

    #[test]
    fn only_a_plan_that_stops_a_running_machine_is_quiesced() {
        let d = tempfile::tempdir().unwrap();
        let (rec, plan) = rec_and_plan(d.path(), Size::M);
        assert!(plan.changes.iter().any(|c| c.kind == "instance.stop"));
        assert!(needed(&plan, &rec));
        let mut stopped = rec.clone();
        stopped.state = BoxState::Paused;
        assert!(!needed(&plan, &stopped), "a stopped box has nothing to end");
        let mut relabel = plan.clone();
        relabel.changes.retain(|c| c.kind != "instance.stop");
        assert!(
            !needed(&relabel, &rec),
            "a change that stops nothing asks nothing"
        );
    }

    #[test]
    fn text_from_a_box_cannot_move_the_cursor_or_run_long() {
        assert_eq!(clean("a\u{1b}[31mb\nc", 50), "a?[31mb?c");
        assert_eq!(clean(&"x".repeat(100), 10), "xxxxxxxxxx...");
        // characters that print as nothing or reorder text cannot hide a program's name
        assert_eq!(
            clean("a\u{202E}b\u{200B}c\u{2066}d\u{FEFF}e", 50),
            "a?b?c?d?e"
        );
    }

    #[test]
    fn a_value_with_a_placeholder_in_it_is_not_filled_in_by_a_later_argument() {
        let out = crate::messages::t(
            "quiesce.saved",
            &[
                ("repo", "{ref}"),
                ("ref", "refs/ozbox/wip/20261109T123456Z"),
            ],
        );
        assert!(
            out.contains("in {ref} as refs/ozbox/wip/20261109T123456Z"),
            "{out}"
        );
    }

    #[test]
    fn the_warning_lists_what_ends_and_never_calls_an_unanswered_box_empty() {
        let mut a = Scripted::new(Box::new(|_, _| Ok((200, json!({})))));
        a.runs = Ok((
            200,
            json!({ "runs": [
                { "state": "running", "program": "build\u{1b}[2J" },
                { "state": "queued", "program": "test" },
                { "state": "exited", "program": "old" }
            ]}),
        ));
        a.sessions = Ok((
            200,
            json!({ "sessions": [{ "engine": "claude-code" }, { "engine": "codex" }, { "engine": "claude-code" }] }),
        ));
        let text = preview(&a, &rec()).notes("main").join("\n");
        assert!(
            text.contains("Sessions come back; running programs end."),
            "{text}"
        );
        assert!(
            text.contains("2 supervised run(s): build?[2J, test"),
            "{text}"
        );
        assert!(
            text.contains("3 coding-agent session(s): 2 Claude Code"),
            "{text}"
        );
        assert!(!text.contains('\u{1b}'));
        assert!(text.contains("nothing is pushed"));
        assert!(text.contains("including the home folder and nested repositories"));
        assert!(text.contains("meant to reopen"), "Preview: {text}");

        let mut a = Scripted::new(Box::new(|_, _| {
            Err(AgentError::Unreachable("no route".into()))
        }));
        a.runs = Err(AgentError::Unreachable("no route".into()));
        a.sessions = Err(AgentError::Unreachable("no route".into()));
        let text = preview(&a, &rec()).notes("main").join("\n");
        assert!(text.contains("could not list them (no route)"), "{text}");
        assert!(!text.contains("no supervised runs") && !text.contains("no coding-agent sessions"));
        assert!(
            !text.contains("Sessions come back;"),
            "no promise from a box that was not asked"
        );

        let a = Scripted::new(Box::new(|_, _| Ok((404, json!({ "error": "not found" })))));
        let text = preview(&a, &rec()).notes("main").join("\n");
        assert!(text.contains("may not bring sessions back"), "{text}");
        // an older agent does not get the promise of the new one, and the path that can push is named
        assert!(!text.contains("nothing is pushed"), "{text}");
        assert!(
            text.contains("NOT snapshotted") && text.contains("NOT asked to end"),
            "{text}"
        );
        assert!(text.contains("--legacy-checkpoint"));
        assert!(
            text.contains("pushes it if that box has a push remote"),
            "{text}"
        );
        // a 503 is not "older": the box could not start the service
        let a = Scripted::new(Box::new(|_, _| {
            Ok((503, json!({ "code": "quiesce_unavailable" })))
        }));
        let text = preview(&a, &rec()).notes("main").join("\n");
        assert!(
            !text.contains("nothing is pushed") && !text.contains("is older"),
            "{text}"
        );
        assert!(text.contains("may NOT be snapshotted"), "{text}");
    }

    #[test]
    fn a_finished_quiesce_reports_each_run_and_where_the_work_was_saved() {
        let report = json!({
            "runs": { "runs": [
                { "program": "dev-server", "how": "ended" },
                { "program": "stuck\u{1b}]0;x\u{7}", "how": "killed" },
                { "program": "q", "how": "cancelled" }
            ], "not_stopped": 0 },
            "checkpoint": { "repos_scanned": 2, "errors": [],
                "branches": [
                    { "repo": "web", "branch": "refs/ozbox/wip/20261109T123456Z" },
                    { "repo": "api", "branch": "refs/heads/main; rm -rf /" }
                ] }
        });
        let a = Scripted::new(finishing(report));
        let q = perform(
            &a,
            &rec(),
            &Opts::command(strict()),
            &FakePace(Cell::new(0)),
        );
        assert_eq!(q.step.outcome, StepOutcome::Done);
        assert!(q.proceed);
        let d = &q.step.detail;
        assert!(d.contains("run dev-server: ended when asked"), "{d}");
        assert!(
            d.contains("did not end within the wait and was stopped"),
            "{d}"
        );
        assert!(d.contains("run q: was queued and was cancelled"), "{d}");
        assert!(
            d.contains("saved uncommitted work in web as refs/ozbox/wip/20261109T123456Z"),
            "{d}"
        );
        assert!(
            d.contains("in api as a snapshot"),
            "a ref that is not ours is never printed: {d}"
        );
        assert!(
            !d.contains("rm -rf") && !d.contains('\u{1b}') && !d.contains('\u{7}'),
            "{d}"
        );
        // the documented restore never overwrites newer work, and warns about the one that does
        assert!(
            d.contains("git archive <ref> | tar -x -C ../recovered"),
            "{d}"
        );
        assert!(d.contains("without touching newer work"), "{d}");
        assert!(d.contains("replaces every file the snapshot holds"), "{d}");
        assert!(!d.contains("--worktree"), "{d}");
        assert!(q.touched == Touched::Yes && !q.reconfirm);
    }

    #[test]
    fn a_snapshot_that_failed_is_reported_and_only_strict_stops_the_change() {
        let report = json!({
            "runs": { "runs": [], "not_stopped": 1 },
            "checkpoint": { "repos_scanned": 1, "branches": [], "errors": ["web: git add failed"] }
        });
        let a = Scripted::new(finishing(report.clone()));
        let q = perform(
            &a,
            &rec(),
            &Opts::command(Mode::default()),
            &FakePace(Cell::new(0)),
        );
        assert_eq!(q.step.outcome, StepOutcome::Failed);
        assert!(q.proceed, "reported, not fatal");
        assert!(q
            .step
            .detail
            .contains("could not save: web: git add failed"));
        assert!(q.step.detail.contains("1 run(s) could not be stopped"));
        let a = Scripted::new(finishing(report));
        let q = perform(
            &a,
            &rec(),
            &Opts::command(strict()),
            &FakePace(Cell::new(0)),
        );
        assert!(!q.proceed, "strict refuses to go on");
    }

    #[test]
    fn a_box_that_cannot_be_asked_is_said_so_and_asks_nothing_more() {
        let a = Scripted::new(Box::new(|_, _| {
            Err(AgentError::Unreachable("no route".into()))
        }));
        let q = perform(
            &a,
            &rec(),
            &Opts::command(Mode::default()),
            &FakePace(Cell::new(0)),
        );
        assert_eq!(q.step.outcome, StepOutcome::Skipped);
        assert!(q.step.detail.contains("was not snapshotted") && q.proceed);
        let q = perform(
            &a,
            &rec(),
            &Opts::command(strict()),
            &FakePace(Cell::new(0)),
        );
        assert!(!q.proceed);
        assert_eq!(
            a.calls
                .lock()
                .unwrap()
                .iter()
                .filter(|c| *c == "GET")
                .count(),
            0
        );
    }

    #[test]
    fn an_older_agent_is_never_sent_to_the_pushing_checkpoint_by_itself() {
        let a = Scripted::new(Box::new(|_, _| Ok((404, json!({ "error": "not found" })))));
        let q = perform(
            &a,
            &rec(),
            &Opts::command(Mode::default()),
            &FakePace(Cell::new(0)),
        );
        let d = &q.step.detail;
        assert!(d.contains("older than this program"), "{d}");
        assert!(
            d.contains("NOT snapshotted") && d.contains("NOT asked to end"),
            "{d}"
        );
        assert!(!d.contains("nothing is pushed"), "{d}");
        assert!(
            !a.calls.lock().unwrap().contains(&"checkpoint".to_string()),
            "the pushing checkpoint was not called"
        );
        assert!(
            q.proceed && q.reconfirm && q.older,
            "go on only if asked again"
        );
        // strict refuses it, and still does not call the checkpoint
        let q = perform(
            &a,
            &rec(),
            &Opts::command(strict()),
            &FakePace(Cell::new(0)),
        );
        assert!(!q.proceed);
        assert!(!a.calls.lock().unwrap().contains(&"checkpoint".to_string()));
    }

    #[test]
    fn the_older_checkpoint_is_used_only_behind_its_own_flag_and_says_what_it_does() {
        let a = Scripted::new(Box::new(|_, _| Ok((405, json!({})))));
        let mode = Mode {
            legacy: true,
            ..Mode::default()
        };
        let q = perform(&a, &rec(), &Opts::command(mode), &FakePace(Cell::new(0)));
        assert!(a.calls.lock().unwrap().contains(&"checkpoint".to_string()));
        let d = &q.step.detail;
        assert!(
            d.contains("visible branch") && d.contains("pushes it if that box has a push remote"),
            "{d}"
        );
        assert!(d.contains("Runs were not asked to end"), "{d}");
        assert!(!d.contains("nothing is pushed"), "{d}");
        assert!(q.proceed && !q.reconfirm, "the person asked for it by name");
        // never together with strict: a legacy box cannot ask runs to end
        let a = Scripted::new(Box::new(|_, _| Ok((404, json!({})))));
        let mode = Mode {
            strict: true,
            legacy: true,
            ..Mode::default()
        };
        let q = perform(&a, &rec(), &Opts::command(mode), &FakePace(Cell::new(0)));
        assert!(!q.proceed);
        assert!(!a.calls.lock().unwrap().contains(&"checkpoint".to_string()));
    }

    #[test]
    fn an_older_agent_needs_a_named_choice_and_no_checkpoint_is_never_asked_again() {
        // no choice: refused, naming both flags
        let e = older_choice(&Service::Older, Mode::default(), "main").unwrap_err();
        assert!(
            e.contains("--legacy-checkpoint") && e.contains("--no-checkpoint"),
            "{e}"
        );
        assert!(
            e.contains("PUSHES") && e.contains("Nothing was changed"),
            "{e}"
        );
        // each named choice is said in the plan
        let legacy = Mode {
            legacy: true,
            ..Mode::default()
        };
        assert!(older_choice(&Service::Older, legacy, "main")
            .unwrap()
            .unwrap()
            .contains("visible branch"));
        let none = Mode {
            none: true,
            ..Mode::default()
        };
        assert!(older_choice(&Service::Older, none, "main")
            .unwrap()
            .unwrap()
            .contains("NOT snapshotted"));
        // a current agent, an unknown one and strict (which refuses an older box itself) ask for nothing
        assert_eq!(
            older_choice(&Service::Available, Mode::default(), "main"),
            Ok(None)
        );
        assert_eq!(
            older_choice(&Service::Unknown("x".into()), Mode::default(), "main"),
            Ok(None)
        );
        assert_eq!(older_choice(&Service::Older, strict(), "main"), Ok(None));
        // --no-checkpoint at apply: no checkpoint, no POST of anything else, and no second question
        let a = Scripted::new(Box::new(|_, _| Ok((404, json!({})))));
        let q = perform(&a, &rec(), &Opts::command(none), &FakePace(Cell::new(0)));
        assert!(q.proceed && !q.reconfirm && q.older);
        assert_eq!(q.step.outcome, StepOutcome::Skipped);
        assert!(
            q.step.detail.contains("--no-checkpoint"),
            "{}",
            q.step.detail
        );
        assert!(!a.calls.lock().unwrap().contains(&"checkpoint".to_string()));
    }

    #[test]
    fn a_503_is_a_failure_to_start_not_an_older_agent_and_never_falls_back() {
        let a = Scripted::new(Box::new(|_, _| {
            Ok((503, json!({ "code": "quiesce_unavailable" })))
        }));
        let q = perform(
            &a,
            &rec(),
            &Opts::command(Mode::default()),
            &FakePace(Cell::new(0)),
        );
        let d = &q.step.detail;
        assert!(d.contains("could not start getting ready"), "{d}");
        assert!(
            d.contains("NOT snapshotted") && d.contains("NOT asked to end"),
            "{d}"
        );
        assert!(!a.calls.lock().unwrap().contains(&"checkpoint".to_string()));
        assert!(q.proceed && q.reconfirm && !q.older);
        let q = perform(
            &a,
            &rec(),
            &Opts::command(strict()),
            &FakePace(Cell::new(0)),
        );
        assert!(!q.proceed);
        // a legacy flag does not turn a 503 into the legacy path either
        let mode = Mode {
            legacy: true,
            ..Mode::default()
        };
        perform(&a, &rec(), &Opts::command(mode), &FakePace(Cell::new(0)));
        assert!(!a.calls.lock().unwrap().contains(&"checkpoint".to_string()));
    }

    #[test]
    fn a_strict_refusal_says_what_already_happened() {
        let untouched = strict_refusal("main", Touched::No);
        assert!(
            untouched.contains("no run was ended") && untouched.contains("new runs are allowed"),
            "{untouched}"
        );
        let touched = strict_refusal("main", Touched::Yes);
        assert!(
            touched.contains("have already ended or been cancelled"),
            "{touched}"
        );
        assert!(touched.contains("new runs are allowed again"));
        let maybe = strict_refusal("main", Touched::Maybe);
        assert!(
            maybe.contains("may already have ended some runs"),
            "{maybe}"
        );
        for m in [&untouched, &touched, &maybe] {
            assert!(!m.contains("Nothing was changed"), "{m}");
        }
    }

    #[test]
    fn a_strict_report_that_stopped_before_touching_a_run_says_so() {
        let report = json!({
            "runs": { "runs": [], "not_stopped": 0 },
            "runs_untouched": true,
            "checkpoint": { "repos_scanned": 1, "branches": [], "errors": ["web: git add failed"] }
        });
        let a = Scripted::new(finishing(report));
        let q = perform(
            &a,
            &rec(),
            &Opts::command(strict()),
            &FakePace(Cell::new(0)),
        );
        assert!(!q.proceed);
        assert_eq!(q.touched, Touched::No);
        // and the strict flag reaches the box
        assert!(a.calls.lock().unwrap().contains(&"POST".to_string()));
    }

    #[test]
    fn a_killed_run_is_a_clean_outcome_but_one_still_exiting_or_unstoppable_is_not() {
        let killed = json!({
            "runs": { "runs": [{ "program": "stuck", "how": "killed" }], "not_stopped": 0 },
            "checkpoint": { "repos_scanned": 0, "branches": [], "errors": [] }
        });
        let q = perform(
            &Scripted::new(finishing(killed)),
            &rec(),
            &Opts::command(strict()),
            &FakePace(Cell::new(0)),
        );
        assert!(q.proceed && !q.reconfirm, "killing is the designed outcome");
        let exiting = json!({
            "runs": { "runs": [
                { "program": "slow", "how": "exiting" },
                { "program": "bad", "how": "not_stopped" }
            ], "not_stopped": 2 },
            "checkpoint": { "repos_scanned": 0, "branches": [], "errors": [] }
        });
        let q = perform(
            &Scripted::new(finishing(exiting)),
            &rec(),
            &Opts::command(strict()),
            &FakePace(Cell::new(0)),
        );
        assert!(!q.proceed);
        let d = &q.step.detail;
        assert!(
            d.contains("run slow: was stopped and had not finished exiting"),
            "{d}"
        );
        assert!(d.contains("run bad: could not be stopped"), "{d}");
        assert!(
            !d.contains("2 run(s) could not be stopped"),
            "named runs are not counted twice: {d}"
        );
    }

    #[test]
    fn the_wait_is_at_least_the_boxes_own_bound_plus_a_margin() {
        // the box says a job can take 300 s; the command's own default would have given up at 178
        let a = Scripted::new(Box::new(|m, _| match m {
            "POST" => Ok((202, json!({ "state": "running", "job": 3, "bound_s": 300 }))),
            _ => Ok((200, json!({ "state": "running", "job": 3, "bound_s": 300 }))),
        }));
        let pace = FakePace(Cell::new(0));
        let q = perform(&a, &rec(), &Opts::command(Mode::default()), &pace);
        assert!(
            q.step
                .detail
                .contains("did not finish getting ready within 330 seconds"),
            "{}",
            q.step.detail
        );
        assert!(pace.0.get() >= 330);
        let o = Opts::command(Mode::default());
        assert!(
            o.max_wait_s >= GRACE_S + 137 + 30,
            "covers the daemon's own worst case"
        );
        assert_eq!(Opts::dashboard().max_wait_s, o.max_wait_s);
    }

    #[test]
    fn the_hold_is_lifted_unless_the_change_was_applied() {
        let a = Scripted::new(Box::new(|_, _| Ok((200, json!({})))));
        {
            let r = rec();
            let _h = Hold::new(&a, &r);
        }
        assert_eq!(
            a.calls.lock().unwrap().as_slice(),
            ["DELETE"],
            "dropped: a refusal, a no, a failed apply"
        );
        let a = Scripted::new(Box::new(|_, _| Ok((200, json!({})))));
        {
            let r = rec();
            let mut h = Hold::new(&a, &r);
            h.disarm();
        }
        assert!(
            a.calls.lock().unwrap().is_empty(),
            "applied: nothing to lift"
        );
    }

    #[test]
    fn a_second_request_refused_as_too_soon_is_said_with_the_wait() {
        let a = Scripted::new(Box::new(|_, _| {
            Ok((
                429,
                json!({ "code": "quiesce_too_soon", "retry_after_s": 12 }),
            ))
        }));
        let q = perform(
            &a,
            &rec(),
            &Opts::command(Mode::default()),
            &FakePace(Cell::new(0)),
        );
        assert!(
            q.step.detail.contains("try again in 12 seconds"),
            "{}",
            q.step.detail
        );
        assert!(q.reconfirm);
    }

    #[test]
    fn waiting_is_bounded_and_lost_contact_or_another_request_is_not_a_pass() {
        // never finishes
        let a = Scripted::new(Box::new(|m, _| match m {
            "POST" => Ok((202, json!({ "state": "running", "job": 3 }))),
            _ => Ok((200, json!({ "state": "running", "job": 3 }))),
        }));
        let pace = FakePace(Cell::new(0));
        let q = perform(
            &a,
            &rec(),
            &Opts {
                mode: strict(),
                grace_s: 10,
                max_wait_s: 30,
            },
            &pace,
        );
        assert!(q
            .step
            .detail
            .contains("did not finish getting ready within 30 seconds"));
        assert!(!q.proceed);
        assert!(pace.0.get() <= 31, "slept no longer than the bound");
        // contact lost
        let a = Scripted::new(Box::new(|m, _| match m {
            "POST" => Ok((202, json!({ "state": "running", "job": 3 }))),
            _ => Err(AgentError::Unreachable("gone".into())),
        }));
        let pace = FakePace(Cell::new(0));
        let q = perform(&a, &rec(), &Opts::command(Mode::default()), &pace);
        assert!(q.step.detail.contains("Lost contact"));
        assert!(
            pace.0.get() >= WAIT_MARGIN_S,
            "it kept asking until the time the job may take had passed, not three tries: {}",
            pace.0.get()
        );
        // a few dropped polls in the middle of a job are not the end of it
        let a = Scripted::new(Box::new(|m, n| match (m, n) {
            ("POST", _) => Ok((202, json!({ "state": "running", "job": 3, "bound_s": 100 }))),
            (_, 1..=5) => Err(AgentError::Unreachable("blip".into())),
            _ => Ok((
                200,
                json!({ "state": "done", "job": 3, "report": {
                    "runs": { "runs": [], "not_stopped": 0 },
                    "checkpoint": { "repos_scanned": 0, "branches": [], "errors": [] } } }),
            )),
        }));
        let q = perform(
            &a,
            &rec(),
            &Opts::command(strict()),
            &FakePace(Cell::new(0)),
        );
        assert!(q.proceed && !q.reconfirm, "{}", q.step.detail);
        // a different job or an idle daemon: someone ended it
        let a = Scripted::new(Box::new(|m, _| match m {
            "POST" => Ok((202, json!({ "state": "running", "job": 3 }))),
            _ => Ok((200, json!({ "state": "idle", "job": 4 }))),
        }));
        let q = perform(
            &a,
            &rec(),
            &Opts::command(strict()),
            &FakePace(Cell::new(0)),
        );
        assert!(q.step.detail.contains("ended by another request") && !q.proceed);
        // a refusal
        let a = Scripted::new(Box::new(|_, _| Ok((500, json!({})))));
        let q = perform(
            &a,
            &rec(),
            &Opts::command(strict()),
            &FakePace(Cell::new(0)),
        );
        assert!(q.step.detail.contains("refused (status 500)") && !q.proceed);
    }

    #[test]
    fn an_interrupt_during_the_wait_or_the_question_lifts_the_hold_before_the_process_exits() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let a = Scripted::new(Box::new(|_, _| Ok((200, json!({})))));
        let (hit, done) = (AtomicBool::new(false), AtomicBool::new(false));
        let exited = AtomicBool::new(false);
        let out = watch_interrupt(
            &a,
            &rec(),
            &hit,
            &done,
            &|| exited.store(true, Ordering::SeqCst),
            || {
                hit.store(true, Ordering::SeqCst); // Ctrl-C while the command waits
                let until = std::time::Instant::now() + Duration::from_secs(5);
                while !exited.load(Ordering::SeqCst) && std::time::Instant::now() < until {
                    std::thread::sleep(Duration::from_millis(10));
                }
                7
            },
        );
        assert_eq!(out, 7);
        assert!(exited.load(Ordering::SeqCst), "the process was ended");
        assert_eq!(
            a.calls.lock().unwrap().as_slice(),
            ["DELETE"],
            "after lifting the hold"
        );
        // no interrupt: the body's value comes back and nothing is sent
        let a = Scripted::new(Box::new(|_, _| Ok((200, json!({})))));
        let (hit, done) = (AtomicBool::new(false), AtomicBool::new(false));
        let out = watch_interrupt(&a, &rec(), &hit, &done, &|| panic!("no exit"), || 1);
        assert_eq!(out, 1);
        assert!(a.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn what_the_snapshot_left_out_by_design_is_told_and_is_not_a_failure() {
        let a = Scripted::new(Box::new(|m, _| match m {
            "POST" => Ok((202, json!({ "state": "running", "job": 3 }))),
            _ => Ok((
                200,
                json!({ "state": "done", "job": 3, "report": {
                "runs": { "runs": [], "not_stopped": 0 },
                "checkpoint": { "repos_scanned": 2, "branches": [], "errors": [],
                    "skipped": ["home/ozbox: not saved: home/dotfiles repo"] } } }),
            )),
        }));
        let q = perform(
            &a,
            &rec(),
            &Opts::command(strict()),
            &FakePace(Cell::new(0)),
        );
        assert!(
            q.step.detail.contains("not saved: home/dotfiles repo"),
            "{}",
            q.step.detail
        );
        assert!(
            q.proceed,
            "a choice the snapshot makes by design does not refuse a strict stop"
        );
        assert!(!q.step.detail.contains("no uncommitted work to save"));
    }

    #[test]
    fn release_sends_a_delete_and_ignores_every_answer() {
        let a = Scripted::new(Box::new(|_, _| {
            Err(AgentError::Unreachable("stopped".into()))
        }));
        release(&a, &rec());
        assert_eq!(a.calls.lock().unwrap().as_slice(), ["DELETE"]);
    }
}
