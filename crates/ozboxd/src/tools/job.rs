//! A tool job: the plan's steps run in order as the box user, with root-class steps handed to the privileged helper one
//! at a time. The job writes its own status file after every step, so the daemon (and the dashboard) can show progress
//! and a daemon restart loses nothing.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use ozbox_catalog::{Catalog, Op, Plan, PlanRequest, Privilege};
use serde::{Deserialize, Serialize};

use super::exec::{run_root_action, run_user_action, Ctx, RootPaths};
use super::sys::{Log, Sys};

pub const LOG_CAP: u64 = 2 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobSpec {
    pub id: String,
    /// Who asked: `owner`, `agent:<label>` (after the owner approved) or `approval`.
    pub requested_by: String,
    pub request: PlanRequest,
    /// What was installed when the plan was made (the privileged helper re-plans from the same input).
    pub installed: Vec<String>,
    pub plan: Plan,
    pub created_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepState {
    Pending,
    Running,
    Ok,
    Failed,
    /// Not run: its tool already failed, or a tool it needs did.
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepStatus {
    pub index: usize,
    pub title: String,
    pub state: StepState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Queued,
    Running,
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobStatus {
    pub id: String,
    pub state: JobState,
    pub steps: Vec<StepStatus>,
    pub error: Option<String>,
    pub started_ms: Option<u64>,
    pub ended_ms: Option<u64>,
    /// How each tool in the plan ended, once the job has. A tool that fails does not stop the others: only the tools that
    /// need it are skipped. A status written before this field existed has none.
    #[serde(default)]
    pub outcomes: Vec<ToolOutcome>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeState {
    Ok,
    Failed,
    /// Not tried, because a tool it needs failed.
    Skipped,
}

/// How one tool of a job ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolOutcome {
    pub id: String,
    pub state: OutcomeState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl JobStatus {
    pub fn queued(spec: &JobSpec) -> JobStatus {
        JobStatus {
            id: spec.id.clone(),
            state: JobState::Queued,
            steps: spec
                .plan
                .steps
                .iter()
                .map(|s| StepStatus {
                    index: s.index,
                    title: s.title.clone(),
                    state: StepState::Pending,
                })
                .collect(),
            error: None,
            started_ms: None,
            ended_ms: None,
            outcomes: Vec::new(),
        }
    }
}

/// The first tool in `failed` that `tool` is, or needs (directly or through another tool). `None` when nothing it rests on
/// has failed.
fn blocked_by(catalog: &Catalog, tool: &str, failed: &BTreeMap<String, String>) -> Option<String> {
    let mut seen = BTreeSet::new();
    let mut todo = vec![tool.to_string()];
    while let Some(t) = todo.pop() {
        if failed.contains_key(&t) {
            return Some(t);
        }
        if !seen.insert(t.clone()) {
            continue;
        }
        if let Some(c) = catalog.tool(&t) {
            todo.extend(c.requires.iter().cloned());
        }
    }
    None
}

/// The privileged helper, as the job sees it.
pub trait RootBridge: Send + Sync {
    fn run_step(&self, spec: &JobSpec, index: usize, log: &Log) -> Result<(), String>;
}

pub fn job_dir(state: &Path, id: &str) -> PathBuf {
    state.join("jobs").join(id)
}

pub fn is_job_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 32
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

pub fn write_json(path: &Path, v: &impl Serialize) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec(v).unwrap_or_default())?;
    std::fs::rename(&tmp, path)
}

/// One line per event, appended: who did what to which tools, and how it ended. Ids and outcomes only.
pub fn audit(
    path: &Path,
    ts_ms: u64,
    event: &str,
    actor: &str,
    tools: &[String],
    job: &str,
    outcome: &str,
) {
    use std::io::Write;
    let line = serde_json::json!({
        "ts_ms": ts_ms, "event": event, "actor": actor, "tools": tools, "job": job, "outcome": outcome
    });
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(f, "{line}");
    }
}

/// Where a program is, looked for in the directories a login shell of the box user would use.
pub fn find_bin(sys: &dyn Sys, bin: &str, home: &Path) -> Option<PathBuf> {
    [
        home.join(".local/bin"),
        home.join(".cargo/bin"),
        PathBuf::from("/usr/local/bin"),
        PathBuf::from("/usr/bin"),
        PathBuf::from("/bin"),
    ]
    .into_iter()
    .map(|d| d.join(bin))
    .find(|p| sys.is_executable(p))
}

/// Run a job to the end. Returns the final status (also written to `status.json`).
pub fn run_job(
    dir: &Path,
    catalog: &Catalog,
    sys: &dyn Sys,
    bridge: &dyn RootBridge,
    home: &Path,
    now_ms: &dyn Fn() -> u64,
) -> Result<JobStatus, String> {
    let spec: JobSpec = serde_json::from_slice(
        &std::fs::read(dir.join("job.json"))
            .map_err(|e| format!("cannot read the job: {}", e.kind()))?,
    )
    .map_err(|_| "the job file is not understood".to_string())?;
    let log = Log::open(&dir.join("log"), LOG_CAP)
        .map_err(|e| format!("cannot open the log: {}", e.kind()))?;
    let status_path = dir.join("status.json");
    let audit_path = dir
        .parent()
        .and_then(Path::parent)
        .map(|p| p.join("audit.jsonl"))
        .unwrap_or_else(|| dir.join("audit.jsonl"));
    let ids: Vec<String> = spec.plan.tools.iter().map(|t| t.id.clone()).collect();

    let mut st = JobStatus::queued(&spec);
    st.state = JobState::Running;
    st.started_ms = Some(now_ms());
    let _ = write_json(&status_path, &st);
    log.line(&format!("job {} started", spec.id));

    let tmp = dir.join("tmp");
    let ctx = Ctx {
        sys,
        log: &log,
        home: home.to_path_buf(),
        tmp: tmp.clone(),
        root: RootPaths::default(),
    };
    // A tool whose step fails is recorded and the job goes on with the tools that do not need it, so one vendor's broken
    // package source does not leave every other requested tool uninstalled. Each failure is reported at the end.
    let mut failed: BTreeMap<String, String> = BTreeMap::new();
    for step in &spec.plan.steps {
        if let Some(cause) = blocked_by(catalog, &step.tool, &failed) {
            st.steps[step.index].state = StepState::Skipped;
            log.line(&format!(
                "step {}/{}: {} (skipped: {cause} failed)",
                step.index + 1,
                spec.plan.steps.len(),
                step.title
            ));
            let _ = write_json(&status_path, &st);
            continue;
        }
        let _ = sys.remove_path(&tmp);
        let _ = sys.create_dir_all(&tmp);
        st.steps[step.index].state = StepState::Running;
        let _ = write_json(&status_path, &st);
        log.line(&format!(
            "step {}/{}: {}",
            step.index + 1,
            spec.plan.steps.len(),
            step.title
        ));
        let result = match step.privilege {
            Privilege::Root => bridge.run_step(&spec, step.index, &log),
            Privilege::User => run_user_action(&ctx, &step.action),
        };
        match result {
            Ok(()) => st.steps[step.index].state = StepState::Ok,
            Err(e) => {
                st.steps[step.index].state = StepState::Failed;
                log.line(&format!("failed: {e}"));
                failed.insert(step.tool.clone(), format!("{}: {e}", step.title));
            }
        }
        let _ = write_json(&status_path, &st);
    }
    let _ = sys.remove_path(&tmp);

    // Prove it: every tool that was installed must now be found.
    let mut unverified: BTreeMap<String, String> = BTreeMap::new();
    for t in spec.plan.tools.iter().filter(|t| t.op == Op::Install) {
        if blocked_by(catalog, &t.id, &failed).is_some() {
            continue;
        }
        let Some(d) = catalog.tool(&t.id).and_then(|c| c.detect.as_ref()) else {
            continue;
        };
        if find_bin(sys, &d.bin, home).is_none() {
            unverified.insert(
                t.id.clone(),
                format!("it was installed but {} cannot be found afterwards", d.bin),
            );
            log.line(&format!("verify failed: {}", d.bin));
            continue;
        }
        log.line(&format!("verified {}", t.id));
    }
    let mut problems = Vec::new();
    for t in &spec.plan.tools {
        let own = failed.get(&t.id).or_else(|| unverified.get(&t.id)).cloned();
        let (state, error) = match (own, blocked_by(catalog, &t.id, &failed)) {
            (Some(e), _) => (OutcomeState::Failed, Some(e)),
            (None, None) => (OutcomeState::Ok, None),
            (None, Some(c)) => (
                OutcomeState::Skipped,
                Some(format!("not tried, because {c} (which it needs) failed")),
            ),
        };
        if let Some(e) = &error {
            problems.push(format!("{}: {e}", t.name));
        }
        st.outcomes.push(ToolOutcome {
            id: t.id.clone(),
            state,
            error,
        });
    }
    let failure = (!problems.is_empty()).then(|| problems.join("; "));
    st.ended_ms = Some(now_ms());
    match &failure {
        None => {
            st.state = JobState::Succeeded;
            log.line("done");
        }
        Some(e) => {
            st.state = JobState::Failed;
            st.error = Some(e.clone());
        }
    }
    let _ = write_json(&status_path, &st);
    audit(
        &audit_path,
        now_ms(),
        "tools.job_finished",
        &spec.requested_by,
        &ids,
        &spec.id,
        if failure.is_none() {
            "succeeded"
        } else {
            "failed"
        },
    );
    Ok(st)
}

/// What the privileged helper does for one request: the plan is rebuilt from the catalog compiled into the helper and
/// the request names only a job, a step number and the plan it believes it is running. Anything else is refused.
pub fn run_root_step(
    catalog: &Catalog,
    arch: ozbox_catalog::Arch,
    req: &RootRequest,
    ctx: &Ctx,
) -> Result<(), String> {
    use std::collections::BTreeSet;
    if !is_job_id(&req.job) {
        return Err("bad job id".into());
    }
    let installed: BTreeSet<String> = req.installed.iter().cloned().collect();
    let plan = ozbox_catalog::plan::build_plan(catalog, arch, &installed, &req.request)
        .map_err(|e| e.to_string())?;
    if plan.hash != req.plan_hash {
        return Err("the plan changed since it was approved".into());
    }
    let step = plan.steps.get(req.index).ok_or("no such step")?;
    if step.privilege != Privilege::Root {
        return Err("that step does not run as root".into());
    }
    run_root_action(ctx, &step.action)
}

/// What the unprivileged job leaves for the helper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootRequest {
    pub job: String,
    pub index: usize,
    pub plan_hash: String,
    pub request: PlanRequest,
    pub installed: Vec<String>,
}
