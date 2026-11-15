//! The tool installer: a catalog of things a person can add to a box, planned first and then applied.
//!
//! * `GET /v1/tools` lists every tool with whether it is installed and which version.
//! * `POST /v1/tools/plan` turns a selection into a plan (what will run, how big) and changes nothing.
//! * `POST /v1/tools/apply` runs a plan as a job in its own capped cgroup, refusing a plan that has gone stale.
//! * `POST /v1/tools/requests` lets an agent ask for a tool; only the box owner can approve it.
//!
//! Package-manager steps are the only ones that need root; they go through a narrow helper (see [`root`]).
//! Everything else runs as the box user inside the job's cgroup, with a memory cap.

pub mod exec;
pub mod job;
pub mod root;
pub mod sys;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use ozbox_catalog::plan::build_plan;
use ozbox_catalog::verify::first_version;
use ozbox_catalog::{Arch, Catalog, Op, PlanError, PlanRequest, Verification};
use ozbox_core::{CommandRunner, CommandSpec};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::api::lock;
use crate::http::{Request, Response};
use crate::runs::{RunManager, RunRequest};
use crate::timeutil::Clock;
use job::{audit, is_job_id, job_dir, write_json, JobSpec, JobState, JobStatus};
use sys::Sys;

const MAX_REQUESTS: usize = 200;
const MAX_PENDING: usize = 50;
const MAX_JOBS_LISTED: usize = 20;
const LOG_TAIL_BYTES: u64 = 128 * 1024;
const LOG_TAIL_LINES: usize = 300;
/// A job whose process is gone and whose status never reached an end state is reported failed after this long.
const STALE_AFTER_MS: u64 = 30_000;

fn err(status: u16, code: &str, message: &str) -> Response {
    Response::json(
        status,
        &json!({ "code": code, "message": message, "error": message }),
    )
}

fn plan_err(e: &PlanError) -> Response {
    let status = match e {
        PlanError::Unknown(_) => 404,
        PlanError::StillRequired { .. } | PlanError::Conflict(_) => 409,
        PlanError::Empty => 400,
        PlanError::Unverified { .. } | PlanError::UnsupportedArch { .. } => 422,
    };
    err(status, e.code(), &e.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestState {
    Pending,
    Approved,
    Denied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolRequest {
    pub id: String,
    pub tool: String,
    pub reason: String,
    pub requested_by: String,
    pub created_ms: u64,
    pub state: RequestState,
    /// `once` or `always`, once approved.
    pub decision: Option<String>,
    pub job_id: Option<String>,
}

#[derive(Default)]
struct Inner {
    requests: Vec<ToolRequest>,
    always: BTreeSet<String>,
    active_job: Option<String>,
    counter: u64,
}

pub struct ToolsConfig {
    /// `<state_dir>/tools`
    pub state: PathBuf,
    pub home: PathBuf,
    /// The path of this daemon's binary, started as `<exe> tools-exec <job dir>` for each job.
    pub exe: PathBuf,
    pub job_memory_bytes: u64,
    pub arch: Arch,
}

pub struct ToolsService {
    cfg: ToolsConfig,
    catalog: Catalog,
    runs: Arc<Mutex<RunManager>>,
    sys: Arc<dyn Sys>,
    runner: Arc<dyn CommandRunner>,
    clock: Arc<dyn Clock>,
    inner: Mutex<Inner>,
}

static GLOBAL: OnceLock<Arc<ToolsService>> = OnceLock::new();

/// The daemon's installer, once started. The API routes `/v1/tools/...` to it.
pub fn global() -> Option<&'static Arc<ToolsService>> {
    GLOBAL.get()
}

pub fn install_global(s: Arc<ToolsService>) {
    let _ = GLOBAL.set(s);
}

fn clean(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max).collect()
}

fn label_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 40
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
}

impl ToolsService {
    pub fn new(
        cfg: ToolsConfig,
        catalog: Catalog,
        runs: Arc<Mutex<RunManager>>,
        sys: Arc<dyn Sys>,
        runner: Arc<dyn CommandRunner>,
        clock: Arc<dyn Clock>,
    ) -> ToolsService {
        let _ = std::fs::create_dir_all(cfg.state.join("jobs"));
        let always: BTreeSet<String> = std::fs::read(cfg.state.join("approvals.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let requests: Vec<ToolRequest> = std::fs::read(cfg.state.join("requests.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let counter = requests.len() as u64;
        ToolsService {
            cfg,
            catalog,
            runs,
            sys,
            runner,
            clock,
            inner: Mutex::new(Inner {
                requests,
                always,
                active_job: None,
                counter,
            }),
        }
    }

    fn audit_path(&self) -> PathBuf {
        self.cfg.state.join("audit.jsonl")
    }

    fn save(&self, inner: &Inner) {
        let _ = write_json(&self.cfg.state.join("requests.json"), &inner.requests);
        let _ = write_json(&self.cfg.state.join("approvals.json"), &inner.always);
    }

    // ---- what is on the box ----------------------------------------------------------------------------------

    /// Whether the tool's program is on the box (found, never run).
    fn present(&self, id: &str) -> bool {
        self.catalog
            .tool(id)
            .and_then(|t| t.detect.as_ref())
            .is_some_and(|d| job::find_bin(self.sys.as_ref(), &d.bin, &self.cfg.home).is_some())
    }

    fn detect(&self, id: &str) -> (bool, Option<String>) {
        let Some(d) = self.catalog.tool(id).and_then(|t| t.detect.as_ref()) else {
            return (false, None);
        };
        if !self.present(id) {
            return (false, None);
        }
        let version = if d.version_cmd.is_empty() {
            None
        } else {
            let mut spec = CommandSpec::new(d.version_cmd[0].clone());
            spec.args = d.version_cmd[1..].to_vec();
            spec = spec.env("PATH", exec::env_for(&self.cfg.home)[0].1.clone());
            self.runner
                .run(&spec)
                .ok()
                .and_then(|o| first_version(&format!("{}\n{}", o.stdout, o.stderr)))
        };
        (true, version)
    }

    fn installed_set(&self) -> BTreeSet<String> {
        self.catalog
            .tools
            .iter()
            .filter(|t| self.present(&t.id))
            .map(|t| t.id.clone())
            .collect()
    }

    // ---- routes -----------------------------------------------------------------------------------------------

    pub fn route(&self, req: &Request) -> Response {
        let path = req.path.trim_end_matches('/');
        let segs: Vec<&str> = path
            .trim_start_matches("/v1/tools")
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();
        let m = req.method.as_str();
        match (m, segs.as_slice()) {
            ("GET", []) => self.list(),
            ("POST", ["plan"]) => self.plan(&req.body),
            ("POST", ["apply"]) => self.apply(&req.body),
            ("GET", ["jobs"]) => self.jobs(),
            ("GET", ["jobs", id]) => self.job(id),
            ("GET", ["requests"]) => self.list_requests(),
            ("POST", ["requests"]) => self.new_request(&req.body),
            ("POST", ["requests", id, "decision"]) => self.decide(id, &req.body),
            ("GET", ["audit"]) => self.audit_log(),
            (_, [])
            | (_, ["plan"])
            | (_, ["apply"])
            | (_, ["jobs"])
            | (_, ["jobs", _])
            | (_, ["requests"])
            | (_, ["requests", _, "decision"])
            | (_, ["audit"]) => err(405, "method_not_allowed", "method not allowed"),
            _ => err(404, "not_found", "no such endpoint"),
        }
    }

    fn list(&self) -> Response {
        let active = {
            let a = lock(&self.inner).active_job.clone();
            a.filter(|id| self.status_of(id).is_some_and(|s| !is_end(s.state)))
        };
        let tools: Vec<Value> = self
            .catalog
            .tools
            .iter()
            .map(|t| {
                let (installed, version) = self.detect(&t.id);
                json!({
                    "id": t.id,
                    "installed": installed,
                    "version": version,
                    "managed_by_client": t.verification == Verification::ClientManaged,
                })
            })
            .collect();
        Response::json(
            200,
            &json!({
                "catalog_version": self.catalog.version,
                "arch": self.cfg.arch,
                "tools": tools,
                "active_job": active,
            }),
        )
    }

    /// Bundles and plain ids to a request; the catalog's own expansion.
    fn selection(&self, body: &[u8]) -> Result<PlanRequest, Response> {
        #[derive(Deserialize)]
        struct Sel {
            #[serde(default)]
            install: Vec<String>,
            #[serde(default)]
            remove: Vec<String>,
        }
        let sel: Sel = serde_json::from_slice(body).map_err(|_| {
            err(
                400,
                "bad_request",
                "the body must be JSON with install and/or remove lists",
            )
        })?;
        let ex = |v: &[String]| {
            self.catalog
                .expand(v)
                .map_err(|m| err(404, "unknown_tool", &m))
        };
        Ok(PlanRequest {
            install: ex(&sel.install)?,
            remove: ex(&sel.remove)?,
        })
    }

    fn plan(&self, body: &[u8]) -> Response {
        let req = match self.selection(body) {
            Ok(r) => r,
            Err(r) => return r,
        };
        match build_plan(&self.catalog, self.cfg.arch, &self.installed_set(), &req) {
            Ok(p) => Response::json(200, &json!({ "plan": p })),
            Err(e) => plan_err(&e),
        }
    }

    fn apply(&self, body: &[u8]) -> Response {
        let req = match self.selection(body) {
            Ok(r) => r,
            Err(r) => return r,
        };
        let hash = serde_json::from_slice::<Value>(body)
            .ok()
            .and_then(|v| v["plan_hash"].as_str().map(str::to_string));
        match self.start_job(&req, hash.as_deref(), "owner") {
            Ok(Some(id)) => Response::json(202, &json!({ "job_id": id })),
            Ok(None) => Response::json(200, &json!({ "job_id": null, "noop": true })),
            Err(r) => r,
        }
    }

    /// Plan, check, write the job and start it as a capped run. `None` = nothing to do.
    fn start_job(
        &self,
        req: &PlanRequest,
        expect_hash: Option<&str>,
        actor: &str,
    ) -> Result<Option<String>, Response> {
        let installed = self.installed_set();
        let plan =
            build_plan(&self.catalog, self.cfg.arch, &installed, req).map_err(|e| plan_err(&e))?;
        if let Some(h) = expect_hash {
            if h != plan.hash {
                return Err(err(
                    409,
                    "stale_plan",
                    "what is on the box changed since this plan was made; plan again",
                ));
            }
        } else if actor == "owner" {
            // The dashboard and CLI always send the hash of the plan the person saw.
            return Err(err(
                400,
                "bad_request",
                "apply needs the plan_hash of the plan that was shown",
            ));
        }
        if plan.is_noop() {
            return Ok(None);
        }
        let now = self.clock.now_ms();
        let id = {
            let mut inner = lock(&self.inner);
            if let Some(a) = inner.active_job.clone() {
                if self.status_of(&a).is_some_and(|s| !is_end(s.state)) {
                    return Err(err(409, "busy", "another tool job is still running"));
                }
            }
            inner.counter += 1;
            let id = format!("{now:x}{:x}", inner.counter);
            inner.active_job = Some(id.clone());
            id
        };
        let dir = job_dir(&self.cfg.state, &id);
        let spec = JobSpec {
            id: id.clone(),
            requested_by: actor.to_string(),
            request: req.clone(),
            installed: installed.into_iter().collect(),
            plan: plan.clone(),
            created_ms: now,
        };
        let fail = |m: &str| err(500, "internal", m);
        std::fs::create_dir_all(&dir).map_err(|_| fail("cannot create the job"))?;
        write_json(&dir.join("job.json"), &spec).map_err(|_| fail("cannot write the job"))?;
        write_json(&dir.join("status.json"), &JobStatus::queued(&spec))
            .map_err(|_| fail("cannot write the job"))?;
        let mut rr = RunRequest::new(vec![
            self.cfg.exe.display().to_string(),
            "tools-exec".into(),
            dir.display().to_string(),
        ]);
        rr.memory_request_bytes = self.cfg.job_memory_bytes / 2;
        rr.memory_max_bytes = Some(self.cfg.job_memory_bytes);
        rr.max_runtime_s = Some(3 * 3600);
        rr.labels
            .insert("ozbox.kind".into(), "tools-install".into());
        rr.labels.insert("ozbox.job".into(), id.clone());
        let started = lock(&self.runs).start(rr);
        match started {
            Ok((run_id, _)) => {
                let _ = write_json(&dir.join("run.json"), &json!({ "run_id": run_id }));
            }
            Err(e) => {
                lock(&self.inner).active_job = None;
                return Err(err(
                    503,
                    "cannot_start",
                    &format!("the job could not start: {e}"),
                ));
            }
        }
        let ids: Vec<String> = plan.tools.iter().map(|t| t.id.clone()).collect();
        let verb = if plan.tools.iter().any(|t| t.op == Op::Install) {
            "tools.install_started"
        } else {
            "tools.remove_started"
        };
        audit(&self.audit_path(), now, verb, actor, &ids, &id, "started");
        Ok(Some(id))
    }

    // ---- jobs ---------------------------------------------------------------------------------------------------

    fn status_of(&self, id: &str) -> Option<JobStatus> {
        if !is_job_id(id) {
            return None;
        }
        let dir = job_dir(&self.cfg.state, id);
        let mut st: JobStatus =
            serde_json::from_slice(&std::fs::read(dir.join("status.json")).ok()?).ok()?;
        if !is_end(st.state) {
            // The process is the truth: if its run has ended or vanished, the job did not finish.
            let run_id = std::fs::read(dir.join("run.json"))
                .ok()
                .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
                .and_then(|v| v["run_id"].as_str().map(str::to_string));
            let now = self.clock.now_ms();
            let created = std::fs::metadata(dir.join("job.json"))
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as u64)
                .unwrap_or(now);
            let gone = match run_id {
                Some(r) => match lock(&self.runs).list().into_iter().find(|i| i.id == r) {
                    Some(i) => i.exit_code.is_some() || i.timed_out,
                    None => now.saturating_sub(created) > STALE_AFTER_MS,
                },
                None => now.saturating_sub(created) > STALE_AFTER_MS,
            };
            if gone {
                st.state = JobState::Failed;
                st.error = Some("the install process stopped before it finished".into());
                st.ended_ms = Some(now);
                let _ = write_json(&dir.join("status.json"), &st);
            }
        }
        Some(st)
    }

    fn log_tail(&self, id: &str) -> Vec<String> {
        use std::io::{Read, Seek, SeekFrom};
        let path = job_dir(&self.cfg.state, id).join("log");
        let Ok(mut f) = std::fs::File::open(path) else {
            return Vec::new();
        };
        let len = f.metadata().map(|m| m.len()).unwrap_or(0);
        let start = len.saturating_sub(LOG_TAIL_BYTES);
        let _ = f.seek(SeekFrom::Start(start));
        let mut buf = Vec::new();
        let _ = f.take(LOG_TAIL_BYTES).read_to_end(&mut buf);
        let text = String::from_utf8_lossy(&buf).into_owned();
        let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
        if start > 0 && !lines.is_empty() {
            lines.remove(0); // a cut first line
        }
        let n = lines.len().saturating_sub(LOG_TAIL_LINES);
        lines.split_off(n)
    }

    fn job(&self, id: &str) -> Response {
        match self.status_of(id) {
            None => err(404, "not_found", "no such job"),
            Some(st) => {
                let spec: Option<JobSpec> =
                    std::fs::read(job_dir(&self.cfg.state, id).join("job.json"))
                        .ok()
                        .and_then(|b| serde_json::from_slice(&b).ok());
                Response::json(
                    200,
                    &json!({
                        "job": st,
                        "tools": spec.as_ref().map(|s| s.plan.tools.clone()),
                        "requested_by": spec.as_ref().map(|s| s.requested_by.clone()),
                        "log": self.log_tail(id),
                    }),
                )
            }
        }
    }

    fn jobs(&self) -> Response {
        let mut ids: Vec<String> = std::fs::read_dir(self.cfg.state.join("jobs"))
            .map(|rd| {
                rd.filter_map(Result::ok)
                    .filter_map(|e| e.file_name().into_string().ok())
                    .filter(|n| is_job_id(n))
                    .collect()
            })
            .unwrap_or_default();
        // Ids start with the creation time in hex, so the longest-then-largest are the newest.
        ids.sort_by(|a, b| (b.len(), b).cmp(&(a.len(), a)));
        let items: Vec<Value> = ids
            .iter()
            .take(MAX_JOBS_LISTED)
            .filter_map(|id| {
                let st = self.status_of(id)?;
                let tools: Vec<String> = std::fs::read(job_dir(&self.cfg.state, id).join("job.json"))
                    .ok()
                    .and_then(|b| serde_json::from_slice::<JobSpec>(&b).ok())
                    .map(|s| s.plan.tools.iter().map(|t| t.id.clone()).collect())
                    .unwrap_or_default();
                Some(json!({ "id": id, "state": st.state, "error": st.error,
                             "started_ms": st.started_ms, "ended_ms": st.ended_ms, "tools": tools }))
            })
            .collect();
        Response::json(200, &json!({ "jobs": items }))
    }

    fn audit_log(&self) -> Response {
        let text = std::fs::read_to_string(self.audit_path()).unwrap_or_default();
        let mut events: Vec<Value> = text
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();
        let n = events.len().saturating_sub(200);
        events = events.split_off(n);
        Response::json(200, &json!({ "events": events }))
    }

    // ---- agent requests -------------------------------------------------------------------------------------------

    fn list_requests(&self) -> Response {
        let inner = lock(&self.inner);
        Response::json(
            200,
            &json!({ "requests": inner.requests, "always_allowed": inner.always }),
        )
    }

    fn new_request(&self, body: &[u8]) -> Response {
        #[derive(Deserialize)]
        struct B {
            tool: String,
            #[serde(default)]
            reason: String,
            #[serde(default)]
            agent: String,
        }
        let Ok(b) = serde_json::from_slice::<B>(body) else {
            return err(400, "bad_request", "send {\"tool\": id, \"reason\": text}");
        };
        let Some(t) = self.catalog.tool(&b.tool) else {
            return err(
                404,
                "unknown_tool",
                &format!("there is no tool named {}", clean(&b.tool, 40)),
            );
        };
        if !t.verified {
            return plan_err(&PlanError::Unverified {
                id: t.id.clone(),
                reason: t.unverified_reason.clone().unwrap_or_default(),
            });
        }
        if !t.supports(self.cfg.arch) {
            return plan_err(&PlanError::UnsupportedArch {
                id: t.id.clone(),
                arch: self.cfg.arch,
            });
        }
        if self.present(&t.id) {
            return err(
                409,
                "already_installed",
                &format!("{} is already installed", t.name),
            );
        }
        let agent = if label_ok(&b.agent) {
            b.agent.clone()
        } else {
            "agent".to_string()
        };
        let now = self.clock.now_ms();
        let (request, auto) = {
            let mut inner = lock(&self.inner);
            if let Some(existing) = inner
                .requests
                .iter()
                .find(|r| r.tool == t.id && r.state == RequestState::Pending)
            {
                return Response::json(200, &json!({ "request": existing }));
            }
            if inner
                .requests
                .iter()
                .filter(|r| r.state == RequestState::Pending)
                .count()
                >= MAX_PENDING
            {
                return err(
                    429,
                    "too_many_requests",
                    "too many requests are waiting for the owner",
                );
            }
            inner.counter += 1;
            let r = ToolRequest {
                id: format!("r{now:x}{:x}", inner.counter),
                tool: t.id.clone(),
                reason: clean(&b.reason, 300),
                requested_by: agent.clone(),
                created_ms: now,
                state: RequestState::Pending,
                decision: None,
                job_id: None,
            };
            let auto = inner.always.contains(&t.id);
            inner.requests.push(r.clone());
            let n = inner.requests.len().saturating_sub(MAX_REQUESTS);
            inner.requests.drain(..n);
            self.save(&inner);
            (r, auto)
        };
        audit(
            &self.audit_path(),
            now,
            "tools.requested",
            &format!("agent:{agent}"),
            std::slice::from_ref(&t.id),
            "",
            "pending",
        );
        if auto {
            // The owner already said yes to this tool for good; the install still goes through the normal plan.
            return match self.approve(&request.id, "always", "approval") {
                Ok(r) => Response::json(201, &json!({ "request": r })),
                Err(_) => Response::json(201, &json!({ "request": request })),
            };
        }
        Response::json(201, &json!({ "request": request }))
    }

    fn approve(&self, id: &str, decision: &str, actor: &str) -> Result<ToolRequest, Response> {
        let tool = {
            let inner = lock(&self.inner);
            let r = inner
                .requests
                .iter()
                .find(|r| r.id == id)
                .ok_or_else(|| err(404, "not_found", "no such request"))?;
            if r.state != RequestState::Pending {
                return Err(err(
                    409,
                    "already_decided",
                    "that request was already decided",
                ));
            }
            r.tool.clone()
        };
        let req = PlanRequest {
            install: vec![tool.clone()],
            remove: vec![],
        };
        let installed = self.installed_set();
        let plan =
            build_plan(&self.catalog, self.cfg.arch, &installed, &req).map_err(|e| plan_err(&e))?;
        let job = self.start_job(&req, Some(&plan.hash), actor)?;
        let now = self.clock.now_ms();
        let mut inner = lock(&self.inner);
        if decision == "always" {
            inner.always.insert(tool.clone());
        }
        let out = inner.requests.iter_mut().find(|r| r.id == id).map(|r| {
            r.state = RequestState::Approved;
            r.decision = Some(decision.to_string());
            r.job_id = job;
            r.clone()
        });
        self.save(&inner);
        audit(
            &self.audit_path(),
            now,
            "tools.request_approved",
            actor,
            &[tool],
            out.as_ref().and_then(|r| r.job_id.as_deref()).unwrap_or(""),
            decision,
        );
        out.ok_or_else(|| err(404, "not_found", "no such request"))
    }

    fn decide(&self, id: &str, body: &[u8]) -> Response {
        let decision = serde_json::from_slice::<Value>(body)
            .ok()
            .and_then(|v| v["decision"].as_str().map(str::to_string))
            .unwrap_or_default();
        match decision.as_str() {
            "approve_once" => match self.approve(id, "once", "owner") {
                Ok(r) => Response::json(200, &json!({ "request": r })),
                Err(e) => e,
            },
            "approve_always" => match self.approve(id, "always", "owner") {
                Ok(r) => Response::json(200, &json!({ "request": r })),
                Err(e) => e,
            },
            "deny" => {
                let now = self.clock.now_ms();
                let mut inner = lock(&self.inner);
                let found = inner.requests.iter_mut().find(|r| r.id == id);
                match found {
                    None => err(404, "not_found", "no such request"),
                    Some(r) if r.state != RequestState::Pending => {
                        err(409, "already_decided", "that request was already decided")
                    }
                    Some(r) => {
                        r.state = RequestState::Denied;
                        r.decision = Some("denied".into());
                        let (tool, snap) = (r.tool.clone(), r.clone());
                        self.save(&inner);
                        audit(
                            &self.audit_path(),
                            now,
                            "tools.request_denied",
                            "owner",
                            &[tool],
                            "",
                            "denied",
                        );
                        Response::json(200, &json!({ "request": snap }))
                    }
                }
            }
            _ => err(
                400,
                "bad_request",
                "decision must be approve_once, approve_always or deny",
            ),
        }
    }

    /// The catalog this service plans from.
    pub fn catalog(&self) -> &Catalog {
        &self.catalog
    }

    /// Mark jobs that were running when the daemon last stopped as failed, so nothing shows as running forever.
    pub fn recover(&self) {
        let Ok(rd) = std::fs::read_dir(self.cfg.state.join("jobs")) else {
            return;
        };
        for e in rd.filter_map(Result::ok) {
            let Ok(id) = e.file_name().into_string() else {
                continue;
            };
            let path = e.path().join("status.json");
            if let Some(mut st) = std::fs::read(&path)
                .ok()
                .and_then(|b| serde_json::from_slice::<JobStatus>(&b).ok())
            {
                if !is_end(st.state) {
                    st.state = JobState::Failed;
                    st.error = Some("interrupted by a restart of the box daemon".into());
                    st.ended_ms = Some(self.clock.now_ms());
                    let _ = write_json(&path, &st);
                    audit(
                        &self.audit_path(),
                        self.clock.now_ms(),
                        "tools.job_finished",
                        "daemon",
                        &[],
                        &id,
                        "interrupted",
                    );
                }
            }
        }
    }
}

fn is_end(s: JobState) -> bool {
    matches!(s, JobState::Succeeded | JobState::Failed)
}

/// The run id and catalog helper for tests and the CLI's offline view.
pub fn tool_ids(c: &Catalog) -> BTreeMap<String, bool> {
    c.tools.iter().map(|t| (t.id.clone(), t.verified)).collect()
}

/// The state directory of the installer under the daemon's state directory.
pub fn state_dir(daemon_state: &Path) -> PathBuf {
    daemon_state.join("tools")
}
