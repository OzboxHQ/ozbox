//! `/v1/tasks`, `/v1/approval-requests`, `/v1/approval-policy` and `/v1/spend-caps`: the task board, the approvals inbox
//! and their settings. Everything is read from and written to the task store (`ozbox_core::run`), so the command line
//! (`ozbox run`, `ozbox approvals`) and the dashboard see the same state. The supervisor runs from `App::tick`.
//!
//! Anything that wants to start a run in code (a schedule, a trigger) calls [`App::start_run`].

use std::collections::BTreeMap;

use ozbox_core::agent_engine::FakeEngine;
use ozbox_core::approvals::ApprovalPolicy;
use ozbox_core::claude_code::ClaudeCodeEngine;
use ozbox_core::run::{
    ApprovalRequest, ApprovalState, AuditRecord, Book, DeliverTo, Needs, RunCaps, RunOrigin,
    RunSpec, RunStartError, RunStarted, SpendCaps, Task, TaskState, TaskStore,
};
use ozbox_core::supervisor::{
    self, ActionError, AddBudget, AgentHost, AlertEffect, BoxInfo, Supervisor,
};
use ozbox_core::BoxState;
use serde::Deserialize;
use serde_json::{json, Value};

use super::agent::BoxAgent;
use super::run_transport::{BoxRunTransport, RunLink};
use super::{parse_query, unix_ms, App, Req, Resp};
use crate::broker::{Broker, RunBroker};
use crate::model_engines;
use crate::notify::{Alert, Severity};
use crate::secrets::SecretStore;
use crate::settings::{ModelChoice, ModelsConfig};
use ozbox_core::agent_engine::AgentEngine;
use ozbox_core::run::ModelRef;
use ozbox_core::supervisor::{BrokeredUsage, ModelAssignment, ModelGrant};
use ozbox_core::ModelUsage;
use std::sync::Arc;

/// What the server keeps in memory about runs (the state itself is in the task store).
#[derive(Default)]
pub struct RunsRt {
    pub store: Option<TaskStore>,
    sup: Supervisor,
    pub(super) host: ServeHost,
    /// The newest audit record already copied to the Activity list.
    mirrored: u64,
    pub(super) next_tick_ms: u64,
}

/// The boxes and engines the supervisor can reach from this server.
#[derive(Default)]
pub(super) struct ServeHost {
    boxes: BTreeMap<String, BoxInfo>,
    /// The demo provider's engine.
    engine: FakeEngine,
    /// The demo provider runs a simulated engine; a real provider's boxes run Claude Code through the box daemon.
    simulated: bool,
    /// The engine adapters for real boxes, by engine id. Each talks to the box daemon's run API through the shared link;
    /// nothing in the run path knows which engine it serves, so another engine is one more entry here.
    real_engines: BTreeMap<String, Box<dyn AgentEngine>>,
    /// The boxes and the broker's port, shared by every engine's transport.
    link: RunLink,
    /// The way to the boxes' daemons.
    agent: Option<Arc<dyn BoxAgent>>,
    /// The boxes, as the provider lists them this tick.
    records: BTreeMap<String, ozbox_core::BoxRecord>,
    /// When each box's agent was last asked whether it can take a run, and why not if it cannot.
    probe: BTreeMap<String, (std::time::Instant, Option<String>)>,
    checkpoints: u64,
    /// Refreshed from the server's settings before each tick.
    models: ModelsConfig,
    secrets: Option<Arc<dyn SecretStore>>,
    usage_path: Option<std::path::PathBuf>,
    /// Providers whose monthly cap is reached, worked out once per tick from the usage file.
    capped: BTreeMap<String, String>,
    /// The credential broker: started the first time a run needs model credentials. Runs never receive a provider key;
    /// they receive a token for this broker.
    broker: Option<Arc<dyn RunBroker>>,
    /// Runs that were given a token, so their usage is the broker's figure.
    brokered: std::collections::BTreeSet<String>,
    /// The Oz Box tools' server: runs of an orchestration are handed a token for it (see `orch_routes`).
    mcp: Option<Arc<crate::mcp::McpServer>>,
}

impl ServeHost {
    /// The shared way to the boxes' daemons, for the tool host's backend.
    pub(super) fn link(&self) -> RunLink {
        self.link.clone()
    }

    pub(super) fn set_mcp(&mut self, m: Option<Arc<crate::mcp::McpServer>>) {
        if let Some(s) = &m {
            self.link.set_mcp_port(Some(s.port()));
        }
        self.mcp = m;
    }

    /// Real boxes: keep the adapter and the box list current. The adapter is made once and keeps the state of the runs it
    /// started, so it is never rebuilt.
    fn set_real_boxes(&mut self, agent: &Arc<dyn BoxAgent>, recs: Vec<ozbox_core::BoxRecord>) {
        self.agent = Some(Arc::clone(agent));
        self.link.set_boxes(recs.iter().cloned());
        if !self.real_engines.contains_key("claude-code") {
            self.real_engines.insert(
                "claude-code".to_string(),
                Box::new(ClaudeCodeEngine::new(BoxRunTransport::new(
                    Arc::clone(agent),
                    self.link.clone(),
                ))),
            );
        }
        self.records = recs
            .into_iter()
            .map(|r| (r.spec.name.as_str().to_string(), r))
            .collect();
    }
}

impl AgentHost for ServeHost {
    fn box_info(&self, box_name: &str) -> Option<BoxInfo> {
        self.boxes.get(box_name).copied()
    }
    /// The daemon admits a run by free memory itself and queues what does not fit, so the supervisor's own size cap is the
    /// only gate from here.
    fn has_room(&mut self, _: &str) -> bool {
        true
    }
    fn box_unavailable(&mut self, box_name: &str) -> Option<String> {
        if self.simulated {
            return None;
        }
        // A box that answered is asked again after a few seconds; one that did not, after longer: a box that is down must
        // not make every tick wait on a connection, and one that is up is not asked once per queued run per second.
        const AFTER_ANSWER: std::time::Duration = std::time::Duration::from_secs(5);
        const AFTER_FAILURE: std::time::Duration = std::time::Duration::from_secs(20);
        if let Some((at, why)) = self.probe.get(box_name) {
            let keep = if why.is_some() {
                AFTER_FAILURE
            } else {
                AFTER_ANSWER
            };
            if at.elapsed() < keep {
                return why.clone();
            }
        }
        let (agent, rec) = (self.agent.as_ref()?, self.records.get(box_name)?);
        let why = match agent.runs(rec, "GET", "", &[]) {
            Ok((200, _)) => None,
            Ok(_) => Some(
                "this box's agent is too old to run agents; run `ozbox upgrade` on the box"
                    .to_string(),
            ),
            Err(e) => Some(format!("the box's agent cannot be reached: {e}")),
        };
        self.probe.insert(
            box_name.to_string(),
            (std::time::Instant::now(), why.clone()),
        );
        why
    }
    fn engine(&mut self, id: &str) -> Option<&mut dyn ozbox_core::agent_engine::AgentEngine> {
        if self.simulated {
            return (id == "fake")
                .then_some(&mut self.engine as &mut dyn ozbox_core::agent_engine::AgentEngine);
        }
        self.real_engines
            .get_mut(id)
            .map(|e| e.as_mut() as &mut dyn ozbox_core::agent_engine::AgentEngine)
    }
    fn checkpoint(&mut self, box_name: &str, repo: Option<&str>) -> Result<Option<String>, String> {
        if !self.simulated {
            // the box's own daemon saves uncommitted work to a local `wip/` branch in every repository (pushed only on the opt-in)
            let (Some(agent), Some(rec)) = (self.agent.as_ref(), self.records.get(box_name)) else {
                return Err("the box agent is not connected".into());
            };
            let out = agent.checkpoint_for_run(rec).map_err(|e| e.to_string())?;
            let mine = out
                .branches
                .iter()
                .find(|b| repo.is_none_or(|r| b.repo == r))
                .map(|b| b.branch.clone());
            if mine.is_none() && !out.errors.is_empty() {
                return Err(format!(
                    "the box could not save its work in {} repositories",
                    out.errors.len()
                ));
            }
            return Ok(mine);
        }
        self.checkpoints += 1;
        Ok(Some(format!("wip/{box_name}/{}", self.checkpoints)))
    }

    /// The run's provider and model: its own choice, else the box's, else the fleet's for the engine. The key is read
    /// from the secret store now and returned only in the assignment, which the supervisor hands to the engine at start.
    fn resolve_model(
        &mut self,
        task_id: &str,
        spec: &RunSpec,
        use_fallback: bool,
        grant: ModelGrant,
    ) -> Result<Option<ModelAssignment>, String> {
        let own = spec.model.as_ref().map(|m| ModelChoice {
            provider_id: m.provider_id.clone(),
            model: m.model.clone(),
        });
        let boxn = Some(spec.box_name.as_str());
        if !model_engines::has_choice(&self.models, boxn, &spec.engine, own.as_ref()) {
            return Ok(None); // the engine uses its own login
        }
        let secrets = self
            .secrets
            .clone()
            .ok_or_else(|| "no secret store is available".to_string())?;
        if self.broker.is_none() {
            // On a box the broker runs inside the secrets service (another user); on a laptop it runs here.
            self.broker = Some(match crate::secrets_service::remote_broker_from_env() {
                Some(r) => Arc::new(r) as Arc<dyn RunBroker>,
                None => Broker::start(Arc::clone(&secrets), Arc::new(crate::broker::NetUpstream))?
                    as Arc<dyn RunBroker>,
            });
        }
        let broker = self
            .broker
            .clone()
            .ok_or_else(|| "the credential broker is not running".to_string())?;
        broker.set_models(&self.models);
        // a run on a real box reaches the broker through a reverse forward of this port
        self.link.set_broker_port(Some(broker.port()));
        // the broker, not the run, holds the key: the run is handed a token bound to this run and its remaining budget
        let mut issue = |p: &crate::settings::ModelProvider| {
            broker
                .issue(task_id, p, grant.cap_micros, grant.now_ms)
                .map(|t| model_engines::Access {
                    token: Some(t.token),
                    base_url: t.base_url,
                })
        };
        let r = model_engines::resolve_for(
            &self.models,
            secrets.as_ref(),
            boxn,
            &spec.engine,
            own.as_ref(),
            &mut issue,
        )
        .inspect_err(|_| broker.revoke_run(task_id))?;
        let parts = r.into_parts();
        self.brokered.insert(task_id.to_string());
        if use_fallback {
            let f = parts.fallback;
            // the first choice's token is not needed any more
            let Some(f) = f else {
                broker.revoke_run(task_id);
                return Err("the fallback model cannot be used".to_string());
            };
            let f = f.into_parts();
            return Ok(Some(ModelAssignment {
                provider_id: f.provider_id,
                model: f.model,
                fallback: None,
                env: f.env,
            }));
        }
        let fallback = parts.fallback.map(|f| ModelRef {
            provider_id: f.provider_id.clone(),
            model: f.model.clone(),
        });
        Ok(Some(ModelAssignment {
            provider_id: parts.provider_id,
            model: parts.model,
            fallback,
            env: parts.env,
        }))
    }

    /// A conductor or worker run is handed the address of the Oz Box tools and a token bound to this run.
    fn run_env(&mut self, task_id: &str, spec: &RunSpec) -> BTreeMap<String, String> {
        let Some(m) = self.mcp.as_ref() else {
            return BTreeMap::new();
        };
        let (s, host) = crate::mcp::session_and_host(spec);
        match m.issue_host(
            s,
            Some(host),
            Some(task_id),
            unix_ms(),
            crate::mcp::MAX_TOKEN_TTL_MS,
        ) {
            Ok(i) => crate::mcp::env_for(&i),
            Err(_) => BTreeMap::new(),
        }
    }

    fn end_run(&mut self, task_id: &str) {
        if let Some(m) = &self.mcp {
            m.revoke_run(task_id);
        }
        if let Some(b) = &self.broker {
            b.revoke_run(task_id);
        }
        self.brokered.remove(task_id);
    }

    fn drain_usage(&mut self, task_id: &str) -> Vec<BrokeredUsage> {
        let Some(b) = &self.broker else {
            return Vec::new();
        };
        b.drain_usage(task_id)
            .into_iter()
            .map(|u| BrokeredUsage {
                provider_id: u.provider_id,
                model: u.model,
                input_tokens: u.input_tokens,
                output_tokens: u.output_tokens,
                cached_input_tokens: u.cached_input_tokens,
            })
            .collect()
    }

    fn usage_via_broker(&self, task_id: &str) -> bool {
        self.brokered.contains(task_id)
    }

    fn model_cap_scope(&mut self, provider_id: &str, _: u64) -> Option<String> {
        self.capped.get(provider_id).cloned()
    }

    fn record_usage(&mut self, usage: &ModelUsage) {
        if let Some(p) = &self.usage_path {
            // a usage file that cannot be written must not stop the run; the cost is still counted on the task
            let _ = crate::model_usage::record(p, usage);
        }
    }

    fn estimate_micros(&mut self, usage: &ModelUsage) -> Option<u64> {
        crate::model_usage::cost_of(&self.models, usage)
            .map(|usd| (usd * 1_000_000.0).round() as u64)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewTask {
    engine: String,
    #[serde(default)]
    prompt: String,
    #[serde(default)]
    skill: Option<String>,
    #[serde(rename = "box")]
    box_name: String,
    #[serde(default)]
    repo: Option<String>,
    #[serde(default)]
    branch: Option<String>,
    #[serde(default)]
    caps: RunCaps,
    #[serde(default)]
    deliver_to: Vec<DeliverTo>,
    /// Start a conversation: the agent stays running and each message is its next turn.
    #[serde(default)]
    interactive: bool,
    /// A provider and model for this run only (additive).
    #[serde(default)]
    model: Option<ModelRef>,
    #[serde(default)]
    dry_run: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Resume {
    #[serde(default)]
    add_cents: u64,
    #[serde(default)]
    add_minutes: u64,
    #[serde(default)]
    add_tokens: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bulk {
    action: String,
    ids: Vec<String>,
}

fn action_error(e: &ActionError) -> Resp {
    let (status, code) = match e {
        ActionError::NoSuchTask | ActionError::NoSuchApproval => (404, "not_found"),
        ActionError::WrongState(_) | ActionError::AlreadyDecided => (409, "conflict"),
        ActionError::NotAllowed => (403, "not_allowed"),
        ActionError::StepUpRequired => (403, "step_up_required"),
        ActionError::NotInteractive => (409, "conflict"),
        ActionError::BadMessage => (400, "bad_request"),
    };
    Resp::error(status, code, &e.to_string())
}

fn start_error(e: &RunStartError) -> Resp {
    match e {
        RunStartError::Invalid { .. } => Resp::error(400, "bad_request", &e.to_string()),
        RunStartError::QueueFull => Resp::error(429, "queue_full", &e.to_string()),
        RunStartError::Store(_) => Resp::error(500, "store_unavailable", &e.to_string()),
    }
}

fn excerpt(s: &str, n: usize) -> String {
    s.chars()
        .filter(|c| !c.is_control() || *c == ' ')
        .take(n)
        .collect()
}

pub(super) fn state_name(s: TaskState) -> &'static str {
    match s {
        TaskState::Queued => "queued",
        TaskState::Running => "running",
        TaskState::NeedsYou => "needs_you",
        TaskState::Review => "review",
        TaskState::Done => "done",
        TaskState::Failed => "failed",
        TaskState::Cancelled => "cancelled",
    }
}

/// One task as the API shows it. `full` adds the whole prompt.
pub fn task_json(t: &Task, full: bool) -> Value {
    let mut v = json!({
        "id": t.id,
        "state": state_name(t.state),
        "engine": t.spec.engine,
        "box": t.spec.box_name,
        "repo": t.spec.repo,
        "branch": t.spec.branch,
        "skill": t.spec.skill,
        "prompt": excerpt(&t.spec.prompt, if full { 20_000 } else { 160 }),
        "person": t.spec.requested_by,
        "origin": t.spec.origin,
        "created_ms": t.created_ms,
        "started_ms": t.started_ms,
        "finished_ms": t.finished_ms,
        "elapsed_s": t.active_s,
        "spend_cents": t.spend_cents,
        "cost_source": t.cost_source(),
        "tokens": t.tokens,
        "model": t.model,
        "requested_model": t.spec.model,
        "caps": {
            "max_runtime_s": t.runtime_cap(),
            "max_spend_cents": t.spend_cap(),
            "max_tokens": t.token_cap(),
        },
        "deliver_to": t.spec.deliver_to,
        "needs": t.needs,
        "queue_reason": t.queue_reason,
        "wip_branch": t.wip_branch,
        "links": t.links,
        "summary": t.summary,
        "error": t.error,
        "retry_of": t.retry_of,
        "cancelling": t.cancel_requested,
        "interactive": t.spec.interactive,
        "awaiting_input": t.awaiting_input,
        "turns": t.turns,
        "last_reply": t.last_reply,
    });
    if let (Some(Needs::Approval { approval_id }), Some(o)) = (&t.needs, v.as_object_mut()) {
        o.insert("approval_id".into(), json!(approval_id));
    }
    v
}

pub fn approval_json(a: &ApprovalRequest, now_ms: u64, can_decide: bool) -> Value {
    json!({
        "id": a.id,
        "task_id": a.task_id,
        "kind": a.kind,
        "action": a.action,
        "box": a.box_name,
        "asked_by": a.asked_by,
        "production": a.production,
        "needs_step_up": a.needs_step_up,
        "state": a.state,
        "created_ms": a.created_ms,
        "expires_ms": a.expires_ms,
        "expires_in_s": a.expires_ms.saturating_sub(now_ms) / 1000,
        "decided_by": a.decided_by,
        "decided_ms": a.decided_ms,
        "decided_with_step_up": a.decided_with_step_up,
        "can_decide": can_decide,
    })
}

fn month_of(ms: u64) -> String {
    crate::state::month_key(ms)
}

fn busy(b: &Book) -> bool {
    b.tasks
        .iter()
        .any(|t| !t.state.is_terminal() && t.state != TaskState::Review)
        || b.approvals.iter().any(|a| !a.delivered)
        || super::orch_routes::busy(b)
}

impl App {
    pub fn with_task_store(mut self, path: Option<std::path::PathBuf>) -> Self {
        self.runs.store = path.map(TaskStore::new);
        self.runs.host.simulated = self.simulated_metrics;
        self
    }

    pub(super) fn who(&self, req: &Req) -> String {
        self.auth
            .as_ref()
            .and_then(|a| a.person(req))
            .unwrap_or_else(|| "owner".to_string())
    }

    pub(super) fn run_store(&self) -> Result<TaskStore, Resp> {
        self.runs.store.clone().ok_or_else(|| {
            Resp::error(
                501,
                "tasks_unavailable",
                "runs need a task store on this server",
            )
        })
    }

    /// Change the store as one step, and copy what it audited to the Activity list.
    pub(super) fn runs_update<R>(&mut self, f: impl FnOnce(&mut Book) -> R) -> Result<R, Resp> {
        let store = self.run_store()?;
        let since = self.runs.mirrored;
        let (r, news) = store
            .update(|b| {
                let r = f(b);
                let news: Vec<(AuditRecord, String)> = b
                    .audit
                    .iter()
                    .filter(|a| a.seq > since)
                    .map(|a| {
                        let boxn = a
                            .task_id
                            .as_deref()
                            .and_then(|id| b.task(id))
                            .map(|t| t.spec.box_name.clone())
                            .unwrap_or_else(|| "-".into());
                        (a.clone(), boxn)
                    })
                    .collect();
                (r, news)
            })
            .map_err(|e| {
                Resp::error(
                    500,
                    "store_unavailable",
                    &format!("the task store could not be used: {e}"),
                )
            })?;
        for (a, boxn) in news {
            self.runs.mirrored = self.runs.mirrored.max(a.seq);
            self.log_activity(
                &format!("{} ({})", a.action, a.actor),
                &boxn,
                None,
                &a.detail,
            );
        }
        self.version
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(r)
    }

    /// Start a run. This is the entry point for a schedule or a trigger inside the server; the command line and the
    /// dashboard reach the same code through `POST /v1/tasks`.
    pub fn start_run(&mut self, spec: RunSpec) -> Result<RunStarted, RunStartError> {
        let now = unix_ms();
        let r = self
            .runs_update(|b| b.enqueue(spec, now, None))
            .map_err(|_| RunStartError::Store("runs need a task store on this server".into()))??;
        Ok(RunStarted {
            id: r.0,
            state: TaskState::Queued,
            created: r.1,
        })
    }

    /// Called from `tick`: run the supervisor when there is something to supervise, and tell people what needs them.
    pub(super) fn tick_runs(&mut self, now_ms: u64) {
        if now_ms < self.runs.next_tick_ms {
            return;
        }
        self.runs.next_tick_ms = now_ms + 1000;
        let Some(store) = self.runs.store.clone() else {
            return;
        };
        match store.load() {
            Ok(b) if busy(&b) => {}
            _ => return,
        }
        {
            if let Some(recs) = self.boxes_quietly() {
                self.runs.host.boxes = recs
                    .iter()
                    .map(|r| {
                        let l = &r.spec.labels;
                        (
                            r.spec.name.as_str().to_string(),
                            BoxInfo {
                                size: r.spec.size,
                                running: r.state == BoxState::Running,
                                production: l.get("env").is_some_and(|v| v == "production")
                                    || l.get("production").is_some_and(|v| v == "true"),
                            },
                        )
                    })
                    .collect();
                if !self.simulated_metrics {
                    self.runs.host.set_real_boxes(&self.agent, recs);
                }
            }
        }
        // every run is handed the tool host's address and a token, so it has to be listening before a run starts
        self.orch_ensure_mcp();
        self.refresh_model_host(now_ms);
        let month = month_of(now_ms);
        let mut sup = std::mem::take(&mut self.runs.sup);
        let mut host = std::mem::take(&mut self.runs.host);
        let fx = self.runs_update(|b| sup.tick(b, &mut host, now_ms, &month));
        self.runs.sup = sup;
        self.runs.host = host;
        if let Ok(fx) = fx {
            self.deliver_effects(fx, now_ms);
        }
    }

    /// Give the supervisor's host this tick's model settings, secret store and the providers at their monthly cap.
    fn refresh_model_host(&mut self, now_ms: u64) {
        let h = &mut self.runs.host;
        h.models = self.settings.models.clone();
        h.secrets = Some(Arc::clone(&self.secrets));
        h.usage_path = self
            .settings_path
            .as_deref()
            .map(crate::model_usage::path_for);
        h.capped.clear();
        if h.models
            .providers
            .iter()
            .any(|p| p.monthly_cap_usd.is_some())
        {
            if let Some(path) = &h.usage_path {
                let records = crate::model_usage::read(path, now_ms);
                for p in &h.models.providers {
                    if crate::model_usage::cap_reached(&h.models, &records, &p.id, now_ms) {
                        h.capped.insert(
                            p.id.clone(),
                            format!("monthly limit of the {} model provider", p.label),
                        );
                    }
                }
            }
        }
    }

    fn deliver_effects(&mut self, fx: Vec<AlertEffect>, now_ms: u64) {
        if fx.is_empty() {
            return;
        }
        let alerts = fx
            .into_iter()
            .map(|e| Alert {
                key: e.key,
                kind: e.kind.to_string(),
                severity: if e.urgent {
                    Severity::Urgent
                } else {
                    Severity::Normal
                },
                box_name: Some(e.box_name),
                title: e.title,
                body: e.body,
                ts_ms: now_ms,
            })
            .collect();
        self.route_alerts(alerts, now_ms);
    }

    pub(super) fn tasks_route(&mut self, req: &Req, rest: &[&str]) -> Resp {
        let m = req.method.as_str();
        match (m, rest) {
            ("GET", []) => self.list_tasks(&req.query),
            ("POST", []) => self.new_task(req),
            ("POST", ["bulk"]) => self.bulk_tasks(req),
            ("GET", [id]) => self.one_task(id),
            ("GET", [id, "logs"]) => self.task_logs(id),
            ("POST", [id, verb]) => self.task_verb(req, id, verb),
            _ => Resp::error(404, "not_found", "no such endpoint"),
        }
    }

    fn list_tasks(&self, query: &str) -> Resp {
        let store = match self.run_store() {
            Ok(s) => s,
            Err(r) => return r,
        };
        let book = match store.load() {
            Ok(b) => b,
            Err(e) => return Resp::error(500, "store_unavailable", &e.to_string()),
        };
        let q = parse_query(query);
        let states: Vec<&str> = q
            .get("state")
            .map(|s| s.split(',').collect())
            .unwrap_or_default();
        let since: u64 = q.get("since_ms").and_then(|v| v.parse().ok()).unwrap_or(0);
        let until: u64 = q
            .get("until_ms")
            .and_then(|v| v.parse().ok())
            .unwrap_or(u64::MAX);
        let items: Vec<Value> = book
            .tasks
            .iter()
            .rev()
            .filter(|t| q.get("box").is_none_or(|b| &t.spec.box_name == b))
            .filter(|t| q.get("engine").is_none_or(|e| &t.spec.engine == e))
            .filter(|t| q.get("person").is_none_or(|p| &t.spec.requested_by == p))
            .filter(|t| states.is_empty() || states.contains(&state_name(t.state)))
            .filter(|t| t.created_ms >= since && t.created_ms <= until)
            .map(|t| task_json(t, false))
            .collect();
        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        for t in &book.tasks {
            *counts.entry(state_name(t.state)).or_insert(0) += 1;
        }
        Resp::json(
            200,
            &json!({
                "source": if self.simulated_metrics { "simulated" } else { "live" },
                "rev": book.rev,
                "counts": counts,
                "items": items,
            }),
        )
    }

    fn one_task(&self, id: &str) -> Resp {
        let book = match self.run_store().and_then(|s| {
            s.load()
                .map_err(|e| Resp::error(500, "store_unavailable", &e.to_string()))
        }) {
            Ok(b) => b,
            Err(r) => return r,
        };
        match book.task(id) {
            Some(t) => {
                let approvals: Vec<Value> = book
                    .approvals
                    .iter()
                    .filter(|a| a.task_id == id)
                    .map(|a| approval_json(a, unix_ms(), false))
                    .collect();
                let mut v = task_json(t, true);
                if let Some(o) = v.as_object_mut() {
                    o.insert("approvals".into(), json!(approvals));
                }
                Resp::json(200, &v)
            }
            None => Resp::error(404, "not_found", "no such run"),
        }
    }

    fn task_logs(&self, id: &str) -> Resp {
        let book = match self.run_store().and_then(|s| {
            s.load()
                .map_err(|e| Resp::error(500, "store_unavailable", &e.to_string()))
        }) {
            Ok(b) => b,
            Err(r) => return r,
        };
        match book.task(id) {
            Some(t) => Resp::json(200, &json!({ "id": id, "lines": t.log })),
            None => Resp::error(404, "not_found", "no such run"),
        }
    }

    fn new_task(&mut self, req: &Req) -> Resp {
        let b: NewTask = match serde_json::from_slice(&req.body) {
            Ok(b) => b,
            Err(e) => return Resp::error(400, "bad_request", &format!("invalid request: {e}")),
        };
        let spec = RunSpec {
            interactive: b.interactive,
            engine: b.engine,
            prompt: b.prompt,
            skill: b.skill,
            box_name: b.box_name,
            repo: b.repo,
            branch: b.branch,
            caps: b.caps,
            deliver_to: b.deliver_to,
            requested_by: self.who(req),
            origin: RunOrigin::Manual,
            idempotency_key: None,
            model: b.model,
        };
        if let Err(e) = spec.validate() {
            return start_error(&e);
        }
        if let Some(m) = &spec.model {
            if !self
                .settings
                .models
                .providers
                .iter()
                .any(|p| p.id == m.provider_id)
            {
                return Resp::error(400, "bad_request", "that model provider is not set up");
            }
        }
        let known = self
            .provider
            .list()
            .map(|r| r.iter().any(|x| x.spec.name.as_str() == spec.box_name))
            .unwrap_or(false);
        if !known {
            return Resp::error(404, "not_found", "no such box");
        }
        if b.dry_run {
            let store = match self.run_store() {
                Ok(s) => s,
                Err(r) => return r,
            };
            let ahead = store
                .load()
                .map(|bk| {
                    bk.tasks
                        .iter()
                        .filter(|t| t.state == TaskState::Queued)
                        .count()
                })
                .unwrap_or(0);
            return Resp::json(
                200,
                &json!({
                    "dry_run": true,
                    "would_queue": {
                        "engine": spec.engine, "box": spec.box_name, "repo": spec.repo, "branch": spec.branch,
                        "person": spec.requested_by, "caps": spec.caps, "deliver_to": spec.deliver_to,
                    },
                    "queued_ahead": ahead,
                    "note": "Nothing was started.",
                }),
            );
        }
        match self.start_run(spec) {
            Ok(r) => Resp::json(201, &r),
            Err(e) => start_error(&e),
        }
    }

    fn task_verb(&mut self, req: &Req, id: &str, verb: &str) -> Resp {
        let who = self.who(req);
        let now = unix_ms();
        let id = id.to_string();
        let res: Result<Result<Value, ActionError>, Resp> = match verb {
            "cancel" => self.runs_update(|b| {
                supervisor::cancel(b, &id, &who, now).map(|_| json!({ "id": id }))
            }),
            "retry" => self.runs_update(|b| {
                supervisor::retry(b, &id, &who, now).map(|n| json!({ "id": n, "retry_of": id }))
            }),
            "review" => self.runs_update(|b| {
                supervisor::set_review(b, &id, true, &who, now).map(|_| json!({ "id": id }))
            }),
            "accept" => self.runs_update(|b| {
                supervisor::set_review(b, &id, false, &who, now).map(|_| json!({ "id": id }))
            }),
            "resume" => {
                let r: Resume = match serde_json::from_slice(if req.body.is_empty() {
                    b"{}"
                } else {
                    &req.body
                }) {
                    Ok(r) => r,
                    Err(e) => {
                        return Resp::error(400, "bad_request", &format!("invalid request: {e}"))
                    }
                };
                let paused = self
                    .run_store()
                    .ok()
                    .and_then(|s| s.load().ok())
                    .and_then(|b| {
                        b.task(&id)
                            .map(|t| t.needs == Some(ozbox_core::run::Needs::Paused))
                    })
                    .unwrap_or(false);
                if !paused && r.add_cents == 0 && r.add_minutes == 0 && r.add_tokens == 0 {
                    return Resp::error(400, "bad_request", "say how much to add");
                }
                let add = AddBudget {
                    cents: r.add_cents.min(10_000_000),
                    seconds: r.add_minutes.min(10_000) * 60,
                    tokens: r.add_tokens.min(1_000_000_000),
                };
                self.runs_update(|b| {
                    supervisor::resume(b, &id, add, &who, now).map(|_| json!({ "id": id }))
                })
            }
            "pause" => self.runs_update(|b| {
                supervisor::request_pause(b, &id, &who, now).map(|_| json!({ "id": id }))
            }),
            "message" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Msg {
                    text: String,
                }
                let m: Msg = match serde_json::from_slice(&req.body) {
                    Ok(m) => m,
                    Err(e) => {
                        return Resp::error(400, "bad_request", &format!("invalid request: {e}"))
                    }
                };
                self.runs_update(|b| {
                    supervisor::send_message(b, &id, &m.text, &who, now)
                        .map(|_| json!({ "id": id }))
                })
            }
            _ => return Resp::error(404, "not_found", "no such endpoint"),
        };
        match res {
            Ok(Ok(v)) => Resp::json(200, &v),
            Ok(Err(e)) => action_error(&e),
            Err(r) => r,
        }
    }

    fn bulk_tasks(&mut self, req: &Req) -> Resp {
        let b: Bulk = match serde_json::from_slice(&req.body) {
            Ok(b) => b,
            Err(e) => return Resp::error(400, "bad_request", &format!("invalid request: {e}")),
        };
        if b.ids.is_empty() || b.ids.len() > 100 {
            return Resp::error(400, "bad_request", "choose 1 to 100 runs");
        }
        if !["cancel", "retry", "review"].contains(&b.action.as_str()) {
            return Resp::error(400, "bad_request", "action must be cancel, retry or review");
        }
        let who = self.who(req);
        let now = unix_ms();
        let out = self.runs_update(|bk| {
            b.ids
                .iter()
                .map(|id| {
                    let r = match b.action.as_str() {
                        "cancel" => supervisor::cancel(bk, id, &who, now).map(|_| id.clone()),
                        "retry" => supervisor::retry(bk, id, &who, now),
                        _ => supervisor::set_review(bk, id, true, &who, now).map(|_| id.clone()),
                    };
                    match r {
                        Ok(n) => json!({ "id": id, "ok": true, "result_id": n }),
                        Err(e) => json!({ "id": id, "ok": false, "error": e.to_string() }),
                    }
                })
                .collect::<Vec<_>>()
        });
        match out {
            Ok(results) => Resp::json(200, &json!({ "results": results })),
            Err(r) => r,
        }
    }

    // ---- approvals ---------------------------------------------------------------------------------------------

    pub(super) fn approval_requests(&mut self, req: &Req, rest: &[&str]) -> Resp {
        let who = self.who(req);
        match (req.method.as_str(), rest) {
            ("GET", []) => {
                let book = match self.run_store().and_then(|s| {
                    s.load()
                        .map_err(|e| Resp::error(500, "store_unavailable", &e.to_string()))
                }) {
                    Ok(b) => b,
                    Err(r) => return r,
                };
                let all = parse_query(&req.query)
                    .get("state")
                    .is_some_and(|s| s == "all");
                let now = unix_ms();
                let mut items: Vec<Value> = book
                    .approvals
                    .iter()
                    .filter(|a| all || a.state == ApprovalState::Pending)
                    .map(|a| {
                        let by = book
                            .task(&a.task_id)
                            .map(|t| t.spec.requested_by.clone())
                            .unwrap_or_default();
                        approval_json(a, now, book.policy.may_decide(&who, &by))
                    })
                    .collect();
                items.reverse();
                Resp::json(200, &json!({ "source": "server", "items": items }))
            }
            ("POST", [id, verb]) if *verb == "approve" || *verb == "deny" => {
                let factor = match &self.auth {
                    Some(a) => a
                        .step_up_fresh(req)
                        .then_some(ozbox_core::permissions::SecondFactor::StepUp),
                    None => Some(ozbox_core::permissions::SecondFactor::NoSignIn),
                };
                let (id, approve, now) = (id.to_string(), *verb == "approve", unix_ms());
                if approve {
                    if let Some(r) = self.approval_gate(req, &id) {
                        return r;
                    }
                }
                match self
                    .runs_update(|b| supervisor::decide_with(b, &id, approve, &who, factor, now))
                {
                    Ok(Ok(())) => Resp::json(
                        200,
                        &json!({ "id": id, "state": if approve { "approved" } else { "denied" } }),
                    ),
                    Ok(Err(e)) => action_error(&e),
                    Err(r) => r,
                }
            }
            _ => Resp::error(404, "not_found", "no such endpoint"),
        }
    }

    /// Approving a request that is for production, or that asks for a second factor, does more than record a yes: for
    /// production it makes the one-use grant the action runs under. So it is judged as granting access is: only a role that
    /// may create a grant (an owner), and only with a second factor the dashboard can believe (a passkey just shown, or
    /// the access token on the person's own computer, never on a box with no sign-in). Denying is open to anyone who may
    /// decide approvals. `Some` refuses.
    fn approval_gate(&mut self, req: &Req, id: &str) -> Option<Resp> {
        let a = self
            .run_store()
            .ok()
            .and_then(|s| s.load().ok())
            .and_then(|b| b.approval(id).cloned())?;
        if !(a.production || a.needs_step_up) {
            return None;
        }
        if a.production {
            if let Some(auth) = &self.auth {
                let allowed = auth.who_and_role(req).is_some_and(|(_, role)| {
                    ozbox_core::roles::allowed(role, ozbox_core::permissions::Action::GrantCreate)
                });
                if !allowed {
                    return Some(Resp::error(
                        403,
                        "role_forbidden",
                        "approving a change to production gives access to production, which only an owner may do. Ask an owner",
                    ));
                }
            }
        }
        super::roles::step_up_refusal(
            self.step_up_state(req),
            if a.production {
                "approving a change to production"
            } else {
                "approving something that asks for a second factor"
            },
        )
    }

    pub(super) fn approval_policy(&mut self, req: &Req) -> Resp {
        let who = self.who(req);
        match req.method.as_str() {
            "GET" => match self.run_store().and_then(|s| {
                s.load()
                    .map_err(|e| Resp::error(500, "store_unavailable", &e.to_string()))
            }) {
                Ok(b) => Resp::json(200, &b.policy),
                Err(r) => r,
            },
            "PUT" => {
                let p: ApprovalPolicy = match serde_json::from_slice(&req.body) {
                    Ok(p) => p,
                    Err(e) => {
                        return Resp::error(400, "bad_request", &format!("invalid request: {e}"))
                    }
                };
                if let Err(e) = p.validate() {
                    return Resp::error(400, "bad_request", &e);
                }
                // asking for less is a change a person must confirm with a second factor; asking for more is not. The
                // comparison is made on the stored value inside the store's lock, so a writer that lands in between
                // cannot be overwritten without the second factor.
                let state = self.step_up_state(req);
                let fresh = state == super::roles::StepUp::Fresh;
                let now = unix_ms();
                match self.runs_update(|b| {
                    if !fresh && b.policy.loosens(&p) {
                        return false;
                    }
                    b.policy = p.clone();
                    b.record(now, &who, "approval.policy_changed", None, "");
                    true
                }) {
                    Ok(true) => Resp::json(200, &p),
                    Ok(false) => self.step_up_denied(&who, state, "loosening the approval policy"),
                    Err(r) => r,
                }
            }
            _ => Resp::error(405, "method_not_allowed", "method not allowed"),
        }
    }

    pub(super) fn spend_caps(&mut self, req: &Req) -> Resp {
        let who = self.who(req);
        match req.method.as_str() {
            "GET" => match self.run_store().and_then(|s| {
                s.load()
                    .map_err(|e| Resp::error(500, "store_unavailable", &e.to_string()))
            }) {
                Ok(b) => Resp::json(200, &json!({ "caps": b.caps, "ledger": b.ledger })),
                Err(r) => r,
            },
            "PUT" => {
                let c: SpendCaps = match serde_json::from_slice(&req.body) {
                    Ok(c) => c,
                    Err(e) => {
                        return Resp::error(400, "bad_request", &format!("invalid request: {e}"))
                    }
                };
                let big = 100_000_000u64;
                let bad = c.fleet_monthly_cents.is_some_and(|v| v > big)
                    || c.person_monthly_cents.is_some_and(|v| v > big)
                    || c.per_person.len() > 100
                    || c.per_person
                        .iter()
                        .any(|(k, v)| k.is_empty() || k.len() > 64 || *v > big);
                if bad {
                    return Resp::error(
                        400,
                        "bad_request",
                        "a limit is too large or a person's id is not valid",
                    );
                }
                // raising or removing a limit is a change a person must confirm with a second factor (decided under the
                // store's lock, on the stored value)
                let state = self.step_up_state(req);
                let fresh = state == super::roles::StepUp::Fresh;
                let now = unix_ms();
                match self.runs_update(|b| {
                    if !fresh && b.caps.loosens(&c) {
                        return false;
                    }
                    b.caps = c.clone();
                    b.record(now, &who, "spend.caps_changed", None, "");
                    true
                }) {
                    Ok(true) => Resp::json(200, &json!({ "caps": c })),
                    Ok(false) => self.step_up_denied(&who, state, "raising a spend limit"),
                    Err(r) => r,
                }
            }
            _ => Resp::error(405, "method_not_allowed", "method not allowed"),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ozbox_core::{BoxName, BoxSpec, Provider, Size};
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    const TOKEN: &str = "test-token";

    fn app(dir: &std::path::Path) -> App {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7878);
        let p = ozbox_provider_fake::open(dir);
        for (n, size) in [("alpha", Size::S), ("bravo", Size::M)] {
            let spec = BoxSpec::new(BoxName::new(n).unwrap(), size);
            let provider: &dyn Provider = &p;
            let plan = provider
                .plan(&ozbox_core::Operation::Create { spec })
                .unwrap();
            provider.apply(&plan).unwrap();
        }
        App::new(Box::new(p), true, addr, TOKEN.into())
            .with_task_store(Some(dir.join("tasks.json")))
    }

    fn req(method: &str, path: &str, body: Value) -> Req {
        let (p, q) = path.split_once('?').unwrap_or((path, ""));
        let mut headers = HashMap::new();
        headers.insert("host".to_string(), "127.0.0.1:7878".to_string());
        headers.insert("authorization".to_string(), format!("Bearer {TOKEN}"));
        Req {
            method: method.into(),
            path: p.into(),
            query: q.into(),
            headers,
            body: if body.is_null() {
                Vec::new()
            } else {
                body.to_string().into_bytes()
            },
        }
    }

    fn call(a: &mut App, method: &str, path: &str, body: Value) -> (u16, Value) {
        let r = a.handle(&req(method, path, body));
        (
            r.status,
            serde_json::from_slice(&r.body).unwrap_or(Value::Null),
        )
    }

    fn tick(a: &mut App, from: u64, n: u64) {
        for i in 0..n {
            a.runs.next_tick_ms = 0;
            a.tick_runs(from + i * 1000);
        }
    }

    #[test]
    fn a_task_is_queued_run_finished_and_listed_with_filters() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = app(dir.path());
        let (st, v) = call(
            &mut a,
            "POST",
            "/v1/tasks",
            json!({"engine":"fake","prompt":"sim:steps=2","box":"alpha"}),
        );
        assert_eq!(st, 201, "{v}");
        let id = v["id"].as_str().unwrap().to_string();
        tick(&mut a, 1_000_000, 5);
        let (_, t) = call(&mut a, "GET", &format!("/v1/tasks/{id}"), Value::Null);
        assert_eq!(t["state"], "review", "{t}");
        assert_eq!(t["links"][0]["kind"], "pull_request");
        assert!(t["spend_cents"].as_u64().unwrap() > 0);
        let (_, l) = call(
            &mut a,
            "GET",
            "/v1/tasks?box=alpha&state=review",
            Value::Null,
        );
        assert_eq!(l["items"].as_array().unwrap().len(), 1);
        let (_, l) = call(&mut a, "GET", "/v1/tasks?box=bravo", Value::Null);
        assert!(l["items"].as_array().unwrap().is_empty());
        assert_eq!(l["counts"]["review"], 1);
        let (_, logs) = call(&mut a, "GET", &format!("/v1/tasks/{id}/logs"), Value::Null);
        assert!(!logs["lines"].as_array().unwrap().is_empty());
        // what happened is in the Activity list
        let (_, act) = call(&mut a, "GET", "/v1/activity", Value::Null);
        assert!(act["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["action"].as_str().unwrap().starts_with("run.started")));
    }

    #[test]
    fn a_bad_request_a_missing_box_and_a_dry_run_start_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = app(dir.path());
        assert_eq!(
            call(
                &mut a,
                "POST",
                "/v1/tasks",
                json!({"engine":"Bad","prompt":"x","box":"alpha"})
            )
            .0,
            400
        );
        assert_eq!(
            call(
                &mut a,
                "POST",
                "/v1/tasks",
                json!({"engine":"fake","prompt":"x","box":"nope"})
            )
            .0,
            404
        );
        assert_eq!(
            call(
                &mut a,
                "POST",
                "/v1/tasks",
                json!({"engine":"fake","prompt":"x","box":"alpha","extra":1})
            )
            .0,
            400
        );
        let (st, v) = call(
            &mut a,
            "POST",
            "/v1/tasks",
            json!({"engine":"fake","prompt":"x","box":"alpha","dry_run":true}),
        );
        assert_eq!((st, v["dry_run"].clone()), (200, json!(true)));
        let (_, l) = call(&mut a, "GET", "/v1/tasks", Value::Null);
        assert!(l["items"].as_array().unwrap().is_empty());
    }

    #[test]
    fn the_spend_cap_pause_alerts_and_resumes_through_the_api() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = app(dir.path());
        let (_, v) = call(
            &mut a,
            "POST",
            "/v1/tasks",
            json!({"engine":"fake","prompt":"sim:steps=100 sim:cents=10","box":"bravo","caps":{"max_spend_cents":25}}),
        );
        let id = v["id"].as_str().unwrap().to_string();
        tick(&mut a, 2_000_000, 8);
        let (_, t) = call(&mut a, "GET", &format!("/v1/tasks/{id}"), Value::Null);
        assert_eq!(t["state"], "needs_you");
        assert_eq!(t["needs"]["kind"], "spend_cap");
        assert!(t["wip_branch"].as_str().unwrap().starts_with("wip/bravo/"));
        // the owner was asked through the alert routing (it lands in the alert list)
        let (_, al) = call(&mut a, "GET", "/v1/alerts", Value::Null);
        assert!(al.to_string().contains("run_needs_you"), "{al}");
        assert_eq!(
            call(&mut a, "POST", &format!("/v1/tasks/{id}/resume"), json!({})).0,
            400
        );
        let (st, _) = call(
            &mut a,
            "POST",
            &format!("/v1/tasks/{id}/resume"),
            json!({"add_cents": 500}),
        );
        assert_eq!(st, 200);
        tick(&mut a, 3_000_000, 3);
        let (_, t) = call(&mut a, "GET", &format!("/v1/tasks/{id}"), Value::Null);
        assert_eq!(t["state"], "running", "{t}");
        assert_eq!(t["caps"]["max_spend_cents"], 525);
    }

    #[test]
    fn an_approval_is_listed_decided_audited_and_cannot_be_decided_twice() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = app(dir.path());
        let (_, v) = call(
            &mut a,
            "POST",
            "/v1/tasks",
            json!({"engine":"fake","prompt":"sim:steps=50 sim:push=main","box":"bravo"}),
        );
        let id = v["id"].as_str().unwrap().to_string();
        tick(&mut a, 4_000_000, 5);
        let (_, l) = call(&mut a, "GET", "/v1/approval-requests", Value::Null);
        let item = &l["items"][0];
        assert_eq!(item["action"], "git push origin main");
        assert_eq!(item["kind"], "push_protected_branch");
        assert_eq!(item["can_decide"], true);
        let aid = item["id"].as_str().unwrap().to_string();
        let (st, _) = call(
            &mut a,
            "POST",
            &format!("/v1/approval-requests/{aid}/approve"),
            Value::Null,
        );
        assert_eq!(st, 200, "token mode has no second factor to ask for");
        assert_eq!(
            call(
                &mut a,
                "POST",
                &format!("/v1/approval-requests/{aid}/deny"),
                Value::Null
            )
            .0,
            409
        );
        tick(&mut a, 5_000_000, 2);
        let (_, t) = call(&mut a, "GET", &format!("/v1/tasks/{id}"), Value::Null);
        assert_eq!(t["state"], "running");
        let (_, act) = call(&mut a, "GET", "/v1/activity", Value::Null);
        let text = act.to_string();
        assert!(
            text.contains("approval.requested") && text.contains("approval.approved"),
            "{text}"
        );
        let (_, l) = call(&mut a, "GET", "/v1/approval-requests", Value::Null);
        assert!(l["items"].as_array().unwrap().is_empty());
        let (_, all) = call(
            &mut a,
            "GET",
            "/v1/approval-requests?state=all",
            Value::Null,
        );
        assert_eq!(all["items"][0]["state"], "approved");
    }

    #[test]
    fn policy_and_caps_are_validated_saved_and_audited() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = app(dir.path());
        let (_, p) = call(&mut a, "GET", "/v1/approval-policy", Value::Null);
        assert_eq!(p["expiry_s"], 28800);
        let mut bad = p.clone();
        bad["expiry_s"] = json!(5);
        assert_eq!(call(&mut a, "PUT", "/v1/approval-policy", bad).0, 400);
        let mut good = p.clone();
        good["expiry_s"] = json!(3600);
        good["allow_requester"] = json!(false);
        assert_eq!(call(&mut a, "PUT", "/v1/approval-policy", good).0, 200);
        let (_, p) = call(&mut a, "GET", "/v1/approval-policy", Value::Null);
        assert_eq!(p["expiry_s"], 3600);
        assert_eq!(
            call(
                &mut a,
                "PUT",
                "/v1/spend-caps",
                json!({"fleet_monthly_cents": 5000, "per_person": {"ada": 1000}})
            )
            .0,
            200
        );
        let (_, c) = call(&mut a, "GET", "/v1/spend-caps", Value::Null);
        assert_eq!(c["caps"]["fleet_monthly_cents"], 5000);
        assert_eq!(
            call(
                &mut a,
                "PUT",
                "/v1/spend-caps",
                json!({"fleet_monthly_cents": 99999999999u64})
            )
            .0,
            400
        );
        let (_, act) = call(&mut a, "GET", "/v1/activity", Value::Null);
        assert!(act.to_string().contains("approval.policy_changed"));
    }

    #[test]
    fn loosening_the_policy_or_raising_a_cap_needs_a_second_factor_but_tightening_does_not() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = app(dir.path());
        // on a box with no sign-in no second factor can be shown, so a loosening is refused and says why
        a.on_a_box = true;
        let (_, p) = call(&mut a, "GET", "/v1/approval-policy", Value::Null);
        let mut loose = p.clone();
        loose["allow_requester"] = json!(false);
        let (st, _) = call(&mut a, "PUT", "/v1/approval-policy", loose.clone());
        assert_eq!(st, 200, "tightening needs nothing");
        let (st, body) = call(&mut a, "PUT", "/v1/approval-policy", p.clone());
        assert_eq!(st, 403, "{body}");
        assert_eq!(body["code"], "sign_in_required");
        let (_, now) = call(&mut a, "GET", "/v1/approval-policy", Value::Null);
        assert_eq!(
            now["allow_requester"], false,
            "a refused loosening changes nothing"
        );
        // an expiry is the one setting with a line of its own (D16): up to 8 hours, or any lowering, is not loosening; a raise
        // past 8 hours is, so it is refused here exactly like any other loosening, decided on the server from the stored value
        let put_expiry = |a: &mut App, s: u64| {
            let mut v = now.clone();
            v["expiry_s"] = json!(s);
            call(a, "PUT", "/v1/approval-policy", v)
        };
        assert_eq!(put_expiry(&mut a, 7200).0, 200);
        assert_eq!(
            put_expiry(&mut a, 8 * 3600).0,
            200,
            "back up to exactly 8 hours"
        );
        let (st, body) = put_expiry(&mut a, 8 * 3600 + 60);
        assert_eq!(st, 403, "{body}");
        assert_eq!(body["code"], "sign_in_required");
        assert_eq!(put_expiry(&mut a, 24 * 3600).0, 403);
        let (_, kept) = call(&mut a, "GET", "/v1/approval-policy", Value::Null);
        assert_eq!(
            kept["expiry_s"],
            8 * 3600,
            "a refused raise changes nothing"
        );
        // caps: a first limit and a lower one are fine, a higher one or none is refused
        let put = |a: &mut App, v: Value| call(a, "PUT", "/v1/spend-caps", v);
        assert_eq!(put(&mut a, json!({"fleet_monthly_cents": 5000})).0, 200);
        assert_eq!(put(&mut a, json!({"fleet_monthly_cents": 4000})).0, 200);
        assert_eq!(put(&mut a, json!({"fleet_monthly_cents": 9000})).0, 403);
        assert_eq!(put(&mut a, json!({})).0, 403);
        let (_, c) = call(&mut a, "GET", "/v1/spend-caps", Value::Null);
        assert_eq!(c["caps"]["fleet_monthly_cents"], 4000);
        // on the person's own computer the access token is the second factor
        a.on_a_box = false;
        assert_eq!(put(&mut a, json!({"fleet_monthly_cents": 9000})).0, 200);
    }

    #[test]
    fn cancel_retry_review_and_bulk_work_and_refuse_the_wrong_state() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = app(dir.path());
        let mk = |a: &mut App, prompt: &str| {
            let (_, v) = call(
                a,
                "POST",
                "/v1/tasks",
                json!({"engine":"fake","prompt":prompt,"box":"bravo"}),
            );
            v["id"].as_str().unwrap().to_string()
        };
        let (x, y) = (mk(&mut a, "sim:steps=1000"), mk(&mut a, "sim:steps=1000"));
        tick(&mut a, 6_000_000, 3);
        let (_, r) = call(
            &mut a,
            "POST",
            "/v1/tasks/bulk",
            json!({"action":"cancel","ids":[x, y, "t999"]}),
        );
        assert_eq!(r["results"][0]["ok"], true);
        assert_eq!(r["results"][2]["ok"], false);
        tick(&mut a, 7_000_000, 3);
        let (_, t) = call(&mut a, "GET", &format!("/v1/tasks/{x}"), Value::Null);
        assert_eq!(t["state"], "cancelled");
        let (st, n) = call(&mut a, "POST", &format!("/v1/tasks/{x}/retry"), Value::Null);
        assert_eq!(st, 200);
        assert_eq!(n["retry_of"], json!(x));
        assert_eq!(
            call(
                &mut a,
                "POST",
                &format!("/v1/tasks/{y}/accept"),
                Value::Null
            )
            .0,
            409
        );
        assert_eq!(
            call(
                &mut a,
                "POST",
                &format!("/v1/tasks/{x}/review"),
                Value::Null
            )
            .0,
            200
        );
        assert_eq!(
            call(&mut a, "POST", "/v1/tasks/nope/cancel", Value::Null).0,
            404
        );
        assert_eq!(
            call(
                &mut a,
                "POST",
                "/v1/tasks/bulk",
                json!({"action":"destroy","ids":["t1"]})
            )
            .0,
            400
        );
    }

    #[test]
    fn start_run_is_the_door_for_schedules_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = app(dir.path());
        let spec = RunSpec {
            interactive: false,
            engine: "fake".into(),
            prompt: "nightly check".into(),
            skill: None,
            box_name: "alpha".into(),
            repo: None,
            branch: None,
            caps: RunCaps::default(),
            deliver_to: vec![],
            requested_by: "schedule:nightly".into(),
            origin: RunOrigin::Schedule {
                id: "nightly".into(),
            },
            idempotency_key: Some("nightly:1".into()),
            model: None,
        };
        let first = a.start_run(spec.clone()).unwrap();
        let second = a.start_run(spec).unwrap();
        assert_eq!(
            (first.id.as_str(), second.created),
            (second.id.as_str(), false)
        );
        let (_, l) = call(&mut a, "GET", "/v1/tasks", Value::Null);
        assert_eq!(l["items"][0]["origin"]["kind"], "schedule");
    }

    #[test]
    fn without_a_store_the_routes_say_so() {
        let dir = tempfile::tempdir().unwrap();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7878);
        let mut a = App::new(
            Box::new(ozbox_provider_fake::open(dir.path())),
            true,
            addr,
            TOKEN.into(),
        );
        assert_eq!(call(&mut a, "GET", "/v1/tasks", Value::Null).0, 501);
    }

    // ---- models: the choice, the broker, usage, fallback and the monthly cap, end to end ------------------------

    const SENTINEL: &str = "sk-SENTINEL-4242-never-stored";

    struct Rig {
        a: App,
        up: Arc<crate::broker::tests::FakeUpstream>,
        dir: tempfile::TempDir,
    }

    fn model_app(cap: Option<f64>) -> Rig {
        use crate::settings::{EngineModel, ModelKind, ModelProvider, Settings};
        let dir = tempfile::tempdir().unwrap();
        let secrets = Arc::new(crate::secrets::MemorySecrets::default());
        secrets.set("model-key-oa", SENTINEL).unwrap();
        secrets
            .set("model-key-anth", "sk-ant-other-secret")
            .unwrap();
        let prov = |id: &str, kind: ModelKind, cap: Option<f64>| ModelProvider {
            id: id.into(),
            kind,
            label: id.into(),
            base_url: None,
            local_endpoint: false,
            monthly_cap_usd: cap,
            region: None,
            resource: None,
            hosted_on: None,
        };
        let mut s = Settings::default();
        s.models.providers = vec![
            prov("oa", ModelKind::Openai, cap),
            prov("anth", ModelKind::Anthropic, None),
        ];
        s.models.engines.insert(
            "claude-code".into(),
            EngineModel {
                provider_id: "oa".into(),
                model: "gpt-4o".into(),
                fallback: Some(ModelChoice {
                    provider_id: "anth".into(),
                    model: "claude-sonnet-4-5".into(),
                }),
            },
        );
        let mut a = app(dir.path())
            .with_secrets(secrets.clone())
            .with_settings(s, Some(dir.path().join("settings.json")));
        let up = Arc::new(crate::broker::tests::FakeUpstream::default());
        a.runs.host.broker = Some(Broker::start(secrets, up.clone()).unwrap());
        Rig { a, up, dir }
    }

    fn start(a: &mut App, prompt: &str, extra: Value) -> String {
        let mut body = json!({"engine":"fake","prompt":prompt,"box":"bravo"});
        if let (Some(o), Some(e)) = (body.as_object_mut(), extra.as_object()) {
            o.extend(e.clone());
        }
        let (st, v) = call(a, "POST", "/v1/tasks", body);
        assert_eq!(st, 201, "{v}");
        v["id"].as_str().unwrap().to_string()
    }

    fn task(a: &mut App, id: &str) -> Value {
        call(a, "GET", &format!("/v1/tasks/{id}"), Value::Null).1
    }

    /// Act as the agent would: take what the run was handed (the token and the address in its environment) and make a
    /// model call through it. Returns the HTTP status.
    fn agent_call(a: &App, start_no: usize, key_var: &str, base_var: &str, path: &str) -> u16 {
        let env = &a.runs.host.engine.envs[start_no];
        let (token, base) = (env[key_var].clone(), env[base_var].clone());
        match ureq::AgentBuilder::new()
            .build()
            .post(&format!("{base}{path}"))
            .set("authorization", &format!("Bearer {token}"))
            .set("x-api-key", &token)
            .send_string(r#"{"model":"gpt-4o"}"#)
        {
            Ok(r) => r.status(),
            Err(ureq::Error::Status(c, _)) => c,
            Err(e) => panic!("{e}"),
        }
    }

    const OPENAI_USAGE: &str =
        r#"{"model":"gpt-4o","usage":{"prompt_tokens":1000000,"completion_tokens":100000}}"#;

    #[test]
    fn a_run_is_given_a_token_not_the_key_and_the_brokers_count_is_its_cost() {
        let mut r = model_app(None);
        let base = unix_ms();
        let id = start(&mut r.a, "sim:steps=50", json!({}));
        tick(&mut r.a, base, 3);
        let t = task(&mut r.a, &id);
        assert_eq!(t["state"], "running", "{t}");
        assert_eq!(t["model"]["provider_id"], "oa");
        assert_eq!(t["model"]["model"], "gpt-4o");
        assert_eq!(t["model"]["fallback"]["model"], "claude-sonnet-4-5");
        // what the run holds: a run token and the broker's address, never the key
        let env = r.a.runs.host.engine.envs[0].clone();
        assert!(env["OPENAI_API_KEY"].starts_with("ozrt_"));
        assert!(
            env["OPENAI_BASE_URL"].starts_with("http://127.0.0.1:")
                && env["OPENAI_BASE_URL"].ends_with("/oa/v1")
        );
        assert!(env.values().all(|v| !v.contains("SENTINEL")), "{env:?}");
        // the agent calls the model through the broker; the provider sees the real key, the agent never does
        r.up.reply(200, "application/json", OPENAI_USAGE);
        assert_eq!(
            agent_call(
                &r.a,
                0,
                "OPENAI_API_KEY",
                "OPENAI_BASE_URL",
                "/chat/completions"
            ),
            200
        );
        let sent = r.up.sent.lock().unwrap().clone();
        assert_eq!(sent[0].url, "https://api.openai.com/v1/chat/completions");
        assert!(sent[0]
            .headers
            .iter()
            .any(|(k, v)| k == "Authorization" && v == &format!("Bearer {SENTINEL}")));
        tick(&mut r.a, base + 10_000, 2);
        let t = task(&mut r.a, &id);
        // 1M in + 0.1M out at the built-in gpt-4o price: $3.50, an estimate, counted once
        assert_eq!(t["spend_cents"], 350, "{t}");
        assert_eq!(t["cost_source"], "estimated");
        let usage = crate::model_usage::path_for(&r.dir.path().join("settings.json"));
        let recs = crate::model_usage::read(&usage, base + 20_000);
        assert_eq!(recs.len(), 1);
        assert_eq!(
            (
                recs[0].provider_id.as_str(),
                recs[0].model.as_str(),
                recs[0].box_name.as_deref(),
                recs[0].engine.as_deref()
            ),
            ("oa", "gpt-4o", Some("bravo"), Some("fake"))
        );
        // the key is in no file the server wrote and in no answer
        for f in ["tasks.json", "model-usage.jsonl", "settings.json"] {
            let text = std::fs::read_to_string(r.dir.path().join(f)).unwrap_or_default();
            assert!(!text.contains(SENTINEL), "{f}");
        }
        assert!(!t.to_string().contains(SENTINEL));
        let (_, logs) = call(
            &mut r.a,
            "GET",
            &format!("/v1/tasks/{id}/logs"),
            Value::Null,
        );
        assert!(!logs.to_string().contains(SENTINEL));
    }

    #[test]
    fn the_runs_token_stops_working_the_moment_the_run_ends() {
        let mut r = model_app(None);
        let base = unix_ms();
        let id = start(&mut r.a, "sim:steps=50", json!({}));
        tick(&mut r.a, base, 3);
        r.up.reply(200, "application/json", OPENAI_USAGE);
        assert_eq!(
            agent_call(
                &r.a,
                0,
                "OPENAI_API_KEY",
                "OPENAI_BASE_URL",
                "/chat/completions"
            ),
            200
        );
        let (st, _) = call(
            &mut r.a,
            "POST",
            &format!("/v1/tasks/{id}/cancel"),
            json!({}),
        );
        assert_eq!(st, 200);
        tick(&mut r.a, base + 10_000, 3);
        assert_eq!(task(&mut r.a, &id)["state"], "cancelled");
        let before = r.up.sent.lock().unwrap().len();
        assert_eq!(
            agent_call(
                &r.a,
                0,
                "OPENAI_API_KEY",
                "OPENAI_BASE_URL",
                "/chat/completions"
            ),
            401
        );
        assert_eq!(
            r.up.sent.lock().unwrap().len(),
            before,
            "nothing reached the provider"
        );
    }

    #[test]
    fn a_reported_cost_beats_the_estimate_and_a_per_run_model_beats_the_engines() {
        let mut r = model_app(None);
        let base = unix_ms();
        let id = start(
            &mut r.a,
            "sim:steps=4 sim:reported=42",
            json!({"model": {"provider_id": "anth", "model": "claude-opus-4"}}),
        );
        tick(&mut r.a, base, 8);
        let t = task(&mut r.a, &id);
        assert_eq!(t["model"]["provider_id"], "anth", "{t}");
        assert_eq!(t["requested_model"]["model"], "claude-opus-4");
        assert_eq!(t["spend_cents"], 42);
        assert_eq!(t["cost_source"], "reported");
        let env = r.a.runs.host.engine.envs[0].clone();
        assert!(
            env["ANTHROPIC_API_KEY"].starts_with("ozrt_") && env.contains_key("ANTHROPIC_BASE_URL")
        );
        // an unknown provider is refused up front
        let (st, v) = call(
            &mut r.a,
            "POST",
            "/v1/tasks",
            json!({"engine":"fake","prompt":"x","box":"bravo","model":{"provider_id":"nope","model":"m"}}),
        );
        assert_eq!(st, 400, "{v}");
    }

    #[test]
    fn a_refused_run_continues_on_the_fallback_with_a_fresh_token_and_the_card_says_so() {
        let mut r = model_app(None);
        let base = unix_ms();
        let id = start(&mut r.a, "sim:steps=50 sim:refuse", json!({}));
        tick(&mut r.a, base, 6);
        let t = task(&mut r.a, &id);
        assert_eq!(t["state"], "running", "{t}");
        assert_eq!(t["model"]["provider_id"], "anth");
        assert_eq!(t["model"]["fell_back_from"]["model"], "gpt-4o");
        assert!(t["model"]["fallback_reason"]
            .as_str()
            .unwrap()
            .contains("429"));
        let envs = &r.a.runs.host.engine.envs;
        assert!(
            envs[0].contains_key("OPENAI_API_KEY") && envs[1].contains_key("ANTHROPIC_API_KEY")
        );
        // the first token ended with the first attempt
        assert_eq!(
            agent_call(
                &r.a,
                0,
                "OPENAI_API_KEY",
                "OPENAI_BASE_URL",
                "/chat/completions"
            ),
            401
        );
    }

    #[test]
    fn a_provider_at_its_monthly_cap_holds_the_next_run_in_needs_you() {
        let mut r = model_app(Some(1.0));
        let base = unix_ms();
        let first = start(&mut r.a, "sim:steps=50", json!({}));
        tick(&mut r.a, base, 3);
        r.up.reply(200, "application/json", OPENAI_USAGE); // $3.50 against a $1 cap
        assert_eq!(
            agent_call(
                &r.a,
                0,
                "OPENAI_API_KEY",
                "OPENAI_BASE_URL",
                "/chat/completions"
            ),
            200
        );
        tick(&mut r.a, base + 10_000, 4);
        let t = task(&mut r.a, &first);
        assert_eq!(t["state"], "needs_you", "{t}");
        assert_eq!(t["needs"]["kind"], "monthly_cap");
        let next = start(&mut r.a, "sim:steps=2", json!({}));
        tick(&mut r.a, base + 20_000, 3);
        let t = task(&mut r.a, &next);
        assert_eq!(t["state"], "needs_you", "{t}");
        assert!(t["needs"]["scope"].as_str().unwrap().contains("oa"), "{t}");
    }

    #[test]
    fn a_choice_that_cannot_be_used_keeps_the_run_queued_and_says_what_to_fix() {
        let mut r = model_app(None);
        let base = unix_ms();
        let secrets = r.a.secrets.clone();
        secrets.delete("model-key-oa").unwrap();
        let id = start(&mut r.a, "sim:steps=2", json!({}));
        tick(&mut r.a, base, 3);
        let t = task(&mut r.a, &id);
        assert_eq!(t["state"], "queued");
        assert!(
            t["queue_reason"]
                .as_str()
                .unwrap()
                .contains("no key is saved"),
            "{t}"
        );
        assert!(r.a.runs.host.engine.envs.is_empty(), "nothing was started");
    }

    // ---- a real box: Claude Code through the box daemon's run API ---------------------------------------------------
    //
    // The provider is the fake one but the app is not simulated, so a run goes through the same path a real box's does:
    // the Claude Code adapter, `BoxRunTransport`, and `BoxAgent::runs`. The box daemon is a double that keeps what it was
    // asked to start and serves a scripted log.

    mod real_box {
        use super::*;
        use crate::serve::agent::{
            AgentError, BoxAgent, CheckpointBranch, CheckpointOutcome, Incident, SelfTest,
        };
        use ozbox_core::{BoxRecord, MetricsSample};
        use std::sync::Mutex;

        #[derive(Default)]
        struct Daemon {
            /// The POST bodies, in order. The run id is `r<position>`.
            started: Vec<Value>,
            logs: BTreeMap<String, (String, Option<i32>)>,
            stops: Vec<String>,
            forwards: Vec<u16>,
            requests: Vec<String>,
            down: bool,
            old: bool,
            checkpoint: CheckpointOutcome,
            /// What was appended to each run's standard input, in order.
            inputs: Vec<(String, Value)>,
        }

        #[derive(Clone, Default)]
        struct Handle(Arc<Mutex<Daemon>>);

        impl Handle {
            fn lock(&self) -> std::sync::MutexGuard<'_, Daemon> {
                self.0.lock().unwrap()
            }
            fn say(&self, run: &str, text: &str, exit: Option<i32>) {
                self.lock().logs.insert(run.into(), (text.into(), exit));
            }
        }

        struct Fake(Handle);

        impl BoxAgent for Fake {
            fn metrics_now(&self, _: &BoxRecord, _: u64) -> Result<MetricsSample, AgentError> {
                Err(AgentError::Unsupported("no metrics".into()))
            }
            fn metrics_series(
                &self,
                _: &BoxRecord,
                _: u64,
                _: u64,
                _: u64,
            ) -> Result<Vec<MetricsSample>, AgentError> {
                Err(AgentError::Unsupported("no metrics".into()))
            }
            fn selftest(&self, _: &BoxRecord, _: u64) -> Result<SelfTest, AgentError> {
                Err(AgentError::Unsupported("no self-test".into()))
            }
            fn incidents(
                &self,
                _: &BoxRecord,
                _: u64,
                _: u64,
            ) -> Result<Vec<Incident>, AgentError> {
                Err(AgentError::Unsupported("no incidents".into()))
            }
            fn checkpoint(&self, _: &BoxRecord) -> Result<CheckpointOutcome, AgentError> {
                Ok(self.0.lock().checkpoint.clone())
            }
            fn reverse_forward(&self, _: &BoxRecord, port: u16) -> Result<(), AgentError> {
                self.0.lock().forwards.push(port);
                Ok(())
            }
            fn runs(
                &self,
                _: &BoxRecord,
                method: &str,
                sub: &str,
                body: &[u8],
            ) -> Result<(u16, Value), AgentError> {
                let mut d = self.0.lock();
                if d.down {
                    return Err(AgentError::Unreachable(
                        "the box could not be reached".into(),
                    ));
                }
                d.requests.push(format!("{method} {sub}"));
                if d.old {
                    return Ok((404, json!({ "error": "not found" })));
                }
                match (method, sub) {
                    ("GET", "") => Ok((200, json!({ "runs": [] }))),
                    ("POST", "") => {
                        d.started
                            .push(serde_json::from_slice(body).unwrap_or(Value::Null));
                        let id = format!("r{}", d.started.len());
                        Ok((201, json!({ "id": id, "state": "running" })))
                    }
                    ("GET", s) if s.contains("/log?from=") => {
                        let id = s.trim_start_matches('/').split('/').next().unwrap_or("");
                        let from: usize = s
                            .rsplit('=')
                            .next()
                            .and_then(|n| n.parse().ok())
                            .unwrap_or(0);
                        let (text, exit) = d.logs.get(id).cloned().unwrap_or_default();
                        let tail = text.get(from..).unwrap_or("");
                        Ok((
                            200,
                            json!({ "id": id, "log": { "text": tail, "next": text.len(), "state": "running", "exit_code": exit } }),
                        ))
                    }
                    ("POST", s) if s.ends_with("/stdin") => {
                        let id = s.trim_start_matches('/').split('/').next().unwrap_or("");
                        d.inputs.push((
                            id.to_string(),
                            serde_json::from_slice(body).unwrap_or(Value::Null),
                        ));
                        Ok((200, json!({ "id": id })))
                    }
                    ("DELETE", s) => {
                        d.stops.push(s.trim_start_matches('/').to_string());
                        Ok((200, json!({ "id": s })))
                    }
                    _ => Ok((404, json!({ "error": "no such run" }))),
                }
            }
        }

        const KEY: &str = "sk-ant-SENTINEL-real-box-never-on-the-box";

        struct World {
            a: App,
            d: Handle,
            up: Arc<crate::broker::tests::FakeUpstream>,
            dir: tempfile::TempDir,
        }

        fn world() -> World {
            use crate::settings::{EngineModel, ModelKind, ModelProvider, Settings};
            let dir = tempfile::tempdir().unwrap();
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7878);
            let p = ozbox_provider_fake::open(dir.path());
            for (n, size) in [("alpha", Size::S), ("bravo", Size::M)] {
                let provider: &dyn Provider = &p;
                let plan = provider
                    .plan(&ozbox_core::Operation::Create {
                        spec: BoxSpec::new(BoxName::new(n).unwrap(), size),
                    })
                    .unwrap();
                provider.apply(&plan).unwrap();
            }
            let secrets = Arc::new(crate::secrets::MemorySecrets::default());
            secrets.set("model-key-anth", KEY).unwrap();
            let mut s = Settings::default();
            s.models.providers = vec![ModelProvider {
                id: "anth".into(),
                kind: ModelKind::Anthropic,
                label: "anth".into(),
                base_url: None,
                local_endpoint: false,
                monthly_cap_usd: None,
                region: None,
                resource: None,
                hosted_on: None,
            }];
            s.models.engines.insert(
                "claude-code".into(),
                EngineModel {
                    provider_id: "anth".into(),
                    model: "claude-sonnet-4-5".into(),
                    fallback: None,
                },
            );
            let d = Handle::default();
            let mut a = App::new(Box::new(p), false, addr, TOKEN.into())
                .with_task_store(Some(dir.path().join("tasks.json")))
                .with_agent(Box::new(Fake(d.clone())))
                .with_secrets(secrets.clone())
                .with_settings(s, Some(dir.path().join("settings.json")));
            let up = Arc::new(crate::broker::tests::FakeUpstream::default());
            a.runs.host.broker = Some(Broker::start(secrets, up.clone()).unwrap());
            World { a, d, up, dir }
        }

        fn start(a: &mut App, extra: Value) -> String {
            let mut body = json!({"engine":"claude-code","prompt":"Fix the parser, PROMPT-MARKER","box":"bravo","repo":"web"});
            if let (Some(o), Some(e)) = (body.as_object_mut(), extra.as_object()) {
                o.extend(e.clone());
            }
            let (st, v) = call(a, "POST", "/v1/tasks", body);
            assert_eq!(st, 201, "{v}");
            v["id"].as_str().unwrap().to_string()
        }

        fn task(a: &mut App, id: &str) -> Value {
            call(a, "GET", &format!("/v1/tasks/{id}"), Value::Null).1
        }

        const STREAM: &str = concat!(
            "{\"type\":\"assistant\",\"message\":{\"id\":\"m1\",\"model\":\"claude-sonnet-4-5\",\"content\":[{\"type\":\"text\",\"text\":\"Reading the parser\"}],\"usage\":{\"input_tokens\":100,\"output_tokens\":20}}}\n",
            "{\"type\":\"result\",\"subtype\":\"success\",\"is_error\":false,\"result\":\"Fixed it\",\"total_cost_usd\":0.12}\n"
        );

        #[test]
        fn a_conversation_on_a_real_box_keeps_its_input_open_hands_over_each_message_and_continues_after_a_pause(
        ) {
            let mut w = world();
            let base = unix_ms();
            let id = start(&mut w.a, json!({"interactive": true}));
            tick(&mut w.a, base, 3);
            let body = w.d.lock().started[0].clone();
            assert_eq!(body["keep_stdin_open"], true);
            assert!(body["argv"]
                .as_array()
                .unwrap()
                .iter()
                .any(|a| a == "--input-format"));
            let first = body["stdin"].as_str().unwrap();
            assert!(first.trim_end().starts_with('{') && first.contains("PROMPT-MARKER"));
            // the agent answers: the turn is done and the run still runs, waiting for the person
            let turn = concat!(
                "{\"type\":\"system\",\"session_id\":\"sess-9\"}\n",
                "{\"type\":\"result\",\"subtype\":\"success\",\"is_error\":false,\"result\":\"I fixed the parser\",\"session_id\":\"sess-9\"}\n"
            );
            w.d.say("r1", turn, None);
            tick(&mut w.a, base + 5_000, 2);
            let t = task(&mut w.a, &id);
            assert_eq!(t["state"], "running", "{t}");
            assert_eq!(
                (t["awaiting_input"].as_bool(), t["turns"].as_u64()),
                (Some(true), Some(1))
            );
            assert_eq!(t["last_reply"], "I fixed the parser");
            // a message goes to the box as one line on the same input, over the route that never echoes it
            let (st, v) = call(
                &mut w.a,
                "POST",
                &format!("/v1/tasks/{id}/message"),
                json!({"text":"now add tests"}),
            );
            assert_eq!(st, 200, "{v}");
            tick(&mut w.a, base + 8_000, 2);
            let (rid, sent) = w.d.lock().inputs[0].clone();
            assert_eq!(rid, "r1");
            assert!(
                sent["text"].as_str().unwrap().contains("now add tests") && sent["close"] == false
            );
            // pause saves and stops; resume continues the same conversation under the session id
            let (st, _) = call(
                &mut w.a,
                "POST",
                &format!("/v1/tasks/{id}/pause"),
                Value::Null,
            );
            assert_eq!(st, 200);
            tick(&mut w.a, base + 10_000, 2);
            assert_eq!(task(&mut w.a, &id)["state"], "needs_you");
            assert!(w.d.lock().stops.contains(&"r1".to_string()));
            let (st, v) = call(
                &mut w.a,
                "POST",
                &format!("/v1/tasks/{id}/resume"),
                json!({}),
            );
            assert_eq!(st, 200, "{v}");
            tick(&mut w.a, base + 12_000, 3);
            let second = w.d.lock().started[1].clone();
            assert!(second["argv"]
                .as_array()
                .unwrap()
                .windows(2)
                .any(|p| p[0] == "--resume" && p[1] == "sess-9"));
            // a plain run is not a conversation
            let plain = start(&mut w.a, json!({}));
            let (st, _) = call(
                &mut w.a,
                "POST",
                &format!("/v1/tasks/{plain}/message"),
                json!({"text":"hi"}),
            );
            assert_eq!(st, 409);
        }

        #[test]
        fn a_run_on_a_real_box_goes_queued_running_review_streams_its_log_and_holds_no_key() {
            let mut w = world();
            let base = unix_ms();
            let id = start(&mut w.a, json!({}));
            assert_eq!(task(&mut w.a, &id)["state"], "queued");
            tick(&mut w.a, base, 3);
            let t = task(&mut w.a, &id);
            assert_eq!(t["state"], "running", "{t}");
            assert_eq!(t["model"]["provider_id"], "anth");

            // what the box was asked to run
            let body = w.d.lock().started[0].clone();
            let env = body["env"].as_object().unwrap();
            let token = env["ANTHROPIC_API_KEY"].as_str().unwrap().to_string();
            assert!(token.starts_with("ozrt_"), "a per-run token, not the key");
            let broker_port = w.a.runs.host.broker.as_ref().unwrap().port();
            assert_eq!(
                env["ANTHROPIC_BASE_URL"],
                format!("http://127.0.0.1:{broker_port}/anth")
            );
            // the prompt is the run's standard input and nowhere in the arguments
            assert!(body["stdin"].as_str().unwrap().contains("PROMPT-MARKER"));
            let argv = body["argv"].to_string();
            assert!(!argv.contains("PROMPT-MARKER") && !argv.contains("ozrt_"));
            assert!(body["argv"]
                .as_array()
                .unwrap()
                .iter()
                .any(|a| a == "claude-sonnet-4-5"));
            assert_eq!(body["cwd"], "/work/repos/web");
            // the key is nowhere in the request, and the broker's port and the tool host's were made reachable on the box
            assert!(!body.to_string().contains("SENTINEL"));
            let forwards = w.d.lock().forwards.clone();
            assert_eq!(forwards[0], broker_port);
            assert_eq!(forwards.len(), 2, "the tool host answers every run");
            assert_eq!(
                env["OZBOX_MCP_URL"],
                format!("http://127.0.0.1:{}/mcp", forwards[1])
            );
            assert!(env["OZBOX_MCP_TOKEN"]
                .as_str()
                .unwrap()
                .starts_with("ozmt_"));

            // the agent writes; the server reads it back as it grows, and the run finishes in Review
            w.d.say("r1", STREAM, Some(0));
            tick(&mut w.a, base + 10_000, 3);
            let t = task(&mut w.a, &id);
            assert_eq!(t["state"], "review", "{t}");
            assert_eq!(t["summary"], "Fixed it");
            assert_eq!(t["cost_source"], "reported");
            assert_eq!(t["spend_cents"], 12);
            let (_, logs) = call(
                &mut w.a,
                "GET",
                &format!("/v1/tasks/{id}/logs"),
                Value::Null,
            );
            assert!(logs.to_string().contains("Reading the parser"), "{logs}");

            // the token appears nowhere on the box side but the run's own environment, nor in anything the server wrote
            let requests = w.d.lock().requests.join("\n");
            assert!(!requests.contains(&token));
            for f in ["tasks.json", "settings.json"] {
                let text = std::fs::read_to_string(w.dir.path().join(f)).unwrap_or_default();
                assert!(!text.contains(&token) && !text.contains("SENTINEL"), "{f}");
            }
            assert!(!t.to_string().contains(&token) && !logs.to_string().contains(&token));
            // and it stops working when the run ends
            let status = match ureq::AgentBuilder::new()
                .build()
                .post(&format!("http://127.0.0.1:{broker_port}/anth/v1/messages"))
                .set("x-api-key", &token)
                .send_string("{}")
            {
                Ok(r) => r.status(),
                Err(ureq::Error::Status(c, _)) => c,
                Err(e) => panic!("{e}"),
            };
            assert!(status == 401 || status == 403, "{status}");
        }

        #[test]
        fn cancel_saves_the_work_to_the_branch_the_box_reports_and_stops_the_run() {
            let mut w = world();
            w.d.lock().checkpoint = CheckpointOutcome {
                repos_scanned: 2,
                errors: Vec::new(),
                branches: vec![
                    CheckpointBranch {
                        repo: "other".into(),
                        branch: "wip/bravo/20261110T000000Z".into(),
                    },
                    CheckpointBranch {
                        repo: "web".into(),
                        branch: "wip/bravo/20261110T010203Z".into(),
                    },
                ],
            };
            let base = unix_ms();
            let id = start(&mut w.a, json!({}));
            tick(&mut w.a, base, 3);
            assert_eq!(task(&mut w.a, &id)["state"], "running");
            assert_eq!(
                call(
                    &mut w.a,
                    "POST",
                    &format!("/v1/tasks/{id}/cancel"),
                    json!({})
                )
                .0,
                200
            );
            tick(&mut w.a, base + 10_000, 3);
            let t = task(&mut w.a, &id);
            assert_eq!(t["state"], "cancelled", "{t}");
            // the branch of this run's repository, not another's; and the run on the box was stopped
            assert_eq!(t["wip_branch"], "wip/bravo/20261110T010203Z");
            assert_eq!(w.d.lock().stops, ["r1"]);
        }

        #[test]
        fn a_run_that_reaches_its_limit_is_saved_stopped_and_continues_from_the_saved_branch() {
            let mut w = world();
            w.d.lock().checkpoint.branches = vec![CheckpointBranch {
                repo: "web".into(),
                branch: "wip/bravo/20261110T010203Z".into(),
            }];
            let base = unix_ms();
            let id = start(&mut w.a, json!({"caps":{"max_spend_cents":10}}));
            tick(&mut w.a, base, 3);
            assert_eq!(task(&mut w.a, &id)["state"], "running");
            // the agent calls the model through the broker: a million input tokens is far more than ten cents
            let body = w.d.lock().started[0].clone();
            let token = body["env"]["ANTHROPIC_API_KEY"]
                .as_str()
                .unwrap()
                .to_string();
            let url = body["env"]["ANTHROPIC_BASE_URL"]
                .as_str()
                .unwrap()
                .to_string();
            w.up.reply(
                200,
                "application/json",
                r#"{"model":"claude-sonnet-4-5","usage":{"input_tokens":1000000,"output_tokens":0}}"#,
            );
            let r = ureq::AgentBuilder::new()
                .build()
                .post(&format!("{url}/v1/messages"))
                .set("x-api-key", &token)
                .send_string("{}");
            assert_eq!(r.unwrap().status(), 200);
            tick(&mut w.a, base + 10_000, 4);
            let t = task(&mut w.a, &id);
            assert_eq!(t["state"], "needs_you", "{t}");
            assert_eq!(t["needs"]["kind"], "spend_cap");
            // saved to the branch the box reported, and the run on the box was stopped, not left running unattended
            assert_eq!(t["wip_branch"], "wip/bravo/20261110T010203Z");
            assert_eq!(w.d.lock().stops, ["r1"]);
            // more budget: it queues again and continues from the saved branch, with a token of its own
            let (st, _) = call(
                &mut w.a,
                "POST",
                &format!("/v1/tasks/{id}/resume"),
                json!({"add_cents": 1000}),
            );
            assert_eq!(st, 200);
            tick(&mut w.a, base + 20_000, 3);
            let second = w.d.lock().started.get(1).cloned().unwrap();
            assert!(second["stdin"]
                .as_str()
                .unwrap()
                .contains("wip/bravo/20261110T010203Z"));
            assert_ne!(second["env"]["ANTHROPIC_API_KEY"].as_str().unwrap(), token);
        }

        #[test]
        fn a_box_whose_agent_cannot_be_reached_or_is_too_old_keeps_the_run_queued_and_says_why() {
            let mut w = world();
            w.d.lock().down = true;
            let base = unix_ms();
            let id = start(&mut w.a, json!({}));
            tick(&mut w.a, base, 2);
            let t = task(&mut w.a, &id);
            assert_eq!(t["state"], "queued", "{t}");
            assert!(
                t["queue_reason"]
                    .as_str()
                    .unwrap()
                    .contains("cannot be reached"),
                "{t}"
            );
            // it comes back: the run starts
            w.d.lock().down = false;
            w.a.runs.host.probe.clear();
            tick(&mut w.a, base + 5_000, 3);
            assert_eq!(task(&mut w.a, &id)["state"], "running");

            // an agent from before the run API is not a failure either
            let mut w = world();
            w.d.lock().old = true;
            let id = start(&mut w.a, json!({}));
            tick(&mut w.a, base, 2);
            let t = task(&mut w.a, &id);
            assert_eq!(t["state"], "queued");
            assert!(
                t["queue_reason"]
                    .as_str()
                    .unwrap()
                    .contains("ozbox upgrade"),
                "{t}"
            );
        }
    }
}
