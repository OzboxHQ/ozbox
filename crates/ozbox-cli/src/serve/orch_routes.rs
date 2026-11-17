//! Orchestrations in the dashboard server: `/v1/orchestrations`, the Oz Box tools' endpoint, and the tick that drives them.
//!
//! The tools themselves live in `crate::orch_tools` and are the same code the REST routes, the command line and the MCP
//! server call. What lives here is what only the server can do: hold the provider (so a worker box can be cloned, paused
//! or destroyed by plan-then-apply), start the MCP listener, hand a run its token, run the merge queue's `git` steps, and
//! tick the orchestrations alongside the supervisor.
//!
//! The MCP listener runs on its own threads and cannot touch the provider, which the request loop owns. A box tool becomes a
//! job on a channel; the loop answers it on its next pass (at most a second later) and the caller waits for the answer.

use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ozbox_core::orch::{BoxAction, FeatureState, OrchState, WorkerChannel};
use ozbox_core::orch_merge::{merge_step, Merger};
use ozbox_core::orch_rules::{parse_rules, OrchSettings, Overrides};
use ozbox_core::run::{Book, TaskState};
use ozbox_core::supervisor::AgentHost;
use serde_json::{json, Value};

use super::run_transport::BoxRunTransport;
use super::{unix_ms, App, Req, Resp};
use crate::host_tools::backend::{DaemonBackend, HostBackend, LocalBackend};
use crate::host_tools::{HostTools, OpsFacts};
use crate::mcp::{Composite, McpServer, MAX_TOKEN_TTL_MS};
use crate::orch_tools::{orch_json, orch_summary, BoxOps, Role, Session, ToolError, Tools};

/// A request from a tool thread for something only the request loop can do.
pub enum Job {
    List,
    Plan(Value),
    Apply(String, Value),
}

type Reply = Sender<Result<Value, String>>;

/// The tools' view of the provider from another thread: each call is a job the loop answers.
pub struct JobOps {
    tx: Mutex<Sender<(Job, Reply)>>,
}

impl JobOps {
    fn ask(&self, job: Job) -> Result<Value, String> {
        let (rtx, rrx) = channel();
        self.tx
            .lock()
            .map_err(|_| "the server is shutting down".to_string())?
            .send((job, rtx))
            .map_err(|_| "the server is shutting down".to_string())?;
        match rrx.recv_timeout(Duration::from_secs(90)) {
            Ok(r) => r,
            Err(RecvTimeoutError::Timeout) => Err("the server did not answer in time".into()),
            Err(RecvTimeoutError::Disconnected) => Err("the server is shutting down".into()),
        }
    }
}

impl BoxOps for JobOps {
    fn list(&self) -> Result<Vec<Value>, String> {
        let v = self.ask(Job::List)?;
        Ok(v.as_array().cloned().unwrap_or_default())
    }
    fn plan(&self, operation: Value) -> Result<Value, String> {
        self.ask(Job::Plan(operation))
    }
    fn apply(&self, plan_id: &str, plan: &Value) -> Result<Value, String> {
        self.ask(Job::Apply(plan_id.to_string(), plan.clone()))
    }
}

/// The boxes as they are right now, for a call that is already on the request loop (it cannot wait on itself).
struct SnapshotOps(Vec<Value>);

impl BoxOps for SnapshotOps {
    fn list(&self) -> Result<Vec<Value>, String> {
        Ok(self.0.clone())
    }
    fn plan(&self, _: Value) -> Result<Value, String> {
        Err("make boxes from an agent's tools, or with `ozbox clone`".into())
    }
    fn apply(&self, _: &str, _: &Value) -> Result<Value, String> {
        Err("make boxes from an agent's tools, or with `ozbox clone`".into())
    }
}

/// A message to a worker that is still running goes to its engine's own session channel (the one a chat session uses). An
/// engine or a run with no conversation refuses it, and the message then waits for the worker's turn to end.
struct HostChannel<'a> {
    host: &'a mut super::runs_routes::ServeHost,
    handles: std::collections::BTreeMap<String, (String, String)>,
}

impl WorkerChannel for HostChannel<'_> {
    fn send(&mut self, task_id: &str, text: &str) -> Result<(), String> {
        let (engine, handle) = self
            .handles
            .get(task_id)
            .cloned()
            .ok_or_else(|| "that run is not on an engine".to_string())?;
        let e = self
            .host
            .engine(&engine)
            .ok_or_else(|| "that engine is not set up".to_string())?;
        e.send(&handle, text).map_err(|e| e.to_string())
    }
}

#[derive(Default)]
pub struct OrchRt {
    pub(super) browser: Option<Arc<crate::browser_tools::BrowserHost>>,
    mcp: Option<Arc<McpServer>>,
    /// The tool host runs and agents share (set with `mcp`).
    pub(super) tools: Option<Arc<Composite>>,
    /// The door for coding agents on a box (`crate::agent_mcp`).
    pub(super) agent: Option<Arc<crate::agent_mcp::AgentMcp>>,
    /// When the agent door may be tried again after a failure: 0 is now. A door that opened is never tried again.
    pub(super) agent_retry_at_ms: u64,
    jobs: Option<Receiver<(Job, Reply)>>,
    merger: Option<Box<dyn Merger + Send>>,
    merger_box: Option<String>,
    next_tick_ms: u64,
    /// The worker channel (ADR 0042), when this box is a hub. Attached by [`App::attach_hub`]; `None` keeps the laptop route.
    pub(super) hub: Option<Arc<ozbox_core::hub::engine::HubService>>,
    /// The declared test lanes the merge queue may run over the hub (`test_lane_box = "hub:<name>"`).
    pub(super) lanes: std::collections::BTreeMap<String, ozbox_core::hub::merge::LaneDecl>,
    /// The hub as the server holds it (the daemon's spool, the real signer and sealer, the fabric), when this box is one.
    pub(super) attachment: Option<Arc<crate::hub_fleet::HubAttachment>>,
    /// The conversation fabric's tools (ADR 0057), when this box is a hub.
    pub(super) fabric: Option<Arc<crate::fabric_tools::FabricHost>>,
}

fn bad(msg: &str) -> Resp {
    Resp::error(400, "bad_request", msg)
}

fn tool_resp(e: &ToolError) -> Resp {
    match e {
        ToolError::NotFound(m) => Resp::error(404, "not_found", m),
        ToolError::Invalid(m) => Resp::error(400, "bad_request", m),
        ToolError::Refused(m) => Resp::error(409, "refused", m),
        ToolError::Failed(m) => Resp::error(502, "failed", m),
    }
}

fn orch_err(e: &ozbox_core::orch::OrchError) -> Resp {
    tool_resp(&ToolError::from(e.clone()))
}

fn body_of(req: &Req) -> Result<Value, Resp> {
    if req.body.is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_slice(&req.body).map_err(|e| bad(&format!("invalid request: {e}")))
}

fn text(v: &Value, k: &str) -> Option<String> {
    v.get(k)
        .and_then(Value::as_str)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

impl App {
    /// Start the tools' listener (once) and give the supervisor's host the means to hand a run its token.
    pub(super) fn orch_ensure_mcp(&mut self) -> Option<Arc<McpServer>> {
        if let Some(m) = &self.orch.mcp {
            return Some(Arc::clone(m));
        }
        let store = self.runs.store.clone()?;
        let (tx, rx) = channel();
        let ops: Arc<dyn BoxOps> = Arc::new(JobOps { tx: Mutex::new(tx) });
        // The host tools act on a box through its daemon; the demo provider has no daemon, so it gets a directory per box on
        // this computer instead (never chosen for a real box).
        // A simulated server on a box never runs its stand-ins on the box (X2): the tools and the browser are refused.
        let sim_on_a_box = self.simulated_metrics && crate::this_box::on_a_box();
        let backend: Arc<dyn HostBackend> = if sim_on_a_box {
            Arc::new(super::no_simulation::RefusedHostBackend)
        } else if self.simulated_metrics {
            let base = store
                .path()
                .parent()
                .map(|p| p.join("demo-work"))
                .unwrap_or_else(|| std::path::PathBuf::from("demo-work"));
            Arc::new(LocalBackend::new(base))
        } else {
            Arc::new(DaemonBackend::new(Box::new(BoxRunTransport::new(
                Arc::clone(&self.agent),
                self.runs.host.link(),
            ))))
        };
        let self_memory = self.memory_host().ok();
        // the browser on the box: a worker per session through the daemon; on the demo provider, a thread per session
        let policy_path = store.path().with_file_name("browser-policy.json");
        let browser_backend: Arc<dyn crate::browser_tools::BrowserBackend> = if sim_on_a_box {
            Arc::new(super::no_simulation::RefusedBrowserBackend)
        } else if self.simulated_metrics {
            let base = store
                .path()
                .parent()
                .map(|p| p.join("demo-work"))
                .unwrap_or_else(|| std::path::PathBuf::from("demo-work"));
            Arc::new(crate::browser_tools::InProcessBackend::new(base))
        } else {
            let daemon: Arc<dyn crate::browser_tools::BrowserBackend> =
                Arc::new(crate::browser_tools::DaemonBrowserBackend::new(
                    Box::new(BoxRunTransport::new(
                        Arc::clone(&self.agent),
                        self.runs.host.link(),
                    )),
                    Arc::clone(&backend),
                ));
            // On a box that has the browser's own user (the launcher's socket exists), this box's sessions run as that
            // user; every other box goes through its daemon, as before (ADR 0037, amendment 4).
            crate::browser_launch::LauncherBrowserBackend::detect(Arc::clone(&daemon))
                .unwrap_or(daemon)
        };
        let browser = Arc::new(crate::browser_tools::BrowserHost::new(
            browser_backend,
            store.clone(),
            policy_path,
        ));
        self.orch.browser = Some(Arc::clone(&browser));
        let mut host = HostTools::new(store.clone(), backend, Arc::new(OpsFacts(Arc::clone(&ops))));
        host.browser = Some(browser);
        let tools = Arc::new(Composite {
            orch: Tools::new(store, ops)
                .with_memory(self_memory)
                .with_hub(self.orch.hub.clone())
                .with_fabric(self.orch.fabric.clone()),
            host,
        });
        self.orch.tools = Some(Arc::clone(&tools));
        let server = McpServer::start(tools).ok()?;
        self.orch.jobs = Some(rx);
        self.orch.mcp = Some(Arc::clone(&server));
        self.runs.host.set_mcp(Some(Arc::clone(&server)));
        Some(server)
    }

    /// Make this box a hub (ADR 0042): the orchestration tools hand tasks over it, the merge queue takes its workers' commits and
    /// runs declared lanes across them, and the fleet inbox shows its workers' requests. Called when the server starts, before
    /// the tools do: tools already running keep the route they were made with, so a later call is refused.
    pub fn attach_hub(
        &mut self,
        hub: Arc<ozbox_core::hub::engine::HubService>,
        lanes: std::collections::BTreeMap<String, ozbox_core::hub::merge::LaneDecl>,
    ) -> Result<(), &'static str> {
        if self.orch.mcp.is_some() || self.orch.tools.is_some() {
            return Err("the orchestration tools are already running without the hub: restart the server to attach it");
        }
        self.orch.hub = Some(hub);
        self.orch.lanes = lanes;
        Ok(())
    }

    /// Attach the hub as the daemon, the secrets service and the fabric make it: the channel, the fleet inbox, the merge queue, and the
    /// messaging tools. Called when the server starts, before the tools do.
    pub fn attach_hub_fleet(
        &mut self,
        att: Arc<crate::hub_fleet::HubAttachment>,
        lanes: std::collections::BTreeMap<String, ozbox_core::hub::merge::LaneDecl>,
    ) -> Result<(), &'static str> {
        self.attach_hub(att.svc.clone(), lanes)?;
        self.orch.fabric = Some(Arc::new(crate::fabric_tools::FabricHost::new(
            att.fabric.clone(),
            &att.svc.me,
        )));
        self.orch.attachment = Some(att);
        Ok(())
    }

    fn orch_boxes(&self) -> Vec<Value> {
        self.provider
            .list()
            .map(|recs| {
                recs.iter()
                    .map(|r| {
                        json!({
                            "name": r.spec.name.as_str(),
                            "state": r.state,
                            "size": r.spec.size,
                            "production": r.spec.labels.get("env").is_some_and(|v| v == "production")
                                || r.spec.labels.get("production").is_some_and(|v| v == "true"),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Answer the jobs the tool threads queued: the boxes, and plan-then-apply on the server's own provider. A change that
    /// cannot be undone is refused here too: no tool can confirm one.
    fn orch_answer_jobs(&mut self) {
        let mut jobs = Vec::new();
        if let Some(rx) = &self.orch.jobs {
            while let Ok(j) = rx.try_recv() {
                jobs.push(j);
            }
        }
        for (job, reply) in jobs {
            let out = match job {
                Job::List => Ok(Value::Array(self.orch_boxes())),
                Job::Plan(op) => {
                    let r = self.issue_plan(json!({ "operation": op }).to_string().as_bytes());
                    resp_value(r)
                }
                Job::Apply(id, plan) => {
                    let r = self.apply(
                        json!({ "plan_id": id, "plan": plan })
                            .to_string()
                            .as_bytes(),
                        // an agent's request is never a person's second factor
                        super::roles::StepUp::Needed,
                    );
                    resp_value(r)
                }
            };
            let _ = reply.send(out);
            self.version
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// One pass: answer box jobs, advance the orchestrations and their merge queues, act on worker boxes that are due.
    pub(super) fn tick_orchestrations(&mut self, now_ms: u64) {
        let Some(store) = self.runs.store.clone() else {
            return;
        };
        self.ensure_agent_mcp();
        // a tool call can arrive when nothing is open (an agent starting its first orchestration): always answer jobs
        self.orch_answer_jobs();
        self.tick_browser(now_ms);
        let open = match store.load() {
            Ok(b) => b.orchestrations.iter().any(|o| {
                matches!(o.state, OrchState::Active | OrchState::Paused)
                    || !o.sweep_boxes(now_ms).is_empty()
            }),
            Err(_) => false,
        };
        if !open {
            return;
        }
        self.orch_ensure_mcp();
        if now_ms < self.orch.next_tick_ms {
            return;
        }
        self.orch.next_tick_ms = now_ms + 1000;
        let boxes = self.orch_boxes();
        let running = |name: &str| {
            boxes
                .iter()
                .any(|b| b["name"] == name && b["state"] == "running")
        };
        self.orch_pick_merger(&store);
        let mut merger = self.orch.merger.take();
        let handles = store
            .load()
            .map(|b| {
                b.tasks
                    .iter()
                    .filter_map(|t| {
                        Some((t.id.clone(), (t.spec.engine.clone(), t.handle.clone()?)))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let mut host = std::mem::take(&mut self.runs.host);
        let mut chan = HostChannel {
            host: &mut host,
            handles,
        };
        if let Some(a) = &self.orch.attachment {
            // enrolment's roster, what the workers sent, key asks and the fabric: one round per tick
            a.tick(now_ms);
        }
        let hub = self.orch.hub.clone();
        let lanes = self.orch.lanes.clone();
        // what the workers reported over the hub comes in first: a finished commit joins its merge queue
        let hub_seen = hub.as_ref().and_then(|h| {
            h.with(now_ms, |hub, st| {
                hub.poll(st, now_ms);
                st.clone()
            })
        });
        let acts = self.runs_update(|b| {
            if let Some(st) = &hub_seen {
                ozbox_core::hub::merge::admit_results(b, st, now_ms);
            }
            let mut ready = |f: &ozbox_core::orch::Feature| running(&f.box_name);
            let acts = b.tick_orchestrations(&mut chan, &mut ready, now_ms);
            if let Some(m) = merger.as_deref_mut() {
                let ids: Vec<String> = b
                    .orchestrations
                    .iter()
                    .filter(|o| o.state == OrchState::Active && !o.merge_queue.is_empty())
                    .map(|o| o.id.clone())
                    .collect();
                for id in ids {
                    match &hub {
                        // over the hub: a lane runs the test on the reported commit, and the worker is told what the queue found
                        Some(h) => {
                            let commits = ozbox_core::hub::merge::reported_commits(b, &id);
                            h.with(now_ms, |hub, st| {
                                let step = {
                                    let mut hm = ozbox_core::hub::merge::HubMerger {
                                        inner: &mut *m,
                                        hub,
                                        st: &mut *st,
                                        lanes: &lanes,
                                        commits,
                                        now: now_ms,
                                    };
                                    merge_step(b, &id, &mut hm, now_ms)
                                };
                                if let Some(s) = step {
                                    let _ = ozbox_core::hub::merge::return_to_worker(
                                        hub, st, b, &id, &s, now_ms,
                                    );
                                }
                            });
                        }
                        None => {
                            merge_step(b, &id, m, now_ms);
                        }
                    }
                }
            }
            acts
        });
        self.runs.host = host;
        self.orch.merger = merger;
        if let (Some(h), Some(store)) = (&hub, self.runs.store.clone()) {
            let _ = crate::orch_tools::record_hub_audit(&store, h, "supervisor");
        }
        let Ok(acts) = acts else { return };
        for (oid, act) in acts {
            self.orch_box_action(&store, &oid, &act, now_ms);
        }
    }

    fn orch_pick_merger(&mut self, store: &ozbox_core::run::TaskStore) {
        let Ok(book) = store.load() else { return };
        let Some(o) = book
            .orchestrations
            .iter()
            .find(|o| o.state == OrchState::Active && !o.merge_queue.is_empty())
        else {
            return;
        };
        if self.orch.merger_box.as_deref() == Some(o.conductor_box.as_str())
            && self.orch.merger.is_some()
        {
            return;
        }
        self.orch.merger_box = Some(o.conductor_box.clone());
        self.orch.merger = Some(if self.simulated_metrics {
            Box::new(super::orch_merge::SimMerger)
        } else {
            let rec = self.boxes_quietly().and_then(|v| {
                v.into_iter()
                    .find(|r| r.spec.name.as_str() == o.conductor_box)
            });
            Box::new(super::orch_merge::DaemonMerger::new(
                Arc::clone(&self.agent),
                rec,
            ))
        });
    }

    /// Pause a merged feature's box, or destroy one this orchestration made after the retention days. Both go through
    /// plan-then-apply on the server's own provider; a box the person made themselves is never destroyed.
    fn orch_box_action(
        &mut self,
        store: &ozbox_core::run::TaskStore,
        oid: &str,
        act: &BoxAction,
        now_ms: u64,
    ) {
        let (fid, op, confirm) = match act {
            BoxAction::Pause { feature, box_name } => (
                feature.clone(),
                json!({ "op": "pause", "name": box_name }),
                None,
            ),
            BoxAction::Destroy { feature, box_name } => (
                feature.clone(),
                json!({ "op": "destroy", "name": box_name }),
                Some(box_name.clone()),
            ),
        };
        let planned = self.issue_plan(json!({ "operation": op }).to_string().as_bytes());
        let Ok(p) = resp_value(planned) else {
            // not possible now (the box is gone, or a rule refuses it): count it as done so it is not retried every second
            let _ = store.update(|b| {
                if let Some(o) = b.orchestration_mut(oid) {
                    o.box_done(&fid, act);
                }
            });
            return;
        };
        let mut body = json!({ "plan_id": p["plan_id"], "plan": p["plan"] });
        if let Some(c) = confirm {
            body["confirm_name"] = json!(c);
        }
        // the retention the person set is the authority for destroying a box this orchestration made
        let applied = self.apply(body.to_string().as_bytes(), super::roles::StepUp::Fresh);
        let _ = resp_value(applied);
        let _ = self.runs_update(|b| {
            if let Some(o) = b.orchestration_mut(oid) {
                o.box_done(&fid, act);
            }
            b.record(now_ms, "supervisor", "orchestration.box", None, oid);
        });
    }

    /// The tools for a call that is on the request loop: the boxes are a snapshot, and no box tool is offered.
    fn orch_tools_here(&self) -> Option<Tools> {
        let store = self.runs.store.clone()?;
        Some(
            Tools::new(store, Arc::new(SnapshotOps(self.orch_boxes())))
                .with_memory(self.memory_host.clone())
                .with_hub(self.orch.hub.clone())
                .with_fabric(self.orch.fabric.clone()),
        )
    }

    pub(super) fn orch_route(&mut self, req: &Req, rest: &[&str]) -> Resp {
        let store = match self.run_store() {
            Ok(s) => s,
            Err(r) => return r,
        };
        let who = self.who(req);
        let now = unix_ms();
        let m = req.method.as_str();
        let load = |store: &ozbox_core::run::TaskStore| {
            store
                .load()
                .map_err(|e| Resp::error(500, "store_unavailable", &e.to_string()))
        };
        match (m, rest) {
            ("GET", []) => {
                let book = match load(&store) {
                    Ok(b) => b,
                    Err(r) => return r,
                };
                let items: Vec<Value> = book
                    .orchestrations
                    .iter()
                    .rev()
                    .map(|o| orch_summary(&book, o, now))
                    .collect();
                Resp::json(
                    200,
                    &json!({ "source": if self.simulated_metrics { "simulated" } else { "live" }, "rev": book.rev, "items": items }),
                )
            }
            ("POST", []) => self.orch_start(req, &who, now),
            ("GET", ["settings"]) => match load(&store) {
                Ok(b) => Resp::json(200, &b.orch_settings),
                Err(r) => r,
            },
            ("PUT", ["settings"]) => {
                let s: OrchSettings = match serde_json::from_slice(&req.body) {
                    Ok(s) => s,
                    Err(e) => return bad(&format!("invalid request: {e}")),
                };
                if let Err(e) = s.validate() {
                    return bad(&e);
                }
                match self.runs_update(|b| {
                    b.orch_settings = s.clone();
                    b.record(now, &who, "orchestration.settings_changed", None, "");
                }) {
                    Ok(()) => Resp::json(200, &s),
                    Err(r) => r,
                }
            }
            ("POST", ["rules", "check"]) => {
                let b = match body_of(req) {
                    Ok(b) => b,
                    Err(r) => return r,
                };
                let text = text(&b, "rules").unwrap_or_default();
                let book = match load(&store) {
                    Ok(b) => b,
                    Err(r) => return r,
                };
                match parse_rules(&text) {
                    Ok(o) => Resp::json(
                        200,
                        &ozbox_core::orch::effective(&book.orch_settings, &[&o]),
                    ),
                    Err(e) => bad(&e),
                }
            }
            ("POST", ["mcp-token"]) => {
                let Some(server) = self.orch_ensure_mcp() else {
                    return Resp::error(
                        501,
                        "unavailable",
                        "the Oz Box tools could not start on this computer",
                    );
                };
                self.runs.host.set_mcp(Some(Arc::clone(&server)));
                let s = Session {
                    person: who.clone(),
                    role: Role::Person,
                };
                match server.issue(s, None, now, MAX_TOKEN_TTL_MS) {
                    Ok(i) => {
                        let _ = self.runs_update(|b| {
                            b.record(now, &who, "orchestration.token", None, "person agent")
                        });
                        // shown once: it is never stored in a readable form
                        Resp::json(
                            200,
                            &json!({ "url": i.url, "token": i.token, "expires_in_s": MAX_TOKEN_TTL_MS / 1000, "header": "Authorization: Bearer <token>" }),
                        )
                    }
                    Err(e) => Resp::error(500, "internal", &e),
                }
            }
            ("GET", [id]) => {
                let book = match load(&store) {
                    Ok(b) => b,
                    Err(r) => return r,
                };
                match book.orchestration(id) {
                    Some(o) => Resp::json(200, &orch_json(&book, o, now)),
                    None => Resp::error(404, "not_found", "there is no such orchestration"),
                }
            }
            ("POST", [id, verb @ ("pause" | "resume" | "stop")]) => {
                let (id, verb) = (id.to_string(), *verb);
                match self.runs_update(|b| match verb {
                    "pause" => b.halt_orchestration(&id, false, &who, now),
                    "stop" => b.halt_orchestration(&id, true, &who, now),
                    _ => b.resume_orchestration(&id, &who, now),
                }) {
                    Ok(Ok(())) => Resp::json(200, &json!({ "id": id, "ok": true })),
                    Ok(Err(e)) => orch_err(&e),
                    Err(r) => r,
                }
            }
            ("POST", [id, "budget"]) => {
                let b = match body_of(req) {
                    Ok(b) => b,
                    Err(r) => return r,
                };
                let Some(usd) = b
                    .get("add_usd")
                    .and_then(Value::as_f64)
                    .filter(|v| v.is_finite() && *v > 0.0 && *v <= 100_000.0)
                else {
                    return bad("add_usd: an amount more than zero");
                };
                let id = id.to_string();
                match self.runs_update(|bk| {
                    bk.add_orch_budget(&id, (usd * 100.0).round() as u64, &who, now)
                }) {
                    Ok(Ok(cap)) => Resp::json(200, &json!({ "id": id, "cap_cents": cap })),
                    Ok(Err(e)) => orch_err(&e),
                    Err(r) => r,
                }
            }
            ("POST", [id, "features"]) => {
                let mut b = match body_of(req) {
                    Ok(b) => b,
                    Err(r) => return r,
                };
                b["orchestration"] = json!(id);
                self.orch_tool_call(&who, "task_start", &b, now)
            }
            ("POST", [id, "claims"]) | ("POST", [id, "contracts"]) => {
                let mut b = match body_of(req) {
                    Ok(b) => b,
                    Err(r) => return r,
                };
                b["orchestration"] = json!(id);
                let tool = if rest[1] == "claims" {
                    "claims_declare"
                } else {
                    "contract_publish"
                };
                self.orch_tool_call(&who, tool, &b, now)
            }
            ("POST", [id, "merge", fid]) => {
                let b = json!({ "orchestration": id, "feature": fid });
                self.orch_tool_call(&who, "merge_queue", &b, now)
            }
            ("POST", [id, "features", fid, verb @ ("pause" | "stop")]) => {
                let (id, fid, pause) = (id.to_string(), fid.to_string(), *verb == "pause");
                match self.runs_update(|b| {
                    if b.orchestration(&id).is_some_and(|o| o.requested_by != who) {
                        return Err(ozbox_core::orch::OrchError::NoOrchestration);
                    }
                    b.halt_feature(&id, &fid, pause, now)?;
                    b.record(
                        now,
                        &who,
                        if pause {
                            "orchestration.feature_paused"
                        } else {
                            "orchestration.feature_stopped"
                        },
                        None,
                        &format!("{id}/{fid}"),
                    );
                    Ok(())
                }) {
                    Ok(Ok(())) => Resp::json(200, &json!({ "id": id, "feature": fid, "ok": true })),
                    Ok(Err(e)) => orch_err(&e),
                    Err(r) => r,
                }
            }
            ("POST", [id, "features", fid, "resume"]) => {
                let (id, fid) = (id.to_string(), fid.to_string());
                match self.runs_update(|b| {
                    let paused = b
                        .orchestration(&id)
                        .and_then(|o| o.feature(&fid))
                        .is_some_and(|f| {
                            matches!(
                                f.state,
                                FeatureState::Paused | FeatureState::Stopped | FeatureState::Failed
                            )
                        });
                    if !paused {
                        return Err(ozbox_core::orch::OrchError::Conflict(
                            "only a paused, stopped or failed feature can be resumed".into(),
                        ));
                    }
                    b.resume_feature(&id, &fid, now)
                }) {
                    Ok(Ok(t)) => {
                        Resp::json(200, &json!({ "id": id, "feature": fid, "task_id": t }))
                    }
                    Ok(Err(e)) => orch_err(&e),
                    Err(r) => r,
                }
            }
            ("POST", [id, "features", fid, "reassign"]) => {
                let b = match body_of(req) {
                    Ok(b) => b,
                    Err(r) => return r,
                };
                let Some(to) = text(&b, "box") else {
                    return bad("box: the new worker box");
                };
                let (id, fid) = (id.to_string(), fid.to_string());
                match self.runs_update(|bk| {
                    bk.halt_feature(&id, &fid, true, now).ok();
                    let o = bk
                        .orchestration_mut(&id)
                        .ok_or(ozbox_core::orch::OrchError::NoOrchestration)?;
                    o.reassign(&fid, &to, now)
                }) {
                    Ok(Ok(())) => Resp::json(200, &json!({ "id": id, "feature": fid, "box": to })),
                    Ok(Err(e)) => orch_err(&e),
                    Err(r) => r,
                }
            }
            // the demo has no agent that asks, so a question can be made by hand to try the answer flow
            ("POST", ["demo", id, "ask"]) if self.simulated_metrics => {
                let b = match body_of(req) {
                    Ok(b) => b,
                    Err(r) => return r,
                };
                let (Some(f), Some(t)) = (text(&b, "feature"), text(&b, "text")) else {
                    return bad("feature and text are required");
                };
                let person = b.get("for_person").and_then(Value::as_bool).unwrap_or(true);
                let id = id.to_string();
                match self.runs_update(|bk| {
                    let o = bk
                        .orchestration_mut(&id)
                        .ok_or(ozbox_core::orch::OrchError::NoOrchestration)?;
                    let to = if person { "person" } else { "conductor" };
                    o.post(
                        now,
                        &format!("feature:{f}"),
                        to,
                        ozbox_core::orch::MsgKind::Question,
                        &t,
                        None,
                        person,
                    )
                }) {
                    Ok(Ok(seq)) => Resp::json(200, &json!({ "question": seq })),
                    Ok(Err(e)) => orch_err(&e),
                    Err(r) => r,
                }
            }
            ("POST", [id, "answer"]) => {
                let b = match body_of(req) {
                    Ok(b) => b,
                    Err(r) => return r,
                };
                let (Some(q), Some(t)) =
                    (b.get("question").and_then(Value::as_u64), text(&b, "text"))
                else {
                    return bad("question and text are required");
                };
                let id = id.to_string();
                match self.runs_update(|bk| {
                    let o = bk
                        .orchestration_mut(&id)
                        .ok_or(ozbox_core::orch::OrchError::NoOrchestration)?;
                    let r = o.answer(now, q, true, &t)?;
                    bk.record(now, &who, "orchestration.answered", None, &id);
                    Ok(r)
                }) {
                    Ok(Ok(seq)) => Resp::json(200, &json!({ "answered": q, "message": seq })),
                    Ok(Err(e)) => orch_err(&e),
                    Err(r) => r,
                }
            }
            ("POST", [id, "message"]) => {
                let b = match body_of(req) {
                    Ok(b) => b,
                    Err(r) => return r,
                };
                let (Some(f), Some(t)) = (text(&b, "feature"), text(&b, "text")) else {
                    return bad("feature and text are required");
                };
                let id = id.to_string();
                match self.runs_update(|bk| {
                    let o = bk
                        .orchestration_mut(&id)
                        .ok_or(ozbox_core::orch::OrchError::NoOrchestration)?;
                    let seq = o.post(
                        now,
                        "person",
                        &format!("feature:{f}"),
                        ozbox_core::orch::MsgKind::Instruction,
                        &t,
                        None,
                        false,
                    )?;
                    if let Some(x) = o.feature_mut(&f) {
                        x.resume_pending = true;
                    }
                    Ok(seq)
                }) {
                    Ok(Ok(seq)) => Resp::json(200, &json!({ "message": seq })),
                    Ok(Err(e)) => orch_err(&e),
                    Err(r) => r,
                }
            }
            _ => Resp::error(404, "not_found", "no such endpoint"),
        }
    }

    fn orch_tool_call(&mut self, who: &str, tool: &str, args: &Value, now: u64) -> Resp {
        let Some(tools) = self.orch_tools_here() else {
            return Resp::error(
                501,
                "tasks_unavailable",
                "runs need a task store on this server",
            );
        };
        let s = Session {
            person: who.to_string(),
            role: Role::Person,
        };
        let r = tools.call(&s, tool, args, now);
        self.version
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        match r {
            Ok(v) => Resp::json(200, &v),
            Err(e) => tool_resp(&e),
        }
    }

    fn orch_start(&mut self, req: &Req, who: &str, now: u64) -> Resp {
        let b = match body_of(req) {
            Ok(b) => b,
            Err(r) => return r,
        };
        let Some(goal) = text(&b, "goal") else {
            return bad("goal: say what the orchestration is for");
        };
        let Some(conductor) = text(&b, "conductor_box") else {
            return bad("conductor_box: the box that holds the main branch");
        };
        let rules = match text(&b, "rules") {
            Some(t) => match parse_rules(&t) {
                Ok(o) => o,
                Err(e) => return bad(&e),
            },
            None => Overrides::default(),
        };
        let ask = Overrides {
            max_workers: b
                .get("max_workers")
                .and_then(Value::as_u64)
                .and_then(|n| u8::try_from(n).ok()),
            max_sub_agents: b
                .get("max_sub_agents")
                .and_then(Value::as_u64)
                .and_then(|n| u8::try_from(n).ok()),
            spend_cap_cents: b
                .get("max_spend_usd")
                .and_then(Value::as_f64)
                .filter(|v| v.is_finite() && *v > 0.0)
                .map(|v| (v * 100.0).round() as u64),
            ..Default::default()
        };
        if !self
            .orch_boxes()
            .iter()
            .any(|x| x["name"] == conductor.as_str())
        {
            return Resp::error(
                404,
                "not_found",
                &format!("there is no box named {conductor}"),
            );
        }
        let conduct = b
            .get("start_conductor")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let extra = text(&b, "prompt").unwrap_or_default();
        let who = who.to_string();
        match self.runs_update(|bk| {
            let id = bk.start_orchestration(&goal, &who, &conductor, &[&rules, &ask], now)?;
            let task = if conduct {
                Some(bk.start_conductor(&id, &extra, now)?)
            } else {
                None
            };
            Ok::<_, ozbox_core::orch::OrchError>((id, task))
        }) {
            Ok(Ok((id, task))) => {
                self.orch_ensure_mcp();
                Resp::json(201, &json!({ "id": id, "conductor_task": task }))
            }
            Ok(Err(e)) => orch_err(&e),
            Err(r) => r,
        }
    }
}

/// A server answer as a value: its JSON on success, its message on failure.
fn resp_value(r: Resp) -> Result<Value, String> {
    let v: Value = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
    if (200..300).contains(&r.status) {
        Ok(v)
    } else {
        Err(v["message"]
            .as_str()
            .unwrap_or("the server refused that")
            .to_string())
    }
}

/// Whether the store has anything for the supervisor loop to keep ticking for on behalf of orchestrations.
pub fn busy(b: &Book) -> bool {
    b.orchestrations.iter().any(|o| {
        o.state == OrchState::Active
            && (o.features.iter().any(|f| f.state.is_open()) || !o.merge_queue.is_empty())
    }) || b.tasks.iter().any(|t| {
        matches!(t.state, TaskState::Queued)
            && matches!(
                t.spec.origin,
                ozbox_core::run::RunOrigin::Orchestration { .. }
            )
    })
}

#[cfg(test)]
mod tests;
