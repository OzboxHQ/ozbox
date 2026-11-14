//! The Oz Box tools an agent calls (over MCP, `crate::mcp`) and the REST and CLI layers call the same way.
//!
//! One function, [`Tools::call`], runs a tool for a [`Session`]. A session is bound to a role, and the role decides which
//! tools exist at all and what each may touch:
//!
//! - **Conductor** (the agent on the main box, bound to one orchestration) and **person** (an agent the person connected
//!   themselves, which names the orchestration in each call) get the fleet and orchestration tools. They act as
//!   `conductor:<id>`, never as the person: whatever the person must decide stays with the person.
//! - **Worker** (an agent on a worker box, bound to one feature) gets six tools: ask, report, finish, and the claims and
//!   contracts of its own feature.
//! - **Every role** also gets the five memory and skills tools of [`crate::memory_tools`], bound to the session's own scopes.
//!
//! There is no tool that runs a command, opens a shell, or returns a key: the list is the whole surface, and a test
//! holds it. Box operations are plan-then-apply (ADR 0002) through [`BoxOps`] and only ever inside the limits: a plan whose
//! risk is high is refused here and left to the person.

use std::collections::BTreeMap;
use std::sync::Arc;

use ozbox_core::orch::{
    ClaimOutcome, Feature, FeatureReq, FeatureState, MsgKind, OrchError, OrchState, Orchestration,
    WorkerKind, WorkerPref,
};
use ozbox_core::orch_rules::{parse_rules, Overrides};
use ozbox_core::run::{ApprovalState, Book, RunCaps, TaskStore};
use ozbox_core::supervisor;
use ozbox_core::{Plan, Risk};
use serde_json::{json, Value};

/// What the tools need from the provider: the boxes, and plan-then-apply. The server implements it on its own thread;
/// tests use a fake.
pub trait BoxOps: Send + Sync {
    fn list(&self) -> Result<Vec<Value>, String>;
    /// A plan for an operation (`{"op": "clone", ...}`): the server's own answer with `plan_id` and `plan`.
    fn plan(&self, operation: Value) -> Result<Value, String>;
    /// Apply a plan this server issued. Never confirms a high-risk change: that is the person's.
    fn apply(&self, plan_id: &str, plan: &Value) -> Result<Value, String>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Role {
    /// A run that has the host tools for its own box and none of the orchestration tools.
    Agent,
    Person,
    Conductor {
        orch: String,
    },
    Worker {
        orch: String,
        feature: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub person: String,
    pub role: Role,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolError {
    /// Not allowed here (policy, a limit, a conflict). The text says what to do instead.
    Refused(String),
    Invalid(String),
    NotFound(String),
    Failed(String),
}

impl ToolError {
    pub fn message(&self) -> &str {
        match self {
            ToolError::Refused(s)
            | ToolError::Invalid(s)
            | ToolError::NotFound(s)
            | ToolError::Failed(s) => s,
        }
    }
}

impl From<OrchError> for ToolError {
    fn from(e: OrchError) -> Self {
        match e {
            OrchError::NoOrchestration | OrchError::NoFeature => ToolError::NotFound(e.to_string()),
            OrchError::Invalid(m) => ToolError::Invalid(m),
            OrchError::Limit(m) | OrchError::Conflict(m) | OrchError::NotAllowed(m) => {
                ToolError::Refused(m)
            }
        }
    }
}

type R = Result<Value, ToolError>;

/// The tools of a conductor (and of a person's own agent).
pub const CONDUCTOR_TOOLS: [&str; 18] = [
    "fleet_boxes",
    "box_clone",
    "box_create",
    "box_pause",
    "orchestration_start",
    "task_start",
    "task_status",
    "task_message",
    "task_stop",
    "claims_declare",
    "claims_check",
    "contract_publish",
    "contract_read",
    "approvals_pending",
    "approvals_decide",
    "merge_queue",
    "merge_status",
    "budget_status",
];

/// The tools of a worker.
pub const WORKER_TOOLS: [&str; 6] = [
    "worker_ask",
    "worker_status",
    "worker_done",
    "claims_declare",
    "claims_check",
    "contract_read",
];

pub fn tool_names(role: &Role) -> Vec<&'static str> {
    let mut v = match role {
        Role::Agent => Vec::new(),
        Role::Worker { .. } => WORKER_TOOLS.to_vec(),
        Role::Conductor { .. } => CONDUCTOR_TOOLS
            .iter()
            .copied()
            .filter(|n| *n != "orchestration_start")
            .collect(),
        Role::Person => CONDUCTOR_TOOLS.to_vec(),
    };
    // Every role can read approved memory and skills and propose a note (crate::memory_tools).
    v.extend(crate::memory_tools::MEMORY_TOOLS);
    v
}

fn prop(kind: &str, desc: &str) -> Value {
    json!({ "type": kind, "description": desc })
}

fn def(name: &str, desc: &str, props: Vec<(&str, Value)>, required: &[&str]) -> Value {
    let mut p = serde_json::Map::new();
    for (k, v) in props {
        p.insert(k.to_string(), v);
    }
    json!({
        "name": name,
        "description": desc,
        "inputSchema": { "type": "object", "properties": p, "required": required },
    })
}

fn orch_prop() -> (&'static str, Value) {
    (
        "orchestration",
        prop(
            "string",
            "The orchestration id. Needed only when you are not the conductor of one.",
        ),
    )
}

/// The definitions `tools/list` returns for a role.
pub fn tool_defs(role: &Role) -> Vec<Value> {
    let all = |name: &str| -> Value {
        match name {
            "fleet_boxes" => def("fleet_boxes", "List the boxes of the fleet with their state and size, and which are this orchestration's workers.", vec![orch_prop()], &[]),
            "box_clone" => def("box_clone", "Make a worker box as a copy of the conductor's box (plan, then apply, inside the limits). Set dry_run to see the plan only.", vec![orch_prop(), ("to", prop("string", "The new box's name.")), ("from", prop("string", "A box to copy; default the conductor's box.")), ("dry_run", prop("boolean", "Show the plan and change nothing."))], &["to"]),
            "box_create" => def("box_create", "Make a new worker box from scratch, when the policy allows new boxes.", vec![orch_prop(), ("name", prop("string", "The new box's name.")), ("size", prop("string", "XS, S, M, L, XL, XXL, GPU-S or GPU-L.")), ("dry_run", prop("boolean", "Show the plan and change nothing."))], &["name"]),
            "box_pause" => def("box_pause", "Pause one of this orchestration's worker boxes. Never the conductor's box.", vec![orch_prop(), ("box", prop("string", "The worker box.")), ("dry_run", prop("boolean", "Show the plan and change nothing."))], &["box"]),
            "orchestration_start" => def("orchestration_start", "Start an orchestration: a goal, the conductor box and the limits. Limits can only be tighter than the person's settings.", vec![("goal", prop("string", "What the whole job is.")), ("conductor_box", prop("string", "The box holding the main branch.")), ("rules", prop("string", "The text of an ozbox.orchestration.md file, if there is one.")), ("max_workers", prop("integer", "Worker boxes at once.")), ("max_sub_agents", prop("integer", "Sub-agents per worker.")), ("max_spend_usd", prop("number", "One spend cap for the whole orchestration.")), ("start_conductor", prop("boolean", "Also start a conductor run on that box."))], &["goal", "conductor_box"]),
            "task_start" => def("task_start", "Give a feature to a worker box: its brief, the files it owns and the contracts it builds against. Set dry_run to check it first.", vec![orch_prop(), ("title", prop("string", "A short name for the feature.")), ("brief", prop("string", "What to build.")), ("box", prop("string", "The worker box (one made with box_clone).")), ("claims", json!({"type":"array","items":{"type":"string"},"description":"Files, directories or globs the worker owns."})), ("contracts", json!({"type":"array","items":{"type":"string"},"description":"Contracts to build against."})), ("engine", prop("string", "The agent engine; default the orchestration's.")), ("model", prop("string", "provider/model for this worker.")), ("sub_agents", prop("integer", "Sub-agents the worker may use at once.")), ("max_spend_usd", prop("number", "A cap for this worker.")), ("max_minutes", prop("integer", "A time cap for this worker.")), ("branch", prop("string", "The feature branch.")), ("repo", prop("string", "The repository under /work/repos.")), ("keep", prop("boolean", "Keep the worker box after the merge.")), ("transport", prop("string", "ssh (default) or hub. Hub hands the task over the worker channel and is refused on a box that has none.")), ("dry_run", prop("boolean", "Check and show, change nothing."))], &["title", "brief"]),
            "task_status" => def("task_status", "See a feature (or all of them), the open questions and the conductor's new messages.", vec![orch_prop(), ("feature", prop("string", "A feature id; leave out for all.")), ("since", prop("integer", "Only messages after this number."))], &[]),
            "task_message" => def("task_message", "Send a worker an instruction, or answer its question. A question marked for the person cannot be answered here.", vec![orch_prop(), ("feature", prop("string", "The feature id.")), ("text", prop("string", "The message.")), ("answer_to", prop("integer", "The question's number, to answer it.")), ("escalate", prop("boolean", "Pass the question up to the person instead of answering."))], &["text"]),
            "task_stop" => def("task_stop", "Stop or pause a feature's worker. Its work is saved to its branch first.", vec![orch_prop(), ("feature", prop("string", "The feature id.")), ("mode", prop("string", "stop or pause."))], &["feature"]),
            "claims_declare" => def("claims_declare", "Declare the files and areas a feature owns. An overlap with another feature is refused or sequenced.", vec![orch_prop(), ("feature", prop("string", "The feature id (a worker's own is implied).")), ("claims", json!({"type":"array","items":{"type":"string"}}))], &["claims"]),
            "claims_check" => def("claims_check", "Check whether a feature may edit some paths. Call it before editing anything you do not own.", vec![orch_prop(), ("feature", prop("string", "The feature id (a worker's own is implied).")), ("paths", json!({"type":"array","items":{"type":"string"}}))], &["paths"]),
            "contract_publish" => def("contract_publish", "Publish a shared contract (an API, types, a schema) or a new version of one. Features that use it are told.", vec![orch_prop(), ("name", prop("string", "The contract's name.")), ("kind", prop("string", "api, types, schema or doc.")), ("body", prop("string", "The contract text. Never put a secret in it.")), ("paths", json!({"type":"array","items":{"type":"string"},"description":"Files it describes; workers cannot claim them."})), ("draft", prop("boolean", "A draft cannot be built against yet."))], &["name", "kind", "body"]),
            "contract_read" => def("contract_read", "Read a contract, or list them all.", vec![orch_prop(), ("id", prop("string", "The contract id; leave out to list."))], &[]),
            "approvals_pending" => def("approvals_pending", "Requests waiting for a decision, and whether you may decide each.", vec![orch_prop()], &[]),
            "approvals_decide" => def("approvals_decide", "Decide a request the policy lets you decide. Risky ones (a protected branch, production, a message to someone outside, spend above the cap) are the person's and are refused here.", vec![orch_prop(), ("id", prop("string", "The request id.")), ("approve", prop("boolean", "True to approve, false to deny."))], &["id", "approve"]),
            "merge_queue" => def("merge_queue", "Put a finished feature in the merge queue. The queue rebases it, runs the tests, gets the approval the policy needs and merges.", vec![orch_prop(), ("feature", prop("string", "The feature id."))], &["feature"]),
            "merge_status" => def("merge_status", "The merge queue and where each feature in it is.", vec![orch_prop()], &[]),
            "budget_status" => def("budget_status", "What the orchestration has spent against its one cap.", vec![orch_prop()], &[]),
            "worker_ask" => def("worker_ask", "Ask the conductor (or the person) a question you need answered before you go on. Then write down where you stopped, commit, and end your turn: you are resumed with the answer.", vec![("question", prop("string", "The question.")), ("for_person", prop("boolean", "Only the person may answer (a risky decision)."))], &["question"]),
            "worker_status" => def("worker_status", "Report progress, and read the messages sent to you since last time.", vec![("text", prop("string", "A short progress note, optional.")), ("since", prop("integer", "Only messages after this number."))], &[]),
            "worker_done" => def("worker_done", "Say the feature is complete and its tests pass. It joins the merge queue when the conductor queues it.", vec![("summary", prop("string", "What was built."))], &[]),
            other => crate::memory_tools::tool_def(other),
        }
    };
    tool_names(role).into_iter().map(all).collect()
}

fn s<'a>(a: &'a Value, k: &str) -> Option<&'a str> {
    a.get(k)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
}

fn strs(a: &Value, k: &str) -> Vec<String> {
    a.get(k)
        .and_then(Value::as_array)
        .map(|v| {
            v.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn flag(a: &Value, k: &str) -> bool {
    a.get(k).and_then(Value::as_bool).unwrap_or(false)
}

fn int(a: &Value, k: &str) -> Option<u64> {
    a.get(k).and_then(Value::as_u64)
}

fn usd_to_cents(v: f64) -> Option<u64> {
    (v.is_finite() && v > 0.0 && v <= 100_000.0).then(|| (v * 100.0).round() as u64)
}

fn need<'a>(a: &'a Value, k: &str) -> Result<&'a str, ToolError> {
    s(a, k).ok_or_else(|| ToolError::Invalid(format!("{k} is required")))
}

pub struct Tools {
    pub store: TaskStore,
    pub ops: Arc<dyn BoxOps>,
    /// Memory and skills, when the dashboard has them (the five tools of `crate::memory_tools`).
    pub memory: Option<Arc<crate::memory_tools::MemoryHost>>,
    /// The hub (ADR 0042), when this box has a channel to workers. None on every box today: `transport: hub` is then refused
    /// by name, and `ssh` (the laptop-driven route) is the only one.
    pub hub: Option<Arc<ozbox_core::hub::engine::HubService>>,
}

fn store_err(e: std::io::Error) -> ToolError {
    ToolError::Failed(format!("the task store could not be used: {e}"))
}

impl Tools {
    pub fn new(store: TaskStore, ops: Arc<dyn BoxOps>) -> Self {
        Self {
            store,
            ops,
            memory: None,
            hub: None,
        }
    }

    // the server attaches a hub once a worker channel exists (ADR 0042); until then only the tests do
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn with_hub(mut self, hub: Option<Arc<ozbox_core::hub::engine::HubService>>) -> Self {
        self.hub = hub;
        self
    }

    pub fn with_memory(mut self, memory: Option<Arc<crate::memory_tools::MemoryHost>>) -> Self {
        self.memory = memory;
        self
    }

    /// The orchestration this call is about, and who may act on it.
    fn orch_of(&self, s: &Session, a: &Value, book: &Book) -> Result<String, ToolError> {
        let id = match &s.role {
            Role::Conductor { orch } | Role::Worker { orch, .. } => orch.clone(),
            Role::Agent => {
                return Err(ToolError::NotFound("there is no such orchestration".into()))
            }
            Role::Person => match self::s(a, "orchestration") {
                Some(x) => x.to_string(),
                None => {
                    let open: Vec<_> = book
                        .orchestrations
                        .iter()
                        .filter(|o| o.requested_by == s.person && o.state == OrchState::Active)
                        .collect();
                    match open.as_slice() {
                        [one] => one.id.clone(),
                        _ => return Err(ToolError::Invalid("name the orchestration".into())),
                    }
                }
            },
        };
        match book.orchestration(&id) {
            Some(o) if o.requested_by == s.person => Ok(id),
            _ => Err(ToolError::NotFound("there is no such orchestration".into())),
        }
    }

    /// The feature a call is about: a worker's own, or the one a conductor names.
    fn feature_of(&self, s: &Session, a: &Value) -> Result<String, ToolError> {
        match &s.role {
            Role::Worker { feature, .. } => {
                if let Some(f) = self::s(a, "feature") {
                    if f != feature {
                        return Err(ToolError::Refused(
                            "a worker can act only on its own feature".into(),
                        ));
                    }
                }
                Ok(feature.clone())
            }
            _ => need(a, "feature").map(str::to_string),
        }
    }

    pub fn call(&self, s: &Session, name: &str, a: &Value, now: u64) -> R {
        self.call_as(s, None, name, a, now)
    }

    /// As [`Tools::call`], for a caller that came through the terminal door: `host` carries its enrolment's actor, program,
    /// pid and session code, so the permission card and the waiting answer name it the way a host tool's do, and
    /// `who` is the code-based name a memory proposal's provenance is credited to (the person's own agent did not write it).
    pub fn call_as(
        &self,
        s: &Session,
        host: Option<&crate::mcp::HostScope>,
        name: &str,
        a: &Value,
        now: u64,
    ) -> R {
        if !tool_names(&s.role).contains(&name) {
            return Err(ToolError::NotFound(format!("there is no tool {name}")));
        }
        let who = host
            .and_then(|h| h.code.as_deref())
            .map(|c| format!("terminal-{c}"));
        let who = who.as_deref();
        self.permit(s, host, name, now)?;
        match name {
            "fleet_boxes" => self.fleet_boxes(s, a),
            "box_clone" | "box_create" | "box_pause" => self.box_tool(s, name, a, now),
            "orchestration_start" => self.orchestration_start(s, a, now),
            "task_start" => self.task_start(s, a, now),
            "task_status" => self.task_status(s, a, now),
            "task_message" => self.task_message(s, a, now),
            "task_stop" => self.task_stop(s, a, now),
            "claims_declare" => self.claims_declare(s, a, now),
            "claims_check" => self.claims_check(s, a),
            "contract_publish" => self.contract_publish(s, a, now),
            "contract_read" => self.contract_read(s, a),
            "approvals_pending" => self.approvals_pending(s, a, now),
            "approvals_decide" => self.approvals_decide(s, a, now),
            "merge_queue" => self.merge_queue(s, a, now),
            "merge_status" => self.merge_status(s, a),
            "budget_status" => self.budget_status(s, a),
            "worker_ask" => self.worker_ask(s, a, now),
            "worker_status" => self.worker_status(s, a, now),
            "worker_done" => self.worker_done(s, a, now),
            n if crate::memory_tools::MEMORY_TOOLS.contains(&n) => {
                crate::memory_tools::call(self, s, who, name, a, now)
            }
            _ => Err(ToolError::NotFound(format!("there is no tool {name}"))),
        }
    }

    /// The permission engine decides every call, and the decision is in the audit chain. These tools are governed by the
    /// orchestration's own policy (limits, claims, the merge queue), so the mode alone never asks about them; a rule, plan-only,
    /// the production gate and an explicit ask rule all still apply.
    fn permit(
        &self,
        s: &Session,
        host: Option<&crate::mcp::HostScope>,
        name: &str,
        now: u64,
    ) -> Result<(), ToolError> {
        let writes = !matches!(
            name,
            "fleet_boxes"
                | "task_status"
                | "claims_check"
                | "contract_read"
                | "approvals_pending"
                | "merge_status"
                | "budget_status"
        );
        let (orchestration, actor) = match &s.role {
            Role::Conductor { orch } | Role::Worker { orch, .. } => (
                Some(orch.clone()),
                ozbox_core::permissions::ActorKind::Agent,
            ),
            Role::Person | Role::Agent => (None, ozbox_core::permissions::ActorKind::Mcp),
        };
        // a caller that came through the terminal door is a program the person has to be able to tell from another: it is
        // gated as the door's actor, with its program, pid and code, exactly as a host tool's call is
        let terminal = host.filter(|h| {
            matches!(s.role, Role::Person | Role::Agent)
                && h.actor.is_terminal()
                && h.session.is_some()
        });
        let actor = terminal.map_or(actor, |h| h.actor);
        let call = ozbox_core::tool_gate::ToolCall {
            session_key: terminal
                .and_then(|h| h.session.clone())
                .unwrap_or_else(|| actor_of(s)),
            person: s.person.clone(),
            actor,
            box_name: None,
            run_id: None,
            orchestration,
            env: ozbox_core::permissions::Environment::Sandbox,
            tool: name.to_string(),
            server: "orchestration".to_string(),
            writes: Some(writes),
            path: None,
            command: None,
            sensitive: false,
            summary: String::new(),
            baseline_allow: true,
            person_required: false,
            program: terminal.and_then(|h| h.program.clone()),
            program_pid: terminal.and_then(|h| h.program_pid),
            session_code: terminal.and_then(|h| h.code.clone()),
        };
        match self
            .store
            .update(|b| ozbox_core::tool_gate::gate(b, &call, now))
            .map_err(store_err)?
        {
            ozbox_core::tool_gate::Verdict::Run { .. } => Ok(()),
            ozbox_core::tool_gate::Verdict::Refuse(r) => Err(ToolError::Refused(r.message())),
            ozbox_core::tool_gate::Verdict::Wait { approval_id } => {
                let which = match (call.actor.is_terminal(), call.session_code.as_deref()) {
                    (true, Some(code)) => format!(" The card names this session {code}."),
                    _ => String::new(),
                };
                Err(ToolError::Refused(format!(
                    "A rule says a person must approve this tool first (request {approval_id}, in Approvals).{which} Ask again once it is approved."
                )))
            }
        }
    }

    /// Change one orchestration as one locked step. The closure may refuse; a refusal changes nothing.
    fn with_orch<T>(
        &self,
        s: &Session,
        a: &Value,
        now: u64,
        audit: Option<&str>,
        f: impl FnOnce(&mut Book, &str) -> Result<T, ToolError>,
    ) -> Result<T, ToolError> {
        let actor = actor_of(s);
        let out = self
            .store
            .update(|book| {
                let id = self.orch_of(s, a, book)?;
                let r = f(book, &id)?;
                if let Some(what) = audit {
                    book.record(
                        now,
                        &actor,
                        "orchestration.tool",
                        None,
                        &format!("{what} {id}"),
                    );
                }
                Ok::<_, ToolError>(r)
            })
            .map_err(store_err)?;
        out
    }

    fn read_orch<T>(
        &self,
        s: &Session,
        a: &Value,
        f: impl FnOnce(&Book, &Orchestration) -> Result<T, ToolError>,
    ) -> Result<T, ToolError> {
        let book = self.store.load().map_err(store_err)?;
        let id = self.orch_of(s, a, &book)?;
        let o = book
            .orchestration(&id)
            .ok_or_else(|| ToolError::NotFound("there is no such orchestration".into()))?;
        f(&book, o)
    }

    // ---- fleet and boxes -------------------------------------------------------------------------------------------

    fn fleet_boxes(&self, s: &Session, a: &Value) -> R {
        let boxes = self.ops.list().map_err(ToolError::Failed)?;
        let book = self.store.load().map_err(store_err)?;
        let o = self
            .orch_of(s, a, &book)
            .ok()
            .and_then(|id| book.orchestration(&id).cloned());
        let items: Vec<Value> = boxes
            .into_iter()
            .map(|mut b| {
                let name = b["name"].as_str().unwrap_or("").to_string();
                let role = match &o {
                    Some(o) if o.conductor_box == name => "conductor",
                    Some(o)
                        if o.features
                            .iter()
                            .any(|f| f.state.is_open() && f.box_name == name) =>
                    {
                        "worker"
                    }
                    Some(o) if o.spare_boxes.contains(&name) => "spare",
                    _ => "other",
                };
                if let Some(m) = b.as_object_mut() {
                    m.insert("role".into(), json!(role));
                }
                b
            })
            .collect();
        Ok(json!({ "boxes": items }))
    }

    fn box_tool(&self, s: &Session, name: &str, a: &Value, now: u64) -> R {
        let dry = flag(a, "dry_run");
        // what is asked, checked against this orchestration's policy before any plan is made
        let (op, target, spare): (Value, String, bool) = {
            let book = self.store.load().map_err(store_err)?;
            let id = self.orch_of(s, a, &book)?;
            let o = book
                .orchestration(&id)
                .ok_or_else(|| ToolError::NotFound("there is no such orchestration".into()))?;
            if o.state != OrchState::Active {
                return Err(ToolError::Refused("this orchestration is paused".into()));
            }
            let existing: Vec<String> = self
                .ops
                .list()
                .map_err(ToolError::Failed)?
                .iter()
                .filter_map(|b| b["name"].as_str().map(str::to_string))
                .collect();
            match name {
                "box_clone" | "box_create" => {
                    let to = need(a, if name == "box_clone" { "to" } else { "name" })?.to_string();
                    ozbox_core::BoxName::new(to.clone())
                        .map_err(|e| ToolError::Invalid(e.to_string()))?;
                    if existing.contains(&to) {
                        return Err(ToolError::Refused(format!(
                            "a box named {to} already exists"
                        )));
                    }
                    if to == o.conductor_box {
                        return Err(ToolError::Invalid("a worker needs its own box".into()));
                    }
                    if o.open_workers() >= usize::from(o.policy.max_workers) {
                        return Err(ToolError::Refused(format!(
                            "at most {} worker boxes at once here",
                            o.policy.max_workers
                        )));
                    }
                    if name == "box_clone" {
                        let from = self::s(a, "from").unwrap_or(&o.conductor_box).to_string();
                        let mine = from == o.conductor_box
                            || o.features.iter().any(|f| f.box_name == from)
                            || o.spare_boxes.contains(&from);
                        if !mine || !existing.contains(&from) {
                            return Err(ToolError::Refused(
                                "copy the conductor's box or one of this orchestration's boxes"
                                    .into(),
                            ));
                        }
                        (json!({ "op": "clone", "from": from, "to": to }), to, true)
                    } else {
                        if !o.policy.may_create_boxes {
                            return Err(ToolError::Refused(
                                "this orchestration may only use clones of the conductor's box"
                                    .into(),
                            ));
                        }
                        let size = self::s(a, "size").unwrap_or("M");
                        (
                            json!({ "op": "create", "spec": { "name": to, "size": size } }),
                            to,
                            true,
                        )
                    }
                }
                _ => {
                    let b = need(a, "box")?.to_string();
                    let mine =
                        o.features.iter().any(|f| f.box_name == b) || o.spare_boxes.contains(&b);
                    if b == o.conductor_box || !mine {
                        return Err(ToolError::Refused(
                            "only this orchestration's worker boxes can be paused here".into(),
                        ));
                    }
                    (json!({ "op": "pause", "name": b }), b, false)
                }
            }
        };
        let planned = self.ops.plan(op).map_err(ToolError::Refused)?;
        let plan_id = planned["plan_id"].as_str().unwrap_or("").to_string();
        let risk = serde_json::from_value::<Plan>(planned["plan"].clone())
            .ok()
            .and_then(|p| p.max_risk());
        let summary = planned["plan"]["changes"].clone();
        if risk == Some(Risk::High) {
            return Err(ToolError::Refused(
                "that change cannot be undone, so it is the person's to confirm".into(),
            ));
        }
        if dry {
            return Ok(
                json!({ "applied": false, "plan_id": plan_id, "changes": summary, "risk": risk }),
            );
        }
        let done = self
            .ops
            .apply(&plan_id, &planned["plan"])
            .map_err(ToolError::Failed)?;
        if spare {
            let (target2, actor) = (target.clone(), actor_of(s));
            self.with_orch(s, a, now, None, |book, id| {
                if let Some(o) = book.orchestration_mut(id) {
                    if !o.spare_boxes.contains(&target2) {
                        o.spare_boxes.push(target2);
                    }
                }
                book.record(
                    now,
                    &actor,
                    "orchestration.box",
                    None,
                    &format!("{name} {id}"),
                );
                Ok(())
            })?;
        }
        Ok(json!({ "applied": true, "box": target, "changes": summary, "result": done["result"] }))
    }

    // ---- orchestrations and features ------------------------------------------------------------------------------

    fn orchestration_start(&self, s: &Session, a: &Value, now: u64) -> R {
        let goal = need(a, "goal")?;
        let conductor = need(a, "conductor_box")?;
        let rules = match self::s(a, "rules") {
            Some(t) => parse_rules(t).map_err(ToolError::Invalid)?,
            None => Overrides::default(),
        };
        let req = Overrides {
            max_workers: int(a, "max_workers").and_then(|n| u8::try_from(n).ok()),
            max_sub_agents: int(a, "max_sub_agents").and_then(|n| u8::try_from(n).ok()),
            spend_cap_cents: a
                .get("max_spend_usd")
                .and_then(Value::as_f64)
                .and_then(usd_to_cents),
            ..Default::default()
        };
        let conduct = flag(a, "start_conductor");
        let person = s.person.clone();
        let exists = self
            .ops
            .list()
            .map_err(ToolError::Failed)?
            .iter()
            .any(|b| b["name"].as_str() == Some(conductor));
        if !exists {
            return Err(ToolError::NotFound(format!(
                "there is no box named {conductor}"
            )));
        }
        self.store
            .update(|book| {
                let id =
                    book.start_orchestration(goal, &person, conductor, &[&rules, &req], now)?;
                let task = if conduct {
                    Some(book.start_conductor(&id, "", now)?)
                } else {
                    None
                };
                let o = book
                    .orchestration(&id)
                    .ok_or_else(|| ToolError::NotFound("there is no such orchestration".into()))?;
                Ok::<_, ToolError>(json!({ "id": id, "policy": o.policy, "conductor_task": task }))
            })
            .map_err(store_err)?
    }

    fn task_start(&self, s: &Session, a: &Value, now: u64) -> R {
        if matches!(s.role, Role::Worker { .. }) {
            return Err(ToolError::Refused("a worker cannot start features".into()));
        }
        let dry = flag(a, "dry_run");
        let transport = self::s(a, "transport").unwrap_or("ssh");
        if !matches!(transport, "ssh" | "hub") {
            return Err(ToolError::Invalid("transport is ssh or hub".into()));
        }
        // ADR 0042 section 5: no tool takes a key name. A worker's keys come from the project's declared commands, approved by
        // the owner and checked by the worker. The arguments are an ALLOWLIST taken from the tool's own schema: any argument it
        // does not declare (`keys`, `credentials`, a nested object, anything) is refused and the attempt is recorded.
        let declared: Vec<String> = tool_defs(&s.role)
            .iter()
            .find(|d| d["name"] == "task_start")
            .and_then(|d| d["inputSchema"]["properties"].as_object().cloned())
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default();
        if a.as_object()
            .is_some_and(|m| m.keys().any(|k| !declared.contains(k)))
        {
            // only a valid box name goes into the audit line: a conductor cannot forge fields or store a value in it
            let who = self::s(a, "box")
                .and_then(|b| ozbox_core::name::BoxName::new(b.to_string()).ok())
                .map_or_else(|| "-".to_string(), |b| b.to_string());
            let detail = format!("side=conductor worker={who} task=- code=conductor-named-keys");
            self.store
                .update(|b| {
                    b.record(
                        now,
                        &actor_of(s),
                        ozbox_core::hub::refusal::AUDIT_REFUSED,
                        None,
                        &detail,
                    )
                })
                .map_err(store_err)?;
            return Err(ToolError::Refused(
                "A task never names keys, and takes no argument it does not declare. A worker's keys come from the project's declared commands, which the owner approves.".into(),
            ));
        }
        let decl = ozbox_core::hub::refusal::KeyDeclaration::default();
        let hub = if transport == "hub" {
            Some(self.hub.clone().ok_or_else(|| {
                ToolError::Refused(
                    "this box has no worker channel yet, so a task cannot be handed over it: leave transport at ssh".into(),
                )
            })?)
        } else {
            None
        };
        let fleet = self.ops.list().map_err(ToolError::Failed)?;
        let boxes: Vec<String> = fleet
            .iter()
            .filter_map(|b| b["name"].as_str().map(str::to_string))
            .collect();
        let running: Vec<String> = fleet
            .iter()
            .filter(|b| b["state"] == "running")
            .filter_map(|b| b["name"].as_str().map(str::to_string))
            .collect();
        let caps = RunCaps {
            max_spend_cents: a
                .get("max_spend_usd")
                .and_then(Value::as_f64)
                .and_then(usd_to_cents),
            max_runtime_s: int(a, "max_minutes").map(|m| m * 60),
            ..Default::default()
        };
        let engine = self::s(a, "engine").map(str::to_string);
        let box_name = self::s(a, "box").map(str::to_string);
        let req = FeatureReq {
            title: need(a, "title")?.to_string(),
            brief: need(a, "brief")?.to_string(),
            box_name: box_name.clone(),
            worker: None,
            repo: self::s(a, "repo").map(str::to_string),
            branch: self::s(a, "branch").map(str::to_string),
            claims: strs(a, "claims"),
            contracts: strs(a, "contracts"),
            engine,
            model: self::s(a, "model").map(str::to_string),
            sub_agents: int(a, "sub_agents").and_then(|n| u8::try_from(n).ok()),
            caps,
            keep: flag(a, "keep"),
        };
        let run = |book: &mut Book, id: &str| -> R {
            let o = book
                .orchestration_mut(id)
                .ok_or_else(|| ToolError::NotFound("there is no such orchestration".into()))?;
            let mut req = req.clone();
            if req.box_name.is_none() {
                req.box_name = o.spare_boxes.first().cloned();
            }
            let Some(bn) = req.box_name.clone() else {
                return Err(ToolError::Invalid(
                    "name the worker box, or make one first with box_clone".into(),
                ));
            };
            if !boxes.contains(&bn) {
                return Err(ToolError::Invalid(format!(
                    "there is no box named {bn}: make it first with box_clone"
                )));
            }
            if o.policy.worker.kind == WorkerKind::Reuse
                && o.features
                    .iter()
                    .any(|f| f.state.is_open() && f.box_name == bn)
            {
                return Err(ToolError::Refused(format!(
                    "{bn} is busy with another feature"
                )));
            }
            let fid = o.add_feature(&req, now)?;
            let f = o.feature(&fid).cloned().ok_or(OrchError::NoFeature)?;
            if let Some(f) = o.feature_mut(&fid) {
                f.worker = WorkerPref {
                    kind: if f.box_made {
                        WorkerKind::Clone
                    } else {
                        WorkerKind::Reuse
                    },
                    ..f.worker.clone()
                };
            }
            if hub.is_some() {
                if let Some(fm) = o.feature_mut(&fid) {
                    fm.transport = ozbox_core::orch::Transport::Hub;
                }
            }
            let waits = !f.after.is_empty();
            // A feature that must wait for another cannot go over the hub yet: it would stay Planned, and the server's tick starts
            // every Planned feature whose predecessors merged, by the laptop route. A hub-route feature is therefore never left
            // Planned: it is handed over now (Starting), or refused and Failed (owner decision, 2026-11-14; no persisted transport).
            if hub.is_some() && waits && !dry {
                if let Some(fm) = book.orchestration_mut(id).and_then(|o| o.feature_mut(&fid)) {
                    fm.state = ozbox_core::orch::FeatureState::Failed;
                }
                return Err(ToolError::Refused(
                    "A task that must wait for another cannot be handed over the hub yet. Start it after the other merges, or use the ssh route.".into(),
                ));
            }
            // over the hub the worker is handed the task now, never by the laptop route
            if let (Some(h), false, false) = (&hub, waits, dry) {
                let assign = ozbox_core::hub::engine::Assign {
                    orchestration: id.to_string(),
                    feature: fid.clone(),
                    title: f.title.clone(),
                    brief: f.brief.clone(),
                    branch: f.branch.clone(),
                    repo: f.repo.clone(),
                    claims: f.claims.iter().map(|c| c.pattern.clone()).collect(),
                    contracts: f.contracts.iter().map(|c| c.id.clone()).collect(),
                    keys: decl.clone(),
                    lease_expiry_ms: now
                        .saturating_add(f.caps.max_runtime_s.unwrap_or(4 * 3600) * 1000),
                };
                let sent = h.with(now, |hub, st| {
                    let r = hub.assign(st, &f.box_name, &assign, now);
                    (r, st.take_audit())
                });
                let Some((r, lines)) = sent else {
                    return Err(ToolError::Failed(
                        "the hub's state could not be used".into(),
                    ));
                };
                for l in lines {
                    book.record(l.ts_ms, &actor_of(s), &l.action, None, &l.detail);
                }
                if let Err(e) = r {
                    if let Some(fm) = book.orchestration_mut(id).and_then(|o| o.feature_mut(&fid)) {
                        fm.state = ozbox_core::orch::FeatureState::Failed;
                    }
                    return Err(match e {
                        ozbox_core::hub::engine::HubError::Refused(r) => {
                            ToolError::Refused(r.message)
                        }
                        other => {
                            ToolError::Failed(format!("the task was not handed over: {other}"))
                        }
                    });
                }
                if let Some(fm) = book.orchestration_mut(id).and_then(|o| o.feature_mut(&fid)) {
                    fm.state = ozbox_core::orch::FeatureState::Starting;
                }
            }
            // a feature whose box is already running starts at once; any other waits for the server's tick
            let started = if hub.is_some() {
                !waits && !dry
            } else if !waits && !dry && running.contains(&f.box_name) {
                book.start_feature(id, &fid, now).is_ok()
            } else {
                false
            };
            Ok(json!({
                "feature": fid,
                "branch": f.branch,
                "box": f.box_name,
                "claims": f.claims.iter().map(|c| &c.pattern).collect::<Vec<_>>(),
                "sequenced_after": f.after,
                "state": if waits || !started { "planned" } else { "starting" },
                "applied": !dry,
            }))
        };
        if dry {
            // validate on a copy of the store: nothing is saved
            let mut book = self.store.load().map_err(store_err)?;
            let id = self.orch_of(s, a, &book)?;
            return run(&mut book, &id);
        }
        self.with_orch(s, a, now, Some("task_start"), run)
    }

    fn task_status(&self, s: &Session, a: &Value, now: u64) -> R {
        let since = int(a, "since").unwrap_or(0);
        let want = self::s(a, "feature").map(str::to_string);
        // what the workers reported over the hub: taken in first, and what that turned up (a rejected message, a quarantine) is recorded
        let reports = match &self.hub {
            Some(h) => {
                let (map, lines) = h
                    .with(now, |hub, st| {
                        hub.poll(st, now);
                        let mut m: BTreeMap<(String, String), Value> = BTreeMap::new();
                        for (worker, p) in &st.peers {
                            for (o, f) in &p.assigned {
                                m.insert(
                                    (o.clone(), f.clone()),
                                    json!({
                                        "worker": worker,
                                        "last_seen_ms": p.report.last_seen_ms,
                                        "quarantined": p.quarantined,
                                        "status": p.report.status.get(o).and_then(|m| m.get(f)),
                                        "result": p.report.results.get(o).and_then(|m| m.get(f)),
                                        "keys": {"delivered": 0, "note": "key delivery to workers is not built in this release"},
                                    }),
                                );
                            }
                        }
                        (m, st.take_audit())
                    })
                    .unwrap_or_default();
                if !lines.is_empty() {
                    let actor = actor_of(s);
                    self.store
                        .update(|b| {
                            for l in &lines {
                                b.record(l.ts_ms, &actor, &l.action, None, &l.detail);
                            }
                        })
                        .map_err(store_err)?;
                }
                map
            }
            None => BTreeMap::new(),
        };
        self.read_orch(s, a, |book, o| {
            let feats: Vec<Value> = o
                .features
                .iter()
                .filter(|f| want.as_deref().is_none_or(|w| w == f.id))
                .map(|f| {
                    let mut j = feature_json(book, f);
                    // keyed by orchestration and feature, and only the worker that holds the feature now
                    if let (Some(r), Some(obj)) = (
                        reports
                            .get(&(o.id.clone(), f.id.clone()))
                            .filter(|r| r["worker"] == f.box_name.as_str()),
                        j.as_object_mut(),
                    ) {
                        obj.insert("hub".to_string(), r.clone());
                    }
                    j
                })
                .collect();
            if want.is_some() && feats.is_empty() {
                return Err(ToolError::NotFound("there is no such feature".into()));
            }
            let msgs: Vec<&_> = o.inbox("conductor", since).into_iter().take(50).collect();
            Ok(json!({
                "orchestration": o.id,
                "state": o.state,
                "features": feats,
                "open_questions": o.open_questions(),
                "messages": msgs,
            }))
        })
    }

    fn task_message(&self, s: &Session, a: &Value, now: u64) -> R {
        let text = need(a, "text")?.to_string();
        let ans = int(a, "answer_to");
        let esc = flag(a, "escalate");
        let feature = self::s(a, "feature").map(str::to_string);
        self.with_orch(s, a, now, Some("task_message"), |book, id| {
            let o = book
                .orchestration_mut(id)
                .ok_or(OrchError::NoOrchestration)?;
            if let Some(q) = ans {
                if esc {
                    o.escalate(q, now)?;
                    return Ok(json!({ "escalated": q }));
                }
                let seq = o.answer(now, q, false, &text)?;
                return Ok(json!({ "answered": q, "message": seq }));
            }
            let f = feature.ok_or_else(|| ToolError::Invalid("feature is required".into()))?;
            if o.feature(&f).is_none() {
                return Err(OrchError::NoFeature.into());
            }
            let seq = o.post(
                now,
                "conductor",
                &format!("feature:{f}"),
                MsgKind::Instruction,
                &text,
                None,
                false,
            )?;
            if let Some(x) = o.feature_mut(&f) {
                x.resume_pending = true;
            }
            Ok(json!({ "message": seq }))
        })
    }

    fn task_stop(&self, s: &Session, a: &Value, now: u64) -> R {
        let f = self.feature_of(s, a)?;
        let pause = self::s(a, "mode") == Some("pause");
        self.with_orch(s, a, now, Some("task_stop"), |book, id| {
            book.halt_feature(id, &f, pause, now)?;
            Ok(json!({ "feature": f, "state": if pause { "paused" } else { "stopped" } }))
        })
    }

    // ---- claims and contracts ----------------------------------------------------------------------------------------

    fn claims_declare(&self, s: &Session, a: &Value, now: u64) -> R {
        let f = self.feature_of(s, a)?;
        let claims = strs(a, "claims");
        let worker = matches!(s.role, Role::Worker { .. });
        self.with_orch(s, a, now, Some("claims_declare"), |book, id| {
            let o = book
                .orchestration_mut(id)
                .ok_or(OrchError::NoOrchestration)?;
            if worker && o.feature(&f).is_some_and(|x| !x.claims.is_empty()) {
                return Err(ToolError::Refused(
                    "your claims are already set: ask the conductor to change them".into(),
                ));
            }
            Ok(match o.declare_claims(&f, &claims, now)? {
                ClaimOutcome::Granted => json!({ "result": "granted" }),
                ClaimOutcome::Sequenced { after } => {
                    json!({ "result": "sequenced", "after": after })
                }
            })
        })
    }

    fn claims_check(&self, s: &Session, a: &Value) -> R {
        let f = self.feature_of(s, a)?;
        let paths = strs(a, "paths");
        if paths.is_empty() || paths.len() > 200 {
            return Err(ToolError::Invalid("give 1 to 200 paths".into()));
        }
        self.read_orch(s, a, |_, o| {
            let rows: Vec<Value> = paths
                .iter()
                .map(|p| match o.check_path(&f, p) {
                    Ok(()) => json!({ "path": p, "allowed": true }),
                    Err(e) => json!({ "path": p, "allowed": false, "why": e.to_string() }),
                })
                .collect();
            let all = rows.iter().all(|r| r["allowed"] == true);
            Ok(json!({ "allowed": all, "paths": rows }))
        })
    }

    fn contract_publish(&self, s: &Session, a: &Value, now: u64) -> R {
        let (name, kind, body) = (need(a, "name")?, need(a, "kind")?, need(a, "body")?);
        let (paths, draft) = (strs(a, "paths"), flag(a, "draft"));
        let by = actor_of(s);
        self.with_orch(s, a, now, Some("contract_publish"), |book, id| {
            let o = book
                .orchestration_mut(id)
                .ok_or(OrchError::NoOrchestration)?;
            let (cid, v) = o.publish_contract(&by, name, kind, body, &paths, !draft, now)?;
            Ok(json!({ "id": cid, "version": v, "agreed": !draft }))
        })
    }

    fn contract_read(&self, s: &Session, a: &Value) -> R {
        let want = self::s(a, "id").map(str::to_string);
        let worker = match &s.role {
            Role::Worker { feature, .. } => Some(feature.clone()),
            _ => None,
        };
        // a worker that reads a contract has now seen that version
        if let (Some(w), Some(c)) = (&worker, &want) {
            let _ = self.with_orch(s, a, 0, None, |book, id| {
                if let Some(o) = book.orchestration_mut(id) {
                    let _ = o.ack_contract(w, c);
                }
                Ok(())
            });
        }
        self.read_orch(s, a, |_, o| match &want {
            None => Ok(json!({ "contracts": o.contracts.iter().map(|c| json!({
                "id": c.id, "name": c.name, "kind": c.kind, "version": c.version, "agreed": c.agreed, "paths": c.paths
            })).collect::<Vec<_>>() })),
            Some(id) => o
                .contract(id)
                .map(|c| json!({ "id": c.id, "name": c.name, "kind": c.kind, "version": c.version, "agreed": c.agreed, "paths": c.paths, "body": c.body }))
                .ok_or_else(|| ToolError::NotFound("there is no such contract".into())),
        })
    }

    // ---- approvals and the merge queue ----------------------------------------------------------------------------------

    fn approvals_pending(&self, s: &Session, a: &Value, now: u64) -> R {
        self.read_orch(s, a, |book, o| {
            let items: Vec<Value> = book
                .approvals
                .iter()
                .filter(|x| x.state == ApprovalState::Pending && belongs(o, &x.task_id))
                .map(|x| {
                    let may = o.conductor_may_decide(x);
                    json!({
                        "id": x.id, "kind": x.kind, "action": x.action, "box": x.box_name,
                        "expires_in_s": x.expires_ms.saturating_sub(now) / 1000,
                        "you_may_decide": may,
                        "waiting_for": if may { "you" } else { "the person" },
                    })
                })
                .collect();
            Ok(json!({ "items": items }))
        })
    }

    fn approvals_decide(&self, s: &Session, a: &Value, now: u64) -> R {
        let aid = need(a, "id")?.to_string();
        let approve = a
            .get("approve")
            .and_then(Value::as_bool)
            .ok_or_else(|| ToolError::Invalid("approve must be true or false".into()))?;
        let actor = actor_of(s);
        self.with_orch(s, a, now, None, |book, id| {
            let o = book.orchestration(id).ok_or(OrchError::NoOrchestration)?;
            let req = book
                .approval(&aid)
                .filter(|x| belongs(o, &x.task_id))
                .cloned()
                .ok_or_else(|| ToolError::NotFound("there is no such request here".into()))?;
            if !o.conductor_may_decide(&req) {
                book.record(
                    now,
                    &actor,
                    "approval.refused",
                    None,
                    "the person's to decide",
                );
                return Err(ToolError::Refused(
                    "this one is the person's to decide: it was sent to them".into(),
                ));
            }
            supervisor::decide(book, &aid, approve, &actor, false, now)
                .map_err(|e| ToolError::Refused(e.to_string()))?;
            Ok(json!({ "id": aid, "state": if approve { "approved" } else { "denied" } }))
        })
    }

    fn merge_queue(&self, s: &Session, a: &Value, now: u64) -> R {
        let f = need(a, "feature")?.to_string();
        self.with_orch(s, a, now, Some("merge_queue"), |book, id| {
            let o = book
                .orchestration_mut(id)
                .ok_or(OrchError::NoOrchestration)?;
            let pos = o.enqueue_merge(&f, now)?;
            Ok(json!({ "feature": f, "position": pos }))
        })
    }

    fn merge_status(&self, s: &Session, a: &Value) -> R {
        self.read_orch(s, a, |_, o| {
            Ok(json!({
                "base_branch": o.policy.base_branch,
                "merge_approval": o.policy.merge_approval,
                "test_command": o.policy.test_command,
                "queue": o.merge_queue,
            }))
        })
    }

    fn budget_status(&self, s: &Session, a: &Value) -> R {
        self.read_orch(s, a, |book, o| {
            let spent = book.orchestration_spend(&o.id);
            let per: Vec<Value> = o
                .features
                .iter()
                .map(|f| {
                    let c = f
                        .task_id
                        .as_deref()
                        .and_then(|t| book.task(t))
                        .map_or(0, |t| t.spend_cents);
                    json!({ "feature": f.id, "spent_cents": c })
                })
                .collect();
            Ok(json!({
                "state": o.state,
                "paused_reason": o.paused_reason,
                "spent_cents": spent,
                "cap_cents": o.policy.spend_cap_cents,
                "remaining_cents": o.policy.spend_cap_cents.map(|c| c.saturating_sub(spent)),
                "features": per,
            }))
        })
    }

    // ---- worker tools -----------------------------------------------------------------------------------------------------

    fn worker_ask(&self, s: &Session, a: &Value, now: u64) -> R {
        let f = self.feature_of(s, a)?;
        let q = need(a, "question")?.to_string();
        let person = flag(a, "for_person");
        self.with_orch(s, a, now, Some("worker_ask"), |book, id| {
            let o = book.orchestration_mut(id).ok_or(OrchError::NoOrchestration)?;
            let to = if person { "person" } else { "conductor" };
            let seq = o.post(now, &format!("feature:{f}"), to, MsgKind::Question, &q, None, person)?;
            Ok(json!({
                "question": seq,
                "next": "Write down where you stopped, commit your work, and end your turn. You will be resumed with the answer.",
            }))
        })
    }

    fn worker_status(&self, s: &Session, a: &Value, now: u64) -> R {
        let f = self.feature_of(s, a)?;
        let text = self::s(a, "text").map(str::to_string);
        let since = int(a, "since").unwrap_or(0);
        self.with_orch(s, a, now, None, |book, id| {
            let o = book
                .orchestration_mut(id)
                .ok_or(OrchError::NoOrchestration)?;
            if let Some(t) = text {
                o.post(
                    now,
                    &format!("feature:{f}"),
                    "conductor",
                    MsgKind::Status,
                    &t,
                    None,
                    false,
                )?;
            }
            let msgs: Vec<_> = o
                .inbox(&format!("feature:{f}"), since)
                .into_iter()
                .rev()
                .take(10)
                .cloned()
                .collect();
            let feat = o.feature_mut(&f).ok_or(OrchError::NoFeature)?;
            feat.resume_pending = false;
            Ok(json!({
                "state": feat.state,
                "blocked": feat.blocked_on.is_some(),
                "messages": msgs,
                "claims": feat.claims.iter().map(|c| &c.pattern).collect::<Vec<_>>(),
                "contracts": feat.contracts,
            }))
        })
    }

    fn worker_done(&self, s: &Session, a: &Value, now: u64) -> R {
        let f = self.feature_of(s, a)?;
        let summary = self::s(a, "summary").unwrap_or("done").to_string();
        self.with_orch(s, a, now, Some("worker_done"), |book, id| {
            let o = book.orchestration_mut(id).ok_or(OrchError::NoOrchestration)?;
            let st = o.feature(&f).ok_or(OrchError::NoFeature)?.state;
            if !matches!(
                st,
                FeatureState::Starting | FeatureState::Working | FeatureState::ConflictReturned
            ) {
                return Err(ToolError::Refused(format!("a feature that is {st:?} cannot be finished").to_lowercase()));
            }
            o.post(now, &format!("feature:{f}"), "conductor", MsgKind::Status, &format!("Done: {summary}"), None, false)?;
            o.set_feature_state(&f, FeatureState::ReadyToMerge, now)?;
            Ok(json!({ "state": "ready_to_merge", "next": "The conductor queues it for the merge." }))
        })
    }
}

pub fn actor_of(s: &Session) -> String {
    match &s.role {
        Role::Person | Role::Agent => format!("agent:{}", s.person),
        Role::Conductor { orch } => format!("conductor:{orch}"),
        Role::Worker { orch, feature } => format!("worker:{orch}/{feature}"),
    }
}

/// Whether a task (or the merge pseudo-task) belongs to an orchestration.
fn belongs(o: &Orchestration, task_id: &str) -> bool {
    task_id == ozbox_core::orch_merge::merge_task_id(&o.id)
        || o.conductor_task.as_deref() == Some(task_id)
        || o.features
            .iter()
            .any(|f| f.task_id.as_deref() == Some(task_id))
}

pub fn feature_json(book: &Book, f: &Feature) -> Value {
    let task = f.task_id.as_deref().and_then(|t| book.task(t));
    json!({
        "id": f.id,
        "title": f.title,
        "state": f.state,
        "box": f.box_name,
        "branch": f.branch,
        "claims": f.claims.iter().map(|c| &c.pattern).collect::<Vec<_>>(),
        "contracts": f.contracts,
        "after": f.after,
        "engine": f.engine,
        "model": f.model,
        "sub_agents": f.sub_agents,
        "task_id": f.task_id,
        "task_state": task.map(|t| t.state),
        "spent_cents": task.map_or(0, |t| t.spend_cents),
        "wip_branch": f.wip_branch,
        "blocked_on": f.blocked_on,
        "keep": f.keep,
    })
}

/// An orchestration as `/v1/orchestrations/<id>` and `ozbox orch show --json` give it. Add fields, never rename.
pub fn orch_json(book: &Book, o: &Orchestration, now_ms: u64) -> Value {
    let spent = book.orchestration_spend(&o.id);
    let pending: Vec<Value> = book
        .approvals
        .iter()
        .filter(|a| a.state == ApprovalState::Pending && belongs(o, &a.task_id))
        .map(|a| {
            json!({
                "id": a.id, "kind": a.kind, "action": a.action, "box": a.box_name,
                "needs_person": !o.conductor_may_decide(a),
                "needs_step_up": a.needs_step_up,
                "expires_ms": a.expires_ms,
                "expires_in_s": a.expires_ms.saturating_sub(now_ms) / 1000,
            })
        })
        .collect();
    let skip = o.messages.len().saturating_sub(100);
    json!({
        "id": o.id,
        "goal": o.goal,
        "requested_by": o.requested_by,
        "state": o.state,
        "paused_reason": o.paused_reason,
        "conductor_box": o.conductor_box,
        "conductor_task": o.conductor_task,
        "created_ms": o.created_ms,
        "updated_ms": o.updated_ms,
        "policy": o.policy,
        "spent_cents": spent,
        "cap_cents": o.policy.spend_cap_cents,
        "features": o.features.iter().map(|f| feature_json(book, f)).collect::<Vec<_>>(),
        "contracts": o.contracts.iter().map(|c| json!({
            "id": c.id, "name": c.name, "kind": c.kind, "version": c.version, "agreed": c.agreed,
            "paths": c.paths, "updated_ms": c.updated_ms,
        })).collect::<Vec<_>>(),
        "messages": o.messages.iter().skip(skip).collect::<Vec<_>>(),
        "open_questions": o.open_questions(),
        "merge_queue": o.merge_queue,
        "approvals": pending,
        "spare_boxes": o.spare_boxes,
    })
}

/// One line of `GET /v1/orchestrations` and `ozbox orch list --json`.
pub fn orch_summary(book: &Book, o: &Orchestration, now_ms: u64) -> Value {
    let j = orch_json(book, o, now_ms);
    json!({
        "id": j["id"], "goal": j["goal"], "state": j["state"], "paused_reason": j["paused_reason"],
        "conductor_box": j["conductor_box"], "requested_by": j["requested_by"],
        "spent_cents": j["spent_cents"], "cap_cents": j["cap_cents"],
        "features": o.features.len(),
        "open_features": o.features.iter().filter(|f| f.state.is_open()).count(),
        "needs_you": !o.open_questions().is_empty() || !j["approvals"].as_array().is_none_or(Vec::is_empty),
        "updated_ms": o.updated_ms,
    })
}

#[cfg(test)]
pub(crate) mod tests;
