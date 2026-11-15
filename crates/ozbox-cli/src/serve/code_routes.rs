//! `/v1/boxes/<box>/code`: the box page's Code panel. What the IDE and the desktop on a box are doing, and the changes
//! the person can make, plan first and then apply (ADR 0002): enable or disable a service, serve it on their own address,
//! stop serving it there, and (on the computer the dashboard runs on) open it on localhost.
//!
//! Nothing here answers with a password. A box is probed on a background thread, so a slow SSH never holds the server.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ozbox_core::{BoxName, BoxRecord, BoxState, Provider};
use serde::Deserialize;
use serde_json::{json, Value};

use super::agent::BoxAgent;
use super::{unix_ms, App, Resp};
use crate::code::editors;
use crate::code::proxy::{DashSessions, Gate, Upstream};
use crate::code::{self, BoxCode, Change, CodeSettings, Service};
use crate::messages::t;
use crate::tunnel::TunnelFile;

const STALE_MS: u64 = 10_000;
const MAX_PLANS: usize = 64;
const PLAN_TTL_MS: u64 = 10 * 60_000;

/// Which box a cached answer, a plan or a local proxy belongs to: its name **and** the provider's id for the machine. A box
/// destroyed and made again under the same name is a different machine, with a different password and a different address,
/// so nothing kept for the old one may be reused for it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct BoxKey {
    name: String,
    id: String,
}

impl BoxKey {
    pub(super) fn of(rec: &BoxRecord) -> Self {
        Self {
            name: rec.spec.name.to_string(),
            // the provider's machine id; a record that has none is told apart by when it was made
            id: rec
                .provider_id
                .clone()
                .or_else(|| rec.created_at.clone())
                .unwrap_or_default(),
        }
    }
}

/// When the box was asked, and what it said.
type ProcsEntry = (u64, Result<crate::code::procs::Procs, String>);

#[derive(Clone)]
struct Cached {
    at_ms: u64,
    result: Result<BoxCode, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Action {
    Enable,
    Disable,
    PublicOn,
    PublicOff,
    StopSession,
    StopProcess,
    /// Run the Cloudflare tunnel's connector on the box (the token is in the plan, in memory only).
    ConnectorOn,
    ConnectorOff,
}

struct CodePlan {
    /// The tunnel token of a `ConnectorOn` plan. Held only until the plan is applied or expires; never in an answer.
    token: Option<String>,
    target: Option<String>,
    box_name: String,
    /// The machine the plan was made for: a box made again under the same name is not it.
    key: BoxKey,
    service: Service,
    action: Action,
    address: Option<String>,
    at_ms: u64,
}

#[derive(Clone)]
enum Job {
    Running,
    Done,
    Failed(String),
}

#[derive(Default)]
pub struct CodeState {
    pub settings: Arc<Mutex<CodeSettings>>,
    pub settings_path: Option<std::path::PathBuf>,
    pub gate: Option<Arc<Gate>>,
    cache: Arc<Mutex<HashMap<BoxKey, Cached>>>,
    procs: Arc<Mutex<HashMap<BoxKey, ProcsEntry>>>,
    procs_refreshing: Arc<Mutex<std::collections::HashSet<BoxKey>>>,
    refreshing: Arc<Mutex<std::collections::HashSet<BoxKey>>>,
    plans: HashMap<String, CodePlan>,
    jobs: Arc<Mutex<HashMap<String, Job>>>,
    locals: HashMap<(BoxKey, Service), crate::code::local::Local>,
}

impl CodeState {
    /// Forget everything kept for a box name: its cached answers and its local proxies (dropping one closes it). Called when
    /// the box is destroyed here, so a box made again under the name starts from nothing.
    pub(super) fn forget_box(&mut self, name: &str) {
        self.locals.retain(|(k, _), _| k.name != name);
        self.plans.retain(|_, p| p.box_name != name);
        lock(&self.cache).retain(|k, _| k.name != name);
        lock(&self.procs).retain(|k, _| k.name != name);
    }

    /// Drop what is kept for an older machine of this name (a box destroyed and made again from the command line, which
    /// this server did not see), before anything is looked up for the current one.
    fn forget_older(&mut self, current: &BoxKey) {
        let stale = |k: &BoxKey| k.name == current.name && k.id != current.id;
        self.locals.retain(|(k, _), _| !stale(k));
        lock(&self.cache).retain(|k, _| !stale(k));
        lock(&self.procs).retain(|k, _| !stale(k));
    }

    #[cfg(test)]
    pub(super) fn kept_for(&self, name: &str) -> usize {
        self.locals.keys().filter(|(k, _)| k.name == name).count()
            + lock(&self.cache).keys().filter(|k| k.name == name).count()
            + lock(&self.procs).keys().filter(|k| k.name == name).count()
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// The dashboard's sessions, as the code gate asks about them.
pub struct AuthSessions(pub Arc<super::auth::Auth>);

impl DashSessions for AuthSessions {
    fn alive(&self, key: &str) -> bool {
        // a viewer's sign-in is alive, and still does not open a box's IDE or desktop (ADR 0039)
        self.0.session_may_use_boxes(key)
    }
}

/// A way to a box's service for the code gate.
pub struct AppUpstream {
    pub provider: Arc<dyn Provider>,
    pub agent: Arc<dyn BoxAgent>,
}

impl Upstream for AppUpstream {
    fn dial(&self, box_name: &str, service: Service) -> Result<super::agent::Conn, String> {
        let name = BoxName::new(box_name).map_err(|e| e.to_string())?;
        let rec = self
            .provider
            .get(&name)
            .map_err(|e| e.to_string())?
            .ok_or("no such box")?;
        if rec.state != BoxState::Running {
            return Err("the box is not running".into());
        }
        self.agent
            .connect_tcp(&rec, service.box_port())
            .map_err(|e| e.to_string())
    }
}

impl App {
    pub fn with_code_settings(mut self, path: Option<std::path::PathBuf>) -> Self {
        if let Some(p) = &path {
            if let Ok(s) = CodeSettings::load(p) {
                *lock(&self.code.settings) = s;
            }
        }
        self.code.settings_path = path;
        self
    }

    /// Start the listener that serves the code hosts, when the dashboard is in sign-in mode. Returns the port.
    pub fn start_code_proxy(&mut self, port: u16) -> Result<Option<u16>, String> {
        let (Some(auth), Some(origin)) = (self.auth.clone(), self.access.public_url.clone()) else {
            return Ok(None);
        };
        let gate = Arc::new(Gate::new(
            Arc::clone(&self.code.settings),
            origin,
            Arc::new(AuthSessions(auth)),
            Arc::new(AppUpstream {
                provider: Arc::clone(&self.provider),
                agent: Arc::clone(&self.agent),
            }),
            Arc::clone(&self.secrets),
            Arc::new(unix_ms),
        ));
        let l = std::net::TcpListener::bind(("127.0.0.1", port))
            .map_err(|e| format!("cannot listen on 127.0.0.1:{port} for the code hosts: {e}"))?;
        let bound = l.local_addr().map_err(|e| e.to_string())?.port();
        gate.serve(l, Arc::new(std::sync::atomic::AtomicBool::new(false)));
        self.code.gate = Some(gate);
        Ok(Some(bound))
    }

    /// `GET /code/enter?host=...` on the dashboard's own address: a signed-in person is handed to a code host with a
    /// single-use ticket. Anyone else goes to the dashboard's front page to sign in.
    pub(super) fn code_enter(&mut self, req: &super::Req) -> Resp {
        let (Some(a), Some(gate)) = (self.auth.clone(), self.code.gate.clone()) else {
            return Resp::error(404, "not_found", "no such endpoint");
        };
        if a.origin_ok(req).is_some() {
            return Resp::error(
                403,
                "bad_host",
                "this server answers only on its own address",
            );
        }
        let mut redirect = |to: String| {
            self.extra_headers = vec![("Location".into(), to)];
            Resp {
                status: 302,
                content_type: "text/plain",
                body: Vec::new(),
                no_store: true,
                stream: false,
            }
        };
        let host = super::parse_query(&req.query)
            .get("host")
            .cloned()
            .unwrap_or_default();
        let Some(key) = a.full_session_key(req) else {
            return redirect("/".into());
        };
        if !a.session_may_use_boxes(&key) {
            return Resp::error(
                403,
                "role_forbidden",
                "your role cannot use a terminal or an IDE on a box. Ask an owner",
            );
        }
        match gate.issue_ticket(&key, &host) {
            Some(t) => redirect(format!(
                "https://{host}{}?t={t}",
                crate::code::proxy::ENTER_PATH
            )),
            None => Resp::error(404, "not_found", "that address does not serve a box"),
        }
    }

    fn saved_tunnel_file(&self) -> Option<TunnelFile> {
        let p = self.access.tunnel_path.as_deref()?;
        TunnelFile::load(p).ok().flatten()
    }

    fn start_probe(&self, rec: &BoxRecord) {
        let name = BoxKey::of(rec);
        if !lock(&self.code.refreshing).insert(name.clone()) {
            return;
        }
        let (agent, cache, refreshing, rec) = (
            Arc::clone(&self.agent),
            Arc::clone(&self.code.cache),
            Arc::clone(&self.code.refreshing),
            rec.clone(),
        );
        std::thread::spawn(move || {
            let result = agent.code_status(&rec).map_err(|e| e.to_string());
            lock(&cache).insert(
                name.clone(),
                Cached {
                    at_ms: unix_ms(),
                    result,
                },
            );
            lock(&refreshing).remove(&name);
        });
    }

    pub(super) fn box_code(
        &mut self,
        name: &str,
        method: &str,
        rest: &[&str],
        body: &[u8],
    ) -> Resp {
        match (method, rest) {
            ("GET", []) => self.code_status(name),
            ("GET", ["processes"]) => self.code_processes(name),
            ("POST", ["plan"]) => self.code_plan(name, body),
            ("POST", ["apply"]) => self.code_apply(name, body),
            ("POST", ["open"]) => self.code_open(name, body),
            (_, [] | ["processes"] | ["plan"] | ["apply"] | ["open"]) => {
                Resp::error(405, "method_not_allowed", "method not allowed")
            }
            _ => Resp::error(404, "not_found", "no such endpoint"),
        }
    }

    pub(super) fn code_job(&self, id: &str) -> Resp {
        match lock(&self.code.jobs).get(id) {
            None => Resp::error(404, "not_found", "no such job"),
            Some(Job::Running) => Resp::json(200, &json!({ "state": "running" })),
            Some(Job::Done) => Resp::json(200, &json!({ "state": "done" })),
            Some(Job::Failed(e)) => Resp::json(200, &json!({ "state": "failed", "error": e })),
        }
    }

    fn code_processes(&mut self, name: &str) -> Resp {
        let rec = match self.running_box(name) {
            Ok(r) => r,
            Err(r) => return r,
        };
        let key = BoxKey::of(&rec);
        self.code.forget_older(&key);
        let cached = lock(&self.code.procs).get(&key).cloned();
        let stale = cached
            .as_ref()
            .is_none_or(|c| unix_ms().saturating_sub(c.0) > STALE_MS);
        if stale && lock(&self.code.procs_refreshing).insert(key.clone()) {
            let (agent, cache, refreshing, key) = (
                Arc::clone(&self.agent),
                Arc::clone(&self.code.procs),
                Arc::clone(&self.code.procs_refreshing),
                key,
            );
            std::thread::spawn(move || {
                let r = agent.code_procs(&rec).map_err(|e| e.to_string());
                lock(&cache).insert(key.clone(), (unix_ms(), r));
                lock(&refreshing).remove(&key);
            });
        }
        match cached {
            Some((_, Ok(p))) => Resp::json(200, &json!({ "probed": true, "error": null, "ps": p })),
            Some((_, Err(e))) => {
                Resp::json(200, &json!({ "probed": true, "error": e, "ps": null }))
            }
            None => Resp::json(200, &json!({ "probed": false, "error": null, "ps": null })),
        }
    }

    fn code_status(&mut self, name: &str) -> Resp {
        let rec = match self.record(name) {
            Ok(r) => r,
            Err(r) => return r,
        };
        let running = rec.state == BoxState::Running;
        let key = BoxKey::of(&rec);
        self.code.forget_older(&key);
        let cached = lock(&self.code.cache).get(&key).cloned();
        let stale = cached
            .as_ref()
            .is_none_or(|c| unix_ms().saturating_sub(c.at_ms) > STALE_MS);
        if running && stale {
            self.start_probe(&rec);
        }
        let refreshing = lock(&self.code.refreshing).contains(&key);
        let (probed, error, status) = match (&cached, running) {
            (Some(Cached { result: Ok(s), .. }), true) => (true, Value::Null, Some(*s)),
            (Some(Cached { result: Err(e), .. }), true) => (true, json!(e), None),
            _ => (false, Value::Null, None),
        };
        let settings = lock(&self.code.settings).clone();
        let tunnel = self.saved_tunnel_file().and_then(|f| f.kind());
        let public_mode = self.auth.is_some();
        let services: Vec<Value> = code::ALL
            .iter()
            .map(|&s| {
                let host = settings.host_of(name, s).map(str::to_string);
                json!({
                    "service": s.id(),
                    "state": status.map_or("unknown", |b| b.of(s).label()),
                    "password_set": self.secrets.exists(&s.secret_name(name)).unwrap_or(false),
                    "public_host": host,
                    "command": format!("ozbox {} {name}", s.id()),
                    "enter": host.as_ref().map(|h| format!("/code/enter?host={h}")),
                })
            })
            .collect();
        let editors: Vec<Value> = editors::ALL
            .iter()
            .map(|e| {
                let link = e.url_for_box(name, code::REPOS_DIR);
                json!({
                    "id": e.id(),
                    "name": e.name(),
                    "url": link.as_ref().map(|l| &l.0),
                    "documented": link.as_ref().is_some_and(|l| l.1 == editors::Evidence::Documented),
                    "command": format!("ozbox open {name} --in {}", e.id()),
                })
            })
            .collect();
        Resp::json(
            200,
            &json!({
                "box": name,
                "box_state": rec.state.to_string(),
                "probed": probed,
                "refreshing": refreshing,
                "error": error,
                "linger": status.map(|b| b.linger),
                "connector": { "state": status.map_or("unknown", |b| b.connector.label()) },
                "services": services,
                "editors": editors,
                "mode": if public_mode { "public" } else { "local" },
                "can_serve_public": public_mode && self.code.gate.is_some(),
                "tunnel": tunnel.map(|k| json!({ "kind": k.id(), "supports_hosts": code::settings::supports_more_hosts(k) })),
                "proxy_port": crate::code::proxy::DEFAULT_PORT,
            }),
        )
    }

    fn code_plan(&mut self, name: &str, body: &[u8]) -> Resp {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct B {
            #[serde(default = "default_service")]
            service: Service,
            action: Action,
            address: Option<String>,
            target: Option<String>,
            token: Option<String>,
        }
        let b: B = match serde_json::from_slice(body) {
            Ok(b) => b,
            Err(e) => return Resp::error(400, "bad_request", &format!("invalid request: {e}")),
        };
        let rec = match self.running_box(name) {
            Ok(r) => r,
            Err(r) => return r,
        };
        let key = BoxKey::of(&rec);
        self.code.forget_older(&key);
        let Some(Cached {
            result: Ok(status), ..
        }) = lock(&self.code.cache).get(&key).cloned()
        else {
            return Resp::error(
                409,
                "not_probed",
                "the box has not answered yet; try again in a moment",
            );
        };
        let st = status.of(b.service);
        let secret_set = self
            .secrets
            .exists(&b.service.secret_name(name))
            .unwrap_or(false);
        let mut steps: Vec<Value> = Vec::new();
        let mut changes_box = false;
        let mut address = None;
        match b.action {
            Action::Enable => {
                if !st.program {
                    return Resp::error(
                        422,
                        "no_program",
                        &t("code.err_no_program", &[("program", b.service.program())]),
                    );
                }
                if crate::code_cli::needs_change(st, secret_set, false) {
                    changes_box = true;
                    steps.push(json!({ "code": "set_up", "program": b.service.program() }));
                    steps.push(json!({ "code": "password" }));
                }
            }
            Action::Disable => {
                if st.unit_current || st.active {
                    changes_box = true;
                    steps.push(json!({ "code": "remove" }));
                }
            }
            Action::PublicOn => {
                let Some(addr) = b.address.clone() else {
                    return Resp::error(400, "bad_request", "an address is needed");
                };
                if self.auth.is_none() || self.code.gate.is_none() {
                    return Resp::error(
                        409,
                        "needs_sign_in",
                        &t("code.err_no_dashboard_signin", &[]),
                    );
                }
                if st.label() != "running" {
                    return Resp::error(
                        409,
                        "not_running",
                        "set the service up and start it first",
                    );
                }
                let tunnel = self.saved_tunnel_file().and_then(|f| f.kind());
                let dash_host = self
                    .access
                    .public_url
                    .as_deref()
                    .and_then(|u| crate::tunnel::public_host(u).ok());
                let mut probe = lock(&self.code.settings).clone();
                match probe.set(name, b.service, &addr, dash_host.as_deref(), tunnel) {
                    Ok(host) => {
                        steps.push(json!({ "code": "public_on", "host": host }));
                        address = Some(addr);
                    }
                    Err(k) => return Resp::error(422, k, &t(k, &[])),
                }
            }
            Action::PublicOff => {
                if lock(&self.code.settings).host_of(name, b.service).is_some() {
                    steps.push(json!({ "code": "public_off" }));
                }
            }
            Action::ConnectorOn => {
                let Some(token) = b.token.as_deref() else {
                    return Resp::error(400, "bad_request", &t("code.conn_bad_token", &[]));
                };
                if !code::token_ok(token) {
                    return Resp::error(422, "bad_token", &t("code.conn_bad_token", &[]));
                }
                if !status.connector.program {
                    return Resp::error(422, "no_program", &t("code.conn_no_program", &[]));
                }
                steps.push(json!({ "code": "connector_on" }));
                if status.connector.unit_current || status.connector.active {
                    steps.push(json!({ "code": "connector_replace" }));
                }
                changes_box = true;
            }
            Action::ConnectorOff => {
                if status.connector.unit_current || status.connector.active {
                    steps.push(json!({ "code": "connector_off" }));
                    changes_box = true;
                }
            }
            Action::StopSession | Action::StopProcess => {
                let Some(target) = b.target.clone() else {
                    return Resp::error(400, "bad_request", "say what to stop");
                };
                let Some((_, Ok(p))) = lock(&self.code.procs).get(&key).cloned() else {
                    return Resp::error(
                        409,
                        "not_probed",
                        "the box has not answered yet; try again in a moment",
                    );
                };
                if b.action == Action::StopSession {
                    if !p.sessions.iter().any(|s| s.name == target) {
                        return Resp::error(404, "not_found", "that session is not running");
                    }
                    steps.push(json!({ "code": "stop_session", "name": target }));
                } else {
                    let pid: u32 = target.parse().unwrap_or(0);
                    if !(p.agents.iter().any(|a| a.pid == pid)
                        || p.servers.iter().any(|s| s.pid == pid))
                    {
                        return Resp::error(404, "not_found", "that process is not running");
                    }
                    steps.push(json!({ "code": "stop_process", "pid": pid }));
                }
                changes_box = true;
            }
        }
        if self.code.plans.len() >= MAX_PLANS {
            let now = unix_ms();
            self.code
                .plans
                .retain(|_, p| now.saturating_sub(p.at_ms) < PLAN_TTL_MS);
        }
        let id = match super::random_hex(16) {
            Ok(i) => i,
            Err(e) => return Resp::error(500, "internal", &e),
        };
        self.code.plans.insert(
            id.clone(),
            CodePlan {
                token: b.token.clone().filter(|_| b.action == Action::ConnectorOn),
                box_name: name.to_string(),
                key: BoxKey::of(&rec),
                service: b.service,
                action: b.action,
                target: b.target.clone(),
                address,
                at_ms: unix_ms(),
            },
        );
        Resp::json(
            200,
            &json!({ "plan_id": id, "box": name, "service": b.service.id(), "noop": steps.is_empty(),
                     "changes_box": changes_box, "steps": steps }),
        )
    }

    fn code_apply(&mut self, name: &str, body: &[u8]) -> Resp {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct B {
            plan_id: String,
        }
        let b: B = match serde_json::from_slice(body) {
            Ok(b) => b,
            Err(e) => return Resp::error(400, "bad_request", &format!("invalid request: {e}")),
        };
        let Some(plan) = self.code.plans.remove(&b.plan_id) else {
            return Resp::error(
                404,
                "unknown_plan",
                "this server did not issue that plan, or it was already applied",
            );
        };
        if plan.box_name != name || unix_ms().saturating_sub(plan.at_ms) > PLAN_TTL_MS {
            return Resp::error(
                409,
                "stale_plan",
                "the plan is no longer valid; make a new one",
            );
        }
        let rec = match self.running_box(name) {
            Ok(r) => r,
            Err(r) => return r,
        };
        if plan.key != BoxKey::of(&rec) {
            return Resp::error(
                409,
                "stale_plan",
                "the plan was made for a box that has since been replaced; make a new one",
            );
        }
        let key = BoxKey::of(&rec);
        let job_id = match super::random_hex(8) {
            Ok(i) => i,
            Err(e) => return Resp::error(500, "internal", &e),
        };
        lock(&self.code.jobs).insert(job_id.clone(), Job::Running);
        let procs_cache = Arc::clone(&self.code.procs);
        let (agent, secrets, jobs, cache, settings) = (
            Arc::clone(&self.agent),
            Arc::clone(&self.secrets),
            Arc::clone(&self.code.jobs),
            Arc::clone(&self.code.cache),
            Arc::clone(&self.code.settings),
        );
        let path = self.code.settings_path.clone();
        let jid = job_id.clone();
        std::thread::spawn(move || {
            let outcome = run_plan(&*agent, &*secrets, &settings, path.as_deref(), &rec, &plan);
            lock(&cache).remove(&key);
            lock(&procs_cache).remove(&key);
            lock(&jobs).insert(
                jid,
                match outcome {
                    Ok(()) => Job::Done,
                    Err(e) => Job::Failed(e),
                },
            );
        });
        self.version
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Resp::json(202, &json!({ "job_id": job_id }))
    }

    /// Open a service on `localhost` of the computer this dashboard runs on (the local mode only).
    fn code_open(&mut self, name: &str, body: &[u8]) -> Resp {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct B {
            service: Service,
        }
        let b: B = match serde_json::from_slice(body) {
            Ok(b) => b,
            Err(e) => return Resp::error(400, "bad_request", &format!("invalid request: {e}")),
        };
        if self.auth.is_some() {
            return Resp::error(
                409,
                "use_the_address",
                "this dashboard runs on a shared machine; open the service on its own address",
            );
        }
        let rec = match self.running_box(name) {
            Ok(r) => r,
            Err(r) => return r,
        };
        let Ok(Some(password)) = self.secrets.get(&b.service.secret_name(name)) else {
            return Resp::error(409, "not_set_up", &t("code.err_no_password", &[]));
        };
        let mut nonce = [0u8; 16];
        if getrandom::getrandom(&mut nonce).is_err() {
            return Resp::error(500, "internal", "no secure random source");
        }
        let nonce: String = nonce.iter().map(|x| format!("{x:02x}")).collect();
        let box_key = BoxKey::of(&rec);
        self.code.forget_older(&box_key);
        let key = (box_key, b.service);
        if let Some(l) = self.code.locals.get(&key) {
            return Resp::json(200, &json!({ "url": l.issue_go(&nonce) }));
        }
        let (agent, rec2, port) = (Arc::clone(&self.agent), rec, b.service.box_port());
        let dial: crate::code::local::Dialer =
            Arc::new(move || agent.connect_tcp(&rec2, port).map_err(|e| e.to_string()));
        let login = match b.service {
            Service::Ide => crate::code::local::Login::Form { password },
            Service::Desktop => crate::code::local::Login::Basic {
                user: Service::DESKTOP_USER.into(),
                password,
            },
        };
        match crate::code::local::start(
            dial,
            login,
            crate::code::local::Options {
                port: None,
                nonce,
                warm_every: None,
                on_state: Arc::new(|_| {}),
            },
        ) {
            Ok(l) => {
                let url = l.go_url();
                self.code.locals.insert(key, l);
                Resp::json(200, &json!({ "url": url }))
            }
            Err(e) => Resp::error(500, "cannot_open", &e.to_string()),
        }
    }
}

fn save(
    settings: &Mutex<CodeSettings>,
    path: Option<&std::path::Path>,
    s: CodeSettings,
) -> Result<(), String> {
    if let Some(p) = path {
        s.save(p)?;
    }
    *lock(settings) = s;
    Ok(())
}

fn default_service() -> Service {
    Service::Ide
}

/// What a confirmed plan does, on a background thread. The box's own state is read again first, so a plan made a few
/// minutes ago never does more than is still needed.
fn run_plan(
    agent: &dyn BoxAgent,
    secrets: &dyn crate::secrets::SecretStore,
    settings: &Mutex<CodeSettings>,
    path: Option<&std::path::Path>,
    rec: &BoxRecord,
    plan: &CodePlan,
) -> Result<(), String> {
    let name = plan.box_name.as_str();
    let secret = plan.service.secret_name(name);
    match plan.action {
        Action::Enable => {
            let state = agent
                .code_status(rec)
                .map_err(|e| e.to_string())?
                .of(plan.service);
            let have = secrets.exists(&secret).unwrap_or(false);
            if crate::code_cli::needs_change(state, have, false) {
                let (pw, fresh) = match (have, secrets.get(&secret)) {
                    (true, Ok(Some(p))) => (p, false),
                    _ => (code::new_password()?, true),
                };
                agent
                    .code_change(
                        rec,
                        &Change::Enable {
                            service: plan.service,
                            password: pw.clone(),
                        },
                    )
                    .map_err(|e| e.to_string())?;
                if fresh {
                    secrets
                        .set(&secret, &pw)
                        .map_err(|e| t("code.err_secret", &[("why", &e.to_string())]))?;
                }
            }
            Ok(())
        }
        Action::Disable => {
            let state = agent
                .code_status(rec)
                .map_err(|e| e.to_string())?
                .of(plan.service);
            if state.unit_current || state.active {
                agent
                    .code_change(
                        rec,
                        &Change::Disable {
                            service: plan.service,
                        },
                    )
                    .map_err(|e| e.to_string())?;
            }
            let _ = secrets.delete(&secret);
            let mut s = lock(settings).clone();
            if s.clear(name, plan.service) {
                save(settings, path, s)?;
            }
            Ok(())
        }
        Action::PublicOn => {
            let mut s = lock(settings).clone();
            let addr = plan.address.as_deref().ok_or("no address")?;
            s.set(name, plan.service, addr, None, None)
                .map_err(|k| t(k, &[]))?;
            save(settings, path, s)
        }
        Action::PublicOff => {
            let mut s = lock(settings).clone();
            if s.clear(name, plan.service) {
                save(settings, path, s)?;
            }
            Ok(())
        }
        Action::ConnectorOn => {
            let token = plan.token.clone().ok_or("the plan carries no token")?;
            agent
                .code_change(rec, &Change::Connector { token })
                .map_err(|e| e.to_string())
        }
        Action::ConnectorOff => {
            let st = agent.code_status(rec).map_err(|e| e.to_string())?.connector;
            if st.unit_current || st.active {
                agent
                    .code_change(rec, &Change::ConnectorOff)
                    .map_err(|e| e.to_string())?;
            }
            Ok(())
        }
        Action::StopSession | Action::StopProcess => {
            let target = plan.target.as_deref().ok_or("nothing to stop")?;
            let stop = if plan.action == Action::StopSession {
                crate::code::procs::Stop::session(target)?
            } else {
                crate::code::procs::Stop::process(
                    target.parse().map_err(|_| "not a process number")?,
                )?
            };
            agent.code_stop(rec, &stop).map_err(|e| e.to_string())
        }
    }
}
