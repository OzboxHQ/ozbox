//! `ozbox serve`: a local HTTP server for the web dashboard.
//!
//! * Bound to a loopback address only (ADR 0005). Any other bind is refused before anything listens.
//! * A random access token is generated at start and printed in the URL fragment. Every `/v1` request must carry it
//!   in an `Authorization: Bearer` header. The static dashboard files hold no data and need no token.
//! * Same origin only: the `Host` header must be the address the server is bound to (this also defeats DNS
//!   rebinding) and a present `Origin` header must match it. No CORS headers are ever sent.
//! * Plan, then apply (ADR 0002): `POST /v1/plans` never mutates. `POST /v1/apply` applies only a plan this server
//!   issued, once, and a high-risk plan needs the box name typed.
//!
//! The request handler is a plain function over [`Req`] and [`Resp`], so it is tested without a socket.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ozbox_core::{
    BoxName, BoxRecord, BoxState, Error, MetricsSample, Operation, Plan, Provider, Risk,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::messages::t;
use crate::netguard::{HttpClient, UreqClient};
use crate::notify::Engine;
use crate::pricing::PriceCache;
use crate::secrets::SecretStore;
use crate::settings::Settings;
use crate::sshconfig::{self, RouteInputs};
use crate::state::ServerState;
use agent::AgentError;
pub(crate) use agent::BoxAgent;
use ozbox_core::{CommandRunner, SystemRunner};

pub(crate) mod access;
pub(crate) mod agent;
mod agent_mcp_routes;
mod apply_jobs;
mod approval_requests;
mod approvals;
mod apps;
pub(crate) mod auth;
mod backups;
mod browser_routes;
mod chat_routes;
mod code_routes;
mod cost_routes;
mod demo_telegram;
mod files;
mod fleet_routes;
mod lane;
#[cfg(test)]
mod lane_tests;
mod memory_routes;
mod metrics_sim;
mod models_routes;
pub(crate) mod no_simulation;
mod orch_merge;
mod orch_routes;
mod perm_routes;
mod provider_check;
mod roles;
mod run_transport;
mod sched_routes;
pub(crate) mod setup;
mod sim_code;
mod skills_routes;
mod telegram_bridge;
mod telegram_link;
#[cfg(test)]
mod telegram_tests;
#[cfg(test)]
pub(crate) use sim_code::accept_key as sim_code_accept;
pub(crate) mod runs_routes;
mod sim_restic;
#[cfg(unix)]
mod terminal;
mod test_runs;
mod tools;
mod tools_routes;
#[cfg(unix)]
mod transport;
mod usage;
mod worker;

mod embedded {
    include!(concat!(env!("OUT_DIR"), "/dashboard_assets.rs"));
}

const MAX_BODY: usize = 64 * 1024;
const MAX_ISSUED_PLANS: usize = 256;
const PLAN_TTL: Duration = Duration::from_secs(10 * 60);
/// How much longer than [`PLAN_TTL`] a plan is kept while the box it names is being made ready.
const QUIESCE_PLAN_GRACE: Duration = Duration::from_secs(10 * 60);
const MAX_SERIES_POINTS: u64 = 2000;
const MAX_ACTIVITY: usize = 500;
const MAX_STREAMS: usize = 8;

/// The page served when the program was built without the dashboard. It exists only in such a build: with a dashboard
/// embedded (`dashboard_embedded`, set by build.rs) the text is not in the program at all, which is what lets a release
/// check prove "this binary cannot serve the placeholder" by looking for it.
#[cfg(dashboard_embedded)]
const NOT_BUILT_PAGE: &str = "";
#[cfg(not(dashboard_embedded))]
const NOT_BUILT_PAGE: &str = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Oz Box dashboard</title></head>\
<body><main><h1>The dashboard is not built</h1>\
<p>Run <code>npm ci &amp;&amp; npm run build</code> in <code>packages/dashboard</code>, then rebuild <code>ozbox</code>.</p>\
</main></body></html>";

/// What UI this program carries, read from the program itself: whether a dashboard is embedded, the content hash of
/// exactly what was, and whether the placeholder page is compiled in. `ozbox build-info` prints it, which is how a release
/// check learns the truth by RUNNING the program (a hash the compiler may split across a binary cannot be searched for).
pub fn dashboard_build() -> (bool, &'static str, bool) {
    (
        !embedded::EMBEDDED.is_empty(),
        env!("OZBOX_DASHBOARD_SHA256"),
        !NOT_BUILT_PAGE.is_empty(),
    )
}

/// A parsed HTTP request, independent of the server library.
#[derive(Debug, Clone)]
pub struct Req {
    pub method: String,
    pub path: String,
    pub query: String,
    /// Header names lower-cased.
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl Req {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }
}

#[derive(Debug, Clone)]
pub struct Resp {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
    pub no_store: bool,
    /// The handler authorised an event stream; the server loop takes over the connection.
    pub stream: bool,
}

impl Resp {
    fn json(status: u16, v: &impl Serialize) -> Resp {
        match serde_json::to_vec(v) {
            Ok(body) => Resp {
                status,
                content_type: "application/json",
                body,
                no_store: true,
                stream: false,
            },
            Err(_) => Resp::error(500, "internal", "could not encode the response"),
        }
    }

    fn error(status: u16, code: &str, message: &str) -> Resp {
        let body =
            serde_json::to_vec(&json!({ "code": code, "message": message, "error": message }))
                .unwrap_or_default();
        Resp {
            status,
            content_type: "application/json",
            body,
            no_store: true,
            stream: false,
        }
    }

    fn from_core(e: &Error) -> Resp {
        let (status, code) = match e {
            Error::InvalidName { .. } | Error::Json(_) => (400, "bad_request"),
            Error::NotFound(_) => (404, "not_found"),
            Error::AlreadyExists(_) => (409, "already_exists"),
            Error::InvalidState { .. } => (409, "invalid_state"),
            Error::StalePlan(_) => (409, "stale_plan"),
            Error::Unsupported { .. } => (422, "unsupported"),
            Error::Config(_) => (422, "refused"),
            _ => (502, "provider_error"),
        };
        // a provider's own words name the account and the identity it refused: redact them before they reach a viewer
        let msg = if code == "provider_error" {
            provider_check::safe_error(&e.to_string())
        } else {
            e.to_string()
        };
        Resp::error(status, code, &msg)
    }
}

/// Where the boxes a dashboard lists come from. The dashboard marks demo data on every page and says plainly when the
/// fleet is not connected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FleetMode {
    /// A real provider: boxes can be created, changed and destroyed from here.
    Connected,
    /// A box's own dashboard with no provider: this box only.
    ThisBox,
    /// The simulated provider: nothing here is real.
    Demo,
    /// A box's dashboard that manages the fleet through its own scoped roles (ADR 0040): every change needs a change window
    /// opened from the owner's computer and the owner's passkey over that exact plan.
    Managed,
}

impl FleetMode {
    fn json(self) -> Value {
        match self {
            FleetMode::Connected => {
                json!({ "mode": "connected", "connected": true, "demo": false })
            }
            FleetMode::ThisBox => json!({
                "mode": "this_box",
                "connected": false,
                "demo": false,
                "code": crate::this_box::FLEET_NOT_CONNECTED,
                "message": crate::this_box::FLEET_NOT_CONNECTED_MESSAGE,
                "docs": DOCS_THIS_BOX,
            }),
            FleetMode::Demo => json!({ "mode": "demo", "connected": true, "demo": true }),
            FleetMode::Managed => json!({
                "mode": "managed",
                "connected": true,
                "demo": false,
                "changes_need": ["change_window", "owner_passkey"],
            }),
        }
    }
}

/// Where the dashboard points a person who sees "fleet not connected" (a page of the use-cases guide).
const DOCS_THIS_BOX: &str = "use-cases/coding-from-anywhere#9-run-the-dashboard-on-a-box-always-on";

/// The endpoints that need a fleet behind them: changing boxes, and what is priced or backed up across boxes.
fn needs_fleet(segs: &[&str], post: bool) -> bool {
    matches!(segs, ["plans"] | ["apply"] if post) || matches!(segs, ["cost", ..] | ["backups", ..])
}

/// Filled by the thread that gets a box ready; empty while it works.
type QuiesceSlot = Arc<Mutex<Option<crate::quiesce::Quiesced>>>;

struct Issued {
    plan: Plan,
    at: Instant,
    at_ms: u64,
    /// Upgrade only: the person accepted that the box's secrets store will not survive (see `run::upgrade::store_gate`).
    new_store_accepted: bool,
}

/// One thing that happened through this server, newest last. In memory: it lasts as long as the server runs.
#[derive(Debug, Clone, Serialize)]
pub struct ActivityEntry {
    pub ts_ms: u64,
    /// Who did it, in words: the signed-in person, "access link" on a dashboard opened with one, or "automation".
    pub actor: String,
    pub action: String,
    pub box_name: String,
    pub risk: Option<Risk>,
    pub outcome: String,
}

/// Who a change in Activity is by. Decided once per request (a person is known only behind a sign-in) and carried on whatever
/// outlives the request (a background change, a file transfer), so a person is never credited with someone else's work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Actor {
    /// The signed-in person's id.
    Person(String),
    /// A dashboard with no sign-in: whoever holds the access link.
    AccessLink,
    /// Not a request from a person: a webhook, a trigger, a timer.
    Automation,
}

impl Actor {
    /// What the Activity list shows.
    pub(crate) fn shown(&self) -> String {
        match self {
            Actor::Person(p) => p.clone(),
            Actor::AccessLink => "access link".to_string(),
            Actor::Automation => "automation".to_string(),
        }
    }

    /// What the audit chain records. `owner` is what it has always said for the access link (which only exists where
    /// nobody signs in). Automation is written with a colon, which no person's id can contain, so it is never confused
    /// with someone called "automation".
    fn chain(&self) -> String {
        match self {
            Actor::Person(p) => p.clone(),
            Actor::AccessLink => "owner".to_string(),
            Actor::Automation => "system:automation".to_string(),
        }
    }
}

/// What `ozbox serve` knows: the provider, the token and the plans it has handed out.
pub struct App {
    provider: Arc<dyn Provider>,
    provider_id: String,
    simulated_metrics: bool,
    /// The usage reads of each box and range: one in flight at a time, and the last answer kept to show when the box is slow.
    reads: Mutex<BTreeMap<String, Arc<Mutex<ReadSlot>>>>,
    /// What the reads that wait on the cloud or on a box share, so they run off this loop (see `lane`).
    lane: Arc<lane::Lane>,
    /// How long a read waits for a box it has no earlier answer for, and for one it has.
    read_budget: Duration,
    read_grace: Duration,
    token: String,
    allowed_hosts: Vec<String>,
    plans: HashMap<String, Issued>,
    /// A change that stops a box first gets the box ready on a thread of its own, so this server's one request loop is never
    /// held for minutes: the first apply starts it and answers `quiescing`, the next ones (the page asks again) find it.
    /// (with the box record, so a plan that is dropped can still lift the hold its job placed)
    quiesce_jobs: HashMap<String, (QuiesceSlot, BoxRecord)>,
    plan_ttl: Duration,
    /// The last provider check and when it was made (reused for a few seconds).
    domain: Option<String>,
    settings: Settings,
    settings_path: Option<std::path::PathBuf>,
    agent: Arc<dyn BoxAgent>,
    route_inputs: RouteInputs,
    /// Where the dedicated SSH key lives (`~/.ssh`); `None` skips creating it.
    ssh_dir: Option<std::path::PathBuf>,
    runner: Arc<dyn CommandRunner>,
    secrets: Arc<dyn SecretStore>,
    http: Arc<dyn HttpClient>,
    prices: PriceCache,
    prices_path: Option<std::path::PathBuf>,
    state: ServerState,
    state_path: Option<std::path::PathBuf>,
    engine: Engine,
    /// The Telegram bridge's links, delegations, replay set and what is waiting for a passkey (see `telegram_link`).
    tg: telegram_link::TgRt,
    schedule: apps::Schedule,
    /// The backup schedule's runtime: what is running, and what the worker has finished.
    backup_rt: backups::Runtime,
    activity: VecDeque<ActivityEntry>,
    /// Who the request being answered is from (`Automation` between requests).
    current_actor: Actor,
    /// Skills seen on a box that this dashboard has no push record for (`box:skill:hash`), so each is audited once, not on every look.
    unrecorded_skills: std::collections::BTreeSet<String>,
    /// Per box: when the current day's window began, how many sightings were noted in it, and how many were held back.
    unrecorded_budget: HashMap<String, (u64, usize, usize)>,
    /// The same window across every box: when it began and how many sightings it has noted.
    unrecorded_global: (u64, usize),
    /// Changes to boxes that run in the background (see `apply_jobs`).
    apply_jobs: apply_jobs::Jobs,
    version: Arc<AtomicU64>,
    streams: Arc<AtomicUsize>,
    files: files::Proxy,
    worker: worker::Worker,
    /// Test sends running in the background, read by `GET /v1/alerts/tests/<id>`.
    test_runs: Arc<std::sync::Mutex<test_runs::TestRuns>>,
    /// The local stand-in for Telegram, present only for the simulated server that asked for it (see `demo_telegram`).
    demo_telegram: Option<demo_telegram::Shared>,
    tools_cfg: tools_routes::ToolsCfg,
    /// Agent runs: the task store and the supervisor (see `runs_routes`).
    runs: runs_routes::RunsRt,
    /// Orchestrations: the tools' listener, the merge queue's hands (see `orch_routes`).
    orch: orch_routes::OrchRt,
    /// Agent memory and reviewed skills, opened on first use (see `memory_routes`).
    memory_host: Option<Arc<crate::memory_tools::MemoryHost>>,
    /// The chat gateway's memory: transcripts, rate limits, links (see `chat_routes`).
    chat: chat_routes::ChatRt,
    /// Sign-in for a dashboard on a shared machine; `None` = the local access token.
    auth: Option<Arc<auth::Auth>>,
    /// A box's dashboard that manages the fleet (ADR 0040): the gate every change passes. `None` everywhere today but in
    /// tests: the credential holder it needs is not built, so a box's dashboard still says the fleet is not connected.
    fleet_gate: Option<crate::fleet_gate::FleetGate>,
    /// This server runs on a box (its secrets service is there): without a sign-in, its access token is not proof of the
    /// person there (see `roles::step_up_gate`).
    on_a_box: bool,
    /// Cookies and redirects the last `handle` asked for.
    extra_headers: Vec<(String, String)>,
    /// Approval requests a message was already sent for (see `serve::approval_requests`), so each is told once.
    notified_requests: std::collections::BTreeSet<String>,
    /// How the dashboard is reached from outside, and the tunnel (`/v1/dashboard-access`).
    access: access::AccessCtx,
    setup: setup::SetupState,
    code: code_routes::CodeState,
    sched: sched_routes::Rt,
    /// The real bill beside the estimate, the drift between them and the forgotten resources (see `cost_routes`).
    cost: cost_routes::CostRt,
    #[cfg(unix)]
    terminals: terminal::Sessions,
}

#[derive(Deserialize)]
struct PlanRequest {
    operation: Operation,
    /// Upgrade only: use an image whose release signature could not be verified. Absent means refuse it.
    #[serde(default)]
    allow_unverified_image: bool,
    /// Upgrade only: go ahead although the box's secrets store will not survive, or the box could not be asked (the same
    /// as the command's --accept-new-secrets-store). Absent means refuse such an upgrade.
    #[serde(default)]
    accept_new_secrets_store: bool,
    /// Upgrade only, AWS: do not keep a copy of the old system disk (the same as the command's --no-pre-upgrade-snapshot). Absent
    /// means a copy is kept when the store's key cannot be shown to survive.
    #[serde(default)]
    no_pre_upgrade_snapshot: bool,
}

#[derive(Deserialize)]
struct ApplyRequest {
    plan_id: String,
    /// Optional echo of the plan being confirmed; it must equal the plan this server issued.
    plan: Option<Plan>,
    confirm_name: Option<String>,
    /// The passkey assertion over this plan's fleet challenge (ADR 0040 §2), when the dashboard manages the fleet.
    #[serde(default)]
    fleet_assertion: Option<Value>,
}

/// Parse `--bind`. Only loopback addresses (and `localhost`) are accepted: nothing here may listen publicly.
pub fn parse_bind(raw: &str) -> Result<IpAddr, String> {
    let ip = if raw.eq_ignore_ascii_case("localhost") {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    } else {
        raw.parse::<IpAddr>()
            .map_err(|_| format!("{raw:?} is not an IP address; use 127.0.0.1 or ::1"))?
    };
    if ip.is_loopback() {
        Ok(ip)
    } else {
        Err(format!(
            "refusing to bind {raw}: the dashboard server listens on a loopback address only (127.0.0.1 or ::1)"
        ))
    }
}

fn random_hex(bytes: usize) -> Result<String, String> {
    let mut buf = vec![0u8; bytes];
    getrandom::getrandom(&mut buf).map_err(|e| format!("no secure random source: {e}"))?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub(crate) fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl App {
    pub fn new(
        provider: Box<dyn Provider>,
        simulated_metrics: bool,
        addr: SocketAddr,
        token: String,
    ) -> Self {
        let port = addr.port();
        let mut allowed_hosts = vec![format!("{}:{port}", host_literal(addr.ip()))];
        if addr.ip().is_ipv4() {
            allowed_hosts.push(format!("localhost:{port}"));
        }
        let provider_id = provider.id().to_string();
        let version = Arc::new(AtomicU64::new(0));
        App {
            lane: lane::Lane::new(Arc::clone(&version), lane::Budgets::for_app()),
            provider: Arc::from(provider),
            provider_id,
            simulated_metrics,
            reads: Mutex::new(BTreeMap::new()),
            read_budget: READ_BUDGET,
            read_grace: READ_GRACE,
            token,
            allowed_hosts,
            plans: HashMap::new(),
            quiesce_jobs: HashMap::new(),
            on_a_box: ozbox_core::audit_remote::BOX_MARKERS
                .iter()
                .any(|p| std::path::Path::new(p).exists()),
            plan_ttl: PLAN_TTL,
            domain: None,
            settings: Settings::default(),
            settings_path: None,
            agent: if simulated_metrics {
                Arc::new(agent::SimulatedAgent::default())
            } else {
                Arc::new(agent::NoTransport)
            },
            route_inputs: RouteInputs::default(),
            ssh_dir: None,
            runner: Arc::new(SystemRunner),
            secrets: Arc::new(crate::secrets::MemorySecrets::default()),
            http: Arc::new(UreqClient),
            prices: PriceCache::default(),
            prices_path: None,
            state: ServerState::default(),
            state_path: None,
            engine: Engine::default(),
            tg: telegram_link::TgRt::in_memory(),
            schedule: apps::Schedule::default(),
            backup_rt: backups::Runtime::default(),
            activity: VecDeque::new(),
            current_actor: Actor::Automation,
            unrecorded_skills: std::collections::BTreeSet::new(),
            unrecorded_budget: HashMap::new(),
            unrecorded_global: (0, 0),
            apply_jobs: apply_jobs::Jobs::default(),
            version,
            streams: Arc::new(AtomicUsize::new(0)),
            files: files::Proxy::default(),
            tools_cfg: tools_routes::ToolsCfg::default(),
            runs: runs_routes::RunsRt::default(),
            orch: orch_routes::OrchRt::default(),
            memory_host: None,
            chat: chat_routes::ChatRt::default(),
            setup: setup::SetupState::default(),
            worker: worker::Worker::inline(),
            test_runs: Arc::default(),
            demo_telegram: None,
            auth: None,
            fleet_gate: None,
            extra_headers: Vec::new(),
            notified_requests: std::collections::BTreeSet::new(),
            access: access::AccessCtx::default(),
            code: code_routes::CodeState::default(),
            sched: sched_routes::Rt::default(),
            cost: cost_routes::CostRt::default(),
            #[cfg(unix)]
            terminals: terminal::Sessions::default(),
        }
    }

    /// How the dashboard is reached from outside, for `/v1/dashboard-access`.
    pub fn with_access(mut self, access: access::AccessCtx) -> Self {
        self.access = access;
        self
    }

    /// The domain boxes are reached under (`https://<name>.<domain>`), if one is configured.
    pub fn with_domain(mut self, domain: Option<String>) -> Self {
        self.domain = domain.filter(|d| !d.is_empty());
        self
    }

    /// Budgets and defaults, and the file they are saved to (`None` keeps changes in memory only).
    pub fn with_settings(mut self, settings: Settings, path: Option<std::path::PathBuf>) -> Self {
        self.settings = settings;
        self.settings_path = path;
        self
    }

    /// Run background work on its own thread (the server does; tests keep the inline default).
    pub fn with_background_worker(mut self) -> Self {
        self.worker = worker::Worker::threaded();
        self
    }

    pub fn with_ssh_dir(mut self, dir: Option<std::path::PathBuf>) -> Self {
        self.ssh_dir = dir;
        self
    }

    pub fn with_route_inputs(mut self, inputs: RouteInputs) -> Self {
        self.route_inputs = inputs;
        self
    }

    pub fn with_agent(mut self, agent: Box<dyn BoxAgent>) -> Self {
        self.agent = Arc::from(agent);
        self
    }

    pub fn with_secrets(mut self, secrets: Arc<dyn SecretStore>) -> Self {
        self.secrets = secrets;
        self.sync_second_factor();
        self
    }

    #[cfg(test)]
    fn with_http(mut self, http: Arc<dyn HttpClient>) -> Self {
        self.http = http;
        self.demo_telegram = None;
        self
    }

    #[cfg(test)]
    #[allow(dead_code)]
    fn with_runner(mut self, runner: Arc<dyn CommandRunner>) -> Self {
        self.runner = runner;
        self
    }

    /// Where the price cache and the remembered state are kept (`None` keeps them in memory only).
    pub fn with_files(
        mut self,
        prices: Option<std::path::PathBuf>,
        state: Option<std::path::PathBuf>,
    ) -> Self {
        if let Some(p) = &prices {
            self.prices = PriceCache::load(p);
        }
        if let Some(p) = &state {
            self.state = ServerState::load(p);
        }
        self.prices_path = prices;
        self.state_path = state;
        if let Some(sp) = self.state_path.clone() {
            // the Telegram links and the replay set live in their own, durably written file beside the state
            self.tg = telegram_link::TgRt::beside(&sp);
        }
        self
    }

    /// Where profiles and the tools chosen at create time are kept.
    pub fn with_tools_cfg(
        mut self,
        profiles_dir: Option<std::path::PathBuf>,
        pending: Option<std::path::PathBuf>,
    ) -> Self {
        self.tools_cfg = tools_routes::ToolsCfg::new(profiles_dir, pending);
        self
    }

    pub fn version(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.version)
    }

    pub fn streams(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.streams)
    }

    fn log_activity(&mut self, action: &str, box_name: &str, risk: Option<Risk>, outcome: &str) {
        if self.activity.len() >= MAX_ACTIVITY {
            self.activity.pop_front();
        }
        // Box lifecycle, secret changes (the name only) and settings changes go in the audit chain too: ids and words only.
        let snake = action.replace(' ', "_");
        let word = if action.starts_with("apply ") {
            format!("box.{}", snake.trim_start_matches("apply_"))
        } else if action.contains("secret") {
            format!("secret.{}", snake.replace("_secret", ""))
        } else if box_name == "-" {
            format!("settings.{snake}")
        } else {
            format!("activity.{snake}")
        };
        self.chain_event(
            &self.current_actor.chain(),
            &word,
            (box_name != "-").then_some(box_name),
            outcome,
        );
        self.activity.push_back(ActivityEntry {
            ts_ms: unix_ms(),
            actor: self.current_actor.shown(),
            action: action.to_string(),
            box_name: box_name.to_string(),
            risk,
            outcome: outcome.to_string(),
        });
    }

    #[cfg(test)]
    fn with_read_budgets(mut self, budget: Duration, grace: Duration) -> Self {
        self.read_budget = budget;
        self.read_grace = grace;
        self
    }

    #[cfg(test)]
    fn with_lane_budgets(mut self, budgets: lane::Budgets) -> Self {
        self.lane = lane::Lane::new(Arc::clone(&self.version), budgets);
        self
    }

    #[cfg(test)]
    fn with_plan_ttl(mut self, ttl: Duration) -> Self {
        self.plan_ttl = ttl;
        self
    }

    fn host_ok(&self, host: &str) -> bool {
        self.allowed_hosts
            .iter()
            .any(|h| h.eq_ignore_ascii_case(host))
    }

    /// Same-origin checks, and the bearer token when `need_token`. `None` means the request may go on.
    fn guard(&self, req: &Req, need_token: bool) -> Option<Resp> {
        if let Some(a) = &self.auth {
            if let Some(r) = a.guard(req, need_token) {
                return Some(r);
            }
            // what the signed-in person's role may do: decided here, for every request that reaches the API, a file
            // transfer or a terminal stream (see `roles`)
            return if need_token {
                self.role_gate(req)
            } else {
                None
            };
        }
        // Same origin only: the Host must be where we are bound, and an Origin (sent on cross-site and on
        // same-site POSTs) must be us.
        match req.header("host") {
            Some(h) if self.host_ok(h) => {}
            _ => {
                return Some(Resp::error(
                    403,
                    "bad_host",
                    "this server answers only on its own address",
                ))
            }
        }
        if let Some(origin) = req.header("origin") {
            let ok = origin
                .strip_prefix("http://")
                .is_some_and(|h| self.host_ok(h));
            if !ok {
                return Some(Resp::error(
                    403,
                    "bad_origin",
                    "cross-origin requests are not allowed",
                ));
            }
        }
        if need_token {
            let presented = req
                .header("authorization")
                .and_then(|v| v.strip_prefix("Bearer "))
                .unwrap_or("");
            if !ct_eq(presented, &self.token) {
                return Some(Resp::error(
                    401,
                    "unauthorized",
                    "a valid access token is required",
                ));
            }
        }
        None
    }

    /// Cookies and redirects the last request asked for (taken once).
    pub fn take_extra_headers(&mut self) -> Vec<(String, String)> {
        std::mem::take(&mut self.extra_headers)
    }

    /// Turn on sign-in (the `--public-behind-tunnel` mode): the local token no longer opens anything.
    /// Manage the fleet from this dashboard through `gate` (ADR 0040). Every change then also needs a window for its plan and
    /// the owner's passkey over that plan; nothing else about plan and apply changes.
    #[cfg(test)]
    pub(crate) fn with_fleet_gate(mut self, gate: crate::fleet_gate::FleetGate) -> Self {
        self.fleet_gate = Some(gate);
        self
    }

    pub fn with_auth(mut self, auth: Arc<auth::Auth>) -> Self {
        self.auth = Some(auth);
        self.sync_second_factor();
        self
    }

    /// Answer `req`, waiting for anything that has to be waited for (tests; the server loop uses [`App::begin`] instead, so
    /// that a read that waits on the cloud or on a box is run by a worker and not here; the answers are the same).
    #[cfg(test)]
    pub fn handle(&mut self, req: &Req) -> Resp {
        match self.begin(req) {
            lane::Step::Done(resp) => resp,
            lane::Step::Later(job) => {
                let (resp, headers) = job();
                self.extra_headers = headers;
                resp
            }
        }
    }

    /// The first half of answering `req`, on the request loop: everything that checks who is asking and everything that
    /// changes state happens here. A read that only waits on the cloud or on a box comes back as a job, to be run anywhere.
    fn begin(&mut self, req: &Req) -> lane::Step {
        self.current_actor = Actor::Automation;
        let step = self.begin_request(req);
        // whatever logs next without a request (a timer, a finished background change) is not this person's
        self.current_actor = Actor::Automation;
        step
    }

    /// Who `req` is from: the signed-in person behind a sign-in, the access link without one. Only a request that passed
    /// the guard is asked.
    pub(crate) fn actor_of(&self, req: &Req) -> Actor {
        match &self.auth {
            Some(a) => a.person(req).map_or(Actor::Automation, Actor::Person),
            None => Actor::AccessLink,
        }
    }

    fn begin_request(&mut self, req: &Req) -> lane::Step {
        self.drain_file_activity();
        self.extra_headers.clear();
        if let Some(a) = self.auth.clone() {
            if let Some(out) = a.route(req) {
                self.extra_headers = out.headers;
                return lane::Step::Done(out.resp);
            }
        } else if req.path == "/auth/session" && req.method == "GET" {
            // The dashboard asks which way in this server uses before it shows anything.
            return lane::Step::Done(Resp::json(200, &json!({ "mode": "token" })));
        }
        if req.path == "/hooks/chat/whatsapp" {
            // public and signed by Meta, not by the dashboard's sign-in
            return lane::Step::Done(self.whatsapp_hook(req));
        }
        if req.path.starts_with("/hooks/") {
            // Public and signed: the trigger's own secret is the credential, not the dashboard's sign-in.
            return lane::Step::Done(self.hook_route(req));
        }
        if req.path == "/code/enter" && req.method == "GET" {
            return lane::Step::Done(self.code_enter(req));
        }
        if files::is_files_path(&req.path) {
            return lane::Step::Done(self.files_inline(req));
        }
        if let Some(r) = self.guard(req, req.path == "/v1" || req.path.starts_with("/v1/")) {
            return lane::Step::Done(r);
        }
        if req.path == "/v1" || req.path.starts_with("/v1/") {
            self.current_actor = self.actor_of(req);
            if let Some(job) = self.lane_job(req) {
                return lane::Step::Later(job);
            }
            return lane::Step::Done(self.api(req));
        }
        if req.method != "GET" && req.method != "HEAD" {
            return lane::Step::Done(Resp::error(405, "method_not_allowed", "method not allowed"));
        }
        lane::Step::Done(serve_static(&req.path))
    }

    /// The boxes, for a read this loop answers itself: the last read of the cloud, never a whole read of it (see `lane`).
    fn boxes_for_loop(&self) -> Result<Vec<BoxRecord>, Resp> {
        self.lane.boxes_for_loop(&self.provider)
    }

    /// The boxes, for work the server starts on its own: the last read, and never a wait. `None` before the first read.
    fn boxes_quietly(&self) -> Option<Vec<BoxRecord>> {
        self.lane.boxes_quietly(&self.provider)
    }

    /// A read that only waits on the cloud or on a box, as a job that holds shared handles and none of this server's
    /// state (see `lane`). `None` for everything else, which is answered here by [`App::api`].
    fn lane_job(&self, req: &Req) -> Option<lane::Job> {
        if req.method != "GET" {
            return None;
        }
        let segs: Vec<&str> = req
            .path
            .trim_start_matches('/')
            .split('/')
            .skip(1) // "v1"
            .filter(|s| !s.is_empty())
            .collect();
        let ctx = lane::ReadCtx {
            lane: Arc::clone(&self.lane),
            provider: Arc::clone(&self.provider),
            agent: Arc::clone(&self.agent),
            simulated: self.simulated_metrics,
            provider_id: self.provider_id.clone(),
            mode: match self.fleet_mode() {
                FleetMode::Connected => "connected",
                FleetMode::ThisBox => "this_box",
                FleetMode::Demo => "demo",
                FleetMode::Managed => "managed",
            },
        };
        let query = req.query.clone();
        let name = |n: &str| n.to_string();
        Some(match segs.as_slice() {
            ["provider", "check"] => Box::new(move || ctx.provider_check()),
            ["boxes"] => Box::new(move || ctx.boxes()),
            ["boxes", n] => {
                let n = name(n);
                Box::new(move || ctx.get_box(&n))
            }
            ["boxes", n, "metrics", "now"] => {
                let n = name(n);
                Box::new(move || ctx.metrics_now(&n))
            }
            ["boxes", n, "metrics"] => {
                let n = name(n);
                Box::new(move || ctx.metrics_series(&n, &query))
            }
            ["boxes", n, "selftest"] => {
                let n = name(n);
                Box::new(move || ctx.selftest(&n))
            }
            ["boxes", n, "incidents"] => {
                let n = name(n);
                Box::new(move || ctx.incidents(&n, &query))
            }
            ["boxes", n, "image"] => {
                let n = name(n);
                Box::new(move || ctx.image_info(&n))
            }
            _ => return None,
        })
    }

    fn api(&mut self, req: &Req) -> Resp {
        let segs: Vec<&str> = req
            .path
            .trim_start_matches('/')
            .split('/')
            .skip(1) // "v1"
            .filter(|s| !s.is_empty())
            .collect();
        let get = req.method == "GET";
        let post = req.method == "POST";
        // A dashboard on a box has no fleet behind it: what needs one says so, as a typed error, never with demo rows.
        if self.fleet_mode() == FleetMode::ThisBox && needs_fleet(&segs, post) {
            return Resp::error(
                409,
                crate::this_box::FLEET_NOT_CONNECTED,
                crate::this_box::FLEET_NOT_CONNECTED_MESSAGE,
            );
        }
        match segs.as_slice() {
            ["info"] if get => self.info(),
            ["catalog"] if get => self.catalog_json(),
            ["memory", rest @ ..] => self.memory_route(req, rest),
            ["skills", rest @ ..] => self.skills_route(req, rest),
            ["schedules", rest @ ..] => self.sched_route(&req.method, rest, &req.body),
            ["triggers", rest @ ..] => self.trigger_route(&req.method, rest, &req.body),
            ["profiles", rest @ ..] => self.profiles(&req.method, rest, &req.body),
            ["setup", rest @ ..] => self.setup_route(rest, req),
            ["dashboard-access", rest @ ..] => self.dashboard_access(req, rest),
            ["boxes", name, "tools", rest @ ..] => self.box_tools(name, rest, req),
            ["boxes", name, "skills", rest @ ..] => self.box_skills(name, rest, req),
            ["backups", rest @ ..] => self.backups_fleet(&req.method, rest, &req.body),
            ["boxes", name, "backups", rest @ ..] => self.box_backups(name, &req.method, rest),
            ["boxes", name, "code", rest @ ..] => self.box_code(name, &req.method, rest, &req.body),
            ["code", "jobs", id] if get => self.code_job(id),
            #[cfg(unix)]
            ["boxes", name, "terminal"] if post => self.terminal_open(name, &req.body),
            #[cfg(unix)]
            ["terminal", id, "input"] if post => self.terminal_input(id, &req.body),
            #[cfg(unix)]
            ["terminal", id] if req.method == "DELETE" => self.terminal_close(id),
            ["boxes", name, "ssh"] if get => self.ssh(name, false),
            ["boxes", name, "ssh"] if post => self.ssh(name, true),
            ["usage"] if get => self.usage(&req.query),
            ["cost"] if get => self.cost(),
            ["cost", "refresh"] if post => self.refresh_prices_now(),
            ["cost", rest @ ..] if rest.first().is_some_and(|r| *r != "refresh") => {
                let step_up = self.step_up_state(req);
                self.cost_route(&req.method, rest, &req.body, step_up)
            }
            ["secrets"] if get => self.secrets_status(),
            ["approvals", rest @ ..] if !rest.is_empty() => self.approval_requests_route(req, rest),
            ["secrets", "approvals"] if post => self.secrets_approval(req),
            ["secrets", "approvals"] if get => self.secrets_approvals_list(),
            // Replacing or removing a tunnel token changes where the dashboard is reached from, so behind a sign-in it needs a
            // passkey shown a moment ago, like the other tunnel changes.
            ["secrets", name]
                if matches!(req.method.as_str(), "PUT" | "DELETE")
                    && name.starts_with("tunnel-token-")
                    && self.token_step_up(req).is_some() =>
            {
                self.token_step_up(req).unwrap_or_else(|| {
                    Resp::error(
                        403,
                        "step_up_required",
                        "confirm with your passkey to continue",
                    )
                })
            }
            ["secrets", name] if req.method == "PUT" => self.put_secret(name, &req.body),
            ["secrets", name] if req.method == "DELETE" => self.delete_secret(name),
            ["apps"] if get => self.apps(),
            ["telegram", rest @ ..] => self.telegram_route(req, rest),
            ["apps", "telegram", "chats", id] if req.method == "PUT" => {
                self.link_chat(id, &req.body)
            }
            ["apps", "telegram", "chats", id] if req.method == "DELETE" => self.unpair(id),
            ["apps", "webhooks"] if post => self.add_webhook(&req.body),
            ["apps", "webhooks", id] if req.method == "DELETE" => self.remove_webhook(id),
            ["push", "key"] if get => self.push_key(),
            ["push", "devices"] if post => self.push_add_device(&req.body),
            ["push", "devices", id] if req.method == "DELETE" => self.push_remove_device(id),
            ["alerts"] if get => self.alerts(),
            ["alerts", "summary"] if get => self.alerts_summary(&req.query),
            ["alerts", "test"] if post => self.test_alert(&req.body),
            ["alerts", "tests", id] if get => self.test_run(id),
            ["demo", "telegram", "message"] if post && self.demo_telegram.is_some() => {
                self.demo_telegram_say(&req.body)
            }
            ["demo", "telegram", "legacy-chat"] if post && self.demo_telegram.is_some() => {
                self.demo_telegram_legacy_chat(&req.body)
            }
            ["demo", "telegram", "script"] if post && self.demo_telegram.is_some() => {
                self.demo_telegram_script(&req.body)
            }
            ["demo", "telegram", "fail"] if post && self.demo_telegram.is_some() => {
                self.demo_telegram_fail(&req.body)
            }
            ["demo", "alerts"] if post && self.demo_telegram.is_some() => {
                self.demo_raise_alert(&req.body)
            }
            ["demo", "telegram", "sent"] if get && self.demo_telegram.is_some() => {
                self.demo_telegram_sent()
            }
            ["models"] if get => self.models(),
            ["models", "catalog"] if get => self.models_catalog(),
            ["models", "usage"] if get => self.models_usage(&req.query),
            ["models", "local"] if get => self.models_local(),
            ["models", id, "list"] if post => self.list_provider_models(id),
            ["models", id, "price"] if get => self.model_price(id, &req.query),
            ["boxes", name, "local-ai", rest @ ..] => {
                self.box_local_ai(name, &req.method, rest, &req.body)
            }
            ["models", id, "test"] if post => self.test_model(id, &req.body),
            ["suggestions"] if get => self.suggestions(),
            ["settings"] if get => self.get_settings(),
            ["settings"] if req.method == "PUT" => self.put_settings(req),
            ["runs"] if get => self.runs(),
            ["runs", id, "logs"] if get => self.run_logs(id),
            ["tasks", rest @ ..] => self.tasks_route(req, rest),
            ["orchestrations", rest @ ..] => self.orch_route(req, rest),
            ["chat", rest @ ..] => self.chat_route(req, rest),
            ["approval-requests", rest @ ..] => self.approval_requests(req, rest),
            ["approval-policy"] => self.approval_policy(req),
            ["browser", rest @ ..] => self.browser_route(req, rest),
            ["agent-mcp"] => self.agent_mcp_route(req),
            ["permissions", rest @ ..] => self.perm_route(req, rest),
            ["people", rest @ ..] => self.people_route(req, rest),
            ["audit", rest @ ..] => self.audit_route(req, rest),
            ["host-tools"] if get => self.host_tools_route(req),
            ["spend-caps"] => self.spend_caps(req),
            ["approvals"] if get => self.approvals(),
            ["activity"] if get => Resp::json(
                200,
                &json!({ "source": "server", "since_start": true, "entries": self.activity }),
            ),
            ["events"] if get => {
                if self.streams.load(Ordering::SeqCst) >= MAX_STREAMS {
                    return Resp::error(429, "too_many_streams", "too many open event streams");
                }
                Resp {
                    status: 200,
                    content_type: "text/event-stream",
                    body: Vec::new(),
                    no_store: true,
                    stream: true,
                }
            }
            ["jobs", id] if get => self.apply_job(id),
            ["plans", id] if get => self.get_plan(id),
            ["plans"] if post => self.issue_plan(&req.body),
            ["fleet", "plans", id, "challenge"] if post => self.fleet_challenge(req, id),
            ["apply"] if post => {
                let step_up = self.step_up_state(req);
                self.apply_from(Some(req), &req.body, step_up)
            }
            ["info"]
            | ["boxes"]
            | ["boxes", _]
            | ["boxes", _, "metrics"]
            | ["boxes", _, "ssh"]
            | ["boxes", _, "selftest"]
            | ["boxes", _, "image"]
            | ["boxes", _, "incidents"]
            | ["usage"]
            | ["cost"]
            | ["cost", "refresh"]
            | ["secrets"]
            | ["secrets", _]
            | ["apps"]
            | ["apps", "telegram", "chats", _]
            | ["apps", "webhooks"]
            | ["apps", "webhooks", _]
            | ["push", "key"]
            | ["push", "devices"]
            | ["push", "devices", _]
            | ["alerts"]
            | ["alerts", "summary"]
            | ["alerts", "test"]
            | ["alerts", "tests", _]
            | ["models"]
            | ["models", _, "test"]
            | ["models", "catalog"]
            | ["models", "usage"]
            | ["models", "local"]
            | ["models", _, "list"]
            | ["models", _, "price"]
            | ["suggestions"]
            | ["settings"]
            | ["boxes", _, "metrics", "now"]
            | ["jobs", _]
            | ["plans"]
            | ["apply"] => Resp::error(405, "method_not_allowed", "method not allowed"),
            _ => Resp::error(404, "not_found", "no such endpoint"),
        }
    }

    /// What the boxes this dashboard lists are: a fleet it can manage, this box alone, or made-up demo boxes.
    fn fleet_mode(&self) -> FleetMode {
        if self.fleet_gate.is_some() {
            return FleetMode::Managed;
        }
        match self.provider_id.as_str() {
            crate::this_box::PROVIDER_ID => FleetMode::ThisBox,
            ozbox_provider_fake::PROVIDER_ID => FleetMode::Demo,
            _ => FleetMode::Connected,
        }
    }

    fn info(&self) -> Resp {
        let caps = self.provider.capabilities();
        let sizes: Vec<Value> = caps
            .sizes
            .iter()
            .map(|s| {
                let spec = s.spec();
                json!({
                    "id": s.to_string(),
                    "size": s,
                    "vcpus": spec.vcpus,
                    "memory_gb": spec.memory_gb,
                    "gpus": spec.gpus,
                    "quote": self.size_quote(*s),
                })
            })
            .collect();
        Resp::json(
            200,
            &json!({
                "version": env!("CARGO_PKG_VERSION"),
                // Which UI this program serves: whether one is embedded, and the hash of exactly what was (the release
                // manifest records the same hash).
                "dashboard": {
                    "embedded": !embedded::EMBEDDED.is_empty(),
                    "sha256": env!("OZBOX_DASHBOARD_SHA256"),
                },
                "provider": self.provider_id,
                "fleet": self.fleet_mode().json(),
                "metrics": self.data_source(),
                "secret_store": self.secrets.label(),
                // true when a loosening (a higher limit, a looser policy) will be refused: no sign-in, on a box
                "loosening_refused": self.auth.is_none() && self.on_a_box,
                "domain": self.domain,
                "setup": self.setup_summary(),
                "clock": {
                    "time_zone": self.settings.locale.zone(),
                    "now": crate::timezone::format_with_utc(self.settings.locale.zone(), unix_ms()),
                },
                "capabilities": caps,
                "sizes": sizes,
            }),
        )
    }

    fn record(&self, name: &str) -> Result<BoxRecord, Resp> {
        let name = BoxName::new(name).map_err(|e| Resp::from_core(&e))?;
        match self.provider.get(&name) {
            Ok(Some(r)) => Ok(r),
            Ok(None) => Err(Resp::from_core(&Error::NotFound(name.to_string()))),
            Err(e) => Err(Resp::from_core(&e)),
        }
    }

    fn issue_plan(&mut self, body: &[u8]) -> Resp {
        let mut raw: Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(e) => return Resp::error(400, "bad_request", &format!("invalid request: {e}")),
        };
        crate::settings::fill_create_defaults(&self.settings, &mut raw);
        let mut request: PlanRequest = match serde_json::from_value(raw) {
            Ok(r) => r,
            Err(e) => return Resp::error(400, "bad_request", &format!("invalid request: {e}")),
        };
        // What the fleet cap and budget see. An upgrade is held to what starting the box would be.
        let mut budget_op = request.operation.clone();
        if let Operation::Upgrade { name, image, .. } = &mut request.operation {
            let rec = match self.record(name.as_str()) {
                Ok(r) => r,
                Err(r) => return r,
            };
            // `latest` is a way of asking, never a plan: the plan names the image it resolved to.
            if image.trim().is_empty() || image.trim() == "latest" {
                // A box whose machine is gone is finished on the image it was marked with, not the newest one.
                if let Some(m) = crate::run::upgrade::finishing_image(&rec) {
                    *image = m;
                } else {
                    match self
                        .provider
                        .latest_image_for(rec.spec.region.as_deref(), rec.machine_type.as_deref())
                    {
                        Ok(i) => *image = i.id,
                        Err(e) => return Resp::from_core(&e),
                    }
                }
            }
            budget_op = crate::run::upgrade::budget_view(&request.operation, &rec);
        }
        // A restore into a new box adds a box like a clone does: the fleet cap and the budget see it as one.
        if let Operation::RestoreToNewBox { from, to, .. } = &request.operation {
            budget_op = Operation::Clone {
                from: from.clone(),
                to: to.clone(),
                snapshot: None,
            };
        }
        if let Err(e) = crate::settings::enforce(&self.settings, self.provider.as_ref(), &budget_op)
        {
            return Resp::from_core(&e);
        }
        if let Err(r) = self.guard_rails(&request.operation) {
            return r;
        }
        // `plan` never changes anything (provider contract, rule 1).
        let planned = match self.plan_restic(&request.operation) {
            Some(Ok(p)) => Ok(p),
            Some(Err(resp)) => return resp,
            None => self.provider.plan(&request.operation),
        };
        let mut plan = match planned {
            Ok(p) => p,
            Err(e) => return Resp::from_core(&e),
        };
        // what the provider itself said; the replan that adds a copy of the old system disk keeps what is added after it
        let base_notes = plan.notes.len();
        let mut store_warning: Option<String> = None;
        if let (Operation::Upgrade { name, image, .. }, false) =
            (&request.operation, plan.is_noop())
        {
            // The same rule as the command: an image whose signature could be checked and was not is refused.
            let rec = self.record(name.as_str()).ok();
            let region = rec.as_ref().and_then(|r| r.spec.region.clone());
            let machine = rec.as_ref().and_then(|r| r.machine_type.clone());
            let info = self
                .provider
                .image_info(image, region.as_deref())
                .ok()
                .or_else(|| {
                    self.provider
                        .latest_image_for(region.as_deref(), machine.as_deref())
                        .ok()
                        .filter(|i| &i.id == image)
                });
            match crate::run::upgrade::trust_gate(
                info.as_ref(),
                image,
                request.allow_unverified_image,
            ) {
                Ok(notes) => plan.notes.extend(notes),
                Err(refusal) => {
                    // The text is the command's (it names the CLI flag); `image` and `signature_detail` are additive
                    // fields so a screen can say the same thing in its own words.
                    let detail = info.as_ref().and_then(|i| i.signature_detail.clone());
                    return Resp::json(
                        409,
                        &json!({
                            "code": "image_unverified",
                            "message": refusal,
                            "error": refusal,
                            "image": image,
                            "signature_detail": detail,
                        }),
                    );
                }
            }
            // The same rule as the command: the image and this program must render the same first boot. The dashboard
            // has no override; the command's --allow-first-boot-mismatch is the way past it.
            match crate::run::upgrade::first_boot_gate(
                info.as_ref(),
                image,
                &crate::infra_cli::effective_first_boot(),
                false,
            ) {
                Ok(notes) => plan.notes.extend(notes),
                Err(refusal) => {
                    return Resp::json(
                        409,
                        &json!({
                            "code": "first_boot_mismatch",
                            "message": refusal,
                            "error": refusal,
                            "image": image,
                        }),
                    );
                }
            }
            // The same rule as the command: what happens to the box's secrets store is in every plan, and a store that
            // would be lost (or a box that could not be asked) is refused unless the person accepts it.
            if let Ok(rec) = self.record(name.as_str()) {
                // on AWS the store's fate is read from the box's root, never from the box user's SSH answer
                let root: Option<crate::run::upgrade::RootFacts<'_>> =
                    (self.provider_id == "aws").then_some(&crate::run::aws_root_facts_now);
                let check = crate::run::upgrade::store_check(
                    self.agent.as_ref(),
                    &rec,
                    self.simulated_metrics,
                    // the dashboard does not read this computer's keychain (the command does): an escrow kept there is not counted
                    false,
                    root,
                );
                match crate::run::upgrade::store_gate(
                    &check,
                    name.as_str(),
                    request.accept_new_secrets_store,
                ) {
                    Ok(note) => {
                        // The same rule as the command: a store whose key may be destroyed with the old system disk gets a copy
                        // of that disk first, in the plan, and the warning in words ahead of every other note.
                        let old_disk = crate::run::upgrade::OldDisk::choose(
                            &self.provider_id,
                            request.no_pre_upgrade_snapshot,
                            false,
                        );
                        if crate::run::upgrade::old_disk_copy_wanted(check.fate, old_disk) {
                            plan = match crate::run::upgrade::with_old_disk_copy(
                                self.provider.as_ref(),
                                plan,
                                base_notes,
                            ) {
                                Ok(p) => p,
                                Err(e) => return Resp::from_core(&e),
                            };
                        }
                        plan.notes.push(note);
                        store_warning = crate::run::upgrade::store_loss_warning(
                            &check,
                            name.as_str(),
                            old_disk,
                        );
                        if let Some(w) = &store_warning {
                            plan.notes.insert(0, w.clone());
                        }
                    }
                    Err(refusal) => {
                        return Resp::json(
                            409,
                            &json!({
                                "code": crate::run::upgrade::store_refusal_code(check.fate),
                                "message": refusal,
                                "error": refusal,
                                "fate": check.fate,
                            }),
                        );
                    }
                }
            } else {
                // a store verdict that could not be reached is not a pass (the same rule as an answer that cannot be asked)
                return Resp::json(
                    409,
                    &json!({
                        "code": "secrets_store_unchecked",
                        "message": "The box's secrets store could not be checked, so no upgrade was planned. Nothing was changed. Try again.",
                        "error": "The box's secrets store could not be checked, so no upgrade was planned. Nothing was changed. Try again.",
                    }),
                );
            }
        }
        // A change that stops a running box says what will end, read from the box and never changed, before anyone confirms.
        if !plan.is_noop() {
            if let Ok(Some(rec)) = self.provider.get(plan.operation.box_name()) {
                if crate::quiesce::needed(&plan, &rec) {
                    plan.notes.extend(
                        crate::quiesce::preview(self.agent.as_ref(), &rec)
                            .notes(rec.spec.name.as_str()),
                    );
                }
            }
        }
        let now = Instant::now();
        let ttl = self.plan_ttl;
        // A plan whose box was made ready is kept a little past its time to live, so the page's later asks still find it.
        let quiescing = &self.quiesce_jobs;
        self.plans.retain(|id, i| {
            let age = now.duration_since(i.at);
            age < ttl || (quiescing.contains_key(id) && age < ttl + QUIESCE_PLAN_GRACE)
        });
        let live = &self.plans;
        let dropped: Vec<String> = self
            .quiesce_jobs
            .keys()
            .filter(|id| !live.contains_key(*id))
            .cloned()
            .collect();
        for id in dropped {
            // nobody came back for it: the box must not keep refusing runs (and a job still going is cancelled)
            if let Some((_, rec)) = self.quiesce_jobs.remove(&id) {
                crate::quiesce::release(self.agent.as_ref(), &rec);
            }
        }
        if self.plans.len() >= MAX_ISSUED_PLANS {
            return Resp::error(429, "too_many_plans", "too many open plans; apply or wait");
        }
        let plan_id = match random_hex(16) {
            Ok(id) => id,
            Err(m) => return Resp::error(500, "internal", &m),
        };
        let mut body = plan_body(&plan_id, &plan, self.plan_ttl.as_secs());
        if let Some(w) = &store_warning {
            body["secrets_store_warning"] = json!(w);
        }
        let (verb, name, risk) = (
            plan.operation.verb(),
            plan.operation.box_name().to_string(),
            plan.max_risk(),
        );
        let new_store_accepted = request.accept_new_secrets_store
            && matches!(request.operation, Operation::Upgrade { .. });
        self.plans.insert(
            plan_id,
            Issued {
                plan,
                at: now,
                at_ms: unix_ms(),
                new_store_accepted,
            },
        );
        self.log_activity(
            &format!("plan {verb}"),
            &name,
            risk,
            "proposed, nothing changed",
        );
        Resp::json(200, &body)
    }

    fn apply(&mut self, body: &[u8], step_up: roles::StepUp) -> Resp {
        self.apply_from(None, body, step_up)
    }

    /// `apply` for a person's own request (`req`), or for the server's own follow-up (`None`: an orchestration's step). A
    /// fleet-managing dashboard refuses the second kind: only a person's passkey over the plan lets a fleet change through.
    fn apply_from(&mut self, req: Option<&Req>, body: &[u8], step_up: roles::StepUp) -> Resp {
        let request: ApplyRequest = match serde_json::from_slice(body) {
            Ok(r) => r,
            Err(e) => return Resp::error(400, "bad_request", &format!("invalid request: {e}")),
        };
        // Everything that can refuse an apply is checked on the FIRST ask, before the box is touched. Once its runs have been
        // ended for this plan, a later ask is only the page asking how it is going: it is not asked again for the plan's
        // age, the typed name, the passkey or the permission (each was satisfied at the first ask), because a refusal then
        // would leave a box with no runs and a hold on new ones.
        let quiescing = self.quiesce_jobs.contains_key(&request.plan_id);
        let Some(issued) = self.plans.get(&request.plan_id) else {
            if let Some((_, rec)) = self.quiesce_jobs.remove(&request.plan_id) {
                crate::quiesce::release(self.agent.as_ref(), &rec);
            }
            return Resp::error(
                409,
                "unknown_plan",
                "this server did not issue that plan (or it was already used); plan again",
            );
        };
        if !quiescing && issued.at.elapsed() >= self.plan_ttl {
            self.plans.remove(&request.plan_id);
            return Resp::error(409, "stale_plan", "that plan has expired; plan again");
        }
        if let Some(echo) = request.plan.as_ref().filter(|_| !quiescing) {
            if *echo != issued.plan {
                return Resp::error(
                    409,
                    "plan_mismatch",
                    "the plan sent is not the plan that was issued; plan again",
                );
            }
        }
        let plan = issued.plan.clone();
        let new_store_accepted = issued.new_store_accepted;
        if !quiescing
            && plan.max_risk() == Some(Risk::High)
            && request.confirm_name.as_deref() != Some(plan.operation.box_name().as_str())
        {
            return Resp::error(
                400,
                "confirmation_required",
                "this cannot be undone: type the box name to confirm",
            );
        }
        // Behind a sign-in, a change that cannot be undone also needs a passkey shown within the last few minutes.
        // Checked before the plan is used up, so a refused apply can be retried after confirming.
        if !quiescing && plan.max_risk() == Some(Risk::High) {
            if let Some(refusal) =
                roles::step_up_refusal(step_up, "applying a change that cannot be undone")
            {
                return refusal;
            }
        }
        // The permission engine has the last word on a box that is not a throwaway: a rule can forbid a change, and a
        // change to a production box needs an active grant. Checked before the plan is used up.
        if !quiescing && !plan.is_noop() {
            if let Some(refusal) = self.box_permission(&plan) {
                return refusal;
            }
        }
        // One change per box at a time, and a bound on the total; checked before the plan is used up.
        if !plan.is_noop() {
            if let Some(refusal) = self.apply_job_refusal(&plan) {
                return refusal;
            }
        }
        let verb = plan.operation.verb();
        let name = plan.operation.box_name().to_string();
        let risk = plan.max_risk();
        if plan.is_noop() {
            self.plans.remove(&request.plan_id);
            self.log_activity(&format!("apply {verb}"), &name, risk, "nothing to do");
            return Resp::json(
                200,
                &json!({ "plan": plan, "applied": false, "result": Value::Null }),
            );
        }
        // A box's dashboard that manages the fleet: a window for this plan and the owner's passkey over it, checked last,
        // just before the plan is used up (ADR 0040 §2). A later ask while the box is made ready was already let through.
        if !quiescing {
            if let Some(refusal) = self.fleet_gate_refusal(
                req,
                &request.plan_id,
                &plan,
                request.fleet_assertion.as_ref(),
            ) {
                return refusal;
            }
        }
        // A change that stops the machine (a resize, an upgrade) gets the box ready first: runs end cleanly and uncommitted
        // work is snapshotted, bounded in time, on a thread of its own (see `quiesce_jobs`). An upgrade that does not stop
        // the machine asks the box for its plain checkpoint, as before. /work is kept either way.
        let mut quiesced_box: Option<BoxRecord> = None;
        let upgrade_checkpoint = match &plan.operation {
            Operation::Upgrade { name, .. } | Operation::Resize { name, .. } => {
                let is_upgrade = matches!(plan.operation, Operation::Upgrade { .. });
                match self.provider.get(name).ok().flatten() {
                    Some(rec) if crate::quiesce::needed(&plan, &rec) => {
                        let slot = match self.quiesce_jobs.get(&request.plan_id) {
                            Some((slot, _)) => slot.clone(),
                            None => {
                                let slot: QuiesceSlot = Arc::new(Mutex::new(None));
                                self.quiesce_jobs
                                    .insert(request.plan_id.clone(), (slot.clone(), rec.clone()));
                                let (agent, rec2, out) =
                                    (self.agent.clone(), rec.clone(), slot.clone());
                                std::thread::spawn(move || {
                                    let q = crate::quiesce::perform(
                                        agent.as_ref(),
                                        &rec2,
                                        &crate::quiesce::Opts::dashboard(),
                                        &crate::quiesce::RealPace::new(),
                                    );
                                    if let Ok(mut g) = out.lock() {
                                        *g = Some(q);
                                    }
                                });
                                slot
                            }
                        };
                        let done = slot.lock().ok().and_then(|mut g| g.take());
                        let Some(q) = done else {
                            return Resp::json(
                                202,
                                &json!({
                                    "quiescing": true,
                                    "retry_after_s": 2,
                                    "message": "The box is ending its runs and saving its work. Ask again to continue.",
                                }),
                            );
                        };
                        self.quiesce_jobs.remove(&request.plan_id);
                        // an agent that predates this was named in the plan the person confirmed; any other box that was not
                        // ready is not stopped, because there is nobody to ask again in this request
                        if q.reconfirm && !q.older {
                            crate::quiesce::release(self.agent.as_ref(), &rec);
                            self.log_activity(
                                &format!("apply {verb}"),
                                rec.spec.name.as_str(),
                                risk,
                                "not stopped: the box was not ready",
                            );
                            return Resp::error(
                                409,
                                "quiesce_not_ready",
                                &t(
                                    "quiesce.dashboard_not_ready",
                                    &[
                                        ("box", rec.spec.name.as_str()),
                                        ("detail", &q.step.detail.replace('\n', " ")),
                                    ],
                                ),
                            );
                        }
                        quiesced_box = Some(rec);
                        Some(q.step)
                    }
                    Some(rec) if is_upgrade => Some(crate::run::upgrade::no_save_needed(&rec)),
                    _ => None,
                }
            }
            _ => None,
        };
        // A plan is used once, whatever happens next (it is kept only while the box is being made ready, above, so that the
        // page can ask again).
        self.plans.remove(&request.plan_id);
        // A change to the provider can take minutes (an instance boot): it runs as a job, and this answers `202` at once.
        // The box was made ready above (a change that stops it); the job carries what that said and releases the box if the
        // change fails.
        if let Some(started) =
            self.start_apply_job(&plan, new_store_accepted, upgrade_checkpoint, quiesced_box)
        {
            return started;
        }
        // A restic action is quick (the box's agent does the work) and finishes on this request.
        let applied = self
            .apply_restic(&plan)
            .unwrap_or_else(|| self.provider.apply(&plan));
        match self.finish_apply(&plan, applied, None, None, new_store_accepted, false) {
            Ok(body) => Resp::json(200, &body),
            Err(r) => r,
        }
    }

    /// Ask the permission engine about a box change. `Some` is a refusal to send back; the decision (and a use of a
    /// grant) is in the audit chain either way. With no task store there is no configuration, and nothing is refused.
    fn box_permission(&mut self, plan: &Plan) -> Option<Resp> {
        use ozbox_core::permissions::{self, Action, ActorKind, Ctx, Effect, Environment};
        let store = self.runs.store.clone()?;
        let name = plan.operation.box_name().to_string();
        let production = BoxName::new(&name)
            .ok()
            .and_then(|n| self.provider.get(&n).ok().flatten())
            .is_some_and(|r| {
                let l = &r.spec.labels;
                l.get("env").is_some_and(|v| v == "production")
                    || l.get("production").is_some_and(|v| v == "true")
            });
        let action = match &plan.operation {
            Operation::Create { .. } | Operation::Clone { .. } => Action::BoxCreate,
            Operation::Destroy { .. }
            | Operation::DeleteSnapshot { .. }
            | Operation::DeleteOldWork { .. }
            | Operation::ResticForget { .. } => Action::BoxDestroy,
            _ => Action::BoxChange,
        };
        // the person asking now, the same word in the decision, the chain and a grant's use: a member neither uses nor
        // uses up the owner's grant, and a deny scoped to them matches
        let who = self.current_actor.chain();
        let ctx = Ctx {
            person: who.clone(),
            actor: ActorKind::Person,
            box_name: Some(name.clone()),
            env: if production {
                Environment::Production
            } else {
                Environment::Sandbox
            },
            ..Ctx::default()
        };
        let now = unix_ms();
        let book = store.load().ok()?;
        let d = permissions::decide(&book.perms, &ctx, action, now);
        let ev = permissions::audit_event(&d, &ctx, action, &who, now);
        self.chain_event(&who, &ev.action, Some(&name), &ev.detail);
        if let Some(g) = d.grant.as_deref().filter(|_| d.effect != Effect::Deny) {
            // a person at the dashboard confirming a plan is the yes for an `ask`, so a grant that let it through is used
            let g = g.to_string();
            let _ = store.update(|b| {
                b.perms.use_grant(&g);
                b.record(now, &who, "grant.used", None, &g);
            });
        }
        (d.effect == Effect::Deny).then(|| {
            self.log_activity(
                &format!("apply {}", plan.operation.verb()),
                &name,
                plan.max_risk(),
                "refused by permissions",
            );
            Resp::error(403, "permission_denied", d.reason.sentence())
        })
    }

    /// The SSH routes for a box, as text only: nothing is written to the person's SSH config here. A GET never writes
    /// anything either; the dedicated key is made only by a POST (`make_key`), which a person asks for by name.
    fn ssh(&self, name: &str, make_key: bool) -> Resp {
        let rec = match self.record(name) {
            Ok(r) => r,
            Err(r) => return r,
        };
        let mut inputs = self.route_inputs.clone();
        inputs.domain = self.domain.clone();
        let n = rec.spec.name.as_str();
        // The routes assume the dedicated key exists. A POST creates it if absent; an existing key is never replaced.
        if let (true, Some(dir)) = (make_key, &self.ssh_dir) {
            if sshconfig::ensure_key(self.runner.as_ref(), dir).is_err() {
                return Resp::error(
                    500,
                    "ssh_key_unavailable",
                    "the dedicated SSH key could not be created; run `ozbox connect <box> --ssh --write` once",
                );
            }
        }
        let routes: Vec<Value> = sshconfig::routes(&rec, &inputs)
            .iter()
            .map(|r| {
                json!({
                    "id": r.id(),
                    "label": r.label(),
                    "requirements": r.requirements(),
                    "host": sshconfig::host_alias(n),
                    "config": sshconfig::block(n, r),
                    "command": format!("ssh {}", sshconfig::host_alias(n)),
                })
            })
            .collect();
        let Some(first) = routes.first().cloned() else {
            return Resp::error(
                409,
                "no_route",
                "no SSH route is known for this box: an AWS box needs its instance id and a region, other boxes need a configured domain and tunnel",
            );
        };
        Resp::json(
            200,
            &json!({
                "host": first["host"],
                "config": first["config"],
                "command": first["command"],
                "routes": routes,
                // `None` when this server has no key folder to look in
                "key_exists": self.ssh_dir.as_ref().map(|d| {
                    d.join(sshconfig::KEY_NAME).exists()
                        && d.join(format!("{}.pub", sshconfig::KEY_NAME)).exists()
                }),
            }),
        )
    }

    fn running_box(&self, name: &str) -> Result<BoxRecord, Resp> {
        let rec = self.record(name)?;
        if rec.state != BoxState::Running {
            return Err(Resp::error(
                409,
                "box_not_running",
                &format!(
                    "box {} is {}, so its agent cannot be asked",
                    rec.spec.name, rec.state
                ),
            ));
        }
        Ok(rec)
    }

    fn agent_error(e: &AgentError) -> Resp {
        match e {
            AgentError::Unreachable(why) => Resp::error(502, "agent_unreachable", why),
            AgentError::Unsupported(why) => Resp::error(501, "agent_unreachable", why),
        }
    }

    fn data_source(&self) -> &'static str {
        if self.simulated_metrics {
            "simulated"
        } else {
            "live"
        }
    }

    fn usage(&self, query: &str) -> Resp {
        let params = parse_query(query);
        let Some(range) =
            usage::Range::parse(params.get("range").map(String::as_str).unwrap_or("1m"))
        else {
            return Resp::error(400, "bad_request", "range must be 5s, 1m or 1h");
        };
        let recs = match self.boxes_for_loop() {
            Ok(r) => r,
            Err(r) => return r,
        };
        let now = unix_ms();
        let running: Vec<BoxRecord> = recs
            .iter()
            .filter(|r| r.state == BoxState::Running)
            .cloned()
            .collect();
        // Boxes are asked at the same time, and a slow one never holds the others or the loop for long: it shows its last
        // answer marked with when it is from, or is named as not reached. Never left out.
        let results = self.read_histories(&running, range, now);
        let mut boxes = Vec::new();
        let mut runs = Vec::new();
        let mut unreachable = Vec::new();
        let mut no_samples = Vec::new();
        let mut stale = Vec::new();
        let mut sources: Vec<crate::pricing::PriceSource> = Vec::new();
        for (rec, res) in running.iter().zip(results) {
            let samples = match res {
                HistRead::Fresh(s) => s,
                HistRead::Stale { samples, at_ms } => {
                    stale.push(json!({ "name": rec.spec.name, "as_of_ms": at_ms }));
                    samples
                }
                HistRead::Unread(e) => {
                    unreachable.push(unreachable_json(rec, e));
                    continue;
                }
            };
            // an answer with nothing in it is not "idle" and not "unreachable": the box answered and has no history yet
            if samples.is_empty() {
                no_samples.push(json!({ "name": rec.spec.name }));
                continue;
            }
            runs.extend(usage::by_run(rec.spec.name.as_str(), &samples));
            let c = crate::pricing::box_cost(rec, &self.settings, self.prices.book.as_ref());
            // The figure is in dollars from one source per box. A disk is added only when the price list is in dollars too,
            // never two currencies in one sum. On a box there is no fleet to price.
            let disk_ok = self
                .prices
                .book
                .as_ref()
                .is_none_or(|b| b.currency == "USD");
            let rate = c
                .machine_hourly
                .filter(|_| c.currency.as_deref() == Some("USD") && !self.on_a_box)
                .map(|m| {
                    let d = if disk_ok {
                        c.disk_hourly.unwrap_or(0.0)
                    } else {
                        0.0
                    };
                    if let Some(src) = c.machine_source {
                        sources.push(src);
                    }
                    (m + d) * crate::pricing::HOURS_PER_MONTH
                });
            boxes.push(usage::box_usage(rec, &samples, rate));
        }
        let cost_source = if sources.is_empty() {
            Value::Null
        } else if sources.iter().all(|s| *s == sources[0]) {
            json!(sources[0])
        } else {
            json!("mixed")
        };
        // the figure leaves out any running box that gave nothing to price
        let cost_partial = !unreachable.is_empty() || !no_samples.is_empty();
        let cpu_means: Vec<f64> = boxes.iter().filter_map(|b| b.cpu.map(|s| s.mean)).collect();
        let mem_means: Vec<f64> = boxes
            .iter()
            .filter_map(|b| b.mem_pct.map(|s| s.mean))
            .collect();
        let avg = |v: &[f64]| (!v.is_empty()).then(|| v.iter().sum::<f64>() / v.len() as f64);
        let costs: Option<Vec<f64>> = boxes.iter().map(|b| b.cost_month_est_usd).collect();
        let by_label = usage::group_by_label(&boxes, "project");
        Resp::json(
            200,
            &json!({
                "source": self.data_source(),
                "range": range.label(),
                "step_ms": range.step_ms(),
                "to_ms": metrics_sim::bucket(now, range.step_ms()),
                "boxes": boxes,
                "unreachable": unreachable,
                "no_samples": no_samples,
                "stale": stale,
                "by_label": { "key": "project", "groups": by_label },
                "by_run": runs,
                "fleet": {
                    "cpu_mean": avg(&cpu_means),
                    "mem_mean": avg(&mem_means),
                    "cost_month_est_usd": costs.filter(|c| !c.is_empty()).map(|c| c.iter().sum::<f64>()),
                    "cost_source": cost_source,
                    "cost_partial": cost_partial,
                },
            }),
        )
    }

    /// The weekly "downsize or pause?" suggestions. Never applied here: each carries the operation that applying it
    /// would plan, and the dashboard sends it through the normal plan, confirm, apply flow.
    fn suggestions(&self) -> Resp {
        let recs = match self.boxes_for_loop() {
            Ok(r) => r,
            Err(r) => return r,
        };
        let now = unix_ms();
        let running: Vec<BoxRecord> = recs
            .into_iter()
            .filter(|r| r.state == BoxState::Running)
            .collect();
        let results = self.read_histories(&running, usage::Range::Hour1, now);
        let mut items: Vec<Value> = Vec::new();
        let mut unreachable = Vec::new();
        let mut no_samples = Vec::new();
        for (rec, res) in running.iter().zip(results) {
            let samples = match res {
                HistRead::Fresh(s) | HistRead::Stale { samples: s, .. } => s,
                // a box that could not be read is named, so "nothing to suggest" never hides it
                HistRead::Unread(e) => {
                    unreachable.push(unreachable_json(rec, e));
                    continue;
                }
            };
            if samples.is_empty() {
                no_samples.push(json!({ "name": rec.spec.name }));
                continue;
            }
            let Some(s) = usage::suggest(rec.spec.name.as_str(), rec.spec.size, &samples, |z| {
                self.settings.price(z)
            }) else {
                continue;
            };
            let name = rec.spec.name.as_str();
            let operation = match &s.advice {
                usage::Advice::Downsize { to } => {
                    json!({ "op": "resize", "name": name, "size": to, "work_disk_gb": Value::Null })
                }
                usage::Advice::AutoPause { .. } => json!({ "op": "pause", "name": name }),
            };
            items.push(json!({ "suggestion": s, "operation": operation }));
        }
        Resp::json(
            200,
            &json!({
                "source": self.data_source(),
                "window_days": 7,
                "items": items,
                "unreachable": unreachable,
                "no_samples": no_samples,
            }),
        )
    }

    fn get_settings(&self) -> Resp {
        Resp::json(
            200,
            &json!({ "settings": self.settings, "persisted": self.settings_path.is_some() }),
        )
    }

    fn put_settings(&mut self, req: &Req) -> Resp {
        let body = req.body.as_slice();
        let new: Settings = match serde_json::from_slice(body) {
            Ok(s) => s,
            Err(e) => return Resp::error(400, "bad_request", &format!("invalid settings: {e}")),
        };
        if let Err(e) = new.validate() {
            return Resp::error(400, "invalid_settings", &e.to_string());
        }
        // A webhook needs its address and secret, so it is added through its own call, never through settings.
        if new
            .apps
            .webhooks
            .iter()
            .any(|w| !self.settings.apps.webhooks.iter().any(|o| o.id == w.id))
        {
            return Resp::error(
                400,
                "invalid_settings",
                "add a webhook with its own form: it needs an address and a signing secret",
            );
        }
        // raising or removing a model provider's monthly cap is a loosening, like the fleet and per-person limits
        if self.settings.model_caps_loosen(&new) {
            let state = self.step_up_state(req);
            if state != roles::StepUp::Fresh {
                let who = self.who(req);
                return self.step_up_denied(&who, state, "raising a model spend limit");
            }
        }
        if let Some(p) = &self.settings_path {
            if let Err(e) = new.save_to(p) {
                return Resp::error(500, "cannot_save", &e.to_string());
            }
        }
        let old = std::mem::replace(&mut self.settings, new);
        self.forget_removed(&old);
        self.log_activity("update settings", "-", None, "saved");
        Resp::json(
            200,
            &json!({ "settings": self.settings, "persisted": self.settings_path.is_some() }),
        )
    }

    fn get_plan(&self, id: &str) -> Resp {
        match self.plans.get(id) {
            Some(i) if i.at.elapsed() < self.plan_ttl => Resp::json(
                200,
                &plan_body(id, &i.plan, (self.plan_ttl - i.at.elapsed()).as_secs()),
            ),
            _ => Resp::error(
                409,
                "unknown_plan",
                "that plan is not open (unknown, used or expired)",
            ),
        }
    }

    /// Plans that were proposed and are still waiting for someone to apply them.
    fn approvals(&self) -> Resp {
        let mut items: Vec<Value> = self
            .plans
            .iter()
            .filter(|(_, i)| i.at.elapsed() < self.plan_ttl && !i.plan.is_noop())
            .map(|(id, i)| {
                json!({
                    "plan_id": id,
                    "box_name": i.plan.operation.box_name(),
                    "verb": i.plan.operation.verb(),
                    "max_risk": i.plan.max_risk(),
                    "needs_passkey": i.plan.max_risk() == Some(Risk::High),
                    "changes": i.plan.changes.len(),
                    "proposed_ms": i.at_ms,
                    "expires_in_s": (self.plan_ttl - i.at.elapsed()).as_secs(),
                })
            })
            .collect();
        items.sort_by_key(|v| v["proposed_ms"].as_u64().unwrap_or(0));
        // Plans live only in this server's memory and lapse after `ttl_s`; a restart forgets them, so the page says so.
        Resp::json(
            200,
            &json!({ "source": "server", "persisted": false, "ttl_s": self.plan_ttl.as_secs(), "items": items }),
        )
    }

    fn runs(&self) -> Resp {
        if !self.simulated_metrics {
            return Resp::error(501, "metrics_unavailable", "runs need the box agent");
        }
        let recs = match self.boxes_for_loop() {
            Ok(r) => r,
            Err(r) => return r,
        };
        let now = metrics_sim::bucket(unix_ms(), 5_000);
        let runs: Vec<Value> = recs
            .iter()
            .filter(|r| r.state == BoxState::Running)
            .flat_map(|r| metrics_sim::runs(r, now))
            .collect();
        Resp::json(200, &json!({ "source": "simulated", "runs": runs }))
    }

    fn run_logs(&self, id: &str) -> Resp {
        if !self.simulated_metrics {
            return Resp::error(501, "metrics_unavailable", "logs need the box agent");
        }
        match metrics_sim::run_logs(id) {
            Some(lines) => Resp::json(
                200,
                &json!({ "source": "simulated", "id": id, "lines": lines }),
            ),
            None => Resp::error(404, "not_found", "no such run"),
        }
    }
}

/// Samples for one box across a window, oldest first.
fn history(
    agent: &dyn BoxAgent,
    rec: &BoxRecord,
    range: usage::Range,
    now: u64,
) -> Result<Vec<MetricsSample>, AgentError> {
    let step = range.step_ms();
    let end = metrics_sim::bucket(now, step);
    agent.metrics_series(rec, end.saturating_sub(range.window_ms()), end, step)
}

/// How long a usage or suggestions read waits for the boxes. A box that has not answered by then is reported as
/// not reached; the others are shown.
const READ_BUDGET: Duration = Duration::from_secs(3);
/// How long a read waits for a box it already has an answer for, before showing that answer (marked with when it is from)
/// and letting the read finish in the background.
const READ_GRACE: Duration = Duration::from_millis(300);

/// One box's usage read for one range.
struct ReadSlot {
    /// The machine the answer is about: a box that was replaced starts over.
    instance: Option<String>,
    running: bool,
    /// The last good answer and when it was read.
    last: Option<(u64, Vec<MetricsSample>)>,
}

/// What a read of one box came to.
enum HistRead {
    Fresh(Vec<MetricsSample>),
    /// Not read in time: the last answer, from `at_ms`, while the read goes on in the background.
    Stale {
        samples: Vec<MetricsSample>,
        at_ms: u64,
    },
    Unread(AgentError),
}

/// Ends a read: whatever happens to it (even a panic), the box can be read again.
struct ReadDone(Arc<Mutex<ReadSlot>>);

impl Drop for ReadDone {
    fn drop(&mut self) {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).running = false;
    }
}

/// One box's samples, read on its own thread.
type HistoryRead = Box<dyn FnOnce() -> Result<Vec<MetricsSample>, AgentError> + Send>;

/// Why a read of one box did not come back.
enum ReadMiss {
    TimedOut(Duration),
    Failed,
}

/// Run each read on its own thread and wait for all of them, but no longer than `budget` in total. A read that is
/// still running when the budget ends keeps going on its own and its answer is dropped. The results are in the order of
/// `reads`. A read that panicked is `Failed`, whatever else timed out.
fn read_within<T: Send + 'static>(
    reads: Vec<Box<dyn FnOnce() -> T + Send>>,
    budget: Duration,
) -> Vec<Result<T, ReadMiss>> {
    let n = reads.len();
    let (tx, rx) = std::sync::mpsc::channel::<(usize, Option<T>)>();
    for (i, read) in reads.into_iter().enumerate() {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(read)).ok();
            let _ = tx.send((i, out));
        });
    }
    drop(tx);
    let deadline = Instant::now() + budget;
    let mut got: Vec<Option<Result<T, ReadMiss>>> = (0..n).map(|_| None).collect();
    let mut open = n;
    while open > 0 {
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok((i, v)) => {
                got[i] = Some(v.ok_or(ReadMiss::Failed));
                open -= 1;
            }
            Err(_) => break,
        }
    }
    got.into_iter()
        .map(|g| g.unwrap_or(Err(ReadMiss::TimedOut(budget))))
        .collect()
}

fn unreachable_json(rec: &BoxRecord, e: AgentError) -> Value {
    let (AgentError::Unreachable(why) | AgentError::Unsupported(why)) = e;
    json!({ "name": rec.spec.name, "reason": why })
}

impl App {
    /// One box's samples across a range for every box in `recs`, asked at the same time.
    ///
    /// A box is read by one request at a time: while its read is still running, another does not start a second one (a
    /// slow box would otherwise pile up forwards and processes under a page that polls). A box that has not answered
    /// shows its last good answer, marked with when it is from, or says it is still being read. The server loop is held
    /// for `read_budget` at most, and for `read_grace` when every box has an earlier answer to show.
    fn read_histories(&self, recs: &[BoxRecord], range: usage::Range, now: u64) -> Vec<HistRead> {
        let mut slots: Vec<Arc<Mutex<ReadSlot>>> = Vec::new();
        let mut started: Vec<bool> = Vec::new();
        let mut reads: Vec<HistoryRead> = Vec::new();
        {
            let mut map = self.reads.lock().unwrap_or_else(|e| e.into_inner());
            let live: Vec<String> = recs.iter().map(|r| r.spec.name.to_string()).collect();
            map.retain(|k, _| live.iter().any(|n| k.starts_with(&format!("{n}|"))));
            for rec in recs {
                let key = format!("{}|{}", rec.spec.name.as_str(), range.label());
                let slot = Arc::clone(map.entry(key).or_insert_with(|| {
                    Arc::new(Mutex::new(ReadSlot {
                        instance: rec.provider_id.clone(),
                        running: false,
                        last: None,
                    }))
                }));
                let go = {
                    let mut s = slot.lock().unwrap_or_else(|e| e.into_inner());
                    if s.instance != rec.provider_id {
                        s.instance = rec.provider_id.clone();
                        s.last = None;
                    }
                    let go = !s.running;
                    s.running = true;
                    go
                };
                started.push(go);
                if go {
                    let agent = Arc::clone(&self.agent);
                    let rec = rec.clone();
                    let mine = Arc::clone(&slot);
                    reads.push(Box::new(move || {
                        let _done = ReadDone(Arc::clone(&mine));
                        let out = history(agent.as_ref(), &rec, range, now);
                        if let Ok(samples) = &out {
                            mine.lock().unwrap_or_else(|e| e.into_inner()).last =
                                Some((unix_ms(), samples.clone()));
                        }
                        out
                    }));
                }
                slots.push(slot);
            }
        }
        let all_cached = slots
            .iter()
            .zip(&started)
            .all(|(s, go)| !go || s.lock().unwrap_or_else(|e| e.into_inner()).last.is_some());
        let wait = if all_cached {
            self.read_grace
        } else {
            self.read_budget
        };
        let mut fresh = read_within(reads, wait).into_iter();
        slots
            .iter()
            .zip(started)
            .map(|(slot, go)| {
                let last = || slot.lock().unwrap_or_else(|e| e.into_inner()).last.clone();
                let stale_or = |why: AgentError| match last() {
                    Some((at_ms, samples)) => HistRead::Stale { samples, at_ms },
                    None => HistRead::Unread(why),
                };
                if !go {
                    return stale_or(AgentError::Unreachable(
                        "still being read: the last read of this box has not finished".to_string(),
                    ));
                }
                match fresh.next() {
                    Some(Ok(Ok(samples))) => HistRead::Fresh(samples),
                    Some(Ok(Err(e))) => HistRead::Unread(e),
                    Some(Err(ReadMiss::TimedOut(b))) => stale_or(AgentError::Unreachable(format!(
                        "did not answer within {} seconds (still being read)",
                        b.as_secs().max(1)
                    ))),
                    Some(Err(ReadMiss::Failed)) | None => {
                        HistRead::Unread(AgentError::Unreachable("the read failed".to_string()))
                    }
                }
            })
            .collect()
    }
}

fn plan_body(plan_id: &str, plan: &Plan, expires_in_s: u64) -> Value {
    json!({
        "plan_id": plan_id,
        "plan": plan,
        "box_name": plan.operation.box_name(),
        "max_risk": plan.max_risk(),
        "noop": plan.is_noop(),
        "requires_confirm_name": plan.max_risk() == Some(Risk::High),
        // A change that cannot be undone needs the typed box name. Behind a sign-in (a shared machine) it also needs a
        // passkey shown within the step-up window; the dashboard asks for it when `apply` says `step_up_required`.
        "needs_passkey": plan.max_risk() == Some(Risk::High),
        "expires_in_s": expires_in_s,
    })
}

fn host_literal(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{v6}]"),
    }
}

fn mime(path: &str) -> &'static str {
    match path.rsplit('.').next().unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json",
        "webmanifest" => "application/manifest+json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

fn serve_static(path: &str) -> Resp {
    if embedded::EMBEDDED.is_empty() {
        return Resp {
            status: 200,
            content_type: "text/html; charset=utf-8",
            body: NOT_BUILT_PAGE.as_bytes().to_vec(),
            no_store: true,
            stream: false,
        };
    }
    let wanted = if path == "/" { "/index.html" } else { path };
    let found = embedded::EMBEDDED.iter().find(|(p, _)| *p == wanted);
    let (served, bytes) = match found {
        Some((p, b)) => (*p, *b),
        // A route of the single-page app (no file extension): hand it the entry page.
        None if !wanted.rsplit('/').next().unwrap_or("").contains('.') => {
            match embedded::EMBEDDED.iter().find(|(p, _)| *p == "/index.html") {
                Some((p, b)) => (*p, *b),
                None => return Resp::error(404, "not_found", "not found"),
            }
        }
        None => return Resp::error(404, "not_found", "not found"),
    };
    Resp {
        status: 200,
        content_type: mime(served),
        body: bytes.to_vec(),
        no_store: served == "/index.html" || served == "/sw.js",
        stream: false,
    }
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                let hex = std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(v) => {
                        out.push(v);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub(crate) fn parse_query(q: &str) -> HashMap<String, String> {
    q.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (percent_decode(k), percent_decode(v)),
            None => (percent_decode(p), String::new()),
        })
        .collect()
}

/// `YYYY-MM-DDTHH:MM:SS[.fff](Z|+HH:MM|-HH:MM)` to Unix milliseconds.
pub fn parse_rfc3339_ms(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    let num = |from: usize, len: usize| -> Option<i64> {
        let part = s.get(from..from + len)?;
        if part.bytes().all(|c| c.is_ascii_digit()) {
            part.parse().ok()
        } else {
            None
        }
    };
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || !(b[10] == b'T' || b[10] == b't') {
        return None;
    }
    if b[13] != b':' || b[16] != b':' {
        return None;
    }
    let (y, mo, d) = (num(0, 4)?, num(5, 2)?, num(8, 2)?);
    let (h, mi, sec) = (num(11, 2)?, num(14, 2)?, num(17, 2)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    let mut i = 19;
    let mut millis = 0i64;
    if b.get(i) == Some(&b'.') {
        let start = i + 1;
        let mut end = start;
        while end < b.len() && b[end].is_ascii_digit() {
            end += 1;
        }
        if end == start {
            return None;
        }
        let digits = &s[start..end];
        let first3: String = digits.chars().chain("000".chars()).take(3).collect();
        millis = first3.parse().ok()?;
        i = end;
    }
    let offset_s = match b.get(i)? {
        b'Z' | b'z' if i + 1 == b.len() => 0,
        sign @ (b'+' | b'-') if i + 6 == b.len() && b[i + 3] == b':' => {
            let (oh, om) = (num(i + 1, 2)?, num(i + 4, 2)?);
            let v = oh * 3600 + om * 60;
            if *sign == b'+' {
                v
            } else {
                -v
            }
        }
        _ => return None,
    };
    // Howard Hinnant's days-from-civil.
    let y = if mo <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86_400 + h * 3600 + mi * 60 + sec - offset_s;
    u64::try_from(secs * 1000 + millis).ok()
}

/// Bind, print the URL and serve until the process is stopped.
/// What `ozbox serve` is started with besides the provider.
pub struct Setup {
    pub domain: Option<String>,
    pub settings: Settings,
    pub settings_path: Option<std::path::PathBuf>,
    pub route_inputs: RouteInputs,
    /// Where first-run setup keeps its files, and how to rebuild the provider after it changes the configuration.
    pub init_paths: Option<crate::init::InitPaths>,
    pub rebuild: Option<setup::Rebuild>,
    /// Sign-in for a dashboard on a shared machine (`--public-behind-tunnel`, `--public-url`).
    pub public: Option<PublicSetup>,
    /// A tunnel to start and keep up while serving (`--tunnel`).
    pub tunnel: Option<crate::tunnel_cli::TunnelStart>,
    /// The loopback port that serves the IDE and desktop on the person's own addresses (sign-in mode only).
    pub code_port: u16,
}

/// What the shared-machine mode needs: the allow-list and public address, and where its state is kept.
pub struct PublicSetup {
    pub config: auth::config::AuthConfig,
    pub state_path: Option<std::path::PathBuf>,
}

/// The operating system's keychain, unless `OZBOX_SECRET_STORE=memory` asks for a store that forgets everything when
/// the server stops (for tests and demos on a machine with no keychain).
pub(crate) fn secret_store() -> Arc<dyn SecretStore> {
    crate::secrets_file::select()
}

/// The box agent the command line uses: the demo answers for the fake provider, SSH forwarding otherwise.
pub(crate) fn agent_for(simulated: bool, inputs: RouteInputs) -> Box<dyn BoxAgent> {
    if simulated {
        Box::new(agent::SimulatedAgent::default())
    } else {
        real_agent(inputs)
    }
}

/// The agent for a provider by id: a dashboard on a box reaches its own daemon directly.
pub(crate) fn agent_for_provider(
    provider_id: &str,
    simulated: bool,
    inputs: RouteInputs,
) -> Box<dyn BoxAgent> {
    #[cfg(unix)]
    if provider_id == crate::this_box::PROVIDER_ID {
        return match transport::SshAgent::local(Arc::new(transport::SystemSpawn), inputs) {
            Ok(a) => Box::new(a),
            Err(_) => Box::new(agent::NoTransport),
        };
    }
    #[cfg(not(unix))]
    let _ = provider_id;
    agent_for(simulated, inputs)
}

/// A transport for the box agents of a real provider: SSH forwarding on Unix, nothing elsewhere.
fn real_agent(inputs: RouteInputs) -> Box<dyn BoxAgent> {
    #[cfg(unix)]
    {
        match transport::SshAgent::new(Arc::new(transport::SystemSpawn), inputs) {
            Ok(a) => Box::new(a),
            Err(_) => Box::new(agent::NoTransport),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = inputs;
        Box::new(agent::NoTransport)
    }
}

pub fn serve(
    provider: Box<dyn Provider>,
    simulated_metrics: bool,
    setup: Setup,
    bind: &str,
    port: u16,
) -> Result<(), String> {
    // First thing, before anything is started: a signal that arrives while the tunnel is coming up must still take it
    // down again, not end the process with the tunnel left behind.
    let stop = shutdown_flag();
    let ip = parse_bind(bind)?;
    let server = tiny_http::Server::http(SocketAddr::new(ip, port))
        .map_err(|e| format!("cannot listen on {}:{port}: {e}", host_literal(ip)))?;
    let addr = server
        .server_addr()
        .to_ip()
        .ok_or_else(|| "the server did not bind a TCP address".to_string())?;
    // Belt and braces: whatever the OS says it bound must still be loopback.
    if !addr.ip().is_loopback() {
        return Err("refusing to serve on a non-loopback address".into());
    }
    let token = random_hex(32)?;
    let provider_id = provider.id().to_string();
    let public = setup.public;
    let secrets = secret_store();
    // Internal tokens (sessions, setup codes, tickets) are keyed with a key held in this store, not plainly hashed.
    crate::tokenmac::install(secrets.clone());
    let beside = |name: &str| setup.settings_path.as_ref().map(|p| p.with_file_name(name));
    let (prices_path, state_path) = (beside("prices.json"), beside("state.json"));
    let bill_path = beside("bill.json");
    let sched_tasks_path = beside("tasks.json");
    let tasks_path = beside("tasks.json");
    let mut inputs = setup.route_inputs.clone();
    inputs.domain = setup.domain.clone().filter(|d| !d.is_empty());
    let mut app = App::new(provider, simulated_metrics, addr, token.clone())
        .with_background_worker()
        .with_domain(setup.domain)
        .with_settings(setup.settings, setup.settings_path)
        .with_route_inputs(setup.route_inputs)
        .with_ssh_dir(
            std::env::var_os("OZBOX_SSH_DIR")
                .map(std::path::PathBuf::from)
                .or_else(|| dirs::home_dir().map(|h| h.join(".ssh"))),
        )
        .with_secrets(Arc::clone(&secrets))
        .with_code_settings(crate::code::settings_path())
        .with_files(prices_path, state_path)
        .with_bill_file(bill_path)
        .with_setup(setup.init_paths, setup.rebuild)
        .with_tools_cfg(
            crate::profiles::Store::default_dir(),
            crate::config::Config::path().map(|p| p.with_file_name("pending-tools.json")),
        )
        .with_task_store(tasks_path);
    // Scheduled and triggered runs start only through the run system (`ozbox_core::run`, the same task store `ozbox run`
    // and the task board use); with no store there is no run system and a firing says so.
    if let Some(p) = sched_tasks_path {
        app = app.with_run_system(Arc::new(crate::sched::core_runs::CoreRuns {
            store: ozbox_core::run::TaskStore::new(p),
        }));
    }
    if !simulated_metrics {
        app = app.with_agent(agent_for_provider(&provider_id, false, inputs));
    }
    app.use_demo_telegram(demo_telegram::enabled(
        simulated_metrics,
        std::env::var("OZBOX_DEMO_TELEGRAM").ok().as_deref(),
    ));
    let mut access = access::AccessCtx {
        tunnel_path: crate::tunnel_cli::tunnel_path(),
        ..Default::default()
    };
    if let Some(p) = &public {
        access.strong_methods = p.config.strong_methods();
        access.public_url = Some(p.config.rp.origin.clone());
    }
    {
        // How a tunnel is made from the saved settings: at start-up below, and when the dashboard starts one.
        let (port, secrets, state) = (
            addr.port(),
            Arc::clone(&secrets),
            crate::tunnel_cli::state_path(),
        );
        access.factory = Some(Box::new(move |file: &crate::tunnel::TunnelFile| {
            let env = crate::tunnel::Env {
                port,
                spawner: Arc::new(crate::tunnel::SystemSpawner),
                runner: Arc::new(SystemRunner),
                secrets: Arc::clone(&secrets),
            };
            let built = crate::tunnel::build(file, &env)?;
            Ok(crate::tunnel::runner::Runner::new(
                built,
                &file.public_url,
                Arc::new(UreqClient),
                state.clone(),
                port,
                unix_ms(),
            ))
        }));
    }
    if let Some(ts) = setup.tunnel {
        let env = crate::tunnel::Env {
            port: addr.port(),
            spawner: Arc::new(crate::tunnel::SystemSpawner),
            runner: Arc::new(SystemRunner),
            secrets: Arc::clone(&secrets),
        };
        let built =
            crate::tunnel::build(&ts.file, &env).map_err(|key| crate::messages::t(key, &[]))?;
        let mut r = crate::tunnel::runner::Runner::new(
            built,
            &ts.file.public_url,
            Arc::new(UreqClient),
            ts.state_path,
            addr.port(),
            unix_ms(),
        );
        r.start(unix_ms());
        access.runner = Some(r);
    }
    app = app.with_access(access);
    let mut setup_code = None;
    let mut handed_over = false;
    let mut public_origin = None;
    let mut code_port_used: Option<u16> = None;
    if let Some(p) = public {
        public_origin = Some(p.config.rp.origin.clone());
        let a = Arc::new(
            auth::Auth::try_new(
                p.config,
                p.state_path,
                secrets,
                Arc::new(UreqClient),
                Box::new(unix_ms),
            )
            .map_err(|e| e.to_string())?,
        );
        setup_code = a.issue_setup_code();
        // On a box the code goes to the secrets service, which gives it to the owner's computer through the ingress route
        // (`ozbox secrets ingress setup-code`); it is never printed where the box user reads logs.
        if let Some(code) = &setup_code {
            if crate::secrets_ingress::hand_over_setup_code(code, unix_ms()) {
                handed_over = true;
            }
        }
        app = app.with_auth(a);
        if let Some(port) = app.start_code_proxy(setup.code_port)? {
            code_port_used = Some(port);
        }
    }
    {
        use std::io::Write;
        // A closed stdout (`ozbox serve | head -1`) must not kill the server, so no `println!`.
        let mut out = std::io::stdout();
        match &public_origin {
            // Sign-in mode: no access token exists; the address is the public one the tunnel serves.
            Some(origin) => {
                let _ = writeln!(out, "Oz Box dashboard: {origin} (sign-in required)");
                if let Some(code) = &setup_code {
                    if handed_over {
                        let _ = writeln!(
                            out,
                            "A first-time setup code was made. Read it on your own computer: ozbox secrets ingress setup-code --box <box>"
                        );
                    } else {
                        let _ = writeln!(
                            out,
                            "First-time setup code (single use, 30 minutes): {code}"
                        );
                    }
                }
            }
            None => {
                let _ = writeln!(
                    out,
                    "Oz Box dashboard: http://{}:{}/#token={token}",
                    host_literal(addr.ip()),
                    addr.port()
                );
            }
        }
        if let Some(p) = code_port_used {
            let _ = writeln!(
                out,
                "IDE and desktop addresses are served on 127.0.0.1:{p} (point your tunnel's extra host names there)."
            );
        }
        let _ = writeln!(out, "Listening on loopback only. Press Ctrl+C to stop.");
    }
    flush_stdout();

    run_loop(
        &server,
        &mut app,
        &stop,
        lane::POOL_WORKERS,
        lane::POOL_QUEUE,
    );
    app.sched_shutdown();
    app.tunnel_shutdown(unix_ms());
    Ok(())
}

/// Serve until `stop` turns true or the listener fails. The loop owns `app` and answers everything that checks who is
/// asking or changes something; a read that waits on the cloud or on a box goes to the pool (see `lane`), so it never holds
/// the next request.
fn run_loop(
    server: &tiny_http::Server,
    app: &mut App,
    stop: &AtomicBool,
    workers: usize,
    queue: usize,
) {
    let pool = lane::Pool::new(workers, queue);
    loop {
        // Ctrl+C or a service manager's stop: leave the loop, so the tunnel is taken down by the caller.
        if stop.load(Ordering::SeqCst) {
            use std::io::Write;
            let _ = writeln!(
                std::io::stdout(),
                "{}",
                crate::messages::t("serve.stopping", &[])
            );
            break;
        }
        // Wake about once a second even when nobody asks for anything: alerts, price refreshes, the Telegram bot and
        // idle connections to boxes are all served from here.
        let received = match server.recv_timeout(Duration::from_secs(1)) {
            Ok(r) => r,
            Err(_) => break,
        };
        app.tick(unix_ms());
        app.backups_tick(unix_ms());
        app.sched_tick(unix_ms());
        app.tunnel_tick(unix_ms());
        let Some(mut request) = received else {
            continue;
        };
        let method = request.method().as_str().to_string();
        let url = request.url().to_string();
        let (path, query) = match url.split_once('?') {
            Some((p, q)) => (p.to_string(), q.to_string()),
            None => (url, String::new()),
        };
        let headers: HashMap<String, String> = request
            .headers()
            .iter()
            .map(|h| {
                (
                    h.field.as_str().as_str().to_ascii_lowercase(),
                    h.value.as_str().to_string(),
                )
            })
            .collect();
        #[cfg(unix)]
        if let Some(id) = terminal::output_id(&path) {
            let meta = Req {
                method: method.clone(),
                path: path.clone(),
                query: query.clone(),
                headers: headers.clone(),
                body: Vec::new(),
            };
            match app.prepare_terminal_output(&meta, id) {
                Ok(job) => {
                    std::thread::spawn(move || terminal::run_output(job, request.into_writer()));
                }
                Err(resp) => {
                    let _ = request.respond(to_http(resp, false, &[]));
                }
            }
            continue;
        }
        if files::is_files_path(&path) {
            // File transfers stream on their own thread, so the loop (and the dashboard) never waits on one.
            let meta = Req {
                method: method.clone(),
                path,
                query,
                headers,
                body: Vec::new(),
            };
            match app.prepare_files(&meta) {
                Ok(job) => {
                    std::thread::spawn(move || files::run(job, request));
                }
                Err(resp) => {
                    let _ = request.respond(to_http(resp, false, &[]));
                }
            }
            continue;
        }
        // A skill's files may be far more than 64 KiB. That one route may carry up to the cap that holds the largest skill,
        // and the sign-in and role checks run before any of it is read, as they do for a file transfer.
        let limit = skills_routes::big_body_cap(&method, &path).unwrap_or(MAX_BODY);
        if limit > MAX_BODY {
            let meta = Req {
                method: method.clone(),
                path: path.clone(),
                query: query.clone(),
                headers: headers.clone(),
                body: Vec::new(),
            };
            if let Some(refusal) = app.guard(&meta, true) {
                let _ = request.respond(to_http(refusal, false, &[]));
                continue;
            }
        }
        let too_big = request.body_length().is_some_and(|n| n > limit);
        let mut body = Vec::new();
        let step = if too_big {
            lane::Step::Done(Resp::error(413, "too_large", "request body too large"))
        } else {
            let _ = request
                .as_reader()
                .take(limit as u64 + 1)
                .read_to_end(&mut body);
            if body.len() > limit {
                lane::Step::Done(Resp::error(413, "too_large", "request body too large"))
            } else {
                app.begin(&Req {
                    method: method.clone(),
                    path,
                    query,
                    headers,
                    body,
                })
            }
        };
        let resp = match step {
            lane::Step::Done(resp) => resp,
            lane::Step::Later(job) => {
                // Checked and authorised above; what is left is waiting on the cloud or a box, which a worker does. A full
                // queue is answered at once instead of being queued without limit.
                let work = Box::new(lane::Work {
                    request,
                    method,
                    job,
                });
                if let Err(refused) = pool.submit(work) {
                    let (resp, extra) = lane::busy_reply();
                    send_answer(refused.request, &refused.method, resp, &extra);
                }
                continue;
            }
        };
        if resp.stream {
            spawn_stream(request, app.version(), app.streams());
            continue;
        }
        let extra = app.take_extra_headers();
        send_answer(request, &method, resp, &extra);
    }
}

/// Write `resp` to `request`. An answer that could not be written is the one way a request is lost after it was handled. A
/// browser that closed the connection itself (a page left, a request cancelled) is its own choice and is not worth a line;
/// any other failure is said, with what is safe to say: the kind of failure, the verb and the status. Never the path or
/// query (they can carry a trigger's secret) and never the body.
fn send_answer(request: tiny_http::Request, method: &str, resp: Resp, extra: &[(String, String)]) {
    let status = resp.status;
    if let Err(e) = request.respond(to_http(resp, method == "HEAD", extra)) {
        use std::io::ErrorKind::{BrokenPipe, ConnectionAborted, ConnectionReset};
        if !matches!(e.kind(), BrokenPipe | ConnectionReset | ConnectionAborted) {
            eprintln!(
                "ozbox: serve: could not send the answer to a {method} request (status {status}): {:?}",
                e.kind()
            );
        }
    }
}

/// A flag that turns true when the process is asked to stop (SIGINT, SIGTERM). A second request while it is already
/// stopping ends the process at once, so a stuck shutdown can always be escaped. Windows has no such signals here: the
/// flag stays false and the process is ended the usual way.
fn shutdown_flag() -> Arc<AtomicBool> {
    let flag = Arc::new(AtomicBool::new(false));
    #[cfg(unix)]
    for sig in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
        // Registered first, so the first signal sees the flag still false and only the second one exits.
        let _ = signal_hook::flag::register_conditional_shutdown(sig, 130, Arc::clone(&flag));
        let _ = signal_hook::flag::register(sig, Arc::clone(&flag));
    }
    flag
}

/// Hand an authorised `/v1/events` connection to its own thread. The thread holds only the version counter, never the
/// provider, so the request loop stays single-threaded. It sends `changed` when a change was applied through this
/// server and a comment line every 15 s to keep the connection alive; it ends when the browser goes away.
fn spawn_stream(request: tiny_http::Request, version: Arc<AtomicU64>, streams: Arc<AtomicUsize>) {
    streams.fetch_add(1, Ordering::SeqCst);
    // Read the counter now, on the request loop: a change applied before this thread gets going must still be announced.
    let first_seen = version.load(Ordering::SeqCst);
    std::thread::spawn(move || {
        use std::io::Write;
        let mut w = request.into_writer();
        let head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-store\r\nConnection: close\r\n\
X-Content-Type-Options: nosniff\r\nCross-Origin-Resource-Policy: same-origin\r\n\r\n";
        let mut seen = first_seen;
        let mut quiet = 0u32;
        let mut ok = w.write_all(head.as_bytes()).is_ok()
            && w.write_all(b"retry: 3000\n\nevent: hello\ndata: {}\n\n")
                .is_ok()
            && w.flush().is_ok();
        while ok {
            std::thread::sleep(Duration::from_millis(500));
            let now = version.load(Ordering::SeqCst);
            if now != seen {
                seen = now;
                quiet = 0;
                ok = write!(w, "event: changed\ndata: {{\"version\":{now}}}\n\n").is_ok();
            } else {
                quiet += 1;
                if quiet >= 30 {
                    quiet = 0;
                    ok = w.write_all(b": keepalive\n\n").is_ok();
                }
            }
            ok = ok && w.flush().is_ok();
        }
        streams.fetch_sub(1, Ordering::SeqCst);
    });
}

fn flush_stdout() {
    use std::io::Write;
    let _ = std::io::stdout().flush();
}

fn to_http(
    resp: Resp,
    head: bool,
    extra: &[(String, String)],
) -> tiny_http::Response<std::io::Cursor<Vec<u8>>> {
    let body = if head { Vec::new() } else { resp.body };
    let mut r = tiny_http::Response::from_data(body).with_status_code(resp.status);
    let mut add = |k: &str, v: &str| {
        if let Ok(h) = tiny_http::Header::from_bytes(k.as_bytes(), v.as_bytes()) {
            r.add_header(h);
        }
    };
    add("Content-Type", resp.content_type);
    add("X-Content-Type-Options", "nosniff");
    add("Referrer-Policy", "no-referrer");
    add("Cross-Origin-Resource-Policy", "same-origin");
    add("X-Frame-Options", "DENY");
    add(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; \
         object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    );
    if resp.no_store {
        add("Cache-Control", "no-store");
    }
    for (k, v) in extra {
        add(k, v);
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use ozbox_core::{BoxSpec, Size};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const TOKEN: &str = "test-token";

    fn app(dir: &std::path::Path) -> App {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7878);
        App::new(
            Box::new(ozbox_provider_fake::open(dir)),
            true,
            addr,
            TOKEN.into(),
        )
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

    fn json_of(r: &Resp) -> Value {
        serde_json::from_slice(&r.body).unwrap_or(Value::Null)
    }

    fn create(app: &mut App, name: &str) -> TestResult {
        let spec = BoxSpec::new(BoxName::new(name)?, Size::M);
        let op = Operation::Create { spec };
        let p = app.provider.plan(&op)?;
        app.provider.apply(&p)?;
        Ok(())
    }

    fn plan_for(app: &mut App, op: Value) -> Value {
        let r = app.handle(&req("POST", "/v1/plans", json!({ "operation": op })));
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        json_of(&r)
    }

    fn box_app() -> App {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7878);
        let facts = crate::this_box::Facts {
            hostname: Some("main".into()),
            vcpus: Some(8),
            memory_gb: Some(32),
            work_disk_gb: Some(300),
            image_release: None,
        };
        App::new(
            Box::new(crate::this_box::ThisBoxProvider::from_facts(&facts)),
            false,
            addr,
            TOKEN.into(),
        )
    }

    #[test]
    fn a_boxs_dashboard_lists_this_box_only_and_says_the_fleet_is_not_connected() {
        let mut a = box_app();
        let info = json_of(&a.handle(&req("GET", "/v1/info", Value::Null)));
        assert_eq!(info["provider"], "thisbox");
        assert_eq!(info["fleet"]["mode"], "this_box");
        assert_eq!(info["fleet"]["connected"], false);
        assert_eq!(info["fleet"]["demo"], false);
        assert_eq!(info["fleet"]["code"], "fleet_not_connected");
        assert!(info["fleet"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("Fleet not connected")));
        assert_eq!(info["metrics"], "live");
        let boxes = json_of(&a.handle(&req("GET", "/v1/boxes", Value::Null)));
        let names: Vec<&str> = boxes
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|b| b["spec"]["name"].as_str())
                    .collect()
            })
            .unwrap_or_default();
        assert_eq!(names, vec!["main"]);
    }

    #[test]
    fn on_a_box_every_fleet_endpoint_answers_a_typed_fleet_not_connected_error() -> TestResult {
        let mut a = box_app();
        let op = json!({ "operation": { "op": "pause", "name": "main" } });
        for (method, path, body) in [
            ("POST", "/v1/plans", op.clone()),
            ("POST", "/v1/apply", json!({ "plan_id": "x" })),
            ("GET", "/v1/cost", Value::Null),
            ("POST", "/v1/cost/refresh", json!({})),
            ("GET", "/v1/cost/bill", Value::Null),
            ("GET", "/v1/backups", Value::Null),
        ] {
            let r = a.handle(&req(method, path, body));
            assert_eq!(r.status, 409, "{method} {path}");
            let b = json_of(&r);
            assert_eq!(b["code"], "fleet_not_connected", "{method} {path}");
            assert!(b["message"]
                .as_str()
                .is_some_and(|m| m.contains("sees only this box")));
        }
        // what reads this box is untouched
        assert_eq!(
            a.handle(&req("GET", "/v1/boxes/main", Value::Null)).status,
            200
        );
        // and the provider itself refuses, whatever reaches it
        let pause = Operation::Pause {
            name: BoxName::new("main")?,
        };
        assert!(a.provider.plan(&pause).is_err());
        Ok(())
    }

    #[test]
    fn the_simulated_provider_is_marked_as_demo_data_in_the_api_and_still_works() -> TestResult {
        let dir = tempfile::tempdir()?;
        let mut a = app(dir.path());
        let info = json_of(&a.handle(&req("GET", "/v1/info", Value::Null)));
        assert_eq!(info["fleet"]["mode"], "demo");
        assert_eq!(info["fleet"]["demo"], true);
        assert_eq!(info["fleet"]["connected"], true);
        create(&mut a, "alpha")?;
        let r = a.handle(&req("GET", "/v1/cost", Value::Null));
        assert_ne!(json_of(&r)["code"], "fleet_not_connected");
        Ok(())
    }

    /// A security review (2026-11-11): a dashboard with no sign-in treated its access token as a fresh second factor, so on
    /// a box any process holding the token could take over a browser, resume an agent or change the browser's settings.
    #[test]
    fn on_a_box_without_a_sign_in_the_gated_browser_routes_are_refused_and_say_why() -> TestResult {
        let dir = tempfile::tempdir()?;
        let mut a = app(dir.path());
        a.on_a_box = true;
        for (method, path) in [
            ("POST", "/v1/browser/sessions/s1/takeover"),
            ("POST", "/v1/browser/sessions/s1/resume"),
            ("PUT", "/v1/browser/settings"),
        ] {
            let r = a.handle(&req(method, path, json!({})));
            assert_eq!(r.status, 403, "{path}");
            let body = String::from_utf8_lossy(&r.body).to_string();
            assert!(
                body.contains("sign_in_required") && body.contains("runs on a box"),
                "{body}"
            );
        }
        // on the person's own computer the token is the person, as before
        let mut local = app(dir.path());
        local.on_a_box = false;
        let r = local.handle(&req("PUT", "/v1/browser/settings", json!({})));
        assert!(!String::from_utf8_lossy(&r.body).contains("sign_in_required"));
        Ok(())
    }

    /// A box destroyed and made again under its name is a different machine. Opening its IDE must not reuse the proxy the
    /// old one had (whose dialer holds the old record and whose login is the old password), and a destroy here forgets what
    /// was kept for the name.
    #[test]
    fn a_box_made_again_under_a_destroyed_boxs_name_does_not_get_its_ide_proxy() -> TestResult {
        let dir = tempfile::tempdir()?;
        let mut a = app(dir.path());
        create(&mut a, "dev")?;
        let secret = crate::code::Service::Ide.secret_name("dev");
        a.secrets.set(&secret, "first-password")?;
        let open = |a: &mut App| {
            let r = a.handle(&req(
                "POST",
                "/v1/boxes/dev/code/open",
                json!({ "service": "ide" }),
            ));
            assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
            json_of(&r)["url"].as_str().unwrap_or("").to_string()
        };
        let first = open(&mut a);
        assert!(first.starts_with("http://localhost:"), "{first}");
        // opening again reuses the proxy: the same port, a new one-time address
        let again = open(&mut a);
        assert_eq!(
            first.split("/__").next(),
            again.split("/__").next(),
            "one proxy per box"
        );
        assert_eq!(a.code.kept_for("dev"), 1);

        // destroyed through the dashboard: nothing is kept for the name
        let plan = plan_for(
            &mut a,
            json!({"op": "destroy", "name": "dev", "final_snapshot": false}),
        );
        let r = a.handle(&req(
            "POST",
            "/v1/apply",
            json!({"plan_id": plan["plan_id"], "confirm_name": "dev"}),
        ));
        assert_eq!(r.status, 202, "{}", String::from_utf8_lossy(&r.body));
        assert_eq!(a.code.kept_for("dev"), 0, "a destroy removes the proxy");

        // made again under the same name: its own proxy, on its own port
        create(&mut a, "dev")?;
        a.secrets.set(&secret, "second-password")?;
        let second = open(&mut a);
        assert_ne!(
            first.split("/__").next(),
            second.split("/__").next(),
            "the new box has its own proxy"
        );
        assert_eq!(a.code.kept_for("dev"), 1);
        Ok(())
    }

    /// The same, when the old box went away without this server being asked (destroyed from the command line): the
    /// proxy kept for the old machine is dropped the moment the name is looked up for the new one.
    #[test]
    fn a_box_replaced_behind_the_servers_back_loses_the_old_ide_proxy_on_the_next_open(
    ) -> TestResult {
        let dir = tempfile::tempdir()?;
        let mut a = app(dir.path());
        create(&mut a, "dev")?;
        let secret = crate::code::Service::Ide.secret_name("dev");
        a.secrets.set(&secret, "pw")?;
        let open = |a: &mut App| {
            let r = a.handle(&req(
                "POST",
                "/v1/boxes/dev/code/open",
                json!({ "service": "ide" }),
            ));
            assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
            json_of(&r)["url"].as_str().unwrap_or("").to_string()
        };
        let first = open(&mut a);
        // gone and back again without a word to the server
        let name = BoxName::new("dev")?;
        let p = a.provider.plan(&Operation::Destroy {
            name: name.clone(),
            final_snapshot: false,
            keep_old_system_disks: false,
        })?;
        a.provider.apply(&p)?;
        create(&mut a, "dev")?;
        let second = open(&mut a);
        assert_ne!(first.split("/__").next(), second.split("/__").next());
        assert_eq!(a.code.kept_for("dev"), 1, "the old one was dropped");
        Ok(())
    }

    /// The same decision for every route that asks for a second factor (ADR 0039): on a box with no sign-in, granting
    /// access to production, changing the permission rules, applying a change that cannot be undone and changing how the
    /// dashboard is reached are refused too, with the reason; on the person's own computer they go on as before.
    /// H2. Approving a request for production makes a one-use grant, so on a box with no sign-in (where another process
    /// may hold the token) it is refused like granting access is, and nothing is approved or granted.
    #[test]
    fn on_a_box_without_a_sign_in_a_production_approval_is_refused_and_makes_no_grant() -> TestResult
    {
        let dir = tempfile::tempdir()?;
        let mut a = app(dir.path()).with_task_store(Some(dir.path().join("tasks.json")));
        a.on_a_box = true;
        let store = ozbox_core::run::TaskStore::new(dir.path().join("tasks.json"));
        store.update(|b| {
            b.approvals.push(ozbox_core::run::ApprovalRequest {
                id: "a1".into(),
                task_id: "t1".into(),
                kind: ozbox_core::run::ActionKind::AskCommand,
                action: "psql prod".into(),
                box_name: "dev".into(),
                asked_by: "claude-code".into(),
                production: true,
                needs_step_up: true,
                state: ozbox_core::run::ApprovalState::Pending,
                created_ms: 0,
                expires_ms: u64::MAX / 4,
                reminders: 0,
                decided_by: None,
                decided_ms: None,
                decided_with_step_up: false,
                delivered: false,
                used: false,
            })
        })?;
        let r = a.handle(&req("POST", "/v1/approval-requests/a1/approve", json!({})));
        let v = json_of(&r);
        assert_eq!(
            (r.status, v["code"].as_str()),
            (403, Some("sign_in_required")),
            "{v}"
        );
        let book = store.load()?;
        assert_eq!(
            book.approvals[0].state,
            ozbox_core::run::ApprovalState::Pending
        );
        assert!(book.perms.grants.is_empty(), "no grant was made");
        // denying is not a second-factor act
        let r = a.handle(&req("POST", "/v1/approval-requests/a1/deny", json!({})));
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        Ok(())
    }

    #[test]
    fn on_a_box_without_a_sign_in_every_route_that_asks_for_a_second_factor_is_refused(
    ) -> TestResult {
        let dir = tempfile::tempdir()?;
        let mut a = app(dir.path());
        create(&mut a, "dev")?;
        a.on_a_box = true;
        let grant = json!({"scope": "box", "scope_id": "dev", "reason": "deploy the fix", "minutes": 10, "confirm": "dev"});
        let refused = |a: &mut App, m: &str, p: &str, b: Value| {
            let r = a.handle(&req(m, p, b));
            let v = json_of(&r);
            assert_eq!(
                (r.status, v["code"].as_str()),
                (403, Some("sign_in_required")),
                "{m} {p}: {v}"
            );
            assert!(
                v["message"]
                    .as_str()
                    .unwrap_or("")
                    .contains("runs on a box"),
                "{v}"
            );
        };
        refused(&mut a, "POST", "/v1/permissions/grants", grant.clone());
        refused(
            &mut a,
            "PUT",
            "/v1/permissions",
            json!({"default_mode": "ask"}),
        );
        refused(
            &mut a,
            "PUT",
            "/v1/secrets/tunnel-token-cloudflare",
            json!({"value": "x"}),
        );
        // a change that cannot be undone: refused, and the plan is kept
        let plan = plan_for(
            &mut a,
            json!({"op": "destroy", "name": "dev", "final_snapshot": false}),
        );
        refused(
            &mut a,
            "POST",
            "/v1/apply",
            json!({"plan_id": plan["plan_id"], "confirm_name": "dev"}),
        );
        assert!(a.record("dev").is_ok(), "the box is still there");
        // one that can be undone is not a second-factor act, and goes through
        let pause = plan_for(&mut a, json!({"op": "pause", "name": "dev"}));
        let r = a.handle(&req(
            "POST",
            "/v1/apply",
            json!({"plan_id": pause["plan_id"]}),
        ));
        assert_eq!(r.status, 202, "{}", String::from_utf8_lossy(&r.body));

        // on the person's own computer nothing changes: the typed confirmation still stands in
        a.on_a_box = false;
        let r = a.handle(&req(
            "POST",
            "/v1/permissions/grants",
            json!({"scope": "box", "scope_id": "dev", "reason": "deploy the fix", "minutes": 10, "confirm": "wrong"}),
        ));
        assert_eq!(json_of(&r)["code"], "confirmation_required");
        let again = plan_for(
            &mut a,
            json!({"op": "destroy", "name": "dev", "final_snapshot": false}),
        );
        let r = a.handle(&req(
            "POST",
            "/v1/apply",
            json!({"plan_id": again["plan_id"], "confirm_name": "dev"}),
        ));
        assert_eq!(r.status, 202, "{}", String::from_utf8_lossy(&r.body));
        Ok(())
    }

    #[test]
    fn only_loopback_addresses_can_be_bound() {
        assert!(parse_bind("127.0.0.1").is_ok());
        assert!(parse_bind("::1").is_ok());
        assert!(parse_bind("localhost").is_ok());
        for bad in ["0.0.0.0", "::", "192.168.1.5", "10.0.0.1", "example.com"] {
            assert!(parse_bind(bad).is_err(), "{bad} must be refused");
        }
    }

    #[test]
    fn every_api_request_needs_the_token() -> TestResult {
        let dir = tempfile::tempdir()?;
        let mut a = app(dir.path());
        for tok in [
            None,
            Some("Bearer wrong"),
            Some("Bearer "),
            Some("test-token"),
        ] {
            let mut r = req("GET", "/v1/boxes", Value::Null);
            r.headers.remove("authorization");
            if let Some(t) = tok {
                r.headers.insert("authorization".into(), t.into());
            }
            assert_eq!(a.handle(&r).status, 401, "{tok:?}");
        }
        assert_eq!(a.handle(&req("GET", "/v1/boxes", Value::Null)).status, 200);
        Ok(())
    }

    #[test]
    fn a_foreign_host_or_origin_is_refused() -> TestResult {
        let dir = tempfile::tempdir()?;
        let mut a = app(dir.path());
        let mut r = req("GET", "/v1/boxes", Value::Null);
        r.headers.insert("host".into(), "evil.example:7878".into());
        assert_eq!(a.handle(&r).status, 403);
        let mut r = req("POST", "/v1/plans", json!({}));
        r.headers
            .insert("origin".into(), "http://evil.example".into());
        assert_eq!(a.handle(&r).status, 403);
        let mut r = req("GET", "/v1/boxes", Value::Null);
        r.headers
            .insert("origin".into(), "http://127.0.0.1:7878".into());
        assert_eq!(a.handle(&r).status, 200);
        Ok(())
    }

    #[test]
    fn planning_never_mutates() -> TestResult {
        let dir = tempfile::tempdir()?;
        let mut a = app(dir.path());
        create(&mut a, "dev")?;
        let before = json_of(&a.handle(&req("GET", "/v1/boxes/dev", Value::Null)));
        let p = plan_for(&mut a, json!({"op": "pause", "name": "dev"}));
        assert_eq!(p["noop"], false);
        assert!(p["plan_id"].as_str().is_some_and(|s| s.len() == 32));
        let after = json_of(&a.handle(&req("GET", "/v1/boxes/dev", Value::Null)));
        assert_eq!(before, after);
        assert_eq!(after["state"], "running");
        Ok(())
    }

    /// Apply a change and wait out the first answers of a box being made ready (`202` with `quiescing`): ask again until the
    /// change has started. What comes back is the answer `finished` reads (a `202` with the job).
    fn apply_wait(a: &mut App, body: Value) -> Resp {
        let mut r = a.handle(&req("POST", "/v1/apply", body.clone()));
        for _ in 0..2000 {
            if r.status != 202 || json_of(&r)["quiescing"] != true {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
            r = a.handle(&req("POST", "/v1/apply", body.clone()));
        }
        r
    }

    /// A change to a box runs as a job: the answer is `202`, and the job (already finished, with the inline worker tests
    /// use) holds what applying returned.
    fn finished(a: &mut App, r: &Resp) -> Value {
        assert_eq!(r.status, 202, "{}", String::from_utf8_lossy(&r.body));
        let id = json_of(r)["job_id"].as_str().unwrap_or("").to_string();
        let job = json_of(&a.handle(&req("GET", &format!("/v1/jobs/{id}"), Value::Null)));
        assert_eq!(job["state"], "done", "{job}");
        job["result"].clone()
    }

    /// A fake provider whose `apply` waits while `block` is set, like a machine that takes a while to boot.
    struct Gated {
        inner: ozbox_core::Engine<ozbox_provider_fake::FakeBackend>,
        block: Arc<AtomicBool>,
    }

    impl Provider for Gated {
        fn id(&self) -> &str {
            self.inner.id()
        }
        fn capabilities(&self) -> ozbox_core::Capabilities {
            self.inner.capabilities()
        }
        fn list(&self) -> ozbox_core::Result<Vec<BoxRecord>> {
            self.inner.list()
        }
        fn get(&self, name: &BoxName) -> ozbox_core::Result<Option<BoxRecord>> {
            self.inner.get(name)
        }
        fn plan(&self, op: &Operation) -> ozbox_core::Result<Plan> {
            self.inner.plan(op)
        }
        fn apply(&self, plan: &Plan) -> ozbox_core::Result<Option<BoxRecord>> {
            while self.block.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(5));
            }
            self.inner.apply(plan)
        }
    }

    #[test]
    fn a_slow_change_runs_in_the_background_and_the_server_keeps_answering() -> TestResult {
        let dir = tempfile::tempdir()?;
        let block = Arc::new(AtomicBool::new(false));
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7878);
        let mut a = App::new(
            Box::new(Gated {
                inner: ozbox_provider_fake::open(dir.path()),
                block: block.clone(),
            }),
            true,
            addr,
            TOKEN.into(),
        );
        create(&mut a, "dev")?;
        a.worker = worker::Worker::threaded();
        block.store(true, Ordering::SeqCst);
        let pause = plan_for(&mut a, json!({"op": "pause", "name": "dev"}));
        let snap = plan_for(&mut a, json!({"op": "snapshot", "name": "dev"}));
        let started = Instant::now();
        let r = a.handle(&req(
            "POST",
            "/v1/apply",
            json!({ "plan_id": pause["plan_id"] }),
        ));
        assert_eq!(r.status, 202, "{}", String::from_utf8_lossy(&r.body));
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the request did not wait for the change"
        );
        let id = json_of(&r)["job_id"].as_str().unwrap_or("").to_string();
        // other requests are answered while the change runs, and the job says so
        assert_eq!(a.handle(&req("GET", "/v1/boxes", Value::Null)).status, 200);
        let job = json_of(&a.handle(&req("GET", &format!("/v1/jobs/{id}"), Value::Null)));
        assert_eq!(job["state"], "running", "{job}");
        // one change per box at a time: a second one waits for the first, and its plan is not used up
        let second = a.handle(&req(
            "POST",
            "/v1/apply",
            json!({ "plan_id": snap["plan_id"] }),
        ));
        assert_eq!(second.status, 409);
        assert_eq!(json_of(&second)["code"], "box_busy");
        block.store(false, Ordering::SeqCst);
        let deadline = Instant::now() + Duration::from_secs(10);
        let job = loop {
            let j = json_of(&a.handle(&req("GET", &format!("/v1/jobs/{id}"), Value::Null)));
            if j["state"] != "running" || Instant::now() > deadline {
                break j;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(job["state"], "done", "{job}");
        assert_eq!(job["result"]["result"]["state"], "paused");
        // and now the other plan can be applied
        let third = a.handle(&req(
            "POST",
            "/v1/apply",
            json!({ "plan_id": snap["plan_id"] }),
        ));
        assert_ne!(third.status, 409);
        Ok(())
    }

    #[test]
    fn an_unknown_job_is_not_found() -> TestResult {
        let dir = tempfile::tempdir()?;
        let mut a = app(dir.path());
        assert_eq!(
            a.handle(&req("GET", "/v1/jobs/nope", Value::Null)).status,
            404
        );
        Ok(())
    }

    #[test]
    fn apply_runs_an_issued_plan_once() -> TestResult {
        let dir = tempfile::tempdir()?;
        let mut a = app(dir.path());
        create(&mut a, "dev")?;
        let p = plan_for(&mut a, json!({"op": "pause", "name": "dev"}));
        let body = json!({ "plan_id": p["plan_id"], "plan": p["plan"] });
        let r = a.handle(&req("POST", "/v1/apply", body.clone()));
        let done = finished(&mut a, &r);
        assert_eq!(done["applied"], true);
        assert_eq!(done["result"]["state"], "paused");
        // single use
        assert_eq!(a.handle(&req("POST", "/v1/apply", body)).status, 409);
        Ok(())
    }

    #[test]
    fn apply_refuses_a_plan_this_server_did_not_issue() -> TestResult {
        let dir = tempfile::tempdir()?;
        let mut a = app(dir.path());
        create(&mut a, "dev")?;
        // A genuine plan from the provider, but never issued by the server.
        let op = Operation::Pause {
            name: BoxName::new("dev")?,
        };
        let forged = a.provider.plan(&op)?;
        let r = a.handle(&req(
            "POST",
            "/v1/apply",
            json!({ "plan_id": "00000000000000000000000000000000", "plan": forged }),
        ));
        assert_eq!(r.status, 409);
        assert_eq!(json_of(&r)["code"], "unknown_plan");
        assert_eq!(
            json_of(&a.handle(&req("GET", "/v1/boxes/dev", Value::Null)))["state"],
            "running"
        );
        // An issued id with a doctored plan body is refused too.
        let issued = plan_for(&mut a, json!({"op": "pause", "name": "dev"}));
        let mut doctored = issued["plan"].clone();
        doctored["changes"] = json!([]);
        let r = a.handle(&req(
            "POST",
            "/v1/apply",
            json!({ "plan_id": issued["plan_id"], "plan": doctored }),
        ));
        assert_eq!(json_of(&r)["code"], "plan_mismatch");
        Ok(())
    }

    #[test]
    fn high_risk_needs_the_box_name() -> TestResult {
        let dir = tempfile::tempdir()?;
        let mut a = app(dir.path());
        create(&mut a, "dev")?;
        let p = plan_for(
            &mut a,
            json!({"op": "destroy", "name": "dev", "final_snapshot": true}),
        );
        assert_eq!(p["requires_confirm_name"], true);
        for confirm in [None, Some("other"), Some("DEV")] {
            let r = a.handle(&req(
                "POST",
                "/v1/apply",
                json!({ "plan_id": p["plan_id"], "confirm_name": confirm }),
            ));
            assert_eq!(r.status, 400, "{confirm:?}");
            assert_eq!(json_of(&r)["code"], "confirmation_required");
        }
        assert_eq!(
            a.handle(&req("GET", "/v1/boxes/dev", Value::Null)).status,
            200
        );
        let r = a.handle(&req(
            "POST",
            "/v1/apply",
            json!({ "plan_id": p["plan_id"], "confirm_name": "dev" }),
        ));
        assert_eq!(r.status, 202, "{}", String::from_utf8_lossy(&r.body));
        assert_eq!(
            a.handle(&req("GET", "/v1/boxes/dev", Value::Null)).status,
            404
        );
        Ok(())
    }

    #[test]
    fn a_plan_that_changed_underneath_is_stale() -> TestResult {
        let dir = tempfile::tempdir()?;
        let mut a = app(dir.path());
        create(&mut a, "dev")?;
        let p = plan_for(&mut a, json!({"op": "pause", "name": "dev"}));
        // Someone else pauses it first.
        let op = Operation::Pause {
            name: BoxName::new("dev")?,
        };
        let other = a.provider.plan(&op)?;
        a.provider.apply(&other)?;
        let r = a.handle(&req(
            "POST",
            "/v1/apply",
            json!({ "plan_id": p["plan_id"] }),
        ));
        // the provider refuses the stale plan, on the job: the job fails with the refusal it would have answered
        assert_eq!(r.status, 202);
        let id = json_of(&r)["job_id"].as_str().unwrap_or("").to_string();
        let job = json_of(&a.handle(&req("GET", &format!("/v1/jobs/{id}"), Value::Null)));
        assert_eq!(job["state"], "failed", "{job}");
        assert_eq!(job["status"], 409);
        assert_eq!(job["failure"]["code"], "stale_plan");
        Ok(())
    }

    #[test]
    fn expired_plans_are_refused() -> TestResult {
        let dir = tempfile::tempdir()?;
        let mut a = app(dir.path()).with_plan_ttl(Duration::ZERO);
        create(&mut a, "dev")?;
        let p = plan_for(&mut a, json!({"op": "pause", "name": "dev"}));
        let r = a.handle(&req(
            "POST",
            "/v1/apply",
            json!({ "plan_id": p["plan_id"] }),
        ));
        assert_eq!(json_of(&r)["code"], "stale_plan");
        Ok(())
    }

    #[test]
    fn simulated_metrics_are_flagged_and_deterministic() -> TestResult {
        let dir = tempfile::tempdir()?;
        let mut a = app(dir.path());
        create(&mut a, "dev")?;
        let r = a.handle(&req("GET", "/v1/boxes/dev/metrics/now", Value::Null));
        assert_eq!(r.status, 200);
        let v = json_of(&r);
        assert_eq!(v["source"], "simulated");
        assert!(v["sample"]["cpu_pct"].as_f64().is_some());
        let s1 = a.handle(&req(
            "GET",
            "/v1/boxes/dev/metrics?since=2026-01-01T00:00:00Z&step=1h&x=1",
            Value::Null,
        ));
        // Ten months of hourly points is more than the server will build in one answer.
        assert_eq!(s1.status, 400);
        let now = unix_ms();
        let iso_start = now - 15 * 60 * 1000;
        let q = format!(
            "/v1/boxes/dev/metrics?since={}&step=5s",
            percent_encode_iso(iso_start)
        );
        let r1 = json_of(&a.handle(&req("GET", &q, Value::Null)));
        let r2 = json_of(&a.handle(&req("GET", &q, Value::Null)));
        assert_eq!(r1["source"], "simulated");
        assert!(r1["samples"].as_array().is_some_and(|s| s.len() >= 170));
        assert_eq!(r1["samples"][0], r2["samples"][0]);
        Ok(())
    }

    fn percent_encode_iso(ms: u64) -> String {
        // Build an RFC 3339 string from unix ms (UTC) with the colons percent-encoded.
        let secs = (ms / 1000) as i64;
        let days = secs.div_euclid(86_400);
        let rem = secs.rem_euclid(86_400);
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = if m <= 2 { y + 1 } else { y };
        format!(
            "{y:04}-{m:02}-{d:02}T{:02}%3A{:02}%3A{:02}Z",
            rem / 3600,
            (rem % 3600) / 60,
            rem % 60
        )
    }

    #[test]
    fn a_paused_box_reports_no_usage() -> TestResult {
        let dir = tempfile::tempdir()?;
        let mut a = app(dir.path());
        create(&mut a, "dev")?;
        let p = plan_for(&mut a, json!({"op": "pause", "name": "dev"}));
        a.handle(&req(
            "POST",
            "/v1/apply",
            json!({ "plan_id": p["plan_id"] }),
        ));
        let r = a.handle(&req("GET", "/v1/boxes/dev/metrics/now", Value::Null));
        assert_eq!(r.status, 409);
        Ok(())
    }

    #[test]
    fn real_providers_answer_501_for_metrics() -> TestResult {
        let dir = tempfile::tempdir()?;
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7878);
        let mut a = App::new(
            Box::new(ozbox_provider_fake::open(dir.path())),
            false,
            addr,
            TOKEN.into(),
        );
        create(&mut a, "dev")?;
        let r = a.handle(&req("GET", "/v1/boxes/dev/metrics/now", Value::Null));
        assert_eq!(r.status, 501);
        assert!(json_of(&r)["message"]
            .as_str()
            .is_some_and(|m| m.contains("SSH forwarding")));
        Ok(())
    }

    #[test]
    fn unknown_boxes_and_bad_names_are_clean_errors() -> TestResult {
        let dir = tempfile::tempdir()?;
        let mut a = app(dir.path());
        assert_eq!(
            a.handle(&req("GET", "/v1/boxes/nope", Value::Null)).status,
            404
        );
        assert_eq!(
            a.handle(&req("GET", "/v1/boxes/Bad_Name", Value::Null))
                .status,
            400
        );
        assert_eq!(
            a.handle(&req("DELETE", "/v1/boxes", Value::Null)).status,
            405
        );
        assert_eq!(
            a.handle(&req("GET", "/v1/nothing", Value::Null)).status,
            404
        );
        Ok(())
    }

    #[test]
    fn rfc3339_parses() {
        assert_eq!(parse_rfc3339_ms("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_rfc3339_ms("2026-07-01T00:00:00.500Z"),
            Some(1_782_864_000_500)
        );
        assert_eq!(
            parse_rfc3339_ms("2026-07-01T02:00:00+02:00"),
            Some(1_782_864_000_000)
        );
        assert_eq!(parse_rfc3339_ms("yesterday"), None);
        assert_eq!(parse_rfc3339_ms("2026-13-01T00:00:00Z"), None);
    }

    #[test]
    fn static_pages_need_no_token_and_unbuilt_says_so() -> TestResult {
        let dir = tempfile::tempdir()?;
        let mut a = app(dir.path());
        let mut r = req("GET", "/", Value::Null);
        r.headers.remove("authorization");
        let resp = a.handle(&r);
        assert_eq!(resp.status, 200);
        assert!(resp.content_type.starts_with("text/html"));
        let mut r = req("POST", "/", Value::Null);
        r.headers.remove("authorization");
        assert_eq!(a.handle(&r).status, 405);
        Ok(())
    }

    #[test]
    fn approvals_list_open_plans_and_flag_passkey_for_irreversible_ones() -> TestResult {
        let dir = tempfile::tempdir()?;
        let mut a = app(dir.path());
        create(&mut a, "dev")?;
        let empty = json_of(&a.handle(&req("GET", "/v1/approvals", Value::Null)));
        assert_eq!(empty["items"], json!([]));
        // plans are kept in memory, and the answer says so, with how long one stays open
        assert_eq!(empty["persisted"], false);
        assert_eq!(empty["ttl_s"], 600);
        let low = plan_for(&mut a, json!({"op": "pause", "name": "dev"}));
        let high = plan_for(
            &mut a,
            json!({"op": "destroy", "name": "dev", "final_snapshot": true}),
        );
        assert_eq!(high["needs_passkey"], true);
        assert_eq!(low["needs_passkey"], false);
        let v = json_of(&a.handle(&req("GET", "/v1/approvals", Value::Null)));
        let items = v["items"].as_array().cloned().unwrap_or_default();
        assert_eq!(items.len(), 2);
        assert!(items
            .iter()
            .any(|i| i["needs_passkey"] == true && i["verb"] == "destroy"));
        // a pending plan can be fetched again to review it
        let again = a.handle(&req(
            "GET",
            &format!("/v1/plans/{}", low["plan_id"].as_str().unwrap_or("")),
            Value::Null,
        ));
        assert_eq!(again.status, 200);
        assert_eq!(
            a.handle(&req("GET", "/v1/plans/nope", Value::Null)).status,
            409
        );
        Ok(())
    }

    #[test]
    fn activity_records_what_happened_and_nothing_secret() -> TestResult {
        let dir = tempfile::tempdir()?;
        let mut a = app(dir.path());
        create(&mut a, "dev")?;
        let p = plan_for(&mut a, json!({"op": "pause", "name": "dev"}));
        a.handle(&req(
            "POST",
            "/v1/apply",
            json!({ "plan_id": p["plan_id"] }),
        ));
        let v = json_of(&a.handle(&req("GET", "/v1/activity", Value::Null)));
        let e = v["entries"].as_array().cloned().unwrap_or_default();
        assert_eq!(e.len(), 2);
        assert_eq!(e[0]["action"], "plan pause");
        assert_eq!(e[1]["action"], "apply pause");
        assert_eq!(e[1]["outcome"], "applied");
        assert_eq!(e[1]["box_name"], "dev");
        assert!(!v.to_string().contains(TOKEN));
        Ok(())
    }

    #[test]
    fn runs_are_simulated_and_flagged_and_logs_are_synthetic() -> TestResult {
        let dir = tempfile::tempdir()?;
        let mut a = app(dir.path());
        create(&mut a, "dev")?;
        let v = json_of(&a.handle(&req("GET", "/v1/runs", Value::Null)));
        assert_eq!(v["source"], "simulated");
        let runs = v["runs"].as_array().cloned().unwrap_or_default();
        for s in ["running", "queued", "finished"] {
            assert!(runs.iter().any(|r| r["status"] == s), "{s}");
        }
        let logs = json_of(&a.handle(&req("GET", "/v1/runs/dev-run-1/logs", Value::Null)));
        assert!(logs["lines"][0]
            .as_str()
            .is_some_and(|l| l.contains("simulated")));
        assert_eq!(
            a.handle(&req("GET", "/v1/runs/dev-run-9/logs", Value::Null))
                .status,
            404
        );
        Ok(())
    }

    #[test]
    fn events_need_the_token_and_are_capped() -> TestResult {
        let dir = tempfile::tempdir()?;
        let mut a = app(dir.path());
        let mut r = req("GET", "/v1/events", Value::Null);
        r.headers.remove("authorization");
        assert_eq!(a.handle(&r).status, 401);
        let ok = a.handle(&req("GET", "/v1/events", Value::Null));
        assert!(ok.stream && ok.content_type == "text/event-stream");
        a.streams().store(MAX_STREAMS, Ordering::SeqCst);
        assert_eq!(a.handle(&req("GET", "/v1/events", Value::Null)).status, 429);
        Ok(())
    }

    #[test]
    fn info_says_which_dashboard_is_embedded() -> TestResult {
        let dir = tempfile::tempdir()?;
        let v = json_of(&app(dir.path()).info());
        let embedded = !embedded::EMBEDDED.is_empty();
        assert_eq!(v["dashboard"]["embedded"], embedded);
        let hash = v["dashboard"]["sha256"].as_str().unwrap_or_default();
        if embedded {
            assert_eq!(hash.len(), 64, "{hash}");
            assert!(hash.bytes().all(|b| b.is_ascii_hexdigit()));
        } else {
            assert_eq!(hash, "none");
        }
        Ok(())
    }

    #[test]
    fn info_reports_the_domain_only_when_configured() -> TestResult {
        let dir = tempfile::tempdir()?;
        let a = app(dir.path());
        assert!(json_of(&a.info())["domain"].is_null());
        let b = app(dir.path()).with_domain(Some("example.com".into()));
        assert_eq!(json_of(&b.info())["domain"], "example.com");
        Ok(())
    }

    #[test]
    fn ssh_entry_needs_a_domain_and_is_text_only() -> TestResult {
        let dir = tempfile::tempdir()?;
        let mut a = app(dir.path());
        create(&mut a, "dev")?;
        let none = a.handle(&req("GET", "/v1/boxes/dev/ssh", Value::Null));
        assert_eq!(none.status, 409);
        assert_eq!(json_of(&none)["code"], "no_route");
        let mut b = app(dir.path()).with_domain(Some("example.com".into()));
        let v = json_of(&b.handle(&req("GET", "/v1/boxes/dev/ssh", Value::Null)));
        assert_eq!(v["host"], "ozbox-dev");
        assert_eq!(v["command"], "ssh ozbox-dev");
        assert!(v["config"]
            .as_str()
            .is_some_and(|c| c.contains("HostName ssh-dev.example.com")));
        assert_eq!(
            b.handle(&req("GET", "/v1/boxes/nope/ssh", Value::Null))
                .status,
            404
        );
        Ok(())
    }

    #[test]
    fn the_ssh_endpoint_makes_sure_the_dedicated_key_exists_and_never_replaces_one() -> TestResult {
        let dir = tempfile::tempdir()?;
        let ssh = tempfile::tempdir()?;
        let runner = Arc::new(ozbox_core::RecordingRunner::new());
        let mut a = app(dir.path())
            .with_domain(Some("example.com".into()))
            .with_ssh_dir(Some(ssh.path().to_path_buf()))
            .with_runner(runner.clone());
        create(&mut a, "dev")?;
        // a GET never writes: no key is made and nothing runs
        let got = a.handle(&req("GET", "/v1/boxes/dev/ssh", Value::Null));
        assert_eq!(got.status, 200);
        assert_eq!(json_of(&got)["key_exists"], json!(false));
        assert!(runner.calls().is_empty());
        assert_eq!(
            a.handle(&req("POST", "/v1/boxes/dev/ssh", Value::Null))
                .status,
            200
        );
        let calls = runner.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].program, "ssh-keygen");
        // With both halves present, nothing runs and the private key is untouched.
        std::fs::write(ssh.path().join("ozbox_ed25519"), "PRIVATE")?;
        std::fs::write(ssh.path().join("ozbox_ed25519.pub"), "PUBLIC")?;
        assert_eq!(
            a.handle(&req("POST", "/v1/boxes/dev/ssh", Value::Null))
                .status,
            200
        );
        assert_eq!(runner.calls().len(), 1);
        assert_eq!(
            std::fs::read_to_string(ssh.path().join("ozbox_ed25519"))?,
            "PRIVATE"
        );
        Ok(())
    }

    /// An agent whose every call takes a while, like a box on a bad connection.
    struct SlowAgent {
        delay: Duration,
        calls: Arc<AtomicUsize>,
    }

    impl BoxAgent for SlowAgent {
        fn metrics_now(
            &self,
            _: &BoxRecord,
            _: u64,
        ) -> Result<ozbox_core::MetricsSample, AgentError> {
            std::thread::sleep(self.delay);
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(AgentError::Unreachable("slow".into()))
        }
        fn metrics_series(
            &self,
            _: &BoxRecord,
            _: u64,
            _: u64,
            _: u64,
        ) -> Result<Vec<ozbox_core::MetricsSample>, AgentError> {
            Err(AgentError::Unreachable("slow".into()))
        }
        fn selftest(&self, _: &BoxRecord, _: u64) -> Result<agent::SelfTest, AgentError> {
            Err(AgentError::Unreachable("slow".into()))
        }
        fn incidents(
            &self,
            _: &BoxRecord,
            _: u64,
            _: u64,
        ) -> Result<Vec<agent::Incident>, AgentError> {
            Err(AgentError::Unreachable("slow".into()))
        }
        fn housekeeping(&self, _: u64) {
            std::thread::sleep(self.delay);
        }
    }

    /// A box whose usage read blocks until released, then answers with `samples` (or nothing). Counts the reads started.
    struct BlockedBox {
        started: Arc<AtomicUsize>,
        release: Arc<AtomicBool>,
        samples: Vec<ozbox_core::MetricsSample>,
    }

    impl BoxAgent for BlockedBox {
        fn metrics_now(
            &self,
            _: &BoxRecord,
            _: u64,
        ) -> Result<ozbox_core::MetricsSample, AgentError> {
            Err(AgentError::Unreachable("none".into()))
        }
        fn metrics_series(
            &self,
            _: &BoxRecord,
            _: u64,
            _: u64,
            _: u64,
        ) -> Result<Vec<ozbox_core::MetricsSample>, AgentError> {
            self.started.fetch_add(1, Ordering::SeqCst);
            while !self.release.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(self.samples.clone())
        }
        fn selftest(&self, _: &BoxRecord, _: u64) -> Result<agent::SelfTest, AgentError> {
            Err(AgentError::Unreachable("none".into()))
        }
        fn incidents(
            &self,
            _: &BoxRecord,
            _: u64,
            _: u64,
        ) -> Result<Vec<agent::Incident>, AgentError> {
            Ok(Vec::new())
        }
    }

    fn blocked_app(
        dir: &std::path::Path,
        samples: Vec<ozbox_core::MetricsSample>,
    ) -> (App, Arc<AtomicUsize>, Arc<AtomicBool>) {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7878);
        let started = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(AtomicBool::new(false));
        let a = App::new(
            Box::new(ozbox_provider_fake::open(dir)),
            false,
            addr,
            TOKEN.into(),
        )
        .with_agent(Box::new(BlockedBox {
            started: started.clone(),
            release: release.clone(),
            samples,
        }))
        .with_read_budgets(Duration::from_millis(150), Duration::from_millis(60));
        (a, started, release)
    }

    #[test]
    fn a_slow_box_is_read_once_at_a_time_and_the_loop_is_not_held() -> TestResult {
        let dir = tempfile::tempdir()?;
        let (mut a, started, release) = blocked_app(dir.path(), Vec::new());
        create(&mut a, "dev")?;
        let t = Instant::now();
        let first = json_of(&get(&mut a, "/v1/usage?range=5s"));
        assert!(t.elapsed() < Duration::from_millis(1500), "held the loop");
        assert_eq!(first["unreachable"][0]["name"], "dev", "{first}");
        // polls while the first read is still blocked never start another
        for _ in 0..3 {
            let v = json_of(&get(&mut a, "/v1/usage?range=5s"));
            assert!(
                v["unreachable"][0]["reason"]
                    .as_str()
                    .is_some_and(|r| r.contains("still being read")),
                "{v}"
            );
            let _ = get(&mut a, "/v1/suggestions");
        }
        assert_eq!(started.load(Ordering::SeqCst), 2, "one read per range");
        release.store(true, Ordering::SeqCst);
        Ok(())
    }

    #[test]
    fn a_box_that_answers_with_nothing_is_no_data_yet_not_unreachable() -> TestResult {
        let dir = tempfile::tempdir()?;
        let (mut a, _started, release) = blocked_app(dir.path(), Vec::new());
        release.store(true, Ordering::SeqCst);
        create(&mut a, "dev")?;
        let v = json_of(&get(&mut a, "/v1/usage?range=1m"));
        assert_eq!(v["unreachable"], json!([]), "{v}");
        assert_eq!(v["no_samples"][0]["name"], "dev", "{v}");
        assert_eq!(v["fleet"]["cost_partial"], true, "{v}");
        let v = json_of(&get(&mut a, "/v1/suggestions"));
        assert_eq!(v["unreachable"], json!([]), "{v}");
        assert_eq!(v["no_samples"][0]["name"], "dev", "{v}");
        Ok(())
    }

    #[test]
    fn a_slow_box_shows_its_last_answer_marked_with_when() -> TestResult {
        let dir = tempfile::tempdir()?;
        let sample = ozbox_core::MetricsSample {
            cpu_pct: 12.0,
            mem_total_bytes: 8 << 30,
            mem_available_bytes: 4 << 30,
            ..Default::default()
        };
        let (mut a, _started, release) = blocked_app(dir.path(), vec![sample]);
        release.store(true, Ordering::SeqCst);
        create(&mut a, "dev")?;
        let v = json_of(&get(&mut a, "/v1/usage?range=1m"));
        assert_eq!(v["boxes"][0]["name"], "dev", "{v}");
        assert_eq!(v["stale"], json!([]), "{v}");
        // the box now stalls: the next read shows the earlier answer, marked
        release.store(false, Ordering::SeqCst);
        let v = json_of(&get(&mut a, "/v1/usage?range=1m"));
        assert_eq!(v["boxes"][0]["name"], "dev", "{v}");
        assert_eq!(v["stale"][0]["name"], "dev", "{v}");
        assert!(v["stale"][0]["as_of_ms"].as_u64().is_some_and(|t| t > 0));
        release.store(true, Ordering::SeqCst);
        Ok(())
    }

    #[test]
    fn background_work_never_holds_the_request_thread() -> TestResult {
        let dir = tempfile::tempdir()?;
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7878);
        let calls = Arc::new(AtomicUsize::new(0));
        let mut a = App::new(
            Box::new(ozbox_provider_fake::open(dir.path())),
            false,
            addr,
            TOKEN.into(),
        )
        .with_agent(Box::new(SlowAgent {
            delay: Duration::from_millis(400),
            calls: calls.clone(),
        }))
        .with_background_worker();
        create(&mut a, "dev")?;
        let started = Instant::now();
        a.tick(1_000_000);
        a.tick(1_001_000);
        assert!(
            started.elapsed() < Duration::from_millis(250),
            "ticks returned in {:?}",
            started.elapsed()
        );
        // Requests are served while the worker is still busy.
        let t = Instant::now();
        assert_eq!(get(&mut a, "/v1/info").status, 200);
        assert!(t.elapsed() < Duration::from_millis(250));
        // The slow work does get done, and the next tick picks the result up.
        let deadline = Instant::now() + Duration::from_secs(10);
        while (calls.load(Ordering::SeqCst) == 0 || a.schedule.alerts_busy)
            && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(50));
            a.tick(1_002_000);
        }
        assert!(calls.load(Ordering::SeqCst) >= 1);
        assert!(!a.schedule.alerts_busy, "the result was applied");
        Ok(())
    }

    fn put_req(path: &str, body: &[u8]) -> Req {
        let mut r = req("PUT", path, Value::Null);
        r.body = body.to_vec();
        r
    }

    #[test]
    fn the_file_browser_reads_and_changes_a_demo_box_through_the_proxy() -> TestResult {
        let dir = tempfile::tempdir()?;
        let mut a = app(dir.path());
        create(&mut a, "dev")?;
        let roots = json_of(&get(&mut a, "/v1/boxes/dev/files/roots"));
        let root = roots["roots"][0]["path"].as_str().unwrap_or("").to_string();
        let list =
            |a: &mut App, p: &str| json_of(&get(a, &format!("/v1/boxes/dev/files/list?path={p}")));
        let top = list(&mut a, &root);
        assert!(top["entries"]
            .as_array()
            .is_some_and(|e| e.iter().any(|x| x["name"] == "exchange")));
        // upload (streamed), then it is listed and previewable
        let up = a.handle(&put_req(
            &format!("/v1/boxes/dev/files/upload?path={root}/exchange&name=note.txt"),
            b"hi there",
        ));
        assert_eq!(up.status, 201, "{}", String::from_utf8_lossy(&up.body));
        let pv = json_of(&get(
            &mut a,
            &format!("/v1/boxes/dev/files/preview?path={root}/exchange/note.txt"),
        ));
        assert_eq!(
            (pv["text"].as_str(), pv["editable"].clone()),
            (Some("hi there"), json!(true))
        );
        // a secret is refused with the reason, in the {code, message} shape
        let env = get(
            &mut a,
            &format!("/v1/boxes/dev/files/preview?path={root}/projects/demo/.env"),
        );
        assert_eq!(env.status, 403);
        assert_eq!(json_of(&env)["code"], "secret_blocked");
        assert!(!String::from_utf8_lossy(&env.body).contains("not-a-real-secret"));
        // a share link works without the bearer token, but only on the right host
        let tok = json_of(&a.handle(&req(
            "POST",
            "/v1/boxes/dev/files/tokens",
            json!({ "paths": [format!("{root}/exchange/note.txt")], "ttl_s": 60 }),
        )))["token"]
            .as_str()
            .unwrap_or("")
            .to_string();
        let mut dl = req("GET", &format!("/dl/dev/{tok}"), Value::Null);
        dl.headers.remove("authorization");
        let got = a.handle(&dl);
        assert_eq!(
            (got.status, got.body.as_slice()),
            (200, b"hi there".as_slice())
        );
        dl.headers.insert("host".into(), "evil.example".into());
        assert_eq!(a.handle(&dl).status, 403);
        // changes are in the activity list, with no paths or contents
        let act = json_of(&get(&mut a, "/v1/activity")).to_string();
        assert!(act.contains("files upload") && act.contains("files download"));
        assert!(!act.contains("note.txt") && !act.contains("hi there"));
        Ok(())
    }

    #[test]
    fn file_requests_need_the_token_a_running_box_and_a_transport() -> TestResult {
        let dir = tempfile::tempdir()?;
        let mut a = app(dir.path());
        create(&mut a, "dev")?;
        let mut r = req("GET", "/v1/boxes/dev/files/roots", Value::Null);
        r.headers.remove("authorization");
        assert_eq!(a.handle(&r).status, 401);
        assert_eq!(get(&mut a, "/v1/boxes/ghost/files/roots").status, 404);
        assert_eq!(get(&mut a, "/v1/boxes/dev/files/..%2f..%2fx").status, 404);
        assert_eq!(
            a.handle(&req("PATCH", "/v1/boxes/dev/files/roots", Value::Null))
                .status,
            405
        );
        // a real provider without a transport says so
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7878);
        let mut b = App::new(
            Box::new(ozbox_provider_fake::open(dir.path())),
            false,
            addr,
            TOKEN.into(),
        );
        assert_eq!(get(&mut b, "/v1/boxes/dev/files/roots").status, 501);
        // the number of transfers at once is capped
        let held: Vec<_> = (0..files::MAX_TRANSFERS)
            .map(|_| a.prepare_files(&req("GET", "/v1/boxes/dev/files/roots", Value::Null)))
            .collect();
        assert!(held.iter().all(Result::is_ok));
        assert_eq!(get(&mut a, "/v1/boxes/dev/files/roots").status, 429);
        drop(held);
        assert_eq!(get(&mut a, "/v1/boxes/dev/files/roots").status, 200);
        Ok(())
    }

    #[test]
    fn files_and_terminals_say_whether_they_are_the_demos_and_what_they_run_as() -> TestResult {
        let dir = tempfile::tempdir()?;
        let mut a = app(dir.path());
        create(&mut a, "dev")?;
        // the demo says so on its files, listing and all
        let roots = json_of(&get(&mut a, "/v1/boxes/dev/files/roots"));
        assert_eq!(roots["source"], "simulated");
        let root = roots["roots"][0]["path"].as_str().unwrap_or("").to_string();
        let list = json_of(&get(
            &mut a,
            &format!("/v1/boxes/dev/files/list?path={root}"),
        ));
        assert_eq!(list["source"], "simulated");
        // and a terminal is named before any output: the box, a made-up shell, a demo user
        let t = json_of(&a.handle(&req(
            "POST",
            "/v1/boxes/dev/terminal",
            json!({ "cols": 80, "rows": 24 }),
        )));
        assert_eq!(
            t["target"],
            json!({ "box": "dev", "source": "simulated", "runs_as": "demo" })
        );
        assert!(t["session"].as_str().is_some_and(|s| s.len() == 32));
        // a real server (no demo) names the box user, and the shell is the box's own agent's to start
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7878);
        let mut b = App::new(
            Box::new(ozbox_provider_fake::open(dir.path())),
            false,
            addr,
            TOKEN.into(),
        );
        let t = json_of(&b.handle(&req(
            "POST",
            "/v1/boxes/dev/terminal",
            json!({ "cols": 80, "rows": 24 }),
        )));
        assert_eq!(
            t["target"],
            json!({ "box": "dev", "source": "live", "runs_as": "box_user" })
        );
        Ok(())
    }

    #[test]
    fn a_demo_on_a_box_refuses_the_dashboards_files_and_terminal_through_the_api() -> TestResult {
        // X2 at the API: the demo's agent on a box answers 501 with its reason, so a person gets words, never a shell or a folder.
        let dir = tempfile::tempdir()?;
        let mut a = app(dir.path());
        create(&mut a, "dev")?;
        a.agent = Arc::new(agent::SimulatedAgent::with_host_is_box(true));
        let files = get(&mut a, "/v1/boxes/dev/files/roots");
        assert_eq!(files.status, 501);
        assert!(String::from_utf8_lossy(&files.body).contains("demo"));
        let rec = a.running_box("dev").map_err(|_| "no box")?;
        #[cfg(unix)]
        {
            let refused = a.agent.terminal(&rec, 80, 24, None).err();
            assert!(
                refused.is_some_and(|e| e.to_string().contains("demo terminal")),
                "a demo on a box opened a terminal"
            );
        }
        let _ = rec;
        // and nothing was made on this computer: no demo folder exists under the state directory
        assert!(!dir.path().join("dev").join("work").exists());
        Ok(())
    }

    fn create_with(app: &mut App, name: &str, size: Size, labels: &[(&str, &str)]) -> TestResult {
        let mut spec = BoxSpec::new(BoxName::new(name)?, size);
        spec.labels = labels
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        let p = app.provider.plan(&Operation::Create { spec })?;
        app.provider.apply(&p)?;
        Ok(())
    }

    fn get(a: &mut App, path: &str) -> Resp {
        a.handle(&req("GET", path, Value::Null))
    }

    #[test]
    fn settings_are_validated_saved_to_a_file_and_read_back() -> TestResult {
        let dir = tempfile::tempdir()?;
        let file = dir.path().join("settings.json");
        let mut a = app(dir.path()).with_settings(Settings::default(), Some(file.clone()));
        let v = json_of(&get(&mut a, "/v1/settings"));
        assert_eq!(v["persisted"], true);
        assert_eq!(v["settings"]["defaults"]["work_disk_gb"], 200);
        let mut s = Settings::default();
        s.budget.max_running_boxes = Some(3);
        let ok = a.handle(&req("PUT", "/v1/settings", serde_json::to_value(&s)?));
        assert_eq!(ok.status, 200);
        assert_eq!(
            Settings::load_from(&file)?.budget.max_running_boxes,
            Some(3)
        );
        // a bad value is a 400 and changes nothing
        s.budget.max_running_boxes = Some(0);
        let bad = a.handle(&req("PUT", "/v1/settings", serde_json::to_value(&s)?));
        assert_eq!(bad.status, 400);
        assert_eq!(
            Settings::load_from(&file)?.budget.max_running_boxes,
            Some(3)
        );
        let unknown = a.handle(&req(
            "PUT",
            "/v1/settings",
            json!({ "budget": { "colour": 1 } }),
        ));
        assert_eq!(unknown.status, 400);
        assert_eq!(
            a.handle(&req("DELETE", "/v1/settings", Value::Null)).status,
            405
        );
        Ok(())
    }

    #[test]
    fn raising_or_removing_a_model_cap_on_a_box_with_no_sign_in_is_refused_and_lowering_is_not(
    ) -> TestResult {
        let dir = tempfile::tempdir()?;
        let file = dir.path().join("settings.json");
        let mut a = app(dir.path()).with_settings(Settings::default(), Some(file.clone()));
        a.on_a_box = true;
        let mut s = Settings::default();
        let mut p = crate::settings::ModelProvider {
            id: "openai".into(),
            kind: crate::settings::ModelKind::Openai,
            label: "OpenAI".into(),
            base_url: None,
            local_endpoint: false,
            monthly_cap_usd: Some(50.0),
            region: None,
            resource: None,
            hosted_on: None,
        };
        s.models.providers = vec![p.clone()];
        let put = |a: &mut App, s: &Settings| {
            a.handle(&req(
                "PUT",
                "/v1/settings",
                serde_json::to_value(s).unwrap_or_default(),
            ))
        };
        // a first cap is not a loosening
        assert_eq!(put(&mut a, &s).status, 200);
        p.monthly_cap_usd = Some(20.0);
        s.models.providers = vec![p.clone()];
        assert_eq!(put(&mut a, &s).status, 200, "lowering needs nothing");
        for cap in [Some(90.0), None] {
            p.monthly_cap_usd = cap;
            s.models.providers = vec![p.clone()];
            let r = put(&mut a, &s);
            assert_eq!(r.status, 403);
            assert_eq!(json_of(&r)["code"], "sign_in_required");
        }
        s.models.providers.clear();
        assert_eq!(put(&mut a, &s).status, 403, "dropping a capped provider");
        let kept = Settings::load_from(&file)?;
        assert_eq!(kept.models.providers[0].monthly_cap_usd, Some(20.0));
        // on the person's own computer the access token is the second factor
        a.on_a_box = false;
        assert_eq!(put(&mut a, &s).status, 200);
        Ok(())
    }

    #[test]
    fn create_plans_refuse_at_the_cap_and_fill_defaults() -> TestResult {
        let dir = tempfile::tempdir()?;
        let mut s = Settings::default();
        s.budget.max_running_boxes = Some(1);
        s.defaults.size = Size::L;
        s.defaults.work_disk_gb = 321;
        let mut a = app(dir.path()).with_settings(s, None);
        // size and disk left out: the defaults fill them
        let r = a.handle(&req(
            "POST",
            "/v1/plans",
            json!({ "operation": { "op": "create", "spec": { "name": "one" } } }),
        ));
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        let body = json_of(&r);
        assert_eq!(body["plan"]["operation"]["spec"]["size"], "L");
        assert_eq!(body["plan"]["operation"]["spec"]["work_disk_gb"], 321);
        create(&mut a, "existing")?;
        // the fleet is now at its cap of 1: another create is refused at plan time
        let refused = a.handle(&req(
            "POST",
            "/v1/plans",
            json!({ "operation": { "op": "create", "spec": { "name": "two" } } }),
        ));
        assert_eq!(refused.status, 422);
        assert_eq!(json_of(&refused)["code"], "refused");
        assert!(json_of(&refused)["error"]
            .as_str()
            .is_some_and(|m| m.contains("cap is 1")));
        // pausing is never blocked
        let pause = a.handle(&req(
            "POST",
            "/v1/plans",
            json!({ "operation": { "op": "pause", "name": "existing" } }),
        ));
        assert_eq!(pause.status, 200);
        Ok(())
    }

    #[test]
    fn usage_rolls_up_by_box_label_and_run_and_is_flagged_simulated() -> TestResult {
        let dir = tempfile::tempdir()?;
        let mut a = app(dir.path());
        create_with(&mut a, "web", Size::M, &[("project", "shop")])?;
        create_with(&mut a, "api", Size::M, &[("project", "shop")])?;
        create_with(&mut a, "solo", Size::M, &[])?;
        for range in ["5s", "1m", "1h"] {
            let r = get(&mut a, &format!("/v1/usage?range={range}"));
            assert_eq!(r.status, 200);
            let v = json_of(&r);
            assert_eq!(v["source"], "simulated");
            assert_eq!(v["boxes"].as_array().map(Vec::len), Some(3));
            let points = v["boxes"][0]["points"].as_array().map_or(0, Vec::len);
            assert!((100..=200).contains(&points), "{range}: {points}");
            let groups = v["by_label"]["groups"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            assert_eq!(groups.len(), 2);
            assert!(groups
                .iter()
                .any(|g| g["value"] == "shop" && g["boxes"].as_array().map(Vec::len) == Some(2)));
            assert!(groups.iter().any(|g| g["value"] == "(none)"));
            assert!(v["by_run"].as_array().is_some_and(|r| !r.is_empty()));
            assert_eq!(v["fleet"]["cost_month_est_usd"], Value::Null);
        }
        assert_eq!(get(&mut a, "/v1/usage?range=1d").status, 400);
        Ok(())
    }

    #[test]
    fn usage_costs_appear_only_from_entered_prices() -> TestResult {
        let dir = tempfile::tempdir()?;
        let mut s = Settings::default();
        s.budget.size_prices_usd.insert("M".into(), 150.0);
        let mut a = app(dir.path()).with_settings(s, None);
        create(&mut a, "dev")?;
        let v = json_of(&get(&mut a, "/v1/usage"));
        assert_eq!(v["boxes"][0]["cost_month_est_usd"], 150.0);
        assert_eq!(v["fleet"]["cost_month_est_usd"], 150.0);
        Ok(())
    }

    #[test]
    fn suggestions_find_the_light_and_idle_boxes_and_never_apply_anything() -> TestResult {
        let dir = tempfile::tempdir()?;
        let mut s = Settings::default();
        s.budget.size_prices_usd.insert("M".into(), 200.0);
        s.budget.size_prices_usd.insert("S".into(), 100.0);
        let mut a = app(dir.path()).with_settings(s, None);
        create_with(&mut a, "light", Size::M, &[("sim_profile", "light")])?;
        create_with(&mut a, "idle", Size::M, &[("sim_profile", "idle")])?;
        create_with(&mut a, "busy", Size::M, &[])?;
        let r = get(&mut a, "/v1/suggestions");
        assert_eq!(r.status, 200);
        let v = json_of(&r);
        let items = v["items"].as_array().cloned().unwrap_or_default();
        let by = |n: &str| items.iter().find(|i| i["suggestion"]["box_name"] == n);
        let light = by("light").ok_or("no suggestion for the light box")?;
        assert_eq!(light["suggestion"]["advice"]["kind"], "downsize");
        assert_eq!(light["suggestion"]["advice"]["to"], "S");
        assert_eq!(light["suggestion"]["saving_month_usd"], 100.0);
        assert_eq!(light["operation"]["op"], "resize");
        let idle = by("idle").ok_or("no suggestion for the idle box")?;
        assert_eq!(idle["suggestion"]["advice"]["kind"], "auto_pause");
        assert_eq!(idle["operation"]["op"], "pause");
        assert!(by("busy").is_none());
        // nothing changed
        assert_eq!(
            json_of(&get(&mut a, "/v1/boxes/light"))["spec"]["size"],
            "M"
        );
        assert_eq!(json_of(&get(&mut a, "/v1/boxes/idle"))["state"], "running");
        Ok(())
    }

    #[test]
    fn an_upgrade_plans_from_latest_names_the_image_and_reports_its_checkpoint() -> TestResult {
        let dir = tempfile::tempdir()?;
        let mut a = app(dir.path());
        create(&mut a, "dev")?;
        let info = json_of(&get(&mut a, "/v1/boxes/dev/image"));
        assert_eq!(info["current"], Value::Null);
        assert_eq!(info["latest"]["id"], ozbox_provider_fake::LATEST_IMAGE);
        assert_eq!(info["latest"]["signature_verified"], false);
        assert_eq!(
            info["upgrade_available"],
            Value::Null,
            "unknown current image"
        );
        // `latest` is resolved into the plan, never carried in it
        let p = plan_for(
            &mut a,
            json!({"op": "upgrade", "name": "dev", "image": "latest"}),
        );
        assert_eq!(
            p["plan"]["operation"]["image"],
            ozbox_provider_fake::LATEST_IMAGE
        );
        assert_eq!(p["max_risk"], "medium");
        assert_eq!(p["needs_passkey"], false);
        let body = json!({ "plan_id": p["plan_id"], "plan": p["plan"] });
        // the box is first made ready on a thread of its own: the first answers are `quiescing`
        let r = apply_wait(&mut a, body);
        let done = finished(&mut a, &r);
        assert_eq!(done["applied"], true);
        assert_eq!(done["result"]["state"], "running");
        assert_eq!(
            done["result"]["spec"]["image"],
            ozbox_provider_fake::LATEST_IMAGE
        );
        assert_eq!(done["upgrade"]["checkpoint"]["outcome"], "done");
        // the box answers its self-test afterwards, which is how the dashboard follows up
        assert_eq!(get(&mut a, "/v1/boxes/dev/selftest").status, 200);
        let info = json_of(&get(&mut a, "/v1/boxes/dev/image"));
        assert_eq!(info["upgrade_available"], false);
        // and the same again is nothing to do
        let again = plan_for(
            &mut a,
            json!({"op": "upgrade", "name": "dev", "image": "latest"}),
        );
        assert_eq!(again["noop"], true);
        Ok(())
    }

    #[test]
    fn later_asks_for_a_plan_whose_box_was_made_ready_are_not_refused_for_its_age() -> TestResult {
        let dir = tempfile::tempdir()?;
        let mut a = app(dir.path());
        create(&mut a, "dev")?;
        let p = plan_for(
            &mut a,
            json!({"op": "upgrade", "name": "dev", "image": "latest"}),
        );
        let body = json!({ "plan_id": p["plan_id"], "plan": p["plan"] });
        // the first ask passes every check and starts getting the box ready
        let first = a.handle(&req("POST", "/v1/apply", body.clone()));
        assert_eq!(
            first.status,
            202,
            "{}",
            String::from_utf8_lossy(&first.body)
        );
        // the plan's time to live runs out while the box is getting ready (the runs may already have ended by now)
        a.plan_ttl = Duration::ZERO;
        let r = apply_wait(&mut a, body);
        // the change itself then runs as a job, which is where its answer is
        let done = finished(&mut a, &r);
        assert_eq!(done["applied"], true);
        Ok(())
    }

    #[test]
    fn an_unsigned_image_is_refused_in_the_plan_unless_the_request_allows_it() -> TestResult {
        let dir = tempfile::tempdir()?;
        let mut a = app(dir.path());
        create(&mut a, "dev")?;
        ozbox_provider_fake::FakeBackend::new(dir.path()).mark_images_unsigned()?;
        let op = json!({"op": "upgrade", "name": "dev", "image": "latest"});
        let refused = a.handle(&req("POST", "/v1/plans", json!({ "operation": op })));
        assert_eq!(
            refused.status,
            409,
            "{}",
            String::from_utf8_lossy(&refused.body)
        );
        let body = json_of(&refused);
        assert_eq!(body["code"], "image_unverified");
        // The contract text still names the command's flag; the additive fields let a screen use its own words.
        assert!(body["message"]
            .as_str()
            .is_some_and(|m| m.contains("--allow-unverified-image")));
        assert!(body["signature_detail"].is_string(), "{body}");
        assert!(body["image"].is_string());
        // on request, the plan is issued and carries the warning
        let allowed = a.handle(&req(
            "POST",
            "/v1/plans",
            json!({ "operation": op, "allow_unverified_image": true }),
        ));
        assert_eq!(
            allowed.status,
            200,
            "{}",
            String::from_utf8_lossy(&allowed.body)
        );
        let notes = json_of(&allowed)["plan"]["notes"].to_string();
        assert!(
            notes.contains("WARNING") && notes.contains("--allow-unverified-image"),
            "{notes}"
        );
        Ok(())
    }

    #[test]
    fn upgrading_a_missing_box_or_posting_to_the_image_route_is_refused() -> TestResult {
        let dir = tempfile::tempdir()?;
        let mut a = app(dir.path());
        let r = a.handle(&req(
            "POST",
            "/v1/plans",
            json!({"operation": {"op": "upgrade", "name": "nope", "image": "latest"}}),
        ));
        assert_eq!(r.status, 404);
        assert_eq!(get(&mut a, "/v1/boxes/nope/image").status, 404);
        create(&mut a, "dev")?;
        assert_eq!(
            a.handle(&req("POST", "/v1/boxes/dev/image", Value::Null))
                .status,
            405
        );
        Ok(())
    }

    #[test]
    fn selftest_and_incidents_come_from_the_agent_with_the_failing_step() -> TestResult {
        let dir = tempfile::tempdir()?;
        let mut a = app(dir.path());
        create_with(&mut a, "ok", Size::M, &[])?;
        create_with(&mut a, "bad", Size::M, &[("sim_profile", "failing")])?;
        let ok = json_of(&get(&mut a, "/v1/boxes/ok/selftest"));
        assert_eq!(ok["source"], "simulated");
        assert_eq!(ok["result"]["ok"], true);
        let bad = json_of(&get(&mut a, "/v1/boxes/bad/selftest"));
        assert_eq!(bad["result"]["ok"], false);
        let failing: Vec<&Value> = bad["result"]["checks"]
            .as_array()
            .map(|c| c.iter().filter(|c| c["outcome"] == "fail").collect())
            .unwrap_or_default();
        assert_eq!(failing.len(), 1);
        assert_eq!(failing[0]["step"], "tunnels up");
        let inc = json_of(&get(&mut a, "/v1/boxes/bad/incidents"));
        assert_eq!(inc["incidents"].as_array().map(Vec::len), Some(2));
        assert_eq!(
            get(&mut a, "/v1/boxes/ok/incidents?since=nonsense").status,
            400
        );
        assert_eq!(get(&mut a, "/v1/boxes/nope/selftest").status, 404);
        // a paused box has no agent to ask
        let p = a.provider.plan(&Operation::Pause {
            name: BoxName::new("ok")?,
        })?;
        a.provider.apply(&p)?;
        assert_eq!(get(&mut a, "/v1/boxes/ok/selftest").status, 409);
        Ok(())
    }

    #[test]
    fn a_scripted_agent_can_report_unknown_and_unreachable() -> TestResult {
        let dir = tempfile::tempdir()?;
        let mut fake = agent::FakeAgent::default();
        fake.selftests.insert(
            "dev".into(),
            agent::SelfTest {
                ts_ms: 1,
                ok: true,
                all_verified: false,
                checks: vec![agent::Check {
                    name: "work disk encrypted".into(),
                    outcome: agent::Outcome::Unknown {
                        reason: "not visible".into(),
                    },
                }],
            },
        );
        let mut a = app(dir.path()).with_agent(Box::new(fake));
        create(&mut a, "dev")?;
        create(&mut a, "other")?;
        let v = json_of(&get(&mut a, "/v1/boxes/dev/selftest"));
        assert_eq!(v["result"]["all_verified"], false);
        assert_eq!(v["result"]["checks"][0]["outcome"], "unknown");
        assert_eq!(get(&mut a, "/v1/boxes/other/selftest").status, 502);
        Ok(())
    }

    #[test]
    fn real_providers_answer_501_for_selftest_and_incidents_with_the_reason() -> TestResult {
        let dir = tempfile::tempdir()?;
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7878);
        let mut a = App::new(
            Box::new(ozbox_provider_fake::open(dir.path())),
            false,
            addr,
            TOKEN.into(),
        );
        create(&mut a, "dev")?;
        for path in ["/v1/boxes/dev/selftest", "/v1/boxes/dev/incidents"] {
            let r = get(&mut a, path);
            assert_eq!(r.status, 501, "{path}");
        }
        // Usage and suggestions still answer, and say which boxes could not be reached and why.
        let u = json_of(&get(&mut a, "/v1/usage"));
        assert_eq!(u["boxes"], json!([]));
        assert_eq!(u["unreachable"][0]["name"], "dev");
        assert_eq!(get(&mut a, "/v1/suggestions").status, 200);
        let r = get(&mut a, "/v1/boxes/dev/selftest");
        assert_eq!(json_of(&r)["code"], "agent_unreachable");
        assert!(json_of(&r)["message"]
            .as_str()
            .is_some_and(|m| m.contains("SSH forwarding")));
        Ok(())
    }

    #[test]
    fn a_read_that_is_too_slow_is_reported_not_waited_for_and_not_dropped() {
        let reads: Vec<Box<dyn FnOnce() -> u32 + Send>> = vec![
            Box::new(|| 1),
            Box::new(|| {
                std::thread::sleep(Duration::from_millis(600));
                2
            }),
            Box::new(|| 3),
        ];
        let started = Instant::now();
        let out = read_within(reads, Duration::from_millis(100));
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "waited for the slow one"
        );
        assert!(matches!(out[0], Ok(1)));
        assert!(matches!(out[1], Err(ReadMiss::TimedOut(_))));
        assert!(matches!(out[2], Ok(3)));
    }

    #[test]
    fn a_read_that_panics_is_reported_as_failed() {
        let reads: Vec<Box<dyn FnOnce() -> u32 + Send>> =
            vec![Box::new(|| panic!("boom")), Box::new(|| 7)];
        let out = read_within(reads, Duration::from_secs(2));
        assert!(matches!(out[0], Err(ReadMiss::Failed)));
        assert!(matches!(out[1], Ok(7)));
    }

    #[test]
    fn suggestions_name_the_boxes_they_could_not_read_instead_of_saying_nothing() -> TestResult {
        let dir = tempfile::tempdir()?;
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7878);
        let mut a = App::new(
            Box::new(ozbox_provider_fake::open(dir.path())),
            false,
            addr,
            TOKEN.into(),
        );
        create(&mut a, "dev")?;
        let v = json_of(&get(&mut a, "/v1/suggestions"));
        assert_eq!(v["items"], json!([]));
        assert_eq!(v["unreachable"][0]["name"], "dev");
        assert!(v["unreachable"][0]["reason"]
            .as_str()
            .is_some_and(|r| !r.is_empty()));
        // on the demo provider every box is read: nothing is unreachable
        let dir = tempfile::tempdir()?;
        let mut demo = app(dir.path());
        create(&mut demo, "alpha")?;
        assert_eq!(
            json_of(&get(&mut demo, "/v1/suggestions"))["unreachable"],
            json!([])
        );
        Ok(())
    }

    #[test]
    fn behind_no_sign_in_activity_says_access_link_and_never_this_computer() -> TestResult {
        let dir = tempfile::tempdir()?;
        let mut a = app(dir.path());
        create(&mut a, "dev")?;
        plan_for(&mut a, json!({"op": "pause", "name": "dev"}));
        let v = json_of(&get(&mut a, "/v1/activity"));
        let entries = v["entries"].as_array().cloned().unwrap_or_default();
        assert!(!entries.is_empty());
        assert!(
            entries.iter().all(|e| e["actor"] == "access link"),
            "{entries:?}"
        );
        assert_eq!(v["since_start"], true);
        Ok(())
    }
}
