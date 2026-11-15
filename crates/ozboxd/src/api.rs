//! The local API: JSON over HTTP/1.1 on a Unix socket (default `/run/ozboxd.sock`, mode 0660). There is no network
//! listener anywhere in this crate (a test enforces it). The same messages move to gRPC + mTLS later.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use ozbox_core::MetricsSample;
use serde::Serialize;

use crate::checkpoint::CheckpointReport;
use crate::files::{FilesService, Input, Reply};
use crate::health::{IncidentKind, IncidentLog, PendingUpdates};
use crate::http::{self, Request, Response};
use crate::runs::{RunError, RunManager, RunRequest};
use crate::selftest::SelfTestResult;
use crate::store::{Step, Store};
use crate::timeutil::{parse_rfc3339, Clock};

/// Slow-changing facts the health endpoint reports; refreshed by the daemon.
#[derive(Debug, Clone, Default, Serialize)]
pub struct HealthInfo {
    pub restarts: u64,
    pub image_version: Option<String>,
    pub pending_updates: Option<PendingUpdates>,
    pub oom_kills: u64,
}

pub struct AppState {
    pub version: String,
    pub started_ms: u64,
    pub clock: Arc<dyn Clock>,
    pub latest: Mutex<Option<MetricsSample>>,
    pub store: Mutex<Store>,
    pub runs: Arc<Mutex<RunManager>>,
    pub selftest_last: Mutex<Option<SelfTestResult>>,
    pub selftest_fn: Box<dyn Fn() -> SelfTestResult + Send + Sync>,
    pub incidents: Mutex<IncidentLog>,
    /// The argument is `true` for a run's pause (`?for_run=1`): the local branch is written and never pushed unless the box
    /// was set up to push on stop.
    pub checkpoint_fn: Box<dyn Fn(bool) -> CheckpointReport + Send + Sync>,
    /// Serialises checkpoints so two requests never snapshot the same repos at once.
    pub checkpoint_lock: Mutex<()>,
    pub health: Mutex<HealthInfo>,
}

fn valid_run_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// A poisoned lock still holds consistent data for our purposes; keep serving rather than crash.
pub fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

#[derive(Serialize)]
struct Health<'a> {
    status: &'static str,
    version: &'a str,
    uptime_s: u64,
    #[serde(flatten)]
    info: HealthInfo,
}

impl AppState {
    /// `/v1/backup/...`: restic backups of `/work`, started on request (see `backup_service`).
    fn backup(&self, req: &Request) -> Response {
        let Some(svc) = crate::backup_service::global() else {
            return Response::json(
                501,
                &serde_json::json!({ "error": "this daemon was started without backups", "code": "backup_unavailable" }),
            );
        };
        let sub = req
            .path
            .trim_end_matches('/')
            .trim_start_matches("/v1/backup");
        let body: serde_json::Value = if req.body.is_empty() {
            serde_json::Value::Null
        } else {
            match serde_json::from_slice(&req.body) {
                Ok(v) => v,
                Err(_) => return Response::error(400, "the body is not valid JSON"),
            }
        };
        let now = self.clock.now_ms();
        let provision = |r: &crate::backup_root::Request| {
            crate::backup_root::FileBridge::new(crate::backup_root::ROOT_DIR).send(r)
        };
        let (status, value) = svc.handle(&req.method, sub, &body, &provision, now);
        Response::json(status, &value)
    }

    pub fn route(&self, req: &Request) -> Response {
        let path = req.path.trim_end_matches('/');
        let method = req.method.as_str();
        let not_allowed = || Response::error(405, "method not allowed");
        match path {
            "/v1/health" => match method {
                "GET" => self.health(),
                _ => not_allowed(),
            },
            "/v1/metrics/now" => match method {
                "GET" => match lock(&self.latest).clone() {
                    Some(s) => Response::json(200, &s),
                    None => Response::error(503, "no sample yet"),
                },
                _ => not_allowed(),
            },
            "/v1/metrics" => match method {
                "GET" => self.metrics(req),
                _ => not_allowed(),
            },
            "/v1/runs" => match method {
                "GET" => {
                    Response::json(200, &serde_json::json!({ "runs": lock(&self.runs).list() }))
                }
                "POST" => self.start_run(req),
                _ => not_allowed(),
            },
            "/v1/selftest" => match method {
                "GET" => Response::json(
                    200,
                    &serde_json::json!({ "result": *lock(&self.selftest_last) }),
                ),
                "POST" => {
                    let r = (self.selftest_fn)();
                    *lock(&self.selftest_last) = Some(r.clone());
                    Response::json(200, &r)
                }
                _ => not_allowed(),
            },
            "/v1/incidents" => match method {
                "GET" => {
                    let since = match req.query.get("since") {
                        None => 0,
                        Some(s) => match parse_rfc3339(s) {
                            Some(ms) => ms,
                            None => return Response::error(400, "since must be an RFC 3339 time"),
                        },
                    };
                    Response::json(
                        200,
                        &serde_json::json!({ "incidents": lock(&self.incidents).since(since) }),
                    )
                }
                _ => not_allowed(),
            },
            "/v1/terminal/audit" => match method {
                #[cfg(unix)]
                "GET" => match crate::terminal::global() {
                    Some(t) => {
                        Response::json(200, &serde_json::json!({ "events": t.audit().recent(100) }))
                    }
                    None => Response::json(200, &serde_json::json!({ "events": [] })),
                },
                _ => not_allowed(),
            },
            "/v1/checkpoint" => match method {
                "POST" => self.checkpoint(req.query.contains_key("for_run")),
                _ => not_allowed(),
            },
            "/v1/quiesce" => match crate::quiesce::global() {
                Some(q) => q.route(method, &req.body),
                None => Response::json(
                    503,
                    &serde_json::json!({
                        "code": "quiesce_unavailable",
                        "error": "this daemon was started without the quiesce service"
                    }),
                ),
            },
            p if p == "/v1/backup" || p.starts_with("/v1/backup/") => self.backup(req),
            p if p == "/v1/tools" || p.starts_with("/v1/tools/") => match crate::tools::global() {
                Some(t) => t.route(req),
                None => Response::json(
                    503,
                    &serde_json::json!({
                        "code": "tools_unavailable",
                        "message": "the tool installer is not running on this box",
                        "error": "the tool installer is not running on this box"
                    }),
                ),
            },
            p if crate::skills::handles(p) => match crate::skills::global() {
                Some(svc) => {
                    let (status, v) =
                        svc.route(method, &p["/v1/skills".len()..], &req.body, req.dashboard);
                    Response::json(status, &v)
                }
                None => Response::json(
                    503,
                    &serde_json::json!({
                        "code": "skills_unavailable",
                        "message": "skills on the box's disk are not available on this box",
                        "error": "skills on the box's disk are not available on this box"
                    }),
                ),
            },
            p if p == "/v1/local-ai" || p.starts_with("/v1/local-ai/") => {
                match crate::local_ai::global() {
                    Some(svc) => {
                        let (status, v) =
                            svc.route(method, &p["/v1/local-ai".len()..], &req.query, &req.body);
                        Response::json(status, &v)
                    }
                    None => Response::json(
                        503,
                        &serde_json::json!({
                            "code": "local_ai_unavailable",
                            "message": "local models are not available on this box",
                            "error": "local models are not available on this box"
                        }),
                    ),
                }
            }
            p if p == "/v1/sessions"
                || p == "/v1/processes"
                || p.starts_with("/v1/sessions/")
                || p.starts_with("/v1/processes/") =>
            {
                #[cfg(unix)]
                {
                    crate::procs::route(crate::procs::global(), method, p)
                }
                #[cfg(not(unix))]
                {
                    Response::error(501, "not available on this system")
                }
            }
            p if p == "/v1/agent-events" || p.starts_with("/v1/agent-events/") => {
                self.agent_events(req)
            }
            p if p == "/v1/agent-sessions" || p.starts_with("/v1/agent-sessions/") => {
                #[cfg(unix)]
                {
                    static SVC: std::sync::OnceLock<crate::agent_sessions::SessionService> =
                        std::sync::OnceLock::new();
                    let svc = SVC.get_or_init(|| {
                        crate::agent_sessions::SessionService::new(std::sync::Arc::new(
                            ozbox_core::SystemRunner,
                        ))
                    });
                    let (status, v) = crate::agent_sessions::route(
                        svc,
                        crate::agent_events::global(),
                        method,
                        p,
                        &req.query,
                        &req.body,
                    );
                    Response::json(status, &v)
                }
                #[cfg(not(unix))]
                {
                    Response::error(501, "not available on this system")
                }
            }
            p if p.starts_with("/v1/runs/") => {
                let rest = &p["/v1/runs/".len()..];
                match (method, rest.split_once('/')) {
                    ("GET", Some((id, "log"))) => self.run_log(id, req),
                    ("POST", Some((id, "stdin"))) => self.run_stdin(id, req),
                    ("DELETE", None) => self.stop_run(rest, req),
                    _ => not_allowed(),
                }
            }
            _ => Response::error(404, "not found"),
        }
    }

    fn health(&self) -> Response {
        let now = self.clock.now_ms();
        let info = lock(&self.health).clone();
        Response::json(
            200,
            &Health {
                status: "ok",
                version: &self.version,
                uptime_s: now.saturating_sub(self.started_ms) / 1000,
                info,
            },
        )
    }

    fn metrics(&self, req: &Request) -> Response {
        let Some(since) = req.query.get("since").and_then(|s| parse_rfc3339(s)) else {
            return Response::error(400, "since must be an RFC 3339 time");
        };
        let until = match req.query.get("until") {
            None => u64::MAX,
            Some(u) => match parse_rfc3339(u) {
                Some(v) => v,
                None => return Response::error(400, "until must be an RFC 3339 time"),
            },
        };
        let step_text = req.query.get("step").map(String::as_str).unwrap_or("1m");
        let Some(step) = Step::parse(step_text) else {
            return Response::error(400, "step must be 5s, 1m or 1h");
        };
        let points = lock(&self.store).query(since, until, step);
        Response::json(
            200,
            &serde_json::json!({ "step": step_text, "points": points }),
        )
    }

    /// A controlled run answers only the caller that started it: anything else that reaches this socket (the box user's
    /// own shell among them) is refused its input, its output and stopping it.
    fn refuse_uncontrolled(&self, id: &str, req: &Request) -> Option<Response> {
        if lock(&self.runs).authorized(id, req.capability.as_deref()) {
            None
        } else {
            Some(Response::json(
                403,
                &serde_json::json!({ "error": "this run answers only the caller that started it", "code": "run_controlled" }),
            ))
        }
    }

    fn start_run(&self, req: &Request) -> Response {
        let Ok(rr) = serde_json::from_slice::<RunRequest>(&req.body) else {
            return Response::error(400, "invalid JSON body");
        };
        let controlled = rr.require_capability;
        let result = if controlled {
            lock(&self.runs)
                .start_controlled(rr)
                .map(|(id, state, cap)| (id, state, Some(cap)))
        } else {
            lock(&self.runs)
                .start(rr)
                .map(|(id, state)| (id, state, None))
        };
        match result {
            // the capability is in this answer and nowhere else: the daemon keeps only its hash
            Ok((id, state, Some(cap))) => Response::json(
                201,
                &serde_json::json!({ "id": id, "state": state, "capability": cap }),
            ),
            Ok((id, state, None)) => {
                Response::json(201, &serde_json::json!({ "id": id, "state": state }))
            }
            Err(e) => {
                let status = match e {
                    RunError::Invalid(_) => 400,
                    RunError::QueueFull => 429,
                    RunError::TooLarge => 422,
                    RunError::NotFound => 404,
                    RunError::Start(_) => 500,
                    RunError::Input(_) => 409,
                };
                if matches!(e, RunError::Start(_)) {
                    lock(&self.incidents).record(
                        self.clock.now_ms(),
                        IncidentKind::RunStartFailed,
                        e.to_string(),
                    );
                }
                Response::error(status, &e.to_string())
            }
        }
    }

    /// `GET /v1/runs/<id>/log?from=<byte>`: the run's output from that byte, in whole lines (see `RunManager::read_log`).
    fn run_log(&self, id: &str, req: &Request) -> Response {
        if !valid_run_id(id) {
            return Response::error(404, "no such run");
        }
        if let Some(r) = self.refuse_uncontrolled(id, req) {
            return r;
        }
        let from = match req.query.get("from") {
            None => 0,
            Some(f) => match f.parse::<u64>() {
                Ok(n) => n,
                Err(_) => return Response::error(400, "from must be a byte offset"),
            },
        };
        match lock(&self.runs).read_log(id, from) {
            Ok(c) => Response::json(200, &serde_json::json!({ "id": id, "log": c })),
            Err(RunError::NotFound) => Response::error(404, "no such run"),
            Err(e) => Response::error(500, &e.to_string()),
        }
    }

    /// `/v1/agent-events...`: what coding agents report (see `agent_events`).
    fn agent_events(&self, req: &Request) -> Response {
        let now = self.clock.now_ms();
        let path = req.path.trim_end_matches('/');
        let mut log = crate::agent_events::global()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        match (req.method.as_str(), path) {
            ("GET", "/v1/agent-events") => {
                let since = req
                    .query
                    .get("since")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                Response::json(200, &log.snapshot(since, now))
            }
            ("POST", "/v1/agent-events") => {
                #[derive(serde::Deserialize)]
                struct B {
                    engine: String,
                    #[serde(default)]
                    payload: serde_json::Value,
                    #[serde(default)]
                    cwd: String,
                    #[serde(default)]
                    pane: String,
                }
                let Ok(b) = serde_json::from_slice::<B>(&req.body) else {
                    return Response::error(400, "invalid JSON body");
                };
                match log.report_in_pane(&b.engine, &b.payload, &b.cwd, &b.pane, now) {
                    Ok((seq, permission)) => Response::json(
                        200,
                        &serde_json::json!({ "seq": seq, "permission": permission }),
                    ),
                    Err(m) => Response::error(400, m),
                }
            }
            (m, p) if p.starts_with("/v1/agent-events/permission/") => {
                let id = &p["/v1/agent-events/permission/".len()..];
                match m {
                    "GET" => match log.permission(id, now) {
                        Some(perm) => Response::json(200, &perm),
                        None => Response::error(404, "no such request"),
                    },
                    "POST" => {
                        #[derive(serde::Deserialize)]
                        struct D {
                            decision: String,
                        }
                        let Ok(d) = serde_json::from_slice::<D>(&req.body) else {
                            return Response::error(400, "invalid JSON body");
                        };
                        let allow = match d.decision.as_str() {
                            "allow" => true,
                            "deny" => false,
                            _ => return Response::error(400, "decision must be allow or deny"),
                        };
                        match log.decide(id, allow, now) {
                            Ok(state) => Response::json(
                                200,
                                &serde_json::json!({ "id": id, "state": state }),
                            ),
                            Err(m) => Response::error(409, m),
                        }
                    }
                    _ => Response::error(405, "method not allowed"),
                }
            }
            _ => Response::error(404, "not found"),
        }
    }

    /// `POST /v1/runs/<id>/stdin` with `{"text": "...", "close": false}`: append to a kept-open run's standard input.
    fn run_stdin(&self, id: &str, req: &Request) -> Response {
        if !valid_run_id(id) {
            return Response::error(404, "no such run");
        }
        if let Some(r) = self.refuse_uncontrolled(id, req) {
            return r;
        }
        #[derive(serde::Deserialize)]
        struct Body {
            #[serde(default)]
            text: String,
            #[serde(default)]
            close: bool,
        }
        let Ok(b) = serde_json::from_slice::<Body>(&req.body) else {
            return Response::error(400, "invalid JSON body");
        };
        // The text is a person's message: never logged, never echoed back.
        match lock(&self.runs).send_stdin(id, &b.text, b.close) {
            Ok(()) => Response::json(
                200,
                &serde_json::json!({ "id": id, "accepted": b.text.len() }),
            ),
            Err(RunError::NotFound) => Response::error(404, "no such run"),
            Err(RunError::Invalid(m)) => Response::error(400, &m),
            Err(e) => Response::error(409, &e.to_string()),
        }
    }

    fn stop_run(&self, id: &str, req: &Request) -> Response {
        if !valid_run_id(id) {
            return Response::error(404, "no such run");
        }
        if let Some(r) = self.refuse_uncontrolled(id, req) {
            return r;
        }
        let mut runs = lock(&self.runs);
        match runs.stop(id) {
            Ok(state) => {
                runs.tick();
                Response::json(200, &serde_json::json!({ "id": id, "state": state }))
            }
            Err(e) => Response::error(404, &e.to_string()),
        }
    }

    fn checkpoint(&self, for_run: bool) -> Response {
        let _one_at_a_time = lock(&self.checkpoint_lock);
        let report = (self.checkpoint_fn)(for_run);
        if !report.errors.is_empty() {
            lock(&self.incidents).record(
                self.clock.now_ms(),
                IncidentKind::CheckpointFailed,
                format!("{} repo(s) failed", report.errors.len()),
            );
        }
        Response::json(200, &report)
    }
}

// ---- the Unix socket server ------------------------------------------------------------------------------------

#[cfg(unix)]
pub use unix::{bind_socket, peer_uid, serve, serve_supervisor, serve_with, SupervisorGate};

#[cfg(unix)]
mod unix {
    use super::*;
    use std::io;
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::Path;
    use std::time::{Duration, Instant};

    pub const MAX_CONNECTIONS: usize = 16;
    const REQUEST_DEADLINE: Duration = Duration::from_secs(10);

    /// Bind the socket (replacing a stale socket file, never any other kind of file) and set mode 0660.
    pub fn bind_socket(path: &Path, mode: u32) -> io::Result<UnixListener> {
        match std::fs::symlink_metadata(path) {
            Ok(md) if md.file_type().is_socket() => std::fs::remove_file(path)?,
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "the socket path exists and is not a socket",
                ))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let l = UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
        Ok(l)
    }

    /// A file transfer may take minutes; its sockets wait longer than a JSON request, and a request body may be large.
    const TRANSFER_IDLE: Duration = Duration::from_secs(60);

    fn handle_files(mut stream: UnixStream, head: http::Head, files: &FilesService) -> u16 {
        use std::io::Read;
        let head_only = head.method == "HEAD";
        let method = if head_only {
            "GET"
        } else {
            head.method.as_str()
        };
        let reply = if FilesService::wants_stream_body(method, &head.path) {
            let len = head.content_length as u64;
            let mut body = std::io::Cursor::new(head.early.clone()).chain(&mut stream);
            if !head.length_given {
                Reply::error(
                    411,
                    "length_required",
                    "A body with a Content-Length is required.",
                )
            } else {
                files.call(
                    method,
                    &head.path,
                    &head.query,
                    Input::Stream {
                        reader: &mut body,
                        len,
                    },
                )
            }
        } else if head.content_length > http::MAX_BODY {
            Reply::error(413, "too_large", "request body too large")
        } else {
            let mut body = head.early.clone();
            let deadline = Instant::now() + REQUEST_DEADLINE;
            while body.len() < head.content_length && Instant::now() < deadline {
                let mut chunk = [0u8; 4096];
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => body.extend_from_slice(&chunk[..n]),
                }
            }
            body.truncate(head.content_length);
            files.call(method, &head.path, &head.query, Input::Bytes(&body))
        };
        let status = reply.status;
        let _ = http::write_files_reply(&mut stream, reply, head_only);
        linger_close(&mut stream);
        status
    }

    /// The second socket's gate (ADR 0040, decision 3): who may connect, and what they may ask for. Both checks run
    /// on the connection thread before anything else is read or done, and neither touches the box socket's path.
    type PeerUid = Box<dyn Fn(&UnixStream) -> Option<u32> + Send + Sync>;
    type Cached = Mutex<Option<(Instant, Option<u32>)>>;

    pub struct SupervisorGate {
        peer_uid: PeerUid,
        user_uid: Box<dyn Fn() -> Option<u32> + Send + Sync>,
        audit: Box<dyn Fn(&str) + Send + Sync>,
        cached: Cached,
        /// Refusals are audited at most once per [`REFUSAL_EVERY`] per kind, with the count held back: a connection that
        /// is refused costs one line, not one line per attempt, so a flood cannot push the real lines out of the journal.
        refused: Mutex<[(Option<Instant>, u64, String); 2]>,
        every: Duration,
    }

    const REFUSAL_EVERY: Duration = Duration::from_secs(10);

    /// How long a resolved supervisor uid is kept before the user database is read again.
    const UID_TTL: Duration = Duration::from_secs(30);

    impl SupervisorGate {
        pub fn new(
            peer_uid: impl Fn(&UnixStream) -> Option<u32> + Send + Sync + 'static,
            user_uid: impl Fn() -> Option<u32> + Send + Sync + 'static,
            audit: impl Fn(&str) + Send + Sync + 'static,
        ) -> Self {
            Self {
                peer_uid: Box::new(peer_uid),
                user_uid: Box::new(user_uid),
                audit: Box::new(audit),
                cached: Mutex::new(None),
                refused: Mutex::new([(None, 0, String::new()), (None, 0, String::new())]),
                every: REFUSAL_EVERY,
            }
        }

        /// A shorter (or longer) refusal interval than the default ten seconds.
        pub fn with_refusal_interval(mut self, every: Duration) -> Self {
            self.every = every;
            self
        }

        /// One audit line for an allowed request, after its outcome.
        fn record(&self, line: &str) {
            (self.audit)(line);
        }

        /// The held-back count, on a line of its own with no uid: it covers refusals from any number of callers, so it is never
        /// attributed to the last one (G1 F9). The refusal line before it names the first caller of the interval.
        fn held_line(kind: usize, held: u64) -> String {
            let what = if kind == 0 { "peer" } else { "route" };
            format!("via=supervisor refused={what} callers=not_listed also_refused={held}")
        }

        /// A refusal (`kind` 0 = peer, 1 = route): the first in each interval is written, the rest are counted into the next
        /// line, or written by [`SupervisorGate::flush_due`] when the flood simply stops (G1 N7).
        fn record_refusal(&self, kind: usize, line: &str) {
            let mut r = lock(&self.refused);
            let slot = &mut r[kind.min(1)];
            let due = slot.0.is_none_or(|t| t.elapsed() >= self.every);
            if due {
                let held = slot.1;
                *slot = (Some(Instant::now()), 0, String::new());
                drop(r);
                (self.audit)(line);
                if held > 0 {
                    (self.audit)(&Self::held_line(kind, held));
                }
            } else {
                slot.1 += 1;
            }
        }

        /// Write the count of refusals held back from an interval that has ended, so the last burst of a flood is never lost
        /// because nothing else was refused afterwards. Called on a timer by the daemon.
        pub fn flush_due(&self) {
            let mut lines = Vec::new();
            {
                let mut r = lock(&self.refused);
                for (kind, slot) in r.iter_mut().enumerate() {
                    if slot.1 > 0 && slot.0.is_none_or(|t| t.elapsed() >= self.every) {
                        lines.push(Self::held_line(kind, slot.1));
                        slot.1 = 0;
                        slot.0 = Some(Instant::now());
                    }
                }
            }
            for l in lines {
                (self.audit)(&l);
            }
        }

        fn supervisor_uid(&self) -> Option<u32> {
            let mut c = lock(&self.cached);
            if let Some((at, v)) = *c {
                if v.is_some() && at.elapsed() < UID_TTL {
                    return v;
                }
            }
            let v = (self.user_uid)();
            *c = Some((Instant::now(), v));
            v
        }

        fn admits(&self, stream: &UnixStream) -> Result<(), Option<u32>> {
            let peer = (self.peer_uid)(stream);
            if ozbox_core::daemon_scope::peer_is_supervisor(peer, self.supervisor_uid()) {
                Ok(())
            } else {
                Err(peer)
            }
        }
    }

    /// The kernel's word for who is on the other end (`SO_PEERCRED`). Only Linux can say; elsewhere nobody is admitted.
    #[cfg(target_os = "linux")]
    pub fn peer_uid(s: &UnixStream) -> Option<u32> {
        rustix::net::sockopt::socket_peercred(s)
            .ok()
            .map(|c| c.uid.as_raw())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn peer_uid(_s: &UnixStream) -> Option<u32> {
        None
    }

    fn handle(
        mut stream: UnixStream,
        state: &AppState,
        files: Option<&FilesService>,
        gate: Option<&SupervisorGate>,
    ) {
        let _ = stream.set_nonblocking(false);
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
        if let Some(g) = gate {
            if let Err(peer) = g.admits(&stream) {
                g.record_refusal(
                    0,
                    &format!(
                        "via=supervisor refused=peer uid={}",
                        peer.map_or_else(|| "unknown".to_string(), |u| u.to_string())
                    ),
                );
                let _ = http::write_response(
                    &mut stream,
                    &Response::json(
                        403,
                        &serde_json::json!({ "error": "this socket is the dashboard's alone", "code": "peer_not_allowed" }),
                    ),
                );
                linger_close(&mut stream);
                return;
            }
        }
        let head = match http::read_head(&mut stream, Instant::now() + REQUEST_DEADLINE) {
            Ok(h) => h,
            Err(http::HttpError::Closed) => return,
            Err(e) => {
                let _ =
                    http::write_response(&mut stream, &Response::error(e.status(), &e.to_string()));
                linger_close(&mut stream);
                return;
            }
        };
        let mut route = None;
        if let Some(g) = gate {
            match ozbox_core::daemon_scope::allowed(&head.method, &head.path) {
                Some(r) => route = Some(r),
                None => {
                    g.record_refusal(
                        1,
                        &format!("via=supervisor refused=route method={}", head.method),
                    );
                    let _ = http::write_response(
                        &mut stream,
                        &Response::json(
                            403,
                            &serde_json::json!({ "error": "the dashboard's socket does not offer that", "code": "route_not_allowed" }),
                        ),
                    );
                    linger_close(&mut stream);
                    return;
                }
            }
        }
        // A permission request is answered by a person, never by a process on the box: the coding agent's hook posts the
        // request and polls for the answer, and anything that can reach this API could otherwise approve its own. No socket
        // of this daemon takes the answer; the dashboard's table does not list it, and the box socket refuses it here.
        if head.method == "POST" && head.path.starts_with("/v1/agent-events/permission/") {
            let _ = http::write_response(
                &mut stream,
                &Response::json(
                    403,
                    &serde_json::json!({ "error": "a permission request is not answered through this socket", "code": "decision_not_here" }),
                ),
            );
            linger_close(&mut stream);
            return;
        }
        // Putting a skill on the box's disk, or taking one away, is the dashboard's act, after a person approved the exact
        // files: it is on the dashboard socket's route table only. Every process of the box user can open this socket, and a
        // caller here could write whatever hash and files it likes, so this socket answers `GET` (what is on the disk) and
        // nothing that writes.
        if gate.is_none() && crate::skills::handles(&head.path) && head.method != "GET" {
            let _ = http::write_response(
                &mut stream,
                &Response::json(
                    403,
                    &serde_json::json!({ "error": "a skill is put on this box through the dashboard's socket, not this one", "message": "a skill is put on this box through the dashboard's socket, not this one", "code": "skills_write_not_here" }),
                ),
            );
            linger_close(&mut stream);
            return;
        }
        let path_for_audit = head.path.clone();
        let audit = |status: String, id: Option<String>| {
            if let (Some(g), Some(r)) = (gate, route) {
                let id = id.map_or_else(String::new, |i| format!(" id={i}"));
                g.record(&format!(
                    "via=supervisor route={} method={} status={status}{id}",
                    r.name, r.method
                ));
            }
        };
        if crate::terminal::is_terminal_path(&head.path) {
            let _ = stream.set_read_timeout(None);
            audit("stream".into(), None);
            match crate::terminal::global() {
                Some(t) => t.handle(stream, &head),
                None => {
                    let _ = http::write_response(
                        &mut stream,
                        &Response::error(404, "the terminal is not running on this box"),
                    );
                }
            }
            return;
        }
        if FilesService::handles(&head.path) {
            let _ = stream.set_read_timeout(Some(TRANSFER_IDLE));
            let _ = stream.set_write_timeout(Some(TRANSFER_IDLE));
            match files {
                Some(f) => {
                    let status = handle_files(stream, head, f);
                    audit(status.to_string(), None);
                }
                None => {
                    audit("404".into(), None);
                    let _ = http::write_response(
                        &mut stream,
                        &Response::error(404, "the file API is not enabled on this box"),
                    );
                }
            }
            return;
        }
        let resp =
            if head.content_length > http::body_limit(&head.method, &head.path, gate.is_some()) {
                Response::error(413, "request body too large")
            } else {
                let mut body = head.early.clone();
                let deadline = Instant::now() + REQUEST_DEADLINE;
                let mut bad = None;
                while body.len() < head.content_length {
                    let mut chunk = [0u8; 2048];
                    if Instant::now() >= deadline {
                        bad = Some(Response::error(408, "request timed out"));
                        break;
                    }
                    match std::io::Read::read(&mut stream, &mut chunk) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => body.extend_from_slice(&chunk[..n]),
                    }
                }
                body.truncate(head.content_length);
                bad.unwrap_or_else(|| {
                    state.route(&Request {
                        method: head.method,
                        path: head.path,
                        query: head.query,
                        body,
                        capability: head.capability,
                        dashboard: gate.is_some(),
                    })
                })
            };
        let id = route.and_then(|r| audit_id(r, &path_for_audit, &resp));
        audit(resp.status.to_string(), id);
        let _ = http::write_response(&mut stream, &resp);
        linger_close(&mut stream);
    }

    /// A short id for the audit line, where the route has one: the `{}` segment of its path (a run, session or process id),
    /// or the id of a run just started. Only a plain id is written (never a name that could carry anything else).
    fn audit_id(
        r: &ozbox_core::daemon_scope::Route,
        path: &str,
        resp: &Response,
    ) -> Option<String> {
        let plain = |s: &str| {
            (1..=64).contains(&s.len())
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
        };
        if r.name == "run_start" {
            let v: serde_json::Value = serde_json::from_slice(&resp.body).ok()?;
            let id = v.get("id")?.as_str()?;
            return plain(id).then(|| id.to_string());
        }
        let at = r.path.split('/').position(|seg| seg == "{}")?;
        let id = path.split('/').nth(at)?;
        plain(id).then(|| id.to_string())
    }

    /// Close gracefully. If the client sent more than we read (a refused, oversized request), closing a socket
    /// with unread data makes Linux reset the connection, and the client loses the response it was sent.
    /// So: finish writing, then discard what is left (bounded in bytes and time) before dropping the socket.
    fn linger_close(stream: &mut UnixStream) {
        use std::io::Read;
        const MAX_DRAIN: usize = 1 << 20;
        let _ = stream.shutdown(std::net::Shutdown::Write);
        let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut buf = [0u8; 8192];
        let mut drained = 0usize;
        while drained < MAX_DRAIN && Instant::now() < deadline {
            match stream.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => drained += n,
            }
        }
    }

    /// Accept connections until `shutdown` is set: a thread per connection, at most [`MAX_CONNECTIONS`] at once.
    pub fn serve(
        listener: UnixListener,
        state: Arc<AppState>,
        shutdown: Arc<AtomicBool>,
    ) -> io::Result<()> {
        serve_with(listener, state, None, shutdown)
    }

    /// [`serve`], with the file API mounted under `/v1/files` when `files` is given.
    pub fn serve_with(
        listener: UnixListener,
        state: Arc<AppState>,
        files: Option<Arc<FilesService>>,
        shutdown: Arc<AtomicBool>,
    ) -> io::Result<()> {
        serve_gated(listener, state, files, shutdown, None)
    }

    /// The supervisor's socket: the same server and the same `AppState` (so a run started here passes the same
    /// admission, caps, per-run token and rules as one started on the box socket), behind `gate`.
    pub fn serve_supervisor(
        listener: UnixListener,
        state: Arc<AppState>,
        files: Option<Arc<FilesService>>,
        shutdown: Arc<AtomicBool>,
        gate: Arc<SupervisorGate>,
    ) -> io::Result<()> {
        serve_gated(listener, state, files, shutdown, Some(gate))
    }

    fn serve_gated(
        listener: UnixListener,
        state: Arc<AppState>,
        files: Option<Arc<FilesService>>,
        shutdown: Arc<AtomicBool>,
        gate: Option<Arc<SupervisorGate>>,
    ) -> io::Result<()> {
        listener.set_nonblocking(true)?;
        let live = Arc::new(AtomicUsize::new(0));
        while !shutdown.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    if live.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                        live.fetch_sub(1, Ordering::SeqCst);
                        let _ = stream.set_nonblocking(false);
                        let _ = http::write_response(
                            &mut stream,
                            &Response::error(503, "too many connections"),
                        );
                        continue;
                    }
                    let (st, lv, fl, gt) =
                        (state.clone(), live.clone(), files.clone(), gate.clone());
                    let spawned = std::thread::Builder::new()
                        .name("ozboxd-conn".into())
                        .spawn(move || {
                            handle(stream, &st, fl.as_deref(), gt.as_deref());
                            lv.fetch_sub(1, Ordering::SeqCst);
                        });
                    if spawned.is_err() {
                        live.fetch_sub(1, Ordering::SeqCst);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(40))
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}
