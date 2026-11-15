//! `/v1/browser/...`: the dashboard's and the command line's view of browsing sessions (ADR 0037). A live session is a worker on
//! a box; the page is shown as pictures the worker takes, a person's clicks and keys go back through the same session, and
//! take over, hand back, resume and close are one request each. Recordings are read from the box.
//!
//! Every act by a person is a record in the audit chain (the action word and the session id, never an input). There are
//! Who may look, take over or change the settings is the person's role (ADR 0039, decided in `roles` before a request gets
//! here): a viewer may not look at all, a member may watch and take over, and only an owner changes the settings. Taking
//! over, resuming and changing the settings also need a second factor shown a moment ago (like the other changes that
//! matter), and a person's input and hand-back are accepted only from the person who took over (or with a fresh second
//! factor).

use std::sync::Arc;

use serde_json::{json, Value};

use super::roles::{step_up_refusal, StepUp};
use super::*;
use crate::browser_tools::{BrowserEvent, BrowserHost, PersonAct};
use crate::orch_tools::ToolError;

fn tool_resp(e: &ToolError) -> Resp {
    match e {
        ToolError::NotFound(m) => Resp::error(404, "not_found", m),
        ToolError::Invalid(m) => Resp::error(400, "bad_request", m),
        ToolError::Refused(m) => Resp::error(409, "refused", m),
        ToolError::Failed(m) => Resp::error(502, "failed", m),
    }
}

fn valid_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 63
        && n.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

impl App {
    fn browser_host(&mut self) -> Result<Arc<BrowserHost>, Resp> {
        self.orch_ensure_mcp();
        self.orch.browser.clone().ok_or_else(|| {
            Resp::error(
                501,
                "browser_unavailable",
                "browsing needs the task store on this server",
            )
        })
    }

    fn browser_boxes(&self) -> Vec<String> {
        self.provider
            .list()
            .map(|r| r.iter().map(|x| x.spec.name.to_string()).collect())
            .unwrap_or_default()
    }

    /// Tell the person about what the browser needs them for, on every channel the alerts reach.
    pub(super) fn tick_browser(&mut self, now_ms: u64) {
        let Some(b) = self.orch.browser.clone() else {
            return;
        };
        let events = b.drain_events();
        if events.is_empty() {
            return;
        }
        let alerts: Vec<crate::notify::Alert> =
            events.iter().map(|e| browser_alert(e, now_ms)).collect();
        self.route_alerts(alerts, now_ms);
    }

    pub(super) fn browser_route(&mut self, req: &Req, rest: &[&str]) -> Resp {
        let who = self.who(req);
        let gate = self.step_up_state(req);
        let step_up = || {
            step_up_refusal(
                gate,
                "taking over a browser, resuming one or changing the browser's settings",
            )
            .unwrap_or_else(|| {
                Resp::error(
                    403,
                    "step_up_required",
                    "confirm with your passkey to continue",
                )
            })
        };
        let fresh = gate == StepUp::Fresh;
        // a session id is checked here as well as below, so a path is never built from one that is not
        if let Some(id) = rest
            .get(1)
            .filter(|_| matches!(rest.first(), Some(&"sessions")))
        {
            if !ozbox_browser::record::valid_session_id(id) {
                return Resp::error(404, "not_found", "there is no such browser session");
            }
        }
        if let (Some(&"recordings"), Some(id)) = (rest.first(), rest.get(2)) {
            if !ozbox_browser::record::valid_session_id(id) {
                return Resp::error(404, "not_found", "there is no such recording");
            }
        }
        // taking over relays a person's own keys into a browser that may hold their sign-ins; resuming starts the agent
        // again; the settings decide what asks a person and what is refused. Each needs a fresh second factor.
        if needs_step_up(req.method.as_str(), rest) && !fresh {
            return step_up();
        }
        let host = match self.browser_host() {
            Ok(h) => h,
            Err(r) => return r,
        };
        let body: Value = if req.body.is_empty() {
            json!({})
        } else {
            serde_json::from_slice(&req.body).unwrap_or(Value::Null)
        };
        let text = |k: &str| body.get(k).and_then(Value::as_str).map(str::to_string);
        let q = parse_query(&req.query);
        let qv = |k: &str| q.iter().find(|(a, _)| *a == k).map(|(_, v)| v.clone());
        match (req.method.as_str(), rest) {
            ("GET", ["sessions"]) => {
                let boxes = match qv("box") {
                    Some(b) => vec![b],
                    None => self.browser_boxes(),
                };
                let live: Vec<Value> = host
                    .sessions()
                    .into_iter()
                    .map(|(id, b)| json!({ "id": id, "box": b }))
                    .collect();
                let mut recordings = Vec::new();
                // a running box whose sessions could not be read is named with the reason, never read as "no sessions"
                let running: Vec<String> = self
                    .provider
                    .list()
                    .map(|r| {
                        r.iter()
                            .filter(|x| x.state == BoxState::Running)
                            .map(|x| x.spec.name.to_string())
                            .collect()
                    })
                    .unwrap_or_default();
                let mut unreachable = Vec::new();
                for b in boxes {
                    if !valid_name(&b) {
                        return Resp::error(400, "bad_request", "that is not a box name");
                    }
                    let found = match host.backend.list_sessions(&b) {
                        Ok(f) => f,
                        Err(why) => {
                            if running.contains(&b) {
                                unreachable.push(json!({ "name": b, "reason": why }));
                            }
                            Vec::new()
                        }
                    };
                    for m in found {
                        let mut v = serde_json::to_value(&m).unwrap_or(Value::Null);
                        v["box"] = json!(b);
                        v["live"] = json!(live.iter().any(|l| l["id"] == m.session.as_str()));
                        recordings.push(v);
                    }
                }
                // `simulated` when the browser is the demo's stand-in, not a real Chromium on a box
                let source = if self.simulated_metrics {
                    "simulated"
                } else {
                    "live"
                };
                Resp::json(
                    200,
                    &json!({ "live": live, "recordings": recordings, "source": source, "unreachable": unreachable }),
                )
            }
            ("POST", ["sessions"]) => {
                let Some(b) =
                    text("box").filter(|b| valid_name(b) && self.browser_boxes().contains(b))
                else {
                    return Resp::error(400, "bad_request", "name an existing box");
                };
                let device = match text("device") {
                    None => ozbox_browser::policy::Device::Desktop,
                    Some(d) => match ozbox_browser::policy::Device::parse(&d) {
                        Some(d) => d,
                        None => {
                            return Resp::error(
                                400,
                                "bad_request",
                                "device is desktop, tablet or phone",
                            )
                        }
                    },
                };
                let allowed = self
                    .run_store()
                    .ok()
                    .and_then(|s| s.load().ok())
                    .map(|b| b.perms.browser_hosts)
                    .unwrap_or_default();
                match host.open(
                    &b,
                    None,
                    device,
                    text("project").as_deref(),
                    text("task"),
                    &allowed,
                    None,
                ) {
                    Ok(id) => {
                        host.audit(&format!("person:{who}"), "browser.open", &id);
                        Resp::json(200, &json!({ "id": id, "box": b }))
                    }
                    Err(e) => tool_resp(&e),
                }
            }
            ("GET", ["sessions", id]) => host
                .status(id)
                .map_or_else(|e| tool_resp(&e), |v| Resp::json(200, &v)),
            ("GET", ["sessions", id, "frame"]) => host
                .frame(id)
                .map_or_else(|e| tool_resp(&e), |v| Resp::json(200, &v)),
            ("POST", ["sessions", id, "input"]) => host
                .input(
                    id,
                    &PersonAct::checked(&who),
                    body.get("event").cloned().unwrap_or(Value::Null),
                )
                .map_or_else(
                    |e| tool_resp(&e),
                    |()| Resp::json(200, &json!({ "ok": true })),
                ),
            ("POST", ["sessions", id, "takeover"]) => host
                .takeover(id, &PersonAct::checked(&who))
                .map_or_else(|e| tool_resp(&e), |v| Resp::json(200, &v)),
            ("POST", ["sessions", id, "handback"]) => {
                // the person who holds it hands it back; anyone else needs a fresh second factor
                if host.holder(id).is_some_and(|h| h != who) && !fresh {
                    return step_up();
                }
                host.handback(id, &PersonAct::checked(&who))
                    .map_or_else(|e| tool_resp(&e), |v| Resp::json(200, &v))
            }
            ("POST", ["sessions", id, "close"]) => host.close(id).map_or_else(
                |e| tool_resp(&e),
                |()| {
                    host.audit(&format!("person:{who}"), "browser.close", id);
                    Resp::json(200, &json!({ "closed": true }))
                },
            ),
            ("POST", ["sessions", id, "resume"]) => {
                let Some(b) = text("box").filter(|b| valid_name(b)) else {
                    return Resp::error(400, "bad_request", "name the box");
                };
                let allowed = self
                    .run_store()
                    .ok()
                    .and_then(|s| s.load().ok())
                    .map(|b| b.perms.browser_hosts)
                    .unwrap_or_default();
                host.resume(&b, id, &allowed, &PersonAct::checked(&who))
                    .map_or_else(
                        |e| tool_resp(&e),
                        |id| Resp::json(200, &json!({ "id": id })),
                    )
            }
            ("GET", ["recordings", b, id]) => {
                if !valid_name(b) {
                    return Resp::error(400, "bad_request", "that is not a box name");
                }
                let meta = host
                    .backend
                    .list_sessions(b)
                    .unwrap_or_default()
                    .into_iter()
                    .find(|m| &m.session == id);
                match (meta, host.backend.steps(b, id)) {
                    (Some(m), Ok(steps)) => {
                        host.audit(&format!("person:{who}"), "browser.replay", id);
                        Resp::json(200, &json!({ "meta": m, "steps": steps }))
                    }
                    _ => Resp::error(404, "not_found", "there is no such recording"),
                }
            }
            ("GET", ["recordings", b, id, "shots", name]) => {
                if !valid_name(b) {
                    return Resp::error(400, "bad_request", "that is not a box name");
                }
                match host.backend.shot(b, id, name) {
                    Ok(bytes) => Resp {
                        status: 200,
                        content_type: "image/jpeg",
                        body: bytes,
                        no_store: true,
                        stream: false,
                    },
                    Err(_) => Resp::error(404, "not_found", "there is no such picture"),
                }
            }
            ("GET", ["settings"]) => {
                let project = qv("project");
                Resp::json(
                    200,
                    &json!({ "settings": host.policy(project.as_deref()), "projects": host.policy_file().projects.keys().collect::<Vec<_>>() }),
                )
            }
            ("PUT", ["settings"]) => {
                let Some(p) = body
                    .get("settings")
                    .and_then(|s| serde_json::from_value(s.clone()).ok())
                else {
                    return Resp::error(400, "bad_request", "send the settings");
                };
                let project = text("project");
                match host.set_policy(project.as_deref(), p) {
                    Ok(diff) => {
                        host.audit_detail(
                            &format!("person:{who}"),
                            "browser.settings",
                            &format!("project={} {diff}", project.as_deref().unwrap_or("-")),
                        );
                        Resp::json(200, &json!({ "ok": true }))
                    }
                    Err(e) => Resp::error(400, "bad_request", &e),
                }
            }
            _ => Resp::error(404, "not_found", "there is no such browser route"),
        }
    }
}

/// The browser routes that need a second factor shown a moment ago.
pub(super) fn needs_step_up(method: &str, rest: &[&str]) -> bool {
    matches!(
        (method, rest),
        ("POST", ["sessions", _, "takeover"])
            | ("POST", ["sessions", _, "resume"])
            | ("PUT", ["settings"])
    )
}

fn browser_alert(e: &BrowserEvent, now_ms: u64) -> crate::notify::Alert {
    let (title, urgent) = match e.kind {
        "challenge" => (
            "A browser needs you: a check that only a person can do",
            true,
        ),
        "paused" => ("A browsing task is paused", true),
        "limit" => ("A browsing task reached its limit and paused", true),
        "limit_warning" => ("A browsing task is at 80% of its limit", false),
        _ => ("A browser event", false),
    };
    crate::notify::Alert {
        key: format!("browser:{}:{}", e.kind, e.session),
        kind: format!("browser_{}", e.kind),
        severity: if urgent {
            crate::notify::Severity::Urgent
        } else {
            crate::notify::Severity::Normal
        },
        box_name: Some(e.box_name.clone()),
        title: title.to_string(),
        body: format!(
            "{} (session {} on {}). Open Browser in the dashboard to take over or resume.",
            e.text, e.session, e.box_name
        ),
        ts_ms: now_ms,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::*;

    #[test]
    fn a_server_without_a_task_store_answers_501_with_the_reason() {
        let d = tempfile::tempdir().unwrap();
        let mut a = App::new(
            Box::new(ozbox_provider_fake::open(d.path().join("state"))),
            true,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7878),
            "tok".into(),
        );
        let mut headers = HashMap::new();
        headers.insert("host".to_string(), "127.0.0.1:7878".to_string());
        headers.insert("authorization".to_string(), "Bearer tok".to_string());
        let r = a.handle(&Req {
            method: "GET".into(),
            path: "/v1/browser/sessions".into(),
            query: String::new(),
            headers,
            body: vec![],
        });
        assert_eq!(r.status, 501);
        let v: Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(v["code"], "browser_unavailable");
        assert!(v["message"].as_str().unwrap().contains("task store"));
    }

    /// A browser backend that cannot read any box's recordings.
    struct Unreadable;

    impl crate::browser_tools::BrowserBackend for Unreadable {
        fn start(
            &self,
            _: &str,
            _: &str,
            _: &crate::browser_tools::WorkerRun,
        ) -> Result<String, String> {
            Err("no".into())
        }
        fn send(&self, _: &str, _: &str, _: &str) -> Result<(), String> {
            Err("no".into())
        }
        fn next_line(
            &self,
            _: &str,
            _: &str,
            _: std::time::Instant,
        ) -> Result<Option<String>, String> {
            Err("no".into())
        }
        fn stop(&self, _: &str, _: &str) {}
        fn roots(&self, _: &str) -> (String, String) {
            (String::new(), String::new())
        }
        fn list_sessions(&self, b: &str) -> Result<Vec<ozbox_browser::record::Meta>, String> {
            Err(format!("the recordings of {b} could not be read"))
        }
        fn steps(&self, _: &str, _: &str) -> Result<Vec<ozbox_browser::record::Step>, String> {
            Err("no".into())
        }
        fn shot(&self, _: &str, _: &str, _: &str) -> Result<Vec<u8>, String> {
            Err("no".into())
        }
    }

    /// R5-4. A running box whose recordings could not be read is named with the reason, never read as "no sessions"; a
    /// stopped box that cannot be read is simply not running, and is not named.
    #[test]
    fn a_running_box_that_cannot_be_read_is_named_unreachable_and_a_stopped_one_is_not() {
        use ozbox_core::{BoxName, BoxSpec, Provider, Size};
        let d = tempfile::tempdir().unwrap();
        let p = ozbox_provider_fake::open(d.path().join("state"));
        for n in ["alpha", "bravo"] {
            let provider: &dyn Provider = &p;
            let plan = provider
                .plan(&ozbox_core::Operation::Create {
                    spec: BoxSpec::new(BoxName::new(n).unwrap(), Size::S),
                })
                .unwrap();
            provider.apply(&plan).unwrap();
        }
        let provider: &dyn Provider = &p;
        let plan = provider
            .plan(&ozbox_core::Operation::Pause {
                name: BoxName::new("bravo").unwrap(),
            })
            .unwrap();
        provider.apply(&plan).unwrap();
        let mut a = App::new(
            Box::new(p),
            true,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7878),
            "tok".into(),
        )
        .with_task_store(Some(d.path().join("tasks.json")));
        a.orch_ensure_mcp();
        let store = a.runs.store.clone().unwrap();
        a.orch.browser = Some(Arc::new(crate::browser_tools::BrowserHost::new(
            Arc::new(Unreadable),
            store,
            d.path().join("browser-policy.json"),
        )));
        let mut headers = HashMap::new();
        headers.insert("host".to_string(), "127.0.0.1:7878".to_string());
        headers.insert("authorization".to_string(), "Bearer tok".to_string());
        let r = a.handle(&Req {
            method: "GET".into(),
            path: "/v1/browser/sessions".into(),
            query: String::new(),
            headers,
            body: vec![],
        });
        assert_eq!(r.status, 200);
        let v: Value = serde_json::from_slice(&r.body).unwrap();
        let un = v["unreachable"].as_array().unwrap();
        assert_eq!(un.len(), 1, "{v}");
        assert_eq!(un[0]["name"], "alpha");
        assert!(un[0]["reason"]
            .as_str()
            .unwrap()
            .contains("could not be read"));
        assert_eq!(v["recordings"].as_array().unwrap().len(), 0);
    }
}
