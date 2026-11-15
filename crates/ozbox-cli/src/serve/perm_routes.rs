//! `/v1/permissions` and `/v1/audit`: the permission engine's settings and Production grants, and the tamper-evident audit
//! chain with its check. Everything lives in the task store beside the runs (`ozbox_core::run`), so the command line and
//! the dashboard read and write the same configuration, and every change is a record in the chain.
//!
//! Loosening anything needs the second factor behind a sign-in (a passkey or authenticator code shown moments ago); in
//! signed-out mode there is none to ask for, so a grant needs the name of what it covers typed back and is recorded as a
//! typed confirmation, never as a second factor. Revoking a grant needs nothing: taking access away is always allowed.

use ozbox_core::audit::NewEvent;
use ozbox_core::permissions::{
    self, Action, ActorKind, Ctx, Environment, NewGrant, PermError, PermSettings, Scope,
    SecondFactor, MAX_GRANT_MINUTES,
};
use serde::Deserialize;
use serde_json::{json, Value};

use super::{parse_query, unix_ms, App, Req, Resp};

fn perm_error(e: &PermError) -> Resp {
    let (status, code) = match e {
        PermError::Invalid(_) => (400, "bad_request"),
        PermError::NoSuchGrant => (404, "not_found"),
        PermError::AlreadyRevoked => (409, "conflict"),
    };
    Resp::error(status, code, &e.to_string())
}

#[derive(Deserialize)]
struct GrantBody {
    scope: Scope,
    scope_id: String,
    #[serde(default)]
    actions: Vec<String>,
    reason: String,
    minutes: u64,
    #[serde(default)]
    allow_unattended: bool,
    #[serde(default)]
    max_uses: Option<u32>,
    /// Signed-out mode: the name of what the grant covers, typed back.
    #[serde(default)]
    confirm: Option<String>,
}

#[derive(Deserialize)]
struct CheckBody {
    action: Action,
    #[serde(default)]
    actor: Option<ActorKind>,
    #[serde(default)]
    box_name: Option<String>,
    #[serde(default)]
    project: Option<String>,
    #[serde(default)]
    run_id: Option<String>,
    #[serde(default)]
    orchestration: Option<String>,
    #[serde(default)]
    env: Option<Environment>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    command: Option<String>,
    #[serde(default)]
    tool: Option<String>,
    #[serde(default)]
    server: Option<String>,
    #[serde(default)]
    writes: Option<bool>,
    #[serde(default)]
    sensitive: bool,
}

impl App {
    /// Add one event to the audit chain from outside the task store (a box was created, a secret was used).
    /// Best effort: the action has already happened, and a missing chain is reported by the check, not hidden.
    pub(super) fn chain_event(
        &self,
        actor: &str,
        action: &str,
        subject: Option<&str>,
        detail: &str,
    ) {
        let Some(store) = &self.runs.store else {
            return;
        };
        let _ = store.audit_log().append(NewEvent {
            ts_ms: unix_ms(),
            actor: actor.to_string(),
            action: action.to_string(),
            subject: subject.map(str::to_string),
            detail: detail.to_string(),
            src: None,
        });
    }

    pub(super) fn perm_route(&mut self, req: &Req, rest: &[&str]) -> Resp {
        let who = self.who(req);
        let now = unix_ms();
        match (req.method.as_str(), rest) {
            ("GET", []) => {
                let book = match self.run_store().and_then(|s| {
                    s.load()
                        .map_err(|e| Resp::error(500, "store_unavailable", &e.to_string()))
                }) {
                    Ok(b) => b,
                    Err(r) => return r,
                };
                let grants: Vec<Value> = book
                    .perms
                    .grants
                    .iter()
                    .rev()
                    .map(|g| {
                        let mut v = serde_json::to_value(g).unwrap_or(Value::Null);
                        v["state"] = json!(g.state(now));
                        v["factor_is_real"] = json!(g.factor.is_real());
                        v
                    })
                    .collect();
                Resp::json(
                    200,
                    &json!({
                        "source": "server",
                        "settings": book.perms.settings(),
                        "grants": grants,
                        "now_ms": now,
                        "max_grant_minutes": MAX_GRANT_MINUTES,
                        "signed_in": self.auth.is_some(),
                        "actions": Action::ALL.iter().map(|a| a.name()).collect::<Vec<_>>(),
                    }),
                )
            }
            ("PUT", []) => {
                let s: PermSettings = match serde_json::from_slice(&req.body) {
                    Ok(s) => s,
                    Err(e) => {
                        return Resp::error(400, "bad_request", &format!("invalid request: {e}"))
                    }
                };
                if let Some(r) = super::roles::step_up_refusal(
                    self.step_up_state(req),
                    "changing the permission rules",
                ) {
                    return r;
                }
                let detail = format!("{} rules, {} modes", s.rules.len(), s.modes.len());
                match self.runs_update(|b| {
                    let r = b.perms.apply_settings(s);
                    if r.is_ok() {
                        b.record(now, &who, "permission.settings_changed", None, &detail);
                    }
                    (r, b.perms.settings())
                }) {
                    Ok((Ok(()), settings)) => Resp::json(200, &json!({ "settings": settings })),
                    Ok((Err(e), _)) => perm_error(&e),
                    Err(r) => r,
                }
            }
            ("POST", ["grants"]) => {
                let g: GrantBody = match serde_json::from_slice(&req.body) {
                    Ok(g) => g,
                    Err(e) => {
                        return Resp::error(400, "bad_request", &format!("invalid request: {e}"))
                    }
                };
                // on a box with no sign-in this is refused: the access token is not proof of a person there
                if let Some(r) = super::roles::step_up_refusal(
                    self.step_up_state(req),
                    "granting access to production",
                ) {
                    return r;
                }
                let factor = match &self.auth {
                    Some(_) => SecondFactor::StepUp,
                    None => {
                        if g.confirm.as_deref() != Some(g.scope_id.as_str()) {
                            return Resp::error(
                                400,
                                "confirmation_required",
                                "type the name of what you are granting access to, to confirm",
                            );
                        }
                        SecondFactor::TypedConfirmation
                    }
                };
                let new = NewGrant {
                    granted_by: who.clone(),
                    scope: g.scope,
                    scope_id: g.scope_id,
                    actions: if g.actions.is_empty() {
                        vec!["*".into()]
                    } else {
                        g.actions
                    },
                    reason: g.reason,
                    minutes: g.minutes,
                    factor,
                    allow_unattended: g.allow_unattended,
                    max_uses: g.max_uses,
                };
                match self.runs_update(|b| {
                    let r = b.perms.create_grant(new, now);
                    if let Ok(g) = &r {
                        b.record(
                            now,
                            &who,
                            "grant.created",
                            None,
                            &format!(
                                "{} {:?}:{} {} min via {:?}",
                                g.id,
                                g.scope,
                                g.scope_id,
                                (g.expires_ms - g.created_ms) / 60_000,
                                g.factor
                            )
                            .to_lowercase(),
                        );
                    }
                    r
                }) {
                    Ok(Ok(g)) => Resp::json(201, &g),
                    Ok(Err(e)) => perm_error(&e),
                    Err(r) => r,
                }
            }
            ("POST", ["grants", id, "revoke"]) => {
                let id = id.to_string();
                match self.runs_update(|b| {
                    let r = b.perms.revoke_grant(&id, &who, now);
                    if r.is_ok() {
                        b.record(now, &who, "grant.revoked", None, &id);
                    }
                    r
                }) {
                    Ok(Ok(())) => Resp::json(200, &json!({ "id": id, "state": "revoked" })),
                    Ok(Err(e)) => perm_error(&e),
                    Err(r) => r,
                }
            }
            // A dry run: what would the engine say? It makes no decision, so it is not recorded.
            ("POST", ["check"]) => {
                let c: CheckBody = match serde_json::from_slice(&req.body) {
                    Ok(c) => c,
                    Err(e) => {
                        return Resp::error(400, "bad_request", &format!("invalid request: {e}"))
                    }
                };
                let book = match self.run_store().and_then(|s| {
                    s.load()
                        .map_err(|e| Resp::error(500, "store_unavailable", &e.to_string()))
                }) {
                    Ok(b) => b,
                    Err(r) => return r,
                };
                let ctx = Ctx {
                    person: who,
                    actor: c.actor.unwrap_or(ActorKind::Agent),
                    box_name: c.box_name,
                    project: c.project,
                    run_id: c.run_id,
                    orchestration: c.orchestration,
                    env: c.env.unwrap_or_default(),
                    path: c.path,
                    command: c
                        .command
                        .map(|s| s.split_whitespace().map(str::to_string).collect()),
                    tool: c.tool,
                    server: c.server,
                    writes: c.writes,
                    sensitive: c.sensitive,
                };
                let d = permissions::decide(&book.perms, &ctx, c.action, now);
                Resp::json(
                    200,
                    &json!({
                        "effect": d.effect, "reason": d.reason.code(), "sentence": d.reason.sentence(),
                        "mode": d.mode, "rule": d.rule, "grant": d.grant,
                    }),
                )
            }
            _ => Resp::error(404, "not_found", "no such endpoint"),
        }
    }

    /// `GET /v1/host-tools?env=`: the tools an agent has on a box and what a new call to each would be decided as under the
    /// current mode and rules, in a sandbox, in staging or on production. A dry run: nothing is recorded.
    pub(super) fn host_tools_route(&mut self, req: &Req) -> Resp {
        use crate::host_tools::{Writes, TOOLS};
        let q = parse_query(&req.query);
        let env = match q.get("env").map(String::as_str) {
            Some("staging") => Environment::Staging,
            Some("production") => Environment::Production,
            _ => Environment::Sandbox,
        };
        let book = match self.run_store().and_then(|s| {
            s.load()
                .map_err(|e| Resp::error(500, "store_unavailable", &e.to_string()))
        }) {
            Ok(b) => b,
            Err(r) => return r,
        };
        let who = self.who(req);
        let now = unix_ms();
        let tools: Vec<Value> = TOOLS
            .iter()
            .map(|t| {
                let writes = match t.writes {
                    Writes::Read => Some(false),
                    Writes::Write => Some(true),
                    Writes::Depends => None,
                };
                let ctx = Ctx {
                    person: who.clone(),
                    actor: ActorKind::Agent,
                    env,
                    tool: Some(t.name.to_string()),
                    server: Some(t.server.to_string()),
                    writes,
                    ..Ctx::default()
                };
                let d = permissions::decide(&book.perms, &ctx, Action::ToolCall, now);
                json!({
                    "name": t.name, "server": t.server,
                    "writes": match t.writes { Writes::Read => "read", Writes::Write => "write", Writes::Depends => "depends" },
                    "summary": t.summary, "effect": d.effect, "reason": d.reason.code(), "rule": d.rule,
                })
            })
            .collect();
        Resp::json(
            200,
            &json!({ "source": "server", "env": env, "mode": book.perms.default_mode, "tools": tools }),
        )
    }

    pub(super) fn audit_route(&mut self, req: &Req, rest: &[&str]) -> Resp {
        let store = match self.run_store() {
            Ok(s) => s,
            Err(r) => return r,
        };
        let log = store.audit_log();
        match (req.method.as_str(), rest) {
            ("GET", []) => {
                let q = parse_query(&req.query);
                let limit = q
                    .get("limit")
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or(100)
                    .clamp(1, 500);
                let prefix = q.get("action").cloned().unwrap_or_default();
                let all = match log.entries() {
                    Ok(e) => e,
                    Err(e) => return Resp::error(500, "audit_unavailable", &e.to_string()),
                };
                let total = all.len();
                let (head_seq, head_hash) = all
                    .last()
                    .map(|e| (e.seq, e.hash.clone()))
                    .unwrap_or((0, String::new()));
                let entries: Vec<_> = all
                    .into_iter()
                    .rev()
                    .filter(|e| prefix.is_empty() || e.action.starts_with(&prefix))
                    .take(limit)
                    .collect();
                Resp::json(
                    200,
                    &json!({
                        "source": "server", "entries": entries, "total": total,
                        "head_seq": head_seq, "head_hash": head_hash,
                    }),
                )
            }
            ("GET", ["verify"]) => match log.verify() {
                Ok(r) => Resp::json(
                    200,
                    &json!({ "source": "server", "checked_ms": unix_ms(), "report": r }),
                ),
                Err(e) => Resp::error(500, "audit_unavailable", &e.to_string()),
            },
            ("POST", ["seal"]) => match log.seal_now(unix_ms()) {
                Ok(c) => Resp::json(200, &json!({ "sealed": c.is_some(), "checkpoint": c })),
                Err(e) => Resp::error(500, "audit_unavailable", &e.to_string()),
            },
            _ => Resp::error(404, "not_found", "no such endpoint"),
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
        for (n, prod) in [("alpha", false), ("prod", true)] {
            let mut spec = BoxSpec::new(BoxName::new(n).unwrap(), Size::S);
            if prod {
                spec.labels.insert("env".into(), "production".into());
            }
            let provider: &dyn Provider = &p;
            let plan = provider
                .plan(&ozbox_core::Operation::Create { spec })
                .unwrap();
            provider.apply(&plan).unwrap();
        }
        App::new(Box::new(p), true, addr, TOKEN.into())
            .with_task_store(Some(dir.join("tasks.json")))
    }

    fn call(a: &mut App, method: &str, path: &str, body: Value) -> (u16, Value) {
        let (p, q) = path.split_once('?').unwrap_or((path, ""));
        let mut headers = HashMap::new();
        headers.insert("host".to_string(), "127.0.0.1:7878".to_string());
        headers.insert("authorization".to_string(), format!("Bearer {TOKEN}"));
        let r = a.handle(&Req {
            method: method.into(),
            path: p.into(),
            query: q.into(),
            headers,
            body: if body.is_null() {
                Vec::new()
            } else {
                body.to_string().into_bytes()
            },
        });
        (
            r.status,
            serde_json::from_slice(&r.body).unwrap_or(Value::Null),
        )
    }

    fn grant_body(box_name: &str, confirm: Option<&str>) -> Value {
        let mut v = json!({
            "scope": "box", "scope_id": box_name, "reason": "deploy the fix", "minutes": 30,
        });
        if let Some(c) = confirm {
            v["confirm"] = json!(c);
        }
        v
    }

    fn pause_plan(a: &mut App, name: &str) -> String {
        let (st, v) = call(
            a,
            "POST",
            "/v1/plans",
            json!({ "operation": { "op": "pause", "name": name } }),
        );
        assert_eq!(st, 200, "{v}");
        v["plan_id"].as_str().unwrap().to_string()
    }

    #[test]
    fn the_default_view_is_ask_with_no_rules_and_no_grants() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = app(dir.path());
        let (st, v) = call(&mut a, "GET", "/v1/permissions", Value::Null);
        assert_eq!(st, 200);
        assert_eq!(v["settings"]["default_mode"], "ask");
        assert!(v["settings"]["rules"].as_array().unwrap().is_empty());
        assert!(v["grants"].as_array().unwrap().is_empty());
        assert_eq!(v["signed_in"], false);
        assert_eq!(v["max_grant_minutes"], 240);
    }

    #[test]
    fn a_rule_is_saved_gets_an_id_and_changes_what_the_check_says() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = app(dir.path());
        let settings = json!({
            "default_mode": "ask", "modes": [],
            "rules": [{ "effect": "deny", "action": "git.push", "scope": "box", "scope_id": "alpha" }],
        });
        let (st, v) = call(&mut a, "PUT", "/v1/permissions", settings);
        assert_eq!(st, 200, "{v}");
        assert_eq!(v["settings"]["rules"][0]["id"], "r1");
        let (_, d) = call(
            &mut a,
            "POST",
            "/v1/permissions/check",
            json!({ "action": "git.push", "box_name": "alpha" }),
        );
        assert_eq!(
            (d["effect"].as_str(), d["reason"].as_str()),
            (Some("deny"), Some("rule_deny"))
        );
        let (_, d) = call(
            &mut a,
            "POST",
            "/v1/permissions/check",
            json!({ "action": "git.push", "box_name": "bravo" }),
        );
        assert_eq!(d["effect"], "allow");
        // the change is in the audit log
        let (_, log) = call(&mut a, "GET", "/v1/audit?action=permission.", Value::Null);
        assert_eq!(log["entries"][0]["action"], "permission.settings_changed");
    }

    #[test]
    fn a_bad_rule_is_refused_and_nothing_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = app(dir.path());
        let bad = json!({ "default_mode": "ask", "rules": [{ "effect": "deny", "action": "git push", "scope": "person" }] });
        assert_eq!(call(&mut a, "PUT", "/v1/permissions", bad).0, 400);
        let (_, v) = call(&mut a, "GET", "/v1/permissions", Value::Null);
        assert!(v["settings"]["rules"].as_array().unwrap().is_empty());
        assert_eq!(
            call(&mut a, "PUT", "/v1/permissions", json!({ "nonsense": 1 })).0,
            400
        );
    }

    #[test]
    fn a_grant_signed_out_needs_the_name_typed_and_is_recorded_as_not_a_second_factor() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = app(dir.path());
        let (st, v) = call(
            &mut a,
            "POST",
            "/v1/permissions/grants",
            grant_body("prod", None),
        );
        assert_eq!(
            (st, v["code"].as_str()),
            (400, Some("confirmation_required")),
            "{v}"
        );
        let (st, _) = call(
            &mut a,
            "POST",
            "/v1/permissions/grants",
            grant_body("prod", Some("pord")),
        );
        assert_eq!(st, 400);
        let (st, g) = call(
            &mut a,
            "POST",
            "/v1/permissions/grants",
            grant_body("prod", Some("prod")),
        );
        assert_eq!(st, 201, "{g}");
        assert_eq!(g["factor"], "typed_confirmation");
        let (_, v) = call(&mut a, "GET", "/v1/permissions", Value::Null);
        assert_eq!(v["grants"][0]["state"], "active");
        assert_eq!(v["grants"][0]["factor_is_real"], false);
    }

    #[test]
    fn a_grant_is_capped_in_length_needs_a_reason_and_is_never_for_everything() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = app(dir.path());
        for patch in [
            json!({ "minutes": 241 }),
            json!({ "minutes": 0 }),
            json!({ "reason": "fix" }),
            json!({ "scope": "person" }),
        ] {
            let mut b = grant_body("prod", Some("prod"));
            for (k, v) in patch.as_object().unwrap() {
                b[k] = v.clone();
            }
            assert_eq!(
                call(&mut a, "POST", "/v1/permissions/grants", b).0,
                400,
                "{patch}"
            );
        }
        let (_, v) = call(&mut a, "GET", "/v1/permissions", Value::Null);
        assert!(v["grants"].as_array().unwrap().is_empty());
    }

    #[test]
    fn a_grant_can_be_revoked_once_and_the_production_gate_closes_again() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = app(dir.path());
        let prod = json!({ "action": "git.push", "box_name": "prod", "env": "production" });
        let (_, d) = call(&mut a, "POST", "/v1/permissions/check", prod.clone());
        assert_eq!(d["reason"], "production_no_grant");
        let (_, g) = call(
            &mut a,
            "POST",
            "/v1/permissions/grants",
            grant_body("prod", Some("prod")),
        );
        let id = g["id"].as_str().unwrap().to_string();
        let (_, d) = call(&mut a, "POST", "/v1/permissions/check", prod.clone());
        assert_eq!(d["effect"], "allow");
        assert_eq!(d["grant"], id.as_str());
        let path = format!("/v1/permissions/grants/{id}/revoke");
        assert_eq!(call(&mut a, "POST", &path, json!({})).0, 200);
        assert_eq!(call(&mut a, "POST", &path, json!({})).0, 409);
        assert_eq!(
            call(
                &mut a,
                "POST",
                "/v1/permissions/grants/nope/revoke",
                json!({})
            )
            .0,
            404
        );
        let (_, d) = call(&mut a, "POST", "/v1/permissions/check", prod);
        assert_eq!(d["reason"], "production_no_grant");
        let (_, v) = call(&mut a, "GET", "/v1/permissions", Value::Null);
        assert_eq!(v["grants"][0]["state"], "revoked");
    }

    #[test]
    fn a_change_to_a_production_box_is_refused_without_a_grant_and_allowed_with_one() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = app(dir.path());
        let id = pause_plan(&mut a, "prod");
        let (st, v) = call(&mut a, "POST", "/v1/apply", json!({ "plan_id": id }));
        assert_eq!(
            (st, v["code"].as_str()),
            (403, Some("permission_denied")),
            "{v}"
        );
        // an ordinary box is not held
        let other = pause_plan(&mut a, "alpha");
        assert_eq!(
            call(&mut a, "POST", "/v1/apply", json!({ "plan_id": other })).0,
            202
        );
        call(
            &mut a,
            "POST",
            "/v1/permissions/grants",
            grant_body("prod", Some("prod")),
        );
        let id = pause_plan(&mut a, "prod");
        let (st, v) = call(&mut a, "POST", "/v1/apply", json!({ "plan_id": id }));
        assert_eq!(st, 202, "{v}");
        // both outcomes are in the chain, naming the box and the reason and nothing secret
        let (_, log) = call(&mut a, "GET", "/v1/audit?action=permission.", Value::Null);
        let words: Vec<&str> = log["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["action"].as_str().unwrap())
            .collect();
        assert!(words.contains(&"permission.deny"), "{words:?}");
        let (_, used) = call(&mut a, "GET", "/v1/audit?action=grant.used", Value::Null);
        assert_eq!(used["entries"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn the_chain_verifies_and_an_edit_to_the_file_is_reported_through_the_api() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = app(dir.path());
        call(
            &mut a,
            "POST",
            "/v1/permissions/grants",
            grant_body("prod", Some("prod")),
        );
        call(
            &mut a,
            "POST",
            "/v1/permissions/grants",
            grant_body("alpha", Some("alpha")),
        );
        let (st, v) = call(&mut a, "GET", "/v1/audit/verify", Value::Null);
        assert_eq!(st, 200);
        assert_eq!(v["report"]["ok"], true, "{v}");
        let path = dir.path().join("tasks.audit.jsonl");
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, text.replacen("grant.created", "grant.nothing", 1)).unwrap();
        let (_, v) = call(&mut a, "GET", "/v1/audit/verify", Value::Null);
        assert_eq!(v["report"]["ok"], false);
        assert!(!v["report"]["altered"].as_array().unwrap().is_empty());
    }

    #[test]
    fn the_log_never_holds_the_reason_a_grant_was_given_for() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = app(dir.path());
        let mut b = grant_body("prod", Some("prod"));
        b["reason"] = json!("customer 4471 asked for the refund run");
        call(&mut a, "POST", "/v1/permissions/grants", b);
        let text = std::fs::read_to_string(dir.path().join("tasks.audit.jsonl")).unwrap();
        assert!(text.contains("grant.created"));
        assert!(!text.contains("4471") && !text.contains("refund"));
    }

    #[test]
    fn sealing_and_listing_work_and_a_filter_narrows_the_list() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = app(dir.path());
        call(
            &mut a,
            "POST",
            "/v1/permissions/grants",
            grant_body("prod", Some("prod")),
        );
        let (st, v) = call(&mut a, "POST", "/v1/audit/seal", json!({}));
        assert_eq!(st, 200, "{v}");
        let (_, all) = call(&mut a, "GET", "/v1/audit?limit=50", Value::Null);
        let (_, grants) = call(&mut a, "GET", "/v1/audit?action=grant.", Value::Null);
        assert!(
            all["total"].as_u64().unwrap() >= grants["entries"].as_array().unwrap().len() as u64
        );
        assert!(grants["entries"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["action"].as_str().unwrap().starts_with("grant.")));
        assert!(all["head_hash"].as_str().unwrap().len() == 64);
    }

    #[test]
    fn the_tools_list_shows_each_tool_with_the_decision_for_a_new_call() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = app(dir.path());
        let (st, v) = call(&mut a, "GET", "/v1/host-tools", Value::Null);
        assert_eq!(st, 200);
        let tools = v["tools"].as_array().unwrap();
        assert_eq!(tools.len(), crate::host_tools::TOOLS.len());
        let by = |n: &str, v: &Value| {
            v["tools"]
                .as_array()
                .unwrap()
                .iter()
                .find(|t| t["name"] == n)
                .unwrap()
                .clone()
        };
        assert_eq!(by("files_read", &v)["effect"], "allow");
        assert_eq!(by("shell", &v)["effect"], "ask");
        assert_eq!(by("git_branch", &v)["writes"], "depends");
        // on production a change is refused without a grant and a read is not
        let (_, p) = call(&mut a, "GET", "/v1/host-tools?env=production", Value::Null);
        assert_eq!(
            (
                by("shell", &p)["effect"].as_str(),
                by("shell", &p)["reason"].as_str()
            ),
            (Some("deny"), Some("production_no_grant"))
        );
        assert_eq!(by("files_read", &p)["effect"], "allow");
        // a rule on a tool shows as the reason
        let settings = json!({ "default_mode": "ask", "modes": [], "rules": [{ "effect": "deny", "action": "tool.call", "scope": "person", "tool": "git_*" }], "browser_hosts": ["example.com"] });
        assert_eq!(call(&mut a, "PUT", "/v1/permissions", settings).0, 200);
        let (_, v) = call(&mut a, "GET", "/v1/host-tools", Value::Null);
        assert_eq!(
            (
                by("git_push", &v)["effect"].as_str(),
                by("git_push", &v)["rule"].as_str()
            ),
            (Some("deny"), Some("r1"))
        );
        assert_eq!(by("shell", &v)["effect"], "ask");
        let (_, view) = call(&mut a, "GET", "/v1/permissions", Value::Null);
        assert_eq!(view["settings"]["browser_hosts"], json!(["example.com"]));
        // a bad host is refused
        let bad = json!({ "default_mode": "ask", "modes": [], "rules": [], "browser_hosts": ["http://x"] });
        assert_eq!(call(&mut a, "PUT", "/v1/permissions", bad).0, 400);
    }
}
