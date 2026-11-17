//! `/v1/models/subscriptions/...`: the owner's opt-in to hand one engine's own subscription sign-in to that engine's runs,
//! the vendor's device sign-in started from here, and revoking it (ADR 0055).
//!
//! - `GET  /v1/models/subscriptions`: for each engine that can be opted in, whether it is and whether a sign-in is stored.
//!   Booleans, ids and the vendor's revoke page only.
//! - `POST /v1/models/subscriptions/<id>/opt-in` `{ "confirm": "<id>" }`: turn it on. The owner only, with a fresh
//!   passkey, and the id typed back. Refused where the store cannot keep it from the box user.
//! - `POST /v1/models/subscriptions/<id>/sign-in`: start the vendor's device sign-in (opted in first; the owner, passkey).
//! - `GET  /v1/models/subscriptions/<id>/sign-in`: where it stands, with the vendor's link and one-time code. The owner
//!   only: whoever types the code decides whose account the box holds.
//! - `DELETE /v1/models/subscriptions/<id>`: delete the sign-in and turn the opt-in off. The answer names the runs that
//!   still have a copy until they end and the vendor page where the sign-in is revoked for good.
//!
//! No answer, log line, audit record or error carries the sign-in itself.

use std::sync::Arc;

use serde::Deserialize;
use serde_json::{json, Value};

use super::{roles, unix_ms, App, Req, Resp};
use crate::subscription_signin::{self as ss, Phase};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OptIn {
    confirm: String,
}

impl App {
    pub(super) fn subscriptions_route(&mut self, req: &Req, rest: &[&str]) -> Resp {
        let get = req.method == "GET";
        match rest {
            [] if get => self.subscriptions_list(),
            [id, "opt-in"] if req.method == "POST" => self.subscription_opt_in(req, id),
            [id, "sign-in"] if req.method == "POST" => self.subscription_sign_in(req, id),
            [id, "sign-in"] if get => self.subscription_sign_in_state(id),
            [id] if req.method == "DELETE" => self.subscription_revoke(id),
            [] | [_, "opt-in" | "sign-in"] | [_] => {
                Resp::error(405, "method_not_allowed", "method not allowed")
            }
            _ => Resp::error(404, "not_found", "no such endpoint"),
        }
    }

    fn subscriptions_list(&self) -> Resp {
        let rows: Vec<Value> = ss::ADAPTERS
            .iter()
            .map(|a| {
                let flow = ss_lock(&self.subs).get(a.sub_id).map(|f| f.phase.word());
                json!({
                    "id": a.sub_id,
                    "engine": a.engine,
                    "opted_in": ss::opted_in(self.secrets.as_ref(), a.sub_id),
                    "signed_in": ss::signed_in(self.secrets.as_ref(), a.sub_id),
                    "sign_in": flow,
                    "confirm": a.confirm,
                    "revoke_at": a.revoke_at,
                })
            })
            .collect();
        Resp::json(200, &json!({ "subscriptions": rows }))
    }

    fn subscription_opt_in(&mut self, req: &Req, id: &str) -> Resp {
        let Some(a) = ss::adapter(id) else {
            return not_offered();
        };
        if let Some(r) = roles::step_up_refusal(
            self.step_up_state(req),
            "letting an engine read your subscription sign-in",
        ) {
            return r;
        }
        let body: OptIn = match serde_json::from_slice(&req.body) {
            Ok(b) => b,
            Err(_) => return Resp::error(400, "bad_request", "type the confirmation"),
        };
        if body.confirm != a.confirm {
            return Resp::error(
                400,
                "confirmation_mismatch",
                "type the confirmation exactly as shown to turn this on",
            );
        }
        if let Err(e) = ss::set_opt_in(self.secrets.as_ref(), id, unix_ms()) {
            // a dashboard that runs as the box user cannot keep anything from it, so the store refuses: say so plainly
            let _ = e;
            return Resp::error(
                409,
                "store_unavailable",
                "this dashboard's secrets store cannot keep a sign-in out of the box user's reach. Turn on the dashboard's own user on this box (`ozbox upgrade`), or run the dashboard on your own computer",
            );
        }
        let who = self.current_actor.chain();
        self.chain_event(&who, "subscription.opted_in", Some(id), a.engine);
        Resp::json(200, &json!({ "id": id, "opted_in": true }))
    }

    fn subscription_sign_in(&mut self, req: &Req, id: &str) -> Resp {
        let Some(a) = ss::adapter(id) else {
            return not_offered();
        };
        if let Some(r) = roles::step_up_refusal(
            self.step_up_state(req),
            "signing an engine in with your subscription",
        ) {
            return r;
        }
        if !ss::opted_in(self.secrets.as_ref(), id) {
            return Resp::error(409, "not_opted_in", "turn the opt-in on first");
        }
        match ss::start(
            &self.subs,
            a,
            Arc::clone(&self.sign_in_runner),
            Arc::clone(&self.secrets),
            unix_ms(),
        ) {
            Ok(()) => {
                let who = self.current_actor.chain();
                self.chain_event(&who, "subscription.sign_in_started", Some(id), a.engine);
                Resp::json(202, &json!({ "id": id, "sign_in": "starting" }))
            }
            Err(_) => Resp::error(409, "in_progress", "a sign-in is already going"),
        }
    }

    fn subscription_sign_in_state(&self, id: &str) -> Resp {
        if ss::adapter(id).is_none() {
            return not_offered();
        }
        let flow = ss_lock(&self.subs).get(id).cloned();
        let Some(f) = flow else {
            return Resp::json(200, &json!({ "id": id, "sign_in": null }));
        };
        let mut v = json!({ "id": id, "sign_in": f.phase.word(), "started_ms": f.started_ms });
        match &f.phase {
            Phase::Waiting { link, code } => {
                v["link"] = json!(link);
                v["code"] = json!(code);
            }
            Phase::Failed(why) => v["reason"] = json!(why),
            _ => {}
        }
        Resp::json(200, &v)
    }

    fn subscription_revoke(&mut self, id: &str) -> Resp {
        let Some(a) = ss::adapter(id) else {
            return not_offered();
        };
        if let Err(e) = ss::revoke(self.secrets.as_ref(), id) {
            return Resp::error(500, "store_unavailable", &e);
        }
        ss_lock(&self.subs).remove(id);
        let holding = self.runs.host.runs_holding(id);
        let who = self.current_actor.chain();
        self.chain_event(&who, "subscription.revoked", Some(id), a.engine);
        Resp::json(
            200,
            &json!({
                "id": id,
                "opted_in": false,
                "signed_in": false,
                "runs_holding": holding,
                "revoke_at": a.revoke_at,
            }),
        )
    }

    /// Called from `tick`: write each sign-in that ended to the audit chain, once.
    pub(super) fn tick_subscriptions(&mut self) {
        let ended: Vec<(String, &'static str)> = {
            let mut f = ss_lock(&self.subs);
            f.iter_mut()
                .filter(|(_, x)| !x.audited && matches!(x.phase, Phase::Done | Phase::Failed(_)))
                .map(|(id, x)| {
                    x.audited = true;
                    let what = match x.phase {
                        Phase::Done => "subscription.sign_in_completed",
                        _ => "subscription.sign_in_failed",
                    };
                    (id.clone(), what)
                })
                .collect()
        };
        for (id, what) in ended {
            let detail = match ss_lock(&self.subs).get(&id).map(|x| x.phase.clone()) {
                Some(Phase::Failed(why)) => why.to_string(),
                _ => String::new(),
            };
            self.chain_event("supervisor", what, Some(&id), &detail);
        }
        for (run, box_name, sub) in std::mem::take(&mut self.runs.host.handoffs) {
            self.chain_event(
                "supervisor",
                "subscription.handed_to_run",
                Some(&run),
                &format!("{sub} box={box_name}"),
            );
        }
    }
}

fn ss_lock(
    f: &ss::Flows,
) -> std::sync::MutexGuard<'_, std::collections::BTreeMap<String, ss::Flow>> {
    f.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn not_offered() -> Resp {
    Resp::error(
        404,
        "not_offered",
        "that subscription cannot be handed to an engine's runs (see Settings, Models)",
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::*;
    use crate::secrets::{MemorySecrets, SecretStore};

    const SENTINEL: &str = "SENTINEL-chatgpt-refresh-91c2";

    struct Fake;
    impl ss::DeviceSignIn for Fake {
        fn run(
            &self,
            _: &[&str],
            env: &[(String, String)],
            _: std::time::Instant,
            line: &mut dyn FnMut(&str),
        ) -> Result<bool, &'static str> {
            line("Open https://auth.openai.com/codex/device and enter QRST-4321");
            let home = &env.iter().find(|(k, _)| k == "CODEX_HOME").unwrap().1;
            std::fs::write(
                std::path::Path::new(home).join("auth.json"),
                format!("{{\"refresh_token\":\"{SENTINEL}\"}}"),
            )
            .unwrap();
            Ok(true)
        }
    }

    fn app(secrets: Arc<MemorySecrets>, dir: &std::path::Path) -> App {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7878);
        let mut a = App::new(
            Box::new(ozbox_provider_fake::open(dir.join("state"))),
            true,
            addr,
            "tok".into(),
        )
        .with_secrets(secrets)
        .with_task_store(Some(dir.join("tasks.json")));
        a.on_a_box = false;
        a.sign_in_runner = Arc::new(Fake);
        a
    }

    fn call(a: &mut App, method: &str, path: &str, body: Value) -> (u16, String) {
        let mut headers = HashMap::new();
        headers.insert("host".to_string(), "127.0.0.1:7878".to_string());
        headers.insert("authorization".to_string(), "Bearer tok".to_string());
        let r = a.handle(&Req {
            method: method.into(),
            path: path.into(),
            query: String::new(),
            headers,
            body: if body.is_null() {
                vec![]
            } else {
                body.to_string().into_bytes()
            },
        });
        (r.status, String::from_utf8_lossy(&r.body).into_owned())
    }

    fn wait_done(a: &mut App) {
        for _ in 0..200 {
            let (_, b) = call(
                a,
                "GET",
                "/v1/models/subscriptions/codex-chatgpt/sign-in",
                Value::Null,
            );
            if b.contains("\"done\"") || b.contains("\"failed\"") {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("the sign-in did not end");
    }

    #[test]
    fn opt_in_needs_the_typed_confirmation_and_only_offered_engines_have_one() {
        let d = tempfile::tempdir().unwrap();
        let s = Arc::new(MemorySecrets::default());
        let mut a = app(s.clone(), d.path());
        let (st, b) = call(&mut a, "GET", "/v1/models/subscriptions", Value::Null);
        assert_eq!(st, 200);
        let v: Value = serde_json::from_str(&b).unwrap();
        assert_eq!(v["subscriptions"].as_array().unwrap().len(), 1);
        assert_eq!(v["subscriptions"][0]["opted_in"], false);
        for bad in [
            json!({}),
            json!({"confirm":"yes"}),
            json!({"confirm":"CODEX-CHATGPT"}),
        ] {
            let (st, _) = call(
                &mut a,
                "POST",
                "/v1/models/subscriptions/codex-chatgpt/opt-in",
                bad,
            );
            assert_eq!(st, 400);
        }
        assert!(!ss::opted_in(s.as_ref(), "codex-chatgpt"));
        // a sign-in cannot start before the opt-in
        let (st, _) = call(
            &mut a,
            "POST",
            "/v1/models/subscriptions/codex-chatgpt/sign-in",
            Value::Null,
        );
        assert_eq!(st, 409);
        // no opt-in exists for a vendor whose terms forbid it
        for id in [
            "claude-code-claude",
            "opencode-google",
            "gemini-cli-google",
            "aider-none",
            "opencode-copilot",
        ] {
            let (st, _) = call(
                &mut a,
                "POST",
                &format!("/v1/models/subscriptions/{id}/opt-in"),
                json!({"confirm": id}),
            );
            assert_eq!(st, 404, "{id}");
        }
        let (st, _) = call(
            &mut a,
            "POST",
            "/v1/models/subscriptions/codex-chatgpt/opt-in",
            json!({"confirm":"codex-chatgpt"}),
        );
        assert_eq!(st, 200);
        assert!(ss::opted_in(s.as_ref(), "codex-chatgpt"));
    }

    #[test]
    fn on_a_box_with_no_sign_in_the_opt_in_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let s = Arc::new(MemorySecrets::default());
        let mut a = app(s.clone(), d.path());
        a.on_a_box = true;
        let (st, _) = call(
            &mut a,
            "POST",
            "/v1/models/subscriptions/codex-chatgpt/opt-in",
            json!({"confirm":"codex-chatgpt"}),
        );
        assert_eq!(st, 403);
        assert!(!ss::opted_in(s.as_ref(), "codex-chatgpt"));
    }

    #[test]
    fn sign_in_then_revoke_and_the_sign_in_is_never_in_an_answer_or_the_audit_chain() {
        let d = tempfile::tempdir().unwrap();
        let s = Arc::new(MemorySecrets::default());
        let mut a = app(s.clone(), d.path());
        let mut seen = String::new();
        let (st, b) = call(
            &mut a,
            "POST",
            "/v1/models/subscriptions/codex-chatgpt/opt-in",
            json!({"confirm":"codex-chatgpt"}),
        );
        assert_eq!(st, 200);
        seen.push_str(&b);
        let (st, b) = call(
            &mut a,
            "POST",
            "/v1/models/subscriptions/codex-chatgpt/sign-in",
            Value::Null,
        );
        assert_eq!(st, 202, "{b}");
        seen.push_str(&b);
        wait_done(&mut a);
        let (_, b) = call(
            &mut a,
            "GET",
            "/v1/models/subscriptions/codex-chatgpt/sign-in",
            Value::Null,
        );
        assert!(b.contains("\"done\""), "{b}");
        seen.push_str(&b);
        a.tick_subscriptions();
        assert!(ss::load_login(s.as_ref(), "codex-chatgpt")
            .unwrap()
            .unwrap()
            .contains(SENTINEL));
        let (_, b) = call(&mut a, "GET", "/v1/models/subscriptions", Value::Null);
        assert!(b.contains("\"signed_in\":true"));
        seen.push_str(&b);
        let (_, b) = call(&mut a, "GET", "/v1/models/catalog", Value::Null);
        seen.push_str(&b);
        let (st, b) = call(
            &mut a,
            "DELETE",
            "/v1/models/subscriptions/codex-chatgpt",
            Value::Null,
        );
        assert_eq!(st, 200);
        assert!(b.contains("revoke_at"));
        seen.push_str(&b);
        assert!(!ss::signed_in(s.as_ref(), "codex-chatgpt"));
        assert!(!ss::opted_in(s.as_ref(), "codex-chatgpt"));
        assert!(s
            .all_names()
            .iter()
            .all(|n| !n.starts_with("subscription-")));
        let (_, chain) = call(&mut a, "GET", "/v1/audit", Value::Null);
        for want in [
            "subscription.opted_in",
            "subscription.sign_in_started",
            "subscription.sign_in_completed",
            "subscription.revoked",
        ] {
            assert!(chain.contains(want), "{want} missing from the audit chain");
        }
        seen.push_str(&chain);
        assert!(!seen.contains(SENTINEL), "the sign-in reached an answer");
        assert!(!s.exists("subscription-login-codex-chatgpt").unwrap());
    }
}
