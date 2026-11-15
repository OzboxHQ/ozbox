//! `/v1/agent-mcp`: may coding agents on this box use the Oz Box tools. One setting, shown and changed here.
//!
//! Turning it on is a loosening: behind a sign-in it needs a passkey shown a moment ago, and on a box with no sign-in it is
//! refused (the same rule as the browser's settings: another process on the box could be holding the access token). Turning
//! it off needs nothing, takes effect before the answer returns, and ends every agent's session. Both are in the audit chain.

use serde_json::Value;

use super::{unix_ms, App, Req, Resp};

impl App {
    pub(super) fn agent_mcp_route(&mut self, req: &Req) -> Resp {
        let now = unix_ms();
        match req.method.as_str() {
            "GET" => Resp::json(200, &crate::agent_mcp::view(self.orch.agent.as_ref(), now)),
            "PUT" => {
                let Some(a) = self.orch.agent.clone() else {
                    return Resp::error(
                        409,
                        "not_available",
                        "the Oz Box tools for coding agents are available on a box's own dashboard",
                    );
                };
                let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
                // `{"standing": true, "minutes": n}` gives terminal agents the person's standing permissions for a while;
                // `{"standing": false}` ends that. Anything else is the on/off switch.
                if let Some(standing) = body.get("standing").and_then(Value::as_bool) {
                    return self.agent_mcp_standing(
                        &a,
                        req,
                        standing,
                        body.get("minutes").and_then(Value::as_u64),
                        now,
                    );
                }
                let Some(enabled) = body.get("enabled").and_then(Value::as_bool) else {
                    return Resp::error(400, "bad_request", "send {\"enabled\": true or false}");
                };
                if enabled {
                    if let Some(r) = self.agent_mcp_step_up(req) {
                        return r;
                    }
                }
                let who = self.who(req);
                match a.set_enabled(enabled, &who, now) {
                    Ok(saved) => {
                        self.chain_event(
                            &format!("person:{who}"),
                            "agent_mcp.settings_changed",
                            None,
                            if enabled { "coding agents on this box may use the Oz Box tools" } else { "coding agents on this box may not use the Oz Box tools; their sessions ended" },
                        );
                        Resp::json(200, &self.agent_mcp_answer(&a, now, saved.persisted))
                    }
                    Err(_) => Resp::error(500, "save_failed", "the setting could not be saved"),
                }
            }
            _ => Resp::error(405, "method_not_allowed", "use GET or PUT"),
        }
    }

    /// Loosening needs a passkey shown a moment ago, and on a box with no sign-in it is refused (the person's computer or root
    /// sets that up). None means go ahead.
    fn agent_mcp_step_up(&mut self, req: &Req) -> Option<Resp> {
        super::roles::step_up_refusal(
            self.step_up_state(req),
            "loosening how coding agents reach the box's tools",
        )
    }

    fn agent_mcp_answer(
        &self,
        a: &std::sync::Arc<crate::agent_mcp::AgentMcp>,
        now: u64,
        saved: bool,
    ) -> Value {
        let mut v = crate::agent_mcp::view(Some(a), now);
        v["saved"] = Value::Bool(saved);
        v
    }

    /// Turning standing permission on is a loosening (the same gate as turning the tools on) and says what it covers; turning
    /// it off needs nothing and takes effect first.
    fn agent_mcp_standing(
        &mut self,
        a: &std::sync::Arc<crate::agent_mcp::AgentMcp>,
        req: &Req,
        on: bool,
        minutes: Option<u64>,
        now: u64,
    ) -> Resp {
        if on {
            if let Some(r) = self.agent_mcp_step_up(req) {
                return r;
            }
        }
        let who = self.who(req);
        let m = on.then(|| minutes.unwrap_or(crate::agent_mcp::STANDING_DEFAULT_MINUTES));
        match a.set_standing(m, &who, now) {
            Ok(saved) => {
                self.chain_event(
                    &format!("person:{who}"),
                    "agent_mcp.standing_changed",
                    None,
                    &match m {
                        Some(m) => format!("terminal agents may use this box's standing permissions for {m} minutes"),
                        None => "terminal agents ask for everything again; their sessions ended".to_string(),
                    },
                );
                Resp::json(200, &self.agent_mcp_answer(a, now, saved.persisted))
            }
            Err(msg) => Resp::error(400, "bad_request", &msg),
        }
    }

    /// Open the agent door once, on a box (or in a test that names a socket). The tool host is built the way a run's is.
    pub(super) fn ensure_agent_mcp(&mut self) {
        let now = unix_ms();
        if self.orch.agent.is_some() || now < self.orch.agent_retry_at_ms {
            return;
        }
        // not a box (or no door folder yet): look again in half a minute rather than never (the folder appears when the
        // dashboard's unit is brought up to date and it restarts, and a bind can fail once and work later)
        self.orch.agent_retry_at_ms = now + 30_000;
        let Some((path, uid)) = crate::agent_mcp::locate() else {
            return;
        };
        if self.orch_ensure_mcp().is_none() {
            return;
        }
        let (Some(tools), Some(store)) = (self.orch.tools.clone(), self.runs.store.clone()) else {
            return;
        };
        let Some(state_dir) = store.path().parent().map(std::path::Path::to_path_buf) else {
            return;
        };
        // this box, by this machine's own identity, and only when this dashboard runs as the box's own
        let this_box_mode = self.fleet_mode() == super::FleetMode::ThisBox;
        let own = crate::this_box::box_name(crate::this_box::Facts::detect().hostname.as_deref());
        let test_socket = std::env::var(crate::agent_mcp::SOCKET_ENV).is_ok();
        // The fleet is listed only where the answer is used: a debug build with the test socket named takes the first
        // listed box. Anywhere else the list was thrown away, and with a cloud provider each listing is an API call.
        let listed: Vec<String> = if cfg!(debug_assertions) && test_socket && !this_box_mode {
            self.provider
                .list()
                .map(|r| r.iter().map(|b| b.spec.name.as_str().to_string()).collect())
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let Some(box_name) =
            crate::agent_mcp::door_box_name(this_box_mode, test_socket, own.as_str(), &listed)
        else {
            return;
        };
        crate::agent_mcp::SettingStore::new(&state_dir).ensure();
        let Ok(listener) = crate::agent_mcp::AgentMcp::bind(&path) else {
            return;
        };
        let a = crate::agent_mcp::AgentMcp::new(
            tools,
            crate::agent_mcp::SettingStore::new(&state_dir),
            &box_name,
            uid,
        );
        a.serve(listener);
        self.orch.agent = Some(a);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::agent_mcp::{AgentMcp, SettingStore};
    use crate::mcp::ToolRunner;
    use crate::orch_tools::{Session, ToolError};
    use serde_json::json;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;

    const TOKEN: &str = "test-token";

    struct Nothing;
    impl ToolRunner for Nothing {
        fn run(&self, _: &Session, _: &str, _: &Value, _: u64) -> Result<Value, ToolError> {
            Ok(json!({}))
        }
    }

    fn app(dir: &std::path::Path, on_a_box: bool, door: bool) -> App {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7878);
        let mut a = App::new(
            Box::new(ozbox_provider_fake::open(dir)),
            true,
            addr,
            TOKEN.into(),
        )
        .with_task_store(Some(dir.join("tasks.json")));
        a.on_a_box = on_a_box;
        if door {
            a.orch.agent = Some(AgentMcp::new(
                Arc::new(Nothing),
                SettingStore::new(dir),
                "main-box",
                1000,
            ));
        }
        a
    }

    fn call(a: &mut App, method: &str, body: Value) -> (u16, Value) {
        let mut headers = HashMap::new();
        headers.insert("host".to_string(), "127.0.0.1:7878".to_string());
        headers.insert("authorization".to_string(), format!("Bearer {TOKEN}"));
        let r = a.handle(&Req {
            method: method.into(),
            path: "/v1/agent-mcp".into(),
            query: String::new(),
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

    #[test]
    fn off_a_boxs_own_dashboard_there_is_no_door_and_nothing_to_change() {
        let d = tempfile::tempdir().unwrap();
        let mut a = app(d.path(), false, false);
        let (s, v) = call(&mut a, "GET", Value::Null);
        assert_eq!((s, v["available"].clone()), (200, json!(false)));
        assert_eq!(call(&mut a, "PUT", json!({ "enabled": false })).0, 409);
    }

    #[test]
    fn it_is_on_by_default_and_turning_it_off_needs_nothing_even_on_a_box_with_no_sign_in() {
        let d = tempfile::tempdir().unwrap();
        let mut a = app(d.path(), true, true);
        let (_, v) = call(&mut a, "GET", Value::Null);
        assert_eq!(
            (v["available"].clone(), v["enabled"].clone()),
            (json!(true), json!(true))
        );
        assert_eq!(v["engines"].as_array().unwrap().len(), 4);
        let (s, v) = call(&mut a, "PUT", json!({ "enabled": false }));
        assert_eq!((s, v["enabled"].clone()), (200, json!(false)));
        assert!(!SettingStore::new(d.path()).load().enabled);
    }

    #[test]
    fn turning_it_on_on_a_box_with_no_sign_in_is_refused_and_says_why() {
        let d = tempfile::tempdir().unwrap();
        let mut a = app(d.path(), true, true);
        call(&mut a, "PUT", json!({ "enabled": false }));
        let (s, v) = call(&mut a, "PUT", json!({ "enabled": true }));
        assert_eq!((s, v["code"].as_str()), (403, Some("sign_in_required")));
        assert!(
            !SettingStore::new(d.path()).load().enabled,
            "a refused change changes nothing"
        );
        // on a computer that is not a box (the person's own), the same request is the person's to make
        let mut b = app(d.path(), false, true);
        let (s, v) = call(&mut b, "PUT", json!({ "enabled": true }));
        assert_eq!((s, v["enabled"].clone()), (200, json!(true)));
    }

    #[test]
    fn a_body_that_is_not_a_yes_or_a_no_and_other_methods_are_refused() {
        let d = tempfile::tempdir().unwrap();
        let mut a = app(d.path(), false, true);
        assert_eq!(call(&mut a, "PUT", json!({ "enabled": "yes" })).0, 400);
        assert_eq!(call(&mut a, "PUT", Value::Null).0, 400);
        assert_eq!(call(&mut a, "DELETE", Value::Null).0, 405);
        assert!(SettingStore::new(d.path()).load().enabled);
    }

    /// giving terminal agents the person's standing permissions is a loosening (the same gate as turning the tools
    /// on, so refused on a box with no sign-in), short by default, bounded, and ending it needs nothing.
    #[test]
    fn standing_permission_is_gated_short_bounded_and_ends_without_a_passkey() {
        let d = tempfile::tempdir().unwrap();
        let mut a = app(d.path(), true, true);
        let (s, v) = call(&mut a, "PUT", json!({ "standing": true }));
        assert_eq!((s, v["code"].as_str()), (403, Some("sign_in_required")));
        assert_eq!(SettingStore::new(d.path()).load().standing_until_ms, 0);
        // on a computer that is not a box it is the person's to give, 30 minutes unless they say
        let mut b = app(d.path(), false, true);
        let (s, v) = call(&mut b, "PUT", json!({ "standing": true }));
        assert_eq!(s, 200, "{v}");
        let left = v["standing_until_ms"].as_u64().unwrap() as i64 - unix_ms() as i64;
        assert!(
            (29 * 60_000..=30 * 60_000 + 5_000).contains(&left),
            "{left}"
        );
        assert_eq!(
            call(&mut b, "PUT", json!({ "standing": true, "minutes": 0 })).0,
            400
        );
        assert_eq!(
            call(
                &mut b,
                "PUT",
                json!({ "standing": true, "minutes": 100_000 })
            )
            .0,
            400
        );
        // ending it, even on a box with no sign-in, needs nothing and takes effect first
        let (s, v) = call(&mut a, "PUT", json!({ "standing": false }));
        assert_eq!((s, v["standing_until_ms"].clone()), (200, json!(0)));
        // turning the tools off clears it, and it cannot be given while they are off
        call(&mut b, "PUT", json!({ "standing": true }));
        call(&mut b, "PUT", json!({ "enabled": false }));
        assert_eq!(SettingStore::new(d.path()).load().standing_until_ms, 0);
        assert_eq!(call(&mut b, "PUT", json!({ "standing": true })).0, 400);
    }
}
