//! `/v1/models/...` beyond the provider list: the provider kinds and their set-up fields, the free "list models"
//! check, per-model price data, usage and spend, and local AI on a GPU box (plan, then apply).
//!
//! Nothing here answers with a key. Listing models sends no prompt and costs nothing.

use ozbox_core::{BoxName, BoxState};
use serde::Deserialize;
use serde_json::{json, Value};

use super::{unix_ms, App, Resp};
use crate::local_ai::{self, Runtime};
use crate::model_engines;
use crate::model_prices;
use crate::model_providers as mp;
use crate::model_usage;
use crate::models;

fn model_ok(m: &str) -> bool {
    !m.is_empty()
        && m.len() <= 100
        && m.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b':' | b'/' | b'-'))
}

fn parse<T: serde::de::DeserializeOwned>(b: &[u8]) -> Result<T, Resp> {
    serde_json::from_slice(b)
        .map_err(|e| Resp::error(400, "bad_request", &format!("invalid request: {e}")))
}

impl App {
    /// `GET /v1/models/catalog`: what a provider card offers, and the engines.
    pub(super) fn models_catalog(&self) -> Resp {
        let kinds: Vec<Value> = mp::ALL
            .iter()
            .map(|k| {
                json!({
                    "id": mp::kind_id(*k),
                    "own_cloud": mp::own_cloud(*k),
                    "key_optional": *k == crate::settings::ModelKind::OpenaiCompatible,
                    "suggested_models": mp::suggested_models(*k),
                })
            })
            .collect();
        Resp::json(
            200,
            &json!({
                "kinds": kinds,
                "engines": model_engines::rows(),
                "price_table_as_of": model_prices::TABLE_AS_OF,
            }),
        )
    }

    fn price_json(&self, id: &str, model: &str) -> Value {
        let Some(p) = self.settings.models.providers.iter().find(|p| p.id == id) else {
            return Value::Null;
        };
        match model_prices::lookup(&self.settings.models, p, model) {
            Some(pr) => {
                let age = pr
                    .as_of
                    .as_deref()
                    .and_then(|a| model_prices::age_months(a, unix_ms()));
                let mut v = serde_json::to_value(&pr).unwrap_or(Value::Null);
                v["age_months"] = json!(age);
                v
            }
            None => Value::Null,
        }
    }

    /// `GET /v1/models/<id>/price?model=`
    pub(super) fn model_price(&self, id: &str, query: &str) -> Resp {
        if !self.settings.models.providers.iter().any(|p| p.id == id) {
            return Resp::error(404, "not_found", "no such model provider");
        }
        let q = super::parse_query(query);
        let Some(m) = q.get("model").filter(|m| model_ok(m)) else {
            return Resp::error(400, "no_model", "name a model");
        };
        Resp::json(200, &json!({ "model": m, "price": self.price_json(id, m) }))
    }

    /// `POST /v1/models/<id>/list`: the provider's own list of models. Free.
    pub(super) fn list_provider_models(&self, id: &str) -> Resp {
        let Some(p) = self.settings.models.providers.iter().find(|p| p.id == id) else {
            return Resp::error(404, "not_found", "no such model provider");
        };
        if let Some(host) = p.hosted_on.as_deref() {
            return self.list_hosted(id, host);
        }
        match models::list_models(self.http.as_ref(), self.secrets.as_ref(), p) {
            Ok(r) => {
                model_prices::remember_live(r.live_prices.clone(), unix_ms());
                let with_prices: Vec<Value> = r
                    .models
                    .iter()
                    .map(|m| json!({ "id": m, "price": self.price_json(id, m) }))
                    .collect();
                Resp::json(
                    200,
                    &json!({ "result": {
                        "ok": r.ok, "status": r.status, "latency_ms": r.latency_ms,
                        "detail": r.detail, "models": r.models, "priced": with_prices,
                    } }),
                )
            }
            Err(e) => Resp::error(409, "not_ready", &e),
        }
    }

    /// A local endpoint on a box is asked through that box's daemon: the server on it listens on loopback only.
    fn list_hosted(&self, id: &str, host: &str) -> Resp {
        let rec = match self.record(host) {
            Ok(r) => r,
            Err(r) => return r,
        };
        let runtime = self
            .settings
            .models
            .providers
            .iter()
            .find(|p| p.id == id)
            .and_then(|p| p.base_url.as_deref())
            .map(|u| {
                if u.contains(":8000") {
                    "vllm"
                } else {
                    "ollama"
                }
            })
            .unwrap_or("ollama");
        match self
            .agent
            .local_ai(&rec, &json!({ "action": "list", "runtime": runtime }))
        {
            Ok(v) => {
                let list: Vec<String> = v["models"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|m| m.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                let priced: Vec<Value> = list
                    .iter()
                    .map(|m| json!({ "id": m, "price": self.price_json(id, m) }))
                    .collect();
                Resp::json(
                    200,
                    &json!({ "result": { "ok": true, "status": null, "latency_ms": 0,
                        "detail": format!("Connected through {host}. It holds {} model(s).", list.len()),
                        "models": list, "priced": priced } }),
                )
            }
            Err(e) => Resp::json(
                200,
                &json!({ "result": { "ok": false, "status": null, "latency_ms": 0,
                    "detail": e.to_string(), "models": [], "priced": [] } }),
            ),
        }
    }

    /// `GET /v1/models/usage?days=`: tokens and estimated cost by day, provider, model, box and engine.
    pub(super) fn models_usage(&self, query: &str) -> Resp {
        let q = super::parse_query(query);
        let days = q
            .get("days")
            .and_then(|d| d.parse::<u32>().ok())
            .unwrap_or(30);
        let now = unix_ms();
        let records = self
            .settings_path
            .as_deref()
            .map(|p| model_usage::read(&model_usage::path_for(p), now))
            .unwrap_or_default();
        let s = model_usage::summarize(&self.settings.models, &records, now, days);
        let caps: Vec<Value> = self
            .settings
            .models
            .providers
            .iter()
            .filter_map(|p| {
                p.monthly_cap_usd.map(|cap| {
                    let spent = model_usage::month_spend_usd(&self.settings.models, &records, &p.id, now);
                    json!({ "provider_id": p.id, "cap_usd": cap, "spent_usd": spent, "reached": model_usage::cap_reached(&self.settings.models, &records, &p.id, now) })
                })
            })
            .collect();
        Resp::json(
            200,
            &json!({
                "usage": s,
                "caps": caps,
                "recorded": self.settings_path.is_some(),
                "note": "Costs are estimates from public prices and the token counts the providers reported.",
            }),
        )
    }

    // ---------- local AI ----------

    pub(super) fn box_local_ai(
        &mut self,
        name: &str,
        method: &str,
        rest: &[&str],
        body: &[u8],
    ) -> Resp {
        match (method, rest) {
            ("GET", []) => self.local_ai_status(name),
            ("POST", ["plan"]) => self.local_ai_plan(name, body),
            ("POST", ["apply"]) => self.local_ai_apply(name, body),
            ("GET", ["recommend"]) => self.local_ai_recommend(name),
            (_, [] | ["plan"] | ["apply"] | ["recommend"]) => {
                Resp::error(405, "method_not_allowed", "method not allowed")
            }
            _ => Resp::error(404, "not_found", "no such endpoint"),
        }
    }

    /// `GET /v1/models/local`: the curated list and the local providers already registered.
    pub(super) fn models_local(&self) -> Resp {
        let registered: Vec<Value> = self
            .settings
            .models
            .providers
            .iter()
            .filter(|p| p.local_endpoint)
            .map(|p| json!({ "id": p.id, "label": p.label, "hosted_on": p.hosted_on, "base_url": p.base_url }))
            .collect();
        let mut v = local_ai::catalog_json();
        v["registered"] = json!(registered);
        Resp::json(200, &v)
    }

    fn running_gpu_box(&self, name: &str) -> Result<ozbox_core::BoxRecord, Resp> {
        let rec = self.record(name)?;
        if rec.state != BoxState::Running {
            return Err(Resp::error(
                409,
                "box_not_running",
                "the box must be running to manage its local models",
            ));
        }
        Ok(rec)
    }

    fn runtime_installed(&self, rec: &ozbox_core::BoxRecord, runtime: Runtime) -> bool {
        self.agent
            .tools(rec, "GET", &[], &[])
            .ok()
            .filter(|(s, _)| *s == 200)
            .and_then(|(_, v)| v["tools"].as_array().cloned())
            .is_some_and(|a| {
                a.iter()
                    .any(|t| t["id"] == runtime.tool_id() && t["installed"] == true)
            })
    }

    fn local_ai_status(&self, name: &str) -> Resp {
        let rec = match self.running_gpu_box(name) {
            Ok(r) => r,
            Err(r) => return r,
        };
        let spec = rec.spec.size.spec();
        let runtimes: Vec<Value> = [Runtime::Ollama, Runtime::Vllm]
            .into_iter()
            .map(|rt| {
                let installed = self.runtime_installed(&rec, rt);
                let models: Vec<String> = if installed {
                    self.agent
                        .local_ai(&rec, &json!({ "action": "list", "runtime": rt.id() }))
                        .ok()
                        .and_then(|v| v["models"].as_array().cloned())
                        .map(|a| a.iter().filter_map(|m| m.as_str().map(str::to_string)).collect())
                        .unwrap_or_default()
                } else {
                    Vec::new()
                };
                json!({ "id": rt.id(), "tool_id": rt.tool_id(), "installed": installed, "models": models,
                        "endpoint": rt.endpoint(), "registered": self.settings.models.providers.iter()
                            .any(|p| p.id == local_ai::provider_id(name, rt)) })
            })
            .collect();
        // downloads in progress on the box, with how far each has got (none from a box that does not say)
        let pulls = self
            .agent
            .local_ai(&rec, &json!({ "action": "status" }))
            .ok()
            .and_then(|v| v["status"]["pulls"].as_array().cloned())
            .unwrap_or_default();
        Resp::json(
            200,
            &json!({ "source": self.data_source(), "box": name, "gpus": spec.gpus, "gpu_memory_gb": spec.gpu_memory_gb,
                     "work_disk_gb": rec.spec.work_disk_gb, "runtimes": runtimes, "pulls": pulls }),
        )
    }

    fn free_disk_gb(&self, rec: &ozbox_core::BoxRecord) -> Option<f64> {
        let s = self.agent.metrics_now(rec, unix_ms()).ok()?;
        (s.disk_total_bytes > 0).then(|| s.disk_free_bytes as f64 / 1_073_741_824.0)
    }

    fn make_plan(
        &self,
        name: &str,
        body: &[u8],
    ) -> Result<(local_ai::Plan, Runtime, ozbox_core::BoxRecord), Resp> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct B {
            runtime: String,
            model: String,
            #[serde(default)]
            plan_hash: Option<String>,
            #[serde(default)]
            confirm: bool,
            #[serde(default)]
            install: bool,
        }
        let mut b: B = parse(body)?;
        let _ = (&b.plan_hash, b.confirm, b.install);
        let rt = Runtime::parse(&b.runtime)
            .ok_or_else(|| Resp::error(400, "bad_request", "the runtime is ollama or vllm"))?;
        let rec0 = if b.model == "auto" {
            Some(self.running_gpu_box(name)?)
        } else {
            None
        };
        if let Some(rec) = &rec0 {
            // "auto" is the model this box can run best: the largest Ollama model that fits its memory and free disk.
            let pick = local_ai::recommend(rec, self.free_disk_gb(rec)).ok_or_else(|| {
                Resp::error(
                    409,
                    "not_possible",
                    "no local model fits this box's memory and free disk; resize the box or free some space",
                )
            })?;
            b.model = pick.id.to_string();
        }
        if !model_ok(&b.model) {
            return Err(Resp::error(
                400,
                "no_model",
                "that model name has characters that are not allowed",
            ));
        }
        BoxName::new(name).map_err(|e| Resp::from_core(&e))?;
        let rec = self.running_gpu_box(name)?;
        let installed = self.runtime_installed(&rec, rt);
        let plan = local_ai::plan(&rec, rt, &b.model, installed, self.free_disk_gb(&rec))
            .map_err(|e| Resp::error(409, "not_possible", &e))?;
        Ok((plan, rt, rec))
    }

    /// `GET .../local-ai/recommend`: the model this box can run best, and its plan.
    fn local_ai_recommend(&self, name: &str) -> Resp {
        let body = json!({ "runtime": "ollama", "model": "auto" }).to_string();
        match self.make_plan(name, body.as_bytes()) {
            Ok((p, _, _)) => Resp::json(
                200,
                &json!({ "model": p.model, "label": p.label, "plan": p }),
            ),
            Err(r) => r,
        }
    }

    fn local_ai_plan(&self, name: &str, body: &[u8]) -> Resp {
        match self.make_plan(name, body) {
            Ok((p, _, _)) => Resp::json(200, &json!({ "plan": p })),
            Err(r) => r,
        }
    }

    fn local_ai_apply(&mut self, name: &str, body: &[u8]) -> Resp {
        #[derive(Deserialize)]
        struct H {
            plan_hash: Option<String>,
            confirm: Option<bool>,
            install: Option<bool>,
        }
        let h: H = match parse(body) {
            Ok(h) => h,
            Err(r) => return r,
        };
        if h.confirm != Some(true) {
            return Resp::error(
                400,
                "confirm_required",
                "review the plan and confirm it to download the model",
            );
        }
        let (plan, rt, rec) = match self.make_plan(name, body) {
            Ok(x) => x,
            Err(r) => return r,
        };
        if h.plan_hash.as_deref() != Some(plan.hash.as_str()) {
            return Resp::error(
                409,
                "stale_plan",
                "the box changed since the plan was made; review a fresh plan",
            );
        }
        if let Some(why) = &plan.blocked {
            // One click may install the runtime first, but only when that is the only thing in the way.
            if !(h.install == Some(true) && plan.install_only) {
                return Resp::error(409, "not_possible", why);
            }
            if !super::tools_routes::install_chosen(
                self.agent.as_ref(),
                &rec,
                &[rt.tool_id().to_string()],
            ) {
                return Resp::error(
                    502,
                    "install_failed",
                    "the box could not install the runtime; try again from Tools",
                );
            }
            self.log_activity("install local runtime", name, None, rt.id());
        }
        if let Some(p) = self
            .settings
            .models
            .providers
            .iter()
            .find(|p| p.id == plan.provider_id)
        {
            if p.hosted_on.as_deref() != Some(name) {
                return Resp::error(409, "id_taken", "another provider already uses that name");
            }
        } else if self.settings.models.providers.len() >= 10 {
            return Resp::error(
                409,
                "too_many",
                "at most 10 model providers; remove one first",
            );
        }
        // A real box starts the download and answers at once (a model is gigabytes); the demo box has it already.
        let pulling = match self.agent.local_ai(
            &rec,
            &json!({ "action": "pull", "runtime": rt.id(), "model": plan.model }),
        ) {
            Ok(v) if v["ok"] == true => v["state"] == "pulling",
            Ok(v) => {
                let m = v["message"]
                    .as_str()
                    .unwrap_or("the box could not pull that model");
                return Resp::error(502, "pull_failed", m);
            }
            Err(e) => return Self::agent_error(&e),
        };
        let mut next = self.settings.clone();
        if !next
            .models
            .providers
            .iter()
            .any(|p| p.id == plan.provider_id)
        {
            next.models
                .providers
                .push(local_ai::provider_for(&plan, rt));
        }
        if let Err(e) = next.validate() {
            return Resp::error(400, "invalid_settings", &e.to_string());
        }
        if let Some(p) = &self.settings_path {
            if let Err(e) = next.save_to(p) {
                return Resp::error(500, "cannot_save", &e.to_string());
            }
        }
        self.settings = next;
        self.log_activity(
            "pull local model",
            name,
            None,
            if pulling { "downloading" } else { "pulled" },
        );
        Resp::json(
            200,
            &json!({ "provider_id": plan.provider_id, "endpoint": plan.endpoint, "model": plan.model, "pulling": pulling }),
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;

    use ozbox_core::{BoxName, BoxSpec, GpuKind, Operation, Size};

    use super::*;
    use crate::netguard::FakeHttp;
    use crate::secrets::{MemorySecrets, SecretStore};
    use crate::serve::Req;
    use crate::settings::{ModelKind, ModelProvider};

    struct Rig {
        app: App,
        http: Arc<FakeHttp>,
        secrets: Arc<MemorySecrets>,
        dir: tempfile::TempDir,
    }

    fn rig() -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let http = Arc::new(FakeHttp::default());
        let secrets = Arc::new(MemorySecrets::default());
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7878);
        let mut settings = crate::settings::Settings::default();
        settings.models.providers.push(ModelProvider {
            id: "oa".into(),
            kind: ModelKind::Openai,
            label: "OpenAI".into(),
            base_url: None,
            local_endpoint: false,
            monthly_cap_usd: Some(1.0),
            region: None,
            resource: None,
            hosted_on: None,
        });
        let app = App::new(
            Box::new(ozbox_provider_fake::open(dir.path().join("state"))),
            true,
            addr,
            "tok".into(),
        )
        .with_http(http.clone())
        .with_secrets(secrets.clone())
        .with_settings(settings, Some(dir.path().join("settings.json")));
        Rig {
            app,
            http,
            secrets,
            dir,
        }
    }

    fn call(a: &mut App, method: &str, path: &str, body: Value) -> (u16, Value) {
        let (path, query) = path.split_once('?').unwrap_or((path, ""));
        let mut headers = HashMap::new();
        headers.insert("host".to_string(), "127.0.0.1:7878".to_string());
        headers.insert("authorization".to_string(), "Bearer tok".to_string());
        let r = a.handle(&Req {
            method: method.into(),
            path: path.into(),
            query: query.into(),
            headers,
            body: if body.is_null() {
                vec![]
            } else {
                body.to_string().into_bytes()
            },
        });
        (
            r.status,
            serde_json::from_slice(&r.body).unwrap_or_default(),
        )
    }

    fn make_box(a: &App, name: &str, size: Size) {
        let spec = BoxSpec::new(BoxName::new(name).unwrap(), size);
        let p = a.provider.plan(&Operation::Create { spec }).unwrap();
        a.provider.apply(&p).unwrap();
    }

    #[test]
    fn the_catalog_lists_every_provider_type_and_engine() {
        let mut r = rig();
        let (s, v) = call(&mut r.app, "GET", "/v1/models/catalog", Value::Null);
        assert_eq!(s, 200);
        assert_eq!(v["kinds"].as_array().unwrap().len(), 11);
        assert!(v["kinds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|k| k["id"] == "bedrock" && k["own_cloud"] == true));
        assert_eq!(v["engines"].as_array().unwrap().len(), 5);
        // the engines with an adapter run on a box; the others say they do not yet (ADR 0056)
        let runs: Vec<&str> = v["engines"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["runs"] == true)
            .map(|e| e["id"].as_str().unwrap())
            .collect();
        assert_eq!(runs, ["claude-code", "codex", "gemini-cli"]);
    }

    #[test]
    fn listing_models_is_free_priced_as_an_estimate_and_never_echoes_the_key() {
        let mut r = rig();
        let (s, v) = call(&mut r.app, "POST", "/v1/models/oa/list", Value::Null);
        assert_eq!(
            (s, v["error"].as_str().is_some()),
            (409, true),
            "no key yet: {v}"
        );
        assert!(r.http.requests().is_empty());
        r.secrets.set("model-key-oa", "sk-SENTINEL-4242").unwrap();
        r.http
            .reply(200, r#"{"data":[{"id":"gpt-4o"},{"id":"brand-new"}]}"#);
        let (s, v) = call(&mut r.app, "POST", "/v1/models/oa/list", Value::Null);
        assert_eq!(s, 200, "{v}");
        let res = &v["result"];
        assert_eq!(res["ok"], true);
        let priced = res["priced"].as_array().unwrap();
        assert_eq!(priced[0]["id"], "brand-new");
        assert!(
            priced[0]["price"].is_null(),
            "an unknown model has no price, not a guess"
        );
        assert_eq!(priced[1]["price"]["estimate"], true);
        assert!(priced[1]["price"]["source"]
            .as_str()
            .unwrap()
            .starts_with("https://"));
        assert_eq!(r.http.requests()[0].method, "GET");
        r.http
            .reply(401, r#"{"error":{"message":"bad key sk-SENTINEL-4242"}}"#);
        let (_, v) = call(&mut r.app, "POST", "/v1/models/oa/list", Value::Null);
        assert!(!v.to_string().contains("SENTINEL"), "{v}");
        assert_eq!(v["result"]["ok"], false);
    }

    #[test]
    fn usage_is_read_from_what_runs_recorded_and_a_cap_is_compared_with_it() {
        let mut r = rig();
        let now = unix_ms();
        let path = crate::model_usage::path_for(&r.dir.path().join("settings.json"));
        crate::model_usage::record(
            &path,
            &ozbox_core::ModelUsage {
                ts_ms: now,
                box_name: Some("dev".into()),
                engine: Some("codex".into()),
                provider_id: "oa".into(),
                model: "gpt-4o".into(),
                input_tokens: 1_000_000,
                output_tokens: 0,
                cached_input_tokens: 0,
            },
        )
        .unwrap();
        let (s, v) = call(&mut r.app, "GET", "/v1/models/usage?days=7", Value::Null);
        assert_eq!(s, 200);
        assert_eq!(v["usage"]["total"]["calls"], 1);
        assert_eq!(v["usage"]["by_day"].as_array().unwrap().len(), 7);
        assert_eq!(v["usage"]["estimate"], true);
        assert_eq!(
            v["caps"][0]["reached"], true,
            "$2.50 estimated against a $1 cap"
        );
        assert_eq!(v["usage"]["by_engine"][0]["key"], "codex");
    }

    #[test]
    fn local_ai_refuses_a_box_without_a_gpu_a_missing_runtime_and_an_unconfirmed_or_stale_apply() {
        let mut r = rig();
        make_box(&r.app, "plain", Size::M);
        let body = json!({ "runtime": "vllm", "model": "Qwen/Qwen2.5-Coder-7B-Instruct" });
        let (s, v) = call(
            &mut r.app,
            "POST",
            "/v1/boxes/plain/local-ai/plan",
            body.clone(),
        );
        assert_eq!(s, 409, "{v}");
        assert!(v["message"].as_str().unwrap().contains("GPU"), "{v}");
        make_box(&r.app, "gpu1", Size::Gpu(GpuKind::Small));
        let (s, v) = call(
            &mut r.app,
            "POST",
            "/v1/boxes/gpu1/local-ai/plan",
            body.clone(),
        );
        assert_eq!(s, 200, "{v}");
        let plan = &v["plan"];
        assert_eq!(plan["can_apply"], false, "vLLM is not installed yet");
        assert_eq!(plan["install_tool"], "vllm");
        assert_eq!(plan["download_gb"], 15.2);
        assert_eq!(plan["estimate"], true);
        let mut apply = body.clone();
        apply["plan_hash"] = plan["hash"].clone();
        let (s, _) = call(
            &mut r.app,
            "POST",
            "/v1/boxes/gpu1/local-ai/apply",
            apply.clone(),
        );
        assert_eq!(s, 400, "needs confirm");
        apply["confirm"] = json!(true);
        let (s, v) = call(
            &mut r.app,
            "POST",
            "/v1/boxes/gpu1/local-ai/apply",
            apply.clone(),
        );
        assert_eq!(s, 409, "{v}");
        assert_eq!(v["code"], "not_possible");
        apply["plan_hash"] = json!("0000000000000000");
        let (s, v) = call(&mut r.app, "POST", "/v1/boxes/gpu1/local-ai/apply", apply);
        assert_eq!((s, v["code"].as_str()), (409, Some("stale_plan")));
        assert!(
            r.app
                .settings
                .models
                .providers
                .iter()
                .all(|p| p.hosted_on.is_none()),
            "nothing was registered"
        );
        let (s, _) = call(
            &mut r.app,
            "POST",
            "/v1/boxes/gpu1/local-ai/plan",
            json!({ "runtime": "x", "model": "m" }),
        );
        assert_eq!(s, 400);
    }

    #[test]
    fn one_click_ollama_on_a_box_without_a_gpu_picks_a_model_that_fits_installs_and_registers_it() {
        let mut r = rig();
        make_box(&r.app, "cpu1", Size::S);
        let (s, v) = call(
            &mut r.app,
            "GET",
            "/v1/boxes/cpu1/local-ai/recommend",
            Value::Null,
        );
        assert_eq!(s, 200, "{v}");
        let plan = &v["plan"];
        assert_eq!(plan["compute"], "cpu");
        assert_eq!(
            v["model"], "llama3.1:8b",
            "the largest that fits 16 GB with 4 kept back"
        );
        assert_eq!(plan["install_only"], true, "only the runtime is missing");
        let mut apply = json!({ "runtime": "ollama", "model": "auto", "plan_hash": plan["hash"], "confirm": true });
        let (s, v) = call(
            &mut r.app,
            "POST",
            "/v1/boxes/cpu1/local-ai/apply",
            apply.clone(),
        );
        assert_eq!(
            (s, v["code"].as_str()),
            (409, Some("not_possible")),
            "installing needs its own yes"
        );
        apply["install"] = json!(true);
        let (s, v) = call(&mut r.app, "POST", "/v1/boxes/cpu1/local-ai/apply", apply);
        assert_eq!(s, 200, "{v}");
        assert_eq!(v["provider_id"], "ollama-cpu1");
        assert!(r
            .app
            .settings
            .models
            .providers
            .iter()
            .any(|p| p.id == "ollama-cpu1" && p.local_endpoint));
        // a model that does not fit this box is refused with the memory in the words
        let (s, v) = call(
            &mut r.app,
            "POST",
            "/v1/boxes/cpu1/local-ai/plan",
            json!({ "runtime": "ollama", "model": "llama3.3:70b" }),
        );
        assert_eq!(s, 200, "{v}");
        assert_eq!(v["plan"]["can_apply"], false);
        assert!(v["plan"]["blocked"]
            .as_str()
            .unwrap()
            .contains("without a GPU"));
    }

    #[test]
    fn a_pulled_model_is_a_private_local_endpoint_listed_through_its_box() {
        let mut r = rig();
        make_box(&r.app, "gpu2", Size::Gpu(GpuKind::Small));
        let rec = r.app.record("gpu2").unwrap();
        let plan = local_ai::plan(
            &rec,
            Runtime::Vllm,
            "Qwen/Qwen2.5-Coder-7B-Instruct",
            true,
            Some(150.0),
        )
        .unwrap();
        assert!(plan.can_apply);
        // the box pulls it, as the daemon would
        let v = r
            .app
            .agent
            .local_ai(
                &rec,
                &json!({ "action": "pull", "runtime": "vllm", "model": plan.model }),
            )
            .unwrap();
        assert_eq!(v["ok"], true);
        let mut s = r.app.settings.clone();
        s.models
            .providers
            .push(local_ai::provider_for(&plan, Runtime::Vllm));
        s.validate().unwrap();
        r.app.settings = s;
        let (st, v) = call(
            &mut r.app,
            "POST",
            &format!("/v1/models/{}/list", plan.provider_id),
            Value::Null,
        );
        assert_eq!(st, 200, "{v}");
        assert_eq!(v["result"]["models"][0], "Qwen/Qwen2.5-Coder-7B-Instruct");
        assert_eq!(v["result"]["priced"][0]["price"]["origin"], "local");
        assert!(
            r.http.requests().is_empty(),
            "a box-hosted endpoint is asked through the box, not over the network"
        );
    }
}
