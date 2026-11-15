//! The dashboard's "Set up your fleet": the same steps as `ozbox init` (see `crate::init`), one request each. Checks
//! only read. A step that changes something is planned first, the plan is shown, and `apply` runs exactly that plan
//! once; a plan this server did not issue is refused.
//!
//! Routes: `GET /v1/setup`, `POST /v1/setup/{check,plan,apply,finish,sandbox}`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ozbox_core::Provider;
use serde::Deserialize;
use serde_json::{json, Value};

use super::*;
use crate::init::{self, Finding, HttpLatency, Init, InitPaths, Prepared, SetupFile, Target};

const SETUP_PLAN_TTL: Duration = Duration::from_secs(600);
const MAX_SETUP_PLANS: usize = 8;

/// A provider and what goes with it, rebuilt from the configuration after setup changed it.
pub struct Rebuilt {
    pub provider: Box<dyn Provider>,
    pub simulated: bool,
    pub inputs: RouteInputs,
    pub domain: Option<String>,
}

pub type Rebuild = Arc<dyn Fn() -> Result<Rebuilt, String> + Send + Sync>;

#[derive(Default)]
pub struct SetupState {
    pub paths: Option<InitPaths>,
    pub rebuild: Option<Rebuild>,
    issued: HashMap<String, (Prepared, Target, Instant)>,
}

#[derive(Deserialize)]
struct TargetBody {
    provider: String,
    profile: Option<String>,
    region: Option<String>,
}

impl TargetBody {
    fn target(&self) -> Target {
        Target {
            provider: self.provider.clone(),
            profile: self.profile.clone(),
            region: self.region.clone(),
        }
    }
}

#[derive(Deserialize)]
struct CheckBody {
    check: String,
    #[serde(flatten)]
    target: TargetBody,
}

#[derive(Deserialize)]
struct PlanBody {
    step: String,
    #[serde(flatten)]
    target: TargetBody,
}

#[derive(Deserialize)]
struct ApplyBody {
    plan_id: String,
}

#[derive(Deserialize)]
struct FinishBody {
    #[serde(flatten)]
    target: TargetBody,
    #[serde(default)]
    mfa_ack: bool,
}

fn finding(f: &Finding) -> Resp {
    let status = match f.code.as_str() {
        "command_failed" | "apply_failed" | "plugin_download_failed" | "plan_failed" => 502,
        _ => 422,
    };
    let body = serde_json::to_vec(&json!({
        "code": f.code, "message": f.message, "error": f.message, "fix": f.fix,
    }))
    .unwrap_or_default();
    Resp {
        status,
        content_type: "application/json",
        body,
        no_store: true,
        stream: false,
    }
}

fn parse<T: for<'de> Deserialize<'de>>(body: &[u8]) -> Result<T, Resp> {
    serde_json::from_slice(body)
        .map_err(|e| Resp::error(400, "bad_request", &format!("invalid request: {e}")))
}

impl App {
    /// Wire in where setup keeps its files and how to rebuild the provider once it changes.
    pub fn with_setup(mut self, paths: Option<InitPaths>, rebuild: Option<Rebuild>) -> Self {
        self.setup.paths = paths;
        self.setup.rebuild = rebuild;
        self
    }

    /// The machine this provider maps a size to, and its monthly price from the price table (a price the person
    /// entered, else the provider's public list). `null` where either is not known: shown as an em dash, never guessed.
    pub(super) fn size_quote(&self, size: ozbox_core::Size) -> Value {
        let machine = match self.provider_id.as_str() {
            "aws" => ozbox_provider_aws::machine_choice(size).ok(),
            "hcloud" => ozbox_provider_hcloud::machine_choice(size).ok(),
            _ => None,
        }
        .map(|m| m.machine_type);
        let entered = self.settings.price(size).map(|m| (m, "USD".to_string()));
        let listed = machine
            .as_deref()
            .zip(self.prices.book.as_ref())
            .and_then(|(t, b)| {
                b.machine(t, None)
                    .map(|h| (h * crate::pricing::HOURS_PER_MONTH, b.currency.clone()))
            });
        let (monthly, currency) = match entered.or(listed) {
            Some((m, c)) => (Some(m), Some(c)),
            None => (None, None),
        };
        json!({ "machine_type": machine, "monthly": monthly, "currency": currency })
    }

    fn setup_file(&self) -> SetupFile {
        self.setup
            .paths
            .as_ref()
            .map(|p| SetupFile::load(&p.setup))
            .unwrap_or_default()
    }

    fn setup_guardrails(&self) -> init::Guardrails {
        init::guardrails(
            &self.settings,
            self.secrets.as_ref(),
            self.state.telegram.chats.len(),
        )
    }

    /// What `GET /v1/info` says about setup: whether the dashboard should offer the first-run flow.
    pub(super) fn setup_summary(&self) -> Value {
        let file = self.setup_file();
        let configured = self
            .setup
            .paths
            .as_ref()
            .and_then(|p| crate::config::Config::load_from(&p.config).ok())
            .is_some_and(|c| c.provider.is_some());
        json!({
            "available": self.setup.paths.is_some(),
            "completed": file.completed,
            // A box's own dashboard has no fleet to set up: it says "not connected" instead of offering a wizard.
            "needed": self.setup.paths.is_some()
                && !file.completed
                && !configured
                && self.provider_id != crate::this_box::PROVIDER_ID,
            "require_guardrails": file.require_guardrails,
        })
    }

    /// Refuse to create a box that costs money until a budget and an alert channel exist (when setup asked for it).
    pub(super) fn guard_rails(&self, op: &Operation) -> Result<(), Resp> {
        let file = self.setup_file();
        if !file.require_guardrails {
            return Ok(());
        }
        init::require_guardrails(&file, &self.setup_guardrails(), &self.provider_id, op)
            .map_err(|f| finding(&f))
    }

    pub(super) fn setup_route(&mut self, rest: &[&str], req: &Req) -> Resp {
        let Some(paths) = self.setup.paths.clone() else {
            return Resp::error(
                501,
                "not_available",
                "setup is not available on this server",
            );
        };
        let (get, post) = (req.method == "GET", req.method == "POST");
        match rest {
            [] if get => self.setup_status(&paths),
            ["check"] if post => self.setup_check(&paths, &req.body),
            ["plan"] if post => self.setup_plan(&paths, &req.body),
            ["apply"] if post => self.setup_apply(&paths, &req.body),
            ["finish"] if post => self.setup_finish(&paths, &req.body),
            ["sandbox"] if post => self.setup_sandbox(&paths),
            _ => Resp::error(404, "not_found", "no such setup route"),
        }
    }

    fn with_init<R>(&self, paths: &InitPaths, f: impl FnOnce(&Init<'_>) -> R) -> R {
        let latency = HttpLatency(self.http.as_ref());
        let init = Init {
            runner: self.runner.as_ref(),
            http: self.http.as_ref(),
            latency: &latency,
            paths: paths.clone(),
            retry_delay: Duration::from_secs(3),
        };
        f(&init)
    }

    fn setup_status(&self, paths: &InitPaths) -> Resp {
        let file = self.setup_file();
        let cfg = crate::config::Config::load_from(&paths.config).ok();
        let (provider, region, profile, bucket, subnet) = match &cfg {
            Some(c) => {
                let sec = match c.provider.as_deref() {
                    Some("aws") => c.aws.as_ref(),
                    Some("hcloud") => c.hcloud.as_ref(),
                    _ => None,
                };
                (
                    c.provider.clone(),
                    sec.and_then(|s| s.region.clone()),
                    sec.and_then(|s| s.profile.clone()),
                    sec.is_some_and(|s| s.state_bucket.is_some()),
                    sec.is_some_and(|s| s.subnet_id.is_some()),
                )
            }
            None => (None, None, None, false, false),
        };
        Resp::json(
            200,
            &json!({
                "summary": self.setup_summary(),
                "provider": provider,
                "region": region,
                "profile": profile,
                "state_bucket": bucket,
                "network": subnet,
                "mfa_ack": file.mfa_ack,
                "guardrails": self.setup_guardrails(),
                "providers": init::PROVIDERS,
                "hcloud_token_present": std::env::var("HCLOUD_TOKEN").is_ok_and(|t| !t.is_empty()),
            }),
        )
    }

    fn setup_check(&self, paths: &InitPaths, body: &[u8]) -> Resp {
        let b: CheckBody = match parse(body) {
            Ok(b) => b,
            Err(r) => return r,
        };
        let target = b.target.target();
        self.with_init(paths, |init| {
            let result: Result<Value, Finding> = (|| {
                target.validate()?;
                match (target.provider.as_str(), b.check.as_str()) {
                    ("aws", "sign_in") => Ok(json!({ "identity": init.sign_in(&target)? })),
                    ("aws", "permissions") => {
                        init.sign_in(&target)?;
                        Ok(json!({ "report": init.permissions(&target)? }))
                    }
                    ("aws", "regions") => Ok(json!({ "report": init.regions(&target)? })),
                    ("aws", "security") => {
                        let id = init.sign_in(&target)?;
                        Ok(json!({ "report": init.security(&target, &id)? }))
                    }
                    ("hcloud", "sign_in") => {
                        let token = std::env::var("HCLOUD_TOKEN").ok();
                        init.hcloud_sign_in(token.as_deref())?;
                        Ok(json!({
                            "locations": init.hcloud_locations(token.as_deref().unwrap_or("")),
                        }))
                    }
                    _ => Err(Finding::new(
                        "bad_request",
                        "that check does not exist for this provider".into(),
                    )),
                }
            })();
            match result {
                Ok(v) => Resp::json(200, &v),
                Err(f) => finding(&f),
            }
        })
    }

    fn setup_plan(&mut self, paths: &InitPaths, body: &[u8]) -> Resp {
        let b: PlanBody = match parse(body) {
            Ok(b) => b,
            Err(r) => return r,
        };
        let target = b.target.target();
        let made: Result<Prepared, Finding> = self.with_init(paths, |init| {
            target.validate()?;
            if target.provider != "aws" {
                return Err(Finding::new(
                    "unsupported",
                    "this provider has no steps to plan here".into(),
                ));
            }
            let id = init.sign_in(&target)?;
            match b.step.as_str() {
                "state_bucket" => init.plan_bucket(&target, &id.account),
                "network" => init.plan_network(&target, &id.account),
                _ => Err(Finding::new(
                    "bad_request",
                    "that step does not exist".into(),
                )),
            }
        });
        let prepared = match made {
            Ok(p) => p,
            Err(f) => return finding(&f),
        };
        let now = Instant::now();
        self.setup
            .issued
            .retain(|_, v| now.duration_since(v.2) < SETUP_PLAN_TTL);
        if self.setup.issued.len() >= MAX_SETUP_PLANS {
            return Resp::error(
                429,
                "too_many_plans",
                "too many open setup plans; apply or wait",
            );
        }
        let plan_id = match random_hex(16) {
            Ok(i) => i,
            Err(m) => return Resp::error(500, "internal", &m),
        };
        let mut v = serde_json::to_value(&prepared).unwrap_or(Value::Null);
        if let Some(o) = v.as_object_mut() {
            o.insert("plan_id".into(), json!(plan_id));
            o.insert("expires_in_s".into(), json!(SETUP_PLAN_TTL.as_secs()));
        }
        self.setup.issued.insert(plan_id, (prepared, target, now));
        Resp::json(200, &v)
    }

    fn setup_apply(&mut self, paths: &InitPaths, body: &[u8]) -> Resp {
        let b: ApplyBody = match parse(body) {
            Ok(b) => b,
            Err(r) => return r,
        };
        let Some((prepared, target, at)) = self.setup.issued.remove(&b.plan_id) else {
            return Resp::error(
                409,
                "unknown_plan",
                "this server did not issue that setup plan (or it was already used); plan again",
            );
        };
        if at.elapsed() >= SETUP_PLAN_TTL {
            return Resp::error(409, "stale_plan", "that plan has expired; plan again");
        }
        let res = self.with_init(paths, |init| init.apply(&target, &prepared));
        match res {
            Ok(applied) => {
                self.log_activity(&format!("setup {}", prepared.step), "-", None, "ok");
                Resp::json(200, &json!({ "applied": true, "result": applied }))
            }
            Err(f) => {
                self.log_activity(&format!("setup {}", prepared.step), "-", None, "failed");
                finding(&f)
            }
        }
    }

    fn setup_finish(&mut self, paths: &InitPaths, body: &[u8]) -> Resp {
        let b: FinishBody = match parse(body) {
            Ok(b) => b,
            Err(r) => return r,
        };
        let target = b.target.target();
        let g = self.setup_guardrails();
        let res = self.with_init(paths, |init| init.finish(&target, b.mfa_ack, &g, unix_ms()));
        match res {
            Ok(file) => {
                self.log_activity("setup finished", "-", None, "ok");
                let restart = self.reload_provider();
                Resp::json(
                    200,
                    &json!({ "completed": file.completed, "restart_required": restart }),
                )
            }
            Err(f) => finding(&f),
        }
    }

    fn setup_sandbox(&mut self, paths: &InitPaths) -> Resp {
        let target = Target {
            provider: "fake".into(),
            ..Target::default()
        };
        let g = self.setup_guardrails();
        let res = self.with_init(paths, |init| init.finish(&target, false, &g, unix_ms()));
        match res {
            Ok(_) => {
                self.log_activity("setup sandbox", "-", None, "ok");
                let restart = self.reload_provider();
                Resp::json(
                    200,
                    &json!({ "completed": true, "restart_required": restart }),
                )
            }
            Err(f) => finding(&f),
        }
    }

    /// Switch to the provider the configuration now names. Returns whether a restart is needed instead.
    fn reload_provider(&mut self) -> bool {
        let Some(rebuild) = self.setup.rebuild.clone() else {
            return true;
        };
        match rebuild() {
            Ok(r) => {
                self.provider_id = r.provider.id().to_string();
                self.provider = std::sync::Arc::from(r.provider);
                self.simulated_metrics = r.simulated;
                self.use_demo_telegram(super::demo_telegram::enabled(
                    r.simulated,
                    std::env::var("OZBOX_DEMO_TELEGRAM").ok().as_deref(),
                ));
                self.agent = Arc::from(agent_for_provider(
                    &self.provider_id,
                    r.simulated,
                    r.inputs.clone(),
                ));
                self.route_inputs = r.inputs;
                self.domain = r.domain;
                false
            }
            Err(_) => true,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use ozbox_core::{Output, RecordingRunner};

    use crate::netguard::FakeHttp;

    struct Rig {
        app: App,
        runner: Arc<RecordingRunner>,
        dir: tempfile::TempDir,
    }

    fn rig() -> Rig {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("modules/aws-box")).unwrap();
        std::fs::create_dir_all(dir.path().join("modules/aws-network")).unwrap();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7878);
        let paths = InitPaths {
            config: dir.path().join("config.toml"),
            setup: dir.path().join("setup.json"),
            plugin_cache: dir.path().join("cache"),
            work: dir.path().join("work"),
            modules: dir.path().join("modules"),
        };
        let mut app = App::new(
            Box::new(ozbox_provider_fake::open(dir.path().join("state"))),
            true,
            addr,
            "tok".into(),
        )
        .with_setup(Some(paths), None);
        let runner = Arc::new(RecordingRunner::new());
        app.runner = runner.clone();
        app.http = Arc::new(FakeHttp::default());
        Rig { app, runner, dir }
    }

    fn call(a: &mut App, method: &str, path: &str, body: Value) -> (u16, Value) {
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
        (
            r.status,
            serde_json::from_slice(&r.body).unwrap_or_default(),
        )
    }

    fn out(s: i32, so: &str, se: &str) -> Output {
        Output {
            status: Some(s),
            stdout: so.into(),
            stderr: se.into(),
        }
    }

    const SSO: &str = r#"{"Account":"123456789012","Arn":"arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_Op_1/me"}"#;

    #[test]
    fn first_run_is_needed_until_the_sandbox_or_a_cloud_is_chosen() {
        let mut r = rig();
        let (s, v) = call(&mut r.app, "GET", "/v1/info", Value::Null);
        assert_eq!(s, 200);
        assert_eq!(v["setup"]["needed"], true);
        let (s, v) = call(&mut r.app, "POST", "/v1/setup/sandbox", Value::Null);
        assert_eq!((s, v["completed"].clone()), (200, json!(true)));
        // No way to rebuild the provider in this server, so it says a restart is needed.
        assert_eq!(v["restart_required"], true);
        let (_, v) = call(&mut r.app, "GET", "/v1/info", Value::Null);
        assert_eq!(v["setup"]["needed"], false);
        assert_eq!(v["setup"]["completed"], true);
        assert!(r.runner.calls().is_empty());
    }

    #[test]
    fn a_rebuilt_provider_takes_over_without_a_restart() {
        let mut r = rig();
        let dir = r.dir.path().join("state2");
        r.app.setup.rebuild = Some(Arc::new(move || {
            Ok(Rebuilt {
                provider: Box::new(ozbox_provider_fake::open(dir.clone())),
                simulated: true,
                inputs: RouteInputs::default(),
                domain: None,
            })
        }));
        let (_, v) = call(&mut r.app, "POST", "/v1/setup/sandbox", Value::Null);
        assert_eq!(v["restart_required"], false);
    }

    #[test]
    fn a_checked_sign_in_reports_root_with_a_code_and_a_message() {
        let mut r = rig();
        r.runner.reply(out(
            0,
            r#"{"Account":"123456789012","Arn":"arn:aws:iam::123456789012:root"}"#,
            "",
        ));
        let (s, v) = call(
            &mut r.app,
            "POST",
            "/v1/setup/check",
            json!({ "check": "sign_in", "provider": "aws", "profile": "work" }),
        );
        assert_eq!(s, 422);
        assert_eq!(v["code"], "root_refused");
        assert!(v["message"].as_str().unwrap().contains("root"));
        assert!(v["fix"].is_string());
    }

    #[test]
    fn a_bucket_plan_is_applied_once_and_only_as_issued() {
        let mut r = rig();
        r.runner.reply(out(0, SSO, ""));
        r.runner.reply(out(254, "", "404 Not Found"));
        let body = json!({ "step": "state_bucket", "provider": "aws", "profile": "work", "region": "us-east-1" });
        let (s, plan) = call(&mut r.app, "POST", "/v1/setup/plan", body);
        assert_eq!(s, 200, "{plan}");
        assert_eq!(plan["changes"].as_array().unwrap().len(), 5);
        let before = r.runner.calls().len();
        // Planning ran only the sign-in and the probe.
        assert_eq!(before, 2);
        let id = plan["plan_id"].clone();
        let (s, v) = call(
            &mut r.app,
            "POST",
            "/v1/setup/apply",
            json!({ "plan_id": "0".repeat(32) }),
        );
        assert_eq!((s, v["code"].clone()), (409, json!("unknown_plan")));
        let (s, v) = call(
            &mut r.app,
            "POST",
            "/v1/setup/apply",
            json!({ "plan_id": id }),
        );
        assert_eq!(s, 200, "{v}");
        assert_eq!(v["result"]["bucket"], "ozbox-state-123456789012-us-east-1");
        assert_eq!(r.runner.calls().len() - before, 5);
        let (s, _) = call(
            &mut r.app,
            "POST",
            "/v1/setup/apply",
            json!({ "plan_id": id }),
        );
        assert_eq!(s, 409);
        let (_, st) = call(&mut r.app, "GET", "/v1/setup", Value::Null);
        assert_eq!(st["state_bucket"], true);
        assert_eq!(st["network"], false);
    }

    #[test]
    fn finishing_a_real_cloud_is_refused_until_everything_is_in_place() {
        let mut r = rig();
        let (s, v) = call(
            &mut r.app,
            "POST",
            "/v1/setup/finish",
            json!({ "provider": "aws", "region": "us-east-1", "mfa_ack": true }),
        );
        assert_eq!(s, 422);
        assert_eq!(v["code"], "guardrails_missing");
    }

    #[test]
    fn once_setup_asks_for_it_a_real_cloud_cannot_create_without_a_budget_and_an_alert() {
        let mut r = rig();
        SetupFile {
            completed: true,
            require_guardrails: true,
            ..SetupFile::default()
        }
        .save(&r.dir.path().join("setup.json"))
        .unwrap();
        let op = json!({ "operation": { "op": "create", "spec": { "name": "dev", "size": "S", "work_disk_gb": 20, "image": null, "region": null, "labels": {}, "from_snapshot": null } } });
        // The sandbox is never held back.
        let (s, _) = call(&mut r.app, "POST", "/v1/plans", op.clone());
        assert_eq!(s, 200);
        r.app.provider_id = "aws".into();
        let (s, v) = call(&mut r.app, "POST", "/v1/plans", op);
        assert_eq!((s, v["code"].clone()), (422, json!("guardrails_missing")));
    }

    #[test]
    fn bad_input_is_a_400_or_a_refusal_never_a_command() {
        let mut r = rig();
        let (s, _) = call(&mut r.app, "POST", "/v1/setup/check", json!({ "nope": 1 }));
        assert_eq!(s, 400);
        let (s, v) = call(
            &mut r.app,
            "POST",
            "/v1/setup/check",
            json!({ "check": "sign_in", "provider": "aws", "region": "x; reboot" }),
        );
        assert_eq!((s, v["code"].clone()), (422, json!("bad_region")));
        assert!(r.runner.calls().is_empty());
        assert_eq!(call(&mut r.app, "DELETE", "/v1/setup", Value::Null).0, 404);
    }
}
