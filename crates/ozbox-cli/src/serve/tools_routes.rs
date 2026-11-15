//! The dashboard's view of the tool catalog, a box's tools, and box profiles.
//!
//! Tools are installed by the box's own daemon; this server only forwards (through the box agent: simulated for the demo
//! provider, SSH-forwarded for a real one) and never installs anything itself. Profiles are plain files.

use std::collections::BTreeMap;
use std::path::PathBuf;

use ozbox_catalog::Catalog;
use serde_json::{json, Value};

use super::worker::{Done, Job};
use super::*;
use crate::profiles::{self, Profile, ProfileBox, Store};

/// Where profiles and the tools chosen at create time are kept (`None` = memory only, for tests).
#[derive(Default)]
pub struct ToolsCfg {
    pub profiles_dir: Option<PathBuf>,
    pub pending_path: Option<PathBuf>,
    pub pending: BTreeMap<String, Vec<String>>,
    /// When each box was last tried (milliseconds), so a box that is not up yet is asked about every 30 seconds, not every tick.
    pub tried_ms: BTreeMap<String, u64>,
}

impl ToolsCfg {
    pub fn new(profiles_dir: Option<PathBuf>, pending_path: Option<PathBuf>) -> ToolsCfg {
        let pending = pending_path
            .as_ref()
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        ToolsCfg {
            profiles_dir,
            pending_path,
            pending,
            tried_ms: BTreeMap::new(),
        }
    }

    pub fn save_pending(&self) {
        if let Some(p) = &self.pending_path {
            if let Some(d) = p.parent() {
                let _ = std::fs::create_dir_all(d);
            }
            let _ = std::fs::write(p, serde_json::to_vec(&self.pending).unwrap_or_default());
        }
    }
}

fn catalog() -> Result<Catalog, Resp> {
    ozbox_catalog::embedded().map_err(|e| Resp::error(500, "internal", &e))
}

fn segment_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && s != ".."
        && s != "."
}

impl App {
    pub(super) fn catalog_json(&self) -> Resp {
        match catalog() {
            Ok(c) => Resp::json(200, &json!({ "source": "catalog", "catalog": c })),
            Err(r) => r,
        }
    }

    /// `/v1/boxes/<name>/tools/...`
    pub(super) fn box_tools(&mut self, name: &str, rest: &[&str], req: &Req) -> Resp {
        if rest == ["pending"] {
            return self.pending_tools(name, req);
        }
        if !matches!(req.method.as_str(), "GET" | "POST") || !rest.iter().all(|s| segment_ok(s)) {
            return Resp::error(405, "method_not_allowed", "method not allowed");
        }
        let rec = match self.running_box(name) {
            Ok(r) => r,
            Err(r) => return r,
        };
        let (status, mut v) = match self.agent.tools(&rec, &req.method, rest, &req.body) {
            Ok(x) => x,
            Err(e) => return Self::agent_error(&e),
        };
        if let Some(o) = v.as_object_mut() {
            o.insert("source".into(), json!(self.data_source()));
            if rest.is_empty() && req.method == "GET" {
                o.insert(
                    "pending".into(),
                    json!(self
                        .tools_cfg
                        .pending
                        .get(name)
                        .cloned()
                        .unwrap_or_default()),
                );
            }
        }
        let label = match (req.method.as_str(), rest) {
            ("POST", ["apply"]) if status == 202 => Some("tools apply"),
            ("POST", ["requests", _, "decision"]) if status == 200 => {
                Some("tools request decision")
            }
            _ => None,
        };
        if let Some(l) = label {
            self.log_activity(l, name, None, "ok");
        }
        Resp::json(status, &v)
    }

    fn pending_tools(&mut self, name: &str, req: &Req) -> Resp {
        if let Err(r) = self.record(name) {
            return r;
        }
        match req.method.as_str() {
            "PUT" => {
                let c = match catalog() {
                    Ok(c) => c,
                    Err(r) => return r,
                };
                let items: Vec<String> = serde_json::from_slice::<Value>(&req.body)
                    .ok()
                    .and_then(|v| v["tools"].as_array().cloned())
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                let ids = match c.expand(&items) {
                    Ok(i) => i,
                    Err(m) => return Resp::error(404, "unknown_tool", &m),
                };
                if let Some(t) = ids.iter().filter_map(|i| c.tool(i)).find(|t| !t.verified) {
                    return Resp::error(
                        422,
                        "unverified_tool",
                        &format!(
                            "{} cannot be installed yet: its source is not verified",
                            t.id
                        ),
                    );
                }
                self.tools_cfg.pending.insert(name.to_string(), ids.clone());
                self.tools_cfg.save_pending();
                Resp::json(200, &json!({ "pending": ids }))
            }
            "DELETE" => {
                self.tools_cfg.pending.remove(name);
                self.tools_cfg.save_pending();
                Resp::json(200, &json!({ "pending": Vec::<String>::new() }))
            }
            _ => Resp::error(405, "method_not_allowed", "method not allowed"),
        }
    }

    /// Tools chosen when a box was created are installed by the server itself once the box's own daemon answers, whether
    /// or not a dashboard tab is open: the same plan and apply the Tools page uses, then the wait list is cleared. A box
    /// that is not running or not answering is tried again later; nothing is retried in a tight loop.
    pub(super) fn start_pending_tools(&mut self, now_ms: u64) {
        const RETRY_MS: u64 = 30_000;
        let due: Vec<(String, Vec<String>)> = self
            .tools_cfg
            .pending
            .iter()
            .filter(|(n, ids)| {
                !ids.is_empty()
                    && now_ms.saturating_sub(self.tools_cfg.tried_ms.get(*n).copied().unwrap_or(0))
                        >= RETRY_MS
            })
            .map(|(n, ids)| (n.clone(), ids.clone()))
            .collect();
        for (name, ids) in due {
            if self.schedule.tools_busy.contains(&name) {
                continue;
            }
            self.tools_cfg.tried_ms.insert(name.clone(), now_ms);
            let Ok(rec) = self.running_box(&name) else {
                continue;
            };
            // The calls to the box can wait on the network, so they run on the worker, not on this loop.
            let agent = Arc::clone(&self.agent);
            let job_name = name.clone();
            let asked_by = self.current_actor.clone();
            let job: Job = Box::new(move || Done::ToolsInstalled {
                ok: install_chosen(agent.as_ref(), &rec, &ids),
                name: job_name,
                actor: asked_by,
            });
            if self.submit(job) {
                self.schedule.tools_busy.insert(name);
            }
        }
    }

    /// The worker has finished an install attempt.
    pub(super) fn tools_install_done(&mut self, name: &str, ok: bool) {
        self.schedule.tools_busy.remove(name);
        if ok {
            self.tools_cfg.pending.remove(name);
            self.tools_cfg.tried_ms.remove(name);
            self.tools_cfg.save_pending();
            self.log_activity("tools install (chosen at create)", name, None, "started");
        }
    }

    fn store(&self) -> Result<Store, Resp> {
        match &self.tools_cfg.profiles_dir {
            Some(d) => Ok(Store::new(d.clone())),
            None => Err(Resp::error(
                501,
                "profiles_unavailable",
                "profiles need a home folder; set OZBOX_PROFILES",
            )),
        }
    }

    fn profile_json(name: &str, p: &Result<Profile, String>) -> Value {
        match p {
            Ok(p) => {
                json!({ "name": name, "description": p.description, "tools": p.tools, "box": p.defaults })
            }
            Err(e) => json!({ "name": name, "error": e, "tools": Vec::<String>::new() }),
        }
    }

    pub(super) fn profiles(&mut self, method: &str, rest: &[&str], body: &[u8]) -> Resp {
        let (store, cat) = match (self.store(), catalog()) {
            (Ok(s), Ok(c)) => (s, c),
            (Err(r), _) | (_, Err(r)) => return r,
        };
        match (method, rest) {
            ("GET", []) => {
                let items: Vec<Value> = store
                    .list(&cat)
                    .iter()
                    .map(|(n, p)| Self::profile_json(n, p))
                    .collect();
                Resp::json(200, &json!({ "source": "files", "profiles": items }))
            }
            ("GET", [name]) => match store.load(name, &cat) {
                Ok(p) => Resp::json(200, &json!({ "profile": Self::profile_json(name, &Ok(p)) })),
                Err(e) => Resp::error(404, "not_found", &e),
            },
            ("DELETE", [name]) => match store.delete(name) {
                Ok(()) => Resp::json(200, &json!({ "deleted": name })),
                Err(e) => Resp::error(404, "not_found", &e),
            },
            ("POST", []) => self.save_profile(&store, &cat, body),
            ("GET", _) | ("DELETE", _) | ("POST", _) => {
                Resp::error(404, "not_found", "no such endpoint")
            }
            _ => Resp::error(405, "method_not_allowed", "method not allowed"),
        }
    }

    /// Save a profile: given outright, or taken from a box (its size, disk, labels and installed tools).
    fn save_profile(&mut self, store: &Store, cat: &Catalog, body: &[u8]) -> Resp {
        let v: Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(_) => return Resp::error(400, "bad_request", "the body must be JSON"),
        };
        let Some(name) = v["name"].as_str() else {
            return Resp::error(400, "bad_request", "send a profile name");
        };
        let overwrite = v["overwrite"].as_bool().unwrap_or(false);
        let profile: Profile = if let Some(from) = v["from_box"].as_str() {
            let rec = match self.record(from) {
                Ok(r) => r,
                Err(r) => return r,
            };
            let tools: Vec<String> = match v["tools"].as_array() {
                Some(a) => a
                    .iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect(),
                None => match self.installed_tools(&rec) {
                    Ok(t) => t,
                    Err(r) => return r,
                },
            };
            Profile {
                description: v["description"].as_str().map(str::to_string),
                tools,
                defaults: ProfileBox {
                    size: Some(rec.spec.size.to_string()),
                    disk_gb: Some(rec.spec.work_disk_gb),
                    auto_pause_minutes: Some(self.settings.defaults.auto_pause_minutes),
                    always_on: Some(
                        rec.spec.labels.get("ozbox-always-on").map(String::as_str) == Some("true"),
                    ),
                    labels: profiles::clean_labels(&rec.spec.labels),
                },
            }
        } else {
            match serde_json::from_value(v["profile"].clone()) {
                Ok(p) => p,
                Err(e) => {
                    return Resp::error(
                        400,
                        "bad_request",
                        &format!("the profile is not valid: {e}"),
                    )
                }
            }
        };
        match store.save(name, &profile, cat, overwrite) {
            Ok(_) => Resp::json(
                201,
                &json!({ "profile": Self::profile_json(name, &Ok(profile)) }),
            ),
            Err(e) if e.contains("already exists") => Resp::error(409, "already_exists", &e),
            Err(e) => Resp::error(422, "refused", &e),
        }
    }

    /// The installable tools that are on a running box (the ones a profile can carry).
    fn installed_tools(&self, rec: &BoxRecord) -> Result<Vec<String>, Resp> {
        if rec.state != BoxState::Running {
            return Err(Resp::error(
                409,
                "box_not_running",
                "the box must be running to read which tools it has; or send the tools to keep",
            ));
        }
        let (status, v) = self
            .agent
            .tools(rec, "GET", &[], &[])
            .map_err(|e| Self::agent_error(&e))?;
        if status != 200 {
            return Err(Resp::error(
                502,
                "agent_unreachable",
                "the box could not list its tools",
            ));
        }
        let c = catalog()?;
        Ok(v["tools"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter(|t| t["installed"] == true)
                    .filter_map(|t| t["id"].as_str())
                    .filter(|id| c.tool(id).is_some_and(|t| t.verified))
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default())
    }
}

/// Plan and apply the tools chosen at create time, on one box. `true` when nothing is left to do for it: the plan was
/// empty or the apply was accepted. A box that does not answer, or a refused plan, is tried again later.
pub(super) fn install_chosen(agent: &dyn BoxAgent, rec: &BoxRecord, ids: &[String]) -> bool {
    // Reachable? An answer to the plain listing means the daemon is up.
    if !matches!(agent.tools(rec, "GET", &[], &[]), Ok((200, _))) {
        return false;
    }
    let body = json!({ "install": ids }).to_string().into_bytes();
    let Ok((200, plan)) = agent.tools(rec, "POST", &["plan"], &body) else {
        return false;
    };
    let steps_empty = plan["plan"]["steps"]
        .as_array()
        .is_some_and(std::vec::Vec::is_empty);
    if steps_empty {
        return true;
    }
    let body = json!({ "install": ids, "plan_hash": plan["plan"]["hash"] })
        .to_string()
        .into_bytes();
    matches!(
        agent.tools(rec, "POST", &["apply"], &body),
        Ok((200 | 202, _))
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use ozbox_core::{BoxName, BoxSpec, Operation, Size};

    fn app(dir: &std::path::Path) -> App {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7878);
        let a = App::new(
            Box::new(ozbox_provider_fake::open(dir.join("state"))),
            true,
            addr,
            "tok".into(),
        )
        .with_tools_cfg(Some(dir.join("profiles")), Some(dir.join("pending.json")));
        let spec = BoxSpec::new(BoxName::new("dev").unwrap(), Size::M);
        let p = a.provider.plan(&Operation::Create { spec }).unwrap();
        a.provider.apply(&p).unwrap();
        a
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

    #[test]
    fn the_catalog_is_served_and_box_tools_are_flagged_simulated() {
        let d = tempfile::tempdir().unwrap();
        let mut a = app(d.path());
        let (s, v) = call(&mut a, "GET", "/v1/catalog", Value::Null);
        assert_eq!(s, 200);
        assert!(v["catalog"]["tools"].as_array().unwrap().len() >= 40);
        assert!(v["catalog"]["bundles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|b| b["id"] == "web"));
        let (s, v) = call(&mut a, "GET", "/v1/boxes/dev/tools", Value::Null);
        assert_eq!((s, v["source"].as_str().unwrap()), (200, "simulated"));
        let (_, p) = call(
            &mut a,
            "POST",
            "/v1/boxes/dev/tools/plan",
            json!({ "install": ["bundle:web"] }),
        );
        let hash = p["plan"]["hash"].clone();
        let (s, ap) = call(
            &mut a,
            "POST",
            "/v1/boxes/dev/tools/apply",
            json!({ "install": ["bundle:web"], "plan_hash": hash }),
        );
        assert_eq!(s, 202, "{ap}");
        let (_, act) = call(&mut a, "GET", "/v1/activity", Value::Null);
        assert!(act["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["action"] == "tools apply"));
        // Paths are checked; unknown boxes and paused boxes are clean errors.
        assert_eq!(
            call(&mut a, "GET", "/v1/boxes/dev/tools/..%2fx", Value::Null).0,
            405
        );
        assert_eq!(
            call(&mut a, "GET", "/v1/boxes/ghost/tools", Value::Null).0,
            404
        );
        assert_eq!(
            call(&mut a, "DELETE", "/v1/boxes/dev/tools/plan", Value::Null).0,
            405
        );
    }

    #[test]
    fn real_providers_answer_501_with_the_reason() {
        let d = tempfile::tempdir().unwrap();
        let mut a = app(d.path());
        a.simulated_metrics = false;
        a.agent = Arc::new(super::super::agent::NoTransport);
        let (s, v) = call(&mut a, "GET", "/v1/boxes/dev/tools", Value::Null);
        assert_eq!((s, v["code"].as_str().unwrap()), (501, "agent_unreachable"));
    }

    #[test]
    fn profiles_are_files_saved_from_a_box_and_validated() {
        let d = tempfile::tempdir().unwrap();
        let mut a = app(d.path());
        let (_, p) = call(
            &mut a,
            "POST",
            "/v1/boxes/dev/tools/plan",
            json!({ "install": ["jq"] }),
        );
        let h = p["plan"]["hash"].clone();
        call(
            &mut a,
            "POST",
            "/v1/boxes/dev/tools/apply",
            json!({ "install": ["jq"], "plan_hash": h }),
        );
        let (s, v) = call(
            &mut a,
            "POST",
            "/v1/profiles",
            json!({ "name": "mine", "from_box": "dev" }),
        );
        assert_eq!(s, 201, "{v}");
        assert_eq!(v["profile"]["tools"], json!(["jq"]));
        assert!(d.path().join("profiles/mine.toml").exists());
        assert_eq!(
            call(
                &mut a,
                "POST",
                "/v1/profiles",
                json!({ "name": "mine", "from_box": "dev" })
            )
            .0,
            409
        );
        let (_, l) = call(&mut a, "GET", "/v1/profiles", Value::Null);
        assert_eq!(l["profiles"][0]["name"], "mine");
        assert_eq!(
            call(
                &mut a,
                "POST",
                "/v1/profiles",
                json!({ "name": "Bad Name", "profile": { "tools": [] } })
            )
            .0,
            422
        );
        assert_eq!(
            call(
                &mut a,
                "POST",
                "/v1/profiles",
                json!({ "name": "x", "profile": { "tools": ["docker"] } })
            )
            .0,
            422
        );
        assert_eq!(call(&mut a, "GET", "/v1/profiles/mine", Value::Null).0, 200);
        assert_eq!(
            call(&mut a, "DELETE", "/v1/profiles/mine", Value::Null).0,
            200
        );
        assert_eq!(call(&mut a, "GET", "/v1/profiles/mine", Value::Null).0, 404);
    }

    #[test]
    fn tools_chosen_at_create_wait_as_pending_until_applied() {
        let d = tempfile::tempdir().unwrap();
        let mut a = app(d.path());
        let (s, v) = call(
            &mut a,
            "PUT",
            "/v1/boxes/dev/tools/pending",
            json!({ "tools": ["bundle:ai-agents"] }),
        );
        assert_eq!(s, 200);
        assert!(v["pending"].as_array().unwrap().len() >= 4);
        assert_eq!(
            call(
                &mut a,
                "PUT",
                "/v1/boxes/dev/tools/pending",
                json!({ "tools": ["docker"] })
            )
            .0,
            422
        );
        let (_, l) = call(&mut a, "GET", "/v1/boxes/dev/tools", Value::Null);
        assert!(l["pending"].as_array().unwrap().len() >= 4);
        let saved: BTreeMap<String, Vec<String>> =
            serde_json::from_slice(&std::fs::read(d.path().join("pending.json")).unwrap()).unwrap();
        assert!(saved.contains_key("dev"));
        call(&mut a, "DELETE", "/v1/boxes/dev/tools/pending", Value::Null);
        let (_, l) = call(&mut a, "GET", "/v1/boxes/dev/tools", Value::Null);
        assert!(l["pending"].as_array().unwrap().is_empty());
    }

    #[test]
    fn pending_tools_are_installed_by_the_server_when_the_box_answers() {
        let d = tempfile::tempdir().unwrap();
        let mut a = app(d.path());
        call(
            &mut a,
            "PUT",
            "/v1/boxes/dev/tools/pending",
            json!({ "tools": ["jq"] }),
        );
        a.start_pending_tools(100_000);
        a.apply_done(100_000);
        let (_, l) = call(&mut a, "GET", "/v1/boxes/dev/tools", Value::Null);
        assert!(l["pending"].as_array().unwrap().is_empty(), "{l}");
        assert!(
            l["active_job"].is_string()
                || l["tools"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|t| t["id"] == "jq")
        );
        assert!(a
            .activity
            .iter()
            .any(|e| e.action.contains("chosen at create")));
        let saved: BTreeMap<String, Vec<String>> =
            serde_json::from_slice(&std::fs::read(d.path().join("pending.json")).unwrap()).unwrap();
        assert!(saved.is_empty());
    }

    #[test]
    fn a_box_that_does_not_answer_keeps_its_tools_waiting_and_is_not_asked_every_tick() {
        let d = tempfile::tempdir().unwrap();
        let mut a = app(d.path());
        call(
            &mut a,
            "PUT",
            "/v1/boxes/dev/tools/pending",
            json!({ "tools": ["jq"] }),
        );
        a.simulated_metrics = false;
        a.agent = Arc::new(super::super::agent::NoTransport);
        a.start_pending_tools(100_000);
        a.apply_done(100_000);
        assert_eq!(a.tools_cfg.pending.get("dev").map(Vec::len), Some(1));
        let tried = a.tools_cfg.tried_ms.get("dev").copied();
        a.start_pending_tools(101_000);
        a.apply_done(101_000);
        assert_eq!(a.tools_cfg.tried_ms.get("dev").copied(), tried);
        a.start_pending_tools(131_000);
        a.apply_done(131_000);
        assert_eq!(a.tools_cfg.tried_ms.get("dev").copied(), Some(131_000));
        assert_eq!(a.tools_cfg.pending.get("dev").map(Vec::len), Some(1));
    }
}
