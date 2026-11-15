//! The tool installer as the demo provider answers it: the same shapes the box daemon returns for `/v1/tools/...`, with
//! installs that take a realistic few seconds and change nothing real. Everything it says is flagged `simulated` by the
//! server. The catalog and the plan builder are the real ones.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::Instant;

use ozbox_catalog::plan::build_plan;
use ozbox_catalog::{Arch, Catalog, Op, Plan, PlanError, PlanRequest, Verification};
use serde_json::{json, Value};

const STEP_MS: u64 = 700;
const ROOT_STEP_MS: u64 = 1200;

struct SimJob {
    id: String,
    plan: Plan,
    started: Instant,
    requested_by: String,
    fail_at: Option<usize>,
    applied: bool,
}

pub struct SimTools {
    catalog: Catalog,
    installed: BTreeSet<String>,
    jobs: Vec<SimJob>,
    requests: Vec<Value>,
    always: BTreeSet<String>,
    counter: u64,
    /// Installing `yazi` fails (a box labelled `sim_profile=failing`), so the failure screens can be seen.
    fail_yazi: bool,
    speed: u64,
    path: Option<PathBuf>,
}

fn err(status: u16, code: &str, message: &str) -> (u16, Value) {
    (
        status,
        json!({ "code": code, "message": message, "error": message }),
    )
}

fn plan_err(e: &PlanError) -> (u16, Value) {
    let status = match e {
        PlanError::Unknown(_) => 404,
        PlanError::StillRequired { .. } | PlanError::Conflict(_) => 409,
        PlanError::Empty => 400,
        PlanError::Unverified { .. } | PlanError::UnsupportedArch { .. } => 422,
    };
    err(status, e.code(), &e.to_string())
}

impl SimTools {
    pub fn new(catalog: Catalog, fail_yazi: bool, path: Option<PathBuf>) -> SimTools {
        let installed: BTreeSet<String> = path
            .as_ref()
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        SimTools {
            catalog,
            installed,
            jobs: Vec::new(),
            requests: Vec::new(),
            always: BTreeSet::new(),
            counter: 0,
            fail_yazi,
            // Installs take a few seconds so the progress screens can be seen; OZBOX_SIM_SPEED=0 makes them instant.
            speed: if cfg!(test) {
                0
            } else {
                std::env::var("OZBOX_SIM_SPEED")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(1)
            },
            path,
        }
    }

    /// Tests run steps instantly.
    #[cfg(test)]
    pub fn instant(mut self) -> SimTools {
        self.speed = 0;
        self
    }

    fn save(&self) {
        if let Some(p) = &self.path {
            if let Some(d) = p.parent() {
                let _ = std::fs::create_dir_all(d);
            }
            let _ = std::fs::write(p, serde_json::to_vec(&self.installed).unwrap_or_default());
        }
    }

    fn step_ms(&self, root: bool) -> u64 {
        (if root { ROOT_STEP_MS } else { STEP_MS }) * self.speed
    }

    /// How far a job has got, from the clock.
    fn progress(&self, j: &SimJob) -> (usize, bool) {
        let mut at = j.started.elapsed().as_millis() as u64;
        let mut done = 0usize;
        for s in &j.plan.steps {
            let d = self.step_ms(s.privilege == ozbox_catalog::Privilege::Root);
            if at < d {
                break;
            }
            at -= d;
            done += 1;
        }
        let failed = j.fail_at.is_some_and(|f| done >= f);
        (done.min(j.fail_at.unwrap_or(usize::MAX)), failed)
    }

    /// Apply finished jobs to the installed set, once.
    fn tick(&mut self) {
        let mut changed = false;
        let n = self.jobs.len();
        for i in 0..n {
            let (done, failed) = self.progress(&self.jobs[i]);
            let finished = !failed && done == self.jobs[i].plan.steps.len();
            if finished && !self.jobs[i].applied {
                for t in &self.jobs[i].plan.tools.clone() {
                    match t.op {
                        Op::Install => self.installed.insert(t.id.clone()),
                        Op::Remove => self.installed.remove(&t.id),
                    };
                }
                self.jobs[i].applied = true;
                changed = true;
            }
        }
        if changed {
            self.save();
        }
    }

    fn active(&self) -> Option<String> {
        self.jobs
            .iter()
            .find(|j| {
                let (done, failed) = self.progress(j);
                !failed && done < j.plan.steps.len()
            })
            .map(|j| j.id.clone())
    }

    pub fn call(&mut self, method: &str, segs: &[&str], body: &[u8]) -> (u16, Value) {
        self.tick();
        match (method, segs) {
            ("GET", []) => self.list(),
            ("POST", ["plan"]) => match self.selection(body) {
                Ok(r) => match build_plan(&self.catalog, Arch::Amd64, &self.installed, &r) {
                    Ok(p) => (200, json!({ "plan": p })),
                    Err(e) => plan_err(&e),
                },
                Err(e) => e,
            },
            ("POST", ["apply"]) => self.apply(body),
            ("GET", ["jobs"]) => self.jobs_list(),
            ("GET", ["jobs", id]) => self.job(id),
            ("GET", ["requests"]) => (
                200,
                json!({ "requests": self.requests, "always_allowed": self.always }),
            ),
            ("POST", ["requests"]) => self.new_request(body),
            ("POST", ["requests", id, "decision"]) => self.decide(id, body),
            ("GET", ["audit"]) => (200, json!({ "events": [] })),
            (_, [])
            | (_, ["plan"])
            | (_, ["apply"])
            | (_, ["jobs"])
            | (_, ["jobs", _])
            | (_, ["requests"])
            | (_, ["requests", _, "decision"])
            | (_, ["audit"]) => err(405, "method_not_allowed", "method not allowed"),
            _ => err(404, "not_found", "no such endpoint"),
        }
    }

    fn list(&self) -> (u16, Value) {
        let tools: Vec<Value> = self
            .catalog
            .tools
            .iter()
            .map(|t| {
                let on = self.installed.contains(&t.id);
                json!({
                    "id": t.id, "installed": on,
                    "version": on.then_some("1.0.0"),
                    "managed_by_client": t.verification == Verification::ClientManaged,
                })
            })
            .collect();
        (
            200,
            json!({ "catalog_version": self.catalog.version, "arch": Arch::Amd64,
                    "tools": tools, "active_job": self.active() }),
        )
    }

    fn selection(&self, body: &[u8]) -> Result<PlanRequest, (u16, Value)> {
        let v: Value = serde_json::from_slice(body).map_err(|_| {
            err(
                400,
                "bad_request",
                "the body must be JSON with install and/or remove lists",
            )
        })?;
        let list = |k: &str| -> Vec<String> {
            v[k].as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default()
        };
        let ex = |l: Vec<String>| {
            self.catalog
                .expand(&l)
                .map_err(|m| err(404, "unknown_tool", &m))
        };
        Ok(PlanRequest {
            install: ex(list("install"))?,
            remove: ex(list("remove"))?,
        })
    }

    fn apply(&mut self, body: &[u8]) -> (u16, Value) {
        let req = match self.selection(body) {
            Ok(r) => r,
            Err(e) => return e,
        };
        let hash = serde_json::from_slice::<Value>(body)
            .ok()
            .and_then(|v| v["plan_hash"].as_str().map(str::to_string));
        match self.start(&req, hash.as_deref(), "owner") {
            Ok(Some(id)) => (202, json!({ "job_id": id })),
            Ok(None) => (200, json!({ "job_id": null, "noop": true })),
            Err(e) => e,
        }
    }

    fn start(
        &mut self,
        req: &PlanRequest,
        hash: Option<&str>,
        actor: &str,
    ) -> Result<Option<String>, (u16, Value)> {
        let plan = build_plan(&self.catalog, Arch::Amd64, &self.installed, req)
            .map_err(|e| plan_err(&e))?;
        match hash {
            None => {
                return Err(err(
                    400,
                    "bad_request",
                    "apply needs the plan_hash of the plan that was shown",
                ))
            }
            Some(h) if h != plan.hash => {
                return Err(err(
                    409,
                    "stale_plan",
                    "what is on the box changed since this plan was made; plan again",
                ))
            }
            _ => {}
        }
        if plan.is_noop() {
            return Ok(None);
        }
        if self.active().is_some() {
            return Err(err(409, "busy", "another tool job is still running"));
        }
        self.counter += 1;
        let id = format!("sim{}", self.counter);
        let fail_at = if self.fail_yazi {
            plan.steps
                .iter()
                .find(|s| {
                    s.tool == "yazi"
                        && s.op == Op::Install
                        && matches!(s.action, ozbox_catalog::Action::Exec { .. })
                })
                .map(|s| s.index)
        } else {
            None
        };
        self.jobs.push(SimJob {
            id: id.clone(),
            plan,
            started: Instant::now(),
            requested_by: actor.to_string(),
            fail_at,
            applied: false,
        });
        Ok(Some(id))
    }

    fn job_json(&self, j: &SimJob, with_log: bool) -> Value {
        let (done, failed) = self.progress(j);
        let n = j.plan.steps.len();
        let finished = !failed && done == n;
        let steps: Vec<Value> = j
            .plan
            .steps
            .iter()
            .map(|s| {
                let state = if failed && s.index == done {
                    "failed"
                } else if s.index < done {
                    "ok"
                } else if s.index == done && !failed {
                    "running"
                } else {
                    "pending"
                };
                json!({ "index": s.index, "title": s.title, "state": state })
            })
            .collect();
        let state = if failed {
            "failed"
        } else if finished {
            "succeeded"
        } else {
            "running"
        };
        let mut log: Vec<String> = Vec::new();
        for s in &j.plan.steps {
            if s.index > done {
                break;
            }
            log.push(format!("step {}/{}: {}", s.index + 1, n, s.title));
            if s.index == done && failed {
                log.push("failed: the build ran out of memory (simulated)".into());
            }
        }
        if finished {
            for t in j.plan.tools.iter().filter(|t| t.op == Op::Install) {
                log.push(format!("verified {}", t.id));
            }
            log.push("done".into());
        }
        let ended = (finished || failed).then_some(1);
        let mut v = json!({
            "job": { "id": j.id, "state": state, "steps": steps,
                     "error": failed.then(|| format!("{}: the build ran out of memory (simulated)", j.plan.steps.get(done).map(|s| s.title.clone()).unwrap_or_default())),
                     "started_ms": 1, "ended_ms": ended },
            "tools": j.plan.tools,
            "requested_by": j.requested_by,
        });
        if with_log {
            v["log"] = json!(log);
        }
        v
    }

    fn job(&self, id: &str) -> (u16, Value) {
        match self.jobs.iter().find(|j| j.id == id) {
            Some(j) => (200, self.job_json(j, true)),
            None => err(404, "not_found", "no such job"),
        }
    }

    fn jobs_list(&self) -> (u16, Value) {
        let items: Vec<Value> = self
            .jobs
            .iter()
            .rev()
            .map(|j| {
                let v = self.job_json(j, false);
                json!({ "id": j.id, "state": v["job"]["state"], "error": v["job"]["error"],
                        "started_ms": 1, "ended_ms": v["job"]["ended_ms"],
                        "tools": j.plan.tools.iter().map(|t| t.id.clone()).collect::<Vec<_>>() })
            })
            .collect();
        (200, json!({ "jobs": items }))
    }

    fn new_request(&mut self, body: &[u8]) -> (u16, Value) {
        let v: Value = serde_json::from_slice(body).unwrap_or_default();
        let Some(tool) = v["tool"].as_str() else {
            return err(400, "bad_request", "send {\"tool\": id, \"reason\": text}");
        };
        let Some(t) = self.catalog.tool(tool) else {
            return err(404, "unknown_tool", "there is no such tool");
        };
        if !t.verified {
            return plan_err(&PlanError::Unverified {
                id: t.id.clone(),
                reason: t.unverified_reason.clone().unwrap_or_default(),
            });
        }
        if self.installed.contains(tool) {
            return err(
                409,
                "already_installed",
                &format!("{} is already installed", t.name),
            );
        }
        if let Some(r) = self
            .requests
            .iter()
            .find(|r| r["tool"] == tool && r["state"] == "pending")
        {
            return (200, json!({ "request": r }));
        }
        self.counter += 1;
        let reason: String = v["reason"]
            .as_str()
            .unwrap_or("")
            .chars()
            .filter(|c| !c.is_control())
            .take(300)
            .collect();
        let by = v["agent"]
            .as_str()
            .filter(|a| !a.is_empty() && a.len() <= 40)
            .unwrap_or("agent");
        let r = json!({ "id": format!("rsim{}", self.counter), "tool": tool, "reason": reason,
                        "requested_by": by, "created_ms": 1, "state": "pending",
                        "decision": null, "job_id": null });
        self.requests.push(r.clone());
        if self.always.contains(tool) {
            let id = r["id"].as_str().unwrap_or("").to_string();
            return self.approve(&id, "always", "approval");
        }
        (201, json!({ "request": r }))
    }

    fn approve(&mut self, id: &str, decision: &str, actor: &str) -> (u16, Value) {
        let Some(pos) = self.requests.iter().position(|r| r["id"] == id) else {
            return err(404, "not_found", "no such request");
        };
        if self.requests[pos]["state"] != "pending" {
            return err(409, "already_decided", "that request was already decided");
        }
        let tool = self.requests[pos]["tool"]
            .as_str()
            .unwrap_or("")
            .to_string();
        let req = PlanRequest {
            install: vec![tool.clone()],
            remove: vec![],
        };
        let hash = match build_plan(&self.catalog, Arch::Amd64, &self.installed, &req) {
            Ok(p) => p.hash,
            Err(e) => return plan_err(&e),
        };
        let job = match self.start(&req, Some(&hash), actor) {
            Ok(j) => j,
            Err(e) => return e,
        };
        if decision == "always" {
            self.always.insert(tool);
        }
        self.requests[pos]["state"] = json!("approved");
        self.requests[pos]["decision"] = json!(decision);
        self.requests[pos]["job_id"] = json!(job);
        (200, json!({ "request": self.requests[pos] }))
    }

    fn decide(&mut self, id: &str, body: &[u8]) -> (u16, Value) {
        let d = serde_json::from_slice::<Value>(body)
            .ok()
            .and_then(|v| v["decision"].as_str().map(str::to_string))
            .unwrap_or_default();
        match d.as_str() {
            "approve_once" => self.approve(id, "once", "owner"),
            "approve_always" => self.approve(id, "always", "owner"),
            "deny" => match self.requests.iter_mut().find(|r| r["id"] == id) {
                None => err(404, "not_found", "no such request"),
                Some(r) if r["state"] != "pending" => {
                    err(409, "already_decided", "that request was already decided")
                }
                Some(r) => {
                    r["state"] = json!("denied");
                    r["decision"] = json!("denied");
                    (200, json!({ "request": r }))
                }
            },
            _ => err(
                400,
                "bad_request",
                "decision must be approve_once, approve_always or deny",
            ),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn sim(fail: bool) -> SimTools {
        SimTools::new(ozbox_catalog::embedded().unwrap(), fail, None).instant()
    }

    fn post(s: &mut SimTools, seg: &[&str], v: Value) -> (u16, Value) {
        s.call("POST", seg, &serde_json::to_vec(&v).unwrap())
    }

    #[test]
    fn plan_apply_installs_and_a_second_plan_is_empty() {
        let mut s = sim(false);
        let (_, p) = post(
            &mut s,
            &["plan"],
            json!({ "install": ["bundle:ai-agents"] }),
        );
        let hash = p["plan"]["hash"].as_str().unwrap().to_string();
        let (st, a) = post(
            &mut s,
            &["apply"],
            json!({ "install": ["bundle:ai-agents"], "plan_hash": hash }),
        );
        assert_eq!(st, 202, "{a}");
        let id = a["job_id"].as_str().unwrap().to_string();
        let (_, j) = s.call("GET", &["jobs", &id], &[]);
        assert_eq!(j["job"]["state"], "succeeded");
        let (_, l) = s.call("GET", &[], &[]);
        let on: Vec<&str> = l["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|t| t["installed"] == true)
            .map(|t| t["id"].as_str().unwrap())
            .collect();
        assert!(on.contains(&"claude-code") && on.contains(&"node") && on.contains(&"aider"));
        let (_, p2) = post(
            &mut s,
            &["plan"],
            json!({ "install": ["bundle:ai-agents"] }),
        );
        assert!(p2["plan"]["steps"].as_array().unwrap().is_empty());
        // A stale or missing hash is refused.
        assert_eq!(
            post(
                &mut s,
                &["apply"],
                json!({ "install": ["jq"], "plan_hash": "x" })
            )
            .0,
            409
        );
        assert_eq!(
            post(&mut s, &["apply"], json!({ "install": ["jq"] })).0,
            400
        );
    }

    #[test]
    fn removal_still_required_failure_and_unverified_are_reported() {
        let mut s = sim(true);
        let go = |s: &mut SimTools, v: Value| {
            let (_, p) = post(s, &["plan"], v.clone());
            let mut v = v;
            v["plan_hash"] = p["plan"]["hash"].clone();
            post(s, &["apply"], v)
        };
        assert_eq!(go(&mut s, json!({ "install": ["pnpm"] })).0, 202);
        let (st, e) = post(&mut s, &["plan"], json!({ "remove": ["node"] }));
        assert_eq!((st, e["code"].as_str().unwrap()), (409, "still_required"));
        assert_eq!(
            post(&mut s, &["plan"], json!({ "install": ["docker"] })).0,
            422
        );
        let (_, a) = go(&mut s, json!({ "install": ["yazi"] }));
        let (_, j) = s.call("GET", &["jobs", a["job_id"].as_str().unwrap()], &[]);
        assert_eq!(j["job"]["state"], "failed");
        assert!(j["job"]["error"].as_str().unwrap().contains("simulated"));
    }

    #[test]
    fn requests_wait_for_the_owner() {
        let mut s = sim(false);
        let (st, r) = post(
            &mut s,
            &["requests"],
            json!({ "tool": "jq", "reason": "parse json", "agent": "claude-1" }),
        );
        assert_eq!(
            (st, r["request"]["state"].as_str().unwrap()),
            (201, "pending")
        );
        assert!(s.call("GET", &[], &[]).1["tools"]
            .as_array()
            .unwrap()
            .iter()
            .all(|t| t["installed"] == false));
        let id = r["request"]["id"].as_str().unwrap().to_string();
        let (st, d) = post(
            &mut s,
            &["requests", &id, "decision"],
            json!({ "decision": "approve_always" }),
        );
        assert_eq!(
            (st, d["request"]["state"].as_str().unwrap()),
            (200, "approved")
        );
        assert!(s.call("GET", &[], &[]).1["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["id"] == "jq" && t["installed"] == true));
        assert_eq!(
            post(
                &mut s,
                &["requests", &id, "decision"],
                json!({ "decision": "deny" })
            )
            .0,
            409
        );
    }
}
