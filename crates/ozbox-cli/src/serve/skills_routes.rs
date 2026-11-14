//! Skills beyond the library: adding a person's own, their earlier versions, and putting an approved skill on a box's own
//! disk (`/v1/skills` and `/v1/boxes/<box>/skills`).
//!
//! A skill is content an agent will follow, so every route here keeps the same gate: nothing reaches an agent unless a
//! person approved its exact hash. A push is refused unless the hash the page was looking at is the library's current one and
//! is approved; the box's daemon then re-checks the files and the hash before it writes anything. What a box holds is read
//! from the box (its files are hashed again on every look), never from a record kept here.

use std::collections::BTreeMap;

use ozbox_core::skill_pack::{skill_agent, skill_name_ok, SkillPack, MAX_PACK_BODY};
use ozbox_core::BoxState;
use ozbox_memory::skills::{Origin, Replace, SkillError};
use serde::Deserialize;
use serde_json::{json, Value};

use super::{unix_ms, App, Req, Resp};

fn skill_error(e: SkillError) -> Resp {
    match e {
        SkillError::NotFound => Resp::error(404, "not_found", "there is no such skill"),
        SkillError::Refused(m) => Resp::error(409, "stale", &m),
        SkillError::NotApproved(m) => Resp::error(409, "not_approved", &m),
        SkillError::Invalid(m) => Resp::error(400, "invalid", &m),
        SkillError::Io(m) => Resp::error(500, "internal", &m),
    }
}

fn parse<T: serde::de::DeserializeOwned>(b: &[u8]) -> Result<T, Resp> {
    serde_json::from_slice(b)
        .map_err(|e| Resp::error(400, "bad_request", &format!("invalid request: {e}")))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AddBody {
    files: BTreeMap<String, String>,
    /// The hash of the library's skill of this name that the page was looking at, when it means to replace it.
    #[serde(default)]
    replaces: Option<String>,
    /// The person was told the name is one that ships with Oz Box and chose to replace it in the catalog.
    #[serde(default)]
    shadow_bundled: bool,
    /// `page_upload` or `page_editor`.
    #[serde(default)]
    via: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PushBody {
    hash: String,
    #[serde(default)]
    agents: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreBody {
    hash: String,
}

/// Does a request to this path carry a skill's files, so that it may be bigger than the usual 64 KiB?
pub fn big_body_cap(method: &str, path: &str) -> Option<usize> {
    (method == "POST" && path.trim_end_matches('/') == "/v1/skills").then_some(MAX_PACK_BODY)
}

impl App {
    pub(super) fn skill_add(&mut self, req: &Req) -> Resp {
        let host = match self.memory_host() {
            Ok(h) => h,
            Err(r) => return r,
        };
        let b: AddBody = match parse(&req.body) {
            Ok(b) => b,
            Err(r) => return r,
        };
        let via = match b.via.as_deref() {
            Some("page_editor") => "page_editor",
            _ => "page_upload",
        };
        let files = b
            .files
            .into_iter()
            .map(|(p, t)| (p, t.into_bytes()))
            .collect();
        let pack = match SkillPack::from_files(files) {
            Ok(p) => p,
            Err(e) => return skill_error(e),
        };
        let name = pack.name.clone();
        let who = self.who(req);
        let replace = match b.replaces {
            Some(h) => Replace::Over(h),
            None => Replace::Fresh,
        };
        match host.skills.add_pack(
            pack,
            &Origin {
                by: who,
                via: via.into(),
            },
            &replace,
            b.shadow_bundled,
            unix_ms(),
        ) {
            Ok(item) => {
                self.log_activity("skill add", &name, None, via);
                Resp::json(200, &item)
            }
            Err(e) => skill_error(e),
        }
    }

    pub(super) fn skill_delete(&mut self, name: &str) -> Resp {
        let host = match self.memory_host() {
            Ok(h) => h,
            Err(r) => return r,
        };
        match host.skills.remove_from_library(name) {
            Ok(()) => {
                self.log_activity("skill delete", name, None, "ok");
                Resp::json(200, &json!({ "removed": name }))
            }
            Err(e) => skill_error(e),
        }
    }

    pub(super) fn skill_history(&mut self, name: &str) -> Resp {
        let host = match self.memory_host() {
            Ok(h) => h,
            Err(r) => return r,
        };
        match host.skills.history(name) {
            Ok(v) => Resp::json(200, &json!({ "revisions": v })),
            Err(e) => skill_error(e),
        }
    }

    pub(super) fn skill_restore(&mut self, name: &str, req: &Req) -> Resp {
        let host = match self.memory_host() {
            Ok(h) => h,
            Err(r) => return r,
        };
        let b: RestoreBody = match parse(&req.body) {
            Ok(b) => b,
            Err(r) => return r,
        };
        let who = self.who(req);
        match host.skills.restore(name, &b.hash, &who, unix_ms()) {
            Ok(item) => {
                self.log_activity(
                    "skill restore",
                    name,
                    None,
                    &b.hash.chars().take(12).collect::<String>(),
                );
                Resp::json(200, &item)
            }
            Err(e) => skill_error(e),
        }
    }

    /// What one running box holds, read from the box and compared with the library.
    fn box_skills_view(&mut self, name: &str) -> Value {
        let host = match self.memory_host() {
            Ok(h) => h,
            Err(_) => {
                return json!({ "box": name, "state": "unreachable", "reason": "the skills library could not be opened" })
            }
        };
        let rec = match self.running_box(name) {
            Ok(r) => r,
            Err(_) => {
                return json!({ "box": name, "state": "stopped", "reason": "the box is not running, so what it holds is not known" })
            }
        };
        let (status, v) = match self.agent.skills(&rec, "GET", "", &[]) {
            Ok(x) => x,
            Err(e) => {
                let why = match &e {
                    super::agent::AgentError::Unreachable(w)
                    | super::agent::AgentError::Unsupported(w) => w.clone(),
                };
                return json!({ "box": name, "state": "unreachable", "reason": why });
            }
        };
        if status != 200 {
            let why = v["message"]
                .as_str()
                .unwrap_or("the box could not say what it holds");
            return json!({ "box": name, "state": "unreachable", "reason": why, "code": v["code"] });
        }
        let library: BTreeMap<String, String> = host
            .skills
            .catalog()
            .into_iter()
            .map(|c| (c.name, c.hash))
            .collect();
        let mut skills = Vec::new();
        for s in v["skills"].as_array().into_iter().flatten() {
            let n = s["name"].as_str().unwrap_or_default();
            let places: Vec<Value> = s["places"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|p| {
                    let mut p = p.clone();
                    p["matches_library"] = match library.get(n) {
                        Some(h) => json!(p["state"] == "intact" && p["hash"] == h.as_str()),
                        None => Value::Null,
                    };
                    p
                })
                .collect();
            skills.push(
                json!({ "name": n, "in_library": library.contains_key(n), "places": places }),
            );
        }
        json!({ "box": name, "state": "ok", "agents": v["agents"], "skills": skills, "others": v["others"] })
    }

    /// Every box: what it holds, or why that is not known.
    pub(super) fn skill_holdings(&mut self) -> Resp {
        let names: Vec<(String, bool)> = self
            .provider
            .list()
            .map(|r| {
                r.iter()
                    .map(|x| (x.spec.name.to_string(), x.state == BoxState::Running))
                    .collect()
            })
            .unwrap_or_default();
        let boxes: Vec<Value> = names
            .into_iter()
            .map(|(n, running)| {
                if running {
                    self.box_skills_view(&n)
                } else {
                    json!({ "box": n, "state": "stopped", "reason": "the box is not running, so what it holds is not known" })
                }
            })
            .collect();
        Resp::json(
            200,
            &json!({ "boxes": boxes, "source": self.data_source() }),
        )
    }

    pub(super) fn box_skills(&mut self, name: &str, rest: &[&str], req: &Req) -> Resp {
        match (req.method.as_str(), rest) {
            ("GET", []) => {
                if let Err(r) = self.record(name) {
                    return r;
                }
                let mut v = self.box_skills_view(name);
                v["source"] = json!(self.data_source());
                Resp::json(200, &v)
            }
            ("PUT", [skill]) if skill_name_ok(skill) => self.skill_push(name, skill, req),
            ("DELETE", [skill]) if skill_name_ok(skill) => self.skill_pull(name, skill),
            (_, [] | [_]) => Resp::error(405, "method_not_allowed", "method not allowed"),
            _ => Resp::error(404, "not_found", "no such endpoint"),
        }
    }

    fn skill_push(&mut self, box_name: &str, skill: &str, req: &Req) -> Resp {
        let host = match self.memory_host() {
            Ok(h) => h,
            Err(r) => return r,
        };
        let b: PushBody = match parse(&req.body) {
            Ok(b) => b,
            Err(r) => return r,
        };
        if let Some(ids) = &b.agents {
            if ids.iter().any(|i| skill_agent(i).is_none()) {
                return Resp::error(
                    400,
                    "invalid",
                    "that is not an agent this box can put a skill in",
                );
            }
        }
        let rec = match self.running_box(box_name) {
            Ok(r) => r,
            Err(r) => return r,
        };
        // only exactly what a person approved, and only if that is still the library's current version
        let pack = match host.skills.for_push(skill, &b.hash) {
            Ok(p) => p,
            Err(e) => return skill_error(e),
        };
        let files: BTreeMap<String, String> = pack
            .files
            .iter()
            .map(|(p, bytes)| (p.clone(), String::from_utf8_lossy(bytes).to_string()))
            .collect();
        let who = self.who(req);
        let body = json!({ "hash": b.hash, "pushed_by": who, "agents": b.agents, "files": files })
            .to_string();
        let (status, mut v) =
            match self
                .agent
                .skills(&rec, "PUT", &format!("/{skill}"), body.as_bytes())
            {
                Ok(x) => x,
                Err(e) => return Self::agent_error(&e),
            };
        let short: String = b.hash.chars().take(12).collect();
        if status == 200 {
            let agents: Vec<String> = v["results"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|r| r["ok"] == true)
                .filter_map(|r| r["agent"].as_str().map(str::to_string))
                .collect();
            let _ = host
                .skills
                .record_push(skill, box_name, &b.hash, agents, &who, unix_ms());
            self.log_activity("skill push", box_name, None, &format!("{skill} {short}"));
        } else {
            self.log_activity("skill push", box_name, None, &format!("{skill} refused"));
        }
        if let Some(o) = v.as_object_mut() {
            o.insert("source".into(), json!(self.data_source()));
        }
        Resp::json(status, &v)
    }

    fn skill_pull(&mut self, box_name: &str, skill: &str) -> Resp {
        let host = match self.memory_host() {
            Ok(h) => h,
            Err(r) => return r,
        };
        let rec = match self.running_box(box_name) {
            Ok(r) => r,
            Err(r) => return r,
        };
        let (status, v) = match self.agent.skills(&rec, "DELETE", &format!("/{skill}"), &[]) {
            Ok(x) => x,
            Err(e) => return Self::agent_error(&e),
        };
        if status == 200 || (status == 404 && v["code"] == "not_found") {
            let _ = host.skills.forget_push(skill, box_name);
        }
        self.log_activity(
            "skill remove from box",
            box_name,
            None,
            &format!("{skill} {status}"),
        );
        Resp::json(status, &v)
    }
}
