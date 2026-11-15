//! Skills beyond the library: adding a person's own, their earlier versions, and putting an approved skill on a box's own
//! disk (`/v1/skills` and `/v1/boxes/<box>/skills`).
//!
//! A skill is content an agent will follow, so every route here keeps the same gate: nothing reaches an agent unless a
//! person approved its exact hash. A push is refused unless the hash the page was looking at is the library's current one and
//! is approved; the box's daemon then re-checks the files and the hash before it writes anything. What a box holds is read
//! from the box (its files are hashed again on every look). Who put a skill there is read from this dashboard's own push
//! record, never from the box's: the box user can edit the box's record, so a skill counts as pushed from this dashboard
//! only when this record names the same hash, and anything else is shown as put there on the box.

use std::collections::BTreeMap;

use ozbox_core::skill_pack::{skill_agent, skill_name_ok, SkillPack, MAX_PACK_BODY};
use ozbox_core::BoxState;
use ozbox_memory::skills::{Origin, Replace, SkillError};
use serde::Deserialize;
use serde_json::{json, Value};

use super::{unix_ms, App, Req, Resp};

/// The most "seen on a box" lines kept as already noted.
const MAX_UNRECORDED_NOTED: usize = 500;

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
        let mut unrecorded = Vec::new();
        let mut reported: std::collections::BTreeSet<(String, String)> =
            std::collections::BTreeSet::new();
        for s in v["skills"].as_array().into_iter().flatten() {
            let n = s["name"].as_str().unwrap_or_default();
            // What this dashboard recorded putting there: the only thing that makes a skill "pushed from this dashboard". What
            // the box's own record says (who, which version, when) is text the box user can edit, so none of it is passed on.
            let ours = host.skills.pushed_places(n, name);
            let places: Vec<Value> = s["places"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|p| {
                    let agent = p["agent"].as_str().unwrap_or_default();
                    let state = p["state"].as_str().unwrap_or("modified");
                    let hash = p["hash"].as_str().unwrap_or_default();
                    let disk = p["disk_hash"].as_str();
                    let pushed_here = ours.get(agent).is_some_and(|h| h == hash);
                    reported.insert((n.to_string(), agent.to_string()));
                    if !pushed_here {
                        unrecorded.push(format!("{n}:{agent}"));
                    }
                    json!({
                        "agent": agent,
                        "state": state,
                        "hash": hash,
                        "disk_hash": disk,
                        "origin": if pushed_here { "dashboard" } else { "box" },
                        "matches_library": library.get(n).map(|h| state == "intact" && h == hash),
                    })
                })
                .collect();
            skills.push(
                json!({ "name": n, "in_library": library.contains_key(n), "places": places }),
            );
        }
        // What this dashboard recorded putting there, that the box does not report (its record was deleted, or the folder is
        // gone), still shows, as changed or missing: the box cannot make a copy disappear from the page by leaving it out.
        let others = v["others"].clone();
        for (skill, places) in host.skills.pushed_to(name) {
            for (agent, hash) in places {
                if reported.contains(&(skill.clone(), agent.clone())) {
                    continue;
                }
                let on_disk = others[&agent]
                    .as_array()
                    .is_some_and(|l| l.iter().any(|x| x == skill.as_str()));
                let place = json!({
                    "agent": agent,
                    "state": if on_disk { "modified" } else { "missing" },
                    "hash": hash,
                    "disk_hash": Value::Null,
                    "origin": "dashboard",
                    "matches_library": library.get(&skill).map(|_| false),
                });
                match skills.iter_mut().find(|x| x["name"] == skill.as_str()) {
                    Some(x) => {
                        if let Some(l) = x["places"].as_array_mut() {
                            l.push(place);
                        }
                    }
                    None => skills.push(json!({
                        "name": skill,
                        "in_library": library.contains_key(&skill),
                        "places": [place],
                    })),
                }
            }
        }
        // A skill on a box that this dashboard did not put there is worth a line in the record, once per box, skill and
        // folder, and never more than a few hundred: the box user chooses what its box reports, so it does not get to fill
        // the record by changing a file or inventing names.
        for u in unrecorded {
            let skill = u.split_once(':').map_or(u.as_str(), |(s, _)| s);
            let key = format!("{name}:{u}");
            if skill_name_ok(skill)
                && self.unrecorded_skills.len() < MAX_UNRECORDED_NOTED
                && self.unrecorded_skills.insert(key)
            {
                self.log_activity(
                    "skill seen on box",
                    name,
                    None,
                    "not pushed by this dashboard",
                );
            }
        }
        json!({ "box": name, "state": "ok", "can_write": self.agent.skill_writes(), "agents": v["agents"], "skills": skills, "others": v["others"] })
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
        // The dashboard names, per folder, the hash it recorded putting there: that is what lets the box replace a folder that
        // is already there. A folder it has no record of is never replaced.
        let claims = host.skills.pushed_places(skill, box_name);
        let body = json!({ "hash": b.hash, "agents": b.agents, "claims": claims, "files": files })
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
        // Only what this dashboard recorded putting there is taken away: it names those hashes, and the box leaves anything
        // else alone (`not_claimed`; `not_found` when it has nothing of that name at all).
        let claims = host.skills.pushed_places(skill, box_name);
        let body = json!({ "claims": claims }).to_string();
        let (status, v) =
            match self
                .agent
                .skills(&rec, "DELETE", &format!("/{skill}"), body.as_bytes())
            {
                Ok(x) => x,
                Err(e) => return Self::agent_error(&e),
            };
        // Forget only what the box says it took away. A box that answers "nothing here" does not make this dashboard forget
        // what it recorded: the record is the dashboard's, and the box user can change what the box says.
        let gone: Vec<String> = if status == 200 {
            claims.keys().cloned().collect()
        } else {
            v["results"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|r| r["ok"] == true)
                .filter_map(|r| r["agent"].as_str().map(str::to_string))
                .collect()
        };
        if !gone.is_empty() {
            let _ = host.skills.forget_places(skill, box_name, &gone);
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
