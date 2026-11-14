//! `/v1/memory/...` and `/v1/skills/...`: the dashboard's Memory and Skills pages.
//!
//! A person reviews here what agents propose. Everything a person does (add, edit, approve, forget a note; install,
//! approve, revoke a skill) is a request with the signed-in person as its actor. An agent never reaches these routes:
//! it reaches memory and skills only through the tool host (`crate::memory_tools`).

use std::path::PathBuf;
use std::sync::Arc;

use ozbox_memory::memory::{Caller, Entry, Filter, MemError, Patch, Scope, State};
use ozbox_memory::skills::{InstallScope, SkillError};
use serde::Deserialize;
use serde_json::{json, Value};

use super::{parse_query, unix_ms, App, Req, Resp};
use crate::memory_tools::MemoryHost;

fn parse<T: serde::de::DeserializeOwned>(b: &[u8]) -> Result<T, Resp> {
    serde_json::from_slice(b)
        .map_err(|e| Resp::error(400, "bad_request", &format!("invalid request: {e}")))
}

fn mem_resp(e: MemError) -> Resp {
    match e {
        MemError::NotFound => Resp::error(404, "not_found", "there is no such note"),
        MemError::Denied(m) => Resp::error(403, "forbidden", &m),
        MemError::Secret(_) => Resp::error(422, "looks_like_a_secret", &e.to_string()),
        MemError::Limit(m) => Resp::error(409, "limit", &m),
        MemError::Invalid(m) => Resp::error(400, "invalid", &m),
        MemError::Io(m) => Resp::error(500, "internal", &m),
    }
}

fn skill_resp(e: SkillError) -> Resp {
    match e {
        SkillError::NotFound => Resp::error(404, "not_found", "there is no such skill"),
        SkillError::Refused(m) => Resp::error(409, "stale", &m),
        SkillError::NotApproved(m) => Resp::error(409, "not_approved", &m),
        SkillError::Invalid(m) => Resp::error(400, "invalid", &m),
        SkillError::Io(m) => Resp::error(500, "internal", &m),
    }
}

fn entry_json(e: &Entry) -> Value {
    json!({
        "id": e.id, "scope": e.scope, "title": e.title, "body": e.body, "tags": e.tags,
        "state": e.state, "created_ms": e.created_ms, "updated_ms": e.updated_ms,
        "expires_ms": e.expires_ms, "expired": e.expired, "revision": e.revision,
        "written_by": e.provenance.actor, "by_agent": e.provenance.kind == ozbox_memory::memory::ActorKind::Agent,
        "run": e.provenance.run, "session": e.provenance.session, "reviewed_by": e.provenance.reviewed_by, "reviewed_ms": e.provenance.reviewed_ms,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewNote {
    scope: String,
    title: String,
    body: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    expires_days: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EditNote {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    tags: Option<Vec<String>>,
    /// Days from now; `null` clears the expiry; absent leaves it.
    #[serde(default, deserialize_with = "double_option")]
    expires_days: Option<Option<u64>>,
}

fn double_option<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Option<u64>>, D::Error> {
    Option::<u64>::deserialize(d).map(Some)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopeBody {
    scope: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HashBody {
    hash: String,
}

impl App {
    /// Where the notes and skills live, for a page to say: `persisted` is false when there is no settings file to sit beside
    /// (a folder for this process only, forgotten when it ends); `host` names the box when this server runs on one.
    fn memory_store_json(&self) -> Value {
        let on_a_box = crate::this_box::on_a_box();
        let host = on_a_box.then(|| {
            crate::this_box::box_name(crate::this_box::Facts::detect().hostname.as_deref())
                .to_string()
        });
        json!({ "persisted": self.settings_path.is_some(), "on_a_box": on_a_box, "host": host,
                "folder": self.memory_dir().display().to_string() })
    }

    /// The folder that holds `memory/` and `skills/`: beside the settings file, or this process's own temporary one.
    fn memory_dir(&self) -> PathBuf {
        match &self.settings_path {
            Some(p) => p.with_file_name("agent-memory"),
            None => std::env::temp_dir().join(format!("ozbox-memory-{}", std::process::id())),
        }
    }

    /// The memory and skills stores, opened on first use beside the configuration.
    pub(super) fn memory_host(&mut self) -> Result<Arc<MemoryHost>, Resp> {
        if let Some(h) = &self.memory_host {
            return Ok(Arc::clone(h));
        }
        let dir: PathBuf = self.memory_dir();
        let host = MemoryHost::open(&dir).map_err(|e| Resp::error(500, "internal", &e))?;
        let host = Arc::new(host);
        self.memory_host = Some(Arc::clone(&host));
        Ok(host)
    }

    pub(super) fn memory_route(&mut self, req: &Req, rest: &[&str]) -> Resp {
        let host = match self.memory_host() {
            Ok(h) => h,
            Err(r) => return r,
        };
        let who = self.who(req);
        let me = Caller::Person(who.clone());
        let now = unix_ms();
        match (req.method.as_str(), rest) {
            ("GET", []) => {
                let q = parse_query(&req.query);
                let scope = match q.get("scope").filter(|s| !s.is_empty()) {
                    Some(s) => match Scope::parse(s) {
                        Ok(s) => Some(s),
                        Err(e) => return mem_resp(e),
                    },
                    None => None,
                };
                let state = match q.get("state").map(String::as_str) {
                    Some("pending") => Some(State::Pending),
                    Some("approved") => Some(State::Approved),
                    _ => None,
                };
                let f = Filter {
                    scope,
                    state,
                    include_expired: q.get("expired").is_some_and(|v| v == "1"),
                };
                let found = match q.get("q").filter(|s| !s.trim().is_empty()) {
                    Some(text) => host.memory.search(&me, text, &f, 100, now),
                    None => host.memory.list(&me, &f, now),
                };
                let stats = host.memory.stats(&me, now);
                match (found, stats) {
                    (Ok(list), Ok(stats)) => Resp::json(
                        200,
                        &json!({ "notes": list.iter().take(200).map(entry_json).collect::<Vec<_>>(),
                                 "stats": stats, "person": who, "store": self.memory_store_json() }),
                    ),
                    (Err(e), _) | (_, Err(e)) => mem_resp(e),
                }
            }
            ("POST", []) => {
                let b: NewNote = match parse(&req.body) {
                    Ok(b) => b,
                    Err(r) => return r,
                };
                let scope = match Scope::parse(&b.scope) {
                    Ok(s) => s,
                    Err(e) => return mem_resp(e),
                };
                let r = host.memory.write(
                    &me,
                    &scope,
                    ozbox_memory::memory::NewEntry {
                        title: b.title,
                        body: b.body,
                        tags: b.tags,
                        expires_ms: b.expires_days.map(|d| now + d.min(3650) * 86_400_000),
                    },
                    now,
                );
                match r {
                    Ok(e) => {
                        self.log_activity("memory add", &e.id, None, "ok");
                        Resp::json(200, &entry_json(&e))
                    }
                    Err(e) => mem_resp(e),
                }
            }
            ("POST", ["reindex"]) => match host.memory.reindex() {
                Ok(n) => Resp::json(200, &json!({ "notes": n })),
                Err(e) => mem_resp(e),
            },
            ("GET", [id]) => match host.memory.get(&me, id, now) {
                Ok(e) => Resp::json(200, &entry_json(&e)),
                Err(e) => mem_resp(e),
            },
            ("PUT", [id]) => {
                let b: EditNote = match parse(&req.body) {
                    Ok(b) => b,
                    Err(r) => return r,
                };
                let patch = Patch {
                    title: b.title,
                    body: b.body,
                    tags: b.tags,
                    expires_ms: b
                        .expires_days
                        .map(|o| o.map(|d| now + d.min(3650) * 86_400_000)),
                };
                match host.memory.update(&me, id, patch, now) {
                    Ok(e) => {
                        self.log_activity("memory edit", &e.id, None, "ok");
                        Resp::json(200, &entry_json(&e))
                    }
                    Err(e) => mem_resp(e),
                }
            }
            ("POST", [id, "approve"]) => match host.memory.approve(&me, id, now) {
                Ok(e) => {
                    self.log_activity("memory approve", &e.id, None, "ok");
                    Resp::json(200, &entry_json(&e))
                }
                Err(e) => mem_resp(e),
            },
            ("DELETE", [id]) => match host.memory.forget(&me, id, now) {
                Ok(()) => {
                    self.log_activity("memory forget", id, None, "ok");
                    Resp::json(200, &json!({ "forgotten": id }))
                }
                Err(e) => mem_resp(e),
            },
            (_, [] | ["reindex"] | [_] | [_, "approve"]) => {
                Resp::error(405, "method_not_allowed", "method not allowed")
            }
            _ => Resp::error(404, "not_found", "no such endpoint"),
        }
    }

    pub(super) fn skills_route(&mut self, req: &Req, rest: &[&str]) -> Resp {
        let host = match self.memory_host() {
            Ok(h) => h,
            Err(r) => return r,
        };
        let who = self.who(req);
        let now = unix_ms();
        match (req.method.as_str(), rest) {
            ("GET", []) => Resp::json(
                200,
                &json!({ "skills": host.skills.catalog(), "store": self.memory_store_json() }),
            ),
            ("GET", ["holdings"]) => self.skill_holdings(),
            ("POST", []) => self.skill_add(req),
            ("DELETE", [name]) => self.skill_delete(name),
            ("GET", [name, "history"]) => self.skill_history(name),
            ("POST", [name, "restore"]) => self.skill_restore(name, req),
            ("GET", [name, "review"]) => {
                let q = parse_query(&req.query);
                match host.skills.review(name, q.get("hash").map(String::as_str)) {
                    Ok(r) => Resp::json(200, &r),
                    Err(e) => skill_resp(e),
                }
            }
            ("POST", [name, "install"]) => {
                let b: ScopeBody = match parse(&req.body) {
                    Ok(b) => b,
                    Err(r) => return r,
                };
                let scope = match InstallScope::parse(&b.scope) {
                    Ok(s) => s,
                    Err(e) => return skill_resp(e),
                };
                match host.skills.install(name, &scope, &who, now) {
                    Ok(v) => {
                        self.log_activity("skill install", name, None, &b.scope);
                        Resp::json(200, &v)
                    }
                    Err(e) => skill_resp(e),
                }
            }
            ("POST", [name, "uninstall"]) => {
                let b: ScopeBody = match parse(&req.body) {
                    Ok(b) => b,
                    Err(r) => return r,
                };
                let scope = match InstallScope::parse(&b.scope) {
                    Ok(s) => s,
                    Err(e) => return skill_resp(e),
                };
                match host.skills.uninstall(name, &scope) {
                    Ok(()) => {
                        self.log_activity("skill uninstall", name, None, &b.scope);
                        Resp::json(200, &json!({ "removed": name }))
                    }
                    Err(e) => skill_resp(e),
                }
            }
            ("POST", [name, "approve"]) => {
                let b: HashBody = match parse(&req.body) {
                    Ok(b) => b,
                    Err(r) => return r,
                };
                match host.skills.approve(name, &b.hash, &who, now) {
                    Ok(()) => {
                        self.log_activity(
                            "skill approve",
                            name,
                            None,
                            &b.hash.chars().take(12).collect::<String>(),
                        );
                        Resp::json(200, &json!({ "approved": name, "hash": b.hash }))
                    }
                    Err(e) => skill_resp(e),
                }
            }
            ("POST", [name, "revoke"]) => match host.skills.revoke(name) {
                Ok(()) => {
                    self.log_activity("skill revoke", name, None, "ok");
                    Resp::json(200, &json!({ "revoked": name }))
                }
                Err(e) => skill_resp(e),
            },
            (
                _,
                []
                | ["holdings"]
                | [_]
                | [_, "history" | "review" | "install" | "uninstall" | "approve" | "revoke" | "restore"],
            ) => Resp::error(405, "method_not_allowed", "method not allowed"),
            _ => Resp::error(404, "not_found", "no such endpoint"),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::*;

    fn app(dir: &std::path::Path) -> App {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7878);
        App::new(
            Box::new(ozbox_provider_fake::open(dir.join("state"))),
            true,
            addr,
            "tok".into(),
        )
        .with_settings(
            crate::settings::Settings::default(),
            Some(dir.join("settings.json")),
        )
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

    #[test]
    fn memory_and_skills_say_where_they_are_kept() {
        let d = tempfile::tempdir().unwrap();
        let mut a = app(d.path());
        for path in ["/v1/memory", "/v1/skills"] {
            let (s, v) = call(&mut a, "GET", path, Value::Null);
            assert_eq!(s, 200);
            assert_eq!(v["store"]["persisted"], true, "{path}");
            assert!(v["store"]["on_a_box"].is_boolean(), "{path}");
        }
        // with no settings file to sit beside, the folder is this process's own, and the page is told
        let mut b = App::new(
            Box::new(ozbox_provider_fake::open(d.path().join("state2"))),
            true,
            std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 7878),
            "tok".into(),
        );
        let (_, v) = call(&mut b, "GET", "/v1/memory", Value::Null);
        assert_eq!(v["store"]["persisted"], false);
    }

    #[test]
    fn a_person_adds_edits_searches_approves_and_forgets_notes() {
        let d = tempfile::tempdir().unwrap();
        let mut a = app(d.path());
        let (s, n) = call(
            &mut a,
            "POST",
            "/v1/memory",
            json!({ "scope": "project:acme", "title": "Release order", "body": "Database first, then the app.", "tags": ["release"] }),
        );
        assert_eq!(s, 200, "{n}");
        assert_eq!(n["state"], "approved");
        let id = n["id"].as_str().unwrap().to_string();
        let (s, l) = call(&mut a, "GET", "/v1/memory?q=datab", Value::Null);
        assert_eq!((s, l["notes"].as_array().unwrap().len()), (200, 1));
        let (s, e) = call(
            &mut a,
            "PUT",
            &format!("/v1/memory/{id}"),
            json!({ "body": "Database first, then the app, then the check.", "expires_days": null }),
        );
        assert_eq!(s, 200, "{e}");
        assert_eq!(e["revision"], 2);
        let (s, v) = call(
            &mut a,
            "POST",
            "/v1/memory",
            json!({ "scope": "box:main", "title": "Key", "body": concat!("the key is s", "k-abcdefghijklmnopqrstuvwxyz0123") }),
        );
        assert_eq!((s, v["code"].as_str()), (422, Some("looks_like_a_secret")));
        assert!(!v.to_string().contains("sk-abc"));
        let (s, _) = call(&mut a, "DELETE", &format!("/v1/memory/{id}"), Value::Null);
        assert_eq!(s, 200);
        let (s, _) = call(&mut a, "GET", &format!("/v1/memory/{id}"), Value::Null);
        assert_eq!(s, 404);
        let (s, _) = call(&mut a, "GET", "/v1/memory/..%2f..%2fetc", Value::Null);
        assert_eq!(s, 404);
        let (s, _) = call(
            &mut a,
            "POST",
            "/v1/memory",
            json!({ "scope": "everything", "title": "x", "body": "y" }),
        );
        assert_eq!(s, 400);
    }

    #[test]
    fn an_agent_proposal_is_pending_until_a_person_approves_it() {
        let d = tempfile::tempdir().unwrap();
        let mut a = app(d.path());
        let host = a.memory_host().unwrap();
        let agent = Caller::Agent(ozbox_memory::memory::AgentCtx {
            person: "owner".into(),
            run: Some("t1".into()),
            terminal: None,
            projects: vec![],
            box_name: Some("main".into()),
        });
        let scope = Scope::parse("box:main").unwrap();
        let p = host
            .memory
            .write(
                &agent,
                &scope,
                ozbox_memory::memory::NewEntry {
                    title: "Ports".into(),
                    body: "Preview on 3100.".into(),
                    ..Default::default()
                },
                1,
            )
            .unwrap();
        let (_, l) = call(&mut a, "GET", "/v1/memory?state=pending", Value::Null);
        assert_eq!(l["notes"][0]["by_agent"], true);
        assert_eq!(l["stats"]["pending"], 1);
        assert!(host.memory.get(&agent, &p.id, 2).is_err());
        let (s, e) = call(
            &mut a,
            "POST",
            &format!("/v1/memory/{}/approve", p.id),
            Value::Null,
        );
        assert_eq!((s, e["state"].as_str()), (200, Some("approved")));
        assert!(host.memory.get(&agent, &p.id, 3).is_ok());
    }

    #[test]
    fn skills_are_listed_reviewed_installed_and_approved_by_exact_hash() {
        let d = tempfile::tempdir().unwrap();
        let mut a = app(d.path());
        let (s, l) = call(&mut a, "GET", "/v1/skills", Value::Null);
        assert_eq!(s, 200);
        let skills = l["skills"].as_array().unwrap();
        assert!(skills.len() >= 6, "the shipped skills are in the catalog");
        let k = skills
            .iter()
            .find(|x| x["name"] == "release-runner")
            .unwrap();
        let hash = k["hash"].as_str().unwrap().to_string();
        assert_eq!(k["approved"], false);
        let (s, r) = call(
            &mut a,
            "GET",
            "/v1/skills/release-runner/review",
            Value::Null,
        );
        assert_eq!(s, 200);
        assert_eq!(r["hash"], hash.as_str());
        assert!(r["files"][0]["text"]
            .as_str()
            .unwrap()
            .contains("Release runner"));
        let (s, v) = call(
            &mut a,
            "POST",
            "/v1/skills/release-runner/install",
            json!({ "scope": "fleet" }),
        );
        assert_eq!((s, v["status"].as_str()), (200, Some("needs_review")));
        let (s, v) = call(
            &mut a,
            "POST",
            "/v1/skills/release-runner/approve",
            json!({ "hash": "00" }),
        );
        assert_eq!((s, v["code"].as_str()), (409, Some("stale")));
        let (s, _) = call(
            &mut a,
            "POST",
            "/v1/skills/release-runner/approve",
            json!({ "hash": hash }),
        );
        assert_eq!(s, 200);
        let (_, l) = call(&mut a, "GET", "/v1/skills", Value::Null);
        let k = l["skills"]
            .as_array()
            .unwrap()
            .iter()
            .find(|x| x["name"] == "release-runner")
            .unwrap()
            .clone();
        assert_eq!(k["installs"][0]["status"], "approved");
        let (s, _) = call(
            &mut a,
            "POST",
            "/v1/skills/release-runner/revoke",
            Value::Null,
        );
        assert_eq!(s, 200);
        let (s, _) = call(
            &mut a,
            "POST",
            "/v1/skills/release-runner/install",
            json!({ "scope": "box:../x" }),
        );
        assert_eq!(s, 400);
        let (s, _) = call(&mut a, "GET", "/v1/skills/nope/review", Value::Null);
        assert_eq!(s, 404);
    }

    fn app_with_boxes(dir: &std::path::Path, running: &[&str], paused: &[&str]) -> App {
        use ozbox_core::{BoxName, BoxSpec, Provider, Size};
        let p = ozbox_provider_fake::open(dir.join("state"));
        for n in running.iter().chain(paused) {
            let provider: &dyn Provider = &p;
            let plan = provider
                .plan(&ozbox_core::Operation::Create {
                    spec: BoxSpec::new(BoxName::new(*n).unwrap(), Size::S),
                })
                .unwrap();
            provider.apply(&plan).unwrap();
        }
        for n in paused {
            let provider: &dyn Provider = &p;
            let plan = provider
                .plan(&ozbox_core::Operation::Pause {
                    name: BoxName::new(*n).unwrap(),
                })
                .unwrap();
            provider.apply(&plan).unwrap();
        }
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7878);
        App::new(Box::new(p), true, addr, "tok".into()).with_settings(
            crate::settings::Settings::default(),
            Some(dir.join("settings.json")),
        )
    }

    fn files_body(name: &str, extra: &str) -> Value {
        json!({ "files": {
            "SKILL.md": format!("---\nname: {name}\ndescription: Does a thing.\nversion: 1\n---\n{extra}\n"),
            "notes/a.md": "more",
        }})
    }

    #[test]
    fn a_person_adds_a_skill_of_their_own_and_it_waits_for_approval() {
        let d = tempfile::tempdir().unwrap();
        let mut a = app(d.path());
        let (s, v) = call(&mut a, "POST", "/v1/skills", files_body("mine", "Do it."));
        assert_eq!(s, 200, "{v}");
        assert_eq!(v["source"], "library");
        assert_eq!(v["approved"], false);
        assert_eq!(v["provenance"]["via"], "page_upload");
        assert!(v["provenance"]["by"].as_str().is_some());
        // the same name again needs the hash the person saw, so two tabs cannot overwrite each other
        let (s, r) = call(
            &mut a,
            "POST",
            "/v1/skills",
            files_body("mine", "Do it differently."),
        );
        assert_eq!((s, r["code"].as_str()), (409, Some("stale")));
        let mut again = files_body("mine", "Do it differently.");
        again["replaces"] = json!("00");
        assert_eq!(call(&mut a, "POST", "/v1/skills", again.clone()).0, 409);
        again["replaces"] = v["hash"].clone();
        again["via"] = json!("page_editor");
        let (s, v2) = call(&mut a, "POST", "/v1/skills", again);
        assert_eq!(s, 200, "{v2}");
        assert_eq!(v2["revisions"], 1);
        assert_ne!(v2["hash"], v["hash"]);
        // history and restore: the earlier version is read, restored, and waits for approval again
        let (_, h) = call(&mut a, "GET", "/v1/skills/mine/history", Value::Null);
        assert_eq!(h["revisions"].as_array().unwrap().len(), 2);
        let old = v["hash"].as_str().unwrap();
        let (s, r) = call(
            &mut a,
            "GET",
            &format!("/v1/skills/mine/review?hash={old}"),
            Value::Null,
        );
        assert_eq!(s, 200);
        assert!(r["files"][0]["text"].as_str().unwrap().contains("Do it."));
        let (s, back) = call(
            &mut a,
            "POST",
            "/v1/skills/mine/restore",
            json!({ "hash": old }),
        );
        assert_eq!((s, back["hash"].as_str()), (200, Some(old)));
        assert_eq!(back["provenance"]["via"], "restore");
        // a bundled name is not taken over without saying so
        let (s, r) = call(
            &mut a,
            "POST",
            "/v1/skills",
            files_body("release-runner", "mine"),
        );
        assert_eq!((s, r["code"].as_str()), (409, Some("stale")));
        let mut shadow = files_body("release-runner", "mine");
        shadow["shadow_bundled"] = json!(true);
        let (s, r) = call(&mut a, "POST", "/v1/skills", shadow);
        assert_eq!((s, r["shadows_bundled"].clone()), (200, json!(true)));
        // refused: a secret, a hidden character, a path that escapes, a type that is not text
        let mut bad = files_body("sneaky", "x");
        bad["files"]["k.md"] = json!(concat!("the key is s", "k-abcdefghijklmnopqrstuvwxyz0123"));
        let (s, r) = call(&mut a, "POST", "/v1/skills", bad);
        assert_eq!(s, 400);
        assert!(!r.to_string().contains("sk-abc"));
        for (path, text) in [
            ("n.md", "a\u{202E}b"),
            ("../x.md", "x"),
            ("run.exe", "x"),
            ("link.md", "\u{0}"),
        ] {
            let mut bad = files_body("sneaky", "x");
            bad["files"][path] = json!(text);
            assert_eq!(call(&mut a, "POST", "/v1/skills", bad).0, 400, "{path}");
        }
        assert_eq!(
            call(
                &mut a,
                "POST",
                "/v1/skills",
                json!({ "files": {}, "extra": 1 })
            )
            .0,
            400
        );
        // delete leaves the bundled ones alone
        assert_eq!(
            call(&mut a, "DELETE", "/v1/skills/mine", Value::Null).0,
            200
        );
        assert_eq!(
            call(&mut a, "DELETE", "/v1/skills/mine", Value::Null).0,
            404
        );
        assert_eq!(
            call(
                &mut a,
                "DELETE",
                "/v1/skills/ci-failure-triage",
                Value::Null
            )
            .0,
            404
        );
    }

    #[test]
    fn a_skill_is_put_on_a_boxs_disk_only_when_approved_and_what_the_box_holds_is_read_back() {
        let d = tempfile::tempdir().unwrap();
        let mut a = app_with_boxes(d.path(), &["alpha"], &["bravo"]);
        let (_, v) = call(&mut a, "POST", "/v1/skills", files_body("mine", "Do it."));
        let hash = v["hash"].as_str().unwrap().to_string();
        // not approved: refused, and nothing is written
        let (s, r) = call(
            &mut a,
            "PUT",
            "/v1/boxes/alpha/skills/mine",
            json!({ "hash": hash }),
        );
        assert_eq!((s, r["code"].as_str()), (409, Some("not_approved")));
        let (_, hold) = call(&mut a, "GET", "/v1/boxes/alpha/skills", Value::Null);
        assert_eq!(hold["skills"].as_array().unwrap().len(), 0);
        let (s, _) = call(
            &mut a,
            "POST",
            "/v1/skills/mine/approve",
            json!({ "hash": hash }),
        );
        assert_eq!(s, 200);
        // a hash the library no longer has is a stale push
        let (s, r) = call(
            &mut a,
            "PUT",
            "/v1/boxes/alpha/skills/mine",
            json!({ "hash": "00" }),
        );
        assert_eq!((s, r["code"].as_str()), (409, Some("stale")));
        // an agent this box cannot serve is refused; a stopped box cannot be asked
        let (s, _) = call(
            &mut a,
            "PUT",
            "/v1/boxes/alpha/skills/mine",
            json!({ "hash": hash, "agents": ["nope"] }),
        );
        assert_eq!(s, 400);
        let (s, r) = call(
            &mut a,
            "PUT",
            "/v1/boxes/bravo/skills/mine",
            json!({ "hash": hash }),
        );
        assert_eq!((s, r["code"].as_str()), (409, Some("box_not_running")));
        let (s, r) = call(
            &mut a,
            "PUT",
            "/v1/boxes/alpha/skills/mine",
            json!({ "hash": hash, "agents": ["claude-code", "agents"] }),
        );
        assert_eq!(s, 200, "{r}");
        assert_eq!(r["source"], "simulated");
        let (_, hold) = call(&mut a, "GET", "/v1/boxes/alpha/skills", Value::Null);
        let place = &hold["skills"][0]["places"][0];
        assert_eq!(
            (place["state"].as_str(), place["matches_library"].clone()),
            (Some("intact"), json!(true))
        );
        assert_eq!(hold["skills"][0]["places"].as_array().unwrap().len(), 2);
        // the whole fleet: a stopped box is "not known", never "holds nothing"
        let (_, all) = call(&mut a, "GET", "/v1/skills/holdings", Value::Null);
        let by: std::collections::HashMap<&str, &Value> = all["boxes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| (b["box"].as_str().unwrap(), b))
            .collect();
        assert_eq!(by["alpha"]["state"], "ok");
        assert_eq!(by["bravo"]["state"], "stopped");
        // the library moves on: the box's copy is now different, and a new push needs the new approval
        let mut next = files_body("mine", "Do it better.");
        next["replaces"] = json!(hash);
        let (_, v2) = call(&mut a, "POST", "/v1/skills", next);
        let (_, hold) = call(&mut a, "GET", "/v1/boxes/alpha/skills", Value::Null);
        assert_eq!(hold["skills"][0]["places"][0]["matches_library"], false);
        let (s, r) = call(
            &mut a,
            "PUT",
            "/v1/boxes/alpha/skills/mine",
            json!({ "hash": v2["hash"] }),
        );
        assert_eq!((s, r["code"].as_str()), (409, Some("not_approved")));
        // the recorded push keeps its approval alive, and shows in the catalog
        let (_, l) = call(&mut a, "GET", "/v1/skills", Value::Null);
        let mine = l["skills"]
            .as_array()
            .unwrap()
            .iter()
            .find(|x| x["name"] == "mine")
            .unwrap();
        assert_eq!(mine["pushes"][0]["box_name"], "alpha");
        assert_eq!(mine["pushes"][0]["matches_library"], false);
        // remove: only what the push made
        let (s, _) = call(&mut a, "DELETE", "/v1/boxes/alpha/skills/mine", Value::Null);
        assert_eq!(s, 200);
        let (s, r) = call(&mut a, "DELETE", "/v1/boxes/alpha/skills/mine", Value::Null);
        assert_eq!((s, r["code"].as_str()), (404, Some("not_found")));
        let (_, hold) = call(&mut a, "GET", "/v1/boxes/alpha/skills", Value::Null);
        assert_eq!(hold["skills"].as_array().unwrap().len(), 0);
        let (_, l) = call(&mut a, "GET", "/v1/skills", Value::Null);
        let mine = l["skills"]
            .as_array()
            .unwrap()
            .iter()
            .find(|x| x["name"] == "mine")
            .unwrap();
        assert_eq!(mine["pushes"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn only_a_skills_upload_may_be_larger_than_the_usual_body() {
        assert_eq!(
            super::super::skills_routes::big_body_cap("POST", "/v1/skills"),
            Some(ozbox_core::skill_pack::MAX_PACK_BODY)
        );
        for (m, p) in [
            ("POST", "/v1/memory"),
            ("PUT", "/v1/skills"),
            ("POST", "/v1/skills/x/approve"),
            ("GET", "/v1/skills"),
        ] {
            assert_eq!(
                super::super::skills_routes::big_body_cap(m, p),
                None,
                "{m} {p}"
            );
        }
    }
}
