//! Skills on the box's own disk: the folders its coding agents read.
//!
//! The dashboard sends a skill a person has approved (`PUT /v1/skills/<name>`: the files and the hash that was approved).
//! This service checks it again with the same rules the library uses, refuses it unless the files hash to the hash it was
//! sent with, and writes it into each agent's skills folder under the box user's home: staged in a fresh folder beside the
//! target and swapped in by rename, so an agent reading the folder never sees half a skill. `DELETE` takes it away and
//! `GET` reports what is there.
//!
//! **The box's disk is the box user's.** An agent running as that user can edit these files. This service does not try to
//! prevent that; it detects it: `GET` re-hashes the files on disk every time and says `modified` when they are not what
//! was pushed, and it never trusts its own record for that. It also never writes through a symbolic link, never makes a file
//! executable, and never touches a folder it did not put there: a skill a person placed by hand under the same name is
//! refused, not overwritten, and `DELETE` removes only what a push made.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use ozbox_core::skill_pack::{
    hash_files, skill_agent, skill_name_ok, SkillAgent, SkillPack, SKILL_AGENTS,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::timeutil::Clock;

static GLOBAL: OnceLock<Arc<SkillsService>> = OnceLock::new();

pub fn global() -> Option<&'static Arc<SkillsService>> {
    GLOBAL.get()
}

pub fn install_global(s: Arc<SkillsService>) {
    let _ = GLOBAL.set(s);
}

/// Does this path belong to the skills API?
pub fn handles(path: &str) -> bool {
    path == "/v1/skills" || path.starts_with("/v1/skills/")
}

/// One skill in one agent's folder, as this service put it there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Entry {
    name: String,
    agent: String,
    hash: String,
    version: String,
    pushed_by: String,
    pushed_ms: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Manifest {
    #[serde(default)]
    entries: Vec<Entry>,
}

#[derive(Deserialize)]
struct PushBody {
    hash: String,
    #[serde(default)]
    pushed_by: String,
    #[serde(default)]
    agents: Option<Vec<String>>,
    files: BTreeMap<String, String>,
}

pub struct SkillsService {
    home: PathBuf,
    state: PathBuf,
    clock: Arc<dyn Clock>,
    gate: Mutex<()>,
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique() -> String {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("{}-{n}-{t:x}", std::process::id())
}

fn fail(status: u16, code: &str, msg: &str) -> (u16, Value) {
    (
        status,
        json!({ "error": msg, "message": msg, "code": code }),
    )
}

fn clean(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max).collect()
}

/// Read a folder as a skill's files, refusing anything that is not a plain file or folder. `None` when it cannot be read.
fn read_files(dir: &Path) -> Option<BTreeMap<String, Vec<u8>>> {
    fn walk(
        base: &Path,
        dir: &Path,
        out: &mut BTreeMap<String, Vec<u8>>,
        n: &mut usize,
    ) -> Option<()> {
        for e in fs::read_dir(dir).ok()?.flatten() {
            *n += 1;
            if *n > 400 {
                return None;
            }
            let p = e.path();
            let meta = fs::symlink_metadata(&p).ok()?;
            if meta.is_dir() {
                walk(base, &p, out, n)?;
            } else if meta.is_file() {
                if meta.len() > 1024 * 1024 {
                    return None;
                }
                let rel = p
                    .strip_prefix(base)
                    .ok()?
                    .to_string_lossy()
                    .replace('\\', "/");
                out.insert(rel, fs::read(&p).ok()?);
            } else {
                return None;
            }
        }
        Some(())
    }
    let mut out = BTreeMap::new();
    let mut n = 0;
    walk(dir, dir, &mut out, &mut n)?;
    Some(out)
}

impl SkillsService {
    pub fn new(home: PathBuf, state: PathBuf, clock: Arc<dyn Clock>) -> SkillsService {
        SkillsService {
            home,
            state,
            clock,
            gate: Mutex::new(()),
        }
    }

    fn manifest_path(&self) -> PathBuf {
        self.state.join("skills.json")
    }

    fn manifest(&self) -> Manifest {
        fs::read(self.manifest_path())
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn save(&self, m: &Manifest) -> std::io::Result<()> {
        fs::create_dir_all(&self.state)?;
        let tmp = self.state.join(format!(".skills.json.{}", unique()));
        fs::write(&tmp, serde_json::to_vec_pretty(m)?)?;
        fs::rename(&tmp, self.manifest_path())
    }

    fn folder(&self, a: &SkillAgent) -> PathBuf {
        self.home.join(a.folder)
    }

    /// Is any part of `rel` under the home directory a symbolic link? Writing through one could put files anywhere.
    fn linked_ancestor(&self, rel: &str) -> bool {
        let mut p = self.home.clone();
        for c in rel.split('/') {
            p.push(c);
            if fs::symlink_metadata(&p).is_ok_and(|m| m.file_type().is_symlink()) {
                return true;
            }
        }
        false
    }

    pub fn route(&self, method: &str, sub: &str, body: &[u8]) -> (u16, Value) {
        let _g = self.gate.lock().unwrap_or_else(|p| p.into_inner());
        let name = sub.trim_start_matches('/');
        match (method, name) {
            ("GET", "") => self.status(),
            ("PUT", n) if skill_name_ok(n) => self.push(n, body),
            ("DELETE", n) if skill_name_ok(n) => self.remove(n),
            _ if name.is_empty() || skill_name_ok(name) => {
                fail(405, "method_not_allowed", "method not allowed")
            }
            _ => fail(400, "invalid", "that is not a skill name"),
        }
    }

    fn status(&self) -> (u16, Value) {
        let m = self.manifest();
        let agents: Vec<Value> = SKILL_AGENTS
            .iter()
            .map(|a| {
                json!({ "id": a.id, "label": a.label, "reaches": a.reaches, "folder": format!("~/{}", a.folder),
                        "present": self.home.join(a.marker).is_dir() })
            })
            .collect();
        let mut by_name: BTreeMap<String, Vec<Value>> = BTreeMap::new();
        for e in &m.entries {
            let Some(a) = skill_agent(&e.agent) else {
                continue;
            };
            let dir = self.folder(a).join(&e.name);
            let state = if fs::symlink_metadata(&dir).is_err() {
                "missing"
            } else if self.linked_ancestor(&format!("{}/{}", a.folder, e.name)) {
                "modified"
            } else {
                match read_files(&dir) {
                    Some(f) if hash_files(&f) == e.hash => "intact",
                    Some(_) => "modified",
                    None => "modified",
                }
            };
            by_name.entry(e.name.clone()).or_default().push(json!({
                "agent": e.agent, "state": state, "hash": e.hash, "version": clean(&e.version, 40),
                "pushed_by": clean(&e.pushed_by, 80), "pushed_ms": e.pushed_ms,
            }));
        }
        let skills: Vec<Value> = by_name
            .into_iter()
            .map(|(name, places)| json!({ "name": name, "places": places }))
            .collect();
        let mut others = serde_json::Map::new();
        for a in SKILL_AGENTS {
            let mut names: Vec<String> = fs::read_dir(self.folder(a))
                .into_iter()
                .flatten()
                .flatten()
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| {
                    !n.starts_with('.')
                        && !m.entries.iter().any(|x| x.agent == a.id && &x.name == n)
                })
                .map(|n| clean(&n, 64))
                .collect();
            names.sort();
            names.truncate(50);
            others.insert(a.id.to_string(), json!(names));
        }
        (
            200,
            json!({ "agents": agents, "skills": skills, "others": others }),
        )
    }

    fn push(&self, name: &str, body: &[u8]) -> (u16, Value) {
        let b: PushBody = match serde_json::from_slice(body) {
            Ok(b) => b,
            Err(_) => {
                return fail(
                    400,
                    "bad_request",
                    "the request is not what a skill push looks like",
                )
            }
        };
        let files: BTreeMap<String, Vec<u8>> = b
            .files
            .into_iter()
            .map(|(p, t)| (p, t.into_bytes()))
            .collect();
        let pack = match SkillPack::from_files(files) {
            Ok(p) => p,
            Err(e) => return fail(422, "invalid", &clean(&e.to_string(), 200)),
        };
        if pack.name != name {
            return fail(
                400,
                "invalid",
                "the skill's name does not match the one in its SKILL.md",
            );
        }
        if pack.hash() != b.hash {
            return fail(
                409,
                "hash_mismatch",
                "the files do not hash to the digest that was approved; nothing was written",
            );
        }
        let targets: Vec<&SkillAgent> = match &b.agents {
            Some(ids) if !ids.is_empty() => {
                let mut v = Vec::new();
                for id in ids {
                    match skill_agent(id) {
                        Some(a) if !v.contains(&a) => v.push(a),
                        Some(_) => {}
                        None => {
                            return fail(
                                400,
                                "invalid",
                                "that is not an agent this box can put a skill in",
                            )
                        }
                    }
                }
                v
            }
            _ => {
                let present: Vec<&SkillAgent> = SKILL_AGENTS
                    .iter()
                    .filter(|a| self.home.join(a.marker).is_dir())
                    .collect();
                if present.is_empty() {
                    SKILL_AGENTS.iter().take(1).collect()
                } else {
                    present
                }
            }
        };
        let mut m = self.manifest();
        let now = self.clock.now_ms();
        let who = clean(&b.pushed_by, 80);
        let mut results = Vec::new();
        for a in targets {
            match self.write_one(a, &pack, &m) {
                Ok(()) => {
                    m.entries.retain(|e| !(e.name == name && e.agent == a.id));
                    m.entries.push(Entry {
                        name: name.to_string(),
                        agent: a.id.to_string(),
                        hash: b.hash.clone(),
                        version: clean(&pack.version, 40),
                        pushed_by: who.clone(),
                        pushed_ms: now,
                    });
                    results.push(json!({ "agent": a.id, "ok": true }));
                }
                Err((code, msg)) => results
                    .push(json!({ "agent": a.id, "ok": false, "code": code, "message": msg })),
            }
        }
        if m.entries.iter().all(|e| e.name != name) && results.iter().all(|r| r["ok"] == false) {
            let first = &results[0];
            return (
                409,
                json!({ "error": first["message"], "message": first["message"], "code": first["code"], "results": results }),
            );
        }
        if self.save(&m).is_err() {
            return fail(
                500,
                "internal",
                "the skill was written but this box could not record it",
            );
        }
        (
            200,
            json!({ "ok": true, "name": name, "hash": b.hash, "results": results }),
        )
    }

    fn write_one(
        &self,
        a: &SkillAgent,
        pack: &SkillPack,
        m: &Manifest,
    ) -> Result<(), (&'static str, String)> {
        let rel = a.folder;
        if self.linked_ancestor(rel) {
            return Err((
                "unsafe_path",
                format!("{rel} on this box is a link; nothing was written"),
            ));
        }
        let folder = self.folder(a);
        fs::create_dir_all(&folder).map_err(|_| ("io", format!("{rel} could not be made")))?;
        let target = folder.join(&pack.name);
        let ours = m
            .entries
            .iter()
            .any(|e| e.name == pack.name && e.agent == a.id);
        if let Ok(meta) = fs::symlink_metadata(&target) {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err((
                    "unsafe_path",
                    format!("{rel}/{} is not a plain folder; left alone", pack.name),
                ));
            }
            if !ours {
                return Err((
                    "not_ours",
                    format!(
                        "{rel}/{} is already there and was not put there by Oz Box; left alone",
                        pack.name
                    ),
                ));
            }
        }
        let stage = folder.join(format!(".ozbox-stage-{}", unique()));
        let wrote = (|| -> std::io::Result<()> {
            for (p, bytes) in &pack.files {
                let f = stage.join(p);
                if let Some(d) = f.parent() {
                    fs::create_dir_all(d)?;
                }
                write_plain(&f, bytes)?;
            }
            Ok(())
        })();
        if wrote.is_err() {
            let _ = fs::remove_dir_all(&stage);
            return Err(("io", "the files could not be written".into()));
        }
        let aside = folder.join(format!(".ozbox-old-{}", unique()));
        let had = target.exists();
        if had && fs::rename(&target, &aside).is_err() {
            let _ = fs::remove_dir_all(&stage);
            return Err(("io", "the existing copy could not be moved aside".into()));
        }
        if fs::rename(&stage, &target).is_err() {
            if had {
                let _ = fs::rename(&aside, &target);
            }
            let _ = fs::remove_dir_all(&stage);
            return Err(("io", "the new copy could not be put in place".into()));
        }
        if had {
            let _ = fs::remove_dir_all(&aside);
        }
        // what is on disk now is what was approved
        match read_files(&target) {
            Some(f) if hash_files(&f) == pack.hash() => Ok(()),
            _ => Err((
                "verify",
                "the copy on disk does not match what was sent".into(),
            )),
        }
    }

    fn remove(&self, name: &str) -> (u16, Value) {
        let mut m = self.manifest();
        let mine: Vec<Entry> = m
            .entries
            .iter()
            .filter(|e| e.name == name)
            .cloned()
            .collect();
        if mine.is_empty() {
            return fail(
                404,
                "not_found",
                "Oz Box did not put a skill of that name on this box",
            );
        }
        let mut results = Vec::new();
        for e in &mine {
            let Some(a) = skill_agent(&e.agent) else {
                continue;
            };
            let dir = self.folder(a).join(name);
            let rel = format!("{}/{name}", a.folder);
            let ok = if self.linked_ancestor(&rel) {
                false
            } else {
                match fs::symlink_metadata(&dir) {
                    Err(_) => true,
                    Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {
                        fs::remove_dir_all(&dir).is_ok()
                    }
                    Ok(_) => false,
                }
            };
            if ok {
                m.entries
                    .retain(|x| !(x.name == name && x.agent == e.agent));
            }
            results.push(json!({ "agent": e.agent, "ok": ok }));
        }
        if self.save(&m).is_err() {
            return fail(
                500,
                "internal",
                "the skill was removed but this box could not record it",
            );
        }
        let all = results.iter().all(|r| r["ok"] == true);
        (
            if all { 200 } else { 409 },
            json!({ "ok": all, "name": name, "results": results }),
        )
    }
}

/// A plain file, new, mode 0644: never executable, never following a link.
fn write_plain(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut o = fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o644);
    }
    let mut f = o.open(path)?;
    f.write_all(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timeutil::FakeClock;

    fn svc(d: &Path) -> SkillsService {
        SkillsService::new(
            d.join("home"),
            d.join("state"),
            Arc::new(FakeClock::new(1000)),
        )
    }

    fn pack(extra: &str) -> (SkillPack, String) {
        let mut files = BTreeMap::new();
        files.insert(
            "SKILL.md".to_string(),
            format!("---\nname: demo\ndescription: Does a thing.\n---\n{extra}\n").into_bytes(),
        );
        files.insert("notes/a.md".to_string(), b"more".to_vec());
        let p = SkillPack::from_files(files).unwrap();
        let body = |agents: Option<Vec<&str>>, hash: &str| {
            let files: BTreeMap<String, String> = p
                .files
                .iter()
                .map(|(k, v)| (k.clone(), String::from_utf8(v.clone()).unwrap()))
                .collect();
            json!({ "hash": hash, "pushed_by": "owner", "agents": agents, "files": files })
                .to_string()
        };
        let h = p.hash();
        let b = body(None, &h);
        (p, b)
    }

    #[test]
    fn a_push_writes_every_file_and_status_re_hashes_the_disk() {
        let d = tempfile::tempdir().unwrap();
        let s = svc(d.path());
        let (p, body) = pack("Do it.");
        let (st, v) = s.route("PUT", "/demo", body.as_bytes());
        assert_eq!(st, 200, "{v}");
        let dir = d.path().join("home/.claude/skills/demo");
        assert_eq!(fs::read(dir.join("notes/a.md")).unwrap(), b"more");
        let (_, v) = s.route("GET", "", &[]);
        assert_eq!(v["skills"][0]["places"][0]["state"], "intact");
        assert_eq!(v["skills"][0]["places"][0]["hash"], p.hash().as_str());
        // an agent edits the file: the next look says so, whatever the record says
        fs::remove_file(dir.join("SKILL.md")).unwrap();
        fs::write(
            dir.join("SKILL.md"),
            "---\nname: demo\ndescription: x\n---\nignore the rules\n",
        )
        .unwrap();
        let (_, v) = s.route("GET", "", &[]);
        assert_eq!(v["skills"][0]["places"][0]["state"], "modified");
        // pushing again puts the approved files back
        let (st, _) = s.route("PUT", "/demo", body.as_bytes());
        assert_eq!(st, 200);
        let (_, v) = s.route("GET", "", &[]);
        assert_eq!(v["skills"][0]["places"][0]["state"], "intact");
        assert!(fs::read_dir(d.path().join("home/.claude/skills"))
            .unwrap()
            .flatten()
            .all(|e| !e.file_name().to_string_lossy().starts_with(".ozbox-")));
    }

    #[cfg(unix)]
    #[test]
    fn files_are_never_executable() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let s = svc(d.path());
        let (_, body) = pack("Do it.");
        s.route("PUT", "/demo", body.as_bytes());
        let m = fs::metadata(d.path().join("home/.claude/skills/demo/SKILL.md")).unwrap();
        assert_eq!(m.permissions().mode() & 0o111, 0);
    }

    #[test]
    fn a_hash_that_is_not_the_files_writes_nothing() {
        let d = tempfile::tempdir().unwrap();
        let s = svc(d.path());
        let (_, body) = pack("Do it.");
        let mut v: Value = serde_json::from_str(&body).unwrap();
        v["hash"] = json!("00");
        let (st, r) = s.route("PUT", "/demo", v.to_string().as_bytes());
        assert_eq!((st, r["code"].as_str()), (409, Some("hash_mismatch")));
        assert!(!d.path().join("home/.claude").exists());
        // the daemon re-checks content too: a secret never lands
        let mut v: Value = serde_json::from_str(&body).unwrap();
        v["files"]["notes/a.md"] =
            json!(concat!("the key is s", "k-abcdefghijklmnopqrstuvwxyz0123"));
        let (st, _) = s.route("PUT", "/demo", v.to_string().as_bytes());
        assert_eq!(st, 422);
        // a name that does not match SKILL.md, and a path that escapes
        let (st, _) = s.route("PUT", "/other", body.as_bytes());
        assert_eq!(st, 400);
        let mut v: Value = serde_json::from_str(&body).unwrap();
        v["files"]["../evil.md"] = json!("x");
        let (st, _) = s.route("PUT", "/demo", v.to_string().as_bytes());
        assert_eq!(st, 422);
    }

    #[test]
    fn a_skill_a_person_put_there_is_never_overwritten_or_removed() {
        let d = tempfile::tempdir().unwrap();
        let s = svc(d.path());
        let mine = d.path().join("home/.claude/skills/demo");
        fs::create_dir_all(&mine).unwrap();
        fs::write(mine.join("SKILL.md"), "mine").unwrap();
        let (_, body) = pack("Do it.");
        let (st, v) = s.route("PUT", "/demo", body.as_bytes());
        assert_eq!((st, v["code"].as_str()), (409, Some("not_ours")));
        assert_eq!(fs::read_to_string(mine.join("SKILL.md")).unwrap(), "mine");
        let (st, _) = s.route("DELETE", "/demo", &[]);
        assert_eq!(st, 404);
        assert!(mine.exists());
        let (_, v) = s.route("GET", "", &[]);
        assert_eq!(v["others"]["claude-code"][0], "demo");
    }

    #[cfg(unix)]
    #[test]
    fn nothing_is_written_through_a_link() {
        let d = tempfile::tempdir().unwrap();
        let s = svc(d.path());
        let out = d.path().join("elsewhere");
        fs::create_dir_all(&out).unwrap();
        fs::create_dir_all(d.path().join("home")).unwrap();
        std::os::unix::fs::symlink(&out, d.path().join("home/.claude")).unwrap();
        let (_, body) = pack("Do it.");
        let (st, v) = s.route("PUT", "/demo", body.as_bytes());
        assert_eq!((st, v["code"].as_str()), (409, Some("unsafe_path")));
        assert_eq!(fs::read_dir(&out).unwrap().count(), 0);
    }

    #[test]
    fn remove_takes_away_only_what_a_push_made() {
        let d = tempfile::tempdir().unwrap();
        let s = svc(d.path());
        let (_, body) = pack("Do it.");
        let mut v: Value = serde_json::from_str(&body).unwrap();
        v["agents"] = json!(["claude-code", "agents"]);
        let (st, r) = s.route("PUT", "/demo", v.to_string().as_bytes());
        assert_eq!(st, 200, "{r}");
        assert!(d.path().join("home/.agents/skills/demo/SKILL.md").exists());
        let (st, _) = s.route("DELETE", "/demo", &[]);
        assert_eq!(st, 200);
        assert!(!d.path().join("home/.claude/skills/demo").exists());
        assert!(!d.path().join("home/.agents/skills/demo").exists());
        let (_, v) = s.route("GET", "", &[]);
        assert_eq!(v["skills"].as_array().unwrap().len(), 0);
        let (st, _) = s.route("PUT", "/demo", br#"{"x":1}"#);
        assert_eq!(st, 400);
        let (st, _) = s.route("PATCH", "/demo", &[]);
        assert_eq!(st, 405);
        let (st, _) = s.route("GET", "/..", &[]);
        assert_eq!(st, 400);
    }
}
