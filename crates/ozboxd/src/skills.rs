//! Skills on the box's own disk: the folders its coding agents read.
//!
//! The dashboard sends a skill a person has approved (`PUT /v1/skills/<name>`: the files and the hash that was approved).
//! This service checks it again with the same rules the library uses, refuses it unless the files hash to the hash it was
//! sent with, and writes it into each agent's skills folder under the box user's home: staged in a fresh folder beside the
//! target and swapped in by rename, so an agent reading the folder never sees half a skill. `DELETE` takes it away and
//! `GET` reports what is there.
//!
//! **Who may write.** Only the dashboard's own socket (behind the supervisor gate, on the route table in
//! `ozbox_core::daemon_scope`). The box socket is open to every process of the box user, including the coding agents, and a
//! caller there could send any files with their own hash, so it answers `GET` only and refuses `PUT` and `DELETE` (403). The
//! daemon does not take a name or a claim of who pushed from a request; the only act it records is the push itself.
//!
//! **The box's disk is the box user's.** An agent running as that user can edit these files, and this daemon runs as that
//! user too, so its own record (`<state>/skills.json`) is not out of the agent's reach either. The service therefore does not
//! trust the record for anything that matters:
//!
//! - `GET` re-hashes the files on disk every time, with a bound on how much it reads, and reports the disk's own hash next to
//!   what the record says. It says `modified` when they differ.
//! - A folder that exists is replaced or removed only when the dashboard names, in the same request, the hash it recorded
//!   putting there (`claims`), and the record agrees, or the folder's files hash to exactly that. A skill a person placed by
//!   hand, or an entry an agent forged into the record, has no such claim, so it is refused (`not_ours`), never overwritten.
//!   The dashboard keeps its record where the box user cannot reach it.
//! - It never writes through a symbolic link (when it looks) and never makes a file executable. That does not stop an agent
//!   running a file, so the review marks scripts and the commands a `SKILL.md` runs.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use ozbox_core::skill_pack::{
    legacy_name_ok, skill_agent, skill_name_ok, PackHasher, SkillAgent, SkillPack, MAX_FILES,
    MAX_FILE_BYTES, MAX_TOTAL_BYTES, SKILL_AGENTS,
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

/// One skill in one agent's folder, as this service last put it there. A record, not proof: the box user can edit it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Entry {
    name: String,
    agent: String,
    hash: String,
    version: String,
    pushed_ms: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Manifest {
    #[serde(default)]
    entries: Vec<Entry>,
}

#[derive(Deserialize)]
struct PushBody {
    hash: String,
    #[serde(default)]
    agents: Option<Vec<String>>,
    /// Per agent, the hash the dashboard recorded putting in that folder. Required to replace a folder that is there.
    #[serde(default)]
    claims: BTreeMap<String, String>,
    files: BTreeMap<String, String>,
}

#[derive(Deserialize, Default)]
struct RemoveBody {
    #[serde(default)]
    claims: BTreeMap<String, String>,
}

pub struct SkillsService {
    home: PathBuf,
    state: PathBuf,
    clock: Arc<dyn Clock>,
    /// Held by `PUT` and `DELETE`, one at a time. `GET` does not take it for the slow part (hashing the disk).
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

const MAX_DIRS: usize = 200;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
/// The places one `GET` follows (an agent could write any number of records), and the bytes it reads across all of them.
const MAX_PLACES: usize = 64;
const MAX_LOOK_BYTES: u64 = 16 * 1024 * 1024;
const MAX_DEPTH: usize = 4;

/// The hash of a skill folder on disk, read with a bound: at most `MAX_FILES` files, `MAX_DIRS` folders, `MAX_DEPTH` levels,
/// `MAX_FILE_BYTES` per file and `MAX_TOTAL_BYTES` in all (the limits a skill is accepted under). Anything over, a link, a
/// special file or a file that changed while it was read is `None`, which callers report as `modified`. Files are hashed one
/// at a time, so memory is a few KiB whatever is on the disk.
fn hash_dir(dir: &Path) -> Option<String> {
    hash_dir_within(dir, None)
}

/// [`hash_dir`], also drawing the bytes it would read from `budget` (what one look at the whole box may read in all). A folder
/// that would overdraw it is `None`, like any other folder that cannot be vouched for.
fn hash_dir_within(dir: &Path, budget: Option<&mut u64>) -> Option<String> {
    struct Found {
        rel: String,
        path: PathBuf,
        len: u64,
    }
    fn walk(
        base: &Path,
        dir: &Path,
        depth: usize,
        out: &mut Vec<Found>,
        dirs: &mut usize,
        total: &mut u64,
    ) -> Option<()> {
        for e in fs::read_dir(dir).ok()? {
            let e = e.ok()?;
            let p = e.path();
            let meta = fs::symlink_metadata(&p).ok()?;
            if meta.is_dir() {
                *dirs += 1;
                if *dirs > MAX_DIRS || depth + 1 >= MAX_DEPTH {
                    return None;
                }
                walk(base, &p, depth + 1, out, dirs, total)?;
            } else if meta.is_file() {
                if out.len() >= MAX_FILES || meta.len() > MAX_FILE_BYTES as u64 {
                    return None;
                }
                *total += meta.len();
                if *total > MAX_TOTAL_BYTES as u64 {
                    return None;
                }
                let rel = p
                    .strip_prefix(base)
                    .ok()?
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push(Found {
                    rel,
                    path: p,
                    len: meta.len(),
                });
            } else {
                return None;
            }
        }
        Some(())
    }
    let mut found = Vec::new();
    let (mut dirs, mut total) = (0usize, 0u64);
    walk(dir, dir, 0, &mut found, &mut dirs, &mut total)?;
    if let Some(b) = budget {
        if total > *b {
            return None;
        }
        *b -= total;
    }
    found.sort_by(|a, b| a.rel.cmp(&b.rel));
    let mut h = PackHasher::new();
    for f in &found {
        let file = open_plain(&f.path)?;
        // opened, not followed: what was opened must be the plain file that was looked at
        let meta = file.metadata().ok()?;
        if !meta.is_file() || meta.len() != f.len {
            return None;
        }
        if !h.add(&f.rel, f.len, file.take(f.len + 1)).ok()? {
            return None;
        }
    }
    Some(h.finish())
}

/// Open a file to read, only if it is a plain file: never through a link, and without waiting on a pipe. A path that was swapped
/// for a link or a FIFO between looking at it and opening it is refused here, not followed or waited on.
fn open_plain(path: &Path) -> Option<fs::File> {
    let mut o = fs::OpenOptions::new();
    o.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let f = o.open(path).ok()?;
    f.metadata().ok()?.is_file().then_some(f)
}

/// A copy that was put in place and can still be taken back: the folder the swap moved aside, until the whole push is done.
struct Placed {
    target: PathBuf,
    aside: Option<PathBuf>,
}

impl Placed {
    fn commit(self) {
        if let Some(a) = self.aside {
            let _ = fs::remove_dir_all(a);
        }
    }

    fn roll_back(self) {
        let _ = fs::remove_dir_all(&self.target);
        if let Some(a) = self.aside {
            let _ = fs::rename(a, &self.target);
        }
    }
}

impl SkillsService {
    pub fn new(home: PathBuf, state: PathBuf, clock: Arc<dyn Clock>) -> SkillsService {
        let svc = SkillsService {
            home,
            state,
            clock,
            gate: Mutex::new(()),
        };
        // Leftovers of a push that was cut short (nothing is in flight at start): swept, never read as skills.
        if !fs::symlink_metadata(svc.work_dir()).is_ok_and(|m| m.file_type().is_symlink()) {
            let _ = fs::remove_dir_all(svc.work_dir());
        }
        svc
    }

    fn manifest_path(&self) -> PathBuf {
        self.state.join("skills.json")
    }

    /// The record, read as a plain file of at most 1 MiB (the box user can write anything there, so it is bounded and never a
    /// link or a pipe); anything else reads as an empty record.
    fn manifest(&self) -> Manifest {
        let Some(f) = open_plain(&self.manifest_path()) else {
            return Manifest::default();
        };
        let mut buf = Vec::new();
        if f.take(MAX_MANIFEST_BYTES + 1)
            .read_to_end(&mut buf)
            .is_err()
            || buf.len() as u64 > MAX_MANIFEST_BYTES
        {
            return Manifest::default();
        }
        serde_json::from_slice(&buf).unwrap_or_default()
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

    /// Where a push is staged and the old copy set aside: beside the agents' skills folders, on the same filesystem (so a swap
    /// is a rename) but outside them, so a program reading a skills folder never meets a half-written or set-aside one.
    fn work_dir(&self) -> PathBuf {
        self.home.join(".ozbox-skills-work")
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

    /// `dashboard` is true only for a request that came in on the dashboard's own socket. A write from anywhere else is
    /// refused here as well as at the socket, so no caller of this service can write without being the dashboard.
    pub fn route(&self, method: &str, sub: &str, body: &[u8], dashboard: bool) -> (u16, Value) {
        let name = sub.trim_start_matches('/');
        match (method, name) {
            ("GET", "") => self.status(),
            ("PUT" | "DELETE", n) if legacy_name_ok(n) && !dashboard => fail(
                403,
                "skills_write_not_here",
                "a skill is put on this box through the dashboard's socket, not this one",
            ),
            ("PUT", n) if skill_name_ok(n) => {
                let _g = self.gate.lock().unwrap_or_else(|p| p.into_inner());
                self.push(n, body)
            }
            ("DELETE", n) if legacy_name_ok(n) => {
                let _g = self.gate.lock().unwrap_or_else(|p| p.into_inner());
                self.remove(n, body)
            }
            _ if name.is_empty() || skill_name_ok(name) => {
                fail(405, "method_not_allowed", "method not allowed")
            }
            _ => fail(400, "invalid", "that is not a skill name"),
        }
    }

    /// What is on disk for one recorded place: the state against the record, and the disk's own hash when it can be read.
    fn inspect(
        &self,
        a: &SkillAgent,
        e: &Entry,
        budget: &mut u64,
    ) -> (&'static str, Option<String>) {
        let dir = self.folder(a).join(&e.name);
        if fs::symlink_metadata(&dir).is_err() {
            return ("missing", None);
        }
        if self.linked_ancestor(&format!("{}/{}", a.folder, e.name)) {
            return ("modified", None);
        }
        match hash_dir_within(&dir, Some(budget)) {
            Some(h) if h == e.hash => ("intact", Some(h)),
            other => ("modified", other),
        }
    }

    fn status(&self) -> (u16, Value) {
        let m = self.manifest();
        // An entry the box user wrote could name anything: only a real agent and a valid skill name are followed.
        // Each (name, agent) once (the last record wins), and no more than [`MAX_PLACES`] of them: the record is the box
        // user's to write, so how many places it names, and how much they hold, is not for it to decide.
        let mut places: Vec<(&Entry, &SkillAgent)> = Vec::new();
        for e in &m.entries {
            // a copy under a name from before the format is still shown (and removable); nothing new is put under one
            if !legacy_name_ok(&e.name) {
                continue;
            }
            let Some(a) = skill_agent(&e.agent) else {
                continue;
            };
            places.retain(|(x, xa)| !(x.name == e.name && xa.id == a.id));
            places.push((e, a));
        }
        places.truncate(MAX_PLACES);
        // The disk is read without the write gate: hashing is bounded, and a push in flight can only make a place look
        // missing or modified for a moment, so anything that is not intact is looked at once more after any write has ended.
        let mut budget = MAX_LOOK_BYTES;
        let mut seen: Vec<(&'static str, Option<String>)> = places
            .iter()
            .map(|(e, a)| self.inspect(a, e, &mut budget))
            .collect();
        if seen.iter().any(|(s, _)| *s != "intact") {
            drop(self.gate.lock().unwrap_or_else(|p| p.into_inner()));
            let mut budget = MAX_LOOK_BYTES;
            for (i, (e, a)) in places.iter().enumerate() {
                if seen[i].0 != "intact" {
                    seen[i] = self.inspect(a, e, &mut budget);
                }
            }
        }
        let agents: Vec<Value> = SKILL_AGENTS
            .iter()
            .map(|a| {
                json!({ "id": a.id, "label": a.label, "reaches": a.reaches, "folder": format!("~/{}", a.folder),
                        "present": self.home.join(a.marker).is_dir() })
            })
            .collect();
        let mut by_name: BTreeMap<String, Vec<Value>> = BTreeMap::new();
        for ((e, a), (state, disk)) in places.iter().zip(seen) {
            // `others` is best effort: the box user can add or remove folders at any moment, so it is a look, not a ledger.
            // `hash` and `version` are what the record says (the box user can edit it); `disk_hash` is what is there.
            by_name.entry(e.name.clone()).or_default().push(json!({
                "agent": a.id, "state": state, "hash": e.hash, "disk_hash": disk,
                "version": clean(&e.version, 40), "pushed_ms": e.pushed_ms,
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
                .take(1000)
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| !m.entries.iter().any(|x| x.agent == a.id && &x.name == n))
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
        let m = self.manifest();
        let now = self.clock.now_ms();
        let mut results = Vec::new();
        let mut placed: Vec<(&SkillAgent, Placed)> = Vec::new();
        for a in targets {
            match self.write_one(a, &pack, &m, b.claims.get(a.id).map(String::as_str)) {
                Ok(p) => placed.push((a, p)),
                Err((code, msg)) => results
                    .push(json!({ "agent": a.id, "ok": false, "code": code, "message": msg })),
            }
        }
        if placed.is_empty() {
            let first = &results[0];
            return (
                409,
                json!({ "error": first["message"], "message": first["message"], "code": first["code"], "results": results }),
            );
        }
        let mut next = m.clone();
        for (a, _) in &placed {
            next.entries
                .retain(|e| !(e.name == name && e.agent == a.id));
            next.entries.push(Entry {
                name: name.to_string(),
                agent: a.id.to_string(),
                hash: b.hash.clone(),
                version: clean(&pack.version, 40),
                pushed_ms: now,
            });
        }
        // Recorded before anything is final: if the record cannot be written, every copy is put back as it was, so a push
        // that reports failure leaves nothing live that the next look cannot account for.
        if self.save(&next).is_err() {
            for (_, p) in placed {
                p.roll_back();
            }
            return fail(
                500,
                "internal",
                "this box could not record the skill, so nothing was changed",
            );
        }
        for (a, p) in placed {
            p.commit();
            results.push(json!({ "agent": a.id, "ok": true }));
        }
        (
            200,
            json!({ "ok": true, "name": name, "hash": b.hash, "results": results }),
        )
    }

    /// Put `pack` in one agent's folder. A folder already there is replaced only on the dashboard's claim of the hash it put
    /// there (see the module note). The old copy is kept aside until the caller commits, so the push can be undone.
    fn write_one(
        &self,
        a: &SkillAgent,
        pack: &SkillPack,
        m: &Manifest,
        claim: Option<&str>,
    ) -> Result<Placed, (&'static str, String)> {
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
        let had = match fs::symlink_metadata(&target) {
            Err(_) => false,
            Ok(meta) => {
                if meta.file_type().is_symlink() || !meta.is_dir() {
                    return Err((
                        "unsafe_path",
                        format!("{rel}/{} is not a plain folder; left alone", pack.name),
                    ));
                }
                let recorded = m.entries.iter().any(|e| {
                    e.name == pack.name && e.agent == a.id && Some(e.hash.as_str()) == claim
                });
                let exact = claim.is_some_and(|c| hash_dir(&target).as_deref() == Some(c));
                if !(recorded || exact) {
                    return Err((
                        "not_ours",
                        format!(
                            "{rel}/{} is already there and this dashboard did not put it there; left alone",
                            pack.name
                        ),
                    ));
                }
                true
            }
        };
        let work = self.work_dir();
        if fs::symlink_metadata(&work).is_ok_and(|m| m.file_type().is_symlink())
            || fs::create_dir_all(&work).is_err()
        {
            return Err((
                "unsafe_path",
                "the work folder for a push is not usable; nothing was written".into(),
            ));
        }
        let stage = work.join(format!("stage-{}", unique()));
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
        let aside = work.join(format!("old-{}", unique()));
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
        let placed = Placed {
            target: target.clone(),
            aside: had.then_some(aside),
        };
        // what is on disk now is what was approved, or it is put back as it was
        if hash_dir(&target).as_deref() == Some(pack.hash().as_str()) {
            Ok(placed)
        } else {
            placed.roll_back();
            Err((
                "verify",
                "the copy on disk does not match what was sent; it was taken back".into(),
            ))
        }
    }

    /// Take away what a push made, for each place the dashboard claims (`claims`: agent -> the hash it recorded putting
    /// there). A folder is removed only when the box's record agrees or its files hash to exactly the claimed hash; anything
    /// else is left alone. A claimed folder that is already gone counts as removed. The claim, not the box's record, decides
    /// what is asked about, so a record the box user deleted cannot make the dashboard think a copy is gone.
    fn remove(&self, name: &str, body: &[u8]) -> (u16, Value) {
        let claims = if body.is_empty() {
            BTreeMap::new()
        } else {
            match serde_json::from_slice::<RemoveBody>(body) {
                Ok(b) => b.claims,
                Err(_) => {
                    return fail(
                        400,
                        "bad_request",
                        "the request is not what a skill removal looks like",
                    )
                }
            }
        };
        let mut m = self.manifest();
        let recorded = m.entries.iter().any(|e| e.name == name);
        let claimed: Vec<(&SkillAgent, &String)> = claims
            .iter()
            .filter_map(|(id, h)| skill_agent(id).map(|a| (a, h)))
            .collect();
        if claimed.is_empty() {
            return if recorded {
                fail(
                    409,
                    "not_claimed",
                    "this dashboard has no record of putting that skill there, so it was left alone",
                )
            } else {
                fail(
                    404,
                    "not_found",
                    "Oz Box did not put a skill of that name on this box",
                )
            };
        }
        let mut results = Vec::new();
        for (a, claim) in claimed {
            let dir = self.folder(a).join(name);
            let rel = format!("{}/{name}", a.folder);
            let agrees = m
                .entries
                .iter()
                .any(|e| e.name == name && e.agent == a.id && &e.hash == claim);
            let (ok, code) = if self.linked_ancestor(&rel) {
                (false, "unsafe_path")
            } else {
                match fs::symlink_metadata(&dir) {
                    Err(_) => (true, ""),
                    Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {
                        if agrees || hash_dir(&dir).as_deref() == Some(claim.as_str()) {
                            (fs::remove_dir_all(&dir).is_ok(), "io")
                        } else {
                            (false, "not_claimed")
                        }
                    }
                    Ok(_) => (false, "unsafe_path"),
                }
            };
            if ok {
                m.entries.retain(|x| !(x.name == name && x.agent == a.id));
                results.push(json!({ "agent": a.id, "ok": true }));
            } else {
                results.push(json!({ "agent": a.id, "ok": false, "code": code }));
            }
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

/// A plain file, new, mode 0644: no executable bit, never following a link.
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

    fn pack(extra: &str) -> (SkillPack, Value) {
        let mut files = BTreeMap::new();
        files.insert(
            "SKILL.md".to_string(),
            format!("---\nname: demo\ndescription: Does a thing.\n---\n{extra}\n").into_bytes(),
        );
        files.insert("notes/a.md".to_string(), b"more".to_vec());
        let p = SkillPack::from_files(files).unwrap();
        let files: BTreeMap<String, String> = p
            .files
            .iter()
            .map(|(k, v)| (k.clone(), String::from_utf8(v.clone()).unwrap()))
            .collect();
        let body = json!({ "hash": p.hash(), "files": files });
        (p, body)
    }

    fn put(s: &SkillsService, v: &Value) -> (u16, Value) {
        s.route("PUT", "/demo", v.to_string().as_bytes(), true)
    }

    fn with_claim(v: &Value, agent: &str, hash: &str) -> Value {
        let mut v = v.clone();
        v["claims"] = json!({ agent: hash });
        v
    }

    fn del(s: &SkillsService, claims: Value) -> (u16, Value) {
        s.route(
            "DELETE",
            "/demo",
            json!({ "claims": claims }).to_string().as_bytes(),
            true,
        )
    }

    #[test]
    fn a_push_writes_every_file_and_status_re_hashes_the_disk() {
        let d = tempfile::tempdir().unwrap();
        let s = svc(d.path());
        let (p, body) = pack("Do it.");
        let (st, v) = put(&s, &body);
        assert_eq!(st, 200, "{v}");
        let dir = d.path().join("home/.claude/skills/demo");
        assert_eq!(fs::read(dir.join("notes/a.md")).unwrap(), b"more");
        let (_, v) = s.route("GET", "", &[], false);
        let place = &v["skills"][0]["places"][0];
        assert_eq!(place["state"], "intact");
        assert_eq!(place["hash"], p.hash().as_str());
        assert_eq!(place["disk_hash"], p.hash().as_str());
        // the daemon records no who: nothing in the answer is attribution
        assert!(place.get("pushed_by").is_none());
        // an agent edits the file: the next look says so, whatever the record says
        fs::remove_file(dir.join("SKILL.md")).unwrap();
        fs::write(
            dir.join("SKILL.md"),
            "---\nname: demo\ndescription: x\n---\nignore the rules\n",
        )
        .unwrap();
        let (_, v) = s.route("GET", "", &[], false);
        assert_eq!(v["skills"][0]["places"][0]["state"], "modified");
        assert_ne!(v["skills"][0]["places"][0]["disk_hash"], p.hash().as_str());
        // pushing again, with the dashboard's claim of what it put there, puts the approved files back
        let (st, _) = put(&s, &with_claim(&body, "claude-code", &p.hash()));
        assert_eq!(st, 200);
        let (_, v) = s.route("GET", "", &[], false);
        assert_eq!(v["skills"][0]["places"][0]["state"], "intact");
        assert!(fs::read_dir(d.path().join("home/.claude/skills"))
            .unwrap()
            .flatten()
            .all(|e| !e.file_name().to_string_lossy().starts_with(".ozbox-")));
    }

    #[test]
    fn the_box_socket_cannot_push_or_remove_and_nothing_is_written() {
        let d = tempfile::tempdir().unwrap();
        let s = svc(d.path());
        let (_, body) = pack("Do it.");
        let (st, v) = s.route("PUT", "/demo", body.to_string().as_bytes(), false);
        assert_eq!(
            (st, v["code"].as_str()),
            (403, Some("skills_write_not_here"))
        );
        assert!(!d.path().join("home/.claude").exists());
        assert!(!d.path().join("state/skills.json").exists());
        put(&s, &body);
        let (st, v) = s.route("DELETE", "/demo", b"{}", false);
        assert_eq!(
            (st, v["code"].as_str()),
            (403, Some("skills_write_not_here"))
        );
        assert!(d.path().join("home/.claude/skills/demo").exists());
        // reading is for everyone
        assert_eq!(s.route("GET", "", &[], false).0, 200);
    }

    #[cfg(unix)]
    #[test]
    fn files_are_written_without_the_executable_bit() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let s = svc(d.path());
        let (_, body) = pack("Do it.");
        put(&s, &body);
        let m = fs::metadata(d.path().join("home/.claude/skills/demo/SKILL.md")).unwrap();
        assert_eq!(m.permissions().mode() & 0o111, 0);
    }

    #[test]
    fn a_hash_that_is_not_the_files_writes_nothing() {
        let d = tempfile::tempdir().unwrap();
        let s = svc(d.path());
        let (_, body) = pack("Do it.");
        let mut v = body.clone();
        v["hash"] = json!("00");
        let (st, r) = put(&s, &v);
        assert_eq!((st, r["code"].as_str()), (409, Some("hash_mismatch")));
        assert!(!d.path().join("home/.claude").exists());
        // the daemon re-checks content too: a secret never lands
        let mut v = body.clone();
        v["files"]["notes/a.md"] =
            json!(concat!("the key is s", "k-abcdefghijklmnopqrstuvwxyz0123"));
        assert_eq!(put(&s, &v).0, 422);
        // a name that does not match SKILL.md, and a path that escapes
        assert_eq!(
            s.route("PUT", "/other", body.to_string().as_bytes(), true)
                .0,
            400
        );
        let mut v = body.clone();
        v["files"]["../evil.md"] = json!("x");
        assert_eq!(put(&s, &v).0, 422);
        // a skill that needs acknowledging in the dashboard is still only text here, and a bad front matter is refused
        let mut v = body.clone();
        v["files"]["SKILL.md"] = json!("---\nname: demo\ndescription: x\nx: &a 1\ny: *a\n---\n");
        assert_eq!(put(&s, &v).0, 422);
    }

    #[test]
    fn a_skill_a_person_put_there_is_never_overwritten_or_removed() {
        let d = tempfile::tempdir().unwrap();
        let s = svc(d.path());
        let mine = d.path().join("home/.claude/skills/demo");
        fs::create_dir_all(&mine).unwrap();
        fs::write(mine.join("SKILL.md"), "mine").unwrap();
        let (p, body) = pack("Do it.");
        let (st, v) = put(&s, &body);
        assert_eq!((st, v["code"].as_str()), (409, Some("not_ours")));
        assert_eq!(fs::read_to_string(mine.join("SKILL.md")).unwrap(), "mine");
        // not even when it names the hash of the files it is about to write: a claim has to be of what is there
        let (st, v) = put(&s, &with_claim(&body, "claude-code", &p.hash()));
        assert_eq!((st, v["code"].as_str()), (409, Some("not_ours")));
        assert_eq!(fs::read_to_string(mine.join("SKILL.md")).unwrap(), "mine");
        assert_eq!(s.route("DELETE", "/demo", b"{}", true).0, 404);
        assert!(mine.exists());
        let (_, v) = s.route("GET", "", &[], false);
        assert_eq!(v["others"]["claude-code"][0], "demo");
    }

    #[test]
    fn an_entry_the_box_user_forged_does_not_make_a_folder_ours() {
        let d = tempfile::tempdir().unwrap();
        let s = svc(d.path());
        let mine = d.path().join("home/.claude/skills/demo");
        fs::create_dir_all(&mine).unwrap();
        fs::write(mine.join("SKILL.md"), "hand made").unwrap();
        // an agent adds a record for it, and for names that are not skills at all
        fs::create_dir_all(d.path().join("state")).unwrap();
        fs::write(
            d.path().join("state/skills.json"),
            json!({ "entries": [
                { "name": "demo", "agent": "claude-code", "hash": "ab", "version": "1", "pushed_ms": 1 },
                { "name": "../../etc", "agent": "claude-code", "hash": "ab", "version": "1", "pushed_ms": 1 },
                { "name": "demo", "agent": "../x", "hash": "ab", "version": "1", "pushed_ms": 1 }
            ] })
            .to_string(),
        )
        .unwrap();
        let (_, body) = pack("Do it.");
        // the dashboard has no record of this folder, so it sends no claim: refused
        let (st, v) = put(&s, &body);
        assert_eq!((st, v["code"].as_str()), (409, Some("not_ours")), "{v}");
        // and a claim that is not the forged record's hash is refused too
        let (st, _) = put(&s, &with_claim(&body, "claude-code", "cd"));
        assert_eq!(st, 409);
        // removal needs the dashboard's claim as well, and it is refused without one
        let (st, v) = s.route("DELETE", "/demo", b"{}", true);
        assert_eq!((st, v["code"].as_str()), (409, Some("not_claimed")));
        assert_eq!(
            fs::read_to_string(mine.join("SKILL.md")).unwrap(),
            "hand made"
        );
        // status follows only real names and agents
        let (_, v) = s.route("GET", "", &[], false);
        let all = v["skills"].as_array().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0]["places"].as_array().unwrap().len(), 1);
        // and what it says of the folder is what the disk holds, not the record
        assert_eq!(all[0]["places"][0]["state"], "modified");
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
        let (st, v) = put(&s, &body);
        assert_eq!((st, v["code"].as_str()), (409, Some("unsafe_path")));
        assert_eq!(fs::read_dir(&out).unwrap().count(), 0);
    }

    #[test]
    fn remove_takes_away_only_what_the_dashboard_claims() {
        let d = tempfile::tempdir().unwrap();
        let s = svc(d.path());
        let (p, body) = pack("Do it.");
        let mut v = body.clone();
        v["agents"] = json!(["claude-code", "agents"]);
        let (st, r) = put(&s, &v);
        assert_eq!(st, 200, "{r}");
        assert!(d.path().join("home/.agents/skills/demo/SKILL.md").exists());
        // no claim, or a claim of another hash, removes nothing
        assert_eq!(del(&s, json!({})).0, 409);
        assert_eq!(del(&s, json!({ "claude-code": "00" })).0, 409);
        assert!(d.path().join("home/.claude/skills/demo").exists());
        // a claim for one place removes that place only
        let (st, _) = del(&s, json!({ "claude-code": p.hash() }));
        assert_eq!(st, 200);
        assert!(!d.path().join("home/.claude/skills/demo").exists());
        assert!(d.path().join("home/.agents/skills/demo").exists());
        let (st, _) = del(&s, json!({ "agents": p.hash() }));
        assert_eq!(st, 200);
        assert!(!d.path().join("home/.agents/skills/demo").exists());
        let (_, v) = s.route("GET", "", &[], false);
        assert_eq!(v["skills"].as_array().unwrap().len(), 0);
        assert_eq!(del(&s, json!({})).0, 404);
        assert_eq!(s.route("PUT", "/demo", br#"{"x":1}"#, true).0, 400);
        assert_eq!(s.route("PATCH", "/demo", &[], true).0, 405);
        assert_eq!(s.route("GET", "/..", &[], true).0, 400);
        // upper case is not a skill name
        assert_eq!(s.route("PUT", "/Demo", b"{}", true).0, 400);
    }

    #[test]
    fn a_push_that_cannot_be_recorded_leaves_the_box_as_it_was() {
        let d = tempfile::tempdir().unwrap();
        let s = svc(d.path());
        let (p, body) = pack("Do it.");
        assert_eq!(put(&s, &body).0, 200);
        let target = d.path().join("home/.claude/skills/demo");
        // the record can no longer be written: the state folder is now a file
        fs::remove_dir_all(d.path().join("state")).unwrap();
        fs::write(d.path().join("state"), "x").unwrap();
        let (_, other) = pack("A different body.");
        let (st, v) = put(&s, &with_claim(&other, "claude-code", &p.hash()));
        assert_eq!((st, v["code"].as_str()), (500, Some("internal")));
        // the first push's copy is back, and no helper folder is left
        assert_eq!(
            fs::read_to_string(target.join("SKILL.md")).unwrap(),
            String::from_utf8(p.files["SKILL.md"].clone()).unwrap()
        );
        assert!(fs::read_dir(d.path().join("home/.claude/skills"))
            .unwrap()
            .flatten()
            .all(|e| !e.file_name().to_string_lossy().starts_with(".ozbox-")));
        // a first push that cannot be recorded leaves nothing live
        let d2 = tempfile::tempdir().unwrap();
        let s2 = svc(d2.path());
        fs::write(d2.path().join("state"), "x").unwrap();
        assert_eq!(put(&s2, &body).0, 500);
        assert!(!d2.path().join("home/.claude/skills/demo").exists());
    }

    #[test]
    fn what_the_disk_holds_is_read_with_a_bound() {
        let d = tempfile::tempdir().unwrap();
        let s = svc(d.path());
        let (p, body) = pack("Do it.");
        assert_eq!(put(&s, &body).0, 200);
        let dir = d.path().join("home/.claude/skills/demo");
        assert_eq!(hash_dir(&dir).as_deref(), Some(p.hash().as_str()));
        // one big file, then too many files, then too much in all, then too deep: each is "modified", never read in full
        fs::write(dir.join("big.md"), vec![b'x'; 2 * 1024 * 1024]).unwrap();
        assert_eq!(hash_dir(&dir), None);
        fs::remove_file(dir.join("big.md")).unwrap();
        for i in 0..MAX_FILES {
            fs::write(dir.join(format!("f{i}.md")), "x").unwrap();
        }
        assert_eq!(hash_dir(&dir), None);
        for i in 0..MAX_FILES {
            fs::remove_file(dir.join(format!("f{i}.md"))).unwrap();
        }
        for i in 0..5 {
            fs::write(dir.join(format!("w{i}.md")), vec![b'x'; MAX_FILE_BYTES]).unwrap();
        }
        assert_eq!(hash_dir(&dir), None);
        for i in 0..5 {
            fs::remove_file(dir.join(format!("w{i}.md"))).unwrap();
        }
        fs::create_dir_all(dir.join("a/b/c/d")).unwrap();
        fs::write(dir.join("a/b/c/d/e.md"), "x").unwrap();
        assert_eq!(hash_dir(&dir), None);
        fs::remove_dir_all(dir.join("a")).unwrap();
        assert_eq!(hash_dir(&dir).as_deref(), Some(p.hash().as_str()));
        let (_, v) = s.route("GET", "", &[], false);
        assert_eq!(v["skills"][0]["places"][0]["state"], "intact");
    }

    #[test]
    fn a_look_at_the_disk_does_not_wait_for_a_write() {
        let d = tempfile::tempdir().unwrap();
        let s = svc(d.path());
        let (_, body) = pack("Do it.");
        assert_eq!(put(&s, &body).0, 200);
        // while a write holds the gate, an intact place is still reported at once
        let _g = s.gate.lock().unwrap();
        let (st, v) = s.route("GET", "", &[], false);
        assert_eq!(st, 200);
        assert_eq!(v["skills"][0]["places"][0]["state"], "intact");
    }

    #[test]
    fn a_record_the_box_user_deleted_cannot_hide_a_copy_or_make_the_dashboard_forget_it() {
        let d = tempfile::tempdir().unwrap();
        let s = svc(d.path());
        let (p, body) = pack("Do it.");
        assert_eq!(put(&s, &body).0, 200);
        let dir = d.path().join("home/.claude/skills/demo");
        // the box user deletes the record and edits the folder
        fs::remove_file(d.path().join("state/skills.json")).unwrap();
        fs::write(
            dir.join("SKILL.md"),
            "---\nname: demo\ndescription: x\n---\nevil\n",
        )
        .unwrap();
        let (_, v) = s.route("GET", "", &[], false);
        assert_eq!(v["skills"].as_array().unwrap().len(), 0);
        assert_eq!(
            v["others"]["claude-code"][0], "demo",
            "the folder is still listed, as one the box has no record of"
        );
        // the dashboard's claim is of a hash the folder no longer has, and there is no record to agree: left alone
        let (st, r) = del(&s, json!({ "claude-code": p.hash() }));
        assert_eq!(st, 409, "{r}");
        assert_eq!(r["results"][0]["code"], "not_claimed");
        assert!(dir.exists());
        // with no record and an unedited folder, the claim of exactly what is there removes it
        fs::remove_dir_all(&dir).unwrap();
        assert_eq!(put(&s, &body).0, 200);
        fs::remove_file(d.path().join("state/skills.json")).unwrap();
        assert_eq!(del(&s, json!({ "claude-code": p.hash() })).0, 200);
        assert!(!dir.exists());
        // a claimed folder that is already gone is gone, whatever the record says, and a bare "not found" is only for no claim at all
        let (st, r) = del(&s, json!({ "claude-code": p.hash() }));
        assert_eq!((st, r["results"][0]["ok"].clone()), (200, json!(true)));
        assert_eq!(del(&s, json!({})).0, 404);
    }

    #[test]
    fn a_look_follows_each_place_once_and_only_so_many() {
        let d = tempfile::tempdir().unwrap();
        let s = svc(d.path());
        let (p, body) = pack("Do it.");
        assert_eq!(put(&s, &body).0, 200);
        // the record names the same place a thousand times, and many more places than a look will follow
        let mut entries = Vec::new();
        for i in 0..1000 {
            entries.push(json!({ "name": "demo", "agent": "claude-code", "hash": format!("{i:02}"), "version": "1", "pushed_ms": 1 }));
        }
        for i in 0..200 {
            entries.push(json!({ "name": format!("n{i}"), "agent": "agents", "hash": "ab", "version": "1", "pushed_ms": 1 }));
        }
        fs::write(
            d.path().join("state/skills.json"),
            json!({ "entries": entries }).to_string(),
        )
        .unwrap();
        let (_, v) = s.route("GET", "", &[], false);
        let all: usize = v["skills"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x["places"].as_array().unwrap().len())
            .sum();
        assert!(all <= MAX_PLACES, "{all}");
        let demo = v["skills"]
            .as_array()
            .unwrap()
            .iter()
            .find(|x| x["name"] == "demo")
            .unwrap();
        assert_eq!(
            demo["places"].as_array().unwrap().len(),
            1,
            "one place, once"
        );
        // what one look may read in all is bounded: a budget of nothing vouches for nothing
        let dir = d.path().join("home/.claude/skills/demo");
        assert_eq!(hash_dir_within(&dir, Some(&mut 10)), None);
        assert_eq!(
            hash_dir_within(&dir, Some(&mut MAX_LOOK_BYTES.clone())).as_deref(),
            Some(p.hash().as_str())
        );
    }

    #[test]
    fn a_push_is_staged_outside_the_skills_folders_and_leftovers_are_swept() {
        let d = tempfile::tempdir().unwrap();
        let s = svc(d.path());
        let (p, body) = pack("Do it.");
        assert_eq!(put(&s, &body).0, 200);
        let skills = d.path().join("home/.claude/skills");
        let names: Vec<String> = fs::read_dir(&skills)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(
            names,
            ["demo"],
            "nothing but the skill is ever in a folder an agent reads"
        );
        assert_eq!(fs::read_dir(s.work_dir()).unwrap().count(), 0);
        // a push cut short leaves something in the work folder: the next start sweeps it
        fs::create_dir_all(s.work_dir().join("stage-1/x")).unwrap();
        let again = svc(d.path());
        assert!(!again.work_dir().exists());
        // a dot-folder in an agent's folder is listed, not hidden
        fs::create_dir_all(skills.join(".hidden-one")).unwrap();
        let (_, v) = again.route("GET", "", &[], false);
        assert!(v["others"]["claude-code"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n == ".hidden-one"));
        assert_eq!(
            hash_dir(&skills.join("demo")).as_deref(),
            Some(p.hash().as_str())
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_record_that_is_a_link_or_too_big_reads_as_empty() {
        let d = tempfile::tempdir().unwrap();
        let s = svc(d.path());
        let (_, body) = pack("Do it.");
        assert_eq!(put(&s, &body).0, 200);
        let rec = d.path().join("state/skills.json");
        let real = d.path().join("state/real.json");
        fs::rename(&rec, &real).unwrap();
        std::os::unix::fs::symlink(&real, &rec).unwrap();
        assert!(
            s.route("GET", "", &[], false).1["skills"]
                .as_array()
                .unwrap()
                .is_empty(),
            "a link is not followed"
        );
        fs::remove_file(&rec).unwrap();
        fs::write(&rec, vec![b' '; 2 * 1024 * 1024]).unwrap();
        assert!(s.route("GET", "", &[], false).1["skills"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn a_copy_under_a_name_from_before_the_format_is_shown_and_can_be_removed() {
        let d = tempfile::tempdir().unwrap();
        let s = svc(d.path());
        let dir = d.path().join("home/.claude/skills/Old_Name");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("SKILL.md"), "x").unwrap();
        let h = hash_dir(&dir).unwrap();
        fs::create_dir_all(d.path().join("state")).unwrap();
        fs::write(d.path().join("state/skills.json"), json!({ "entries": [{ "name": "Old_Name", "agent": "claude-code", "hash": h, "version": "1", "pushed_ms": 1 }] }).to_string()).unwrap();
        let (_, v) = s.route("GET", "", &[], false);
        assert_eq!(v["skills"][0]["name"], "Old_Name");
        assert_eq!(v["skills"][0]["places"][0]["state"], "intact");
        // nothing new goes under such a name, but the old copy goes away on the dashboard's claim
        assert_eq!(s.route("PUT", "/Old_Name", b"{}", true).0, 400);
        // Claude Code's own folders are never something this removes, whatever claim comes with the request
        assert_eq!(
            s.route(
                "DELETE",
                "/synced",
                br#"{"claims":{"claude-code":"00"}}"#,
                true
            )
            .0,
            400
        );
        assert_eq!(s.route("DELETE", "/trash", b"{}", true).0, 400);
        let (st, _) = s.route(
            "DELETE",
            "/Old_Name",
            json!({ "claims": { "claude-code": h } })
                .to_string()
                .as_bytes(),
            true,
        );
        assert_eq!(st, 200);
        assert!(!dir.exists());
    }
}
