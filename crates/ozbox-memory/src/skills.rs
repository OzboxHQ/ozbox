//! Reviewed skills: folders with a `SKILL.md` (the open Agent Skills format), a catalog with versions and a content
//! hash, installs per fleet, box or project, and a review gate.
//!
//! **The gate.** A skill is *usable* only while a person has approved the exact hash of the files that are installed.
//! Installing copies the files into a snapshot named by their hash; approving records `(name, hash, person)`. Changing
//! any file, anywhere, produces a different hash, so an updated skill needs a new approval, and a snapshot edited on disk
//! after approval no longer matches its hash and stops being usable. There is no agent-facing way to approve, install or
//! change a skill: agents only read usable ones through the tool host.
//!
//! A skill is guidance, not security: what an agent may do is enforced by the server whatever a skill says.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use ozbox_core::skill_pack::SKILL_AGENTS;
use serde::{Deserialize, Serialize};

use crate::lock::FileLock;
use crate::{name_ok, write_atomic};

pub use ozbox_core::skill_front::Asks;
pub use ozbox_core::skill_pack::{
    file_kind, hash_files, spdx_ok, SkillError, SkillPack, MAX_FILES, MAX_FILE_BYTES,
    MAX_PACK_BODY, MAX_TOTAL_BYTES,
};

fn io<E: fmt::Display>(e: E) -> SkillError {
    SkillError::Io(format!("the skills store could not be used: {e}"))
}

/// Where an install applies.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum InstallScope {
    Fleet,
    Box(String),
    Project(String),
}

impl InstallScope {
    pub fn parse(s: &str) -> Result<InstallScope, SkillError> {
        let bad =
            || SkillError::Invalid("an install scope is fleet, box:name or project:name".into());
        match s.split_once(':') {
            None if s == "fleet" => Ok(InstallScope::Fleet),
            Some(("box", n)) if name_ok(n) => Ok(InstallScope::Box(n.into())),
            Some(("project", n)) if name_ok(n) => Ok(InstallScope::Project(n.into())),
            _ => Err(bad()),
        }
    }
}

impl fmt::Display for InstallScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InstallScope::Fleet => f.write_str("fleet"),
            InstallScope::Box(n) => write!(f, "box:{n}"),
            InstallScope::Project(n) => write!(f, "project:{n}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Install {
    pub name: String,
    pub scope: String,
    pub hash: String,
    pub source: String,
    pub installed_by: String,
    pub installed_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approval {
    pub name: String,
    pub hash: String,
    pub approved_by: String,
    pub approved_ms: u64,
    /// The commands and permissions the person knowingly accepted (`hooks`, `allowed-tools`, ...), bound to this hash. An
    /// approval counts only while it covers everything the files ask for (`SkillPack::asks`).
    #[serde(default)]
    pub acks: Vec<String>,
}

/// A skill put on a box's own disk, as last recorded here. The box's own files are the truth: the dashboard asks the box
/// what it holds. This record keeps the approval and the files that were pushed alive, and says who did it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Push {
    pub name: String,
    pub box_name: String,
    pub hash: String,
    #[serde(default)]
    pub agents: Vec<String>,
    /// For each agent folder this dashboard put the skill in, the hash it put there. What the dashboard may claim, when it
    /// replaces or removes a folder, and the only thing it calls "pushed from this dashboard". A push that reached only
    /// some agents leaves the others at the hash they had.
    #[serde(default)]
    pub places: BTreeMap<String, String>,
    pub pushed_by: String,
    pub pushed_ms: u64,
}

impl Push {
    /// The hash recorded for one agent's folder. A record from before `places` existed holds one hash for its `agents`.
    pub fn hash_for(&self, agent: &str) -> Option<&str> {
        match self.places.get(agent) {
            Some(h) => Some(h.as_str()),
            None if self.places.is_empty() && self.agents.iter().any(|a| a == agent) => {
                Some(self.hash.as_str())
            }
            None => None,
        }
    }

    /// Every hash this record holds a copy of.
    fn hashes(&self) -> BTreeSet<&str> {
        let mut s: BTreeSet<&str> = self.places.values().map(String::as_str).collect();
        s.insert(self.hash.as_str());
        s
    }
}

/// One version of a library skill: the files hash, the version its `SKILL.md` names, who added it, when and how.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revision {
    pub name: String,
    pub hash: String,
    pub version: String,
    pub by: String,
    /// `page_upload`, `page_editor`, `cli` or `restore`.
    pub via: String,
    pub ms: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Registry {
    #[serde(default)]
    installs: Vec<Install>,
    #[serde(default)]
    approvals: Vec<Approval>,
    #[serde(default)]
    pushes: Vec<Push>,
    #[serde(default)]
    revisions: Vec<Revision>,
}

/// Who added a skill to the library and how.
#[derive(Debug, Clone)]
pub struct Origin {
    pub by: String,
    pub via: String,
}

/// What adding a skill may replace. A page names the hash it was looking at, so two tabs cannot overwrite each other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Replace {
    /// There must be no skill of this name in the library.
    Fresh,
    /// The library's skill must still have this hash.
    Over(String),
    /// Replace whatever is there (the command line, which a person runs on purpose).
    Force,
}

/// Versions kept per skill.
pub const MAX_REVISIONS: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Installed and a person approved exactly these files.
    Approved,
    /// Installed, waiting for a person to review these files.
    NeedsReview,
    /// The installed files no longer match what was installed (changed on disk): unusable until reinstalled.
    Modified,
}

#[derive(Debug, Clone, Serialize)]
pub struct InstallView {
    pub scope: String,
    pub hash: String,
    pub source: String,
    pub status: Status,
    pub installed_by: String,
    pub installed_ms: u64,
    /// The catalog now holds different files than this install.
    pub update_available: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileInfo {
    pub path: String,
    pub bytes: usize,
    /// `instructions`, `script` (an agent may run it) or `text`.
    pub kind: &'static str,
}

/// Where a skill came from, shown before anyone approves it.
#[derive(Debug, Clone, Serialize)]
pub struct Provenance {
    /// `bundled` (ships with Oz Box), `library` (added by a person) or `removed`.
    pub origin: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    /// `page_upload`, `page_editor`, `cli` or `restore`; none for a folder put in the library by hand.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ms: Option<u64>,
}

/// A skill pushed to a box, as last recorded.
#[derive(Debug, Clone, Serialize)]
pub struct PushView {
    pub box_name: String,
    pub hash: String,
    pub agents: Vec<String>,
    pub pushed_by: String,
    pub pushed_ms: u64,
    /// The library holds these same files now.
    pub matches_library: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RevisionView {
    pub hash: String,
    pub version: String,
    pub by: String,
    pub via: String,
    pub ms: u64,
    pub current: bool,
    pub approved: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CatalogItem {
    pub name: String,
    pub description: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    pub hash: String,
    /// `bundled` (ships with Oz Box) or `library` (added by a person).
    pub source: String,
    pub files: Vec<FileInfo>,
    /// A person approved these exact files, including every command and permission they ask for.
    pub approved: bool,
    /// The commands and permissions the files ask for, each of which must be acknowledged to approve (empty for a plain skill).
    pub asks: Vec<&'static str>,
    pub installs: Vec<InstallView>,
    pub provenance: Provenance,
    /// A skill of your own has the name of one that ships with Oz Box and is what the catalog offers.
    pub shadows_bundled: bool,
    pub pushes: Vec<PushView>,
    /// Earlier versions kept in the library (newest first), for a skill of your own.
    pub revisions: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct Review {
    pub name: String,
    pub description: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    pub hash: String,
    pub approved: bool,
    /// What the files ask an agent program to do: the commands and permissions that need an acknowledgement before
    /// approval, and the other settings declared.
    pub asks: Asks,
    pub files: Vec<ReviewFile>,
    pub provenance: Provenance,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReviewFile {
    pub path: String,
    pub text: String,
    pub kind: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct Usable {
    pub name: String,
    pub description: String,
    pub version: String,
    pub hash: String,
}

pub struct SkillStore {
    root: PathBuf,
    bundled: Vec<SkillPack>,
}

impl SkillStore {
    pub fn open(
        root: impl Into<PathBuf>,
        bundled: Vec<SkillPack>,
    ) -> Result<SkillStore, SkillError> {
        let s = SkillStore {
            root: root.into(),
            bundled,
        };
        fs::create_dir_all(s.root.join("library")).map_err(io)?;
        fs::create_dir_all(s.root.join("store")).map_err(io)?;
        Ok(s)
    }

    fn lock(&self) -> Result<FileLock, SkillError> {
        FileLock::take(&self.root.join("skills.lock")).map_err(io)
    }

    fn registry(&self) -> Registry {
        fs::read(self.root.join("skills.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn save(&self, r: &Registry) -> Result<(), SkillError> {
        write_atomic(
            &self.root.join("skills.json"),
            &serde_json::to_vec_pretty(r).map_err(io)?,
        )
        .map_err(io)
    }

    fn snapshot_dir(&self, name: &str, hash: &str) -> PathBuf {
        self.root.join("store").join(name).join(hash)
    }

    /// The skills a person can choose from: the library (theirs) over the ones that ship with Oz Box.
    fn sources(&self) -> BTreeMap<String, (SkillPack, &'static str)> {
        let mut m: BTreeMap<String, (SkillPack, &'static str)> = BTreeMap::new();
        for b in &self.bundled {
            m.insert(b.name.clone(), (b.clone(), "bundled"));
        }
        if let Ok(rd) = fs::read_dir(self.root.join("library")) {
            for e in rd.flatten() {
                if let Ok(p) = SkillPack::from_dir(&e.path()) {
                    m.insert(p.name.clone(), (p, "library"));
                }
            }
        }
        m
    }

    fn read_snapshot(&self, name: &str, hash: &str) -> Option<SkillPack> {
        let dir = self.snapshot_dir(name, hash);
        let mut files = BTreeMap::new();
        fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) -> Option<()> {
            for e in fs::read_dir(dir).ok()?.flatten() {
                let p = e.path();
                let meta = fs::symlink_metadata(&p).ok()?;
                if meta.is_dir() {
                    walk(base, &p, out)?;
                } else if meta.is_file() {
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
        walk(&dir, &dir, &mut files)?;
        // The files must still be exactly what was installed.
        if hash_files(&files) != hash {
            return None;
        }
        SkillPack::from_files(files).ok()
    }

    /// Is there an approval of exactly these files that also covers every command and permission they ask for?
    fn approved(reg: &Registry, p: &SkillPack, hash: &str) -> bool {
        // a pack whose asks cannot be read is never approved
        let Ok(asks) = p.asks() else {
            return false;
        };
        let need = asks.keys();
        reg.approvals.iter().any(|a| {
            a.name == p.name && a.hash == hash && need.iter().all(|k| a.acks.iter().any(|x| x == k))
        })
    }

    /// Drop approvals and snapshots nothing refers to any more, so a changed skill really starts again unapproved.
    fn gc(&self, reg: &mut Registry) {
        let src = self.sources();
        let live: BTreeSet<(String, String)> = reg
            .installs
            .iter()
            .map(|i| (i.name.clone(), i.hash.clone()))
            .chain(reg.pushes.iter().flat_map(|p| {
                p.hashes()
                    .into_iter()
                    .map(|h| (p.name.clone(), h.to_string()))
            }))
            .chain(src.iter().map(|(n, (p, _))| (n.clone(), p.hash())))
            .collect();
        reg.approvals
            .retain(|a| live.contains(&(a.name.clone(), a.hash.clone())));
        let held: BTreeSet<(String, String)> = reg
            .installs
            .iter()
            .map(|i| (i.name.clone(), i.hash.clone()))
            .chain(reg.pushes.iter().flat_map(|p| {
                p.hashes()
                    .into_iter()
                    .map(|h| (p.name.clone(), h.to_string()))
            }))
            .collect();
        if let Ok(names) = fs::read_dir(self.root.join("store")) {
            for n in names.flatten() {
                let name = n.file_name().to_string_lossy().to_string();
                if let Ok(hashes) = fs::read_dir(n.path()) {
                    for h in hashes.flatten() {
                        let hash = h.file_name().to_string_lossy().to_string();
                        if !held.contains(&(name.clone(), hash)) {
                            let _ = fs::remove_dir_all(h.path());
                        }
                    }
                }
                let _ = fs::remove_dir(n.path()); // only if now empty
            }
        }
    }

    fn view(&self, reg: &Registry, i: &Install, current: Option<&str>) -> InstallView {
        let status = match self.read_snapshot(&i.name, &i.hash) {
            None => Status::Modified,
            Some(p) if Self::approved(reg, &p, &i.hash) => Status::Approved,
            Some(_) => Status::NeedsReview,
        };
        InstallView {
            scope: i.scope.clone(),
            hash: i.hash.clone(),
            source: i.source.clone(),
            status,
            installed_by: i.installed_by.clone(),
            installed_ms: i.installed_ms,
            update_available: current.is_some_and(|c| c != i.hash),
        }
    }

    fn file_infos(p: &SkillPack) -> Vec<FileInfo> {
        p.files
            .iter()
            .map(|(k, v)| FileInfo {
                path: k.clone(),
                bytes: v.len(),
                kind: file_kind(k),
            })
            .collect()
    }

    fn provenance(reg: &Registry, name: &str, hash: &str, source: &str) -> Provenance {
        let rev = reg
            .revisions
            .iter()
            .rev()
            .find(|r| r.name == name && r.hash == hash);
        Provenance {
            origin: source.to_string(),
            by: rev.map(|r| r.by.clone()),
            via: rev.map(|r| r.via.clone()),
            ms: rev.map(|r| r.ms),
        }
    }

    fn push_views(reg: &Registry, name: &str, current: Option<&str>) -> Vec<PushView> {
        reg.pushes
            .iter()
            .filter(|p| p.name == name)
            .map(|p| PushView {
                box_name: p.box_name.clone(),
                hash: p.hash.clone(),
                agents: p.agents.clone(),
                pushed_by: p.pushed_by.clone(),
                pushed_ms: p.pushed_ms,
                matches_library: current.is_some_and(|c| c == p.hash),
            })
            .collect()
    }

    pub fn catalog(&self) -> Vec<CatalogItem> {
        let reg = self.registry();
        let mut out = Vec::new();
        let src = self.sources();
        for (name, (p, source)) in &src {
            let hash = p.hash();
            let bundled_too = self.bundled.iter().any(|b| &b.name == name);
            out.push(CatalogItem {
                name: name.clone(),
                description: p.description.clone(),
                version: p.version.clone(),
                license: p.license.clone(),
                approved: Self::approved(&reg, p, &hash),
                asks: p.asks().map(|a| a.keys()).unwrap_or_default(),
                files: Self::file_infos(p),
                installs: reg
                    .installs
                    .iter()
                    .filter(|i| &i.name == name)
                    .map(|i| self.view(&reg, i, Some(&hash)))
                    .collect(),
                provenance: Self::provenance(&reg, name, &hash, source),
                shadows_bundled: *source == "library" && bundled_too,
                pushes: Self::push_views(&reg, name, Some(&hash)),
                revisions: reg
                    .revisions
                    .iter()
                    .filter(|r| &r.name == name && r.hash != hash)
                    .count(),
                source: (*source).to_string(),
                hash,
            });
        }
        // An install or push whose source has been removed from the library still shows, so it can be removed.
        let orphans: BTreeSet<(String, String)> = reg
            .installs
            .iter()
            .map(|i| (i.name.clone(), i.hash.clone()))
            .chain(reg.pushes.iter().flat_map(|p| {
                p.hashes()
                    .into_iter()
                    .map(|h| (p.name.clone(), h.to_string()))
            }))
            .filter(|(n, _)| !src.contains_key(n))
            .collect();
        let mut seen = BTreeSet::new();
        for (name, hash) in orphans {
            if !seen.insert(name.clone()) {
                continue;
            }
            if let Some(p) = self.read_snapshot(&name, &hash) {
                out.push(CatalogItem {
                    name: name.clone(),
                    description: p.description.clone(),
                    version: p.version.clone(),
                    license: p.license.clone(),
                    hash: hash.clone(),
                    source: "removed".into(),
                    approved: Self::approved(&reg, &p, &hash),
                    asks: p.asks().map(|a| a.keys()).unwrap_or_default(),
                    files: Self::file_infos(&p),
                    installs: reg
                        .installs
                        .iter()
                        .filter(|i| i.name == name)
                        .map(|i| self.view(&reg, i, None))
                        .collect(),
                    provenance: Self::provenance(&reg, &name, &hash, "removed"),
                    shadows_bundled: false,
                    pushes: Self::push_views(&reg, &name, None),
                    revisions: 0,
                });
            }
        }
        out
    }

    fn history_dir(&self, name: &str, hash: &str) -> PathBuf {
        self.root.join("history").join(name).join(hash)
    }

    fn read_dir_pack(dir: &Path, hash: &str) -> Option<SkillPack> {
        let mut files = BTreeMap::new();
        fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) -> Option<()> {
            for e in fs::read_dir(dir).ok()?.flatten() {
                let p = e.path();
                let meta = fs::symlink_metadata(&p).ok()?;
                if meta.is_dir() {
                    walk(base, &p, out)?;
                } else if meta.is_file() {
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
        walk(dir, dir, &mut files)?;
        if hash_files(&files) != hash {
            return None;
        }
        SkillPack::from_files(files).ok()
    }

    fn write_pack_dir(dir: &Path, pack: &SkillPack) -> Result<(), SkillError> {
        let _ = fs::remove_dir_all(dir);
        for (p, b) in &pack.files {
            write_atomic(&dir.join(p), b).map_err(io)?;
        }
        Ok(())
    }

    /// Add a skill to the library (the person's own skills). Everything an agent could be told is in `pack`, already checked.
    /// Replacing one that is there archives it first, so it can be read and restored; the new files are a new hash and wait
    /// for a new approval.
    pub fn add_pack(
        &self,
        pack: SkillPack,
        origin: &Origin,
        replace: &Replace,
        allow_shadow: bool,
        now: u64,
    ) -> Result<CatalogItem, SkillError> {
        self.add_pack_inner(pack, origin, replace, allow_shadow, now)
    }

    /// Whatever is added starts unapproved, even when an approval of exactly these files is still on record (a version that
    /// is still installed or on a box): approvals are of what a person looked at for this purpose. Restoring an earlier
    /// version and adding its identical bytes again are the same act. (Adding what is already current changes nothing.)
    fn add_pack_inner(
        &self,
        pack: SkillPack,
        origin: &Origin,
        replace: &Replace,
        allow_shadow: bool,
        now: u64,
    ) -> Result<CatalogItem, SkillError> {
        let _l = self.lock()?;
        let name = pack.name.clone();
        let lib = self.root.join("library");
        // A folder that differs from this name only by case is the same folder on a disk that does not tell them apart, so
        // it is refused, never replaced.
        for e in fs::read_dir(&lib).into_iter().flatten().flatten() {
            let n = e.file_name().to_string_lossy().to_string();
            if n != name && n.eq_ignore_ascii_case(&name) {
                return Err(SkillError::Refused(format!(
                    "the library already holds a folder called {n}, which is the same name apart from upper and lower case; use another name, or remove that one first"
                )));
            }
        }
        let dest = lib.join(&name);
        let existing = if dest.is_dir() {
            SkillPack::from_dir(&dest).ok()
        } else {
            None
        };
        if existing.is_none() && fs::symlink_metadata(&dest).is_ok() {
            // never delete what is not recognisably this skill
            return Err(SkillError::Refused(format!(
                "the library already holds something called {name} that is not a readable skill; remove it first"
            )));
        }
        match (&existing, replace) {
            (Some(_), Replace::Fresh) => {
                return Err(SkillError::Refused(format!(
                    "your library already has a skill called {name}; choose to replace it, or use another name"
                )))
            }
            (Some(e), Replace::Over(h)) if &e.hash() != h => {
                return Err(SkillError::Refused(format!(
                    "{name} changed in the library since you looked at it; reload and try again"
                )))
            }
            (None, Replace::Over(_)) => {
                return Err(SkillError::Refused(format!(
                    "{name} is not in the library any more; reload and try again"
                )))
            }
            _ => {}
        }
        if existing.is_none()
            && !allow_shadow
            && matches!(replace, Replace::Fresh | Replace::Over(_))
            && self.bundled.iter().any(|b| b.name == name)
        {
            return Err(SkillError::Refused(format!(
                "a skill that ships with Oz Box is called {name}; yours would replace it in the catalog. Confirm that, or use another name"
            )));
        }
        let hash = pack.hash();
        if existing.as_ref().is_some_and(|e| e.hash() == hash) {
            drop(_l);
            return self
                .catalog()
                .into_iter()
                .find(|c| c.name == name)
                .ok_or(SkillError::NotFound);
        }
        let mut reg = self.registry();
        if let Some(e) = &existing {
            let h = e.hash();
            let hd = self.history_dir(&name, &h);
            if Self::read_dir_pack(&hd, &h).is_none() {
                Self::write_pack_dir(&hd, e)?;
            }
            if !reg.revisions.iter().any(|r| r.name == name && r.hash == h) {
                reg.revisions.push(Revision {
                    name: name.clone(),
                    hash: h,
                    version: e.version.clone(),
                    by: "unknown".into(),
                    via: "folder".into(),
                    ms: 0,
                });
            }
        }
        let tmp = self.root.join("library").join(format!(".{name}.new"));
        Self::write_pack_dir(&tmp, &pack)?;
        let _ = fs::remove_dir_all(&dest);
        fs::rename(&tmp, &dest).map_err(io)?;
        // the new version's own copy, so it can be read after a later replacement
        let hd = self.history_dir(&name, &hash);
        if Self::read_dir_pack(&hd, &hash).is_none() {
            Self::write_pack_dir(&hd, &pack)?;
        }
        reg.revisions
            .retain(|r| !(r.name == name && r.hash == hash));
        reg.revisions.push(Revision {
            name: name.clone(),
            hash: hash.clone(),
            version: pack.version.clone(),
            by: origin.by.clone(),
            via: origin.via.clone(),
            ms: now,
        });
        // keep the last MAX_REVISIONS of this skill, and drop the archived files of the rest
        let mine: Vec<usize> = reg
            .revisions
            .iter()
            .enumerate()
            .filter(|(_, r)| r.name == name)
            .map(|(i, _)| i)
            .collect();
        if mine.len() > MAX_REVISIONS {
            let drop_n = mine.len() - MAX_REVISIONS;
            let gone: Vec<usize> = mine.into_iter().take(drop_n).collect();
            for i in &gone {
                let _ = fs::remove_dir_all(self.history_dir(&name, &reg.revisions[*i].hash));
            }
            let mut i = 0;
            reg.revisions.retain(|_| {
                i += 1;
                !gone.contains(&(i - 1))
            });
        }
        reg.approvals
            .retain(|a| !(a.name == name && a.hash == hash));
        self.gc(&mut reg);
        self.save(&reg)?;
        drop(_l);
        self.catalog()
            .into_iter()
            .find(|c| c.name == name)
            .ok_or(SkillError::NotFound)
    }

    /// Copy a folder into the library (`ozbox skills add`). Replacing one changes its hash.
    pub fn add_to_library(
        &self,
        dir: &Path,
        who: &str,
        now: u64,
    ) -> Result<CatalogItem, SkillError> {
        let pack = SkillPack::from_dir(dir)?;
        self.add_pack(
            pack,
            &Origin {
                by: who.to_string(),
                via: "cli".into(),
            },
            &Replace::Force,
            true,
            now,
        )
    }

    /// The versions of a library skill kept here, newest first.
    pub fn history(&self, name: &str) -> Result<Vec<RevisionView>, SkillError> {
        let reg = self.registry();
        let src = self.sources();
        let current = src.get(name).map(|(p, _)| p.hash());
        let mut v: Vec<RevisionView> = reg
            .revisions
            .iter()
            .filter(|r| r.name == name)
            .map(|r| RevisionView {
                hash: r.hash.clone(),
                version: r.version.clone(),
                by: r.by.clone(),
                via: r.via.clone(),
                ms: r.ms,
                current: current.as_deref() == Some(r.hash.as_str()),
                approved: Self::read_dir_pack(&self.history_dir(name, &r.hash), &r.hash)
                    .is_some_and(|p| Self::approved(&reg, &p, &r.hash)),
            })
            .collect();
        if v.is_empty() && !src.contains_key(name) {
            return Err(SkillError::NotFound);
        }
        v.reverse();
        Ok(v)
    }

    /// Make an earlier version of a library skill the current one again. It is a new addition: it waits for approval.
    pub fn restore(
        &self,
        name: &str,
        hash: &str,
        who: &str,
        now: u64,
    ) -> Result<CatalogItem, SkillError> {
        if !skill_name_ok_here(name) {
            return Err(SkillError::NotFound);
        }
        let reg = self.registry();
        if !reg
            .revisions
            .iter()
            .any(|r| r.name == name && r.hash == hash)
        {
            return Err(SkillError::NotFound);
        }
        let pack = Self::read_dir_pack(&self.history_dir(name, hash), hash).ok_or_else(|| {
            SkillError::Refused("that version's files are not intact any more".into())
        })?;
        let current = self
            .sources()
            .get(name)
            .filter(|(_, s)| *s == "library")
            .map(|(p, _)| p.hash());
        let replace = match current.clone() {
            Some(h) => Replace::Over(h),
            None => Replace::Fresh,
        };
        self.add_pack_inner(
            pack,
            &Origin {
                by: who.to_string(),
                via: "restore".into(),
            },
            &replace,
            true,
            now,
        )
    }

    pub fn remove_from_library(&self, name: &str) -> Result<(), SkillError> {
        if !name_ok(name) {
            return Err(SkillError::NotFound);
        }
        let _l = self.lock()?;
        let dir = self.root.join("library").join(name);
        // the exact name: on a disk that does not tell `Demo` from `demo`, a look-alike must not be the one that is removed
        let exact = fs::read_dir(self.root.join("library"))
            .into_iter()
            .flatten()
            .flatten()
            .any(|e| e.file_name().to_string_lossy() == name);
        if !exact || !dir.is_dir() {
            return Err(SkillError::NotFound);
        }
        fs::remove_dir_all(dir).map_err(io)?;
        let _ = fs::remove_dir_all(self.root.join("history").join(name));
        let mut reg = self.registry();
        reg.revisions.retain(|r| r.name != name);
        self.gc(&mut reg);
        self.save(&reg)
    }

    /// The files to put on a box's disk: the catalog's current files, and only if a person approved exactly them. `hash` is
    /// what the person was looking at; if the library has changed since, this is refused like a stale approval.
    pub fn for_push(&self, name: &str, hash: &str) -> Result<SkillPack, SkillError> {
        let reg = self.registry();
        let src = self.sources();
        let (pack, _) = src.get(name).ok_or(SkillError::NotFound)?;
        if pack.hash() != hash {
            return Err(SkillError::Refused(
                "those are not the files of this skill any more; review it again".into(),
            ));
        }
        if !Self::approved(&reg, pack, hash) {
            return Err(SkillError::NotApproved(
                "a person has not approved these files yet (with every command and permission they ask for acknowledged); review and approve them first".into(),
            ));
        }
        Ok(pack.clone())
    }

    /// Record that `hash` of `name` was put on `box_name` (replacing an earlier record for that box).
    pub fn record_push(
        &self,
        name: &str,
        box_name: &str,
        hash: &str,
        agents: Vec<String>,
        who: &str,
        now: u64,
    ) -> Result<(), SkillError> {
        let _l = self.lock()?;
        // The files that were sent: the library's, or, when the library has moved on since the push began, the version it
        // archived. Either way the hash recorded is the one actually put on the box, and it is recorded even if the
        // approval was withdrawn meanwhile (the copy is on the box, and the dashboard must be able to account for it).
        let src = self.sources();
        let pack = match src.get(name) {
            Some((p, _)) if p.hash() == hash => p.clone(),
            _ => Self::read_dir_pack(&self.history_dir(name, hash), hash).ok_or_else(|| {
                SkillError::Refused(
                    "the files that were sent are no longer kept here, so the copy on the box could not be recorded".into(),
                )
            })?,
        };
        let dir = self.snapshot_dir(name, hash);
        if self.read_snapshot(name, hash).is_none() {
            Self::write_pack_dir(&dir, &pack)?;
        }
        let mut reg = self.registry();
        // A push that reached only some folders leaves the others at the hash they had.
        let mut places: BTreeMap<String, String> = reg
            .pushes
            .iter()
            .find(|p| p.name == name && p.box_name == box_name)
            .map(|old| {
                SKILL_AGENTS
                    .iter()
                    .filter_map(|a| {
                        old.hash_for(a.id)
                            .map(|h| (a.id.to_string(), h.to_string()))
                    })
                    .collect()
            })
            .unwrap_or_default();
        for a in &agents {
            places.insert(a.clone(), hash.to_string());
        }
        reg.pushes
            .retain(|p| !(p.name == name && p.box_name == box_name));
        reg.pushes.push(Push {
            name: name.to_string(),
            box_name: box_name.to_string(),
            hash: hash.to_string(),
            agents: places.keys().cloned().collect(),
            places,
            pushed_by: who.to_string(),
            pushed_ms: now,
        });
        let approved = Self::approved(&reg, &pack, hash);
        self.gc(&mut reg);
        self.save(&reg)?;
        if approved {
            Ok(())
        } else {
            Err(SkillError::NotApproved(
                "the approval was withdrawn while the skill was being put on the box; the copy is recorded and can be removed".into(),
            ))
        }
    }

    /// What this dashboard recorded putting on `box_name` for `name`, per agent folder: the hashes it may claim.
    pub fn pushed_places(&self, name: &str, box_name: &str) -> BTreeMap<String, String> {
        let reg = self.registry();
        reg.pushes
            .iter()
            .find(|p| p.name == name && p.box_name == box_name)
            .map(|p| {
                SKILL_AGENTS
                    .iter()
                    .filter_map(|a| p.hash_for(a.id).map(|h| (a.id.to_string(), h.to_string())))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Every skill this dashboard recorded putting on `box_name`, and for each the hash per agent folder.
    pub fn pushed_to(&self, box_name: &str) -> BTreeMap<String, BTreeMap<String, String>> {
        let reg = self.registry();
        reg.pushes
            .iter()
            .filter(|p| p.box_name == box_name)
            .map(|p| {
                (
                    p.name.clone(),
                    SKILL_AGENTS
                        .iter()
                        .filter_map(|a| p.hash_for(a.id).map(|h| (a.id.to_string(), h.to_string())))
                        .collect(),
                )
            })
            .collect()
    }

    /// Forget some of the places recorded for `name` on `box_name` (the folders a removal took away).
    pub fn forget_places(
        &self,
        name: &str,
        box_name: &str,
        agents: &[String],
    ) -> Result<(), SkillError> {
        let _l = self.lock()?;
        let mut reg = self.registry();
        for p in reg
            .pushes
            .iter_mut()
            .filter(|p| p.name == name && p.box_name == box_name)
        {
            let mut places: BTreeMap<String, String> = SKILL_AGENTS
                .iter()
                .filter_map(|a| p.hash_for(a.id).map(|h| (a.id.to_string(), h.to_string())))
                .collect();
            places.retain(|a, _| !agents.contains(a));
            p.agents = places.keys().cloned().collect();
            p.places = places;
        }
        reg.pushes.retain(|p| !p.agents.is_empty());
        self.gc(&mut reg);
        self.save(&reg)
    }

    /// Forget the record of `name` on `box_name`. Not an error when there is none: the box's disk is what counts.
    pub fn forget_push(&self, name: &str, box_name: &str) -> Result<(), SkillError> {
        let _l = self.lock()?;
        let mut reg = self.registry();
        reg.pushes
            .retain(|p| !(p.name == name && p.box_name == box_name));
        self.gc(&mut reg);
        self.save(&reg)
    }

    /// Library folders that cannot be read as a skill, with why, so a person can see and remove them (a folder from before
    /// names were lower case, one whose front matter is no longer valid, one that was edited by hand).
    pub fn unreadable(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for e in fs::read_dir(self.root.join("library"))
            .into_iter()
            .flatten()
            .flatten()
        {
            let n = e.file_name().to_string_lossy().to_string();
            if n.starts_with('.') || !e.path().is_dir() {
                continue;
            }
            if let Err(why) = SkillPack::from_dir(&e.path()) {
                out.push((
                    n.chars().take(64).collect(),
                    why.to_string().chars().take(200).collect(),
                ));
            }
        }
        out.sort();
        out.truncate(50);
        out
    }

    /// Where the skills are kept, for a page to say.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Install (or update to the catalog's current files) at a scope. Installing never approves.
    pub fn install(
        &self,
        name: &str,
        scope: &InstallScope,
        who: &str,
        now: u64,
    ) -> Result<InstallView, SkillError> {
        let _l = self.lock()?;
        let src = self.sources();
        let (pack, source) = src.get(name).ok_or(SkillError::NotFound)?;
        let hash = pack.hash();
        let dir = self.snapshot_dir(name, &hash);
        if self.read_snapshot(name, &hash).is_none() {
            let _ = fs::remove_dir_all(&dir);
            for (p, b) in &pack.files {
                write_atomic(&dir.join(p), b).map_err(io)?;
            }
        }
        let mut reg = self.registry();
        reg.installs
            .retain(|i| !(i.name == name && i.scope == scope.to_string()));
        let rec = Install {
            name: name.to_string(),
            scope: scope.to_string(),
            hash: hash.clone(),
            source: (*source).to_string(),
            installed_by: who.to_string(),
            installed_ms: now,
        };
        reg.installs.push(rec.clone());
        self.gc(&mut reg);
        self.save(&reg)?;
        Ok(self.view(&reg, &rec, Some(&hash)))
    }

    pub fn uninstall(&self, name: &str, scope: &InstallScope) -> Result<(), SkillError> {
        let _l = self.lock()?;
        let mut reg = self.registry();
        let before = reg.installs.len();
        reg.installs
            .retain(|i| !(i.name == name && i.scope == scope.to_string()));
        if reg.installs.len() == before {
            return Err(SkillError::NotFound);
        }
        self.gc(&mut reg);
        self.save(&reg)
    }

    /// Approve exactly `hash` of `name`. The hash must be one the person could have been looking at: the catalog's
    /// current files or an installed snapshot. An approval of anything else is refused, so a stale page cannot approve
    /// files that changed after it was loaded.
    pub fn approve(
        &self,
        name: &str,
        hash: &str,
        who: &str,
        now: u64,
        acks: &[String],
    ) -> Result<(), SkillError> {
        let _l = self.lock()?;
        let src = self.sources();
        let mut reg = self.registry();
        let pack = src
            .get(name)
            .filter(|(p, _)| p.hash() == hash)
            .map(|(p, _)| p.clone())
            .or_else(|| {
                reg.installs
                    .iter()
                    .any(|i| i.name == name && i.hash == hash)
                    .then(|| self.read_snapshot(name, hash))
                    .flatten()
            })
            .ok_or_else(|| {
                SkillError::Refused(
                    "those are not the files of this skill any more; review it again".into(),
                )
            })?;
        let need = pack.asks()?.keys();
        if let Some(k) = acks.iter().find(|k| !need.contains(&k.as_str())) {
            return Err(SkillError::Invalid(format!(
                "{} is not something this skill asks for",
                k.chars().take(40).collect::<String>()
            )));
        }
        let missing: Vec<&str> = need
            .iter()
            .copied()
            .filter(|k| !acks.iter().any(|a| a == k))
            .collect();
        if !missing.is_empty() {
            return Err(SkillError::NotApproved(format!(
                "this skill asks to run commands or widen what an agent may do ({}); each one has to be acknowledged on its own before the skill can be approved",
                missing.join(", ")
            )));
        }
        // an approval is of exactly these files with exactly these acknowledgements: a new one replaces an older record
        reg.approvals
            .retain(|a| !(a.name == name && a.hash == hash));
        reg.approvals.push(Approval {
            name: name.to_string(),
            hash: hash.to_string(),
            approved_by: who.to_string(),
            approved_ms: now,
            acks: need.iter().map(|k| (*k).to_string()).collect(),
        });
        self.gc(&mut reg);
        self.save(&reg)
    }

    /// Withdraw every approval of a skill. It stays installed and waits for review again.
    pub fn revoke(&self, name: &str) -> Result<(), SkillError> {
        let _l = self.lock()?;
        let mut reg = self.registry();
        reg.approvals.retain(|a| a.name != name);
        self.save(&reg)
    }

    /// Everything a person should read before approving: the catalog's current files, or those of an installed hash.
    pub fn review(&self, name: &str, hash: Option<&str>) -> Result<Review, SkillError> {
        let reg = self.registry();
        let src = self.sources();
        let pack = match hash {
            Some(h) => self.read_snapshot(name, h).or_else(|| {
                src.get(name)
                    .filter(|(p, _)| p.hash() == h)
                    .map(|(p, _)| p.clone())
                    .or_else(|| {
                        // an earlier version of a skill of your own, to read before restoring it
                        reg.revisions
                            .iter()
                            .any(|r| r.name == name && r.hash == h)
                            .then(|| Self::read_dir_pack(&self.history_dir(name, h), h))
                            .flatten()
                    })
            }),
            None => src.get(name).map(|(p, _)| p.clone()),
        }
        .ok_or(SkillError::NotFound)?;
        let h = pack.hash();
        let source = match src.get(name) {
            Some((p, s)) if p.hash() == h => *s,
            Some(_) | None => "library",
        };
        Ok(Review {
            provenance: Self::provenance(&reg, name, &h, source),
            name: pack.name.clone(),
            description: pack.description.clone(),
            version: pack.version.clone(),
            license: pack.license.clone(),
            approved: Self::approved(&reg, &pack, &h),
            asks: pack.asks()?,
            hash: h,
            files: pack
                .files
                .iter()
                .map(|(p, b)| ReviewFile {
                    path: p.clone(),
                    text: String::from_utf8_lossy(b).to_string(),
                    kind: file_kind(p),
                })
                .collect(),
        })
    }

    fn applies(i: &Install, scopes: &[InstallScope]) -> bool {
        match InstallScope::parse(&i.scope) {
            Ok(InstallScope::Fleet) => true,
            Ok(s) => scopes.contains(&s),
            Err(_) => false,
        }
    }

    /// The skills an agent bound to `scopes` may use now: installed there, approved at the installed hash, files intact.
    pub fn usable(&self, scopes: &[InstallScope]) -> Vec<Usable> {
        let reg = self.registry();
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        for i in reg.installs.iter().filter(|i| Self::applies(i, scopes)) {
            if seen.contains(&i.name) {
                continue;
            }
            if let Some(p) = self
                .read_snapshot(&i.name, &i.hash)
                .filter(|p| Self::approved(&reg, p, &i.hash))
            {
                seen.insert(i.name.clone());
                out.push(Usable {
                    name: p.name,
                    description: p.description,
                    version: p.version,
                    hash: i.hash.clone(),
                });
            }
        }
        out
    }

    /// Read a usable skill's `SKILL.md` or one of its files, for an agent.
    pub fn read(
        &self,
        name: &str,
        file: Option<&str>,
        scopes: &[InstallScope],
    ) -> Result<String, SkillError> {
        let u = self
            .usable(scopes)
            .into_iter()
            .find(|u| u.name == name)
            .ok_or_else(|| {
                SkillError::Refused(
                    "that skill is not installed here, or no person has approved its current files"
                        .into(),
                )
            })?;
        let pack = self
            .read_snapshot(name, &u.hash)
            .ok_or(SkillError::NotFound)?;
        let path = file.unwrap_or("SKILL.md");
        let bytes = pack
            .files
            .get(path)
            .ok_or_else(|| SkillError::Invalid("that skill has no such file".into()))?;
        Ok(String::from_utf8_lossy(bytes).to_string())
    }
}

fn skill_name_ok_here(n: &str) -> bool {
    ozbox_core::skill_pack::skill_name_ok(n)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn pack(name: &str, body: &str) -> SkillPack {
        let mut f = BTreeMap::new();
        f.insert(
            "SKILL.md".to_string(),
            format!(
                "---\nname: {name}\ndescription: Does a thing.\nversion: 1.0.0\n---\n\n{body}\n"
            )
            .into_bytes(),
        );
        SkillPack::from_files(f).unwrap()
    }

    fn write_dir(root: &Path, name: &str, body: &str, extra: Option<(&str, &str)>) -> PathBuf {
        let d = root.join(name);
        fs::create_dir_all(&d).unwrap();
        fs::write(
            d.join("SKILL.md"),
            format!("---\nname: {name}\ndescription: Mine.\n---\n{body}\n"),
        )
        .unwrap();
        if let Some((p, t)) = extra {
            fs::write(d.join(p), t).unwrap();
        }
        d
    }

    fn store(d: &Path) -> SkillStore {
        SkillStore::open(
            d.join("skills"),
            vec![pack("triage", "Group failures by cause.")],
        )
        .unwrap()
    }

    #[test]
    fn a_skill_is_unusable_until_a_person_approves_exactly_these_files() {
        let d = tempfile::tempdir().unwrap();
        let s = store(d.path());
        let item = &s.catalog()[0];
        assert!(!item.approved);
        s.install("triage", &InstallScope::Fleet, "alice", 1)
            .unwrap();
        assert!(s.usable(&[]).is_empty(), "installed is not approved");
        assert!(s.read("triage", None, &[]).is_err());
        s.approve("triage", &item.hash, "alice", 2, &[]).unwrap();
        let u = s.usable(&[]);
        assert_eq!(u.len(), 1);
        assert!(s
            .read("triage", None, &[])
            .unwrap()
            .contains("Group failures"));
        // a hash nobody could have reviewed is refused
        assert!(matches!(
            s.approve("triage", "deadbeef", "alice", 3, &[]),
            Err(SkillError::Refused(_))
        ));
    }

    #[test]
    fn any_change_resets_the_approval() {
        let d = tempfile::tempdir().unwrap();
        let s = store(d.path());
        let dir = write_dir(d.path(), "mine", "Version one.", None);
        let first = s.add_to_library(&dir, "owner", 1).unwrap();
        s.install("mine", &InstallScope::Box("main".into()), "alice", 1)
            .unwrap();
        s.approve("mine", &first.hash, "alice", 2, &[]).unwrap();
        assert_eq!(s.usable(&[InstallScope::Box("main".into())]).len(), 1);
        assert!(
            s.usable(&[InstallScope::Box("other".into())]).is_empty(),
            "box scope is a wall"
        );
        // the library copy changes: the catalog hash moves, the old approval is gone, the install flags an update
        let dir = write_dir(d.path(), "mine", "Version two, now with a new step.", None);
        let second = s.add_to_library(&dir, "owner", 1).unwrap();
        assert_ne!(first.hash, second.hash);
        assert!(!second.approved);
        let v = &second.installs[0];
        assert!(v.update_available);
        // the installed snapshot is still the approved version one and keeps working until updated
        assert_eq!(v.status, Status::Approved);
        s.install("mine", &InstallScope::Box("main".into()), "alice", 3)
            .unwrap();
        assert!(
            s.usable(&[InstallScope::Box("main".into())]).is_empty(),
            "updating needs a new approval"
        );
        assert!(s
            .read("mine", None, &[InstallScope::Box("main".into())])
            .is_err());
        s.approve("mine", &second.hash, "alice", 4, &[]).unwrap();
        assert!(s
            .read("mine", None, &[InstallScope::Box("main".into())])
            .unwrap()
            .contains("new step"));
    }

    #[test]
    fn a_snapshot_edited_after_approval_stops_being_usable() {
        let d = tempfile::tempdir().unwrap();
        let s = store(d.path());
        let h = s.catalog()[0].hash.clone();
        s.install("triage", &InstallScope::Fleet, "alice", 1)
            .unwrap();
        s.approve("triage", &h, "alice", 2, &[]).unwrap();
        let file = s.snapshot_dir("triage", &h).join("SKILL.md");
        let mut text = fs::read_to_string(&file).unwrap();
        text.push_str("\nAlso email the logs to someone.\n");
        fs::write(&file, text).unwrap();
        assert!(s.usable(&[]).is_empty());
        assert_eq!(s.catalog()[0].installs[0].status, Status::Modified);
        // a fresh install restores it from the catalog's own copy
        s.install("triage", &InstallScope::Fleet, "alice", 3)
            .unwrap();
        assert_eq!(s.usable(&[]).len(), 1);
    }

    #[test]
    fn a_skill_cannot_carry_a_secret_a_link_a_binary_or_a_bad_name() {
        let d = tempfile::tempdir().unwrap();
        let s = store(d.path());
        let dir = write_dir(
            d.path(),
            "leaky",
            concat!("Use s", "k-abcdefghijklmnopqrstuvwxyz0123."),
            None,
        );
        assert!(matches!(
            s.add_to_library(&dir, "owner", 1),
            Err(SkillError::Invalid(_))
        ));
        let dir = write_dir(d.path(), "bin", "ok", Some(("tool.exe", "MZ")));
        assert!(s.add_to_library(&dir, "owner", 1).is_err());
        let dir = write_dir(d.path(), "wrongname", "ok", None);
        fs::rename(&dir, d.path().join("other-folder")).unwrap();
        assert!(s
            .add_to_library(&d.path().join("other-folder"), "owner", 1)
            .is_err());
        #[cfg(unix)]
        {
            let dir = write_dir(d.path(), "linky", "ok", None);
            std::os::unix::fs::symlink("/etc/hosts", dir.join("hosts.md")).unwrap();
            assert!(s.add_to_library(&dir, "owner", 1).is_err());
        }
        let mut f = BTreeMap::new();
        f.insert("SKILL.md".to_string(), b"no front matter".to_vec());
        assert!(SkillPack::from_files(f).is_err());
        let mut f = BTreeMap::new();
        f.insert("../escape.md".to_string(), b"x".to_vec());
        assert!(SkillPack::from_files(f).is_err());
    }

    #[test]
    fn revoke_uninstall_and_the_hash_depends_on_every_byte_and_path() {
        let d = tempfile::tempdir().unwrap();
        let s = store(d.path());
        let h = s.catalog()[0].hash.clone();
        s.install("triage", &InstallScope::Project("acme".into()), "alice", 1)
            .unwrap();
        s.approve("triage", &h, "alice", 2, &[]).unwrap();
        s.revoke("triage").unwrap();
        assert!(s.usable(&[InstallScope::Project("acme".into())]).is_empty());
        s.approve("triage", &h, "alice", 3, &[]).unwrap();
        s.uninstall("triage", &InstallScope::Project("acme".into()))
            .unwrap();
        assert!(s.usable(&[InstallScope::Project("acme".into())]).is_empty());
        assert_eq!(
            s.uninstall("triage", &InstallScope::Fleet),
            Err(SkillError::NotFound)
        );
        assert_ne!(pack("a", "x").hash(), pack("a", "y").hash());
        let mut one = pack("a", "x");
        let before = one.hash();
        one.files.insert("notes.md".into(), b"x".to_vec());
        assert_ne!(before, one.hash());
        assert!(InstallScope::parse("box:../x").is_err());
        assert!(InstallScope::parse("everything").is_err());
    }

    #[test]
    fn review_shows_the_files_that_would_be_approved() {
        let d = tempfile::tempdir().unwrap();
        let s = store(d.path());
        let r = s.review("triage", None).unwrap();
        assert_eq!(r.files[0].path, "SKILL.md");
        assert!(r.files[0].text.contains("Group failures"));
        assert_eq!(r.hash, s.catalog()[0].hash);
        assert_eq!(s.review("nope", None).unwrap_err(), SkillError::NotFound);
    }

    fn origin() -> Origin {
        Origin {
            by: "owner".into(),
            via: "page_upload".into(),
        }
    }

    #[test]
    fn replacing_a_library_skill_needs_the_hash_that_was_seen_and_keeps_the_old_version() {
        let d = tempfile::tempdir().unwrap();
        let s = store(d.path());
        let one = s
            .add_pack(pack("mine", "one"), &origin(), &Replace::Fresh, false, 1)
            .unwrap();
        assert!(matches!(
            s.add_pack(pack("mine", "two"), &origin(), &Replace::Fresh, false, 2),
            Err(SkillError::Refused(_))
        ));
        assert!(matches!(
            s.add_pack(
                pack("mine", "two"),
                &origin(),
                &Replace::Over("00".into()),
                false,
                2
            ),
            Err(SkillError::Refused(_))
        ));
        let two = s
            .add_pack(
                pack("mine", "two"),
                &origin(),
                &Replace::Over(one.hash.clone()),
                false,
                3,
            )
            .unwrap();
        assert_ne!(one.hash, two.hash);
        assert_eq!(
            (two.revisions, two.provenance.via.as_deref()),
            (1, Some("page_upload"))
        );
        let h = s.history("mine").unwrap();
        assert_eq!(h.len(), 2);
        assert!(h[0].current && !h[1].current);
        // the old version can be read, and restoring it is a new addition that needs approval
        assert!(s.review("mine", Some(&one.hash)).unwrap().files[0]
            .text
            .contains("one"));
        s.approve("mine", &two.hash, "owner", 4, &[]).unwrap();
        let back = s.restore("mine", &one.hash, "owner", 5).unwrap();
        assert_eq!(
            (back.hash.as_str(), back.approved),
            (one.hash.as_str(), false)
        );
        assert_eq!(back.provenance.via.as_deref(), Some("restore"));
        // a shipped skill's name is not taken without saying so
        assert!(matches!(
            s.add_pack(pack("triage", "mine"), &origin(), &Replace::Fresh, false, 6),
            Err(SkillError::Refused(_))
        ));
        let sh = s
            .add_pack(pack("triage", "mine"), &origin(), &Replace::Fresh, true, 6)
            .unwrap();
        assert!(sh.shadows_bundled && sh.source == "library");
        // deleting forgets the versions too
        s.remove_from_library("mine").unwrap();
        assert!(s.history("mine").is_err());
    }

    #[test]
    fn a_restored_version_is_unapproved_even_while_a_box_holds_it() {
        let d = tempfile::tempdir().unwrap();
        let s = store(d.path());
        let one = s
            .add_pack(pack("mine", "one"), &origin(), &Replace::Fresh, false, 1)
            .unwrap();
        s.approve("mine", &one.hash, "owner", 2, &[]).unwrap();
        s.record_push(
            "mine",
            "alpha",
            &one.hash,
            vec!["claude-code".into()],
            "owner",
            3,
        )
        .unwrap();
        let two = s
            .add_pack(
                pack("mine", "two"),
                &origin(),
                &Replace::Over(one.hash.clone()),
                false,
                4,
            )
            .unwrap();
        // the box still holds `one`, so its approval is still on record; restoring it must not bring it back approved
        let back = s.restore("mine", &one.hash, "owner", 5).unwrap();
        assert_eq!(
            (back.hash.as_str(), back.approved),
            (one.hash.as_str(), false)
        );
        assert!(matches!(
            s.for_push("mine", &one.hash),
            Err(SkillError::NotApproved(_))
        ));
        // approving it again works, and restoring what is already current changes nothing
        s.approve("mine", &one.hash, "owner", 6, &[]).unwrap();
        let again = s.restore("mine", &one.hash, "owner", 7).unwrap();
        assert!(again.approved);
        assert_ne!(two.hash, one.hash);
    }

    fn risky(front: &str, body: &str) -> SkillPack {
        let mut f = BTreeMap::new();
        f.insert(
            "SKILL.md".to_string(),
            format!("---\nname: risky\ndescription: Does a thing.\n{front}---\n{body}\n")
                .into_bytes(),
        );
        SkillPack::from_files(f).unwrap()
    }

    #[test]
    fn a_skill_that_runs_commands_needs_each_one_acknowledged_before_it_can_be_approved_or_pushed()
    {
        let d = tempfile::tempdir().unwrap();
        let s = store(d.path());
        let item = s
            .add_pack(
                risky(
                    "allowed-tools: Bash\nhooks:\n  Stop: x\n",
                    "Run !`ls` first.",
                ),
                &origin(),
                &Replace::Fresh,
                false,
                1,
            )
            .unwrap();
        let r = s.review("risky", None).unwrap();
        assert_eq!(r.asks.keys(), ["allowed-tools", "hooks", "shell-injection"]);
        let all: Vec<String> = r.asks.keys().iter().map(|k| (*k).to_string()).collect();
        // none, some, an unknown one: each refused, and nothing is approved
        for acks in [vec![], all[..2].to_vec(), vec!["bogus".to_string()]] {
            assert!(s.approve("risky", &item.hash, "owner", 2, &acks).is_err());
        }
        assert!(
            !s.catalog()
                .iter()
                .find(|c| c.name == "risky")
                .unwrap()
                .approved
        );
        assert!(matches!(
            s.for_push("risky", &item.hash),
            Err(SkillError::NotApproved(_))
        ));
        // an installed copy that is "approved" without acknowledgements (an older record) does not count either
        s.approve("risky", &item.hash, "owner", 3, &all).unwrap();
        assert!(s.for_push("risky", &item.hash).is_ok());
        s.install("risky", &InstallScope::Fleet, "owner", 4)
            .unwrap();
        assert_eq!(s.usable(&[InstallScope::Fleet]).len(), 1);
        // a plain skill needs none
        let plain = s
            .add_pack(pack("plain", "x"), &origin(), &Replace::Fresh, false, 5)
            .unwrap();
        s.approve("plain", &plain.hash, "owner", 6, &[]).unwrap();
    }

    #[test]
    fn adding_never_deletes_a_folder_that_is_not_this_skill() {
        let d = tempfile::tempdir().unwrap();
        let s = store(d.path());
        // something unreadable already there under the name
        let odd = s.root().join("library").join("mine");
        fs::create_dir_all(odd.join("sub")).unwrap();
        fs::write(odd.join("sub/keep.txt"), "mine").unwrap();
        let r = s.add_pack(pack("mine", "one"), &origin(), &Replace::Fresh, false, 1);
        assert!(matches!(r, Err(SkillError::Refused(_))), "{r:?}");
        assert_eq!(
            fs::read_to_string(odd.join("sub/keep.txt")).unwrap(),
            "mine"
        );
        // the same name apart from case (a folder from before names were lower case only)
        let lib = s.root().join("library");
        fs::create_dir_all(lib.join("Other")).unwrap();
        fs::write(lib.join("Other/keep.txt"), "x").unwrap();
        let r = s.add_pack(pack("other", "one"), &origin(), &Replace::Fresh, false, 2);
        assert!(matches!(r, Err(SkillError::Refused(_))), "{r:?}");
        assert!(lib.join("Other/keep.txt").exists());
    }

    #[test]
    fn only_an_approved_and_current_hash_may_be_pushed_and_a_push_keeps_its_approval_alive() {
        let d = tempfile::tempdir().unwrap();
        let s = store(d.path());
        let one = s
            .add_pack(pack("mine", "one"), &origin(), &Replace::Fresh, false, 1)
            .unwrap();
        assert!(matches!(
            s.for_push("mine", &one.hash),
            Err(SkillError::NotApproved(_))
        ));
        s.approve("mine", &one.hash, "owner", 2, &[]).unwrap();
        assert!(matches!(
            s.for_push("mine", "00"),
            Err(SkillError::Refused(_))
        ));
        let p = s.for_push("mine", &one.hash).unwrap();
        assert_eq!(p.hash(), one.hash);
        s.record_push(
            "mine",
            "alpha",
            &one.hash,
            vec!["claude-code".into()],
            "owner",
            3,
        )
        .unwrap();
        // the library moves on and then the skill is removed: the pushed files and their approval stay readable
        let two = s
            .add_pack(
                pack("mine", "two"),
                &origin(),
                &Replace::Over(one.hash.clone()),
                false,
                4,
            )
            .unwrap();
        assert!(!two.approved);
        s.remove_from_library("mine").unwrap();
        let cat = s.catalog();
        let left = cat.iter().find(|c| c.name == "mine").unwrap();
        assert_eq!((left.source.as_str(), left.approved), ("removed", true));
        assert_eq!(left.pushes[0].box_name, "alpha");
        s.forget_push("mine", "alpha").unwrap();
        assert!(s.catalog().iter().all(|c| c.name != "mine"));
    }

    #[test]
    fn adding_a_past_versions_identical_files_is_the_same_act_as_restoring_it() {
        let d = tempfile::tempdir().unwrap();
        let s = store(d.path());
        let one = s
            .add_pack(pack("mine", "one"), &origin(), &Replace::Fresh, false, 1)
            .unwrap();
        s.approve("mine", &one.hash, "owner", 2, &[]).unwrap();
        s.record_push(
            "mine",
            "alpha",
            &one.hash,
            vec!["claude-code".into()],
            "owner",
            3,
        )
        .unwrap();
        s.add_pack(
            pack("mine", "two"),
            &origin(),
            &Replace::Over(one.hash.clone()),
            false,
            4,
        )
        .unwrap();
        // the box still holds `one`, so its approval is on record; adding the same bytes again must not bring it back approved
        let again = s
            .add_pack(
                pack("mine", "one"),
                &origin(),
                &Replace::Over(
                    s.catalog()
                        .iter()
                        .find(|c| c.name == "mine")
                        .unwrap()
                        .hash
                        .clone(),
                ),
                false,
                5,
            )
            .unwrap();
        assert_eq!(
            (again.hash.as_str(), again.approved),
            (one.hash.as_str(), false)
        );
    }

    #[test]
    fn a_push_that_landed_is_recorded_as_sent_even_if_the_library_moved_or_the_approval_went() {
        let d = tempfile::tempdir().unwrap();
        let s = store(d.path());
        let one = s
            .add_pack(pack("mine", "one"), &origin(), &Replace::Fresh, false, 1)
            .unwrap();
        s.approve("mine", &one.hash, "owner", 2, &[]).unwrap();
        // the library moves on while the push is in flight: the hash that was sent is still recorded
        s.add_pack(
            pack("mine", "two"),
            &origin(),
            &Replace::Over(one.hash.clone()),
            false,
            3,
        )
        .unwrap();
        // (the library moving on also lets go of the approval nothing holds, so the caller is told; the copy is recorded)
        let r = s.record_push(
            "mine",
            "alpha",
            &one.hash,
            vec!["claude-code".into()],
            "owner",
            4,
        );
        assert!(matches!(r, Err(SkillError::NotApproved(_))), "{r:?}");
        assert_eq!(s.pushed_places("mine", "alpha")["claude-code"], one.hash);
        // the approval is withdrawn meanwhile: the copy is still recorded, and the caller is told
        s.revoke("mine").unwrap();
        let r = s.record_push(
            "mine",
            "beta",
            &one.hash,
            vec!["claude-code".into()],
            "owner",
            5,
        );
        assert!(matches!(r, Err(SkillError::NotApproved(_))), "{r:?}");
        assert_eq!(s.pushed_places("mine", "beta")["claude-code"], one.hash);
        // files that are not kept anywhere cannot be recorded, and the error says so
        let r = s.record_push(
            "mine",
            "gamma",
            "00",
            vec!["claude-code".into()],
            "owner",
            6,
        );
        assert!(matches!(r, Err(SkillError::Refused(_))));
        assert!(s.pushed_places("mine", "gamma").is_empty());
    }

    #[test]
    fn a_library_folder_that_cannot_be_read_is_listed_with_why() {
        let d = tempfile::tempdir().unwrap();
        let s = store(d.path());
        let dir = s.root().join("library").join("Old_Name");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("SKILL.md"),
            "---\nname: Old_Name\ndescription: x\n---\n",
        )
        .unwrap();
        let u = s.unreadable();
        assert_eq!(u.len(), 1);
        assert_eq!(u[0].0, "Old_Name");
        assert!(u[0].1.contains("name"), "{}", u[0].1);
        s.remove_from_library("Old_Name").unwrap();
        assert!(s.unreadable().is_empty());
    }
}
