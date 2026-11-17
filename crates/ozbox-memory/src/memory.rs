//! Agent memory: Markdown notes in a git repository, a SQLite full-text index over them, scopes, provenance, review
//! and expiry.
//!
//! **Layout.** `entries/<kind>/<name>/<id>.md` under the memory root, each file a TOML front matter between `+++` lines
//! and then the note's Markdown. Every change is one git commit whose message names the verb, the id, the scope and the
//! actor (never the text). `.index/` (the SQLite file) is not committed: it is rebuilt from the files whenever the
//! repository's head moves, so editing, pulling or reverting with plain git just works.
//!
//! **Who may do what.** A [`Caller::Person`] reads and writes every scope that is theirs and what they write is approved.
//! A [`Caller::Agent`] is bound to the scopes its session names; it can read only approved, unexpired notes there and can
//! only *propose* notes, which stay `pending` and invisible to every agent until a person approves them. An agent can
//! neither edit nor forget a note. Text is scanned for secrets on every write and refused if it looks like one.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

use crate::lock::FileLock;
use crate::secret_shape::find_secret;
use crate::{name_ok, random_id, write_atomic};

pub const MAX_TITLE: usize = 120;
pub const MAX_BODY: usize = 8 * 1024;
pub const MAX_TAGS: usize = 8;
pub const MAX_PER_SCOPE: usize = 500;
pub const MAX_PENDING_PER_SCOPE: usize = 50;
const ORIGIN_DAYS_MAX: u64 = 3650;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemError {
    /// Not allowed for this caller (the text says what to do instead).
    Denied(String),
    Invalid(String),
    NotFound,
    /// The text looks like a secret; the value is the kind.
    Secret(&'static str),
    Limit(String),
    Io(String),
}

impl fmt::Display for MemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MemError::Denied(s) | MemError::Invalid(s) | MemError::Limit(s) | MemError::Io(s) => {
                f.write_str(s)
            }
            MemError::NotFound => f.write_str("there is no such note"),
            MemError::Secret(k) => write!(
                f,
                "that text looks like {k}. Memory never holds a secret: write what it is for, not the value."
            ),
        }
    }
}

impl std::error::Error for MemError {}

fn io<E: fmt::Display>(e: E) -> MemError {
    MemError::Io(format!("the memory store could not be used: {e}"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScopeKind {
    Person,
    Project,
    Box,
}

impl ScopeKind {
    fn id(self) -> &'static str {
        match self {
            ScopeKind::Person => "person",
            ScopeKind::Project => "project",
            ScopeKind::Box => "box",
        }
    }
}

/// Whose memory a note is: a person's, a project's or a box's.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Scope {
    pub kind: ScopeKind,
    pub name: String,
}

impl Scope {
    pub fn new(kind: ScopeKind, name: &str) -> Result<Scope, MemError> {
        if !name_ok(name) {
            return Err(MemError::Invalid(
                "a scope name is letters, digits, dot, dash and underscore, 1 to 64".into(),
            ));
        }
        Ok(Scope {
            kind,
            name: name.to_string(),
        })
    }

    /// `person:alice`, `project:billing`, `box:main`.
    pub fn parse(s: &str) -> Result<Scope, MemError> {
        let (k, n) = s.split_once(':').ok_or_else(|| {
            MemError::Invalid("a scope looks like person:name, project:name or box:name".into())
        })?;
        let kind = match k {
            "person" => ScopeKind::Person,
            "project" => ScopeKind::Project,
            "box" => ScopeKind::Box,
            _ => {
                return Err(MemError::Invalid(
                    "a scope is person, project or box".into(),
                ))
            }
        };
        Scope::new(kind, n)
    }

    fn dir(&self, root: &Path) -> PathBuf {
        root.join("entries").join(self.kind.id()).join(&self.name)
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.kind.id(), self.name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    /// Written by an agent; no agent can read it until a person approves it.
    Pending,
    Approved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ActorKind {
    Person,
    Agent,
}

/// Who wrote a note, and who reviewed it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    pub actor: String,
    pub kind: ActorKind,
    /// The run that wrote it, for an agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<String>,
    /// The terminal enrolment that wrote it (a coding agent in a box's terminal, by the door's key for it). It is not a run,
    /// so it has its own field: nothing that links a run to its page may read it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    /// The box an agent wrote it on, when that was not this box (a proposal over the fabric, ADR 0056).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub box_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewed_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Entry {
    pub id: String,
    pub scope: String,
    pub title: String,
    pub body: String,
    pub tags: Vec<String>,
    pub state: State,
    pub created_ms: u64,
    pub updated_ms: u64,
    pub expires_ms: Option<u64>,
    pub revision: u32,
    pub provenance: Provenance,
    /// Computed from `expires_ms` at the time of the read.
    pub expired: bool,
}

#[derive(Serialize, Deserialize)]
struct Front {
    id: String,
    scope: String,
    title: String,
    state: State,
    #[serde(default)]
    tags: Vec<String>,
    created_ms: u64,
    updated_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires_ms: Option<u64>,
    #[serde(default = "one")]
    revision: u32,
    provenance: Provenance,
}

fn one() -> u32 {
    1
}

fn render(e: &Entry) -> Result<String, MemError> {
    let f = Front {
        id: e.id.clone(),
        scope: e.scope.clone(),
        title: e.title.clone(),
        state: e.state,
        tags: e.tags.clone(),
        created_ms: e.created_ms,
        updated_ms: e.updated_ms,
        expires_ms: e.expires_ms,
        revision: e.revision,
        provenance: e.provenance.clone(),
    };
    let toml = toml::to_string(&f).map_err(io)?;
    Ok(format!("+++\n{toml}+++\n\n{}\n", e.body))
}

fn parse_file(text: &str, now: u64) -> Result<Entry, MemError> {
    let rest = text
        .strip_prefix("+++\n")
        .ok_or_else(|| MemError::Invalid("a note starts with a +++ front matter".into()))?;
    let end = rest
        .find("\n+++")
        .ok_or_else(|| MemError::Invalid("the front matter is not closed".into()))?;
    let (front, body) = rest.split_at(end + 1);
    let body = body.trim_start_matches("+++").trim();
    let f: Front =
        toml::from_str(front).map_err(|e| MemError::Invalid(format!("front matter: {e}")))?;
    Ok(Entry {
        expired: f.expires_ms.is_some_and(|x| x <= now),
        id: f.id,
        scope: f.scope,
        title: f.title,
        body: body.to_string(),
        tags: f.tags,
        state: f.state,
        created_ms: f.created_ms,
        updated_ms: f.updated_ms,
        expires_ms: f.expires_ms,
        revision: f.revision,
        provenance: f.provenance,
    })
}

fn id_ok(id: &str) -> bool {
    id.len() == 12
        && id
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

/// What an agent's session is bound to. Built by the tool host from the session, never from anything the agent says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentCtx {
    /// The person the agent works for: their `person:` scope is readable.
    pub person: String,
    pub run: Option<String>,
    /// The door's key for a coding agent in the box's terminal; names it in a proposal's provenance, never as a run.
    pub terminal: Option<String>,
    pub projects: Vec<String>,
    pub box_name: Option<String>,
    /// An agent on another box whose proposal came over the fabric (ADR 0056): its address, `agent:<box>/<session>`, which is
    /// what the note is credited to, and the box its provenance names.
    pub origin: Option<String>,
}

impl AgentCtx {
    /// The box an `origin` address names.
    pub fn origin_box(&self) -> Option<String> {
        let a = self.origin.as_deref()?.strip_prefix("agent:")?;
        a.split_once('/').map(|(b, _)| b.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Caller {
    Person(String),
    Agent(AgentCtx),
}

impl Caller {
    pub fn actor(&self) -> String {
        match self {
            Caller::Person(p) => p.clone(),
            Caller::Agent(a) => match &a.origin {
                Some(o) => o.clone(),
                None => format!(
                    "agent:{}",
                    a.terminal
                        .as_deref()
                        .or(a.run.as_deref())
                        .unwrap_or("session")
                ),
            },
        }
    }

    /// May this caller see notes of the scope at all (agents: approved ones only, see [`Memory::get`]).
    pub fn can_read(&self, s: &Scope) -> bool {
        match self {
            Caller::Person(p) => s.kind != ScopeKind::Person || &s.name == p,
            Caller::Agent(a) => match s.kind {
                ScopeKind::Person => s.name == a.person,
                ScopeKind::Project => a.projects.iter().any(|p| p == &s.name),
                ScopeKind::Box => a.box_name.as_deref() == Some(s.name.as_str()),
            },
        }
    }

    fn is_person(&self) -> bool {
        matches!(self, Caller::Person(_))
    }
}

#[derive(Debug, Clone, Default)]
pub struct NewEntry {
    pub title: String,
    pub body: String,
    pub tags: Vec<String>,
    pub expires_ms: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct Patch {
    pub title: Option<String>,
    pub body: Option<String>,
    pub tags: Option<Vec<String>>,
    /// `Some(None)` clears the expiry.
    pub expires_ms: Option<Option<u64>>,
}

#[derive(Debug, Clone, Default)]
pub struct Filter {
    pub scope: Option<Scope>,
    pub state: Option<State>,
    pub include_expired: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Stats {
    pub total: usize,
    pub pending: usize,
    pub approved: usize,
    pub expired: usize,
}

pub struct Memory {
    root: PathBuf,
}

impl Memory {
    /// Open the store at `root`, creating the git repository on first use, and bring the index up to date.
    pub fn open(root: impl Into<PathBuf>) -> Result<Memory, MemError> {
        let m = Memory { root: root.into() };
        fs::create_dir_all(m.root.join("entries")).map_err(io)?;
        let _l = m.lock()?;
        if !m.root.join(".git").exists() {
            m.git(&["init", "-q", "-b", "main"])?;
            write_atomic(&m.root.join(".gitignore"), b".index/\n*.lock\n*.tmp\n").map_err(io)?;
            m.commit("memory: start the store")?;
        }
        m.sync_locked()?;
        Ok(m)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn lock(&self) -> Result<FileLock, MemError> {
        FileLock::take(&self.root.join("memory.lock")).map_err(io)
    }

    fn git(&self, args: &[&str]) -> Result<String, MemError> {
        let out = Command::new("git")
            .arg("-C")
            .arg(&self.root)
            .args([
                "-c",
                "user.name=Oz Box memory",
                "-c",
                "user.email=memory@ozbox.invalid",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.autocrlf=false",
            ])
            .args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .map_err(|e| {
                MemError::Io(format!(
                    "git is needed for memory and could not be run: {e}"
                ))
            })?;
        if !out.status.success() {
            return Err(MemError::Io(format!(
                "git {} failed: {}",
                args.first().copied().unwrap_or(""),
                String::from_utf8_lossy(&out.stderr)
                    .lines()
                    .next()
                    .unwrap_or("")
            )));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    /// Commit everything under the repository. Nothing to commit is not an error.
    fn commit(&self, msg: &str) -> Result<(), MemError> {
        self.git(&["add", "-A"])?;
        if self.git(&["status", "--porcelain"])?.is_empty() {
            return Ok(());
        }
        self.git(&["commit", "-q", "-m", msg])?;
        Ok(())
    }

    fn head(&self) -> String {
        self.git(&["rev-parse", "HEAD"]).unwrap_or_default()
    }

    fn db(&self) -> Result<Connection, MemError> {
        fs::create_dir_all(self.root.join(".index")).map_err(io)?;
        let c = Connection::open(self.root.join(".index").join("memory.db")).map_err(io)?;
        c.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(io)?;
        c.execute_batch(
            "CREATE TABLE IF NOT EXISTS entries(id TEXT PRIMARY KEY, scope TEXT NOT NULL, state TEXT NOT NULL,
                 expires_ms INTEGER, updated_ms INTEGER NOT NULL);
             CREATE VIRTUAL TABLE IF NOT EXISTS fts USING fts5(id UNINDEXED, title, body, tags,
                 tokenize='unicode61 remove_diacritics 2');
             CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);",
        )
        .map_err(io)?;
        Ok(c)
    }

    /// Make the index agree with the files: commit edits made outside Oz Box, and rebuild when the head moved.
    fn sync_locked(&self) -> Result<(), MemError> {
        if !self.git(&["status", "--porcelain"])?.is_empty() {
            self.commit("memory: edits made outside Oz Box")?;
        }
        let head = self.head();
        let db = self.db()?;
        let known: Option<String> = db
            .query_row("SELECT v FROM meta WHERE k='head'", [], |r| r.get(0))
            .ok();
        if known.as_deref() != Some(head.as_str()) {
            self.reindex_with(&db, &head)?;
        }
        Ok(())
    }

    fn all_files(&self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let base = self.root.join("entries");
        let Ok(kinds) = fs::read_dir(&base) else {
            return out;
        };
        for k in kinds.flatten() {
            let Ok(names) = fs::read_dir(k.path()) else {
                continue;
            };
            for n in names.flatten() {
                let Ok(files) = fs::read_dir(n.path()) else {
                    continue;
                };
                for f in files.flatten() {
                    let p = f.path();
                    if p.extension().is_some_and(|e| e == "md") {
                        out.push(p);
                    }
                }
            }
        }
        out
    }

    fn reindex_with(&self, db: &Connection, head: &str) -> Result<(), MemError> {
        db.execute_batch("DELETE FROM entries; DELETE FROM fts;")
            .map_err(io)?;
        for p in self.all_files() {
            let Ok(text) = fs::read_to_string(&p) else {
                continue;
            };
            // A file that does not parse is left alone and left out of the index.
            if let Ok(e) = parse_file(&text, 0) {
                if id_ok(&e.id) && Scope::parse(&e.scope).is_ok() {
                    Self::index_put(db, &e)?;
                }
            }
        }
        db.execute(
            "INSERT OR REPLACE INTO meta(k,v) VALUES('head',?1)",
            params![head],
        )
        .map_err(io)?;
        Ok(())
    }

    /// Rebuild the index from the files (it is disposable).
    pub fn reindex(&self) -> Result<usize, MemError> {
        let _l = self.lock()?;
        let db = self.db()?;
        self.reindex_with(&db, &self.head())?;
        Ok(db
            .query_row("SELECT count(*) FROM entries", [], |r| r.get::<_, i64>(0))
            .map_err(io)? as usize)
    }

    fn index_put(db: &Connection, e: &Entry) -> Result<(), MemError> {
        db.execute(
            "INSERT OR REPLACE INTO entries(id,scope,state,expires_ms,updated_ms) VALUES(?1,?2,?3,?4,?5)",
            params![
                e.id,
                e.scope,
                match e.state {
                    State::Pending => "pending",
                    State::Approved => "approved",
                },
                e.expires_ms.map(|x| x as i64),
                e.updated_ms as i64
            ],
        )
        .map_err(io)?;
        db.execute("DELETE FROM fts WHERE id=?1", params![e.id])
            .map_err(io)?;
        db.execute(
            "INSERT INTO fts(id,title,body,tags) VALUES(?1,?2,?3,?4)",
            params![e.id, e.title, e.body, e.tags.join(" ")],
        )
        .map_err(io)?;
        Ok(())
    }

    /// After a change has been committed, move the index and its recorded head forward together.
    fn after_change(&self, upsert: Option<&Entry>, remove: Option<&str>) {
        let head = self.head();
        let done = (|| -> Result<(), MemError> {
            let db = self.db()?;
            if let Some(id) = remove {
                db.execute("DELETE FROM entries WHERE id=?1", params![id])
                    .map_err(io)?;
                db.execute("DELETE FROM fts WHERE id=?1", params![id])
                    .map_err(io)?;
            }
            if let Some(e) = upsert {
                Self::index_put(&db, e)?;
            }
            db.execute(
                "INSERT OR REPLACE INTO meta(k,v) VALUES('head',?1)",
                params![head],
            )
            .map_err(io)?;
            Ok(())
        })();
        if done.is_err() {
            // Leave the recorded head behind so the next open rebuilds from the files.
            if let Ok(db) = self.db() {
                let _ = db.execute("DELETE FROM meta WHERE k='head'", []);
            }
        }
    }

    fn path_of(&self, scope: &Scope, id: &str) -> PathBuf {
        scope.dir(&self.root).join(format!("{id}.md"))
    }

    fn load(&self, id: &str, now: u64) -> Result<Entry, MemError> {
        if !id_ok(id) {
            return Err(MemError::NotFound);
        }
        let db = self.db()?;
        let scope: String = db
            .query_row("SELECT scope FROM entries WHERE id=?1", params![id], |r| {
                r.get(0)
            })
            .map_err(|_| MemError::NotFound)?;
        let scope = Scope::parse(&scope)?;
        let text = fs::read_to_string(self.path_of(&scope, id)).map_err(|_| MemError::NotFound)?;
        let e = parse_file(&text, now)?;
        // The file is the truth: a note whose front matter names another scope or id is not served.
        if e.id != id || e.scope != scope.to_string() {
            return Err(MemError::NotFound);
        }
        Ok(e)
    }

    fn check_text(title: &str, body: &str, tags: &[String]) -> Result<(), MemError> {
        let title = title.trim();
        if title.is_empty() || title.chars().count() > MAX_TITLE {
            return Err(MemError::Invalid(format!(
                "give the note a title of 1 to {MAX_TITLE} characters"
            )));
        }
        if title.contains('\n') {
            return Err(MemError::Invalid("a title is one line".into()));
        }
        if body.trim().is_empty() {
            return Err(MemError::Invalid("a note needs some text".into()));
        }
        if body.len() > MAX_BODY {
            return Err(MemError::Limit(format!(
                "a note is at most {} KB; split it",
                MAX_BODY / 1024
            )));
        }
        if tags.len() > MAX_TAGS || tags.iter().any(|t| !name_ok(t)) {
            return Err(MemError::Invalid(format!(
                "tags are up to {MAX_TAGS} words of letters, digits, dot, dash and underscore"
            )));
        }
        for text in [title, body] {
            if let Some(kind) = find_secret(text) {
                return Err(MemError::Secret(kind));
            }
        }
        Ok(())
    }

    fn check_expiry(expires: Option<u64>, now: u64) -> Result<(), MemError> {
        match expires {
            Some(x) if x <= now => Err(MemError::Invalid("the expiry is already past".into())),
            Some(x) if x > now + ORIGIN_DAYS_MAX * 86_400_000 => {
                Err(MemError::Invalid("the expiry is too far away".into()))
            }
            _ => Ok(()),
        }
    }

    fn scope_counts(&self, scope: &Scope) -> Result<(usize, usize), MemError> {
        let db = self.db()?;
        let n = |state: Option<&str>| -> Result<usize, MemError> {
            let c: i64 = match state {
                Some(s) => db.query_row(
                    "SELECT count(*) FROM entries WHERE scope=?1 AND state=?2",
                    params![scope.to_string(), s],
                    |r| r.get(0),
                ),
                None => db.query_row(
                    "SELECT count(*) FROM entries WHERE scope=?1",
                    params![scope.to_string()],
                    |r| r.get(0),
                ),
            }
            .map_err(io)?;
            Ok(c as usize)
        };
        Ok((n(None)?, n(Some("pending"))?))
    }

    /// Add a note. A person's is approved at once; an agent's is a pending proposal.
    pub fn write(
        &self,
        caller: &Caller,
        scope: &Scope,
        input: NewEntry,
        now: u64,
    ) -> Result<Entry, MemError> {
        if !caller.can_read(scope) {
            return Err(MemError::Denied(
                "that memory is not yours to write to".into(),
            ));
        }
        Self::check_text(&input.title, &input.body, &input.tags)?;
        Self::check_expiry(input.expires_ms, now)?;
        let _l = self.lock()?;
        self.sync_locked()?;
        let (total, pending) = self.scope_counts(scope)?;
        if total >= MAX_PER_SCOPE {
            return Err(MemError::Limit(format!(
                "{scope} holds {MAX_PER_SCOPE} notes already; forget some first"
            )));
        }
        if !caller.is_person() && pending >= MAX_PENDING_PER_SCOPE {
            return Err(MemError::Limit(format!(
                "{scope} has {MAX_PENDING_PER_SCOPE} proposals waiting for review; a person must review them first"
            )));
        }
        let (kind, run, session, box_name) = match caller {
            Caller::Person(_) => (ActorKind::Person, None, None, None),
            Caller::Agent(a) => (
                ActorKind::Agent,
                a.run.clone(),
                a.terminal.clone(),
                a.origin_box(),
            ),
        };
        let person = caller.is_person();
        let e = Entry {
            id: random_id(),
            scope: scope.to_string(),
            title: input.title.trim().to_string(),
            body: input.body.trim().to_string(),
            tags: input.tags,
            state: if person {
                State::Approved
            } else {
                State::Pending
            },
            created_ms: now,
            updated_ms: now,
            expires_ms: input.expires_ms,
            revision: 1,
            provenance: Provenance {
                actor: caller.actor(),
                kind,
                run,
                session,
                box_name,
                reviewed_by: person.then(|| caller.actor()),
                reviewed_ms: person.then_some(now),
            },
            expired: false,
        };
        write_atomic(&self.path_of(scope, &e.id), render(&e)?.as_bytes()).map_err(io)?;
        self.commit(&format!(
            "memory: {} {} ({}) by {}",
            if person { "add" } else { "propose" },
            e.id,
            scope,
            commit_safe(&caller.actor())
        ))?;
        self.after_change(Some(&e), None);
        Ok(e)
    }

    /// Change a note. A person only; the note stays approved and its revision rises.
    pub fn update(
        &self,
        caller: &Caller,
        id: &str,
        patch: Patch,
        now: u64,
    ) -> Result<Entry, MemError> {
        if !caller.is_person() {
            return Err(MemError::Denied(
                "an agent cannot change a note; propose a new one and a person will review it"
                    .into(),
            ));
        }
        let _l = self.lock()?;
        self.sync_locked()?;
        let mut e = self.load(id, now)?;
        let scope = Scope::parse(&e.scope)?;
        if !caller.can_read(&scope) {
            return Err(MemError::NotFound);
        }
        if let Some(t) = patch.title {
            e.title = t.trim().to_string();
        }
        if let Some(b) = patch.body {
            e.body = b.trim().to_string();
        }
        if let Some(t) = patch.tags {
            e.tags = t;
        }
        if let Some(x) = patch.expires_ms {
            Self::check_expiry(x, now)?;
            e.expires_ms = x;
        }
        Self::check_text(&e.title, &e.body, &e.tags)?;
        e.updated_ms = now;
        e.revision += 1;
        e.state = State::Approved;
        e.expired = false;
        e.provenance.reviewed_by = Some(caller.actor());
        e.provenance.reviewed_ms = Some(now);
        write_atomic(&self.path_of(&scope, &e.id), render(&e)?.as_bytes()).map_err(io)?;
        self.commit(&format!(
            "memory: edit {} ({}) by {}",
            e.id,
            scope,
            commit_safe(&caller.actor())
        ))?;
        self.after_change(Some(&e), None);
        Ok(e)
    }

    /// Approve a pending proposal. A person only, and never the text the agent wrote changed on the way.
    pub fn approve(&self, caller: &Caller, id: &str, now: u64) -> Result<Entry, MemError> {
        if !caller.is_person() {
            return Err(MemError::Denied("only a person approves memory".into()));
        }
        let _l = self.lock()?;
        self.sync_locked()?;
        let mut e = self.load(id, now)?;
        let scope = Scope::parse(&e.scope)?;
        if !caller.can_read(&scope) {
            return Err(MemError::NotFound);
        }
        if e.state == State::Approved {
            return Ok(e);
        }
        e.state = State::Approved;
        e.provenance.reviewed_by = Some(caller.actor());
        e.provenance.reviewed_ms = Some(now);
        write_atomic(&self.path_of(&scope, &e.id), render(&e)?.as_bytes()).map_err(io)?;
        self.commit(&format!(
            "memory: approve {} ({}) by {}",
            e.id,
            scope,
            commit_safe(&caller.actor())
        ))?;
        self.after_change(Some(&e), None);
        Ok(e)
    }

    /// Forget a note, or reject a proposal. A person only. The file leaves the tree; git history keeps it.
    pub fn forget(&self, caller: &Caller, id: &str, now: u64) -> Result<(), MemError> {
        if !caller.is_person() {
            return Err(MemError::Denied("only a person forgets memory".into()));
        }
        let _l = self.lock()?;
        self.sync_locked()?;
        let e = self.load(id, now)?;
        let scope = Scope::parse(&e.scope)?;
        if !caller.can_read(&scope) {
            return Err(MemError::NotFound);
        }
        fs::remove_file(self.path_of(&scope, id)).map_err(io)?;
        self.commit(&format!(
            "memory: {} {} ({}) by {}",
            if e.state == State::Pending {
                "reject"
            } else {
                "forget"
            },
            id,
            scope,
            commit_safe(&caller.actor())
        ))?;
        self.after_change(None, Some(id));
        Ok(())
    }

    fn visible(&self, caller: &Caller, e: &Entry) -> bool {
        let Ok(scope) = Scope::parse(&e.scope) else {
            return false;
        };
        if !caller.can_read(&scope) {
            return false;
        }
        match caller {
            Caller::Person(_) => true,
            // An agent never sees a proposal or a note past its expiry.
            Caller::Agent(_) => e.state == State::Approved && !e.expired,
        }
    }

    pub fn get(&self, caller: &Caller, id: &str, now: u64) -> Result<Entry, MemError> {
        {
            let _l = self.lock()?;
            self.sync_locked()?;
        }
        let e = self.load(id, now)?;
        // The same answer for absent and not yours.
        if self.visible(caller, &e) {
            Ok(e)
        } else {
            Err(MemError::NotFound)
        }
    }

    pub fn list(&self, caller: &Caller, f: &Filter, now: u64) -> Result<Vec<Entry>, MemError> {
        {
            let _l = self.lock()?;
            self.sync_locked()?;
        }
        let db = self.db()?;
        let mut st = db
            .prepare("SELECT id FROM entries ORDER BY updated_ms DESC")
            .map_err(io)?;
        let ids: Vec<String> = st
            .query_map([], |r| r.get(0))
            .map_err(io)?
            .filter_map(Result::ok)
            .collect();
        self.collect(caller, &ids, f, now, usize::MAX)
    }

    fn collect(
        &self,
        caller: &Caller,
        ids: &[String],
        f: &Filter,
        now: u64,
        limit: usize,
    ) -> Result<Vec<Entry>, MemError> {
        let mut out = Vec::new();
        for id in ids {
            let Ok(e) = self.load(id, now) else { continue };
            if !self.visible(caller, &e) {
                continue;
            }
            if f.scope.as_ref().is_some_and(|s| s.to_string() != e.scope) {
                continue;
            }
            if f.state.is_some_and(|s| s != e.state) {
                continue;
            }
            if e.expired && !f.include_expired {
                continue;
            }
            out.push(e);
            if out.len() >= limit {
                break;
            }
        }
        Ok(out)
    }

    /// Full-text search, best match first, over the notes the caller may see.
    pub fn search(
        &self,
        caller: &Caller,
        query: &str,
        f: &Filter,
        limit: usize,
        now: u64,
    ) -> Result<Vec<Entry>, MemError> {
        let Some(q) = fts_query(query) else {
            let mut all = self.list(caller, f, now)?;
            all.truncate(limit);
            return Ok(all);
        };
        {
            let _l = self.lock()?;
            self.sync_locked()?;
        }
        let db = self.db()?;
        let mut st = db
            .prepare("SELECT id FROM fts WHERE fts MATCH ?1 ORDER BY rank LIMIT 200")
            .map_err(io)?;
        let ids: Vec<String> = st
            .query_map(params![q], |r| r.get(0))
            .map_err(io)?
            .filter_map(Result::ok)
            .collect();
        self.collect(caller, &ids, f, now, limit.clamp(1, 100))
    }

    /// Remove notes whose expiry has passed. Returns how many.
    pub fn sweep(&self, now: u64) -> Result<usize, MemError> {
        let _l = self.lock()?;
        self.sync_locked()?;
        let db = self.db()?;
        let mut st = db
            .prepare(
                "SELECT id, scope FROM entries WHERE expires_ms IS NOT NULL AND expires_ms <= ?1",
            )
            .map_err(io)?;
        let due: Vec<(String, String)> = st
            .query_map(params![now as i64], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(io)?
            .filter_map(Result::ok)
            .collect();
        drop(st);
        for (id, scope) in &due {
            if let Ok(s) = Scope::parse(scope) {
                let _ = fs::remove_file(self.path_of(&s, id));
            }
        }
        if !due.is_empty() {
            self.commit(&format!("memory: {} note(s) expired", due.len()))?;
            let head = self.head();
            for (id, _) in &due {
                let _ = db.execute("DELETE FROM entries WHERE id=?1", params![id]);
                let _ = db.execute("DELETE FROM fts WHERE id=?1", params![id]);
            }
            let _ = db.execute(
                "INSERT OR REPLACE INTO meta(k,v) VALUES('head',?1)",
                params![head],
            );
        }
        Ok(due.len())
    }

    pub fn stats(&self, caller: &Caller, now: u64) -> Result<Stats, MemError> {
        let all = self.list(
            caller,
            &Filter {
                include_expired: true,
                ..Filter::default()
            },
            now,
        )?;
        Ok(Stats {
            total: all.len(),
            pending: all.iter().filter(|e| e.state == State::Pending).count(),
            approved: all.iter().filter(|e| e.state == State::Approved).count(),
            expired: all.iter().filter(|e| e.expired).count(),
        })
    }
}

/// A commit message carries names and ids only, never note text.
fn commit_safe(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':' | '@'))
        .take(64)
        .collect()
}

/// Turn what a person typed into an FTS5 query that cannot be anything but words: each term quoted and a prefix.
fn fts_query(q: &str) -> Option<String> {
    let terms: Vec<String> = q
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .take(8)
        .map(|t| t.chars().take(40).collect::<String>())
        .collect();
    if terms.is_empty() {
        return None;
    }
    Some(
        terms
            .iter()
            .map(|t| format!("\"{t}\"*"))
            .collect::<Vec<_>>()
            .join(" "),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn person() -> Caller {
        Caller::Person("alice".into())
    }

    fn agent() -> Caller {
        Caller::Agent(AgentCtx {
            person: "alice".into(),
            run: Some("run-1".into()),
            terminal: None,
            projects: vec!["acme".into()],
            box_name: Some("main".into()),
            origin: None,
        })
    }

    fn ne(title: &str, body: &str) -> NewEntry {
        NewEntry {
            title: title.into(),
            body: body.into(),
            ..NewEntry::default()
        }
    }

    fn open() -> (tempfile::TempDir, Memory) {
        let d = tempfile::tempdir().unwrap();
        let m = Memory::open(d.path().join("memory")).unwrap();
        (d, m)
    }

    #[test]
    fn a_note_is_a_markdown_file_in_git_and_is_found_by_search() {
        let (_d, m) = open();
        let s = Scope::parse("project:acme").unwrap();
        let e = m
            .write(
                &person(),
                &s,
                ne(
                    "Deploy order",
                    "Run the database release before the app release.",
                ),
                1_000,
            )
            .unwrap();
        assert_eq!(e.state, State::Approved);
        let file = fs::read_to_string(m.path_of(&s, &e.id)).unwrap();
        assert!(file.starts_with("+++\n") && file.contains("database release"));
        let log = m.git(&["log", "--format=%s"]).unwrap();
        assert!(log.contains(&format!("memory: add {} (project:acme) by alice", e.id)));
        assert!(
            !log.contains("database release"),
            "the text never goes in a commit message"
        );
        let hits = m
            .search(&person(), "databas rel", &Filter::default(), 10, 2_000)
            .unwrap();
        assert_eq!(hits.len(), 1, "a prefix matches");
        assert!(m
            .search(&person(), "unrelated", &Filter::default(), 10, 2_000)
            .unwrap()
            .is_empty());
        // FTS syntax typed by a person is only words.
        assert!(m
            .search(
                &person(),
                "\"; DROP TABLE x -- OR NEAR(",
                &Filter::default(),
                10,
                2_000
            )
            .is_ok());
    }

    #[test]
    fn an_agent_only_proposes_and_nothing_unreviewed_is_readable_by_any_agent() {
        let (_d, m) = open();
        let s = Scope::parse("project:acme").unwrap();
        let p = m
            .write(
                &agent(),
                &s,
                ne("Prefers tabs", "The team uses tabs."),
                1_000,
            )
            .unwrap();
        assert_eq!(p.state, State::Pending);
        assert_eq!(p.provenance.run.as_deref(), Some("run-1"));
        assert_eq!(
            m.get(&agent(), &p.id, 2_000),
            Err(MemError::NotFound),
            "not even its own proposal"
        );
        assert!(m
            .search(&agent(), "tabs", &Filter::default(), 10, 2_000)
            .unwrap()
            .is_empty());
        assert_eq!(
            m.search(&person(), "tabs", &Filter::default(), 10, 2_000)
                .unwrap()
                .len(),
            1
        );
        assert!(matches!(
            m.approve(&agent(), &p.id, 3_000),
            Err(MemError::Denied(_))
        ));
        assert!(matches!(
            m.forget(&agent(), &p.id, 3_000),
            Err(MemError::Denied(_))
        ));
        let a = m.approve(&person(), &p.id, 3_000).unwrap();
        assert_eq!(a.provenance.reviewed_by.as_deref(), Some("alice"));
        assert!(m.get(&agent(), &p.id, 4_000).is_ok());
        assert!(matches!(
            m.update(&agent(), &p.id, Patch::default(), 5_000),
            Err(MemError::Denied(_))
        ));
    }

    #[test]
    fn scopes_are_walls_for_agents_and_people_alike() {
        let (_d, m) = open();
        let other_project = Scope::parse("project:other").unwrap();
        let other_person = Scope::parse("person:bob").unwrap();
        let mine = Scope::parse("person:alice").unwrap();
        let e = m
            .write(
                &person(),
                &other_project,
                ne("Other", "Other project note."),
                1,
            )
            .unwrap();
        assert!(matches!(
            m.write(&agent(), &other_project, ne("x", "y"), 1),
            Err(MemError::Denied(_))
        ));
        assert_eq!(m.get(&agent(), &e.id, 2), Err(MemError::NotFound));
        assert!(matches!(
            m.write(&person(), &other_person, ne("x", "y"), 1),
            Err(MemError::Denied(_))
        ));
        let own = m
            .write(&person(), &mine, ne("Style", "Short answers."), 1)
            .unwrap();
        assert!(
            m.get(&agent(), &own.id, 2).is_ok(),
            "an agent reads its person's notes"
        );
        let carol = Caller::Person("carol".into());
        assert_eq!(
            m.get(&carol, &own.id, 2),
            Err(MemError::NotFound),
            "another person's scope"
        );
    }

    #[test]
    fn secrets_are_refused_and_the_error_never_repeats_them() {
        let (_d, m) = open();
        let s = Scope::parse("box:main").unwrap();
        let err = m
            .write(
                &person(),
                &s,
                ne("Key", concat!("use s", "k-abcdefghijklmnopqrstuvwxyz0123")),
                1,
            )
            .unwrap_err();
        assert!(matches!(err, MemError::Secret(_)));
        assert!(!err.to_string().contains("sk-abc"));
        assert!(m.list(&person(), &Filter::default(), 2).unwrap().is_empty());
        assert!(m
            .write(&person(), &s, ne("T", "the password = {{secret:DB}}"), 1)
            .is_ok());
    }

    #[test]
    fn expiry_hides_from_agents_then_sweeps_and_history_keeps_the_note() {
        let (_d, m) = open();
        let s = Scope::parse("project:acme").unwrap();
        let e = m
            .write(
                &person(),
                &s,
                NewEntry {
                    expires_ms: Some(10_000),
                    ..ne("Freeze", "Code freeze until the audit ends.")
                },
                1_000,
            )
            .unwrap();
        assert!(m.get(&agent(), &e.id, 9_000).is_ok());
        assert_eq!(m.get(&agent(), &e.id, 10_000), Err(MemError::NotFound));
        let shown = m.get(&person(), &e.id, 10_000).unwrap();
        assert!(shown.expired, "a person still sees it, marked");
        assert_eq!(m.sweep(10_000).unwrap(), 1);
        assert_eq!(m.get(&person(), &e.id, 10_001), Err(MemError::NotFound));
        assert!(m.git(&["log", "--format=%s"]).unwrap().contains("expired"));
    }

    #[test]
    fn editing_with_plain_git_is_picked_up_and_the_index_is_disposable() {
        let (d, m) = open();
        let s = Scope::parse("box:main").unwrap();
        let e = m
            .write(
                &person(),
                &s,
                ne("Ports", "The preview runs on port 3100."),
                1,
            )
            .unwrap();
        // someone edits the file by hand
        let p = m.path_of(&s, &e.id);
        let text = fs::read_to_string(&p).unwrap().replace("3100", "3200");
        fs::write(&p, text).unwrap();
        let m2 = Memory::open(d.path().join("memory")).unwrap();
        let hits = m2
            .search(&person(), "3200", &Filter::default(), 5, 5)
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert!(m2
            .git(&["log", "--format=%s"])
            .unwrap()
            .contains("edits made outside Oz Box"));
        // lose the index entirely: nothing is lost
        fs::remove_dir_all(m2.root().join(".index")).unwrap();
        let m3 = Memory::open(d.path().join("memory")).unwrap();
        assert_eq!(m3.list(&person(), &Filter::default(), 5).unwrap().len(), 1);
        assert_eq!(m3.reindex().unwrap(), 1);
    }

    #[test]
    fn limits_and_names_are_enforced() {
        let (_d, m) = open();
        let s = Scope::parse("project:acme").unwrap();
        assert!(Scope::parse("project:../x").is_err());
        assert!(Scope::parse("team:x").is_err());
        assert!(matches!(
            m.write(&person(), &s, ne("", "x"), 1),
            Err(MemError::Invalid(_))
        ));
        assert!(matches!(
            m.write(&person(), &s, ne("t", &"x ".repeat(MAX_BODY)), 1),
            Err(MemError::Limit(_))
        ));
        for i in 0..MAX_PENDING_PER_SCOPE {
            m.write(&agent(), &s, ne(&format!("p{i}"), "proposal"), 1)
                .unwrap();
        }
        assert!(matches!(
            m.write(&agent(), &s, ne("more", "x"), 1),
            Err(MemError::Limit(_))
        ));
        assert!(m
            .write(&person(), &s, ne("fine", "a person can still write"), 1)
            .is_ok());
        assert_eq!(
            m.get(&person(), "../../etc/pwd", 1),
            Err(MemError::NotFound)
        );
    }

    #[test]
    fn two_processes_writing_at_once_lose_nothing() {
        let (d, m) = open();
        let root = d.path().join("memory");
        drop(m);
        let hands: Vec<_> = (0..3)
            .map(|n| {
                let r = root.clone();
                std::thread::spawn(move || {
                    let m = Memory::open(r).unwrap();
                    let s = Scope::parse("project:acme").unwrap();
                    for i in 0..4 {
                        m.write(
                            &Caller::Person("alice".into()),
                            &s,
                            ne(&format!("n{n}-{i}"), "text"),
                            1,
                        )
                        .unwrap();
                    }
                })
            })
            .collect();
        for h in hands {
            h.join().unwrap();
        }
        let m = Memory::open(root).unwrap();
        assert_eq!(m.list(&person(), &Filter::default(), 2).unwrap().len(), 12);
    }
}
