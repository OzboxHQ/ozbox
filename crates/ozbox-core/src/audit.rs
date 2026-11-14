//! The audit chain: an append-only, hash-chained record of what was decided and done.
//!
//! One file of JSON lines, only ever appended to. Every entry carries the hash of the entry before it, so changing,
//! removing or reordering any line breaks the chain from that point on, and [`verify`] names where. Every so often a
//! **checkpoint** line is added: the sequence number and head hash of the chain so far, with an HMAC tag under a seal key.
//! A checkpoint is copied to an **anchor** file as well, so cutting the tail off the chain (which also removes the
//! checkpoints written after the cut) still shows against the anchor.
//!
//! What this does and does not give. The chain *detects* any edit, deletion, insertion or reordering that does not
//! recompute every later hash; the seal tag stops someone who can write the file from recomputing the hashes without the
//! key. Where the key and the file live decides who that someone can be: with the box user running both the supervisor and
//! the agents (ADR 0018, ADR 0022), an agent that is the same operating-system user can read the key too, so on a box today
//! the chain is tamper-*evident* against anything short of a deliberate, key-reading rewrite, and the head hash shown in
//! the dashboard can be copied off the box to pin it. Moving the writer to a user of its own closes that.
//!
//! An entry holds ids and action words only: never a secret value, a prompt, a command line or file contents.

use std::io::{self, BufRead, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use ring::digest::{digest, SHA256};
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

/// The `prev` of the first entry.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
/// A checkpoint is written after this many entries ...
pub const CHECKPOINT_EVERY: u64 = 50;
/// ... or when the last one is older than this (milliseconds), at the next entry.
pub const CHECKPOINT_AGE_MS: u64 = 10 * 60 * 1000;
const MAX_ACTOR: usize = 80;
const MAX_ACTION: usize = 80;
const MAX_SUBJECT: usize = 120;
const MAX_DETAIL: usize = 160;

/// One audited event, as handed to [`AuditLog::append`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewEvent {
    pub ts_ms: u64,
    /// A person, `supervisor`, `engine:<id>`, `chat:<id>`, `schedule:<id>` ...
    pub actor: String,
    /// A dotted action word: `permission.deny`, `grant.created`, `run.queued`, `box.destroy` ...
    pub action: String,
    /// The id the action is about (task, approval, grant, box, secret name).
    pub subject: Option<String>,
    /// A few words. Never a value, a prompt or a command line.
    pub detail: String,
    /// Where it came from in another record that counts up (the task store's audit list): the store's epoch and the
    /// record's number, so a retry after a crash cannot repeat it.
    pub src: Option<(String, u64)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub seq: u64,
    pub ts_ms: u64,
    pub actor: String,
    pub action: String,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub detail: String,
    /// `epoch:number` of the record this came from, if it came from one.
    #[serde(default)]
    pub src: Option<String>,
    pub prev: String,
    pub hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// The last entry it covers.
    pub seq: u64,
    pub head: String,
    pub ts_ms: u64,
    /// HMAC-SHA256 of `seq` and `head` under the seal key, in hex.
    pub tag: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "k")]
enum Line {
    #[serde(rename = "e")]
    Entry(AuditEntry),
    #[serde(rename = "c")]
    Checkpoint(Checkpoint),
}

pub fn hex(bytes: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(D[(b >> 4) as usize] as char);
        s.push(D[(b & 15) as usize] as char);
    }
    s
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok())
        .collect()
}

/// The hash of an entry's content and the hash before it.
pub fn entry_hash(e: &AuditEntry) -> String {
    let canonical =
        serde_json::json!([e.seq, e.ts_ms, e.actor, e.action, e.subject, e.detail, e.src, e.prev]);
    hex(digest(&SHA256, canonical.to_string().as_bytes()).as_ref())
}

fn parse_src(s: &str) -> Option<(String, u64)> {
    let (ep, n) = s.rsplit_once(':')?;
    Some((ep.to_string(), n.parse().ok()?))
}

fn clean(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max).collect()
}

fn seal_message(seq: u64, head: &str) -> String {
    format!("ozbox-audit-checkpoint\n{seq}\n{head}")
}

/// Where the seal key comes from: a file the writer owns (a laptop, tests), or bytes the writer was given (the box's
/// audit service, which keeps the key in the secret store and never in a file).
#[derive(Clone)]
enum KeySource {
    File(PathBuf),
    Bytes(std::sync::Arc<Vec<u8>>),
}

impl std::fmt::Debug for KeySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeySource::File(p) => write!(f, "File({p:?})"),
            KeySource::Bytes(_) => write!(f, "Bytes(..)"),
        }
    }
}

/// Where the chain lives and how it is sealed. On a box the writer is the audit service (see [`crate::audit_remote`]):
/// then this holds no key and writes no file, and appending, sealing and checking go over its socket.
#[derive(Debug, Clone)]
pub struct AuditLog {
    path: PathBuf,
    anchor: PathBuf,
    key: KeySource,
    remote: Option<std::sync::Arc<crate::audit_remote::Remote>>,
    /// The chain file is readable by every user of the machine (the service that writes it is the only one that can
    /// change it). The anchor and the lock stay private.
    public: bool,
}

/// Where the chain is, as far as appending needs to know.
#[derive(Debug, Default, Clone)]
struct Tail {
    seq: u64,
    hash: Option<String>,
    last_src: Option<(String, u64)>,
    last_checkpoint_seq: u64,
    last_checkpoint_ms: u64,
}

impl AuditLog {
    /// The chain beside a task store: `tasks.json` -> `tasks.audit.jsonl` (+ `.anchor`, `.key`).
    pub fn beside(store: &Path) -> Self {
        let stem = store
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "tasks".into());
        let dir = store.parent().unwrap_or_else(|| Path::new("."));
        let local = Self {
            path: dir.join(format!("{stem}.audit.jsonl")),
            anchor: dir.join(format!("{stem}.audit.anchor")),
            key: KeySource::File(dir.join(format!("{stem}.audit.key"))),
            remote: None,
            public: false,
        };
        match crate::audit_remote::Remote::discover(&stem, &local.path) {
            Some(r) => Self {
                path: r.chain_path(),
                remote: Some(std::sync::Arc::new(r)),
                ..local
            },
            None => local,
        }
    }

    /// A chain written through this service client.
    pub fn through(remote: crate::audit_remote::Remote) -> Self {
        let path = remote.chain_path();
        Self {
            anchor: path.with_extension("anchor"),
            key: KeySource::File(path.with_extension("key")),
            path,
            remote: Some(std::sync::Arc::new(remote)),
            public: false,
        }
    }

    /// A chain at these exact paths, written here and never through a service: what the audit service itself uses.
    pub fn at(path: impl Into<PathBuf>, anchor: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let key = path.with_extension("key");
        Self {
            path,
            anchor: anchor.into(),
            key: KeySource::File(key),
            remote: None,
            public: false,
        }
    }

    /// Make the chain file readable by everyone on the machine. Only the service that owns it can write it.
    #[must_use]
    pub fn world_readable(mut self) -> Self {
        self.public = true;
        self
    }

    /// Seal with these key bytes instead of a key file.
    #[must_use]
    pub fn with_key_bytes(mut self, key: Vec<u8>) -> Self {
        self.key = KeySource::Bytes(std::sync::Arc::new(key));
        self
    }

    /// Whether this chain is written by a service rather than by this process.
    pub fn is_remote(&self) -> bool {
        self.remote.is_some()
    }

    /// Put the anchor (a second copy of every checkpoint) somewhere else, ideally a place the writer's user owns.
    #[must_use]
    pub fn with_anchor(mut self, anchor: impl Into<PathBuf>) -> Self {
        self.anchor = anchor.into();
        self
    }

    /// Use a seal key stored elsewhere.
    #[must_use]
    pub fn with_key_file(mut self, key: impl Into<PathBuf>) -> Self {
        self.key = KeySource::File(key.into());
        self
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The seal key's file, when the key is kept in one.
    #[cfg(test)]
    fn key_path(&self) -> Option<PathBuf> {
        match &self.key {
            KeySource::File(p) => Some(p.clone()),
            KeySource::Bytes(_) => None,
        }
    }

    /// The anchor file (the second copy of every checkpoint).
    pub fn anchor_path(&self) -> &Path {
        &self.anchor
    }

    fn file_mode(&self) -> u32 {
        if self.public {
            0o644
        } else {
            0o600
        }
    }

    /// Whether the chain file exists and holds anything.
    pub fn has_entries(&self) -> bool {
        std::fs::metadata(&self.path).is_ok_and(|m| m.len() > 0)
    }

    /// Take in a chain written as files by an earlier version of the box (the box user's own writer): its lines are copied
    /// as they are, so every hash and every seal still stands, and the chain goes on from its last entry. Refused when this
    /// chain already holds entries (nothing here is ever merged or rewritten).
    pub fn adopt(&self, old: &LegacyChain) -> io::Result<()> {
        let _lock = self.lock()?;
        if self.has_entries() {
            return Err(io::Error::other("this audit chain already holds entries"));
        }
        append_to(&self.path, &old.chain_text, self.file_mode())?;
        if !old.anchor_text.is_empty() {
            append_to(&self.anchor, &old.anchor_text, 0o600)?;
        }
        Ok(())
    }

    fn lock(&self) -> io::Result<Lock> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        // one advisory lock on an open descriptor: never judged by age, never removed (see `crate::filelock`)
        Lock::acquire(&self.path.with_extension("lock"), Duration::from_secs(5)).map_err(|e| {
            if e.kind() == io::ErrorKind::TimedOut {
                io::Error::new(io::ErrorKind::TimedOut, "the audit log is busy")
            } else {
                e
            }
        })
    }

    /// The seal key, made on first use. Readable only by its owner.
    fn seal_key(&self, create: bool) -> io::Result<Option<hmac::Key>> {
        let key_path = match &self.key {
            KeySource::Bytes(b) if b.len() >= 32 => {
                return Ok(Some(hmac::Key::new(hmac::HMAC_SHA256, b)))
            }
            KeySource::Bytes(_) => return Err(io::Error::other("the audit seal key is damaged")),
            KeySource::File(p) => p,
        };
        match std::fs::read(key_path) {
            Ok(raw) if raw.len() >= 32 => return Ok(Some(hmac::Key::new(hmac::HMAC_SHA256, &raw))),
            Ok(_) => return Err(io::Error::other("the audit seal key is damaged")),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        if !create {
            return Ok(None);
        }
        let mut raw = [0u8; 32];
        SystemRandom::new()
            .fill(&mut raw)
            .map_err(|_| io::Error::other("no random numbers are available"))?;
        write_private(key_path, &raw)?;
        Ok(Some(hmac::Key::new(hmac::HMAC_SHA256, &raw)))
    }

    fn tail(&self) -> io::Result<Tail> {
        let mut file = match std::fs::File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Tail::default()),
            Err(e) => return Err(e),
        };
        let len = file.metadata()?.len();
        let take = len.min(256 * 1024);
        file.seek(SeekFrom::Start(len - take))?;
        let mut raw = Vec::new();
        file.read_to_end(&mut raw)?;
        let buf = String::from_utf8_lossy(&raw);
        let mut tail = Tail::default();
        // The first line of a partial read may be cut; it is skipped by failing to parse.
        for line in buf.lines() {
            match serde_json::from_str::<Line>(line) {
                Ok(Line::Entry(e)) => {
                    tail.seq = e.seq;
                    tail.hash = Some(e.hash.clone());
                    if let Some(s) = e.src.as_deref().and_then(parse_src) {
                        tail.last_src = Some(s);
                    }
                }
                Ok(Line::Checkpoint(c)) => {
                    tail.last_checkpoint_seq = c.seq;
                    tail.last_checkpoint_ms = c.ts_ms;
                }
                Err(_) => {}
            }
        }
        if tail.seq == 0 && len > take {
            return Err(io::Error::other("the audit log's last entry is unreadable"));
        }
        Ok(tail)
    }

    /// The last source record already in the chain (what a task store has mirrored so far).
    pub fn last_src(&self) -> io::Result<Option<(String, u64)>> {
        if let Some(r) = &self.remote {
            return r.last_src();
        }
        let _l = self.lock()?;
        Ok(self.tail()?.last_src)
    }

    /// Add one event.
    pub fn append(&self, ev: NewEvent) -> io::Result<AuditEntry> {
        let mut v = self.append_many(vec![ev])?;
        v.pop()
            .ok_or_else(|| io::Error::other("nothing was written"))
    }

    /// Add events in order, as one locked write. Events whose `src` is already in the chain are skipped.
    pub fn append_many(&self, events: Vec<NewEvent>) -> io::Result<Vec<AuditEntry>> {
        if events.is_empty() {
            return Ok(Vec::new());
        }
        if let Some(r) = &self.remote {
            return r.append_many(events);
        }
        let _lock = self.lock()?;
        let mut tail = self.tail()?;
        let key = self.seal_key(true)?;
        let mut out = Vec::new();
        let mut text = String::new();
        let mut anchor_text = String::new();
        for ev in events {
            if let (Some((ep, n)), Some((lep, ln))) = (&ev.src, &tail.last_src) {
                if ep == lep && n <= ln {
                    continue;
                }
            }
            let mut e = AuditEntry {
                seq: tail.seq + 1,
                ts_ms: ev.ts_ms,
                actor: clean(&ev.actor, MAX_ACTOR),
                action: clean(&ev.action, MAX_ACTION),
                subject: ev.subject.as_deref().map(|s| clean(s, MAX_SUBJECT)),
                detail: clean(&crate::approvals::scrub_secrets(&ev.detail), MAX_DETAIL),
                src: ev.src.as_ref().map(|(ep, n)| format!("{ep}:{n}")),
                prev: tail.hash.clone().unwrap_or_else(|| GENESIS.to_string()),
                hash: String::new(),
            };
            e.hash = entry_hash(&e);
            tail.seq = e.seq;
            tail.hash = Some(e.hash.clone());
            if ev.src.is_some() {
                tail.last_src = ev.src.clone();
            }
            text.push_str(&line_of(&Line::Entry(e.clone()))?);
            let due = e.seq - tail.last_checkpoint_seq >= CHECKPOINT_EVERY
                || (tail.last_checkpoint_ms > 0
                    && e.ts_ms.saturating_sub(tail.last_checkpoint_ms) >= CHECKPOINT_AGE_MS
                    && e.seq > tail.last_checkpoint_seq);
            if due || (tail.last_checkpoint_seq == 0 && e.seq == 1) {
                if let Some(k) = &key {
                    let c = make_checkpoint(k, e.seq, &e.hash, e.ts_ms);
                    let l = line_of(&Line::Checkpoint(c.clone()))?;
                    text.push_str(&l);
                    anchor_text.push_str(&l);
                    tail.last_checkpoint_seq = c.seq;
                    tail.last_checkpoint_ms = c.ts_ms;
                }
            }
            out.push(e);
        }
        if text.is_empty() {
            return Ok(out);
        }
        append_to(&self.path, &text, self.file_mode())?;
        if !anchor_text.is_empty() {
            append_to(&self.anchor, &anchor_text, 0o600)?;
        }
        Ok(out)
    }

    /// Seal the chain as it stands now (a checkpoint covering the last entry).
    pub fn seal_now(&self, ts_ms: u64) -> io::Result<Option<Checkpoint>> {
        if let Some(r) = &self.remote {
            return r.seal();
        }
        let _lock = self.lock()?;
        let tail = self.tail()?;
        let (Some(hash), Some(key)) = (tail.hash.clone(), self.seal_key(true)?) else {
            return Ok(None);
        };
        if tail.last_checkpoint_seq >= tail.seq {
            return Ok(None);
        }
        let c = make_checkpoint(&key, tail.seq, &hash, ts_ms);
        let l = line_of(&Line::Checkpoint(c.clone()))?;
        append_to(&self.path, &l, self.file_mode())?;
        append_to(&self.anchor, &l, 0o600)?;
        Ok(Some(c))
    }

    /// Every entry, oldest first. A line that is not an entry is left out (see [`AuditLog::verify`]).
    pub fn entries(&self) -> io::Result<Vec<AuditEntry>> {
        Ok(self.read_all()?.0)
    }

    fn read_all(&self) -> io::Result<(Vec<AuditEntry>, Vec<Checkpoint>, Vec<usize>)> {
        let (mut entries, mut checks, mut bad) = (Vec::new(), Vec::new(), Vec::new());
        let file = match std::fs::File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok((entries, checks, bad)),
            Err(e) => return Err(e),
        };
        for (i, line) in io::BufReader::new(file).lines().enumerate() {
            let line = match line {
                Ok(l) => l,
                Err(_) => {
                    bad.push(i + 1);
                    continue;
                }
            };
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<Line>(&line) {
                Ok(Line::Entry(e)) => entries.push(e),
                Ok(Line::Checkpoint(c)) => checks.push(c),
                Err(_) => bad.push(i + 1),
            }
        }
        Ok((entries, checks, bad))
    }

    fn read_anchor(&self) -> Vec<Checkpoint> {
        let Ok(file) = std::fs::File::open(&self.anchor) else {
            return Vec::new();
        };
        io::BufReader::new(file)
            .lines()
            .map_while(Result::ok)
            .filter_map(|l| match serde_json::from_str::<Line>(&l) {
                Ok(Line::Checkpoint(c)) => Some(c),
                _ => None,
            })
            .collect()
    }

    /// Check the whole chain against its checkpoints and the anchor.
    pub fn verify(&self) -> io::Result<VerifyReport> {
        if let Some(r) = &self.remote {
            return r.verify();
        }
        let (entries, checks, bad) = self.read_all()?;
        let key = self.seal_key(false).ok().flatten();
        Ok(verify(
            &entries,
            &checks,
            &self.read_anchor(),
            &bad,
            key.as_ref(),
        ))
    }
}

/// An audit chain as files, read for taking over (see [`AuditLog::adopt`]). Only lines that parse as chain lines are kept,
/// so reading a file that is not a chain yields nothing and copies nothing.
#[derive(Debug)]
pub struct LegacyChain {
    pub entries: Vec<AuditEntry>,
    pub checkpoints: Vec<Checkpoint>,
    pub anchors: Vec<Checkpoint>,
    pub unreadable: Vec<usize>,
    /// The seal key the old writer used, if its file was there.
    pub key: Option<Vec<u8>>,
    chain_text: String,
    anchor_text: String,
    pub path: PathBuf,
    /// Who owns the chain file. The anchor and key beside it are read, and anything is destroyed, only when they have
    /// the same owner and are plain files (never a link): the service that reads them holds file capabilities.
    owner: Option<u32>,
}

/// The owner of a plain file (not a link), or `None`.
#[cfg(unix)]
fn plain_owner(p: &Path) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(p)
        .ok()
        .filter(|m| m.file_type().is_file())
        .map(|m| m.uid())
}

#[cfg(not(unix))]
fn plain_owner(p: &Path) -> Option<u32> {
    std::fs::symlink_metadata(p)
        .ok()
        .filter(|m| m.file_type().is_file())
        .map(|_| 0)
}

/// Open a plain file owned by `owner`, and make sure what was opened is what was looked at: a link put in its place between
/// the look and the open is caught by comparing the two (device and inode). No `O_NOFOLLOW` is needed for that.
#[cfg(unix)]
fn open_plain(p: &Path, owner: Option<u32>, write: bool) -> Option<std::fs::File> {
    use std::os::unix::fs::MetadataExt;
    let before = std::fs::symlink_metadata(p).ok()?;
    if !before.file_type().is_file() || owner.is_some_and(|o| before.uid() != o) {
        return None;
    }
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(write)
        .open(p)
        .ok()?;
    let after = f.metadata().ok()?;
    (after.dev() == before.dev() && after.ino() == before.ino()).then_some(f)
}

#[cfg(not(unix))]
fn open_plain(p: &Path, _: Option<u32>, write: bool) -> Option<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(write)
        .open(p)
        .ok()
}

fn read_plain(p: &Path, owner: Option<u32>, max: u64) -> Option<Vec<u8>> {
    use std::io::Read;
    let f = open_plain(p, owner, false)?;
    let mut out = Vec::new();
    f.take(max).read_to_end(&mut out).ok()?;
    Some(out)
}

impl LegacyChain {
    /// Read the chain at `chain_path` (`<stem>.audit.jsonl`) with its anchor and key beside it (`<stem>.audit.anchor`,
    /// `<stem>.audit.key`). `None` when there is no chain file.
    pub fn read(chain_path: &Path) -> io::Result<Option<LegacyChain>> {
        let meta = match std::fs::symlink_metadata(chain_path) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        if !meta.is_file() || meta.len() > 256 << 20 {
            return Err(io::Error::other("that is not an audit chain"));
        }
        let owner = plain_owner(chain_path);
        let raw = read_plain(chain_path, owner, 256 << 20)
            .and_then(|b| String::from_utf8(b).ok())
            .ok_or_else(|| io::Error::other("that is not an audit chain"))?;
        let (mut entries, mut checkpoints, mut unreadable) = (Vec::new(), Vec::new(), Vec::new());
        let mut chain_text = String::new();
        for (i, line) in raw.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<Line>(line) {
                Ok(l @ Line::Entry(_)) | Ok(l @ Line::Checkpoint(_)) => {
                    chain_text.push_str(&line_of(&l)?);
                    match l {
                        Line::Entry(e) => entries.push(e),
                        Line::Checkpoint(c) => checkpoints.push(c),
                    }
                }
                Err(_) => unreadable.push(i + 1),
            }
        }
        let beside = |ext: &str| {
            let name = chain_path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let stem = name.strip_suffix(".audit.jsonl").unwrap_or(&name);
            chain_path.with_file_name(format!("{stem}.audit.{ext}"))
        };
        let (mut anchors, mut anchor_text) = (Vec::new(), String::new());
        if let Some(a) =
            read_plain(&beside("anchor"), owner, 64 << 20).and_then(|b| String::from_utf8(b).ok())
        {
            for line in a.lines() {
                if let Ok(l @ Line::Checkpoint(_)) = serde_json::from_str::<Line>(line) {
                    anchor_text.push_str(&line_of(&l)?);
                    if let Line::Checkpoint(c) = l {
                        anchors.push(c);
                    }
                }
            }
        }
        let key = read_plain(&beside("key"), owner, 4096).filter(|k| k.len() >= 32);
        Ok(Some(LegacyChain {
            entries,
            checkpoints,
            anchors,
            unreadable,
            key,
            chain_text,
            anchor_text,
            path: chain_path.to_path_buf(),
            owner,
        }))
    }

    /// The old chain checked on its own, with its own key.
    pub fn report(&self) -> VerifyReport {
        let key = self
            .key
            .as_ref()
            .map(|k| hmac::Key::new(hmac::HMAC_SHA256, k));
        verify(
            &self.entries,
            &self.checkpoints,
            &self.anchors,
            &self.unreadable,
            key.as_ref(),
        )
    }

    /// Remove the old files. The key is overwritten first (best effort on a journaled disk).
    pub fn destroy(&self) {
        let name = self
            .path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let stem = name.strip_suffix(".audit.jsonl").unwrap_or(&name);
        let key = self.path.with_file_name(format!("{stem}.audit.key"));
        // only the old writer's own plain files: never through a link, never a file someone else owns
        if let Some(mut f) = open_plain(&key, self.owner, true) {
            use std::io::Write;
            if let Ok(m) = f.metadata() {
                let _ = f.write_all(&vec![0u8; m.len().min(4096) as usize]);
                let _ = f.sync_all();
            }
        }
        for ext in ["key", "anchor", "jsonl"] {
            let p = self.path.with_file_name(format!("{stem}.audit.{ext}"));
            if self.owner.is_some() && plain_owner(&p) == self.owner {
                let _ = std::fs::remove_file(p);
            }
        }
    }
}

type Lock = crate::filelock::FileLock;

fn line_of(l: &Line) -> io::Result<String> {
    let mut s = serde_json::to_string(l).map_err(io::Error::other)?;
    s.push('\n');
    Ok(s)
}

fn make_checkpoint(key: &hmac::Key, seq: u64, head: &str, ts_ms: u64) -> Checkpoint {
    let tag = hmac::sign(key, seal_message(seq, head).as_bytes());
    Checkpoint {
        seq,
        head: head.to_string(),
        ts_ms,
        tag: hex(tag.as_ref()),
    }
}

fn write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)?.write_all(data)
}

/// Append to a file that is only ever added to (opened for append, never truncated).
fn append_to(path: &Path, text: &str, mode: u32) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut o = std::fs::OpenOptions::new();
    o.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut f = o.open(path)?;
    f.write_all(text.as_bytes())?;
    f.sync_data()
}

/// A hole in the sequence: entries between these two are gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gap {
    pub after_seq: u64,
    pub before_seq: u64,
}

/// A checkpoint (or the anchor) says the chain reached further than the file does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Truncated {
    pub sealed_seq: u64,
    pub last_seq: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyReport {
    /// Nothing is wrong. (Entries after the last checkpoint are not wrong, only not sealed yet.)
    pub ok: bool,
    pub entries: u64,
    pub checkpoints: u64,
    pub head_seq: u64,
    pub head_hash: String,
    /// Entries whose content or link no longer matches their hash.
    pub altered: Vec<u64>,
    /// Entries that are missing from the sequence.
    pub deleted: Vec<Gap>,
    /// Entries that appear after a later one.
    pub out_of_order: Vec<u64>,
    /// Checkpoints whose tag does not verify, or whose head is not the entry it names.
    pub bad_seals: Vec<u64>,
    pub truncated: Option<Truncated>,
    /// Lines that could not be read at all (1-based).
    pub unreadable_lines: Vec<usize>,
    /// Entries after the last checkpoint.
    pub unsealed_tail: u64,
    /// The seal key was available, so checkpoint tags were checked.
    pub seals_checked: bool,
    /// A chain kept apart from this one when a box was upgraded while the new chain was already being written (see
    /// `audit_remote`): checked on its own, and `ok` is false when it is not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy: Option<Box<VerifyReport>>,
}

/// Check entries and checkpoints. Pure: the file reading is the caller's.
pub fn verify(
    entries: &[AuditEntry],
    checkpoints: &[Checkpoint],
    anchors: &[Checkpoint],
    unreadable: &[usize],
    key: Option<&hmac::Key>,
) -> VerifyReport {
    let mut r = VerifyReport {
        entries: entries.len() as u64,
        checkpoints: checkpoints.len() as u64,
        unreadable_lines: unreadable.to_vec(),
        seals_checked: key.is_some(),
        ..VerifyReport::default()
    };
    let mut prev = GENESIS.to_string();
    let mut last_seq = 0u64;
    let mut hashes = std::collections::BTreeMap::new();
    for e in entries {
        if entry_hash(e) != e.hash {
            r.altered.push(e.seq);
        }
        if e.seq <= last_seq {
            r.out_of_order.push(e.seq);
        } else {
            if e.seq > last_seq + 1 {
                r.deleted.push(Gap {
                    after_seq: last_seq,
                    before_seq: e.seq,
                });
            } else if e.prev != prev && !r.altered.contains(&e.seq) {
                // In order, but it does not follow the entry before it: that one, or this link, was rewritten.
                r.altered.push(e.seq);
            }
            last_seq = e.seq;
            prev = e.hash.clone();
        }
        hashes.insert(e.seq, e.hash.clone());
    }
    r.head_seq = last_seq;
    r.head_hash = prev;
    let mut sealed = 0u64;
    for c in checkpoints.iter().chain(anchors.iter()) {
        if let Some(k) = key {
            let ok = from_hex(&c.tag).is_some_and(|t| {
                hmac::verify(k, seal_message(c.seq, &c.head).as_bytes(), &t).is_ok()
            });
            if !ok {
                r.bad_seals.push(c.seq);
                continue;
            }
        }
        match hashes.get(&c.seq) {
            Some(h) if *h != c.head => {
                // The entry a checkpoint covers is not the one that was sealed.
                if !r.altered.contains(&c.seq) {
                    r.altered.push(c.seq);
                }
            }
            Some(_) => {}
            None if c.seq > last_seq => {
                let t = r.truncated.get_or_insert(Truncated {
                    sealed_seq: c.seq,
                    last_seq,
                });
                t.sealed_seq = t.sealed_seq.max(c.seq);
            }
            None => {}
        }
        if c.seq <= last_seq {
            sealed = sealed.max(c.seq);
        }
    }
    r.unsealed_tail = last_seq.saturating_sub(sealed);
    r.altered.sort_unstable();
    r.altered.dedup();
    r.bad_seals.sort_unstable();
    r.bad_seals.dedup();
    r.ok = r.altered.is_empty()
        && r.deleted.is_empty()
        && r.out_of_order.is_empty()
        && r.bad_seals.is_empty()
        && r.truncated.is_none()
        && r.unreadable_lines.is_empty();
    r
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn ev(n: u64, action: &str) -> NewEvent {
        NewEvent {
            ts_ms: 1_000 + n,
            actor: "alice".into(),
            action: action.into(),
            subject: Some(format!("t{n}")),
            detail: String::new(),
            src: None,
        }
    }

    fn log(dir: &Path) -> AuditLog {
        AuditLog::beside(&dir.join("tasks.json"))
    }

    /// The service reads and destroys an old chain with file capabilities: a link beside the chain must never make it
    /// read, or zero, another file.
    #[cfg(unix)]
    #[test]
    fn an_old_chain_is_read_and_destroyed_without_following_a_link() {
        let d = tempfile::tempdir().unwrap();
        let l = log(d.path());
        l.append(ev(1, "run.queued")).unwrap();
        let victim = d.path().join("victim");
        std::fs::write(&victim, "SENTINEL-precious-0123456789abcdef0123456789").unwrap();
        // the key is a link to another file
        let key = d.path().join("tasks.audit.key");
        std::fs::remove_file(&key).unwrap();
        std::os::unix::fs::symlink(&victim, &key).unwrap();
        let old = LegacyChain::read(&d.path().join("tasks.audit.jsonl"))
            .unwrap()
            .unwrap();
        assert!(old.key.is_none(), "a linked key is not read");
        old.destroy();
        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "SENTINEL-precious-0123456789abcdef0123456789",
            "a linked key is not zeroed"
        );
        // the chain file itself as a link is refused outright
        let other = d.path().join("other");
        std::fs::create_dir_all(&other).unwrap();
        std::os::unix::fs::symlink(&victim, other.join("tasks.audit.jsonl")).unwrap();
        assert!(LegacyChain::read(&other.join("tasks.audit.jsonl")).is_err());
    }

    #[test]
    fn four_writers_at_once_leave_one_unbroken_chain() {
        let d = tempfile::tempdir().unwrap();
        let l = log(d.path());
        std::thread::scope(|s| {
            for w in 0..4u64 {
                let l = &l;
                s.spawn(move || {
                    for i in 0..20u64 {
                        l.append(ev(w * 100 + i, "run.queued")).unwrap();
                    }
                });
            }
        });
        let r = l.verify().unwrap();
        assert!(r.ok, "{r:?}");
        assert_eq!(l.entries().unwrap().len(), 80);
        // the lock file is never removed (removing it is how a second holder gets in)
        assert!(d.path().join("tasks.audit.lock").exists());
    }

    fn fill(l: &AuditLog, n: u64) {
        for i in 1..=n {
            l.append(ev(i, "run.queued")).unwrap();
        }
    }

    fn rewrite(l: &AuditLog, f: impl FnOnce(Vec<String>) -> Vec<String>) {
        let text = std::fs::read_to_string(l.path()).unwrap();
        let lines: Vec<String> = text.lines().map(str::to_string).collect();
        let mut out = f(lines).join("\n");
        out.push('\n');
        std::fs::write(l.path(), out).unwrap();
    }

    fn entry_lines(lines: &[String]) -> Vec<usize> {
        lines
            .iter()
            .enumerate()
            .filter(|(_, l)| l.contains("\"k\":\"e\""))
            .map(|(i, _)| i)
            .collect()
    }

    #[test]
    fn an_untouched_chain_verifies_and_is_sealed() {
        let d = tempfile::tempdir().unwrap();
        let l = log(d.path());
        fill(&l, 120);
        let v = l.verify().unwrap();
        assert!(v.ok, "{v:?}");
        assert_eq!(v.entries, 120);
        assert!(v.seals_checked);
        assert!(v.checkpoints >= 2);
        assert!(v.unsealed_tail < CHECKPOINT_EVERY);
        l.seal_now(9_999).unwrap();
        assert_eq!(l.verify().unwrap().unsealed_tail, 0);
    }

    #[test]
    fn an_empty_chain_is_fine() {
        let d = tempfile::tempdir().unwrap();
        let v = log(d.path()).verify().unwrap();
        assert!(v.ok);
        assert_eq!(v.entries, 0);
    }

    #[test]
    fn each_entry_carries_the_hash_before_it() {
        let d = tempfile::tempdir().unwrap();
        let l = log(d.path());
        fill(&l, 3);
        let e = l.entries().unwrap();
        assert_eq!(e[0].prev, GENESIS);
        assert_eq!(e[1].prev, e[0].hash);
        assert_eq!(e[2].prev, e[1].hash);
    }

    #[test]
    fn an_edited_field_is_named() {
        let d = tempfile::tempdir().unwrap();
        let l = log(d.path());
        fill(&l, 10);
        rewrite(&l, |mut lines| {
            let i = entry_lines(&lines)[4];
            lines[i] = lines[i].replace("alice", "mallory");
            lines
        });
        let v = l.verify().unwrap();
        assert!(!v.ok);
        assert_eq!(v.altered, vec![5]);
    }

    #[test]
    fn an_edit_with_the_hash_recomputed_still_breaks_the_next_link() {
        let d = tempfile::tempdir().unwrap();
        let l = log(d.path());
        fill(&l, 10);
        let mut all = l.entries().unwrap();
        all[3].actor = "mallory".into();
        all[3].hash = entry_hash(&all[3]);
        // the attacker rewrites only that entry cleanly
        let r = verify(&all, &[], &[], &[], None);
        assert!(!r.ok);
        assert!(r.altered.contains(&5), "{r:?}");
    }

    #[test]
    fn a_deleted_middle_entry_is_a_gap() {
        let d = tempfile::tempdir().unwrap();
        let l = log(d.path());
        fill(&l, 10);
        rewrite(&l, |mut lines| {
            let i = entry_lines(&lines)[5];
            lines.remove(i);
            lines
        });
        let v = l.verify().unwrap();
        assert!(!v.ok);
        assert_eq!(
            v.deleted,
            vec![Gap {
                after_seq: 5,
                before_seq: 7
            }]
        );
    }

    #[test]
    fn two_swapped_lines_are_out_of_order() {
        let d = tempfile::tempdir().unwrap();
        let l = log(d.path());
        fill(&l, 10);
        rewrite(&l, |mut lines| {
            let e = entry_lines(&lines);
            lines.swap(e[5], e[6]);
            lines
        });
        let v = l.verify().unwrap();
        assert!(!v.ok);
        assert!(v.out_of_order.contains(&6), "{v:?}");
    }

    #[test]
    fn cutting_the_tail_shows_against_the_checkpoint_and_the_anchor() {
        let d = tempfile::tempdir().unwrap();
        let l = log(d.path());
        fill(&l, 60);
        l.seal_now(5_000).unwrap();
        // cut the last 12 entries AND any checkpoint line after them
        rewrite(&l, |lines| {
            let e = entry_lines(&lines);
            lines[..e[47]].to_vec()
        });
        let v = l.verify().unwrap();
        assert!(!v.ok);
        let t = v.truncated.unwrap();
        assert_eq!(t.sealed_seq, 60);
        assert_eq!(t.last_seq, 47);
    }

    #[test]
    fn a_forged_seal_is_caught() {
        let d = tempfile::tempdir().unwrap();
        let l = log(d.path());
        fill(&l, 55);
        rewrite(&l, |lines| {
            lines
                .into_iter()
                .map(|x| {
                    if x.contains("\"k\":\"c\"") {
                        let i = x.find("\"tag\":\"").unwrap() + 7;
                        let mut s = x.clone();
                        s.replace_range(i..i + 4, "0000");
                        s
                    } else {
                        x
                    }
                })
                .collect()
        });
        let v = l.verify().unwrap();
        assert!(!v.ok);
        assert!(!v.bad_seals.is_empty());
    }

    #[test]
    fn a_whole_chain_rewritten_without_the_key_fails_its_seals() {
        let d = tempfile::tempdir().unwrap();
        let l = log(d.path());
        fill(&l, 60);
        // an attacker rebuilds every entry consistently, with new content, and keeps the old checkpoint lines
        let (mut entries, checks, _) = l.read_all().unwrap();
        let mut prev = GENESIS.to_string();
        for e in &mut entries {
            e.actor = "mallory".into();
            e.prev = prev.clone();
            e.hash = entry_hash(e);
            prev = e.hash.clone();
        }
        let key = l.seal_key(false).unwrap().unwrap();
        let v = verify(&entries, &checks, &[], &[], Some(&key));
        assert!(!v.ok);
        assert!(!v.altered.is_empty(), "the sealed heads no longer match");
    }

    #[test]
    fn garbage_lines_are_reported() {
        let d = tempfile::tempdir().unwrap();
        let l = log(d.path());
        fill(&l, 3);
        rewrite(&l, |mut lines| {
            lines.insert(2, "not json".into());
            lines
        });
        let v = l.verify().unwrap();
        assert!(!v.ok);
        assert_eq!(v.unreadable_lines, vec![3]);
    }

    #[test]
    fn a_source_record_is_never_chained_twice() {
        let d = tempfile::tempdir().unwrap();
        let l = log(d.path());
        let mk = |s| NewEvent {
            src: Some(("e1".to_string(), s)),
            ..ev(s, "run.queued")
        };
        l.append_many(vec![mk(1), mk(2)]).unwrap();
        // a retry after a crash offers the same records again
        let again = l.append_many(vec![mk(1), mk(2), mk(3)]).unwrap();
        assert_eq!(again.len(), 1);
        assert_eq!(l.entries().unwrap().len(), 3);
        assert_eq!(l.last_src().unwrap(), Some(("e1".to_string(), 3)));
        // a store that was reset starts a new epoch, and its records are not mistaken for old ones
        let fresh = NewEvent {
            src: Some(("e2".to_string(), 1)),
            ..ev(9, "run.queued")
        };
        assert_eq!(l.append_many(vec![fresh]).unwrap().len(), 1);
    }

    #[test]
    fn nothing_secret_or_long_is_stored() {
        let d = tempfile::tempdir().unwrap();
        let l = log(d.path());
        l.append(NewEvent {
            detail: format!("curl --token sk-live-123 {}", "x".repeat(500)),
            ..ev(1, "x")
        })
        .unwrap();
        let text = std::fs::read_to_string(l.path()).unwrap();
        assert!(!text.contains("sk-live-123"));
        assert!(l.entries().unwrap()[0].detail.chars().count() <= MAX_DETAIL);
    }

    #[test]
    fn the_files_are_private() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let d = tempfile::tempdir().unwrap();
            let l = log(d.path());
            fill(&l, 1);
            for p in [
                l.path().to_path_buf(),
                l.key_path().unwrap(),
                l.anchor.clone(),
            ] {
                let m = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
                assert_eq!(m, 0o600, "{p:?}");
            }
        }
    }

    #[test]
    fn the_chain_survives_a_restart() {
        let d = tempfile::tempdir().unwrap();
        fill(&log(d.path()), 5);
        let l2 = log(d.path());
        l2.append(ev(6, "run.started")).unwrap();
        let v = l2.verify().unwrap();
        assert!(v.ok, "{v:?}");
        assert_eq!(v.head_seq, 6);
    }
}
