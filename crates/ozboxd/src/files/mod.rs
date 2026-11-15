//! The box's file API: browse, preview, edit, upload, download, trash, search and expiring download links, all jailed to
//! the shared folders (by default `/work`). Everything here is a plain function of a request, so it is tested against a
//! temporary directory; `http` only moves bytes between a socket and [`FilesService::call`].
//!
//! Rules enforced here, not by the caller: no path leaves its root (symlinks included); files that can hold secrets are
//! never read, previewed, downloaded or uploaded; deleting moves to a trash that keeps things for 30 days; a stale edit
//! is refused; every change and every download leaves an audit line (names and sizes, never contents).

mod jail;
mod share;
mod tokens;
mod write;
mod zipw;

use std::collections::{BTreeMap, VecDeque};
use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub use jail::{blocked, valid_name, Jail, Op, Refusal, Resolved, STATE_DIR};
pub use tokens::{TokenRec, MAX_TTL_S};

use crate::timeutil::Clock;

pub const MAX_WRITE: u64 = 1024 * 1024;
pub const PREVIEW_TEXT_MAX: usize = 256 * 1024;
pub const MAX_LIST_PAGE: usize = 1000;
const MAX_LIST_ENTRIES: usize = 50_000;
const AUDIT_KEEP: usize = 500;

#[derive(Debug, Clone)]
pub struct FilesConfig {
    pub roots: Vec<PathBuf>,
    pub max_upload: u64,
    pub max_zip: u64,
    pub max_zip_files: usize,
    pub trash_days: u64,
    pub search_max_results: usize,
    pub search_max_visited: usize,
    pub search_timeout: Duration,
}

impl FilesConfig {
    pub fn new(roots: Vec<PathBuf>) -> Self {
        Self {
            roots,
            max_upload: 2 * 1024 * 1024 * 1024,
            max_zip: 1024 * 1024 * 1024,
            max_zip_files: 20_000,
            trash_days: 30,
            search_max_results: 200,
            search_max_visited: 50_000,
            search_timeout: Duration::from_secs(3),
        }
    }
}

pub enum Input<'a> {
    None,
    Bytes(&'a [u8]),
    Stream { reader: &'a mut dyn Read, len: u64 },
}

pub enum Body {
    Bytes(Vec<u8>),
    Stream {
        reader: Box<dyn Read + Send>,
        len: u64,
    },
}

pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Body,
}

impl Reply {
    pub fn json(status: u16, v: &impl Serialize) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Body::Bytes(serde_json::to_vec(v).unwrap_or_else(|_| b"{}".to_vec())),
        }
    }

    pub fn error(status: u16, code: &str, message: &str) -> Self {
        Self::json(
            status,
            &json!({ "code": code, "message": message, "error": message }),
        )
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The body when it is in memory (JSON answers and errors).
    pub fn bytes(&self) -> Option<&[u8]> {
        match &self.body {
            Body::Bytes(b) => Some(b),
            Body::Stream { .. } => None,
        }
    }
}

/// A failure that becomes an error reply.
#[derive(Debug)]
pub(crate) struct Fail {
    pub status: u16,
    pub code: String,
    pub message: String,
    pub extra: Option<Value>,
}

impl Fail {
    pub fn new(status: u16, code: &str, message: &str) -> Self {
        Self {
            status,
            code: code.into(),
            message: message.into(),
            extra: None,
        }
    }
    pub fn with(mut self, extra: Value) -> Self {
        self.extra = Some(extra);
        self
    }
}

impl From<Refusal> for Fail {
    fn from(r: Refusal) -> Self {
        Fail::new(r.status(), r.code(), r.message())
    }
}

impl From<std::io::Error> for Fail {
    fn from(e: std::io::Error) -> Self {
        io_fail(&e)
    }
}

pub(crate) fn io_fail(e: &std::io::Error) -> Fail {
    use std::io::ErrorKind::*;
    match (e.kind(), e.raw_os_error()) {
        (NotFound, _) => Refusal::NotFound.into(),
        (PermissionDenied, _) => Fail::new(403, "permission", "The box does not allow that."),
        (_, Some(28)) => Fail::new(507, "no_space", "The box's disk is full."),
        (AlreadyExists, _) => Fail::new(409, "exists", "Something with that name already exists."),
        (_, Some(18)) => Fail::new(
            422,
            "cross_device",
            "That cannot be moved between these disks.",
        ),
        _ => Fail::new(500, "io", "The file system could not do that."),
    }
}

impl From<Fail> for Reply {
    fn from(f: Fail) -> Self {
        let mut v = json!({ "code": f.code, "message": f.message, "error": f.message });
        if let (Some(Value::Object(extra)), Some(obj)) = (f.extra, v.as_object_mut()) {
            obj.extend(extra);
        }
        Reply::json(f.status, &v)
    }
}

pub(crate) type R<T> = Result<T, Fail>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub ts_ms: u64,
    pub action: String,
    /// `root:relative/path`. Never contents.
    pub path: Option<String>,
    pub to: Option<String>,
    pub size: Option<u64>,
    pub count: Option<u64>,
    pub token: Option<String>,
    pub outcome: String,
}

struct Audit {
    file: PathBuf,
    ring: VecDeque<AuditEvent>,
}

impl Audit {
    fn open(file: PathBuf) -> Self {
        let mut ring = VecDeque::new();
        if let Ok(text) = std::fs::read_to_string(&file) {
            for l in text.lines() {
                if let Ok(e) = serde_json::from_str::<AuditEvent>(l) {
                    ring.push_back(e);
                    if ring.len() > AUDIT_KEEP {
                        ring.pop_front();
                    }
                }
            }
        }
        Self { file, ring }
    }

    fn push(&mut self, e: AuditEvent) {
        use std::io::Write;
        if let (Ok(line), Ok(mut f)) = (
            serde_json::to_string(&e),
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.file),
        ) {
            let _ = writeln!(f, "{line}");
        }
        self.ring.push_back(e);
        if self.ring.len() > AUDIT_KEEP {
            self.ring.pop_front();
            if std::fs::metadata(&self.file).map(|m| m.len()).unwrap_or(0) > 1024 * 1024 {
                let text: String = self
                    .ring
                    .iter()
                    .filter_map(|e| serde_json::to_string(e).ok())
                    .map(|l| l + "\n")
                    .collect();
                let _ = std::fs::write(&self.file, text);
            }
        }
    }
}

pub struct FilesService {
    pub(crate) jail: Jail,
    pub(crate) cfg: FilesConfig,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) tokens: Mutex<tokens::TokenStore>,
    audit: Mutex<Audit>,
    /// Serialises changes, so a stale-edit check and the write it guards cannot interleave with another change.
    pub(crate) change_lock: Mutex<()>,
}

pub(crate) fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

pub(crate) fn sha256_hex(data: &[u8]) -> String {
    tokens::hex(ring::digest::digest(&ring::digest::SHA256, data).as_ref())
}

fn num<T: std::str::FromStr>(q: &BTreeMap<String, String>, k: &str, default: T) -> R<T> {
    match q.get(k) {
        None => Ok(default),
        Some(v) => v
            .parse()
            .map_err(|_| Fail::new(400, "bad_request", &format!("{k} must be a number"))),
    }
}

fn flag(q: &BTreeMap<String, String>, k: &str) -> bool {
    matches!(q.get(k).map(String::as_str), Some("1" | "true" | "yes"))
}

pub(crate) fn json_body<T: serde::de::DeserializeOwned>(input: &Input<'_>) -> R<T> {
    match input {
        Input::Bytes(b) => serde_json::from_slice(b)
            .map_err(|_| Fail::new(400, "bad_request", "The request body is not valid.")),
        _ => Err(Fail::new(400, "bad_request", "A JSON body is required.")),
    }
}

pub(crate) fn mtime_ms(md: &std::fs::Metadata) -> u64 {
    md.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Serialize)]
struct Entry {
    name: String,
    path: String,
    kind: &'static str,
    size: u64,
    modified_ms: u64,
    symlink: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    blocked: Option<&'static str>,
}

impl FilesService {
    pub fn new(cfg: FilesConfig, clock: Arc<dyn Clock>) -> std::io::Result<Self> {
        let jail = Jail::new(&cfg.roots)?;
        let state = jail.root_canon(0).join(STATE_DIR).join("files");
        let tokens = tokens::TokenStore::open(&state)?;
        let audit = Audit::open(state.join("audit.jsonl"));
        Ok(Self {
            jail,
            cfg,
            clock,
            tokens: Mutex::new(tokens),
            audit: Mutex::new(audit),
            change_lock: Mutex::new(()),
        })
    }

    pub fn audit_events(&self) -> Vec<AuditEvent> {
        lock(&self.audit).ring.iter().cloned().collect()
    }

    pub(crate) fn audit(
        &self,
        action: &str,
        path: Option<String>,
        to: Option<String>,
        size: Option<u64>,
        outcome: &str,
    ) {
        self.audit_full(AuditEvent {
            ts_ms: self.clock.now_ms(),
            action: action.into(),
            path,
            to,
            size,
            count: None,
            token: None,
            outcome: outcome.into(),
        });
    }

    pub(crate) fn audit_full(&self, e: AuditEvent) {
        lock(&self.audit).push(e);
    }

    /// Does this request carry a body that must be streamed rather than read into memory?
    pub fn wants_stream_body(method: &str, path: &str) -> bool {
        method == "PUT"
            && matches!(
                path.trim_end_matches('/'),
                "/v1/files/upload" | "/v1/files/write"
            )
    }

    pub fn handles(path: &str) -> bool {
        path == "/v1/files" || path.starts_with("/v1/files/")
    }

    pub fn call(
        &self,
        method: &str,
        path: &str,
        q: &BTreeMap<String, String>,
        input: Input<'_>,
    ) -> Reply {
        match self.route(method, path.trim_end_matches('/'), q, input) {
            Ok(r) => r,
            Err(f) => f.into(),
        }
    }

    fn route(
        &self,
        method: &str,
        path: &str,
        q: &BTreeMap<String, String>,
        input: Input<'_>,
    ) -> R<Reply> {
        let sub = path.strip_prefix("/v1/files").unwrap_or("");
        let not_allowed = || Fail::new(405, "method_not_allowed", "method not allowed");
        let ok = |v: Value| Ok(Reply::json(200, &v));
        match (method, sub) {
            ("GET", "/roots") => ok(json!({ "roots": self.jail.roots().into_iter()
                .map(|(label, p)| json!({ "label": label, "path": p.display().to_string() })).collect::<Vec<_>>(),
                "limits": { "max_upload": self.cfg.max_upload, "max_edit": MAX_WRITE, "max_zip": self.cfg.max_zip,
                            "trash_days": self.cfg.trash_days } })),
            ("GET", "/list") => self.list(q).map(|v| Reply::json(200, &v)),
            ("GET", "/stat") => self.stat(q),
            ("GET", "/preview") => self.preview(q),
            ("GET", "/read") => self.read(q),
            ("GET", "/search") => self.search(q),
            ("GET", "/audit") => {
                let limit: usize = num(q, "limit", 100)?;
                let ev = self.audit_events();
                let skip = ev.len().saturating_sub(limit.min(AUDIT_KEEP));
                ok(json!({ "events": ev.into_iter().skip(skip).collect::<Vec<_>>() }))
            }
            ("GET", "/download") => self.download(q),
            ("GET", "/trash") => self.trash_list(),
            ("GET", "/tokens") => self.tokens_list(),
            ("POST", "/tokens") => self.token_create(&input),
            ("DELETE", t) if t.starts_with("/tokens/") => self.token_revoke(&t["/tokens/".len()..]),
            ("PUT", "/write") => self.write_text(q, input),
            ("PUT", "/upload") => self.upload(q, input),
            ("POST", "/mkdir") => self.mkdir(&input),
            ("POST", "/rename") => self.rename(&input),
            ("POST", "/delete") => self.delete(&input),
            ("POST", "/trash/restore") => self.trash_restore(&input),
            ("POST", "/trash/empty") => self.trash_empty(&input),
            (
                _,
                "/roots" | "/list" | "/stat" | "/preview" | "/read" | "/search" | "/audit"
                | "/download" | "/trash" | "/tokens" | "/write" | "/upload" | "/mkdir" | "/rename"
                | "/delete" | "/trash/restore" | "/trash/empty",
            ) => Err(not_allowed()),
            (_, t) if t.starts_with("/tokens/") => Err(not_allowed()),
            _ => Err(Fail::new(404, "not_found", "no such endpoint")),
        }
    }

    pub(crate) fn path_arg(q: &BTreeMap<String, String>, key: &str) -> R<String> {
        q.get(key)
            .cloned()
            .ok_or_else(|| Fail::new(400, "bad_request", &format!("{key} is required")))
    }

    // ---- reading ---------------------------------------------------------------------------------------------

    fn entry_for(
        &self,
        dir: &Resolved,
        name: &str,
        rel_dir: &std::path::Path,
        hidden: bool,
    ) -> Option<Entry> {
        let rel = rel_dir.join(name);
        if matches!(blocked(&rel, Op::Read), Some(Refusal::Internal)) {
            return None;
        }
        if !hidden && name.starts_with('.') {
            return None;
        }
        let shown = format!(
            "{}/{}",
            dir.shown.display().to_string().trim_end_matches('/'),
            name
        );
        let real = dir.real.join(name);
        let lmd = std::fs::symlink_metadata(&real).ok()?;
        let is_link = lmd.file_type().is_symlink();
        let mut blocked_code = blocked(&rel, Op::Read).map(|r| r.code());
        let mut md = lmd;
        if is_link {
            match self.jail.resolve(&shown, Op::Read, true) {
                Ok(r) => match std::fs::metadata(&r.real) {
                    Ok(m) => md = m,
                    Err(_) => blocked_code = Some("symlink_escape"),
                },
                Err(r) => blocked_code = blocked_code.or(Some(r.code())),
            }
        }
        let kind = if md.is_dir() {
            "dir"
        } else if md.is_file() {
            "file"
        } else {
            blocked_code = blocked_code.or(Some("not_regular"));
            "other"
        };
        Some(Entry {
            name: name.to_string(),
            path: shown,
            kind,
            size: if md.is_file() { md.len() } else { 0 },
            modified_ms: mtime_ms(&md),
            symlink: is_link,
            blocked: blocked_code,
        })
    }

    fn list(&self, q: &BTreeMap<String, String>) -> R<Value> {
        let dir = self
            .jail
            .resolve(&Self::path_arg(q, "path")?, Op::Read, true)?;
        let md = std::fs::metadata(&dir.real)?;
        if !md.is_dir() {
            return Err(Fail::new(422, "not_a_directory", "That is not a folder."));
        }
        let hidden = flag(q, "hidden");
        let offset: usize = num(q, "offset", 0)?;
        let limit: usize = num::<usize>(q, "limit", 200)?.clamp(1, MAX_LIST_PAGE);
        let mut entries = Vec::new();
        let mut truncated = false;
        for e in std::fs::read_dir(&dir.real)? {
            let Ok(e) = e else { continue };
            let name = e.file_name().to_string_lossy().into_owned();
            if let Some(en) = self.entry_for(&dir, &name, &dir.rel, hidden) {
                entries.push(en);
            }
            if entries.len() >= MAX_LIST_ENTRIES {
                truncated = true;
                break;
            }
        }
        let sort = q.get("sort").map(String::as_str).unwrap_or("name");
        let desc = q.get("order").map(String::as_str) == Some("desc");
        entries.sort_by(|a, b| {
            // Folders first whatever the key, then the key, then the name for a stable order.
            let by_kind = (a.kind != "dir").cmp(&(b.kind != "dir"));
            let by_key = match sort {
                "size" => a.size.cmp(&b.size),
                "modified" => a.modified_ms.cmp(&b.modified_ms),
                "kind" => a.kind.cmp(b.kind),
                _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
            };
            let by_key = if desc { by_key.reverse() } else { by_key };
            by_kind
                .then(by_key)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        let total = entries.len();
        let page: Vec<Entry> = entries.into_iter().skip(offset).take(limit).collect();
        Ok(json!({
            "path": dir.shown.display().to_string(),
            "root": self.jail.root_shown(dir.root).display().to_string(),
            "entries": page, "total": total, "offset": offset, "limit": limit, "truncated": truncated,
        }))
    }

    fn stat(&self, q: &BTreeMap<String, String>) -> R<Reply> {
        let r = self
            .jail
            .resolve(&Self::path_arg(q, "path")?, Op::Read, false)?;
        let name = r
            .rel
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let parent = r.rel.parent().map(PathBuf::from).unwrap_or_default();
        let parent_shown = r
            .shown
            .parent()
            .map(PathBuf::from)
            .unwrap_or_else(|| r.shown.clone());
        let dir = Resolved {
            real: r
                .real
                .parent()
                .map(PathBuf::from)
                .unwrap_or_else(|| r.real.clone()),
            root: r.root,
            rel: parent.clone(),
            shown: parent_shown,
        };
        let entry = if name.is_empty() {
            Entry {
                name: self.jail.root_shown(r.root).display().to_string(),
                path: r.shown.display().to_string(),
                kind: "dir",
                size: 0,
                modified_ms: 0,
                symlink: false,
                blocked: None,
            }
        } else {
            self.entry_for(&dir, &name, &parent, true)
                .ok_or(Refusal::NotFound)?
        };
        Ok(Reply::json(200, &entry))
    }

    fn open_regular(&self, path: &str, op: Op) -> R<(Resolved, std::fs::File, std::fs::Metadata)> {
        let r = self.jail.resolve(path, op, true)?;
        let before = std::fs::metadata(&r.real)?;
        if !before.is_file() {
            return Err(if before.is_dir() {
                Fail::new(422, "not_a_file", "That is a folder.")
            } else {
                Refusal::NotRegular.into()
            });
        }
        let f = std::fs::File::open(&r.real)?;
        let md = f.metadata()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            // The file we opened must be the file we checked (a swap between the two is refused).
            if md.ino() != before.ino() || md.dev() != before.dev() {
                return Err(Refusal::SymlinkEscape.into());
            }
        }
        if !md.is_file() {
            return Err(Refusal::NotRegular.into());
        }
        Ok((r, f, md))
    }

    fn preview(&self, q: &BTreeMap<String, String>) -> R<Reply> {
        let (r, mut f, md) = self.open_regular(&Self::path_arg(q, "path")?, Op::Read)?;
        let name = r
            .rel
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let size = md.len();
        let mut head = Vec::new();
        f.by_ref().take(MAX_WRITE + 1).read_to_end(&mut head)?;
        let whole = size <= MAX_WRITE && head.len() as u64 == size;
        let mime = jail::mime_for(&name);
        let kind = if jail::is_image(&name) && mime != "image/x-icon" {
            "image"
        } else if mime == "application/pdf" && head.starts_with(b"%PDF") {
            "pdf"
        } else if jail::looks_like_text(&head) {
            "text"
        } else {
            "binary"
        };
        let writable = blocked(&r.rel, Op::Write).is_none();
        let mut v = json!({
            "path": r.shown.display().to_string(), "name": name, "size": size, "modified_ms": mtime_ms(&md),
            "kind": kind, "mime": mime,
            "editable": kind == "text" && whole && writable,
            "hash": whole.then(|| sha256_hex(&head)),
        });
        if kind == "text" {
            let cut = head.len().min(PREVIEW_TEXT_MAX);
            let text = String::from_utf8_lossy(&head[..cut]).into_owned();
            v["text"] = Value::String(text);
            v["truncated"] = Value::Bool(size > cut as u64);
        }
        Ok(Reply::json(200, &v))
    }

    fn read(&self, q: &BTreeMap<String, String>) -> R<Reply> {
        use std::io::{Seek, SeekFrom};
        const MAX_RANGE: u64 = 64 * 1024 * 1024;
        let (r, mut f, md) = self.open_regular(&Self::path_arg(q, "path")?, Op::Read)?;
        let size = md.len();
        let offset: u64 = num(q, "offset", 0)?;
        if offset > size {
            return Err(Fail::new(
                416,
                "bad_range",
                "The range starts past the end of the file.",
            ));
        }
        let want: u64 = num(q, "length", (size - offset).min(8 * 1024 * 1024))?;
        let len = want.min(size - offset).min(MAX_RANGE);
        f.seek(SeekFrom::Start(offset))?;
        self.audit(
            "read",
            Some(self.jail.audit_name(&r)),
            None,
            Some(len),
            "ok",
        );
        Ok(Reply {
            status: 200,
            headers: vec![
                ("Content-Type".into(), "application/octet-stream".into()),
                ("X-Ozbox-Size".into(), size.to_string()),
                ("X-Content-Type-Options".into(), "nosniff".into()),
            ],
            body: Body::Stream {
                reader: Box::new(f.take(len)),
                len,
            },
        })
    }

    // ---- search ----------------------------------------------------------------------------------------------

    fn search(&self, q: &BTreeMap<String, String>) -> R<Reply> {
        let dir = self
            .jail
            .resolve(&Self::path_arg(q, "path")?, Op::Read, true)?;
        let query = q.get("q").cloned().unwrap_or_default();
        if query.is_empty() || query.len() > 200 {
            return Err(Fail::new(
                400,
                "bad_request",
                "q must be 1 to 200 characters",
            ));
        }
        let content = flag(q, "content");
        let limit: usize = num::<usize>(q, "limit", 100)?.clamp(1, self.cfg.search_max_results);
        let needle = query.to_lowercase();
        let wildcard = needle.contains(['*', '?']);
        let started = Instant::now();
        let (mut results, mut visited) = (Vec::new(), 0usize);
        let (mut truncated, mut timed_out) = (false, false);
        let mut stack = vec![(dir.real.clone(), dir.rel.clone(), dir.shown.clone())];
        'walk: while let Some((real, rel, shown)) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&real) else {
                continue;
            };
            for e in rd.flatten() {
                visited += 1;
                if started.elapsed() > self.cfg.search_timeout {
                    timed_out = true;
                    break 'walk;
                }
                if visited > self.cfg.search_max_visited {
                    truncated = true;
                    break 'walk;
                }
                let name = e.file_name().to_string_lossy().into_owned();
                let child_rel = rel.join(&name);
                if matches!(name.as_str(), ".git" | "node_modules" | STATE_DIR)
                    || blocked(&child_rel, Op::Read).is_some()
                {
                    continue;
                }
                let Ok(md) = e.metadata() else { continue };
                if md.file_type().is_symlink() {
                    continue; // links are never followed by a search
                }
                let child_shown = shown.join(&name);
                let name_hit = if wildcard {
                    glob(&needle, &name.to_lowercase())
                } else {
                    name.to_lowercase().contains(&needle)
                };
                if md.is_dir() {
                    if name_hit && !content {
                        results.push(json!({ "path": child_shown.display().to_string(), "name": name, "kind": "dir" }));
                    }
                    stack.push((e.path(), child_rel, child_shown));
                } else if md.is_file() {
                    if !content && name_hit {
                        results.push(json!({ "path": child_shown.display().to_string(), "name": name, "kind": "file", "size": md.len() }));
                    } else if content && !wildcard && md.len() <= MAX_WRITE {
                        if let Some((line, snippet)) = grep_file(&e.path(), &needle) {
                            results.push(json!({ "path": child_shown.display().to_string(), "name": name, "kind": "file",
                                "size": md.len(), "line": line, "snippet": snippet }));
                        }
                    }
                }
                if results.len() >= limit {
                    truncated = true;
                    break 'walk;
                }
            }
        }
        Ok(Reply::json(
            200,
            &json!({ "results": results, "truncated": truncated, "timed_out": timed_out, "visited": visited }),
        ))
    }
}

/// `*` and `?` against a whole name (both already lower-cased).
pub fn glob(pat: &str, name: &str) -> bool {
    let (p, n): (Vec<char>, Vec<char>) = (pat.chars().collect(), name.chars().collect());
    let (mut pi, mut ni, mut star, mut mark) = (0, 0, None, 0);
    while ni < n.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == n[ni]) {
            pi += 1;
            ni += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ni;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ni = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// The first line containing `needle` (lower-case) in a text file, and a short snippet of it.
fn grep_file(path: &std::path::Path, needle: &str) -> Option<(usize, String)> {
    let bytes = std::fs::read(path).ok()?;
    if !jail::looks_like_text(&bytes) {
        return None;
    }
    let text = String::from_utf8_lossy(&bytes);
    text.lines().enumerate().find_map(|(i, l)| {
        l.to_lowercase()
            .contains(needle)
            .then(|| (i + 1, l.chars().take(160).collect::<String>()))
    })
}

#[cfg(test)]
mod tests;
