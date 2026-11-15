//! Coding agents on a box reach the Oz Box tools (ADR 0043).
//!
//! The Oz Box tool host (`crate::mcp`, with the shell, git, files and browser tools) used to be reachable only by runs Oz
//! Box starts. A person who opens Claude Code in the web IDE's terminal on the box got nothing. This module is the door
//! for that agent, and it is a different door from the dashboard's:
//!
//! * **A socket of its own**, `/run/ozbox-agent-mcp/mcp.sock`, that answers two paths only: `POST /v1/enrol` and
//!   `POST /mcp`. It is not the dashboard's HTTP server and shares none of its routes, cookies or tokens, so no request
//!   on it can reach the dashboard's API. There is no tunnel route and no loopback port.
//! * **The kernel names the caller.** Every request is checked against the peer's user id (`SO_PEERCRED` on Linux): only the
//!   box user. Nothing else on the computer is let in, whatever it knows. A process inside one of Oz Box's own runs
//!   (`run-<id>.scope` in its cgroup) is refused too, which stops an honest run's own engine from taking a second token. That
//!   check is NOT a wall: a hostile run can leave its scope (it is the same user). So nothing rests on it. Whoever gets a
//!   token is a **terminal agent** (`ActorKind::Terminal`): no `auto` mode, no box grant covers it, every risky act asks and
//!   the card says "a program that calls itself <name> ... in this box's terminal". An escaped run gains nothing it did not already have.
//! * **A token nobody stores.** The engine's config is static (`ozbox agent-mcp bridge`, no secret). The bridge enrols over
//!   the socket, holds a short-lived token in its own memory, and enrols again when it ends or the dashboard restarts. Turning
//!   the setting off revokes every token at once and refuses the next enrolment.
//! * **Nothing loosens.** The token is a session of the tool host's own: its tools, its permission engine (ADR 0039), the
//!   browser's submit/payment/send/new-domain approvals, and the person's name on every approval. It names this box only,
//!   and each program (a process, named by its pid and start time, which the door reads from the kernel) has a key of its
//!   own that stays the same when it renews, so approvals, the audit and browser sessions are never shared between programs and
//!   never lost to a renewal. The card and the audit name the program (read from `/proc`, never from the caller) and its pid.

use std::cell::Cell;
use std::collections::{HashMap, VecDeque};
use std::io::{BufReader, Read, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ring::hmac;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::broker::ProxyRequest;
use crate::mcp::{HostScope, McpServer, Reach, ToolRunner};
use crate::orch_tools::{Role, Session};
use ozbox_core::permissions::ActorKind;

pub mod bridge;
pub mod engines;
pub mod http;
#[cfg(test)]
mod tests;

/// The folder systemd makes for the dashboard (`RuntimeDirectory=ozbox-agent-mcp`), owned by the dashboard's user.
pub const SOCKET_DIR: &str = "/run/ozbox-agent-mcp";
pub const SOCKET_PATH: &str = "/run/ozbox-agent-mcp/mcp.sock";
/// Overrides the socket path and the allowed user in a DEBUG build only (the tests and the dashboard's browser tests).
/// A release build ignores them, so nothing in a box's environment can move the door or let another user in.
pub const SOCKET_ENV: &str = "OZBOX_AGENT_MCP_SOCKET";
pub const UID_ENV: &str = "OZBOX_AGENT_MCP_UID";
/// A token lives this long; the bridge enrols again a little before it ends.
pub const TOKEN_TTL_MS: u64 = 30 * 60 * 1000;
const MAX_BODY: usize = 256 * 1024;
const MAX_CONNECTIONS: usize = 32;
/// Connections one process may hold (an engine's bridge holds one).
const MAX_PER_PEER: usize = 4;
/// A connection that has not sent a whole first request (head and body) this soon after it was accepted is dropped, however
/// slowly it trickles: the deadline is for the request, not for each read.
const FIRST_REQUEST: Duration = Duration::from_secs(10);
/// A caller the door refuses at accept is answered once and closed. It waits this long for the caller to say something, so the
/// answer reaches a caller that writes at once, and never longer.
const REFUSAL_WAIT: Duration = Duration::from_millis(250);
/// How many refused callers are being answered at once; more are dropped without an answer.
const MAX_REFUSING: usize = 8;
/// Letters and digits of a session code: nothing that is easy to misread (no I, O, 0 or 1).
const CODE_ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
/// Characters in a session code: 30 bits, so a guess through the door's rate limit takes decades.
const CODE_LEN: usize = 6;
/// How many parents are looked at when naming the engine, and the programs that are only a wrapper on the way to it.
const WALK_CAP: usize = 8;
const WRAPPERS: [&str; 7] = ["sh", "bash", "dash", "zsh", "fish", "ash", "ksh"];
/// Programs that host a terminal or a session, and Oz Box's own (names as `clean_program` leaves them, so `tmux: server` is
/// `tmuxserver`). A bridge started by hand from a shell in the web terminal or over SSH has one of these behind the shell, and
/// none of them is an engine: the walk stops there and the card says the program does not say what it is, rather than naming
/// `sshd` or, worse, `ozboxd`, which a person could read as Oz Box itself asking. `ozbox` is the bridge's own name.
const SESSION_HOSTS: &[&str] = &[
    "ozbox",
    "ozboxd",
    "sshd",
    "sshd-session",
    "login",
    "su",
    "sudo",
    "runuser",
    "tmux",
    "tmuxserver",
    "screen",
    "script",
    "systemd",
];
/// How long a connection may sit idle between requests.
const IDLE: Duration = Duration::from_secs(15 * 60);
/// Enrolments the door answers in a minute for one process, and tokens one process may hold live (its oldest go first), so
/// one program cannot spend another's budget or push its token out. A process renews once in about 25 minutes.
const ENROLS_PER_PROCESS_PER_MINUTE: usize = 4;
const TOKENS_PER_PROCESS: usize = 2;
/// The door's own ceiling in a minute and in tokens, whatever the processes (memory and work stay bounded). When the token
/// ceiling is reached, a process that holds no token is refused with 429 (retry after 60 s); one that already holds a token
/// gives up its own oldest to make room, so no process can push out another's.
const ENROLS_PER_MINUTE: usize = 30;
const MAX_LIVE_TOKENS: usize = 16;
/// Standing permission for terminal agents (off by default): how long it lasts when the person does not say, and the most.
pub const STANDING_DEFAULT_MINUTES: u64 = 30;
pub const STANDING_MAX_MINUTES: u64 = 240;

/// The setting a person controls from the dashboard: may coding agents on this box use the Oz Box tools.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Setting {
    pub enabled: bool,
    /// Who last changed it (the person whose name goes on every approval an agent's call asks for).
    pub by: String,
    pub at_ms: u64,
    /// Until when terminal agents may use the person's standing permissions (`auto` mode, box grants). 0 is never: the
    /// default. It ends by itself, is cleared by turning the door off, and ends every token when it is set or cleared.
    #[serde(default)]
    pub standing_until_ms: u64,
}

impl Setting {
    pub fn standing_left_ms(&self, now_ms: u64) -> u64 {
        self.standing_until_ms.saturating_sub(now_ms)
    }
}

impl Default for Setting {
    /// On, for the box's owner: the tools are the box's own, every terminal agent asks for every risky act, and the person
    /// can turn it off. On a box with no sign-in, turning it back on needs the laptop's sign-in setup or root (ADR 0043).
    fn default() -> Self {
        Setting {
            enabled: true,
            by: "owner".into(),
            at_ms: 0,
            standing_until_ms: 0,
        }
    }
}

/// Where the setting is kept (a file in the dashboard's state folder, which only the dashboard's user can open).
#[derive(Debug, Clone)]
pub struct SettingStore {
    path: PathBuf,
}

impl SettingStore {
    pub fn new(state_dir: &Path) -> SettingStore {
        SettingStore {
            path: state_dir.join("agent-mcp.json"),
        }
    }

    /// The saved setting; none saved means the default. A file that cannot be read or understood means OFF: an unreadable
    /// choice is never read as a yes.
    pub fn load(&self) -> Setting {
        match std::fs::read_to_string(&self.path) {
            Ok(t) => serde_json::from_str(&t).unwrap_or_else(|_| Self::unreadable()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Setting::default(),
            Err(_) => Self::unreadable(),
        }
    }

    fn unreadable() -> Setting {
        Setting {
            enabled: false,
            by: "unreadable".into(),
            at_ms: 0,
            standing_until_ms: 0,
        }
    }

    /// Write the default the first time the door opens, so the choice is on disk from then on. A file that
    /// is there is never touched.
    pub fn ensure(&self) {
        if !self.path.exists() {
            let _ = self.save(&Setting::default());
        }
    }

    pub fn save(&self, s: &Setting) -> std::io::Result<()> {
        let tmp = self.path.with_extension("json.tmp");
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        f.write_all(serde_json::to_string(s).unwrap_or_default().as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, &self.path)
    }
}

/// Who is on the other end of a connection, from the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Peer {
    pub uid: u32,
    pub pid: Option<u32>,
}

/// Why a caller is turned away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The kernel did not name the caller, or it is not the box user.
    NotYou,
    /// The caller is inside one of Oz Box's own runs.
    InARun,
    /// The person turned the tools off for agents on this box.
    Off,
}

impl Refusal {
    pub fn message(self) -> &'static str {
        match self {
            Refusal::NotYou => "this door opens only for the box's own user",
            Refusal::InARun => "a run Oz Box started has its own tools and token; this door is for a coding agent you start in a terminal",
            Refusal::Off => "coding agents on this box may not use the Oz Box tools: turn that on in the dashboard (Settings, Coding agents on this box)",
        }
    }
}

/// May this caller in? The whole decision, with nothing to read: the peer, the allowed user, the setting, and whether the
/// peer's process is inside a run (`None` when that could not be told, which counts as inside one). A caller whose process
/// the kernel did not name is treated the same way.
pub fn admit(
    peer: Option<Peer>,
    allowed_uid: u32,
    enabled: bool,
    in_run: impl FnOnce(u32) -> Option<bool>,
) -> Result<(), Refusal> {
    let Some(p) = peer else {
        return Err(Refusal::NotYou);
    };
    if p.uid != allowed_uid {
        return Err(Refusal::NotYou);
    }
    match p.pid {
        Some(pid) if in_run(pid) == Some(false) => {}
        _ => return Err(Refusal::InARun),
    }
    if !enabled {
        return Err(Refusal::Off);
    }
    Ok(())
}

/// Is a process, by its `/proc/<pid>/cgroup` text, inside a run's scope (`run-<id>.scope`)?
pub fn cgroup_in_run(cgroup: &str) -> bool {
    cgroup.lines().any(|l| {
        l.rsplit(':').next().is_some_and(|path| {
            path.split('/')
                .any(|seg| seg.starts_with("run-") && seg.ends_with(".scope"))
        })
    })
}

/// What the door reads about a peer's process from `/proc`, so a session's key and the words on a card come from the kernel and
/// never from the caller. The peer is the engine's BRIDGE (`ozbox agent-mcp bridge`), so the name that
/// means something to a person is its parent's: the program that started it. That name is the parent's own `comm`, which any
/// program can set, so it is only ever shown as a claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcIdent {
    /// When the process started (`/proc/<pid>/stat`, field 22, in clock ticks since boot). With the pid it names one process:
    /// a new process that reuses a pid has another start time.
    pub start: u64,
    /// The word the ENGINE calls itself (its `comm`): the first ancestor of the bridge that is not a shell. Letters, digits, `.`,
    /// `_` and `-` only; "unknown" if it cannot be told.
    pub program: String,
    /// That program's pid, when it could be told: the one the card shows and the audit repeats.
    pub parent_pid: Option<u32>,
}

/// The start time out of a `/proc/<pid>/stat` line. The program name sits in brackets and may contain spaces and brackets, so
/// the fields are counted from the LAST `)`: field 3 (the state) follows it, which makes field 22 the 20th word after it.
pub fn parse_stat_start(stat: &str) -> Option<u64> {
    let after = &stat[stat.rfind(')')? + 1..];
    after.split_whitespace().nth(19)?.parse().ok()
}

/// The parent's pid out of a `/proc/<pid>/stat` line (field 4, the second word after the last `)`). Pid 0 is nobody.
pub fn parse_stat_ppid(stat: &str) -> Option<u32> {
    let after = &stat[stat.rfind(')')? + 1..];
    after
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
        .filter(|p| *p > 0)
}

/// A program name as a card and the audit may carry it: a short word with nothing in it that could be read as more.
pub fn clean_program(raw: &str) -> String {
    let base = raw.rsplit('/').next().unwrap_or(raw);
    let c: String = base
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        .take(32)
        .collect();
    if c.is_empty() {
        "unknown".into()
    } else {
        c
    }
}

/// The program that started a bridge, named by walking up its parents: a shell or a wrapper between the engine and
/// the bridge is skipped, so the card names the first program that is not a shell. `read` says a process's `comm` and its
/// parent. systemd, init, a process that cannot be read and a chain longer than the cap are "unknown", with no pid: the person
/// is not told a program that is not the engine's.
pub fn engine_in_chain(
    first: Option<u32>,
    read: impl Fn(u32) -> Option<(String, Option<u32>)>,
) -> (String, Option<u32>) {
    let mut cur = first;
    for _ in 0..WALK_CAP {
        let Some(pid) = cur.filter(|p| *p > 1) else {
            break;
        };
        let Some((comm, parent)) = read(pid) else {
            break;
        };
        let name = clean_program(comm.trim());
        if name == "init" || SESSION_HOSTS.contains(&name.as_str()) {
            break;
        }
        if WRAPPERS.contains(&name.as_str()) {
            cur = parent;
            continue;
        }
        return (name, Some(pid));
    }
    ("unknown".to_string(), None)
}

fn proc_ident(pid: u32) -> Option<ProcIdent> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let start = parse_stat_start(&stat)?;
    // `comm` is readable by every user; `exe` of another user's process is not, and is the caller's choice besides
    let read = |p: u32| {
        let comm = std::fs::read_to_string(format!("/proc/{p}/comm")).ok()?;
        let parent = std::fs::read_to_string(format!("/proc/{p}/stat"))
            .ok()
            .and_then(|t| parse_stat_ppid(&t));
        Some((comm, parent))
    };
    let (program, parent_pid) = engine_in_chain(parse_stat_ppid(&stat), read);
    Some(ProcIdent {
        start,
        program,
        parent_pid,
    })
}

fn proc_in_run(pid: u32) -> Option<bool> {
    std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .ok()
        .map(|t| cgroup_in_run(&t))
}

#[cfg(target_os = "linux")]
fn peer_of(s: &UnixStream) -> Option<Peer> {
    rustix::net::sockopt::socket_peercred(s).ok().map(|c| Peer {
        uid: c.uid.as_raw(),
        pid: u32::try_from(c.pid.as_raw_nonzero().get()).ok(),
    })
}

/// Only Linux names a caller (a box is Linux). Elsewhere nobody is named, so nobody is let in.
#[cfg(not(target_os = "linux"))]
fn peer_of(_: &UnixStream) -> Option<Peer> {
    None
}

/// The session code of one process: a keyed hash of its pid and start time. The key is the door's own, made at its start and kept in
/// its memory, so no program can compute the code of another process, and none can pick a pid to land on a code. It
/// does not depend on the epoch, so it stays the same while the process lives, through off and on and changes of standing
/// permission; a dashboard restart makes a new key and so new codes.
pub fn session_code_of(key: &hmac::Key, pid: u32, start: u64) -> String {
    let tag = hmac::sign(key, format!("oz-session-code:{pid}:{start}").as_bytes());
    let b = tag.as_ref();
    let bits = u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
    (0..CODE_LEN)
        .map(|i| char::from(CODE_ALPHABET[((bits >> (i * 5)) & 31) as usize]))
        .collect()
}

fn random_hmac_key() -> hmac::Key {
    let mut k = [0u8; 32];
    if getrandom::getrandom(&mut k).is_err() {
        // the system has no random source (it has, on Linux, from boot): the time and the pid still make a key no caller can
        // see, which is all a code needs
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        k[..16].copy_from_slice(&t.to_le_bytes());
        k[16..20].copy_from_slice(&std::process::id().to_le_bytes());
    }
    hmac::Key::new(hmac::HMAC_SHA256, &k)
}

/// A random start for the key's epoch: the caller never sees it, so no one can choose the key of a process that is not theirs.
fn random_epoch() -> u64 {
    let mut b = [0u8; 4];
    let _ = getrandom::getrandom(&mut b);
    u64::from(u32::from_le_bytes(b)) << 8
}

/// A connection's reader with a deadline for the whole of what is being read, not for each read: a caller that sends a byte
/// every few seconds is cut off when the deadline passes. `until` is None once the deadline no longer applies.
struct Deadline {
    s: UnixStream,
    until: Rc<Cell<Option<Instant>>>,
}

impl Read for Deadline {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if let Some(t) = self.until.get() {
            let left = t.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(std::io::ErrorKind::TimedOut.into());
            }
            self.s.set_read_timeout(Some(left))?;
        }
        self.s.read(buf)
    }
}

/// The user the box's agents run as (`id -u ozbox`), from the system's own user list.
pub fn box_user_uid() -> Option<u32> {
    let t = std::fs::read_to_string("/etc/passwd").ok()?;
    ozbox_core::daemon_scope::passwd_ids(&t, "ozbox").map(|(u, _)| u)
}

/// The door: the setting, the token store and the tool host's session rules, behind a socket.
pub struct AgentMcp {
    server: Arc<McpServer>,
    store: SettingStore,
    setting: Mutex<Setting>,
    box_name: String,
    uid: u32,
    peer: fn(&UnixStream) -> Option<Peer>,
    in_run: fn(u32) -> Option<bool>,
    /// Who the peer's process is (its start time and program), asked of the kernel at each enrolment.
    ident: fn(u32) -> Option<ProcIdent>,
    /// The tool host the door's server runs, kept to close the browser sessions that a change of epoch strands.
    runner: Arc<dyn ToolRunner>,
    /// Makes the session codes: made at start, never leaves this process.
    code_key: hmac::Key,
    /// Counts up on a turn-off and a change of person, and starts from a random number, so a key
    /// made before one is never the key made after it: what the old key held (approvals, browser sessions) is
    /// stranded. Turning standing permission ON or extending it does not move it: that gives a program more, and what it was
    /// approved and opened under is still the person's own choice.
    epoch: Arc<AtomicU64>,
    /// Held while the epoch and the setting change and while an enrolment reads them and issues its token, so no token is made
    /// under a setting or an epoch that a change has already ended.
    gate: Mutex<()>,
    /// How long a connection has to send its first whole request (the tests make it short).
    first_request_ms: AtomicU64,
    /// Refused callers being answered now (bounded).
    refusing: AtomicUsize,
    /// Closes of stranded browser sessions still running on their own threads.
    closing: AtomicUsize,
    open: AtomicUsize,
    /// Connections held by each process (by pid), so one process cannot take every slot.
    per_peer: Mutex<HashMap<u32, usize>>,
    /// When each recent enrolment was answered (the last minute), for each process's budget (by its session key) and for the
    /// door's own ceiling.
    enrols: Mutex<HashMap<String, VecDeque<u64>>>,
}

/// What `set_enabled` and `set_standing` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Saved {
    pub setting: Setting,
    /// False when it is in force in this process but could not be written (only a turn-off or a standing-off can be this:
    /// they take effect first, so a full disk cannot leave the door open).
    pub persisted: bool,
}

impl AgentMcp {
    /// `runner` is the same tool host runs get. The server inside is never put on a port: it holds this door's tokens only,
    /// so a token from here is worth nothing on the loopback port a run uses, and the reverse.
    pub fn new(
        runner: Arc<dyn ToolRunner>,
        store: SettingStore,
        box_name: &str,
        uid: u32,
    ) -> Arc<AgentMcp> {
        Self::new_with(
            runner,
            store,
            box_name,
            uid,
            peer_of,
            proc_in_run,
            proc_ident,
        )
    }

    /// As [`AgentMcp::new`], saying how the kernel is asked who is calling, whether that caller is inside a run, and which
    /// process it is: the tests answer for themselves, since they cannot be a different user.
    pub fn new_with(
        runner: Arc<dyn ToolRunner>,
        store: SettingStore,
        box_name: &str,
        uid: u32,
        peer: fn(&UnixStream) -> Option<Peer>,
        in_run: fn(u32) -> Option<bool>,
        ident: fn(u32) -> Option<ProcIdent>,
    ) -> Arc<AgentMcp> {
        let setting = Mutex::new(store.load());
        let epoch = Arc::new(AtomicU64::new(random_epoch()));
        // a browser session that finishes opening after the epoch moved is closed by the host, not orphaned: the
        // key ends in the epoch it was made under
        let current = Arc::clone(&epoch);
        runner.set_key_current(Arc::new(move |key: &str| {
            key.rsplit('-').next() == Some(current.load(Ordering::SeqCst).to_string().as_str())
        }));
        Arc::new(AgentMcp {
            server: Arc::new(McpServer::new(Arc::clone(&runner), 0)),
            runner,
            code_key: random_hmac_key(),
            gate: Mutex::new(()),
            first_request_ms: AtomicU64::new(
                u64::try_from(FIRST_REQUEST.as_millis()).unwrap_or(10_000),
            ),
            refusing: AtomicUsize::new(0),
            closing: AtomicUsize::new(0),
            store,
            setting,
            box_name: box_name.to_string(),
            uid,
            peer,
            in_run,
            ident,
            epoch,
            open: AtomicUsize::new(0),
            per_peer: Mutex::new(HashMap::new()),
            enrols: Mutex::new(HashMap::new()),
        })
    }

    pub fn setting(&self) -> Setting {
        self.setting
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Does the file on disk say what this process is doing? False after a turn-off that could not be written.
    pub fn persisted(&self) -> bool {
        self.store.load() == self.setting()
    }

    pub fn live_tokens(&self, now_ms: u64) -> usize {
        self.server.live_tokens(now_ms)
    }

    fn put(&self, next: &Setting) {
        *self
            .setting
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = next.clone();
    }

    /// Change the setting. Turning it off puts it off in memory and revokes every token FIRST, then saves, so a disk that
    /// is full or read-only can never leave it on: it is then off until the dashboard restarts, and `persisted`
    /// says so. Turning it on saves first and changes nothing if that fails. Either way standing permission ends.
    pub fn set_enabled(
        self: &Arc<Self>,
        enabled: bool,
        by: &str,
        now_ms: u64,
    ) -> std::io::Result<Saved> {
        let cur = self.setting();
        let next = Setting {
            enabled,
            by: by.to_string(),
            at_ms: now_ms,
            standing_until_ms: 0,
        };
        if !enabled {
            self.apply(&next, true, true);
            // the waiting cards end before the (possibly slow) save, so the window a call can file one in is as short as it can be
            self.runner.end_waiting_approvals(now_ms);
            let persisted = self.store.save(&next).is_ok();
            self.close_stranded();
            return Ok(Saved {
                setting: next,
                persisted,
            });
        }
        self.store.save(&next)?;
        // a change of person ends what the old person's agents were approved and opened under; the same person turning it on
        // again (it was off, so the key already moved on) keeps nothing to strand
        let moved = cur.by != next.by;
        self.apply(&next, moved, moved);
        if moved {
            self.runner.end_waiting_approvals(now_ms);
            self.close_stranded();
        }
        Ok(Saved {
            setting: next,
            persisted: true,
        })
    }

    /// Give terminal agents the person's standing permissions (`auto` mode, box grants) for `minutes` (`Some`), or end that
    /// (`None`). Every token is revoked, so the next enrolment gets the actor the new setting says. Ending it takes effect
    /// first, as turning the door off does. Neither ending it nor turning it on or extending it moves the keys, so an agent in
    /// the middle of a browser task is not cut off, and ending it early agrees with it running out.
    pub fn set_standing(
        self: &Arc<Self>,
        minutes: Option<u64>,
        by: &str,
        now_ms: u64,
    ) -> Result<Saved, String> {
        let cur = self.setting();
        let Some(m) = minutes else {
            let next = Setting {
                standing_until_ms: 0,
                by: by.to_string(),
                at_ms: now_ms,
                ..cur
            };
            // ending it early is the same as it running out: a session's allowed hosts are read from the box's
            // settings when it opens and each new request is decided again under the actor of the moment, so an agent in the
            // middle of a browser task is not cut off. Every token ends, and the next enrolment is a plain terminal agent
            // again. Two things do depend on standing, and are handled at the call: a session a standing enrolment opened on
            // a production box is refused a plain terminal agent, and a call waiting for an answer is ended.
            self.apply(&next, false, true);
            // a call waiting for a person's answer asked under the standing permission just ended
            self.runner.end_waiting_approvals(now_ms);
            let persisted = self.store.save(&next).is_ok();
            return Ok(Saved {
                setting: next,
                persisted,
            });
        };
        if !cur.enabled {
            return Err("turn the Oz Box tools on for coding agents first".into());
        }
        if m == 0 || m > STANDING_MAX_MINUTES {
            return Err(format!(
                "standing permission lasts from 1 minute to {} hours",
                STANDING_MAX_MINUTES / 60
            ));
        }
        let moved = cur.by != by;
        let next = Setting {
            standing_until_ms: now_ms + m * 60_000,
            by: by.to_string(),
            at_ms: now_ms,
            ..cur
        };
        self.store
            .save(&next)
            .map_err(|_| "the setting could not be saved".to_string())?;
        self.apply(&next, moved, moved);
        if moved {
            self.runner.end_waiting_approvals(now_ms);
            self.close_stranded();
        }
        Ok(Saved {
            setting: next,
            persisted: true,
        })
    }

    /// Put a new setting in force and end every token, as one step no enrolment can fall in the middle of: the setting is
    /// changed, the epoch moves on when `strand` says the keys must not survive, and the tokens are revoked, all under the gate
    /// an enrolment holds while it reads them and issues its token.
    ///
    /// `ends` says the change ends what waiting calls asked under (a turn-off, an early end of standing, another person): the
    /// door's generation moves inside the same step, so an enrolment can never hold a token of the new setting with the old
    /// generation (the sweep of the waiting cards follows, outside the gate).
    fn apply(&self, next: &Setting, strand: bool, ends: bool) {
        let _g = self
            .gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.put(next);
        if strand {
            self.epoch.fetch_add(1, Ordering::SeqCst);
        }
        if ends {
            self.runner.bump_door_generation();
        }
        self.server.revoke_all();
    }

    /// Close the browser sessions that a key from an older epoch opened: nobody can drive them any more, and one left open
    /// would hold a browser until the dashboard restarts. Sessions opened under the current epoch are left alone.
    ///
    /// This runs on a thread of its own: closing waits up to 15 s for a browser that may have hung, and the caller
    /// is the dashboard's single request loop, which the person's click and every other page wait on. The change itself is
    /// already in force when this is called, so nothing is waiting for the close. The epoch is read when each session is
    /// looked at, not when the thread starts, so a session opened under a newer epoch is never taken for a stranded one.
    fn close_stranded(self: &Arc<Self>) {
        let me = Arc::clone(self);
        me.closing.fetch_add(1, Ordering::SeqCst);
        let worker = Arc::clone(&me);
        let spawned = std::thread::Builder::new()
            .name("ozbox-mcp-close".into())
            .spawn(move || {
                worker.runner.close_stranded_sessions(&|key: &str| {
                    let now = worker.epoch.load(Ordering::SeqCst).to_string();
                    key.rsplit('-').next() != Some(now.as_str())
                });
                worker.closing.fetch_sub(1, Ordering::SeqCst);
            });
        if spawned.is_err() {
            // no thread to be had: the sessions stay until the next change or a restart, and the setting is still in force
            me.closing.fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// Closes still running in the background (the tests wait for them).
    #[cfg(test)]
    pub(crate) fn closing(&self) -> usize {
        self.closing.load(Ordering::SeqCst)
    }

    /// Bind the socket at `path`: a stale socket left by an earlier start is replaced, anything else in the way is not.
    pub fn bind(path: &Path) -> std::io::Result<UnixListener> {
        if let Ok(m) = std::fs::symlink_metadata(path) {
            if m.file_type().is_socket() {
                std::fs::remove_file(path)?;
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "something that is not a socket is in the way",
                ));
            }
        }
        let l = UnixListener::bind(path)?;
        // The kernel names every caller, so who may connect is decided there; the mode only lets the box user's user reach it.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
        Ok(l)
    }

    /// May this connection hold a slot? The kernel names the peer at accept: anyone but the box user is dropped at once, and a
    /// process may hold only a few. Returns the key to release with [`AgentMcp::release`].
    pub fn take_slot(&self, peer: Option<Peer>) -> Option<u32> {
        let p = peer?;
        if p.uid != self.uid {
            return None;
        }
        if self.open.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
            return None;
        }
        let key = p.pid.unwrap_or(0);
        let mut m = self
            .per_peer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let n = m.entry(key).or_insert(0);
        if *n >= MAX_PER_PEER {
            return None;
        }
        *n += 1;
        self.open.fetch_add(1, Ordering::SeqCst);
        Some(key)
    }

    pub fn release(&self, key: u32) {
        let mut m = self
            .per_peer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(n) = m.get_mut(&key) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                m.remove(&key);
            }
        }
        self.open.fetch_sub(1, Ordering::SeqCst);
    }

    /// Answer connections on background threads.
    ///
    /// The caller is admitted HERE, at accept and before a byte of its request is read: the kernel has named the peer,
    /// and the setting and the run check need nothing else. A caller that is not the box user is dropped without a word. One that
    /// is in a run, or that the person has turned off, is answered once (see [`AgentMcp::refuse`]) and holds no slot. Only a caller
    /// that is let in takes a slot, and then has [`FIRST_REQUEST`] for its whole first request.
    pub fn serve(self: &Arc<Self>, listener: UnixListener) {
        let me = Arc::clone(self);
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let peer = (me.peer)(&stream);
                match admit(peer, me.uid, me.setting().enabled, me.in_run) {
                    Ok(()) => {}
                    Err(Refusal::NotYou) => continue, // not the box user: no answer
                    Err(why) => {
                        me.refuse(stream, why);
                        continue;
                    }
                }
                let Some(slot) = me.take_slot(peer) else {
                    continue; // dropped: too many open (by this process or at all)
                };
                // Who is on the other end, as the kernel says at accept: this connection is theirs and nobody else's. A process
                // the kernel cannot describe is let go.
                let bound = peer.and_then(|p| p.pid).and_then(|pid| (me.ident)(pid));
                let m = Arc::clone(&me);
                std::thread::spawn(move || {
                    if let Some(b) = bound {
                        m.connection(stream, peer, &b);
                    }
                    m.release(slot);
                });
            }
        });
    }

    /// Say no to a caller admission turned away, and close. It waits a moment for the caller's request so that the answer reaches
    /// a caller that writes at once, and discards what it reads without looking at it. A caller that says nothing is answered
    /// and closed all the same, and never holds a slot; at most [`MAX_REFUSING`] are answered at once, the rest are dropped.
    fn refuse(self: &Arc<Self>, stream: UnixStream, why: Refusal) {
        if self.refusing.fetch_add(1, Ordering::SeqCst) >= MAX_REFUSING {
            self.refusing.fetch_sub(1, Ordering::SeqCst);
            return;
        }
        let me = Arc::clone(self);
        std::thread::spawn(move || {
            let mut s = stream;
            let _ = s.set_read_timeout(Some(REFUSAL_WAIT));
            let _ = s.set_write_timeout(Some(REFUSAL_WAIT));
            let mut sink = [0u8; 4096];
            let _ = s.read(&mut sink);
            let body = json!({ "error": why.message(), "code": format!("{why:?}") }).to_string();
            let _ = http::write_response(&mut s, 403, "application/json", body.as_bytes());
            // The caller's request may still be arriving (it is written in several small pieces). Closing with any of it unread
            // makes Linux reset the connection, which can throw the answer away before the caller reads it, so say we are done
            // and drain what comes, for a short while and a bounded amount, before closing.
            let _ = s.shutdown(std::net::Shutdown::Write);
            let end = Instant::now() + REFUSAL_WAIT;
            let mut left = 64 * 1024usize;
            while left > 0 && Instant::now() < end {
                match s.read(&mut sink) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => left = left.saturating_sub(n),
                }
            }
            me.refusing.fetch_sub(1, Ordering::SeqCst);
        });
    }

    fn connection(&self, stream: UnixStream, peer: Option<Peer>, bound: &ProcIdent) {
        // The first request has one deadline for the whole of it (head and body), however slowly it comes; once it has been
        // read the connection may idle between requests.
        let until = Rc::new(Cell::new(Some(
            Instant::now() + Duration::from_millis(self.first_request_ms.load(Ordering::SeqCst)),
        )));
        let Ok(rd) = stream.try_clone() else { return };
        let mut r = BufReader::new(Deadline {
            s: rd,
            until: Rc::clone(&until),
        });
        let mut w = stream;
        loop {
            let req = match http::read_request(&mut r, MAX_BODY) {
                Ok(r) => r,
                Err(http::ReadError::TooLarge) => {
                    let _ = http::write_response(
                        &mut w,
                        413,
                        "application/json",
                        br#"{"error":"too large"}"#,
                    );
                    return;
                }
                Err(http::ReadError::Malformed) => {
                    let _ = http::write_response(
                        &mut w,
                        400,
                        "application/json",
                        br#"{"error":"not understood"}"#,
                    );
                    return;
                }
                Err(_) => return,
            };
            if until.get().is_some() {
                until.set(None);
                let _ = w.set_read_timeout(Some(IDLE));
            }
            let (status, body, close) =
                self.route_conn(peer, Some(bound), &req, crate::serve::unix_ms());
            if http::write_response(&mut w, status, "application/json", &body).is_err() || close {
                return;
            }
        }
    }

    #[cfg(test)]
    pub fn set_first_request(&self, d: Duration) {
        self.first_request_ms.store(
            u64::try_from(d.as_millis()).unwrap_or(u64::MAX),
            Ordering::SeqCst,
        );
    }

    /// One request, already read, from a connection that was bound to the peer's process as it is now. For the tests.
    #[cfg(test)]
    pub fn route(&self, peer: Option<Peer>, req: &http::Request, now_ms: u64) -> (u16, Vec<u8>) {
        let bound = peer.and_then(|p| p.pid).and_then(|pid| (self.ident)(pid));
        let (s, b, _) = self.route_conn(peer, bound.as_ref(), req, now_ms);
        (s, b)
    }

    /// As [`AgentMcp::route`], with the identity the connection was bound to when it was accepted, and says whether the
    /// connection is to be closed after the answer.
    ///
    /// The caller is admitted FIRST, before the path or the method is looked at, so no answer is given to a caller who is not
    /// let in, and every refusal closes the connection: a process in a run cannot keep a slot by sending
    /// requests the door answers with a 404. Then the process on the other end is read again, and if it is not the one that
    /// connected (the pid was reused, so the connection was handed on and its owner is gone) the connection is closed.
    pub fn route_conn(
        &self,
        peer: Option<Peer>,
        bound: Option<&ProcIdent>,
        req: &http::Request,
        now_ms: u64,
    ) -> (u16, Vec<u8>, bool) {
        let err = |status: u16, msg: &str| {
            (
                status,
                json!({ "error": msg }).to_string().into_bytes(),
                false,
            )
        };
        let setting = self.setting();
        if let Err(why) = admit(peer, self.uid, setting.enabled, self.in_run) {
            return (
                403,
                json!({ "error": why.message(), "code": format!("{why:?}") })
                    .to_string()
                    .into_bytes(),
                true,
            );
        }
        let now_ident = peer.and_then(|p| p.pid).and_then(|pid| (self.ident)(pid));
        let ident = match (bound, now_ident) {
            (Some(b), Some(n)) if b.start == n.start => n,
            _ => {
                return (
                    403,
                    json!({ "error": "the program that opened this connection is gone; connect again", "code": "Changed" })
                        .to_string()
                        .into_bytes(),
                    true,
                );
            }
        };
        let path = req.path.split('?').next().unwrap_or("");
        if path != "/mcp" && path != "/v1/enrol" {
            return err(404, "there is no such endpoint");
        }
        if req.method != "POST" {
            return err(405, "use POST");
        }
        if req
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("origin"))
        {
            return err(403, "this door answers only to a program on this computer");
        }
        if path == "/v1/enrol" {
            let (s, b) = self.enrol(peer, &ident, now_ms);
            return (s, b, false);
        }
        let r = self.server.handle_on(
            Reach::Socket,
            &ProxyRequest {
                method: req.method.clone(),
                path: "/mcp".into(),
                headers: req.headers.clone(),
                body: req.body.clone(),
            },
            now_ms,
        );
        (r.status, r.body, false)
    }
}

impl AgentMcp {
    /// Has the process behind an enrolment key gone? The key is `terminal-<pid>-<start>-<epoch>`; the pid now belongs to nobody, or
    /// to a process that started at another time. Its tokens are then of no use to anyone and must not hold a place.
    fn key_is_gone(&self, key: &str) -> bool {
        let mut it = key.strip_prefix("terminal-").unwrap_or("").split('-');
        let (Some(pid), Some(start)) = (
            it.next().and_then(|p| p.parse::<u32>().ok()),
            it.next().and_then(|p| p.parse::<u64>().ok()),
        ) else {
            return false;
        };
        match (self.ident)(pid) {
            Some(i) => i.start != start,
            None => true,
        }
    }

    /// One enrolment, already admitted. The caller is a terminal agent (see the module docs) with an enrolment key of its own;
    /// it is a standing one only while the person's standing permission lasts, and its token ends with it.
    ///
    /// The whole of it runs under the gate, with the setting and the epoch read inside it: a turn-off, a change of
    /// person or the end of standing permission either completes first (and this enrolment sees it) or waits for this one (and
    /// revokes its token), so no token is ever made under a setting that has already ended.
    fn enrol(&self, peer: Option<Peer>, id: &ProcIdent, now_ms: u64) -> (u16, Vec<u8>) {
        let err =
            |status: u16, msg: &str| (status, json!({ "error": msg }).to_string().into_bytes());
        // The key is the peer's process: its pid and the time it started, read by the door from /proc. It does
        // not change when the same process enrols again, so a renewal keeps its browser sessions and its pending approvals;
        // a new process that reuses the pid has another start time. A process the kernel cannot describe gets nothing.
        let Some(pid) = peer.and_then(|p| p.pid) else {
            return err(403, "the kernel did not name this program");
        };
        let _gate = self
            .gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let setting = self.setting();
        if !setting.enabled {
            return (
                403,
                json!({ "error": Refusal::Off.message(), "code": "Off" })
                    .to_string()
                    .into_bytes(),
            );
        }
        let session = format!(
            "terminal-{pid}-{}-{}",
            id.start,
            self.epoch.load(Ordering::SeqCst)
        );
        {
            let mut w = self
                .enrols
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            w.retain(|_, q| {
                while q
                    .front()
                    .is_some_and(|t| now_ms.saturating_sub(*t) >= 60_000)
                {
                    q.pop_front();
                }
                !q.is_empty()
            });
            if w.get(&session).map_or(0, VecDeque::len) >= ENROLS_PER_PROCESS_PER_MINUTE {
                return err(
                    429,
                    "this program asked for too many sessions; wait a minute",
                );
            }
            if w.values().map(VecDeque::len).sum::<usize>() >= ENROLS_PER_MINUTE {
                return err(
                    429,
                    "too many sessions were asked for at once; wait a minute",
                );
            }
            w.entry(session.clone()).or_default().push_back(now_ms);
        }
        // Places held by processes that are gone are free again. At the cap a newcomer is NEVER let in by pushing a holder out:
        // it waits. A key that already holds a place replaces its own, so a renewal always works.
        for k in self.server.session_keys(now_ms) {
            if k != session && self.key_is_gone(&k) {
                self.server.drop_session(&k);
            }
        }
        let full = self.server.live_tokens(now_ms) >= MAX_LIVE_TOKENS;
        if full && self.server.tokens_of(&session, now_ms) == 0 {
            return (
                429,
                json!({ "error": "the door is full of other programs' sessions; wait a minute and try again", "retry_after_s": 60 })
                    .to_string()
                    .into_bytes(),
            );
        }
        self.server.evict_for_session(
            &session,
            if full { 0 } else { TOKENS_PER_PROCESS - 1 },
            now_ms,
        );
        let code = session_code_of(&self.code_key, pid, id.start);
        let left = setting.standing_left_ms(now_ms);
        let (actor, ttl) = if left > 0 {
            (ActorKind::TerminalStanding, TOKEN_TTL_MS.min(left))
        } else {
            (ActorKind::Terminal, TOKEN_TTL_MS)
        };
        let who = Session {
            person: setting.by.clone(),
            role: Role::Agent,
        };
        let host = HostScope {
            box_name: Some(self.box_name.clone()),
            run_id: None,
            orchestration: None,
            actor,
            session: Some(session.clone()),
            program: Some(id.program.clone()),
            program_pid: id.parent_pid,
            code: Some(code.clone()),
            standing_until_ms: (actor == ActorKind::TerminalStanding).then_some(now_ms + left),
            door_gen: self.runner.door_generation(),
        };
        match self.server.issue_host(who, Some(host), None, now_ms, ttl) {
            Ok(i) => (
                200,
                json!({ "token": i.token, "expires_ms": now_ms + ttl, "person": setting.by, "box": self.box_name,
                        "standing": actor == ActorKind::TerminalStanding, "code": code })
                .to_string()
                .into_bytes(),
            ),
            Err(_) => err(500, "no token could be made"),
        }
    }
}

/// The socket path and the allowed user this process should use: the box's fixed ones, or (debug builds) the overrides.
pub fn locate() -> Option<(PathBuf, u32)> {
    if cfg!(debug_assertions) {
        if let (Ok(s), Ok(u)) = (std::env::var(SOCKET_ENV), std::env::var(UID_ENV)) {
            return u.parse().ok().map(|u| (PathBuf::from(s), u));
        }
    }
    if !crate::this_box::on_a_box() || !Path::new(SOCKET_DIR).is_dir() {
        return None;
    }
    box_user_uid().map(|u| (PathBuf::from(SOCKET_PATH), u))
}

/// Which box the door acts on. It is THIS box, by this machine's own identity (the same source the box page
/// uses), and the door opens only when this dashboard runs as the box's own (`this_box`). A dashboard that has a provider
/// configured lists a fleet, and the first box of a fleet is not the machine a coding agent is sitting on: it stays shut.
/// Only a debug build with the test socket named may take the first listed box (the tests and the dashboard's browser
/// specs run on a computer that is not a box).
pub fn door_box_name(
    this_box_mode: bool,
    test_socket: bool,
    own_name: &str,
    listed: &[String],
) -> Option<String> {
    if this_box_mode {
        return Some(own_name.to_string());
    }
    if cfg!(debug_assertions) && test_socket {
        return listed.first().cloned();
    }
    None
}

/// The same answer as a JSON value for the dashboard's page.
pub fn view(a: Option<&Arc<AgentMcp>>, now_ms: u64) -> Value {
    match a {
        None => json!({ "available": false }),
        Some(a) => {
            let s = a.setting();
            json!({
                "available": true,
                "enabled": s.enabled,
                "by": s.by,
                "at_ms": s.at_ms,
                "standing_until_ms": if s.standing_left_ms(now_ms) > 0 { s.standing_until_ms } else { 0 },
                "sessions": a.live_tokens(now_ms),
                "saved": a.persisted(),
                "engines": engines::ENGINES.iter().map(|e| json!({ "id": e.id, "name": e.name })).collect::<Vec<_>>(),
            })
        }
    }
}
