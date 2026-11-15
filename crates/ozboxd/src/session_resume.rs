//! Sessions come back: the record of the coding agents in the box user's tmux, and the boot step that reopens them.
//!
//! No process survives a stop (a resize, an upgrade, a crash, an out-of-memory kill, a pause), so what comes back is the
//! *session*, not the program. Two halves:
//!
//! * **The record.** Each agent's own hook writes one small JSON file per agent session on `/work`, on every event, so the
//!   record is current at any instant and a crash loses nothing: the engine, the engine's session id, the folder, the tmux
//!   session and window, the pane, and when it was last seen. Nothing else: no prompt text, no transcript path, no
//!   environment, no secret. A write is a temporary file in the same folder, flushed, then a rename, so a reader sees the old
//!   record or the new one, never half of one. The record is **removed** when the person ends the session (`SessionEnd` for
//!   `/exit`, `/clear` or a logout, never for a shutdown), when its tmux pane is gone while the box runs, and when it is
//!   older than [`MAX_AGE_MS`].
//! * **The resume.** `ozboxd session-resume` runs at every boot of the box user's manager. It installs the record hooks
//!   (idempotent), reads the records, and for each one that is recent enough (at most [`MAX_REOPEN`] per boot) recreates the
//!   tmux session and window and reopens the agent with its own resume. An engine whose resume is not proven here gets its
//!   window back in its folder with a line that says resume is not supported for it; nothing pretends. [`plan`] is a pure
//!   function from records to steps.
//!
//! What a resumed agent is **not** sent: a "you were interrupted, continue" message. Nothing here types into an agent. The
//! window shows the offer as a line above the agent, and the person sends it if they want to (ADR 0049).
//!
//! **Data never becomes code.** A record is data the agent's folder names can influence, so every field is checked on read
//! and on write, and none is ever given to tmux as text tmux would expand: names are plain words (no `#`), the folder is
//! only ever a quoted argument of the window's own script (`cd -- "$1"`), never tmux's `-c`, and a folder must be under
//! `/work`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use ozbox_core::{CommandRunner, CommandSpec};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const RECORD_VERSION: u32 = 1;
/// The only place a recorded folder may be: the box user's work and home live under it.
pub const WORK_ROOT: &str = "/work";
/// A record is rewritten at most this often when nothing but the time changed.
pub const TOUCH_EVERY_MS: u64 = 30_000;
/// A record not seen for this long is not reopened and is removed at the next boot: seven days.
pub const MAX_AGE_MS: u64 = 7 * 24 * 60 * 60 * 1000;
/// A record whose folder is gone is kept this long (a folder can come back) and then removed: one day.
pub const FOLDER_GONE_GRACE_MS: u64 = 24 * 60 * 60 * 1000;
/// At most this many sessions reopen in one boot; the rest stay recorded and are listed as "not reopened". Each reopened
/// `claude` is a Node process of a few hundred MB, and the tunnel and the IDE start at the same time: six keeps a 4 vCPU /
/// 8 GiB box clear of the out-of-memory event ADR 0045 exists to prevent.
pub const MAX_REOPEN: usize = 6;
const MAX_RECORD_BYTES: u64 = 8 * 1024;
const MAX_RECORDS: usize = 200;
const TEMP_MAX_AGE: Duration = Duration::from_secs(3600);
pub const PLACE_FORMAT: &str =
    "#{session_name}\t#{window_id}\t#{window_index}\t#{window_name}\t#{pid}\t#{start_time}\t#{pane_id}\t#{pane_pid}";
/// What a hook or the sweep waits for tmux or systemd before giving up: a stuck server must never hold an agent's hook.
const BOUND_SECONDS: &str = "2";
/// The reasons Claude Code gives a `SessionEnd` when the person ended the session. Anything else (`other`, which is what a
/// shutdown's hang-up looks like) leaves the record, so a clean stop never wipes the records it is about to need.
const ENDED_BY_PERSON: [&str; 3] = ["prompt_input_exit", "clear", "logout"];
/// The user unit that runs the resume at every boot of the box user's manager.
pub const UNIT_NAME: &str = "ozbox-session-resume.service";
/// The scope the first tmux server of a boot is started in. The `tmux-spawn-` prefix is what ADR 0045's drop-in
/// (`tmux-spawn-.scope.d`: a soft memory limit and `OOMPolicy=continue`) applies to.
const SCOPE_PREFIX: &str = "tmux-spawn-ozbox-resume-";

/// One agent session, as kept on `/work`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRecord {
    pub v: u32,
    pub engine: String,
    pub session_id: String,
    /// The folder the session was started in (kept from the first event: an engine finds its transcript by this folder).
    pub folder: String,
    pub tmux_session: String,
    pub window_name: String,
    pub window_index: u32,
    /// Which tmux server and pane held it: `<server pid>:<server start>:<pane id>`. A record whose server is the one now
    /// running is an agent that is still alive and is not reopened.
    pub place: String,
    pub last_seen_ms: u64,
}

impl SessionRecord {
    pub fn file_name(&self) -> String {
        format!("{}-{}.json", self.engine, self.session_id)
    }
    fn server(&self) -> &str {
        server_of(&self.place)
    }
    fn pane(&self) -> &str {
        self.place.rsplit_once(':').map(|(_, p)| p).unwrap_or("")
    }
}

fn server_of(place: &str) -> &str {
    place.rsplit_once(':').map(|(s, _)| s).unwrap_or("")
}

/// Where the tmux pane an agent runs in is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TmuxPlace {
    pub session: String,
    pub window_index: u32,
    pub window_name: String,
    pub pane_id: String,
    pub server: String,
    /// `#{pane_pid}`: the process tmux started in the pane. Read in the same call as the rest, so a place never exists without it.
    pub pane_pid: u32,
}

impl TmuxPlace {
    pub fn place(&self) -> String {
        format!("{}:{}", self.server, self.pane_id)
    }
}

/// A tmux session or window name as this module keeps and uses it: ASCII letters, digits, `_`, `-` and spaces, at most 60,
/// not starting with `-` or a space. Everything else becomes `_`. In particular no `#` (tmux expands `#(command)` and
/// `#{format}` in the names it is given), no `:` or `.` (target separators), no control character.
fn safe_name(text: &str) -> String {
    let mut out: String = text
        .chars()
        .take(60)
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == ' ' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if out.starts_with(['-', ' ']) {
        out.replace_range(..1, "_");
    }
    out
}

fn is_clean_name(s: &str) -> bool {
    safe_name(s) == s
}

fn valid_engine(e: &str) -> bool {
    !e.is_empty() && e.len() <= 24 && e.chars().all(|c| c.is_ascii_lowercase() || c == '-')
}

/// Plain words, starting with a letter or digit, so an id can never be read as a flag by the agent.
fn valid_session_id(id: &str) -> bool {
    ozbox_core::claude_code::is_resume_id(id)
}

fn under(folder: &str, root: &str) -> bool {
    folder == root
        || folder
            .strip_prefix(root)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn valid_folder(f: &str, root: &str) -> bool {
    f.starts_with('/')
        && f.len() <= 4096
        && !f.chars().any(char::is_control)
        && !f.split('/').any(|s| s == "..")
        && under(f, root)
}

fn digits(s: &str) -> bool {
    !s.is_empty() && s.len() <= 20 && s.bytes().all(|b| b.is_ascii_digit())
}

/// `<pid>:<start>:<pane id>`, as [`TmuxPlace::place`] makes it.
fn valid_place(p: &str) -> bool {
    let parts: Vec<&str> = p.split(':').collect();
    matches!(parts.as_slice(), [pid, start, pane]
        if digits(pid) && digits(start) && crate::agent_sessions::valid_pane_id(pane))
}

/// Parse `tmux display-message -p -F PLACE_FORMAT` (also what `new-window -P -F` prints). Names are made plain here, so
/// nothing a window is called can reach tmux as a format.
pub fn parse_place(out: &str) -> Option<TmuxPlace> {
    let l = out.lines().next()?;
    let f: Vec<&str> = l.split('\t').collect();
    let [session, window_id, index, name, pid, start, pane, pane_pid] = f.as_slice() else {
        return None;
    };
    let id_ok = window_id
        .strip_prefix('@')
        .is_some_and(|d| digits(d) && d.len() <= 9);
    (id_ok
        && digits(index)
        && digits(pid)
        && digits(start)
        && crate::agent_sessions::valid_pane_id(pane)
        && pane_pid.parse::<u32>().is_ok_and(|p| p > 0))
    .then(|| TmuxPlace {
        session: safe_name(session),
        window_index: index.parse().unwrap_or(0),
        window_name: safe_name(name),
        pane_id: (*pane).to_string(),
        server: format!("{pid}:{start}"),
        pane_pid: pane_pid.parse().unwrap_or(1),
    })
}

fn id_key(engine: &str) -> &'static str {
    if engine == "codex" {
        "thread-id"
    } else {
        "session_id"
    }
}

/// The record one hook event makes, or none when it carries no session id. Only the session id and the folder are read from
/// the engine's payload; everything else in it (prompts, transcript paths, tool input) is never looked at.
pub fn record_from_event(
    engine: &str,
    payload: &Value,
    cwd_default: &str,
    place: &TmuxPlace,
    now_ms: u64,
    root: &str,
) -> Option<SessionRecord> {
    let session_id = payload
        .get(id_key(engine))
        .and_then(Value::as_str)?
        .to_string();
    let folder = payload
        .get("cwd")
        .and_then(Value::as_str)
        .filter(|c| valid_folder(c, root))
        .unwrap_or(cwd_default)
        .to_string();
    (valid_engine(engine) && valid_session_id(&session_id) && valid_folder(&folder, root)).then(
        || SessionRecord {
            v: RECORD_VERSION,
            engine: engine.to_string(),
            session_id,
            folder,
            tmux_session: place.session.clone(),
            window_name: place.window_name.clone(),
            window_index: place.window_index,
            place: place.place(),
            last_seen_ms: now_ms,
        },
    )
}

#[derive(Debug, PartialEq, Eq)]
pub enum Wrote {
    Written,
    /// Nothing but the time changed, and it changed less than [`TOUCH_EVERY_MS`] ago.
    Unchanged,
}

/// Open a record for reading without following a symlink and without blocking on a file that is not a file (a named pipe
/// swapped in would otherwise hold the boot step until its timeout).
fn open_for_read(path: &Path) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
}

fn read_one(path: &Path, root: &str) -> Result<SessionRecord, String> {
    let f = open_for_read(path).map_err(|e| e.kind().to_string())?;
    let meta = f.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.len() > MAX_RECORD_BYTES {
        return Err("not a plain small file".into());
    }
    let mut text = String::new();
    f.take(MAX_RECORD_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|e| e.kind().to_string())?;
    let r: SessionRecord = serde_json::from_str(&text).map_err(|e| format!("not valid: {e}"))?;
    if r.v != RECORD_VERSION {
        return Err(format!("version {} is not understood", r.v));
    }
    // every field, not just the ones a path needs: a record is data a folder name could have shaped
    if !valid_engine(&r.engine)
        || !valid_session_id(&r.session_id)
        || !valid_folder(&r.folder, root)
        || !is_clean_name(&r.tmux_session)
        || !is_clean_name(&r.window_name)
        || !valid_place(&r.place)
    {
        return Err("a field is not acceptable".into());
    }
    if path.file_name().and_then(|n| n.to_str()) != Some(r.file_name().as_str()) {
        return Err("its name does not match its content".into());
    }
    Ok(r)
}

/// Every readable record, and one message per file that was skipped (a corrupt record never stops the others).
pub fn load_records(dir: &Path, root: &str) -> (Vec<SessionRecord>, Vec<String>) {
    let (mut good, mut said) = (Vec::new(), Vec::new());
    let Ok(rd) = fs::read_dir(dir) else {
        return (good, said);
    };
    let mut names: Vec<PathBuf> = rd.filter_map(|e| e.ok().map(|e| e.path())).collect();
    // newest first, so the cap keeps the sessions most likely to be wanted (a name is `<engine>-<id>.json`, so file time is the
    // only order there is)
    names.sort_by_cached_key(|p| {
        (
            std::cmp::Reverse(
                fs::metadata(p)
                    .and_then(|m| m.modified())
                    .unwrap_or(SystemTime::UNIX_EPOCH),
            ),
            p.clone(),
        )
    });
    for p in names {
        let name = p
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("?")
            .to_string();
        if name.starts_with('.') || !name.ends_with(".json") {
            continue; // a temporary file of a write in progress, or something that is not ours
        }
        if good.len() >= MAX_RECORDS {
            said.push(format!("skipping {name}: more than {MAX_RECORDS} records"));
            continue;
        }
        match read_one(&p, root) {
            Ok(r) => good.push(r),
            Err(why) => said.push(format!(
                "skipping {}: {why}",
                name.chars()
                    .filter(|c| !c.is_control())
                    .take(80)
                    .collect::<String>()
            )),
        }
    }
    (good, said)
}

/// Write a record: temporary file beside it, flushed, renamed over it. Keeps the folder the session started in, and removes
/// the record of any other session that held the same tmux pane (a cleared conversation is a new session id in the same
/// pane). `force` skips the "nothing changed" check.
pub fn write_record(dir: &Path, root: &str, new: &SessionRecord, force: bool) -> io::Result<Wrote> {
    ensure_dir(dir)?;
    let path = dir.join(new.file_name());
    let mut rec = new.clone();
    if let Ok(old) = read_one(&path, root) {
        rec.folder = old.folder.clone();
        let same = SessionRecord {
            last_seen_ms: rec.last_seen_ms,
            ..old.clone()
        } == rec;
        if !force && same && rec.last_seen_ms.saturating_sub(old.last_seen_ms) < TOUCH_EVERY_MS {
            return Ok(Wrote::Unchanged);
        }
    }
    write_file(dir, &rec)?;
    prune_place(dir, root, &rec);
    Ok(Wrote::Written)
}

fn write_file(dir: &Path, rec: &SessionRecord) -> io::Result<()> {
    let path = dir.join(rec.file_name());
    let tmp = dir.join(format!(".{}.tmp-{}", rec.file_name(), std::process::id()));
    let result = (|| {
        let mut f = open_private(&tmp)?;
        f.write_all(serde_json::to_string(rec)?.as_bytes())?;
        f.sync_all()?;
        fs::rename(&tmp, &path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn prune_place(dir: &Path, root: &str, keep: &SessionRecord) {
    let (all, _) = load_records(dir, root);
    for r in all {
        if r.place == keep.place && r.session_id != keep.session_id {
            let _ = fs::remove_file(dir.join(r.file_name()));
        }
    }
}

/// Remove one record (a no-op when it is already gone).
pub fn remove_record(dir: &Path, engine: &str, session_id: &str) {
    if valid_engine(engine) && valid_session_id(session_id) {
        let _ = fs::remove_file(dir.join(format!("{engine}-{session_id}.json")));
    }
}

/// Make the records folder (mode 0700) if it is not there. One that is there must be a real folder of this user: a symlink,
/// a file or someone else's folder is refused, and a permission is never set through a link.
fn ensure_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    match fs::symlink_metadata(dir) {
        Ok(m) => {
            if !m.is_dir() {
                return Err(io::Error::other(
                    "the records folder is a link or not a folder",
                ));
            }
            // the process's own user, from the owner of /proc/self (not available off Linux: the check is skipped there)
            if let Ok(me) = fs::metadata("/proc/self") {
                if m.uid() != me.uid() {
                    return Err(io::Error::other(
                        "the records folder belongs to someone else",
                    ));
                }
            }
            if m.permissions().mode() & 0o077 != 0 {
                fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
            }
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir),
        Err(e) => Err(e),
    }
}

fn open_private(path: &Path) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

/// Where the records live: on `/work`, in the box user's own state folder. Never taken from the environment: an agent's
/// repository can set variables in its own shell, and the boot step does not see them.
pub fn records_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(|h| PathBuf::from(h).join(".local/state/ozbox/sessions"))
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// `timeout -k 1 2 <program> <args>`: a stuck tmux or systemd never holds a hook, the sweep or the boot step.
fn bounded(program: &str, args: &[&str]) -> CommandSpec {
    let mut c = CommandSpec::new("timeout")
        .arg("-k")
        .arg("1")
        .arg(BOUND_SECONDS)
        .arg(program);
    for a in args {
        c = c.arg(*a);
    }
    c
}

/// The tmux pane the calling process runs in, from the pane the engine's hook was started in.
pub fn current_place(runner: &dyn CommandRunner, pane: &str) -> Option<TmuxPlace> {
    if !crate::agent_sessions::valid_pane_id(pane) {
        return None;
    }
    let out = runner
        .run(&bounded(
            "tmux",
            &["display-message", "-p", "-t", pane, "-F", PLACE_FORMAT],
        ))
        .ok()?;
    if out.status != Some(0) {
        return None;
    }
    parse_place(&out.stdout)
}

/// May the box (or the box user's manager) be shutting down? A shutdown hangs up every pane, which looks to an agent like being
/// closed: nothing may be removed then. **Fails closed**: only two positive answers, `running` or `degraded`, from both the system
/// and the user manager, say it is not; a timeout, a dead bus, an empty or an unknown answer (`stopping`, `starting`,
/// `maintenance`, `offline`) all mean "may be stopping", and a removal is skipped. A record kept by mistake ages out; one removed
/// by mistake loses a session.
pub fn system_may_be_stopping(runner: &dyn CommandRunner) -> bool {
    stopping_answers(runner).is_some()
}

/// One manager's answer to `is-system-running`, as one short printable word for a log line.
fn manager_answer(runner: &dyn CommandRunner, c: CommandSpec) -> String {
    match runner.run(&c) {
        Ok(o) => {
            let w: String = o
                .stdout
                .lines()
                .next()
                .unwrap_or("")
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
                .take(24)
                .collect();
            if w.is_empty() {
                "no answer".into()
            } else {
                w
            }
        }
        Err(_) => "no answer".into(),
    }
}

/// `None` when both managers say the box is running; otherwise their two answers (system, user), so a skipped sweep can say why.
pub fn stopping_answers(runner: &dyn CommandRunner) -> Option<(String, String)> {
    let sys = manager_answer(runner, bounded("systemctl", &["is-system-running"]));
    let user = manager_answer(
        runner,
        user_bus(bounded("systemctl", &["--user", "is-system-running"])),
    );
    let ok = |a: &str| matches!(a, "running" | "degraded");
    (!(ok(&sys) && ok(&user))).then_some((sys, user))
}

/// Looks of the minute sweep before its silence is worth a journal line: ten minutes of "may be stopping" on a box that is up
/// is not a shutdown, it is a check that cannot pass (a bus that cannot be reached, a manager stuck in `starting`), and every
/// removal except the seven-day one has then stopped.
pub const SKIPS_BEFORE_SAYING: u32 = 10;

/// Counts consecutive skipped sweeps; says so once, and starts again when a sweep is allowed.
#[derive(Default)]
pub struct SkipWatch {
    skipped: u32,
    said: bool,
}

impl SkipWatch {
    /// Feed it what [`stopping_answers`] said before a sweep. Returns the one line to log, or none.
    pub fn look(&mut self, answers: Option<(String, String)>) -> Option<String> {
        let Some((sys, user)) = answers else {
            *self = Self::default();
            return None;
        };
        self.skipped = self.skipped.saturating_add(1);
        if self.skipped < SKIPS_BEFORE_SAYING || self.said {
            return None;
        }
        self.said = true;
        Some(format!(
            "the cleanup of closed windows has been skipped {} times in a row: the system manager says \"{sys}\" and the user manager says \"{user}\"; nothing is removed until both say running or degraded",
            self.skipped
        ))
    }
}

/// Give a `systemctl --user` call the box user's runtime folder when the caller has none (the daemon is a system service, so it
/// does not inherit one; an agent's hook runs in the user's session and does).
fn user_bus(mut c: CommandSpec) -> CommandSpec {
    use std::os::unix::fs::MetadataExt;
    if std::env::var_os("XDG_RUNTIME_DIR").is_none() {
        if let Ok(me) = fs::metadata("/proc/self") {
            let run = format!("/run/user/{}", me.uid());
            c.env.insert(
                "DBUS_SESSION_BUS_ADDRESS".into(),
                format!("unix:path={run}/bus"),
            );
            c.env.insert("XDG_RUNTIME_DIR".into(), run);
        }
    }
    c
}

/// A pane of the tmux server that answered: the process tmux started in it, and the name of the command in its foreground.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PaneInfo {
    pid: Option<u32>,
    command: String,
}

/// What asking tmux for its panes told us: the server that answered (`<pid>:<start>`) and its panes, or nothing. This is only the
/// default socket's server (or the one the caller is inside, from `$TMUX`): it says nothing about any other server.
fn live_panes(runner: &dyn CommandRunner) -> Option<(String, BTreeMap<String, PaneInfo>)> {
    let out = runner
        .run(&bounded(
            "tmux",
            &[
                "list-panes",
                "-a",
                "-F",
                "#{pid}\t#{start_time}\t#{pane_id}\t#{pane_pid}\t#{pane_current_command}",
            ],
        ))
        .ok()?;
    if out.status != Some(0) {
        return None;
    }
    let (mut server, mut panes) = (None, BTreeMap::new());
    for l in out.stdout.lines() {
        let f: Vec<&str> = l.split('\t').collect();
        let (pid, start, pane, info) = match f.as_slice() {
            [pid, start, pane] => (
                pid,
                start,
                pane,
                PaneInfo {
                    pid: None,
                    command: String::new(),
                },
            ),
            [pid, start, pane, ppid, cmd] => (
                pid,
                start,
                pane,
                PaneInfo {
                    pid: ppid.parse().ok(),
                    command: (*cmd).to_string(),
                },
            ),
            _ => continue,
        };
        if digits(pid) && digits(start) && crate::agent_sessions::valid_pane_id(pane) {
            server = Some(format!("{pid}:{start}"));
            panes.insert((*pane).to_string(), info);
        }
    }
    server.map(|s| (s, panes))
}

/// A pane whose foreground is a shell this long has lost its agent (it crashed or was killed and the shell came back): the
/// sweep runs once a minute, so this is three looks in a row. A shell in front for a moment is normal (a window that is just
/// being started), so one look is never enough.
pub const SHELL_GRACE_MS: u64 = 180_000;

fn is_shell(command: &str) -> bool {
    matches!(
        command.trim_start_matches('-'),
        "bash" | "zsh" | "sh" | "dash" | "fish" | "ksh" | "tcsh" | "csh"
    )
}

/// When the box started, in seconds since the epoch (`btime` in `/proc/stat`); none where that is not readable.
pub fn boot_time_secs() -> Option<u64> {
    fs::read_to_string("/proc/stat")
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix("btime ")?.trim().parse().ok())
}

/// What one sweep needs besides tmux and the records.
pub struct SweepOptions<'a> {
    pub now_ms: u64,
    /// When this boot began. A record of a tmux server that began **before** it is the previous boot's, and is the boot step's to
    /// reopen, never the sweep's. Unknown means no record of a server that is gone is removed.
    pub boot_secs: Option<u64>,
    /// Pass a map to remove the record of an agent that crashed back to a shell (the long-lived daemon does; a hook or the boot
    /// step, which see the pane once, do not): record name to when its pane was first seen showing a shell.
    pub watch_shells: Option<&'a mut BTreeMap<String, u64>>,
    /// True once the daemon has been told to stop: no sweep starts, and none goes on, after that.
    pub stop: &'a dyn Fn() -> bool,
}

/// Remove the record of every agent that is gone while the box runs: its tmux window was closed, its tmux server ended in this
/// boot (`kill-server`, an out-of-memory kill of the server), or (with `watch_shells`) the agent died and left a shell in its
/// pane for [`SHELL_GRACE_MS`] with no Claude Code anywhere below the pane's process. **Never while the system may be stopping**
/// ([`system_may_be_stopping`], fail closed): a shutdown ends every pane and the records are what the next boot needs. The
/// records are read **before** tmux is asked, so a session that starts in between keeps the record it writes; and each record is
/// read again just before it goes, and is kept if it moved. Returns how many were removed.
///
/// A server is called ended only on **positive evidence about that server**: the process the record names is gone, or is not
/// tmux (`procs`), and it began after this boot did. What `list-panes` answers says only what the caller's own socket holds, so
/// it is never taken to mean that another server (`tmux -L name`) ended. Unknown means keep.
pub fn sweep(
    runner: &dyn CommandRunner,
    procs: &dyn Procs,
    dir: &Path,
    root: &str,
    mut opts: SweepOptions<'_>,
) -> usize {
    if (opts.stop)() || system_may_be_stopping(runner) {
        return 0;
    }
    let (records, _) = load_records(dir, root);
    let view = live_panes(runner);
    let ended_in_this_boot = |r: &SessionRecord| {
        let mut parts = r.server().split(':');
        let pid: Option<u32> = parts.next().and_then(|p| p.parse().ok());
        let start: Option<u64> = parts.next().and_then(|s| s.parse().ok());
        matches!((opts.boot_secs, start), (Some(b), Some(s)) if s >= b)
            && pid.is_some_and(|p| procs.tmux_alive(p) == Some(false))
    };
    let mut gone: Vec<&SessionRecord> = Vec::new();
    let mut shelled_now: BTreeSet<String> = BTreeSet::new();
    for r in &records {
        match &view {
            Some((server, panes)) if r.server() == server => match panes.get(r.pane()) {
                None => gone.push(r),
                Some(p) if is_shell(&p.command) => {
                    if let Some(map) = opts.watch_shells.as_deref_mut() {
                        let since = *map.entry(r.file_name()).or_insert(opts.now_ms);
                        shelled_now.insert(r.file_name());
                        // a wrapper script that did not `exec` the agent, or an agent stopped with Ctrl-Z, also leaves a shell in
                        // front: only a pane with no Claude Code below its process has lost its agent
                        if opts.now_ms.saturating_sub(since) >= SHELL_GRACE_MS
                            && p.pid
                                .is_some_and(|pp| procs.claude_below(pp) == Some(false))
                        {
                            gone.push(r);
                        }
                    }
                }
                Some(_) => {}
            },
            // another server: the previous boot's (the boot step reopens it), one still alive (a different socket), or one that
            // ended in this boot
            _ => {
                if ended_in_this_boot(r) {
                    gone.push(r);
                }
            }
        }
    }
    if let Some(map) = opts.watch_shells.as_deref_mut() {
        map.retain(|k, _| shelled_now.contains(k));
    }
    let mut removed = 0;
    for r in gone {
        // asked again at the last moment: a stop that began while the list was read must not erase anything
        if (opts.stop)() || system_may_be_stopping(runner) {
            return removed;
        }
        // and the record is read again: one that moved to another pane meanwhile (a resumed window's `follow`) stays
        if read_one(&dir.join(r.file_name()), root).is_ok_and(|now| now.place == r.place) {
            remove_record(dir, &r.engine, &r.session_id);
            removed += 1;
        }
    }
    removed
}

/// [`sweep`] as a hook or the boot step runs it: no shell watching, and no stop flag (they are short-lived processes).
pub fn sweep_gone(runner: &dyn CommandRunner, dir: &Path, root: &str) -> usize {
    sweep(
        runner,
        &ProcFs,
        dir,
        root,
        SweepOptions {
            now_ms: now_ms(),
            boot_secs: boot_time_secs(),
            watch_shells: None,
            stop: &|| false,
        },
    )
}

/// A `SessionEnd`: remove the record when the person ended the session (`/exit`, `/clear`, a logout). Any other reason, and
/// any end while the system is stopping, leaves it.
pub fn end_from_hook(runner: &dyn CommandRunner, dir: &Path, engine: &str, payload: &Value) {
    let reason = payload.get("reason").and_then(Value::as_str).unwrap_or("");
    if !ENDED_BY_PERSON.contains(&reason) {
        return;
    }
    let Some(id) = payload.get(id_key(engine)).and_then(Value::as_str) else {
        return;
    };
    if system_may_be_stopping(runner) {
        return;
    }
    remove_record(dir, engine, id);
}

/// The one off switch for everything in ADR 0049: while this file exists, the record hooks write nothing, the daemon and the boot
/// step install no unit and no hook and sweep nothing, and nothing is reopened. `touch ~/.config/ozbox/session-resume.off`.
pub fn off_switch(home: &Path) -> PathBuf {
    home.join(".config/ozbox/session-resume.off")
}

pub fn resume_off(home: &Path) -> bool {
    fs::symlink_metadata(off_switch(home)).is_ok()
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
}

/// The processes around a hook, so who owns a pane can be told without guessing (and tested without a Linux box).
pub trait Procs {
    /// The parent of a process; none when it is gone or this host cannot say.
    fn parent(&self, pid: u32) -> Option<u32>;
    /// Does the process look like the Claude Code program (its name, or the script or program it was started with)?
    fn is_claude(&self, pid: u32) -> bool;
    /// Was it started in print mode (`claude -p` / `--print`): one question, one answer, no one at the keyboard?
    fn print_mode(&self, pid: u32) -> bool;
    /// Is this pid a tmux server still? `Some(false)` is positive evidence that it is gone (no such process, or another program
    /// that reused the number); `None` is "cannot tell" (no `/proc`), which is never taken as gone.
    fn tmux_alive(&self, pid: u32) -> Option<bool>;
    /// Is there a Claude Code anywhere below this process? `None` when the process table cannot be read.
    fn claude_below(&self, pid: u32) -> Option<bool>;
}

/// `/proc`.
pub struct ProcFs;

impl ProcFs {
    fn args(pid: u32) -> Vec<String> {
        fs::read(format!("/proc/{pid}/cmdline"))
            .map(|b| {
                b.split(|c| *c == 0)
                    .filter(|a| !a.is_empty())
                    .map(|a| String::from_utf8_lossy(a).into_owned())
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl Procs for ProcFs {
    fn parent(&self, pid: u32) -> Option<u32> {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        // `pid (comm) S ppid ...`: comm may hold spaces and brackets, so the end of it is the last `)`
        let rest = stat.rsplit_once(") ")?.1;
        rest.split(' ').nth(1)?.parse().ok()
    }
    fn is_claude(&self, pid: u32) -> bool {
        let comm = fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
        let exe = fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|p| p.to_string_lossy().into_owned());
        looks_like_claude(comm.trim(), exe.as_deref(), &Self::args(pid))
    }
    fn print_mode(&self, pid: u32) -> bool {
        Self::args(pid)
            .iter()
            .skip(1)
            .any(|a| a == "-p" || a == "--print")
    }
    fn tmux_alive(&self, pid: u32) -> Option<bool> {
        if !Path::new("/proc/self").exists() {
            return None;
        }
        match fs::read_to_string(format!("/proc/{pid}/comm")) {
            // the server is `tmux: server`; a client is `tmux: client`; a pid some other program now holds is not tmux
            Ok(c) => Some(c.starts_with("tmux")),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Some(false),
            Err(_) => None,
        }
    }
    fn claude_below(&self, pid: u32) -> Option<bool> {
        let mut kids: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
        for e in fs::read_dir("/proc").ok()?.flatten() {
            let Some(p) = e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
                continue;
            };
            if let Some(up) = self.parent(p) {
                kids.entry(up).or_default().push(p);
            }
        }
        let (mut todo, mut seen) = (vec![pid], 0usize);
        while let Some(at) = todo.pop() {
            for k in kids.get(&at).into_iter().flatten() {
                seen += 1;
                if seen > 20_000 {
                    return None;
                }
                if self.is_claude(*k) {
                    return Some(true);
                }
                todo.push(*k);
            }
        }
        Some(false)
    }
}

/// Does a process look like the Claude Code program? By its name (`comm`), by the file it runs (`/proc/<pid>/exe`: a native
/// install started by its resolved path, `.../claude/versions/<ver>`, has the version as its name), or by the program it was
/// started as (`argv[0]`, or one of the next two, ending in `claude`). A script path with `/claude-code/` in it counts only as the
/// script of a `node` or `bun` process (the npm install): a shell whose command line merely names a folder of that name is not it.
pub fn looks_like_claude(comm: &str, exe: Option<&str>, args: &[String]) -> bool {
    let last = |p: &str| p.rsplit('/').next().map(str::to_string);
    if comm == "claude" {
        return true;
    }
    if exe.is_some_and(|e| last(e).as_deref() == Some("claude") || e.contains("/claude/versions/"))
    {
        return true;
    }
    if args
        .iter()
        .take(3)
        .any(|a| last(a).as_deref() == Some("claude"))
    {
        return true;
    }
    let runtime = |p: &str| matches!(last(p).as_deref(), Some("node" | "bun"));
    let is_runtime = comm == "node"
        || comm == "bun"
        || exe.is_some_and(runtime)
        || args.first().is_some_and(|a| runtime(a));
    // the script is the first argument that is not a flag
    is_runtime
        && args
            .iter()
            .skip(1)
            .find(|a| !a.starts_with('-'))
            .is_some_and(|script| script.contains("/claude-code/"))
}

#[derive(Debug, PartialEq, Eq)]
pub enum Ownership {
    /// The hook's Claude Code is the interactive session of the pane.
    Owns,
    /// Another Claude Code sits between this one and the pane: this one was started by an agent (its Bash tool, a script).
    Nested,
    /// Started in print mode: a one-shot, not a conversation anyone would come back to.
    PrintMode,
    /// The hook does not descend from the pane's own process.
    NotInPane,
    /// The process table cannot be read: nothing is concluded, and the record is written as before.
    Unknown,
}

/// Is the Claude Code that ran this hook the one that owns the pane? Walk the parents from the hook up to the pane's own
/// process (`#{pane_pid}`). Claude Code programs are counted by **separated groups**: a wrapper script and the program it starts
/// are adjacent and are one; a Claude Code that an agent started from its own shell has that shell between them, and is
/// another. A `claude -p` inherits `TMUX_PANE` and the same settings, so without this it would replace the pane's record with a
/// one-shot session, and the next boot would reopen that instead of the conversation.
pub fn pane_ownership(procs: &dyn Procs, hook_pid: u32, pane_pid: u32) -> Ownership {
    let Some(mut p) = procs.parent(hook_pid) else {
        return Ownership::Unknown;
    };
    let mut chain = Vec::new();
    for _ in 0..64 {
        chain.push(p);
        if p == pane_pid {
            break;
        }
        match procs.parent(p) {
            Some(up) if up > 1 && up != p => p = up,
            _ => return Ownership::NotInPane,
        }
    }
    if chain.last() != Some(&pane_pid) {
        return Ownership::NotInPane;
    }
    let mut groups: Vec<Vec<u32>> = Vec::new();
    let mut prev_claude = false;
    for pid in &chain {
        let c = procs.is_claude(*pid);
        if c {
            match groups.last_mut() {
                Some(g) if prev_claude => g.push(*pid),
                _ => groups.push(vec![*pid]),
            }
        }
        prev_claude = c;
    }
    if groups.len() > 1 {
        return Ownership::Nested;
    }
    let mine: Vec<u32> = groups.pop().unwrap_or_else(|| vec![chain[0]]);
    if mine.iter().any(|pid| procs.print_mode(*pid)) {
        return Ownership::PrintMode;
    }
    Ownership::Owns
}

/// One record-making event: where the pane is, whether this Claude Code owns it, then the write. Returns whether a record was
/// written or kept current.
#[allow(clippy::too_many_arguments)]
pub fn record_event(
    runner: &dyn CommandRunner,
    procs: &dyn Procs,
    dir: &Path,
    pane: &str,
    hook_pid: u32,
    engine: &str,
    payload: &Value,
    cwd: &str,
    now: u64,
) -> bool {
    let Some(place) = current_place(runner, pane) else {
        return false;
    };
    if engine == "claude-code"
        && !matches!(
            pane_ownership(procs, hook_pid, place.pane_pid),
            Ownership::Owns | Ownership::Unknown
        )
    {
        return false;
    }
    match record_from_event(engine, payload, cwd, &place, now, WORK_ROOT) {
        Some(rec) => write_record(dir, WORK_ROOT, &rec, false).is_ok(),
        None => false,
    }
}

/// Called by every hook of the record, before anything else. Best effort and silent: an agent outside tmux, a full disk or a
/// missing tmux is no record and never an error.
pub fn note_from_hook(runner: &dyn CommandRunner, engine: &str, payload: &Value, cwd: &str) {
    if home_dir().is_some_and(|h| resume_off(&h)) {
        return;
    }
    let Some(dir) = records_dir() else { return };
    let event = payload
        .get("hook_event_name")
        .and_then(Value::as_str)
        .unwrap_or("");
    if event == "SessionEnd" {
        end_from_hook(runner, &dir, engine, payload);
        return;
    }
    let Some(pane) = std::env::var("TMUX_PANE").ok().filter(|p| !p.is_empty()) else {
        return;
    };
    let wrote = record_event(
        runner,
        &ProcFs,
        &dir,
        &pane,
        std::process::id(),
        engine,
        payload,
        cwd,
        now_ms(),
    );
    if wrote && event == "SessionStart" {
        // a session starts rarely: the moment to forget the records of windows that were closed
        sweep_gone(runner, &dir, WORK_ROOT);
    }
}

// ---- the resume ----

/// The engine's own command for reopening a session, where that is proven. Unproven means `None`, which the plan shows as
/// "resume not supported for <engine>".
///
/// * `claude-code`: `claude --resume <id>`, the same flag the supervised runs use (`ozbox_core::claude_code`). The id starts
///   with a letter or digit, so it can never be read as a flag.
/// * `codex`: the CLI documents `codex resume <session id>`, but that its notify `thread-id` is that session id has not been
///   confirmed, so it is not used until it has.
/// * `gemini`, `aider`, `opencode`, `goose`: resume by id is not confirmed.
pub fn resume_argv(engine: &str, session_id: &str) -> Option<Vec<String>> {
    match engine {
        "claude-code" if valid_session_id(session_id) => {
            Some(vec!["claude".into(), "--resume".into(), session_id.into()])
        }
        _ => None,
    }
}

pub const OFFER: &str = "Oz Box brought this session back after the box restarted. What was running when it stopped has ended: the turn in flight, background programs such as dev servers, shell variables and scrollback, and any permission question that was waiting. Nothing has been sent to the agent. If it was in the middle of something, tell it to continue.";

fn unsupported_notice(engine: &str) -> String {
    format!(
        "Oz Box recreated this window after the box restarted, but resume is not supported for {engine}: its conversation was not reopened. Start it again here."
    )
}

fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// The one string tmux runs in the new window: an interactive login shell (so a `claude` put on the path by the person's own
/// profile, nvm or a user prefix is found) that goes to the folder, prints the line, runs the engine's resume (if any and if
/// the program is there), and then stays as a shell, so a resume that fails leaves its error on the screen. Every value is a
/// quoted positional argument; the folder is never given to tmux itself.
pub fn window_command(engine: &str, session_id: &str, folder: &str) -> String {
    let (notice, argv) = match resume_argv(engine, session_id) {
        Some(a) => (OFFER.to_string(), a),
        None => (unsupported_notice(engine), Vec::new()),
    };
    let script = concat!(
        "cd -- \"$1\" || exit 1; shift; ",
        "PATH=\"$PATH:$HOME/.local/bin:$HOME/.claude/local:$HOME/.npm-global/bin:/usr/local/bin\"; export PATH; ",
        "printf '%s\\n' \"$1\"; shift; ",
        "if [ \"$#\" -gt 0 ]; then ",
        "if command -v \"$1\" >/dev/null 2>&1; then \"$@\"; ",
        "else printf 'Oz Box could not find %s on the path, so the session was not reopened.\\n' \"$1\"; fi; fi; ",
        "exec /bin/bash -l"
    );
    let mut parts = vec![
        "/bin/bash".to_string(),
        "-lic".into(),
        script.into(),
        "ozbox-resume".into(),
        folder.to_string(),
        notice,
    ];
    parts.extend(argv);
    parts
        .iter()
        .map(|p| sh_quote(p))
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// `true` when the tmux session does not exist yet (`new-session`), `false` for `new-window` into an existing one.
    pub new_session: bool,
    pub tmux_session: String,
    pub window_name: String,
    pub command: String,
    pub record: SessionRecord,
    pub supported: bool,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Plan {
    pub steps: Vec<Step>,
    pub notes: Vec<String>,
    /// Records to remove: too old, or the folder has been gone past its grace, or superseded by a newer record of the same pane.
    pub forget: Vec<SessionRecord>,
}

/// From the records to the windows to make. Pure: `live_server` is the running tmux server's `<pid>:<start>` (none when there
/// is no server), `live_sessions` the names of its sessions, `folder_exists` the filesystem, `now_ms` the clock.
pub fn plan(
    records: &[SessionRecord],
    live_server: Option<&str>,
    live_sessions: &BTreeSet<String>,
    folder_exists: &dyn Fn(&str) -> bool,
    now_ms: u64,
    max_reopen: usize,
) -> Plan {
    let mut p = Plan::default();
    // newest first: the newest record of a pane wins, and the cap keeps the most recently used
    let mut newest: Vec<&SessionRecord> = records.iter().collect();
    newest.sort_by(|a, b| (b.last_seen_ms, &a.session_id).cmp(&(a.last_seen_ms, &b.session_id)));
    let (mut places, mut kept, mut over, mut folderless) =
        (BTreeSet::new(), Vec::new(), 0usize, 0usize);
    for r in newest {
        if live_server.is_some_and(|s| !s.is_empty() && r.server() == s) {
            continue; // the agent is still alive in the tmux server that is running
        }
        let age = now_ms.saturating_sub(r.last_seen_ms);
        if age > MAX_AGE_MS || !places.insert(r.place.clone()) {
            p.forget.push(r.clone());
            continue;
        }
        if !folder_exists(&r.folder) {
            if age > FOLDER_GONE_GRACE_MS {
                p.forget.push(r.clone());
            } else {
                folderless += 1;
            }
            continue;
        }
        if kept.len() >= max_reopen {
            over += 1;
            continue;
        }
        kept.push(r);
    }
    if folderless > 0 {
        p.notes.push(format!(
            "not reopening {folderless} session(s): the folder is gone"
        ));
    }
    if over > 0 {
        p.notes.push(format!(
            "{over} more session(s) were not reopened: at most {max_reopen} come back at one boot, so the box is not out of memory while it starts"
        ));
    }
    kept.sort_by(|a, b| {
        (&a.tmux_session, a.window_index, &a.session_id).cmp(&(
            &b.tmux_session,
            b.window_index,
            &b.session_id,
        ))
    });
    let mut known = live_sessions.clone();
    for r in kept {
        // already plain when read from a record; made plain again here so no path to tmux depends on that
        let name = match safe_name(&r.tmux_session) {
            n if n.is_empty() => "agent".to_string(),
            n => n,
        };
        let new_session = !known.contains(&name);
        known.insert(name.clone());
        let supported = resume_argv(&r.engine, &r.session_id).is_some();
        let window = match safe_name(&r.window_name) {
            n if n.is_empty() => safe_name(&r.engine),
            n => n,
        };
        p.steps.push(Step {
            new_session,
            tmux_session: name,
            window_name: window,
            command: window_command(&r.engine, &r.session_id, &r.folder),
            record: r.clone(),
            supported,
        });
    }
    p
}

/// The tmux command for one step, as an argument list. The only values tmux itself reads are the plain session and window
/// names (no `#`), the exact-match target `=name:` and our own `-F` format; the folder is inside the quoted command.
pub fn tmux_args(s: &Step) -> Vec<String> {
    let mut a: Vec<String> = Vec::new();
    if s.new_session {
        a.extend(["new-session", "-d", "-s"].map(String::from));
        a.push(s.tmux_session.clone());
    } else {
        a.extend(["new-window", "-d", "-t"].map(String::from));
        a.push(format!("={}:", s.tmux_session));
    }
    a.push("-n".into());
    a.push(s.window_name.clone());
    a.extend(["-P", "-F"].map(String::from));
    a.push(PLACE_FORMAT.to_string());
    a.push(s.command.clone());
    a
}

fn tmux_spec(s: &Step) -> CommandSpec {
    let mut cmd = CommandSpec::new("tmux");
    cmd.args = tmux_args(s);
    cmd
}

/// The same tmux command, started in a scope of its own (`systemd-run --user --scope`), so the server and the panes under it
/// are not inside the resume service's cgroup. Named with the prefix ADR 0045's drop-in covers.
fn scoped_spec(unit: &str, s: &Step) -> CommandSpec {
    let mut cmd = CommandSpec::new("systemd-run");
    cmd.args = ["--user", "--scope", "--quiet", "--collect"]
        .map(String::from)
        .into();
    cmd.args.push(format!("--unit={unit}"));
    cmd.args.push("--".into());
    cmd.args.push("tmux".into());
    cmd.args.extend(tmux_args(s));
    cmd
}

fn live_tmux(runner: &dyn CommandRunner) -> (Option<String>, BTreeSet<String>) {
    let sessions = runner.run(
        &CommandSpec::new("tmux")
            .arg("list-sessions")
            .arg("-F")
            .arg("#{session_name}\t#{pid}\t#{start_time}"),
    );
    let Ok(out) = sessions.map(|o| (o.status, o.stdout)) else {
        return (None, BTreeSet::new());
    };
    if out.0 != Some(0) {
        return (None, BTreeSet::new());
    }
    let (mut server, mut names) = (None, BTreeSet::new());
    for l in out.1.lines() {
        let f: Vec<&str> = l.split('\t').collect();
        if let [name, pid, start] = f.as_slice() {
            // a session whose own name is not plain cannot be targeted safely: it is not "known", so a plain-named session
            // is made instead of a window being added to it
            if is_clean_name(name) {
                names.insert((*name).to_string());
            }
            server = Some(format!("{pid}:{start}"));
        }
    }
    (server, names)
}

/// Remove the temporary files of writes a power cut interrupted.
fn clean_temp_files(dir: &Path) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let name = e.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') && name.contains(".tmp-") {
            let old = e
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| SystemTime::now().duration_since(t).ok())
                .is_some_and(|age| age > TEMP_MAX_AGE);
            if old {
                let _ = fs::remove_file(e.path());
            }
        }
    }
}

/// After a window was made: the record follows the session to its new pane. Not a "seen" (its time is kept, so an agent
/// nobody uses still ages out), and not a prune: if the resumed agent already wrote a record of its own for this pane (its
/// first event can land before tmux returns, and `--resume` may give it a new id), that one is newer and this old one is
/// dropped instead of being written over it.
fn follow(dir: &Path, root: &str, old: &SessionRecord, place: &TmuxPlace) {
    let new_place = place.place();
    let (all, _) = load_records(dir, root);
    if all
        .iter()
        .any(|r| r.place == new_place && (r.session_id != old.session_id || r.engine != old.engine))
    {
        remove_record(dir, &old.engine, &old.session_id);
        return;
    }
    let mut rec = old.clone();
    rec.tmux_session = place.session.clone();
    rec.window_name = place.window_name.clone();
    rec.window_index = place.window_index;
    rec.place = new_place;
    let _ = write_file(dir, &rec);
}

/// Reopen every recorded session that is not alive. Returns one line per outcome (engine and tmux session only).
pub fn resume_all(runner: &dyn CommandRunner, dir: &Path, root: &str, now_ms: u64) -> Vec<String> {
    clean_temp_files(dir);
    let (records, mut said) = load_records(dir, root);
    let (server, sessions) = live_tmux(runner);
    let plan = plan(
        &records,
        server.as_deref(),
        &sessions,
        &|f| {
            // a symlink out of /work does not make a folder acceptable
            fs::canonicalize(f)
                .ok()
                .and_then(|c| c.to_str().map(|c| c.to_string()))
                .is_some_and(|c| under(&c, root) || under(&c, &canonical_root(root)))
        },
        now_ms,
        MAX_REOPEN,
    );
    said.extend(plan.notes);
    for r in &plan.forget {
        remove_record(dir, &r.engine, &r.session_id);
    }
    // the first server of this boot starts in a scope of its own, which is what puts it under the memory guard (ADR 0045)
    let mut scope_pending = server.is_none();
    for s in plan.steps {
        let out = if scope_pending && s.new_session {
            let unit = format!("{SCOPE_PREFIX}{now_ms}");
            match runner.run(&scoped_spec(&unit, &s)) {
                Ok(o) if o.status == Some(0) => Ok(o),
                _ => {
                    said.push("tmux could not be started in a scope of its own; started inside the resume service".into());
                    runner.run(&tmux_spec(&s))
                }
            }
        } else {
            runner.run(&tmux_spec(&s))
        };
        match out {
            Ok(o) if o.status == Some(0) => {
                scope_pending = false;
                match parse_place(&o.stdout) {
                    Some(place) => {
                        follow(dir, root, &s.record, &place);
                        said.push(format!(
                            "{} in tmux session {}: {}",
                            s.record.engine,
                            place.session,
                            if s.supported {
                                "reopened with its own resume"
                            } else {
                                "window recreated, resume not supported for this engine"
                            }
                        ));
                    }
                    None => said.push(format!(
                        "{} in tmux session {}: window made, place unreadable",
                        s.record.engine, s.tmux_session
                    )),
                }
            }
            _ => said.push(format!(
                "{} in tmux session {}: tmux could not make the window",
                s.record.engine, s.tmux_session
            )),
        }
    }
    said
}

fn canonical_root(root: &str) -> String {
    fs::canonicalize(root)
        .ok()
        .and_then(|c| c.to_str().map(|c| c.to_string()))
        .unwrap_or_else(|| root.to_string())
}

// ---- the user unit ----

/// What the unit file says. `KillMode=process` is a safety net: the first tmux server starts in a scope of its own, and if a
/// scope cannot be made the server would otherwise die with the unit when it is restarted.
pub fn unit_text(binary: &str) -> String {
    format!(
        "[Unit]\n\
Description=Oz Box: bring the agent sessions back\n\
After=basic.target\n\
ConditionPathExists={binary}\n\
\n\
[Service]\n\
Type=oneshot\n\
RemainAfterExit=yes\n\
ExecStart={binary} session-resume\n\
KillMode=process\n\
TimeoutStartSec=120\n\
\n\
[Install]\n\
WantedBy=default.target\n"
    )
}

#[derive(Debug, PartialEq, Eq)]
pub enum UnitOutcome {
    Installed,
    AlreadyThere,
    /// The person masked or replaced the unit with a link of their own: that is how it is turned off, and it stays off.
    LeftAlone,
}

/// Proof that the first install enabled the unit: from then on, a missing link is the person's own `disable`.
fn enabled_marker(home: &Path) -> PathBuf {
    home.join(".local/state/ozbox/session-resume-enabled")
}

/// Put the user unit in the box user's own systemd folder (`~/.config/systemd/user`, on `/work`) and enable it, the way
/// `systemctl --user enable` would: a link in `default.target.wants`. Written by the daemon, as the box user, so a box made
/// before this release gets it too at its next start, with no root helper and no first-boot template. It takes effect at the
/// next start of the box user's manager, which is when it is needed. Idempotent.
pub fn install_user_unit(home: &Path, binary: &str) -> io::Result<UnitOutcome> {
    let binary = if binary
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "/._-".contains(c))
        && binary.starts_with('/')
    {
        binary
    } else {
        "/usr/local/bin/ozboxd"
    };
    let base = home.join(".config/systemd/user");
    fs::create_dir_all(&base)?;
    let unit = base.join(UNIT_NAME);
    let mut changed = false;
    match fs::symlink_metadata(&unit) {
        Ok(m) if m.file_type().is_symlink() => return Ok(UnitOutcome::LeftAlone),
        Ok(m) if !m.is_file() => return Ok(UnitOutcome::LeftAlone),
        Ok(_) if fs::read_to_string(&unit).ok().as_deref() == Some(unit_text(binary).as_str()) => {}
        _ => {
            let tmp = base.join(format!(".{UNIT_NAME}.tmp-{}", std::process::id()));
            fs::write(&tmp, unit_text(binary))?;
            fs::rename(&tmp, &unit)?;
            changed = true;
        }
    }
    let wants = base.join("default.target.wants");
    fs::create_dir_all(&wants)?;
    let link = wants.join(UNIT_NAME);
    let target = PathBuf::from("..").join(UNIT_NAME);
    match fs::read_link(&link) {
        Ok(t) if t == target => {}
        Ok(_) => return Ok(UnitOutcome::LeftAlone),
        Err(_) if fs::symlink_metadata(&link).is_ok() => return Ok(UnitOutcome::LeftAlone),
        // no link: the first install makes it, and only the first. After that a missing link is the person's `systemctl --user
        // disable`, and it stays disabled (a marker says the first install happened)
        Err(_) if enabled_marker(home).exists() => {}
        Err(_) => {
            std::os::unix::fs::symlink(&target, &link)?;
            changed = true;
        }
    }
    // written whenever the link is there, so a box that had it before this marker existed is also treated as installed
    if fs::read_link(&link).is_ok() && !enabled_marker(home).exists() {
        let m = enabled_marker(home);
        if let Some(parent) = m.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&m, b"")?;
    }
    Ok(if changed {
        UnitOutcome::Installed
    } else {
        UnitOutcome::AlreadyThere
    })
}

/// The path hooks and the unit name for this program: where it is running from, without the " (deleted)" Linux adds to a
/// binary that was replaced under a running process, and only if it is a plain absolute path; otherwise the fixed install path.
pub fn binary_path() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| {
            p.to_str()
                .map(|s| s.trim_end_matches(" (deleted)").to_string())
        })
        .filter(|b| {
            b.starts_with('/')
                && b.chars()
                    .all(|c| c.is_ascii_alphanumeric() || "/._-".contains(c))
        })
        .unwrap_or_else(|| "/usr/local/bin/ozboxd".to_string())
}

/// `ozboxd session-resume`: the record hooks first (so the next session is recorded), then the resume, then the sweep. Always
/// exits 0: a boot step that fails must not leave the user manager unhealthy.
pub fn main_session_resume() -> i32 {
    let runner = ozbox_core::SystemRunner;
    if home_dir().is_some_and(|h| resume_off(&h)) {
        println!("turned off (~/.config/ozbox/session-resume.off exists): nothing reopened, nothing changed");
        return 0;
    }
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        let bin = binary_path();
        for (engine, o) in crate::hook_cli::install_at_boot(&home, &bin) {
            println!("hooks, {engine}: {}", crate::hook_cli::outcome_word(&o));
        }
    }
    match records_dir() {
        Some(dir) => {
            for line in resume_all(&runner, &dir, WORK_ROOT, now_ms()) {
                println!("{line}");
            }
            // no sweep here: this step runs inside the user manager's own start job, which says `starting`, so the sweep's
            // fail-closed check could never pass. The minute sweep in the daemon and the hooks do that work.
        }
        None => println!("no home folder, so there are no sessions to reopen"),
    }
    0
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ozbox_core::{Output, RecordingRunner};
    use serde_json::json;
    use std::sync::Mutex;

    const ROOT: &str = "/work";
    const ID1: &str = "11111111-1111-4111-8111-111111111111";
    const ID2: &str = "22222222-2222-4222-8222-222222222222";
    const ID3: &str = "33333333-3333-4333-8333-333333333333";

    fn place(server: &str, pane: &str) -> TmuxPlace {
        TmuxPlace {
            session: "work".into(),
            window_index: 1,
            window_name: "claude".into(),
            pane_id: pane.into(),
            server: server.into(),
            pane_pid: 5,
        }
    }

    fn rec(engine: &str, id: &str, server: &str, pane: &str, at: u64) -> SessionRecord {
        record_from_event(
            engine,
            &json!({ "session_id": id, "cwd": "/work/repos/web" }),
            "/work/x",
            &place(server, pane),
            at,
            ROOT,
        )
        .unwrap()
    }

    fn ok(stdout: &str) -> Output {
        Output {
            status: Some(0),
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    fn fail() -> Output {
        Output {
            status: Some(1),
            ..Output::default()
        }
    }

    /// A runner that answers by what was asked, so a test reads as the box's situation and not as a queue.
    struct Scripted {
        calls: Mutex<Vec<CommandSpec>>,
        answer: Box<dyn Fn(&CommandSpec) -> Output + Send + Sync>,
    }
    impl Scripted {
        fn new(f: impl Fn(&CommandSpec) -> Output + Send + Sync + 'static) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                answer: Box::new(f),
            }
        }
        fn calls(&self) -> Vec<CommandSpec> {
            self.calls.lock().unwrap().clone()
        }
    }
    impl CommandRunner for Scripted {
        fn run(&self, c: &CommandSpec) -> ozbox_core::Result<Output> {
            self.calls.lock().unwrap().push(c.clone());
            Ok((self.answer)(c))
        }
    }

    fn mentions(c: &CommandSpec, what: &str) -> bool {
        c.args.iter().any(|a| a == what)
    }

    #[test]
    fn a_record_holds_only_the_named_fields_never_a_prompt_a_transcript_or_a_secret() {
        let payload = json!({
            "session_id": ID1, "cwd": "/work/repos/web", "hook_event_name": "UserPromptSubmit",
            "prompt": "deploy with key hunter2-SECRETSECRET", "transcript_path": "/work/home/ozbox/.claude/projects/x.jsonl",
            "tool_input": { "command": "echo TOKEN=abc" }
        });
        let r =
            record_from_event("claude-code", &payload, "/x", &place("1:2", "%3"), 5, ROOT).unwrap();
        let text = serde_json::to_string(&r).unwrap();
        for bad in [
            "SECRET",
            "hunter2",
            "transcript",
            "TOKEN",
            "deploy",
            "prompt",
        ] {
            assert!(!text.contains(bad), "{bad} leaked into {text}");
        }
        let keys: BTreeSet<String> = serde_json::from_str::<serde_json::Map<String, Value>>(&text)
            .unwrap()
            .keys()
            .cloned()
            .collect();
        let want: BTreeSet<String> = [
            "v",
            "engine",
            "session_id",
            "folder",
            "tmux_session",
            "window_name",
            "window_index",
            "place",
            "last_seen_ms",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(keys, want);
        assert_eq!(r.place, "1:2:%3");
    }

    #[test]
    fn an_event_without_a_usable_id_or_a_folder_under_work_makes_no_record() {
        let p = place("1:2", "%3");
        let mk = |payload: Value, cwd: &str| {
            record_from_event("claude-code", &payload, cwd, &p, 1, ROOT)
        };
        assert!(mk(json!({}), "/work/x").is_none());
        assert!(mk(json!({"session_id": "a/../b"}), "/work/x").is_none());
        assert!(mk(json!({"session_id": ID1, "cwd": "/work/a/../b"}), "rel").is_none());
        // a folder outside /work is not recorded, and neither is a sibling that only shares the prefix
        assert!(mk(json!({"session_id": ID1, "cwd": "/etc"}), "/tmp/x").is_none());
        assert!(mk(
            json!({"session_id": ID1, "cwd": "/workshop/x"}),
            "/workshop/x"
        )
        .is_none());
        // an id that would be read as a flag is not recorded
        assert!(mk(
            json!({"session_id": "--dangerously-skip-permissions"}),
            "/work/x"
        )
        .is_none());
        let c = record_from_event("codex", &json!({"thread-id": "t1"}), "/work/w", &p, 1, ROOT)
            .unwrap();
        assert_eq!(c.session_id, "t1");
    }

    #[test]
    fn a_write_is_atomic_leaves_no_temporary_file_and_is_private() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("s");
        let r = rec("claude-code", ID1, "1:2", "%3", 100);
        assert_eq!(write_record(&dir, ROOT, &r, false).unwrap(), Wrote::Written);
        let names: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec![format!("claude-code-{ID1}.json")]);
        {
            use std::os::unix::fs::PermissionsExt;
            let m = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(m(&dir), 0o700);
            assert_eq!(m(&dir.join(format!("claude-code-{ID1}.json"))), 0o600);
        }
        // a failed write (the temp name is taken by a directory) leaves the old record whole
        let blocker = dir.join(format!(
            ".claude-code-{ID1}.json.tmp-{}",
            std::process::id()
        ));
        fs::create_dir(&blocker).unwrap();
        let mut newer = r.clone();
        newer.window_name = "other".into();
        assert!(write_record(&dir, ROOT, &newer, false).is_err());
        assert_eq!(load_records(&dir, ROOT).0, vec![r]);
    }

    #[test]
    fn a_touch_is_skipped_until_it_is_old_and_the_first_folder_is_kept() {
        let d = tempfile::tempdir().unwrap();
        let r = rec("claude-code", ID1, "1:2", "%3", 1_000);
        write_record(d.path(), ROOT, &r, false).unwrap();
        let mut later = r.clone();
        later.last_seen_ms = 1_000 + TOUCH_EVERY_MS - 1;
        later.folder = "/work/repos/elsewhere".into();
        assert_eq!(
            write_record(d.path(), ROOT, &later, false).unwrap(),
            Wrote::Unchanged
        );
        later.last_seen_ms = 1_000 + TOUCH_EVERY_MS;
        assert_eq!(
            write_record(d.path(), ROOT, &later, false).unwrap(),
            Wrote::Written
        );
        let (all, said) = load_records(d.path(), ROOT);
        assert!(said.is_empty());
        assert_eq!(all[0].folder, "/work/repos/web", "the folder it started in");
        assert_eq!(all[0].last_seen_ms, 1_000 + TOUCH_EVERY_MS);
    }

    #[test]
    fn a_cleared_conversation_replaces_the_record_of_the_same_pane_and_two_panes_of_one_window_keep_two(
    ) {
        let d = tempfile::tempdir().unwrap();
        write_record(
            d.path(),
            ROOT,
            &rec("claude-code", ID1, "1:2", "%3", 1),
            false,
        )
        .unwrap();
        // a second agent in a split pane of the same window (same window, its own pane)
        write_record(
            d.path(),
            ROOT,
            &rec("claude-code", ID2, "1:2", "%4", 1),
            false,
        )
        .unwrap();
        // /clear in the first pane: a new session id in the same pane replaces the old record
        write_record(
            d.path(),
            ROOT,
            &rec("claude-code", ID3, "1:2", "%3", 2),
            false,
        )
        .unwrap();
        let ids: BTreeSet<String> = load_records(d.path(), ROOT)
            .0
            .into_iter()
            .map(|r| r.session_id)
            .collect();
        assert_eq!(ids, BTreeSet::from([ID2.to_string(), ID3.to_string()]));
    }

    #[test]
    fn a_corrupt_mismatched_linked_or_pipe_record_is_skipped_with_a_message_and_the_rest_load() {
        let d = tempfile::tempdir().unwrap();
        write_record(
            d.path(),
            ROOT,
            &rec("claude-code", ID1, "1:2", "%3", 1),
            false,
        )
        .unwrap();
        fs::write(d.path().join("claude-code-bad.json"), "{not json").unwrap();
        let liar = serde_json::to_string(&rec("claude-code", ID2, "1:2", "%9", 1)).unwrap();
        fs::write(d.path().join("claude-code-y.json"), liar).unwrap();
        fs::write(d.path().join("claude-code-huge.json"), vec![b' '; 20_000]).unwrap();
        fs::write(d.path().join(".claude-code-z.json.tmp-1"), "{").unwrap();
        // a symlink to a good record is not followed
        std::os::unix::fs::symlink(
            d.path().join(format!("claude-code-{ID1}.json")),
            d.path().join(format!("claude-code-{ID3}.json")),
        )
        .unwrap();
        // a named pipe is refused without blocking
        let fifo = d.path().join("claude-code-pipe.json");
        if std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .is_ok_and(|s| s.success())
        {
            let (ok_, said) = load_records(d.path(), ROOT);
            assert_eq!(ok_.len(), 1);
            assert_eq!(said.len(), 5, "{said:?}");
        } else {
            let (ok_, said) = load_records(d.path(), ROOT);
            assert_eq!(ok_.len(), 1);
            assert_eq!(said.len(), 4, "{said:?}");
        }
    }

    #[test]
    fn every_field_of_a_record_is_checked_on_read_hostile_names_and_places_are_refused() {
        let d = tempfile::tempdir().unwrap();
        let good = rec("claude-code", ID1, "1:2", "%3", 1);
        let try_ = |f: &dyn Fn(&mut SessionRecord)| {
            let mut r = good.clone();
            f(&mut r);
            let p = d.path().join(r.file_name());
            fs::write(&p, serde_json::to_string(&r).unwrap()).unwrap();
            let out = read_one(&p, ROOT);
            fs::remove_file(&p).unwrap();
            out.is_ok()
        };
        assert!(try_(&|_| {}));
        assert!(!try_(&|r| r.tmux_session = "#(touch /tmp/x)".into()));
        assert!(!try_(&|r| r.window_name = "#{pane_current_path}".into()));
        assert!(!try_(&|r| r.window_name = "a;b".into()));
        assert!(!try_(&|r| r.window_name = "x\ny".into()));
        assert!(!try_(&|r| r.tmux_session = "-s".into()));
        assert!(!try_(&|r| r.place = "1:2:@3".into()));
        assert!(!try_(&|r| r.place = "#(x):2:%3".into()));
        assert!(!try_(&|r| r.folder = "/etc".into()));
        assert!(!try_(&|r| r.folder = "/work/../etc".into()));
        assert!(!try_(&|r| r.folder = "/work/a\nb".into()));
    }

    #[test]
    fn what_a_window_is_called_can_never_reach_tmux_as_a_format() {
        for hostile in [
            "#(touch /tmp/ozbox-fmt-probe)",
            "#{pane_current_path}",
            "a\nb",
            "x;kill-server",
            "-s evil",
            "#",
            "##(x)",
            "$(id)",
            "a:b.c",
        ] {
            // as tmux reports it, then as a record that was edited by hand and slipped past a reader
            let line = format!("{hostile}\t@1\t0\t{hostile}\t9\t10\t%1\t5");
            let first = line.lines().next().unwrap_or("");
            if let Some(p) = parse_place(first) {
                assert!(
                    !p.session.contains('#') && !p.window_name.contains('#'),
                    "{hostile}"
                );
                assert!(!p.session.starts_with('-') && !p.window_name.starts_with('-'));
            }
            let mut r = rec("claude-code", ID1, "1:2", "%3", 1);
            r.tmux_session = hostile.into();
            r.window_name = hostile.into();
            let p = plan(&[r], None, &BTreeSet::new(), &|_| true, 2, MAX_REOPEN);
            let s = &p.steps[0];
            let args = tmux_args(s);
            let fi = args.iter().position(|a| a == "-F").unwrap();
            for (i, a) in args.iter().enumerate() {
                if i == fi + 1 || i == args.len() - 1 {
                    continue; // our own format, and the quoted window command
                }
                assert!(
                    !a.contains('#') && !a.contains('\n') && !a.contains(';'),
                    "{hostile}: {a}"
                );
            }
            assert!(!s.tmux_session.starts_with('-') && !s.window_name.starts_with('-'));
            // the target is an exact match and the folder is not an option of tmux at all
            assert!(!args.contains(&"-c".to_string()));
            // and the command string has nothing outside quotes: every word is single-quoted
            assert!(s.command.starts_with('\'') && s.command.ends_with('\''));
        }
    }

    #[test]
    fn a_folder_named_like_a_command_is_only_ever_a_quoted_argument_of_the_windows_own_script() {
        let mut r = rec("claude-code", ID1, "1:2", "%3", 1);
        // the folder rules refuse control characters and "..", but `#(`, quotes and `;` are legal in a folder name
        r.folder = "/work/repos/#(touch /tmp/ozbox-fmt-probe);'x".into();
        let p = plan(
            &[r.clone()],
            None,
            &BTreeSet::new(),
            &|_| true,
            2,
            MAX_REOPEN,
        );
        let args = tmux_args(&p.steps[0]);
        assert!(!args.iter().any(|a| a == "-c"));
        let outside: Vec<&String> = args[..args.len() - 1].iter().collect();
        assert!(outside.iter().all(|a| !a.contains("touch")), "{outside:?}");
        let cmd = &p.steps[0].command;
        assert!(cmd.contains("'cd -- \"$1\" || exit 1;"), "{cmd}");
        assert!(
            cmd.contains("'/work/repos/#(touch /tmp/ozbox-fmt-probe);'\\''x'"),
            "{cmd}"
        );
        assert_eq!(&args[0], "new-session");
    }

    #[test]
    fn the_plan_reopens_claude_with_its_own_resume_and_recreates_other_engines_without_pretending()
    {
        let recs = vec![
            rec("claude-code", ID1, "1:2", "%3", 1),
            SessionRecord {
                engine: "codex".into(),
                ..rec("claude-code", "t9", "1:2", "%4", 1)
            },
        ];
        let p = plan(&recs, None, &BTreeSet::new(), &|_| true, 2, MAX_REOPEN);
        assert_eq!(p.steps.len(), 2);
        let claude = p
            .steps
            .iter()
            .find(|s| s.record.engine == "claude-code")
            .unwrap();
        assert!(claude.supported && claude.new_session);
        assert!(
            claude
                .command
                .contains(&format!("'claude' '--resume' '{ID1}'")),
            "{}",
            claude.command
        );
        assert!(claude.command.contains("Nothing has been sent"));
        let codex = p.steps.iter().find(|s| s.record.engine == "codex").unwrap();
        assert!(!codex.supported);
        assert!(codex.command.contains("resume is not supported for codex"));
        assert!(!codex.command.contains("--resume") && !codex.command.contains("'t9'"));
        // the first window makes the session, the second joins it, by an exact-match target
        assert_eq!(p.steps.iter().filter(|s| s.new_session).count(), 1);
        let a = tmux_args(&p.steps[1]);
        assert_eq!(&a[..3], ["new-window", "-d", "-t"]);
        assert_eq!(a[3], "=work:");
    }

    #[test]
    fn what_is_alive_is_not_reopened_a_gone_folder_waits_then_goes_and_a_quote_cannot_break_out() {
        let alive = rec("claude-code", ID1, "7:8", "%1", 1);
        let dead = rec("claude-code", ID2, "1:2", "%1", 1);
        let p = plan(
            &[alive, dead],
            Some("7:8"),
            &BTreeSet::from(["work".to_string()]),
            &|_| true,
            2,
            MAX_REOPEN,
        );
        assert_eq!(p.steps.len(), 1);
        assert_eq!(p.steps[0].record.session_id, ID2);
        assert!(
            !p.steps[0].new_session,
            "the session exists, so a window is added to it"
        );
        // a folder that is gone is noted and kept for a day, then forgotten
        let gone = SessionRecord {
            folder: "/work/gone".into(),
            ..rec("claude-code", ID3, "1:2", "%1", 1_000)
        };
        let soon = plan(
            std::slice::from_ref(&gone),
            None,
            &BTreeSet::new(),
            &|f| f != "/work/gone",
            2_000,
            MAX_REOPEN,
        );
        assert!(soon.steps.is_empty() && soon.notes.len() == 1 && soon.forget.is_empty());
        let late = plan(
            &[gone],
            None,
            &BTreeSet::new(),
            &|f| f != "/work/gone",
            1_000 + FOLDER_GONE_GRACE_MS + 1,
            MAX_REOPEN,
        );
        assert!(late.steps.is_empty() && late.forget.len() == 1);
        assert_eq!(sh_quote("it's"), "'it'\\''s'");
        // an id that is not plain words, or that starts like a flag, never reaches a command
        assert_eq!(resume_argv("claude-code", "a b;rm"), None);
        assert_eq!(
            resume_argv("claude-code", "--dangerously-skip-permissions"),
            None
        );
    }

    #[test]
    fn an_old_record_is_not_reopened_and_at_most_the_cap_come_back_the_newest_first() {
        let now = 10 * MAX_AGE_MS;
        let mut recs = vec![rec(
            "claude-code",
            "00000000-0000-4000-8000-000000000000",
            "1:2",
            "%90",
            now - MAX_AGE_MS - 1,
        )];
        for i in 0..(MAX_REOPEN + 3) {
            recs.push(rec(
                "claude-code",
                &format!("00000000-0000-4000-8000-00000000{i:04}"),
                "1:2",
                &format!("%{i}"),
                now - 1_000 * (i as u64 + 1),
            ));
        }
        let p = plan(&recs, None, &BTreeSet::new(), &|_| true, now, MAX_REOPEN);
        assert_eq!(p.steps.len(), MAX_REOPEN);
        assert_eq!(p.forget.len(), 1, "the old one is forgotten");
        assert!(
            p.notes
                .iter()
                .any(|n| n.contains("3 more session(s) were not reopened")),
            "{:?}",
            p.notes
        );
        // the newest came back
        assert!(p.steps.iter().any(|s| s.record.place.ends_with(":%0")));
        assert!(!p
            .steps
            .iter()
            .any(|s| s.record.place.ends_with(&format!(":%{}", MAX_REOPEN + 2))));
        // and a younger record of the same pane supersedes an older one
        let two = plan(
            &[
                rec("claude-code", ID1, "1:2", "%3", 5),
                rec("claude-code", ID2, "1:2", "%3", 9),
            ],
            None,
            &BTreeSet::new(),
            &|_| true,
            10,
            MAX_REOPEN,
        );
        assert_eq!(two.steps.len(), 1);
        assert_eq!(two.steps[0].record.session_id, ID2);
        assert_eq!(two.forget.len(), 1);
    }

    #[test]
    fn a_session_the_person_ended_leaves_no_record_but_a_shutdown_or_another_reason_leaves_it() {
        let d = tempfile::tempdir().unwrap();
        let put = |id: &str| {
            write_record(
                d.path(),
                ROOT,
                &rec("claude-code", id, "1:2", &format!("%{}", &id[..1]), 1),
                false,
            )
            .unwrap();
        };
        let calm = Scripted::new(|_| ok("running\n"));
        let stopping = Scripted::new(|c| {
            if mentions(c, "is-system-running") {
                ok("stopping\n")
            } else {
                ok("")
            }
        });
        let end = |runner: &dyn CommandRunner, id: &str, reason: &str| {
            end_from_hook(
                runner,
                d.path(),
                "claude-code",
                &json!({"hook_event_name": "SessionEnd", "session_id": id, "reason": reason}),
            );
        };
        let left = || load_records(d.path(), ROOT).0.len();
        put(ID1);
        put(ID2);
        put(ID3);
        assert_eq!(left(), 3);
        end(&calm, ID1, "prompt_input_exit");
        assert_eq!(left(), 2, "/exit ends it");
        end(&calm, ID2, "other");
        assert_eq!(left(), 2, "a hang-up is not the person ending it");
        end(&stopping, ID2, "prompt_input_exit");
        assert_eq!(left(), 2, "never while the system is stopping");
        end(&calm, ID2, "clear");
        end(&calm, ID3, "logout");
        assert_eq!(left(), 0);
        // an end for a session that has no record, or a hostile id, does nothing and cannot reach another file
        end(&calm, "../x", "logout");
        end(&calm, "--x", "logout");
    }

    #[test]
    fn a_record_whose_window_was_killed_while_the_box_runs_is_removed_but_never_during_a_stop() {
        let d = tempfile::tempdir().unwrap();
        write_record(
            d.path(),
            ROOT,
            &rec("claude-code", ID1, "9:10", "%1", 1),
            false,
        )
        .unwrap();
        write_record(
            d.path(),
            ROOT,
            &rec("claude-code", ID2, "9:10", "%2", 1),
            false,
        )
        .unwrap();
        write_record(
            d.path(),
            ROOT,
            &rec("claude-code", ID3, "1:2", "%7", 1),
            false,
        )
        .unwrap();
        let tmux = |stop: bool| {
            Scripted::new(move |c| {
                if mentions(c, "is-system-running") {
                    ok(if stop { "stopping\n" } else { "running\n" })
                } else if mentions(c, "list-panes") {
                    ok("9\t10\t%1\n") // %2 was killed
                } else {
                    ok("")
                }
            })
        };
        assert_eq!(sweep_gone(&tmux(true), d.path(), ROOT), 0);
        assert_eq!(load_records(d.path(), ROOT).0.len(), 3);
        assert_eq!(sweep_gone(&tmux(false), d.path(), ROOT), 1);
        let ids: BTreeSet<String> = load_records(d.path(), ROOT)
            .0
            .into_iter()
            .map(|r| r.session_id)
            .collect();
        // the live server's other pane stays, and so does a record of a server that is gone (that is what boot resumes)
        assert_eq!(ids, BTreeSet::from([ID1.to_string(), ID3.to_string()]));
        // tmux that cannot be asked removes nothing
        let dead = Scripted::new(|c| {
            if mentions(c, "list-panes") {
                fail()
            } else {
                ok("")
            }
        });
        assert_eq!(sweep_gone(&dead, d.path(), ROOT), 0);
        // every call is bounded
        let r = tmux(false);
        sweep_gone(&r, d.path(), ROOT);
        assert!(r.calls().iter().all(|c| c.program == "timeout"));
    }

    #[test]
    fn a_boot_resume_starts_tmux_in_its_own_scope_rewrites_the_record_keeps_its_time_and_a_second_run_does_nothing(
    ) {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().to_str().unwrap().to_string();
        let folder = format!("{root}/repo");
        fs::create_dir(&folder).unwrap();
        let mut r = rec("claude-code", ID1, "1:2", "%3", 1_000);
        r.folder = folder;
        let dir = d.path().join("s");
        write_record(&dir, &root, &r, false).unwrap();
        let runner = RecordingRunner::new();
        // no tmux server yet (list-sessions fails), then the scoped new-session prints its place
        runner.reply(fail());
        runner.reply(ok("work\t@0\t0\tclaude\t900\t5000\t%0\t5\n"));
        let said = resume_all(&runner, &dir, &root, 9_000);
        assert!(
            said.iter()
                .any(|l| l.contains("reopened with its own resume")),
            "{said:?}"
        );
        let calls = runner.calls();
        assert_eq!(calls[1].program, "systemd-run");
        assert!(mentions(&calls[1], "--scope") && mentions(&calls[1], "--user"));
        let unit = calls[1]
            .args
            .iter()
            .find(|a| a.starts_with("--unit="))
            .unwrap();
        assert!(
            unit.starts_with("--unit=tmux-spawn-"),
            "ADR 0045's drop-in prefix: {unit}"
        );
        let at = calls[1].args.iter().position(|a| a == "tmux").unwrap();
        assert_eq!(calls[1].args[at + 1], "new-session");
        let (now, _) = load_records(&dir, &root);
        assert_eq!(now[0].place, "900:5000:%0");
        assert_eq!(
            now[0].last_seen_ms, 1_000,
            "a resume is not a sighting of the agent"
        );
        // the server is now alive and holds that place: nothing more is made
        let again = RecordingRunner::new();
        again.reply(ok("work\t900\t5000\n"));
        assert!(resume_all(&again, &dir, &root, 9_500).is_empty());
        assert_eq!(again.calls().len(), 1);
    }

    #[test]
    fn if_a_scope_cannot_be_made_tmux_is_started_plainly_and_the_second_window_joins_the_first_server(
    ) {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().to_str().unwrap().to_string();
        fs::create_dir(format!("{root}/a")).unwrap();
        let dir = d.path().join("s");
        let mut a = rec("claude-code", ID1, "1:2", "%3", 5);
        a.folder = format!("{root}/a");
        let mut b = rec("claude-code", ID2, "1:2", "%4", 4);
        b.folder = format!("{root}/a");
        b.window_index = 2;
        for r in [&a, &b] {
            write_record(&dir, &root, r, false).unwrap();
        }
        let runner = RecordingRunner::new();
        runner.reply(fail()); // list-sessions
        runner.reply(fail()); // systemd-run
        runner.reply(ok("work\t@0\t0\tclaude\t900\t5000\t%0\t5\n")); // plain new-session
        runner.reply(ok("work\t@1\t1\tclaude\t900\t5000\t%1\t5\n")); // new-window
        let said = resume_all(&runner, &dir, &root, 9_000);
        assert!(
            said.iter().any(|l| l.contains("inside the resume service")),
            "{said:?}"
        );
        let calls = runner.calls();
        assert_eq!(calls[2].program, "tmux");
        assert_eq!(calls[2].args[0], "new-session");
        assert_eq!(
            calls[3].program, "tmux",
            "the server is up: no second scope"
        );
        assert_eq!(calls[3].args[0], "new-window");
        assert_eq!(load_records(&dir, &root).0.len(), 2);
    }

    #[test]
    fn a_failing_tmux_is_reported_and_the_record_is_kept_for_the_next_boot() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().to_str().unwrap().to_string();
        let mut r = rec("claude-code", ID1, "1:2", "%3", 1);
        r.folder = root.clone();
        let dir = d.path().join("s");
        write_record(&dir, &root, &r, false).unwrap();
        let runner = RecordingRunner::new();
        for _ in 0..3 {
            runner.reply(fail());
        }
        let said = resume_all(&runner, &dir, &root, 2);
        assert!(said.iter().any(|l| l.contains("could not make the window")));
        assert_eq!(load_records(&dir, &root).0, vec![r]);
    }

    #[test]
    fn a_resumed_agent_that_already_wrote_its_own_record_is_not_overwritten_by_the_old_one() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path();
        let old = rec("claude-code", ID1, "1:2", "%3", 100);
        write_record(dir, ROOT, &old, false).unwrap();
        // the resumed agent's first event (a new id from --resume) lands before tmux returns
        let new = rec("claude-code", ID2, "900:5000", "%0", 9_000);
        write_record(dir, ROOT, &new, false).unwrap();
        follow(dir, ROOT, &old, &place("900:5000", "%0"));
        let ids: Vec<String> = load_records(dir, ROOT)
            .0
            .into_iter()
            .map(|r| r.session_id)
            .collect();
        assert_eq!(
            ids,
            vec![ID2.to_string()],
            "the next boot reopens the new conversation, not the old"
        );
        // and if both ever sit on one pane, the newer is the one a plan reopens
        write_file(
            dir,
            &SessionRecord {
                place: "900:5000:%0".into(),
                ..old.clone()
            },
        )
        .unwrap();
        let p = plan(
            &load_records(dir, ROOT).0,
            None,
            &BTreeSet::new(),
            &|_| true,
            10_000,
            MAX_REOPEN,
        );
        assert_eq!(p.steps.len(), 1);
        assert_eq!(p.steps[0].record.session_id, ID2);
    }

    #[test]
    fn a_leftover_temporary_file_older_than_an_hour_is_removed_and_a_fresh_one_is_not() {
        let d = tempfile::tempdir().unwrap();
        let stale = d.path().join(format!(".claude-code-{ID1}.json.tmp-7"));
        let fresh = d.path().join(format!(".claude-code-{ID2}.json.tmp-8"));
        fs::write(&stale, "{").unwrap();
        fs::write(&fresh, "{").unwrap();
        let old = SystemTime::now() - Duration::from_secs(2 * 3600);
        fs::File::options()
            .write(true)
            .open(&stale)
            .unwrap()
            .set_modified(old)
            .unwrap();
        clean_temp_files(d.path());
        assert!(!stale.exists() && fresh.exists());
    }

    #[test]
    fn the_records_folder_is_never_a_link_and_a_permission_is_never_set_through_one() {
        let d = tempfile::tempdir().unwrap();
        let target = d.path().join("real");
        fs::create_dir(&target).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let link = d.path().join("sessions");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(ensure_dir(&link).is_err());
        assert!(
            write_record(&link, ROOT, &rec("claude-code", ID1, "1:2", "%3", 1), false).is_err()
        );
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&target).unwrap().permissions().mode() & 0o777,
                0o755
            );
        }
        // the folder cannot be redirected through the environment (the needle is built so this file does not contain it)
        let needle = ["OZBOX_SESSION", "_DIR"].concat();
        assert!(
            !include_str!("session_resume.rs")[..include_str!("session_resume.rs")
                .find("#[cfg(test)]")
                .unwrap()]
                .contains(&needle)
        );
    }

    #[test]
    fn a_hook_outside_tmux_or_with_a_bad_pane_writes_nothing_and_every_tmux_call_is_bounded() {
        let runner = RecordingRunner::new();
        assert!(current_place(&runner, "not-a-pane").is_none());
        assert!(runner.calls().is_empty());
        runner.reply(ok("work\t@5\t2\tclaude\t10\t20\t%4\t5\n"));
        let p = current_place(&runner, "%4").unwrap();
        assert_eq!((p.place().as_str(), p.window_index), ("10:20:%4", 2));
        let c = &runner.calls()[0];
        assert_eq!(
            c.program, "timeout",
            "a stuck tmux never holds an agent's hook"
        );
        assert_eq!(&c.args[..3], ["-k", "1", "2"]);
        assert!(parse_place("garbage").is_none());
        assert!(parse_place("work\t@5\t2\tclaude\t10\t20\t%x\t5").is_none());
    }

    #[test]
    fn the_user_unit_is_written_once_enabled_in_the_box_users_own_folder_and_a_mask_is_respected() {
        let h = tempfile::tempdir().unwrap();
        let bin = "/usr/local/bin/ozboxd";
        assert_eq!(
            install_user_unit(h.path(), bin).unwrap(),
            UnitOutcome::Installed
        );
        let unit = h.path().join(".config/systemd/user").join(UNIT_NAME);
        let text = fs::read_to_string(&unit).unwrap();
        for want in [
            "Type=oneshot",
            "RemainAfterExit=yes",
            "ExecStart=/usr/local/bin/ozboxd session-resume",
            "KillMode=process",
            "WantedBy=default.target",
            "ConditionPathExists=/usr/local/bin/ozboxd",
            "After=basic.target",
        ] {
            assert!(text.contains(want), "the unit must have {want}");
        }
        let link = h
            .path()
            .join(".config/systemd/user/default.target.wants")
            .join(UNIT_NAME);
        assert_eq!(
            fs::read_link(&link).unwrap(),
            PathBuf::from("..").join(UNIT_NAME)
        );
        assert_eq!(
            install_user_unit(h.path(), bin).unwrap(),
            UnitOutcome::AlreadyThere
        );
        // an older text is brought up to date
        fs::write(&unit, "[Unit]\n").unwrap();
        assert_eq!(
            install_user_unit(h.path(), bin).unwrap(),
            UnitOutcome::Installed
        );
        // a path with odd characters falls back to the fixed one, never into the unit text
        let odd = tempfile::tempdir().unwrap();
        install_user_unit(odd.path(), "/tmp/x y\nExecStartPre=/bin/sh").unwrap();
        let t =
            fs::read_to_string(odd.path().join(".config/systemd/user").join(UNIT_NAME)).unwrap();
        assert!(!t.contains("ExecStartPre") && t.contains("/usr/local/bin/ozboxd session-resume"));
        // a mask (a link to /dev/null) is how the person turns it off, and it stays off
        let m = tempfile::tempdir().unwrap();
        let base = m.path().join(".config/systemd/user");
        fs::create_dir_all(&base).unwrap();
        std::os::unix::fs::symlink("/dev/null", base.join(UNIT_NAME)).unwrap();
        assert_eq!(
            install_user_unit(m.path(), bin).unwrap(),
            UnitOutcome::LeftAlone
        );
        assert!(fs::read_link(base.join(UNIT_NAME)).is_ok());
    }

    // ---- round 2: S16 fail closed, S18 ownership and removal, S19 race, S20 off switches ----

    /// systemctl and tmux answered one by one: `None` is a dead bus (the call fails), `Some("")` a timeout or an empty answer.
    struct Bus {
        system: Option<&'static str>,
        user: Option<&'static str>,
        panes: Output,
    }
    impl CommandRunner for Bus {
        fn run(&self, c: &CommandSpec) -> ozbox_core::Result<Output> {
            if mentions(c, "is-system-running") {
                let a = if mentions(c, "--user") {
                    self.user
                } else {
                    self.system
                };
                match a {
                    Some(t) => Ok(ok(t)),
                    None => Err(ozbox_core::Error::Io(io::Error::other("no bus"))),
                }
            } else if mentions(c, "list-panes") {
                Ok(self.panes.clone())
            } else {
                Ok(ok(""))
            }
        }
    }

    fn bus(system: Option<&'static str>, user: Option<&'static str>, panes: &str) -> Bus {
        Bus {
            system,
            user,
            panes: ok(panes),
        }
    }

    fn put(dir: &Path, id: &str, server: &str, pane: &str) {
        write_record(dir, ROOT, &rec("claude-code", id, server, pane, 1), false).unwrap();
    }

    fn opts<'a>(
        now: u64,
        boot: Option<u64>,
        watch: Option<&'a mut BTreeMap<String, u64>>,
        stop: &'a dyn Fn() -> bool,
    ) -> SweepOptions<'a> {
        SweepOptions {
            now_ms: now,
            boot_secs: boot,
            watch_shells: watch,
            stop,
        }
    }

    #[test]
    fn the_stopping_check_fails_closed_a_timeout_a_dead_bus_or_an_unknown_answer_removes_nothing() {
        let no = || false;
        // each of these is "may be stopping": both managers must positively say running or degraded
        let answers: [(Option<&'static str>, Option<&'static str>); 9] = [
            (Some(""), Some("")),          // a timeout, or nothing printed
            (None, None),                  // a dead bus
            (Some("running\n"), Some("")), // only one answered
            (Some("running\n"), None),
            (Some("stopping\n"), Some("running\n")),
            (Some("running\n"), Some("stopping\n")),
            (Some("starting\n"), Some("running\n")),
            (Some("maintenance\n"), Some("maintenance\n")),
            (Some("offline\n"), Some("running\n")),
        ];
        for (system, user) in answers {
            let d = tempfile::tempdir().unwrap();
            put(d.path(), ID1, "9:10", "%1");
            put(d.path(), ID2, "9:10", "%2");
            let r = bus(system, user, "9\t10\t%1\n"); // %2 is gone, which is what a shutdown looks like
            assert!(system_may_be_stopping(&r), "{system:?} {user:?}");
            assert_eq!(
                sweep(&r, &nobody(), d.path(), ROOT, opts(5, Some(0), None, &no)),
                0,
                "{system:?} {user:?}"
            );
            end_from_hook(
                &r,
                d.path(),
                "claude-code",
                &json!({"hook_event_name":"SessionEnd","session_id":ID1,"reason":"prompt_input_exit"}),
            );
            assert_eq!(
                load_records(d.path(), ROOT).0.len(),
                2,
                "{system:?} {user:?}"
            );
        }
        // only a positive answer from both lets a removal through
        for (system, user) in [
            ("running\n", "running\n"),
            ("degraded\n", "running\n"),
            ("running\n", "degraded\n"),
        ] {
            let d = tempfile::tempdir().unwrap();
            put(d.path(), ID1, "9:10", "%1");
            put(d.path(), ID2, "9:10", "%2");
            let r = bus(Some(system), Some(user), "9\t10\t%1\n");
            assert!(!system_may_be_stopping(&r));
            assert_eq!(
                sweep(&r, &nobody(), d.path(), ROOT, opts(5, Some(0), None, &no)),
                1
            );
        }
    }

    #[test]
    fn a_daemon_told_to_stop_runs_no_sweep_not_at_the_start_and_not_between_records() {
        let d = tempfile::tempdir().unwrap();
        put(d.path(), ID1, "9:10", "%1");
        put(d.path(), ID2, "9:10", "%2");
        put(d.path(), ID3, "9:10", "%3");
        let r = Scripted::new(|c| {
            if mentions(c, "list-panes") {
                ok("9\t10\t%1\n")
            } else {
                ok("running\n")
            }
        });
        // already told to stop: nothing is asked of tmux or systemd at all
        assert_eq!(
            sweep(
                &r,
                &nobody(),
                d.path(),
                ROOT,
                opts(5, Some(0), None, &|| true)
            ),
            0
        );
        assert!(r.calls().is_empty());
        assert_eq!(load_records(d.path(), ROOT).0.len(), 3);
        // told to stop in the middle (the flag is read at the start, and again before each removal)
        let looks = std::cell::Cell::new(0);
        let stop = || {
            looks.set(looks.get() + 1);
            looks.get() > 2
        };
        let removed = sweep(&r, &nobody(), d.path(), ROOT, opts(5, Some(0), None, &stop));
        assert_eq!(
            removed, 1,
            "the first removal went through, the second was refused"
        );
        assert_eq!(load_records(d.path(), ROOT).0.len(), 2);
    }

    #[test]
    fn a_tmux_server_is_called_ended_only_on_proof_about_that_server_and_the_previous_boots_stay_for_the_resume(
    ) {
        let calm = |panes: &str| bus(Some("running\n"), Some("running\n"), panes);
        let no = || false;
        // the record is of server pid 9, started at 1000
        let setup = || {
            let d = tempfile::tempdir().unwrap();
            put(d.path(), ID1, "9:1000", "%1");
            d
        };
        let gone = || Fake {
            tmux: [(9, false)].into(),
            ..table(&[], &[], &[])
        };
        let alive = || Fake {
            tmux: [(9, true)].into(),
            ..table(&[], &[], &[])
        };
        // process 9 is gone, it began after this boot did: the server ended while the box ran (kill-server, an OOM kill)
        let d = setup();
        assert_eq!(
            sweep(
                &calm(""),
                &gone(),
                d.path(),
                ROOT,
                opts(5, Some(500), None, &no)
            ),
            1
        );
        // whatever tmux says, as long as it can be asked: the same with a different server answering now
        let d = setup();
        assert_eq!(
            sweep(
                &calm("77\t1500\t%0\n"),
                &gone(),
                d.path(),
                ROOT,
                opts(5, Some(500), None, &no)
            ),
            1
        );
        // this boot began later: the server is the previous boot's, and the boot step reopens it
        let d = setup();
        assert_eq!(
            sweep(
                &calm(""),
                &gone(),
                d.path(),
                ROOT,
                opts(5, Some(2000), None, &no)
            ),
            0
        );
        assert_eq!(load_records(d.path(), ROOT).0.len(), 1);
        // the boot time is not known: nothing of a server that is not the one answering is removed
        let d = setup();
        assert_eq!(
            sweep(&calm(""), &gone(), d.path(), ROOT, opts(5, None, None, &no)),
            0
        );
        // ANOTHER server that is alive (`tmux -L name`), with the default socket's server answering or not answering: kept
        for panes in ["77\t1500\t%0\n", ""] {
            let d = setup();
            assert_eq!(
                sweep(
                    &calm(panes),
                    &alive(),
                    d.path(),
                    ROOT,
                    opts(5, Some(500), None, &no)
                ),
                0,
                "{panes:?}"
            );
            assert_eq!(load_records(d.path(), ROOT).0.len(), 1);
        }
        // two live servers at once, a record of each: a sweep from inside either removes neither
        let d = tempfile::tempdir().unwrap();
        put(d.path(), ID1, "9:1000", "%1"); // the default server
        put(d.path(), ID2, "20:1200", "%1"); // a `-L work` server: not the one list-panes talks to
        let both = Fake {
            tmux: [(9, true), (20, true)].into(),
            ..table(&[], &[], &[])
        };
        assert_eq!(
            sweep(
                &calm("9\t1000\t%1\n"),
                &both,
                d.path(),
                ROOT,
                opts(5, Some(500), None, &no)
            ),
            0
        );
        assert_eq!(load_records(d.path(), ROOT).0.len(), 2);
        // no process table to ask (the pid cannot be checked): nothing is removed
        let d = setup();
        assert_eq!(
            sweep(
                &calm(""),
                &table(&[], &[], &[]),
                d.path(),
                ROOT,
                opts(5, Some(500), None, &no)
            ),
            0
        );
        // tmux answering nothing at all (a timeout) removes none of the live server's panes' records either
        let d = setup();
        let timeout = Bus {
            system: Some("running\n"),
            user: Some("running\n"),
            panes: Output {
                status: Some(124),
                ..Output::default()
            },
        };
        assert_eq!(
            sweep(
                &timeout,
                &alive(),
                d.path(),
                ROOT,
                opts(5, Some(500), None, &no)
            ),
            0
        );
    }

    #[test]
    fn an_agent_that_crashed_back_to_a_shell_loses_its_record_after_the_grace_a_live_or_wrapped_or_stopped_one_never_does(
    ) {
        let d = tempfile::tempdir().unwrap();
        put(d.path(), ID1, "9:10", "%1");
        put(d.path(), ID2, "9:10", "%2");
        let no = || false;
        let mut watch = BTreeMap::new();
        // %1: a shell in front, pane process 101; %2: node in front, pane process 102
        let shell = bus(
            Some("running\n"),
            Some("running\n"),
            "9\t10\t%1\t101\tbash\n9\t10\t%2\t102\tnode\n",
        );
        let claude = bus(
            Some("running\n"),
            Some("running\n"),
            "9\t10\t%1\t101\tnode\n9\t10\t%2\t102\tnode\n",
        );
        let nothing_below = Fake {
            below: [(101, false), (102, true)].into(),
            ..table(&[], &[], &[])
        };
        // a shell in front for a moment is normal (a window being started): kept, and remembered
        assert_eq!(
            sweep(
                &shell,
                &nothing_below,
                d.path(),
                ROOT,
                opts(1_000, Some(0), Some(&mut watch), &no)
            ),
            0
        );
        assert_eq!(watch.len(), 1);
        assert_eq!(
            sweep(
                &shell,
                &nothing_below,
                d.path(),
                ROOT,
                opts(1_000 + SHELL_GRACE_MS - 1, Some(0), Some(&mut watch), &no)
            ),
            0
        );
        // the agent came back (or the person started one): the clock starts again
        assert_eq!(
            sweep(
                &claude,
                &nothing_below,
                d.path(),
                ROOT,
                opts(1_000 + SHELL_GRACE_MS, Some(0), Some(&mut watch), &no)
            ),
            0
        );
        assert!(watch.is_empty());
        assert_eq!(
            sweep(
                &shell,
                &nothing_below,
                d.path(),
                ROOT,
                opts(500_000, Some(0), Some(&mut watch), &no)
            ),
            0
        );
        // a shell in front for three minutes but a Claude Code below the pane's process (a wrapper script that did not exec the
        // agent, or an agent stopped with Ctrl-Z): kept, however long
        let wrapped = Fake {
            below: [(101, true), (102, true)].into(),
            ..table(&[], &[], &[])
        };
        assert_eq!(
            sweep(
                &shell,
                &wrapped,
                d.path(),
                ROOT,
                opts(
                    500_000 + 10 * SHELL_GRACE_MS,
                    Some(0),
                    Some(&mut watch),
                    &no
                )
            ),
            0
        );
        // the process table cannot be read: kept
        assert_eq!(
            sweep(
                &shell,
                &table(&[], &[], &[]),
                d.path(),
                ROOT,
                opts(
                    500_000 + 10 * SHELL_GRACE_MS,
                    Some(0),
                    Some(&mut watch),
                    &no
                )
            ),
            0
        );
        // three minutes of a shell and no Claude Code below: the record goes, the other pane's stays
        assert_eq!(
            sweep(
                &shell,
                &nothing_below,
                d.path(),
                ROOT,
                opts(500_000 + SHELL_GRACE_MS, Some(0), Some(&mut watch), &no)
            ),
            1
        );
        let left: Vec<String> = load_records(d.path(), ROOT)
            .0
            .into_iter()
            .map(|r| r.session_id)
            .collect();
        assert_eq!(left, vec![ID2.to_string()]);
        // a hook or the boot step does not watch shells at all
        let d2 = tempfile::tempdir().unwrap();
        put(d2.path(), ID1, "9:10", "%1");
        assert_eq!(
            sweep(
                &shell,
                &nothing_below,
                d2.path(),
                ROOT,
                opts(u64::MAX / 2, Some(0), None, &no)
            ),
            0
        );
        for c in ["bash", "-zsh", "sh", "fish"] {
            assert!(is_shell(c), "{c}");
        }
        for c in ["node", "claude", "2.0.5", "vim", ""] {
            assert!(!is_shell(c), "{c}");
        }
    }

    #[test]
    fn a_session_that_starts_while_the_sweep_runs_keeps_its_record() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().to_path_buf();
        put(&dir, ID1, "9:10", "%1");
        let no = || false;
        // tmux is asked after the records were read: a session that begins during that call is not in the list of panes
        let d2 = dir.clone();
        let r = Scripted::new(move |c| {
            if mentions(c, "list-panes") {
                write_record(&d2, ROOT, &rec("claude-code", ID2, "9:10", "%5", 2), false).unwrap();
                ok("9\t10\t%1\n")
            } else {
                ok("running\n")
            }
        });
        assert_eq!(
            sweep(&r, &nobody(), &dir, ROOT, opts(5, Some(0), None, &no)),
            0
        );
        assert_eq!(
            load_records(&dir, ROOT).0.len(),
            2,
            "the new session's record is there"
        );
        // a record that moved to another pane meanwhile (a resumed window's follow) is read again and kept
        let d3 = tempfile::tempdir().unwrap();
        let dir3 = d3.path().to_path_buf();
        put(&dir3, ID1, "9:10", "%1");
        let d4 = dir3.clone();
        let r = Scripted::new(move |c| {
            if mentions(c, "list-panes") {
                let mut moved = rec("claude-code", ID1, "9:10", "%9", 3);
                moved.last_seen_ms = 3;
                write_file(&d4, &moved).unwrap();
                ok("9\t10\t%9\n9\t10\t%8\n") // %1 is not there
            } else {
                ok("running\n")
            }
        });
        assert_eq!(
            sweep(&r, &nobody(), &dir3, ROOT, opts(5, Some(0), None, &no)),
            0
        );
        assert_eq!(load_records(&dir3, ROOT).0.len(), 1);
    }

    /// A process table: `parent` links, which processes are Claude Code, which were started in print mode.
    struct Fake {
        parent: std::collections::HashMap<u32, u32>,
        claude: BTreeSet<u32>,
        print: BTreeSet<u32>,
        tmux: std::collections::HashMap<u32, bool>,
        below: std::collections::HashMap<u32, bool>,
    }
    impl Procs for Fake {
        fn parent(&self, pid: u32) -> Option<u32> {
            self.parent.get(&pid).copied()
        }
        fn is_claude(&self, pid: u32) -> bool {
            self.claude.contains(&pid)
        }
        fn print_mode(&self, pid: u32) -> bool {
            self.print.contains(&pid)
        }
        fn tmux_alive(&self, pid: u32) -> Option<bool> {
            self.tmux.get(&pid).copied()
        }
        fn claude_below(&self, pid: u32) -> Option<bool> {
            self.below.get(&pid).copied()
        }
    }
    /// A process table that knows nothing: every "is it alive" question is "cannot tell".
    fn nobody() -> Fake {
        table(&[], &[], &[])
    }
    fn table(links: &[(u32, u32)], claude: &[u32], print: &[u32]) -> Fake {
        Fake {
            parent: links.iter().copied().collect(),
            claude: claude.iter().copied().collect(),
            print: print.iter().copied().collect(),
            tmux: Default::default(),
            below: Default::default(),
        }
    }

    #[test]
    fn only_the_claude_that_owns_the_pane_counts_a_nested_one_and_a_print_mode_one_do_not() {
        // pane shell 100 -> claude 200 -> the hook 300
        let own = table(&[(300, 200), (200, 100), (100, 50)], &[200], &[]);
        assert_eq!(pane_ownership(&own, 300, 100), Ownership::Owns);
        // a wrapper script and the program it starts are one: adjacent, not separated
        let wrapped = table(
            &[(300, 210), (210, 200), (200, 100), (100, 50)],
            &[200, 210],
            &[],
        );
        assert_eq!(pane_ownership(&wrapped, 300, 100), Ownership::Owns);
        // the pane's own program is claude (new-window claude)
        let direct = table(&[(300, 100), (100, 50)], &[100], &[]);
        assert_eq!(pane_ownership(&direct, 300, 100), Ownership::Owns);
        // the agent's Bash tool ran `claude -p`: shell 100 -> claude 200 -> bash 210 -> claude 220 -> hook 301
        let nested = table(
            &[(301, 220), (220, 210), (210, 200), (200, 100), (100, 50)],
            &[200, 220],
            &[220],
        );
        assert_eq!(pane_ownership(&nested, 301, 100), Ownership::Nested);
        // a `claude -p` the person ran from the shell directly
        let print = table(&[(301, 200), (200, 100), (100, 50)], &[200], &[200]);
        assert_eq!(pane_ownership(&print, 301, 100), Ownership::PrintMode);
        // not under the pane's process at all, or no process table
        let stray = table(&[(300, 200), (200, 1)], &[200], &[]);
        assert_eq!(pane_ownership(&stray, 300, 100), Ownership::NotInPane);
        assert_eq!(
            pane_ownership(&table(&[], &[], &[]), 300, 100),
            Ownership::Unknown
        );
    }

    #[test]
    fn a_nested_or_print_mode_claude_never_replaces_the_panes_record() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("s");
        let r = Scripted::new(|_| ok("work\t@0\t0\tclaude\t900\t5000\t%3\t100\n"));
        let payload = |id: &str| json!({"session_id": id, "cwd": "/work/repos/web", "hook_event_name": "Stop"});
        let procs = table(
            &[
                (300, 200),
                (200, 100),
                (301, 220),
                (220, 210),
                (210, 200),
                (302, 202),
                (202, 100),
            ],
            &[200, 220, 202],
            &[220, 202],
        );
        // the interactive session writes its record
        assert!(record_event(
            &r,
            &procs,
            &dir,
            "%3",
            300,
            "claude-code",
            &payload(ID1),
            "/work/x",
            10
        ));
        // a `claude -p` the agent ran from its Bash tool is another session id in the same pane: no record, the first stays
        assert!(!record_event(
            &r,
            &procs,
            &dir,
            "%3",
            301,
            "claude-code",
            &payload(ID2),
            "/work/x",
            20
        ));
        // and so does a print-mode session started from the shell
        assert!(!record_event(
            &r,
            &procs,
            &dir,
            "%3",
            302,
            "claude-code",
            &payload(ID3),
            "/work/x",
            30
        ));
        let ids: Vec<String> = load_records(&dir, ROOT)
            .0
            .into_iter()
            .map(|r| r.session_id)
            .collect();
        assert_eq!(ids, vec![ID1.to_string()]);
        // a /clear in the interactive session is still a new id in the same pane, and still replaces the old one
        assert!(record_event(
            &r,
            &procs,
            &dir,
            "%3",
            300,
            "claude-code",
            &payload(ID2),
            "/work/x",
            40
        ));
        let ids: Vec<String> = load_records(&dir, ROOT)
            .0
            .into_iter()
            .map(|r| r.session_id)
            .collect();
        assert_eq!(ids, vec![ID2.to_string()]);
        // one tmux call per event: the pane's own process comes with the place
        assert_eq!(r.calls().len(), 4); // four events, four calls
    }

    #[test]
    fn a_place_without_the_panes_own_process_writes_no_record() {
        // S24: the ownership check can never be skipped on its own: no readable pane_pid, no record
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("s");
        let procs = table(&[(300, 100), (100, 50)], &[100], &[]);
        let payload =
            json!({"session_id": ID1, "cwd": "/work/repos/web", "hook_event_name": "Stop"});
        for line in [
            "work\t@0\t0\tclaude\t900\t5000\t%3\n",
            "work\t@0\t0\tclaude\t900\t5000\t%3\t\n",
            "work\t@0\t0\tclaude\t900\t5000\t%3\t0\n",
        ] {
            let r = Scripted::new(move |_| ok(line));
            assert!(!record_event(
                &r,
                &procs,
                &dir,
                "%3",
                300,
                "claude-code",
                &payload,
                "/work/x",
                10
            ));
        }
        assert!(load_records(&dir, ROOT).0.is_empty());
        // a failing tmux call is no record either
        let bad = Scripted::new(|_| fail());
        assert!(!record_event(
            &bad,
            &procs,
            &dir,
            "%3",
            300,
            "claude-code",
            &payload,
            "/work/x",
            10
        ));
        assert_eq!(bad.calls().len(), 1);
    }

    #[test]
    fn a_sweep_skipped_ten_times_in_a_row_says_so_once_with_the_managers_answers() {
        let stopping = || stopping_answers(&bus(Some("starting\n"), None, ""));
        let a = stopping().unwrap();
        assert_eq!(a, ("starting".to_string(), "no answer".to_string()));
        let mut w = SkipWatch::default();
        for _ in 1..SKIPS_BEFORE_SAYING {
            assert!(w.look(stopping()).is_none());
        }
        let line = w.look(stopping()).unwrap();
        assert!(
            line.contains("\"starting\"") && line.contains("\"no answer\""),
            "{line}"
        );
        // once, not every minute
        for _ in 0..30 {
            assert!(w.look(stopping()).is_none());
        }
        // a sweep that is allowed resets it; the next run of skips says so again
        assert!(w.look(None).is_none());
        for _ in 1..SKIPS_BEFORE_SAYING {
            assert!(w.look(stopping()).is_none());
        }
        assert!(w.look(stopping()).is_some());
        // a skip run that never reaches ten says nothing
        let mut w = SkipWatch::default();
        for _ in 0..50 {
            for _ in 1..SKIPS_BEFORE_SAYING {
                assert!(w.look(stopping()).is_none());
            }
            assert!(w.look(None).is_none());
        }
        // both running: no answers
        assert!(stopping_answers(&bus(Some("running\n"), Some("degraded\n"), "")).is_none());
    }

    #[test]
    fn claude_code_is_told_by_its_name_its_file_or_its_script_and_a_folder_name_alone_is_not_enough(
    ) {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        // by name, by the program it was started as, and by the file it runs (a native install by its resolved path)
        assert!(looks_like_claude("claude", None, &[]));
        assert!(looks_like_claude(
            "bash",
            None,
            &a(&["bash", "/home/o/bin/claude"])
        ));
        assert!(looks_like_claude(
            "2.1.140",
            Some("/work/home/ozbox/.local/share/claude/versions/2.1.140"),
            &a(&["/work/home/ozbox/.local/share/claude/versions/2.1.140"])
        ));
        assert!(looks_like_claude("x", Some("/opt/tools/claude"), &[]));
        // the npm install: a node (or bun) process running the package's script
        assert!(looks_like_claude(
            "node",
            Some("/usr/bin/node"),
            &a(&[
                "node",
                "/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js",
                "--resume"
            ])
        ));
        assert!(looks_like_claude(
            "bun",
            None,
            &a(&["bun", "--silent", "/x/claude-code/cli.js"])
        ));
        // a shell, an editor or a script runner whose command line only mentions such a folder is not Claude Code
        assert!(!looks_like_claude(
            "bash",
            Some("/bin/bash"),
            &a(&["bash", "-c", "cd /work/repos/claude-code/ && ls"])
        ));
        assert!(!looks_like_claude(
            "vim",
            None,
            &a(&["vim", "/work/repos/claude-code/README.md"])
        ));
        assert!(!looks_like_claude(
            "bash",
            None,
            &a(&["bash", "/work/repos/claude-code/run.sh"])
        ));
        // a node process that runs something else, and has the folder only as a later argument
        assert!(!looks_like_claude(
            "node",
            None,
            &a(&["node", "server.js", "/work/repos/claude-code/x"])
        ));
        // nothing readable
        assert!(!looks_like_claude("", None, &[]));
    }

    #[test]
    fn the_record_cap_keeps_the_newest_not_the_first_by_name() {
        let d = tempfile::tempdir().unwrap();
        let base = SystemTime::now() - Duration::from_secs(10_000);
        for i in 0..MAX_RECORDS + 3 {
            let id = format!("{:08x}-0000-4000-8000-000000000000", i);
            let r = rec("claude-code", &id, "1:2", &format!("%{i}"), 1);
            let p = d.path().join(r.file_name());
            fs::write(&p, serde_json::to_string(&r).unwrap()).unwrap();
            // file i is i seconds newer than file 0, and the names sort the other way for the last three
            fs::File::options()
                .write(true)
                .open(&p)
                .unwrap()
                .set_modified(base + Duration::from_secs(i as u64))
                .unwrap();
        }
        let (kept, said) = load_records(d.path(), ROOT);
        assert_eq!(kept.len(), MAX_RECORDS);
        assert_eq!(said.len(), 3);
        // the three oldest (i = 0, 1, 2) are the ones left out
        let ids: BTreeSet<String> = kept.iter().map(|r| r.session_id.clone()).collect();
        for i in 0..3 {
            assert!(!ids.contains(&format!("{:08x}-0000-4000-8000-000000000000", i)));
        }
        assert!(ids.contains(&format!(
            "{:08x}-0000-4000-8000-000000000000",
            MAX_RECORDS + 2
        )));
    }

    #[test]
    fn the_unit_is_enabled_once_and_a_disable_by_the_person_stays_disabled() {
        let h = tempfile::tempdir().unwrap();
        let bin = "/usr/local/bin/ozboxd";
        assert_eq!(
            install_user_unit(h.path(), bin).unwrap(),
            UnitOutcome::Installed
        );
        let link = h
            .path()
            .join(".config/systemd/user/default.target.wants")
            .join(UNIT_NAME);
        assert!(fs::symlink_metadata(&link).is_ok());
        // `systemctl --user disable` removes the link
        fs::remove_file(&link).unwrap();
        for _ in 0..2 {
            assert_eq!(
                install_user_unit(h.path(), bin).unwrap(),
                UnitOutcome::AlreadyThere
            );
            assert!(
                fs::symlink_metadata(&link).is_err(),
                "a disabled unit is not enabled again"
            );
        }
        // the unit's own text is still kept current
        let unit = h.path().join(".config/systemd/user").join(UNIT_NAME);
        fs::write(&unit, "[Unit]\n").unwrap();
        assert_eq!(
            install_user_unit(h.path(), bin).unwrap(),
            UnitOutcome::Installed
        );
        assert!(fs::symlink_metadata(&link).is_err());
        // and enabling it again by hand is respected
        std::os::unix::fs::symlink(PathBuf::from("..").join(UNIT_NAME), &link).unwrap();
        assert_eq!(
            install_user_unit(h.path(), bin).unwrap(),
            UnitOutcome::AlreadyThere
        );
    }

    #[test]
    fn the_off_switch_is_one_file() {
        let h = tempfile::tempdir().unwrap();
        assert!(!resume_off(h.path()));
        fs::create_dir_all(h.path().join(".config/ozbox")).unwrap();
        fs::write(off_switch(h.path()), "").unwrap();
        assert!(resume_off(h.path()));
        assert_eq!(
            off_switch(h.path()),
            h.path().join(".config/ozbox/session-resume.off")
        );
    }
}
