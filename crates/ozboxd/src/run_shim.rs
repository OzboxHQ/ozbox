//! The run shim (ADR 0038 section 4, items 2 and 3): `ozboxd run-shim <id> <record sha256> <runs dir>`.
//!
//! A run is a transient service of the box user's own manager, and this is its program. The shim owns the run's ends so
//! the box daemon can be restarted (or replaced by a live update) without the run noticing: the program's output goes
//! to `<runs dir>/<id>/log`, its standard input is held open behind a socket (`io.sock`, in a directory only the box
//! user can enter), and its exit status is written to `<runs dir>/<id>/exit`. The daemon keeps no connection: every
//! request (`status`, more `stdin`, `close_stdin`) opens the socket, sends one frame and reads one frame, so a daemon
//! that starts again has nothing to recover but the path.
//!
//! The program's argv, working directory, environment (secret) and first standard-input text arrive in the one `start`
//! request, over that socket, never as an argument or a unit property (which `ps` and `systemctl show` print). The
//! program is started from the argv array with `Command`: no shell ever sees it.
//!
//! The protocol is versioned (`proto`). A shim answers every request with its own version; a daemon drives any version
//! it knows (today, 1) and reports a run whose shim is newer rather than guess.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::run_units::{sha256_hex, RunRecord};
use crate::runs::{CappedLog, MAX_STDIN, MAX_STDIN_PENDING};

/// The protocol version this shim speaks.
pub const PROTO: u32 = 1;
/// The versions a daemon can drive.
pub const SUPPORTED_PROTOS: &[u32] = &[1];
/// The most one frame may carry (argv, environment and a first text all fit well inside it).
pub const MAX_FRAME: usize = 4 << 20;
pub const SOCK: &str = "io.sock";
pub const LOG: &str = "log";
pub const EXIT: &str = "exit";
pub const RECORD: &str = "run.json";
/// Written once the unit has started and its shim has answered. A run with no unit, no status and no such marker never
/// started (the daemon stopped between writing its record and starting it), which is not the same as being killed.
pub const STARTED: &str = "started";
/// How long a shim waits for the daemon's `start` before it gives up and ends (the unit then ends with it).
const START_WAIT: Duration = Duration::from_secs(30);
/// How long after the program exits its last output is given to reach the log, before the status is written.
const OUTPUT_SETTLE: Duration = Duration::from_millis(300);

/// One request. Not `Debug`: `start` carries the environment, which is secret.
#[derive(Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum Request {
    Start {
        proto: u32,
        argv: Vec<String>,
        #[serde(default)]
        cwd: Option<PathBuf>,
        #[serde(default)]
        env: BTreeMap<String, String>,
        #[serde(default)]
        stdin: Option<String>,
    },
    Status,
    Stdin {
        text: String,
    },
    CloseStdin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Fault {
    /// The program could not be started (not found, not executable).
    StartFailed,
    /// More text is waiting than the program has read.
    WouldBlock,
    /// The standard input is closed, or the run was not started with it open.
    BrokenPipe,
    /// A request the shim does not accept now (not started, started twice, too long).
    Refused,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reply {
    pub ok: bool,
    /// The shim's protocol version.
    pub proto: u32,
    pub pid: Option<u32>,
    /// The program's exit status, once it has ended.
    pub exited: Option<i32>,
    pub fault: Option<Fault>,
}

impl Reply {
    fn ok(shared: Option<&Shared>) -> Self {
        Self {
            ok: true,
            proto: PROTO,
            pid: shared.map(|s| s.pid),
            exited: shared.and_then(|s| s.exited.lock().ok().and_then(|e| *e)),
            fault: None,
        }
    }
    fn fault(f: Fault) -> Self {
        Self {
            ok: false,
            proto: PROTO,
            fault: Some(f),
            ..Self::default()
        }
    }
}

pub fn write_frame<W: Write, T: Serialize>(w: &mut W, v: &T) -> io::Result<()> {
    let body = serde_json::to_vec(v).map_err(io::Error::other)?;
    if body.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame too long",
        ));
    }
    w.write_all(&(body.len() as u32).to_be_bytes())?;
    w.write_all(&body)?;
    w.flush()
}

pub fn read_frame<R: Read, T: DeserializeOwned>(r: &mut R) -> io::Result<T> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let n = u32::from_be_bytes(len) as usize;
    if n > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too long"));
    }
    let mut body = vec![0u8; n];
    r.read_exact(&mut body)?;
    serde_json::from_slice(&body).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))
}

/// One request to a run's shim and its answer. A connection that is refused or whose socket is gone means the shim has
/// ended; a read that times out means it is not answering now (frozen), which is not the same thing.
pub fn call(sock: &Path, req: &Request, timeout: Duration) -> io::Result<Reply> {
    call_checked(sock, req, timeout, &|_| Ok(())).map(|(r, _)| r)
}

/// As [`call`], but the process on the other end of the socket is looked at BEFORE anything is sent: `verify` gets the pid the
/// kernel reports for it (`SO_PEERCRED`; `None` where the kernel cannot say) and may refuse. A request carries the run's
/// argv, environment and input, so it must never be sent to a process that is not the run's shim. Returns the answer and
/// that pid.
pub fn call_checked(
    sock: &Path,
    req: &Request,
    timeout: Duration,
    verify: &dyn Fn(Option<u32>) -> io::Result<()>,
) -> io::Result<(Reply, Option<u32>)> {
    let mut s = UnixStream::connect(sock)?;
    s.set_read_timeout(Some(timeout))?;
    s.set_write_timeout(Some(timeout))?;
    let pid = peer_pid(&s);
    verify(pid)?;
    write_frame(&mut s, req)?;
    Ok((read_frame(&mut s)?, pid))
}

/// The kernel's word for which process is on the other end of a connection (`SO_PEERCRED`).
#[cfg(target_os = "linux")]
pub fn peer_pid(s: &UnixStream) -> Option<u32> {
    rustix::net::sockopt::socket_peercred(s)
        .ok()
        .map(|c| c.pid.as_raw_nonzero().get() as u32)
}

#[cfg(not(target_os = "linux"))]
pub fn peer_pid(_s: &UnixStream) -> Option<u32> {
    None
}

/// Who may talk to a run's shim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerPolicy {
    /// Anyone who can open the socket (tests, and a box where the daemon's service cgroup is not known).
    Any,
    /// Only a process in this cgroup or below it (the daemon's own service). Processes outside the service (SSH sessions,
    /// the box user's own units) cannot reach the socket; dashboard terminals and runs in cgroup scopes sit under the
    /// service and still can. Defence in depth, not a boundary between processes of the box user.
    DaemonCgroup(String),
}

/// The part of a cgroup path that is the service itself: everything up to and including the first component ending in
/// `.service` (`/system.slice/ozboxd.service/daemon` gives `/system.slice/ozboxd.service`).
pub fn service_cgroup_of(cgroup: &str) -> Option<String> {
    let mut out = String::new();
    for c in cgroup.split('/').filter(|c| !c.is_empty()) {
        if c == ".." {
            return None;
        }
        out.push('/');
        out.push_str(c);
        if c.ends_with(".service") {
            return Some(out);
        }
    }
    None
}

/// Whether a process whose `/proc/<pid>/cgroup` reads `proc_cgroup` is inside `expected` (the service's cgroup or below it).
pub fn cgroup_is_within(proc_cgroup: &str, expected: &str) -> bool {
    let Some(path) = proc_cgroup.lines().find_map(|l| l.strip_prefix("0::")) else {
        return false;
    };
    let path = path.trim();
    path == expected
        || path
            .strip_prefix(expected)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Whether the peer of a connection may talk to this shim. Fails closed: a policy that names a cgroup admits nobody whose
/// cgroup cannot be read.
fn peer_allowed(conn: &UnixStream, policy: &PeerPolicy) -> bool {
    match policy {
        PeerPolicy::Any => true,
        PeerPolicy::DaemonCgroup(expected) => peer_pid(conn)
            .and_then(|p| fs::read_to_string(format!("/proc/{p}/cgroup")).ok())
            .is_some_and(|t| cgroup_is_within(&t, expected)),
    }
}

/// The text waiting for a run's standard input, written by one thread so a program that is not reading never blocks the
/// shim (a pipe holds about 64 KiB).
struct Feed {
    tx: mpsc::Sender<Vec<u8>>,
    pending: Arc<AtomicUsize>,
}

struct Shared {
    pid: u32,
    exited: Mutex<Option<i32>>,
    feed: Mutex<Option<Feed>>,
}

/// The state of the shim before the program exists.
enum Phase {
    Waiting,
    Started(Arc<Shared>),
}

struct Hold {
    phase: Mutex<Phase>,
    /// Hands the started child to the main thread, which waits for it.
    started: mpsc::Sender<Msg>,
    rec: RunRecord,
    dir: PathBuf,
    peers: PeerPolicy,
}

enum Msg {
    Started(Started),
    /// The program could not be started; its status (127) and a line in the log are already written.
    Failed,
}

struct Started {
    child: std::process::Child,
    pumps: Vec<mpsc::Receiver<()>>,
    shared: Arc<Shared>,
}

/// Run the shim. Returns the program's exit status, which is also the unit's, or an error the unit's journal will show
/// (never a secret: ids, kinds and reasons only).
pub fn serve(dir: &Path, id: &str, record_sha256: &str) -> Result<i32, String> {
    serve_with(dir, id, record_sha256, None)
}

/// As [`serve`]. `peers` of `None` takes the policy from the (verified) record: only the daemon's own service cgroup when
/// the record names one, anyone otherwise.
pub fn serve_with(
    dir: &Path,
    id: &str,
    record_sha256: &str,
    peers: Option<PeerPolicy>,
) -> Result<i32, String> {
    // the record this unit was started for must be exactly the record on disk
    let bytes =
        fs::read(dir.join(RECORD)).map_err(|e| format!("the run's record: {}", e.kind()))?;
    if sha256_hex(&bytes) != record_sha256 {
        return Err("the run's record is not the one this unit was started for".into());
    }
    let rec = RunRecord::parse(&bytes)?;
    if rec.id != id {
        return Err("the run's record names another run".into());
    }
    let peers = peers.unwrap_or_else(|| match &rec.daemon_cgroup {
        Some(c) => PeerPolicy::DaemonCgroup(c.clone()),
        None => PeerPolicy::Any,
    });
    // a signal that ends a service also reaches the program; the shim stays to write its status
    let term = Arc::new(AtomicBool::new(false));
    for sig in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGHUP] {
        let _ = signal_hook::flag::register(sig, term.clone());
    }
    let sock = dir.join(SOCK);
    let _ = fs::remove_file(&sock);
    let listener = UnixListener::bind(&sock).map_err(|e| format!("socket: {}", e.kind()))?;
    fs::set_permissions(&sock, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("socket mode: {}", e.kind()))?;
    let (tx, rx) = mpsc::channel::<Msg>();
    let hold = Arc::new(Hold {
        phase: Mutex::new(Phase::Waiting),
        started: tx,
        rec,
        dir: dir.to_path_buf(),
        peers,
    });
    {
        let hold = hold.clone();
        std::thread::Builder::new()
            .name("run-shim-io".into())
            .spawn(move || {
                for conn in listener.incoming().flatten() {
                    let hold = hold.clone();
                    // one thread a connection: a request that stalls never holds up the next
                    let _ = std::thread::Builder::new()
                        .name("run-shim-conn".into())
                        .spawn(move || handle(&hold, conn));
                }
            })
            .map_err(|e| format!("thread: {}", e.kind()))?;
    }
    let started = match rx.recv_timeout(START_WAIT) {
        Ok(Msg::Started(s)) => s,
        Ok(Msg::Failed) => return Ok(127),
        Err(_) => return Err("no start request arrived".into()),
    };
    let Started {
        mut child,
        pumps,
        shared,
    } = started;
    let code = match child.wait() {
        Ok(st) => {
            use std::os::unix::process::ExitStatusExt;
            st.code().unwrap_or_else(|| 128 + st.signal().unwrap_or(0))
        }
        Err(_) => 255,
    };
    // the last of its output reaches the log before the status says it is over
    for done in pumps {
        let _ = done.recv_timeout(OUTPUT_SETTLE);
    }
    write_exit(dir, code).map_err(|e| format!("status: {}", e.kind()))?;
    if let Ok(mut e) = shared.exited.lock() {
        *e = Some(code);
    }
    drop(term);
    Ok(code)
}

fn handle(hold: &Hold, mut conn: UnixStream) {
    let _ = conn.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = conn.set_write_timeout(Some(Duration::from_secs(10)));
    // before a byte is read: a process that is not the daemon gets a refusal, never an answer (and never a start)
    if !peer_allowed(&conn, &hold.peers) {
        let _ = write_frame(&mut conn, &Reply::fault(Fault::Refused));
        return;
    }
    let Ok(req) = read_frame::<_, Request>(&mut conn) else {
        let _ = write_frame(&mut conn, &Reply::fault(Fault::Refused));
        return;
    };
    let reply = answer(hold, req);
    let _ = write_frame(&mut conn, &reply);
}

fn answer(hold: &Hold, req: Request) -> Reply {
    let Ok(mut phase) = hold.phase.lock() else {
        return Reply::fault(Fault::Refused);
    };
    match (&*phase, req) {
        (
            Phase::Waiting,
            Request::Start {
                proto,
                argv,
                cwd,
                env,
                stdin,
            },
        ) => {
            if !SUPPORTED_PROTOS.contains(&proto) || argv.is_empty() {
                return Reply::fault(Fault::Refused);
            }
            match start_program(hold, &argv, cwd.as_deref(), &env, stdin) {
                Ok((child, pumps, shared)) => {
                    let reply = Reply::ok(Some(&shared));
                    *phase = Phase::Started(shared.clone());
                    let _ = hold.started.send(Msg::Started(Started {
                        child,
                        pumps,
                        shared,
                    }));
                    reply
                }
                Err(kind) => {
                    // as a shell would: the run exists, wrote why to its output and ended with 127
                    append_log(
                        &hold.dir,
                        &format!("ozbox-run: could not start the program ({kind})\n"),
                    );
                    let _ = write_exit(&hold.dir, 127);
                    let _ = hold.started.send(Msg::Failed);
                    Reply::fault(Fault::StartFailed)
                }
            }
        }
        (Phase::Waiting, _) => Reply::fault(Fault::Refused),
        (Phase::Started(_), Request::Start { .. }) => Reply::fault(Fault::Refused),
        (Phase::Started(shared), Request::Status) => Reply::ok(Some(shared)),
        (Phase::Started(shared), Request::Stdin { text }) => {
            if text.len() > MAX_STDIN || text.contains('\0') {
                return Reply::fault(Fault::Refused);
            }
            let Ok(feed) = shared.feed.lock() else {
                return Reply::fault(Fault::Refused);
            };
            let Some(feed) = feed.as_ref() else {
                return Reply::fault(Fault::BrokenPipe);
            };
            if text.is_empty() {
                return Reply::ok(Some(shared));
            }
            if feed.pending.load(Ordering::SeqCst) + text.len() > MAX_STDIN_PENDING {
                return Reply::fault(Fault::WouldBlock);
            }
            feed.pending.fetch_add(text.len(), Ordering::SeqCst);
            let n = text.len();
            if feed.tx.send(text.into_bytes()).is_err() {
                feed.pending.fetch_sub(n, Ordering::SeqCst);
                return Reply::fault(Fault::BrokenPipe);
            }
            Reply::ok(Some(shared))
        }
        (Phase::Started(shared), Request::CloseStdin) => {
            if let Ok(mut f) = shared.feed.lock() {
                *f = None;
            }
            Reply::ok(Some(shared))
        }
    }
}

type StartedParts = (std::process::Child, Vec<mpsc::Receiver<()>>, Arc<Shared>);

/// Start the program from its argv array. A shell is never involved.
fn start_program(
    hold: &Hold,
    argv: &[String],
    cwd: Option<&Path>,
    env: &BTreeMap<String, String>,
    stdin: Option<String>,
) -> Result<StartedParts, String> {
    let mut c = Command::new(&argv[0]);
    c.args(&argv[1..]);
    if let Some(d) = cwd {
        c.current_dir(d);
    }
    c.envs(env);
    c.stdin(if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    c.stdout(Stdio::piped()).stderr(Stdio::piped());
    let log_file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(hold.dir.join(LOG))
        .map_err(|e| format!("log: {}", e.kind()))?;
    let log = Arc::new(Mutex::new(CappedLog::new(log_file, hold.rec.log_max_bytes)));
    let mut child = c.spawn().map_err(|e| format!("{:?}", e.kind()))?;
    let mut pumps = Vec::new();
    if let Some(o) = child.stdout.take() {
        pumps.push(pump(o, log.clone()));
    }
    if let Some(e) = child.stderr.take() {
        pumps.push(pump(e, log));
    }
    let shared = Arc::new(Shared {
        pid: child.id(),
        exited: Mutex::new(None),
        feed: Mutex::new(None),
    });
    if let (Some(text), Some(mut pipe)) = (stdin, child.stdin.take()) {
        let keep = hold.rec.keep_stdin_open;
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        let pending = Arc::new(AtomicUsize::new(0));
        if keep {
            if let Ok(mut f) = shared.feed.lock() {
                *f = Some(Feed {
                    tx,
                    pending: pending.clone(),
                });
            }
        }
        let _ = std::thread::Builder::new()
            .name("run-shim-stdin".into())
            .spawn(move || {
                if pipe.write_all(text.as_bytes()).is_err() {
                    return;
                }
                if !keep {
                    return; // dropping the pipe is the program's end-of-file
                }
                // ends when the feed is dropped (close, or the program leaving)
                while let Ok(more) = rx.recv() {
                    let n = more.len();
                    let ok = pipe.write_all(&more).and_then(|_| pipe.flush()).is_ok();
                    pending.fetch_sub(n, Ordering::SeqCst);
                    if !ok {
                        return;
                    }
                }
            });
    }
    Ok((child, pumps, shared))
}

/// Copy a pipe into the capped log; the receiver says when the pipe has ended.
fn pump<R: Read + Send + 'static>(mut src: R, log: Arc<Mutex<CappedLog>>) -> mpsc::Receiver<()> {
    let (done, rx) = mpsc::channel();
    let _ = std::thread::Builder::new()
        .name("run-shim-log".into())
        .spawn(move || {
            let mut buf = [0u8; 8192];
            while let Ok(n) = src.read(&mut buf) {
                if n == 0 {
                    break;
                }
                if let Ok(mut l) = log.lock() {
                    l.write(&buf[..n]);
                }
            }
            let _ = done.send(());
        });
    rx
}

fn append_log(dir: &Path, line: &str) {
    if let Ok(mut f) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join(LOG))
    {
        let _ = f.write_all(line.as_bytes());
    }
}

/// A file written whole and durably: to a temporary file in the same folder, flushed to disk, renamed into place, and the
/// folder flushed, so a crash or a power loss leaves the old file or the new one, never half of one, and never a rename
/// that the disk has not recorded.
pub fn write_atomic(dir: &Path, name: &str, bytes: &[u8], mode: u32) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = dir.join(format!("{name}.tmp"));
    let _ = fs::remove_file(&tmp);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, dir.join(name))?;
    fs::File::open(dir)?.sync_all()
}

/// The exit status, written whole and durably (see [`write_atomic`]).
pub fn write_exit(dir: &Path, code: i32) -> io::Result<()> {
    write_atomic(dir, EXIT, format!("{{\"code\":{code}}}").as_bytes(), 0o600)
}

/// The exit status a run's shim wrote, if it has.
pub fn read_exit(dir: &Path) -> Option<i32> {
    #[derive(Deserialize)]
    struct Exit {
        code: i32,
    }
    let bytes = fs::read(dir.join(EXIT)).ok()?;
    serde_json::from_slice::<Exit>(&bytes).ok().map(|e| e.code)
}
