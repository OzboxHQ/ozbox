//! The browser's own Unix user (ADR 0037, amendment 4).
//!
//! The browser worker, its Chromium and its profiles run as `ozbox-browser`, not as the box user an agent's shell runs as.
//! A process of the box user then cannot read a profile's cookies, start a Chromium against a profile, open Chromium's
//! control pipe through `/proc/<pid>/fd`, or signal the worker: the kernel refuses each across users.
//!
//! The pieces, in the way the per-project runner users work (see `runner.rs`):
//!
//! * a **root launcher**, socket-activated (`ozbox-browser.socket`), one process per connection (`ozbox browser-launch`).
//!   It reads the session's first line (the worker's settings and key), refuses anything that is not what the browser
//!   tools send, and starts `ozbox browser-worker` with `systemd-run` as `ozbox-browser` inside a systemd sandbox. The
//!   connection is the worker's standard input and output, so the sealed channel of `ozbox_browser::channel` stays the
//!   only way in and no new port or file is involved;
//! * the **socket belongs to the dashboard's user** (`ozbox-supervisor`), never to the box group. If the box user (an agent)
//!   could connect it could start a worker against any profile and drive it with a key of its own, which would close
//!   nothing. So the isolated browser exists where the dashboard runs on the box as its own user; a dashboard on another
//!   computer reaches a worker through the box daemon, as the box user, as before (the plan says which);
//! * [`LauncherBrowserBackend`], the dashboard's end: it talks to the socket and falls back to the daemon for any other box.
//!
//! Every pure decision (what the launcher accepts, the exact `systemd-run` argument list, which box is this one) is a
//! function here so a test can read it on any computer; the sandbox itself is proven only on a Linux box.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ozbox_browser::channel::Channel;
use ozbox_browser::protocol::{Reply, Start};
use ozbox_browser::record::{self, Meta, Step};

use crate::browser_tools::{BrowserBackend, WorkerRun};

pub const BROWSER_USER: &str = "ozbox-browser";
pub const LAUNCH_SOCKET: &str = "/run/ozbox-browser/launch.sock";
/// The launcher's socket unit: installed by the setup, readable by everyone.
pub const LAUNCH_UNIT: &str = "/etc/systemd/system/ozbox-browser.socket";
/// What the box's other users may read: recordings and the documents a session released.
pub const SHARED_ROOT: &str = "/work/ozbox-browser/shared";
/// What only the browser's user may open: profiles, held-back downloads, a paused session's saved place, its home.
pub const PRIVATE_ROOT: &str = "/work/ozbox-browser/private";
pub const WORK: &str = "/work";
/// The most the launcher reads for a session's first line, and the memory a session may be given.
const MAX_FIRST_LINE: usize = 64 * 1024;
const MIN_MEMORY: u64 = 256 * 1024 * 1024;
const MAX_MEMORY: u64 = 32 * 1024 * 1024 * 1024;
/// A session never runs longer than this, whatever it asks for (the policy's own limits are far below).
const MAX_RUNTIME_S: u64 = 3 * 24 * 3600;
const WORKER_PROGRAM: &str = "/usr/local/bin/ozbox";

/// Whether the launcher will start this session, and why not. The paths are the box's fixed ones: a host that names another
/// folder is refused, so the worker can never be pointed at the box user's files, the secrets store or the system.
pub fn check_start(s: &Start) -> Result<(), String> {
    if !record::valid_session_id(&s.session) {
        return Err("that is not a session id".into());
    }
    if s.root != SHARED_ROOT {
        return Err("the recording folder is not this box's".into());
    }
    if s.private_root.as_deref() != Some(PRIVATE_ROOT) {
        return Err("the private folder is not this box's".into());
    }
    if s.work != WORK {
        return Err("the work folder is not this box's".into());
    }
    s.policy.validate()?;
    let m = s.memory_max_bytes.unwrap_or(0);
    if !(MIN_MEMORY..=MAX_MEMORY).contains(&m) {
        return Err("a session needs a memory limit between 256 MiB and 32 GiB".into());
    }
    let t = s.max_runtime_s.unwrap_or(0);
    if t == 0 || t > MAX_RUNTIME_S {
        return Err("a session needs a time limit of up to three days".into());
    }
    // the key must be one a channel accepts, so a refusal can be sealed and a worker will open it
    Channel::worker(&s.key, &s.session).map(|_| ())
}

/// The exact `systemd-run` call that starts a session's worker. Pure, so a test reads it: it is the whole of the sandbox.
/// It holds no secret (the key travels on standard input, never in an argument).
///
/// What each choice is for:
/// * `--pipe --wait`: the connection is the worker's standard input and output, and the launcher ends when the worker does;
/// * the user and group are the browser's own; no supplementary group, so it cannot open the box daemon's or the
///   secrets service's sockets (they are also out of its view);
/// * `ProtectSystem=strict` and one writable folder: its own tree;
/// * `ProtectHome` and an explicit hide of the box user's home and the other service accounts' folders;
/// * `ProtectProc=invisible`: it does not see the other users' processes;
/// * a memory cap, no swap, a task cap and a backstop run time;
/// * the box's metadata addresses are refused by the kernel, so a page that gets code running in the renderer still cannot
///   reach the cloud account's credentials; the box's loopback stays open (a person may browse their own dev server);
/// * `UMask=0027`: a file the worker writes is readable by the group of its folder (recordings) and by no one else.
///
/// Left out on purpose: `NoNewPrivileges`, `RestrictNamespaces` and a system-call filter. Chromium's own sandbox is made
/// from user namespaces, and on an Ubuntu image the AppArmor profile that allows it attaches at exec; a filter written
/// without a real box to try it on would break the browser or give a false sense of safety. A real-box run is the place to try tightening them.
pub fn systemd_run_argv(s: &Start) -> Vec<String> {
    let home = format!("{PRIVATE_ROOT}/home");
    let mut v: Vec<String> = ["systemd-run", "--quiet", "--pipe", "--wait", "--collect"]
        .iter()
        .map(|x| (*x).to_string())
        .collect();
    v.push(format!("--unit=ozbox-browser-{}", s.session));
    // every session is in one slice, which has a ceiling of its own (the setup makes it), so the browsers together can never
    // take the memory the agent's work and the box's own program need
    v.push("--slice=ozbox-browser.slice".into());
    v.push(format!("--uid={BROWSER_USER}"));
    v.push(format!("--gid={BROWSER_USER}"));
    v.push(format!("--working-directory={PRIVATE_ROOT}"));
    let memory = s.memory_max_bytes.unwrap_or(MIN_MEMORY);
    let runtime = s.max_runtime_s.unwrap_or(3600);
    let props = [
        format!("Environment=HOME={home}"),
        format!("Environment=XDG_CONFIG_HOME={home}/config"),
        format!("Environment=XDG_CACHE_HOME={home}/cache"),
        "Environment=PATH=/usr/local/bin:/usr/bin:/bin".to_string(),
        "UMask=0027".into(),
        "PrivateTmp=yes".into(),
        "ProtectSystem=strict".into(),
        "ProtectHome=yes".into(),
        "ProtectProc=invisible".into(),
        "ProtectKernelTunables=yes".into(),
        "ProtectKernelModules=yes".into(),
        "ProtectKernelLogs=yes".into(),
        "ProtectControlGroups=yes".into(),
        "RestrictSUIDSGID=yes".into(),
        "LockPersonality=yes".into(),
        "LimitCORE=0".into(),
        format!("MemoryMax={memory}"),
        "MemorySwapMax=0".into(),
        "TasksMax=4096".into(),
        format!("RuntimeMaxSec={}", runtime.saturating_add(300)),
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK".into(),
        "IPAddressDeny=169.254.169.254/32 fd00:ec2::254/128".into(),
        "ReadWritePaths=/work/ozbox-browser".into(),
        // the box user's home, the other service accounts' folders and the box's own sockets are not in its view
        "InaccessiblePaths=-/work/home -/work/ozbox-supervisor -/var/lib/ozbox-run -/var/lib/ozbox-secrets -/run/ozbox-secrets -/run/ozbox-runner -/run/ozbox-admin -/run/ozbox-browser -/run/ozboxd -/etc/ozbox".to_string(),
    ];
    for p in props {
        v.push("-p".into());
        v.push(p);
    }
    v.push("--".into());
    v.push(WORKER_PROGRAM.into());
    v.push("browser-worker".into());
    v
}

/// Read one line of at most `max` bytes, leaving whatever follows it in the reader. `None` when the line is too long or the
/// input ended first.
fn read_first_line<R: BufRead>(r: &mut R, max: usize) -> Option<String> {
    let mut line: Vec<u8> = Vec::new();
    loop {
        let buf = r.fill_buf().ok()?;
        if buf.is_empty() {
            return None;
        }
        let (take, done) = match buf.iter().position(|b| *b == b'\n') {
            Some(i) => (i + 1, true),
            None => (buf.len(), false),
        };
        if line.len() + take > max {
            return None;
        }
        line.extend_from_slice(&buf[..take]);
        r.consume(take);
        if done {
            return String::from_utf8(line).ok();
        }
    }
}

/// Answer a refusal in the only way the session's tool host can read it: sealed with the session's own key.
fn refuse<W: Write>(out: &mut W, s: &Start, why: &str) {
    if let Ok(mut c) = Channel::worker(&s.key, &s.session) {
        let r = Reply::err(0, "failed", why.to_string());
        let line = c.seal(0, &serde_json::to_vec(&r).unwrap_or_default());
        let _ = writeln!(out, "{line}");
        let _ = out.flush();
    }
}

/// Whether `bytes` of memory are free, by the text of `/proc/meminfo` (`MemAvailable`). A text that says nothing is not
/// refused: the ceiling of the browsers' slice still applies.
pub fn fits(meminfo: &str, bytes: u64) -> bool {
    let kib = meminfo.lines().find_map(|l| {
        let rest = l.strip_prefix("MemAvailable:")?;
        rest.trim()
            .trim_end_matches("kB")
            .trim()
            .parse::<u64>()
            .ok()
    });
    match kib {
        None => true,
        Some(k) => k.saturating_mul(1024) >= bytes,
    }
}

/// How long a worker has to end after its input ended, before its unit is stopped.
const STOP_GRACE: Duration = Duration::from_secs(5);

/// The launcher's work for one connection: check the first line, start the worker as the browser's user, and carry the
/// connection to its standard input and output until either side ends. `program` is `systemd-run` (a test gives a stand-in).
/// Returns whether a worker was started.
#[cfg(test)]
pub fn serve<R, W>(program: &str, input: R, output: W) -> bool
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    serve_with(program, "systemctl", STOP_GRACE, None, input, output)
}

/// [`serve`] with the stopper, the grace and the memory source named. When the host ends the connection and the worker has not
/// ended after `grace`, the stopper stops its unit (a worker that ignores the end of its input cannot keep running, nor keep
/// this process and its connection slot). When `meminfo` is given, a session that asks for more memory than is free is refused.
pub fn serve_with<R, W>(
    program: &str,
    stopper: &str,
    grace: Duration,
    meminfo: Option<&Path>,
    input: R,
    mut output: W,
) -> bool
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    let mut reader = BufReader::new(input);
    let Some(mut first) = read_first_line(&mut reader, MAX_FIRST_LINE) else {
        return false;
    };
    let Ok(start) = serde_json::from_str::<Start>(first.trim()) else {
        zeroize::Zeroize::zeroize(&mut first);
        return false;
    };
    if let Err(why) = check_start(&start) {
        zeroize::Zeroize::zeroize(&mut first);
        refuse(&mut output, &start, &why);
        return false;
    }
    if let Some(p) = meminfo {
        let text = std::fs::read_to_string(p).unwrap_or_default();
        if !fits(&text, start.memory_max_bytes.unwrap_or(0)) {
            zeroize::Zeroize::zeroize(&mut first);
            refuse(
                &mut output,
                &start,
                "this box does not have that much memory free for a browser session now; close another session or try again",
            );
            return false;
        }
    }
    let unit = format!("ozbox-browser-{}.service", start.session);
    let argv = systemd_run_argv(&start);
    let spawned = Command::new(program)
        .args(&argv[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    let Ok(mut child) = spawned else {
        zeroize::Zeroize::zeroize(&mut first);
        refuse(&mut output, &start, "the browser could not be started");
        return false;
    };
    let (Some(mut to_worker), Some(mut from_worker)) = (child.stdin.take(), child.stdout.take())
    else {
        zeroize::Zeroize::zeroize(&mut first);
        let _ = child.kill();
        return false;
    };
    let worker_done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let done = Arc::clone(&worker_done);
    let stopper = stopper.to_string();
    // The first line, then whatever the host sends after it. When the host ends the connection, the worker's input ends,
    // and the worker closes its browser cleanly; one that does not is stopped after the grace. This thread is never waited
    // for: the launcher ends when the worker does, and that closes the connection, whichever side is still open.
    std::thread::spawn(move || {
        let wrote = to_worker.write_all(first.as_bytes());
        zeroize::Zeroize::zeroize(&mut first);
        let mut ended_by_host = wrote.is_err();
        if !ended_by_host {
            let _ = to_worker.flush();
            let mut buf = [0u8; 16 * 1024];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => {
                        ended_by_host = true;
                        break;
                    }
                    Ok(n) => {
                        if to_worker.write_all(&buf[..n]).is_err() || to_worker.flush().is_err() {
                            break;
                        }
                    }
                }
            }
        }
        // the buffer of the reader held the first line: it is gone with the reader
        drop(to_worker);
        if ended_by_host {
            let t = Instant::now();
            while t.elapsed() < grace && !done.load(std::sync::atomic::Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(20));
            }
            if !done.load(std::sync::atomic::Ordering::SeqCst) {
                let _ = Command::new(&stopper)
                    .args(["stop", &unit])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
        }
    });
    let mut buf = [0u8; 16 * 1024];
    loop {
        match from_worker.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if output.write_all(&buf[..n]).is_err() || output.flush().is_err() {
                    break;
                }
            }
        }
    }
    drop(from_worker);
    let _ = child.wait();
    worker_done.store(true, std::sync::atomic::Ordering::SeqCst);
    true
}

/// The launcher's entry: the connection is standard input and output (the socket unit connects both).
pub fn serve_stdio() {
    serve_with(
        "systemd-run",
        "systemctl",
        STOP_GRACE,
        Some(Path::new("/proc/meminfo")),
        std::io::stdin(),
        std::io::stdout(),
    );
    // Ending the process closes the connection, so the dashboard sees the end of the session at once even when its own
    // side is still open (the thread that reads it may be waiting for a line that will never come).
    std::process::exit(0);
}

/// The setup script (the user, its folders, the launcher's units), carried in the program so first-boot configuration does not
/// have to carry it.
const SETUP_SCRIPT: &str = include_str!("../../../infra/cloud-init/scripts/ozbox-browser-setup.sh");

/// Run the setup script with bash, as the caller (root). Ends the process with the script's exit status.
pub fn run_setup(args: &[String]) -> Result<(), crate::run::CliError> {
    let mut c = Command::new("bash")
        .arg("-s")
        .arg("--")
        .args(args)
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|_| crate::run::CliError::Msg("bash could not be started".into()))?;
    if let Some(mut i) = c.stdin.take() {
        let _ = i.write_all(SETUP_SCRIPT.as_bytes());
    }
    let st = c
        .wait()
        .map_err(|_| crate::run::CliError::Msg("the setup did not finish".into()))?;
    std::process::exit(st.code().unwrap_or(1));
}

// ---- the dashboard's end -------------------------------------------------------------------------------------------------

/// The name of the box this computer is, from its host name (first-boot configuration sets the host name to the box name).
pub fn local_box_name(hostname_file: &str) -> Option<String> {
    let n = hostname_file.trim();
    (!n.is_empty() && n.len() <= 63).then(|| n.to_string())
}

struct Conn {
    stream: UnixStream,
    lines: mpsc::Receiver<String>,
    ended: bool,
}

/// Browser sessions on this box through the launcher's socket, and any other box through `other` (the daemon). A handle
/// that begins with `sock-` is the launcher's; every other is `other`'s.
pub struct LauncherBrowserBackend {
    socket: PathBuf,
    local_box: String,
    other: Arc<dyn BrowserBackend>,
    conns: Mutex<HashMap<String, Conn>>,
    next: Mutex<u64>,
    /// Where recordings are read from (the shared root, which this dashboard's user may read through an ACL entry of its own: it is
    /// not in the box user's group, ADR 0040 decision 3).
    shared: PathBuf,
}

fn lk<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl LauncherBrowserBackend {
    pub fn new(
        socket: impl Into<PathBuf>,
        local_box: impl Into<String>,
        shared: impl Into<PathBuf>,
        other: Arc<dyn BrowserBackend>,
    ) -> Self {
        Self {
            socket: socket.into(),
            local_box: local_box.into(),
            other,
            conns: Mutex::new(HashMap::new()),
            next: Mutex::new(0),
            shared: shared.into(),
        }
    }

    /// The launcher's backend, when this computer is a box that is set up for it (its launcher's socket exists, or its unit is
    /// installed: the setup ran) and knows its own name; otherwise `None`, and the caller keeps using the daemon for every box.
    ///
    /// Once the setup has run here, this box's sessions NEVER fall back to the box user's browser: a launcher that does not
    /// answer is a refusal that says so, checked at every start (a socket that is not there when the dashboard starts, or
    /// stops later, must not quietly move a person's sign-ins into a profile the agent can read).
    pub fn detect(other: Arc<dyn BrowserBackend>) -> Option<Arc<dyn BrowserBackend>> {
        Self::detect_at(
            Path::new(LAUNCH_SOCKET),
            Path::new(LAUNCH_UNIT),
            Path::new("/etc/hostname"),
            Path::new(SHARED_ROOT),
            other,
        )
    }

    pub(crate) fn detect_at(
        socket: &Path,
        unit: &Path,
        hostname: &Path,
        shared: &Path,
        other: Arc<dyn BrowserBackend>,
    ) -> Option<Arc<dyn BrowserBackend>> {
        use std::os::unix::fs::FileTypeExt;
        let is_socket = std::fs::symlink_metadata(socket).is_ok_and(|m| m.file_type().is_socket());
        // the unit is world-readable; its being there means the setup ran, whether or not the socket can be seen from here
        let set_up = is_socket || std::fs::symlink_metadata(unit).is_ok();
        let name = std::fs::read_to_string(hostname)
            .ok()
            .and_then(|t| local_box_name(&t));
        match (set_up, name) {
            (true, Some(n)) => Some(Arc::new(Self::new(socket, n, shared, other))),
            _ => None,
        }
    }

    fn is_local(&self, box_name: &str) -> bool {
        box_name == self.local_box
    }

    fn mine(handle: &str) -> bool {
        handle.starts_with("sock-")
    }
}

impl BrowserBackend for LauncherBrowserBackend {
    fn start(&self, box_name: &str, first_line: &str, run: &WorkerRun) -> Result<String, String> {
        if !self.is_local(box_name) {
            return self.other.start(box_name, first_line, run);
        }
        let mut stream = UnixStream::connect(&self.socket).map_err(|_| {
            "this box's browser launcher did not answer, so no browser session was started (it is never started as the box user instead, because that would keep its sign-ins where an agent can read them): run `ozbox browser-setup` on the box as root, or upgrade the box".to_string()
        })?;
        let reader = stream.try_clone().map_err(|e| e.to_string())?;
        let (tx, rx) = mpsc::channel::<String>();
        std::thread::spawn(move || {
            for line in BufReader::new(reader).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let mut first = first_line.to_string();
        if !first.ends_with('\n') {
            first.push('\n');
        }
        let wrote = stream
            .write_all(first.as_bytes())
            .and_then(|()| stream.flush());
        zeroize::Zeroize::zeroize(&mut first);
        wrote.map_err(|e| e.to_string())?;
        let handle = {
            let mut n = lk(&self.next);
            *n += 1;
            format!("sock-{}", *n)
        };
        lk(&self.conns).insert(
            handle.clone(),
            Conn {
                stream,
                lines: rx,
                ended: false,
            },
        );
        Ok(handle)
    }

    fn send(&self, box_name: &str, handle: &str, line: &str) -> Result<(), String> {
        if !Self::mine(handle) {
            return self.other.send(box_name, handle, line);
        }
        let mut g = lk(&self.conns);
        let c = g.get_mut(handle).ok_or("that session is not running")?;
        let mut l = line.to_string();
        l.push('\n');
        c.stream
            .write_all(l.as_bytes())
            .and_then(|()| c.stream.flush())
            .map_err(|_| "the browser session has ended".to_string())
    }

    fn next_line(
        &self,
        box_name: &str,
        handle: &str,
        deadline: Instant,
    ) -> Result<Option<String>, String> {
        if !Self::mine(handle) {
            return self.other.next_line(box_name, handle, deadline);
        }
        // Wait in short turns so a lock is never held across a long wait.
        loop {
            {
                let mut g = lk(&self.conns);
                let c = g.get_mut(handle).ok_or("that session is not running")?;
                if c.ended {
                    return Err("the browser session has ended".into());
                }
                match c.lines.recv_timeout(Duration::from_millis(50)) {
                    Ok(l) => return Ok(Some(l)),
                    Err(RecvTimeoutError::Disconnected) => {
                        c.ended = true;
                        return Err("the browser session has ended".into());
                    }
                    Err(RecvTimeoutError::Timeout) => {}
                }
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
        }
    }

    fn stop(&self, box_name: &str, handle: &str) {
        if !Self::mine(handle) {
            return self.other.stop(box_name, handle);
        }
        if let Some(c) = lk(&self.conns).remove(handle) {
            // ending the connection ends the worker's input: it closes its browser and exits
            let _ = c.stream.shutdown(std::net::Shutdown::Both);
        }
    }

    fn roots(&self, box_name: &str) -> (String, String) {
        if self.is_local(box_name) {
            (SHARED_ROOT.into(), WORK.into())
        } else {
            self.other.roots(box_name)
        }
    }

    fn private_root(&self, box_name: &str) -> Option<String> {
        if self.is_local(box_name) {
            Some(PRIVATE_ROOT.into())
        } else {
            self.other.private_root(box_name)
        }
    }

    fn list_sessions(&self, box_name: &str) -> Result<Vec<Meta>, String> {
        if !self.is_local(box_name) {
            return self.other.list_sessions(box_name);
        }
        Ok(record::list_sessions(&self.shared))
    }

    fn steps(&self, box_name: &str, session: &str) -> Result<Vec<Step>, String> {
        if !self.is_local(box_name) {
            return self.other.steps(box_name, session);
        }
        record::load_steps(&self.shared, session)
    }

    fn shot(&self, box_name: &str, session: &str, name: &str) -> Result<Vec<u8>, String> {
        if !self.is_local(box_name) {
            return self.other.shot(box_name, session, name);
        }
        if !record::valid_session_id(session) || !crate::browser_tools::valid_shot(name) {
            return Err("no such picture".into());
        }
        std::fs::read(
            record::session_dir(&self.shared, session)
                .join("shots")
                .join(name),
        )
        .map_err(|_| "no such picture".into())
    }
}

#[cfg(test)]
mod tests;
