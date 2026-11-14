//! Reaching a box's daemon from this computer, with no inbound port on the box (ADR 0005).
//!
//! The daemon listens on a Unix socket. To read it, this opens an `ssh -L <local socket>:<daemon socket>` forward over
//! the provider's own route (AWS Session Manager, or a Cloudflare tunnel), on demand:
//!
//! * The forward is a child `ssh` process started with an argv array, against a throw-away config file written from the
//!   same text `ozbox connect --ssh` shows, so it does not depend on the person's own SSH setup.
//! * The local socket lives in a directory created with mode 0700 and a random name; the config file is 0600.
//! * One forward per box is cached and reused. Idle forwards are closed by [`BoxAgent::housekeeping`]; all of them are
//!   closed when the server stops.
//! * Requests are HTTP/1.1 over that socket, one connection per request (the daemon closes after each answer), with a
//!   deadline and a size limit.
//! * A forward that cannot be made, or an answer that cannot be read, is [`AgentError::Unreachable`] with a reason a
//!   person can act on.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ozbox_core::{BoxRecord, CommandSpec, MetricsSample};
use serde::Deserialize;
use serde_json::Value;

use super::agent::{
    parse_image_agent, AgentError, BoxAgent, FileInput, FileReply, ImageAgent, Incident, SelfTest,
    IMAGE_AGENT_COMMAND,
};
use crate::sshconfig::{self, RouteInputs};
use crate::state::format_rfc3339;

pub const DAEMON_SOCKET: &str = "/run/ozboxd/ozboxd.sock";
/// The dashboard user's own socket to the box daemon (ADR 0040, decision 3). systemd (root) binds it in a folder root owns
/// (`ozboxd-supervisor.socket`), `root:ozbox-supervisor 0660`, and hands it to the daemon; see `ozbox_core::daemon_scope`.
/// On a box this is the only path the dashboard's agent connects to.
pub const DAEMON_SUPERVISOR_SOCKET: &str = "/run/ozbox-supervisor-api/daemon.sock";
/// Overrides the socket path in a DEBUG build only (the browser tests start a stand-in daemon). A release build ignores it, so
/// nothing in a box's environment can point the dashboard at another socket.
pub const DAEMON_SUPERVISOR_SOCKET_ENV: &str = "OZBOX_DAEMON_SUPERVISOR_SOCKET";
/// The dashboard's own audit line for a call on its socket to the box daemon (G1 M4, N7): every change, and the terminal
/// attach, which is a read that puts a keyboard in a session. Only the route's name and method, never a path, id or body.
fn dashboard_audit_line(method: &str, route: &str) -> Option<String> {
    let read = matches!(method, "GET" | "HEAD");
    (!read || route == "terminal_attach")
        .then(|| format!("ozbox: audit via=dashboard-socket route={route} method={method}"))
}

const NOT_ON_A_BOX: &str = "that is not available on a box's dashboard";
const MAX_ANSWER: usize = 4 * 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(8);

/// A running forward.
pub trait Forward: Send {
    fn alive(&mut self) -> bool;
    fn kill(&mut self);
    /// The last words the forward printed, for the reason when it dies.
    fn last_words(&self) -> String;
}

/// Starts a forward. Separate from [`ozbox_core::CommandRunner`], which runs a command to completion.
pub trait Spawn: Send + Sync {
    fn spawn(&self, spec: &CommandSpec, stderr_to: &Path) -> std::io::Result<Box<dyn Forward>>;
}

pub struct SystemSpawn;

struct Proc {
    child: Child,
    stderr: PathBuf,
}

impl Forward for Proc {
    fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
    fn last_words(&self) -> String {
        last_line(&self.stderr)
    }
}

fn last_line(path: &Path) -> String {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|t| {
            t.lines()
                .rev()
                .find(|l| !l.trim().is_empty())
                .map(str::to_string)
        })
        .map(|l| l.chars().filter(|c| !c.is_control()).take(240).collect())
        .unwrap_or_default()
}

impl Spawn for SystemSpawn {
    fn spawn(&self, spec: &CommandSpec, stderr_to: &Path) -> std::io::Result<Box<dyn Forward>> {
        let err = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(stderr_to)?;
        let child = Command::new(&spec.program)
            .args(&spec.args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(err))
            .spawn()?;
        Ok(Box::new(Proc {
            child,
            stderr: stderr_to.to_path_buf(),
        }))
    }
}

struct Tunnel {
    proc: Box<dyn Forward>,
    /// The machine the forward goes to. An upgrade replaces a box's machine and gives it a new id; a forward opened to
    /// the old one can still look alive for a while, and must never be reused for the new one.
    instance: Option<String>,
    socket: PathBuf,
    last_used: Instant,
    /// Transfers in progress: a forward carrying one is never closed as idle.
    active: Arc<AtomicUsize>,
}

/// A reverse forward: a port on this computer's loopback made reachable on the box's own loopback address.
struct Reverse {
    proc: Box<dyn Forward>,
    instance: Option<String>,
    last_used: Instant,
}

/// Counts a transfer against its forward for as long as it lives.
struct ActiveGuard(Arc<AtomicUsize>);

impl ActiveGuard {
    fn new(c: Arc<AtomicUsize>) -> Self {
        c.fetch_add(1, Ordering::SeqCst);
        Self(c)
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

struct GuardedReader<R> {
    inner: R,
    _guard: ActiveGuard,
}

impl<R: Read> Read for GuardedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

pub struct SshAgent {
    spawner: Arc<dyn Spawn>,
    dir: PathBuf,
    inputs: RouteInputs,
    idle: Duration,
    connect_wait: Duration,
    tunnels: Mutex<BTreeMap<String, Tunnel>>,
    /// One opener per forward key: a second caller for the same key waits for the first and reuses its forward, so a
    /// shared socket path is never deleted under a handshake that is still running.
    opening: Mutex<BTreeMap<String, Arc<Mutex<()>>>>,
    /// Reverse forwards, by box and port (`<box>#R<port>`): how a run on a box reaches the credential broker that runs
    /// here, over the same outbound connection and never through a port open on the box.
    reverses: Mutex<BTreeMap<String, Reverse>>,
    /// How long a new reverse forward is watched for an early failure (a port already taken on the box).
    reverse_settle: Duration,
    /// The dashboard runs on the box itself: the dashboard user's own socket to the daemon is opened directly, with no SSH.
    /// It is the only socket used, and only for the routes of `ozbox_core::daemon_scope`.
    local: Option<PathBuf>,
    /// The owner and group the socket must have (`root` and this process's own group) before anything is sent to it.
    /// `None` only in tests, which bind their stand-in sockets as themselves.
    local_trust: Option<(u32, u32)>,
}

/// This process's effective group id, from `/proc/self/status` (`Gid:` real, effective, saved, filesystem). An unreadable
/// answer is `u32::MAX`, a group nothing has, so the socket check then fails closed.
fn own_gid() -> u32 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|t| {
            t.lines()
                .find_map(|l| l.strip_prefix("Gid:"))
                .and_then(|r| r.split_whitespace().nth(1).and_then(|g| g.parse().ok()))
        })
        .unwrap_or(u32::MAX)
}

/// Why the dashboard's socket is not used.
#[derive(Debug, PartialEq, Eq)]
pub enum SocketCheck {
    Missing,
    /// Not the socket the host set up: a link, another kind of file, or the wrong owner, group or mode.
    NotTrusted,
}

/// Whether `path` is the socket the host set up for this user: a real socket (never a link), owned by `owner_uid`, in
/// `group_gid`, mode `0660`, in a folder that `owner_uid` owns and nobody else can write to. Read with `lstat`, so a link
/// is never followed. The folder is root's, so the box user cannot replace or impersonate the socket.
pub fn check_scoped_socket(path: &Path, owner_uid: u32, group_gid: u32) -> Result<(), SocketCheck> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let md = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(SocketCheck::Missing),
        Err(_) => return Err(SocketCheck::NotTrusted),
    };
    if !md.file_type().is_socket()
        || md.uid() != owner_uid
        || md.gid() != group_gid
        || md.mode() & 0o7777 != 0o660
    {
        return Err(SocketCheck::NotTrusted);
    }
    let dir = path.parent().ok_or(SocketCheck::NotTrusted)?;
    let dm = std::fs::symlink_metadata(dir).map_err(|_| SocketCheck::NotTrusted)?;
    if !dm.is_dir() || dm.uid() != owner_uid || dm.mode() & 0o022 != 0 {
        return Err(SocketCheck::NotTrusted);
    }
    Ok(())
}

fn short_hash(s: &str) -> String {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for b in s.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{:08x}", (h ^ (h >> 32)) as u32)
}

impl SshAgent {
    /// A fresh private directory under `/tmp` (short, because a Unix socket path is limited to about 104 bytes).
    pub fn new(spawner: Arc<dyn Spawn>, inputs: RouteInputs) -> Result<Self, String> {
        let mut rnd = [0u8; 6];
        getrandom::getrandom(&mut rnd).map_err(|e| format!("no secure random source: {e}"))?;
        let name: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
        let dir = PathBuf::from(format!("/tmp/ozbox-{name}"));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .map_err(|e| format!("cannot create the runtime directory: {e}"))?;
        Ok(SshAgent {
            spawner,
            dir,
            inputs,
            idle: Duration::from_secs(300),
            connect_wait: crate::ssh_limits::forward_wait(),
            tunnels: Mutex::new(BTreeMap::new()),
            opening: Mutex::new(BTreeMap::new()),
            reverses: Mutex::new(BTreeMap::new()),
            reverse_settle: Duration::from_secs(3),
            local: None,
            local_trust: None,
        })
    }

    /// The agent of a dashboard that runs on the box it shows: the dashboard user's own socket to the daemon (a fixed path;
    /// a debug build honours `OZBOX_DAEMON_SUPERVISOR_SOCKET` for the browser tests), loopback ports by plain TCP, and
    /// nothing that needs an SSH route. The socket must be owned by root, in this process's own group and `0660` before it
    /// is used; there is no other socket to fall back to.
    pub fn local(spawner: Arc<dyn Spawn>, inputs: RouteInputs) -> Result<Self, String> {
        #[cfg(debug_assertions)]
        let test_socket = std::env::var(DAEMON_SUPERVISOR_SOCKET_ENV)
            .or_else(|_| std::env::var(crate::this_box::DAEMON_SOCKET_ENV))
            .ok();
        #[cfg(not(debug_assertions))]
        let test_socket: Option<String> = None;
        match test_socket {
            Some(p) => Self::local_at(spawner, inputs, PathBuf::from(p)),
            None => {
                let mut a =
                    Self::local_at(spawner, inputs, PathBuf::from(DAEMON_SUPERVISOR_SOCKET))?;
                a.local_trust = Some((0, own_gid()));
                Ok(a)
            }
        }
    }

    pub fn local_at(
        spawner: Arc<dyn Spawn>,
        inputs: RouteInputs,
        socket: PathBuf,
    ) -> Result<Self, String> {
        let mut a = Self::new(spawner, inputs)?;
        a.local = Some(socket);
        Ok(a)
    }

    #[cfg(test)]
    fn tuned(mut self, idle: Duration, connect_wait: Duration) -> Self {
        self.idle = idle;
        self.connect_wait = connect_wait;
        self.reverse_settle = Duration::from_millis(60);
        self
    }

    fn sock_path(&self, name: &str) -> PathBuf {
        self.dir.join(format!("s{}.sock", short_hash(name)))
    }

    /// The throw-away SSH settings file for a box, written from the same text `ozbox connect --ssh` shows.
    fn conf_for(&self, rec: &BoxRecord) -> Result<PathBuf, AgentError> {
        if self.local.is_some() {
            return Err(AgentError::Unreachable(
                "this dashboard runs on the box itself, so this needs a connection from your own computer".into(),
            ));
        }
        let route = sshconfig::routes(rec, &self.inputs).into_iter().next().ok_or_else(|| {
            AgentError::Unreachable(
                "no SSH route is known for this box: an AWS box needs its instance id and a region, other boxes need a configured domain and tunnel".into(),
            )
        })?;
        let name = rec.spec.name.as_str();
        let conf = self.dir.join(format!("c{}.conf", short_hash(name)));
        write_private(&conf, &sshconfig::block(name, &route)).map_err(|_| {
            AgentError::Unreachable("cannot write the temporary SSH settings".into())
        })?;
        Ok(conf)
    }

    /// The forward key of a box: its agent socket, or one loopback port on the box.
    fn key_of(name: &str, port: Option<u16>) -> String {
        match port {
            None => name.to_string(),
            Some(p) => format!("{name}#{p}"),
        }
    }

    /// The ssh invocation that forwards a local socket to the box's agent socket (`port` `None`) or to a loopback port
    /// on the box (`Some`; the IDE and the desktop), as an argv array.
    pub fn command_for(
        &self,
        rec: &BoxRecord,
        port: Option<u16>,
    ) -> Result<(CommandSpec, String), AgentError> {
        let name = rec.spec.name.as_str();
        let conf = self.conf_for(rec)?;
        let sock = self.sock_path(&Self::key_of(name, port));
        let target = match port {
            None => DAEMON_SOCKET.to_string(),
            Some(p) => format!("127.0.0.1:{p}"),
        };
        let spec = CommandSpec::new("ssh")
            .arg("-F")
            .arg(conf.to_string_lossy())
            .args(["-N", "-T"])
            .args(["-o", "BatchMode=yes"])
            .args(["-o".to_string(), crate::ssh_limits::option()])
            .args(["-o", "ExitOnForwardFailure=yes"])
            .args(["-o", "StreamLocalBindUnlink=yes"])
            .args(["-o", "StrictHostKeyChecking=accept-new"])
            .args([
                "-o",
                "ServerAliveInterval=15",
                "-o",
                "ServerAliveCountMax=3",
            ])
            .arg("-L")
            .arg(format!("{}:{target}", sock.display()))
            .arg(sshconfig::host_alias(name));
        Ok((spec, sock.to_string_lossy().into_owned()))
    }

    /// The ssh invocation that makes `port` on this computer's loopback reachable at the same number on the box's
    /// loopback. Both ends are spelled out as `127.0.0.1`: the box side is never a wildcard, so no other machine can use
    /// it, and `GatewayPorts` is not relied on. `ExitOnForwardFailure` ends it at once if the box's port is taken.
    pub fn command_for_reverse(
        &self,
        rec: &BoxRecord,
        port: u16,
    ) -> Result<CommandSpec, AgentError> {
        let conf = self.conf_for(rec)?;
        Ok(CommandSpec::new("ssh")
            .arg("-F")
            .arg(conf.to_string_lossy())
            .args(["-N", "-T"])
            .args(["-o", "BatchMode=yes"])
            .args(["-o".to_string(), crate::ssh_limits::option()])
            .args(["-o", "ExitOnForwardFailure=yes"])
            .args(["-o", "StrictHostKeyChecking=accept-new"])
            .args([
                "-o",
                "ServerAliveInterval=15",
                "-o",
                "ServerAliveCountMax=3",
            ])
            .arg("-R")
            .arg(format!("127.0.0.1:{port}:127.0.0.1:{port}"))
            .arg(sshconfig::host_alias(rec.spec.name.as_str())))
    }

    /// Run one fixed command on the box over the same route and return what it printed. `remote` is fixed program text
    /// chosen by this program, never user input.
    pub fn exec_command(&self, rec: &BoxRecord, remote: &str) -> Result<CommandSpec, AgentError> {
        let conf = self.conf_for(rec)?;
        Ok(CommandSpec::new("ssh")
            .arg("-F")
            .arg(conf.to_string_lossy())
            .arg("-T")
            .args(["-o", "BatchMode=yes"])
            .args(["-o".to_string(), crate::ssh_limits::option()])
            .args(["-o", "StrictHostKeyChecking=accept-new"])
            .args([
                "-o",
                "ServerAliveInterval=15",
                "-o",
                "ServerAliveCountMax=3",
            ])
            .arg(sshconfig::host_alias(rec.spec.name.as_str()))
            .arg(remote))
    }

    /// [`Self::exec_command`], run to completion within `limit`.
    pub fn exec(
        &self,
        rec: &BoxRecord,
        remote: &str,
        limit: Duration,
    ) -> Result<(bool, String), AgentError> {
        let spec = self.exec_command(rec, remote)?;
        let mut child = Command::new(&spec.program)
            .args(&spec.args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| {
                AgentError::Unreachable(
                    "the ssh program could not be started; is OpenSSH installed?".into(),
                )
            })?;
        let start = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let mut out = String::new();
                    if let Some(mut so) = child.stdout.take() {
                        let _ = so.by_ref().take(MAX_ANSWER as u64).read_to_string(&mut out);
                    }
                    if !status.success() && out.trim().is_empty() {
                        let mut err = String::new();
                        if let Some(mut se) = child.stderr.take() {
                            let _ = se.by_ref().take(2000).read_to_string(&mut err);
                        }
                        let why: String = err
                            .lines()
                            .rev()
                            .find(|l| !l.trim().is_empty())
                            .unwrap_or("the connection closed")
                            .chars()
                            .filter(|c| !c.is_control())
                            .take(240)
                            .collect();
                        return Err(AgentError::Unreachable(why));
                    }
                    return Ok((status.success(), out));
                }
                Ok(None) if start.elapsed() < limit => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(AgentError::Unreachable(
                        "the box did not answer over SSH in time".into(),
                    ));
                }
            }
        }
    }

    /// [`Self::exec_command`] with `script` on standard input (never in an argument), run to completion within `limit`.
    /// Returns the exit status and `(true, what it printed)`.
    pub fn exec_stdin(
        &self,
        rec: &BoxRecord,
        remote: &str,
        script: String,
        limit: Duration,
    ) -> Result<(Option<i32>, (bool, String)), AgentError> {
        let spec = self.exec_command(rec, remote)?.stdin(script.into_bytes());
        let mut child = Command::new(&spec.program)
            .args(&spec.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| {
                AgentError::Unreachable(
                    "the ssh program could not be started; is OpenSSH installed?".into(),
                )
            })?;
        if let (Some(mut i), Some(bytes)) = (child.stdin.take(), spec.stdin.as_ref()) {
            let _ = i.write_all(bytes);
        }
        let start = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let mut out = String::new();
                    if let Some(mut so) = child.stdout.take() {
                        let _ = so.by_ref().take(MAX_ANSWER as u64).read_to_string(&mut out);
                    }
                    if status.code() == Some(255) {
                        // ssh's own words (a refused key, a timeout, a missing proxy program), not a generic line
                        let mut err = String::new();
                        if let Some(mut se) = child.stderr.take() {
                            let _ = se.by_ref().take(2000).read_to_string(&mut err);
                        }
                        let why: String = err
                            .lines()
                            .rev()
                            .find(|l| !l.trim().is_empty() && !l.contains("Permanently added"))
                            .unwrap_or("the connection closed")
                            .chars()
                            .filter(|c| !c.is_control())
                            .take(240)
                            .collect();
                        return Err(AgentError::Unreachable(why));
                    }
                    return Ok((status.code(), (status.success(), out)));
                }
                Ok(None) if start.elapsed() < limit => {
                    std::thread::sleep(Duration::from_millis(50))
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(AgentError::Unreachable(
                        "the box did not answer over SSH in time".into(),
                    ));
                }
            }
        }
    }

    /// The local socket for a box, opening the forward if there is none that works. A dashboard on a box has no such
    /// socket for a call off the dashboard's table: that is not available there (it never reaches the box user's socket).
    fn socket(&self, rec: &BoxRecord) -> Result<PathBuf, AgentError> {
        if self.local.is_some() {
            return Err(AgentError::Unsupported(NOT_ON_A_BOX.into()));
        }
        self.socket_for(rec, None)
    }

    /// The socket for one call. On a box the dashboard's own socket carries the routes of the table, and nothing else is
    /// sent anywhere: a route off the table is "not available on a box's dashboard", never tried on another socket.
    fn socket_route(
        &self,
        rec: &BoxRecord,
        method: &str,
        path: &str,
    ) -> Result<PathBuf, AgentError> {
        if self.local.is_some() {
            let bare = path.split(['?', '#']).next().unwrap_or(path);
            match ozbox_core::daemon_scope::allowed(method, bare) {
                None => return Err(AgentError::Unsupported(NOT_ON_A_BOX.into())),
                // The dashboard's own record of what it asked the box user's daemon to do, written to the dashboard's
                // journal (which the box user cannot read or flood): the daemon's journal line is the box's own claim.
                // Only changes (reads are not noise here), and only the route's name, never a path, id or body.
                Some(r) => {
                    if let Some(line) = dashboard_audit_line(method, r.name) {
                        eprintln!("{line}");
                    }
                }
            }
        }
        self.socket_for(rec, None)
    }

    fn socket_for(&self, rec: &BoxRecord, port: Option<u16>) -> Result<PathBuf, AgentError> {
        if let (Some(sock), None) = (&self.local, port) {
            // The socket is already local: no forward. It is checked (never followed through a link) and then opened
            // without connecting (a socket file refuses an open with ENXIO once the caller may reach it), which tells "not
            // there" from "not allowed" without using up a connection.
            if let Some((uid, gid)) = self.local_trust {
                match check_scoped_socket(sock, uid, gid) {
                    Ok(()) => {}
                    Err(SocketCheck::Missing) => {
                        return Err(AgentError::Unreachable(
                            "this box's agent is not running (its socket is missing). A box whose agent predates this release has none: upgrade it with ozbox admin <box> -- reinstall-ozboxd".into(),
                        ))
                    }
                    Err(SocketCheck::NotTrusted) => {
                        return Err(AgentError::Unreachable(
                            "the dashboard's socket to this box's agent is not the one the box set up (wrong owner, group or mode), so it is not used".into(),
                        ))
                    }
                }
            }
            return match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(sock)
            {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(AgentError::Unreachable(
                    "this box's agent is not running (its socket is missing). A box whose agent predates this release has none: upgrade it with ozbox admin <box> -- reinstall-ozboxd".into(),
                )),
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    Err(AgentError::Unreachable(
                        "the dashboard's user may not open this box's agent socket".into(),
                    ))
                }
                _ => Ok(sock.clone()),
            };
        }
        let name = Self::key_of(rec.spec.name.as_str(), port);
        let gate = {
            let mut o = self.opening.lock().map_err(|_| poisoned())?;
            Arc::clone(o.entry(name.clone()).or_default())
        };
        // held to the end: whoever comes second finds the first one's forward below
        let _opening = gate.lock().unwrap_or_else(|e| e.into_inner());
        {
            let mut t = self.tunnels.lock().map_err(|_| poisoned())?;
            if let Some(tun) = t.get_mut(&name) {
                if tun.instance == rec.provider_id
                    && tun.proc.alive()
                    && UnixStream::connect(&tun.socket).is_ok()
                {
                    tun.last_used = Instant::now();
                    return Ok(tun.socket.clone());
                }
                tun.proc.kill();
                t.remove(&name);
            }
        }
        let (spec, sock) = self.command_for(rec, port)?;
        let sock = PathBuf::from(sock);
        let _ = std::fs::remove_file(&sock);
        let log = self.dir.join(format!("e{}.log", short_hash(&name)));
        let mut proc = self.spawner.spawn(&spec, &log).map_err(|_| {
            AgentError::Unreachable(
                "the ssh program could not be started; is OpenSSH installed?".into(),
            )
        })?;
        let start = Instant::now();
        loop {
            if UnixStream::connect(&sock).is_ok() {
                break;
            }
            if !proc.alive() {
                let why = proc.last_words();
                return Err(AgentError::Unreachable(format!(
                    "the SSH connection to the box closed before it was ready{}",
                    if why.is_empty() {
                        String::new()
                    } else {
                        format!(": {why}")
                    }
                )));
            }
            if start.elapsed() > self.connect_wait {
                let why = proc.last_words();
                proc.kill();
                return Err(AgentError::Unreachable(format!(
                    "the SSH connection to the box did not come up in time{}",
                    if why.is_empty() {
                        String::new()
                    } else {
                        format!(": {why}")
                    }
                )));
            }
            std::thread::sleep(Duration::from_millis(40));
        }
        let mut t = self.tunnels.lock().map_err(|_| poisoned())?;
        let old = t.insert(
            name,
            Tunnel {
                proc,
                instance: rec.provider_id.clone(),
                socket: sock.clone(),
                last_used: Instant::now(),
                active: Arc::new(AtomicUsize::new(0)),
            },
        );
        if let Some(mut o) = old {
            // never leave a replaced ssh running
            o.proc.kill();
        }
        Ok(sock)
    }

    /// The box's agent's own answer for sessions, agents and servers; `None` when it cannot be had (unreachable, or an
    /// agent from before these endpoints), so the caller falls back to SSH.
    fn daemon_procs(&self, rec: &BoxRecord) -> Option<crate::code::procs::Procs> {
        let s = self.get(rec, "/v1/sessions").ok()?;
        let p = self.get(rec, "/v1/processes").ok()?;
        Some(crate::code::procs::Procs {
            tmux: s.get("tmux")?.as_bool()?,
            sessions: serde_json::from_value(s.get("sessions")?.clone()).ok()?,
            agents: serde_json::from_value(p.get("agents")?.clone()).ok()?,
            servers: serde_json::from_value(p.get("servers")?.clone()).ok()?,
        })
    }

    /// A stop through the box's agent. `None`: not reachable or an older agent (404/405): use SSH. `Some`: its answer.
    fn daemon_stop(
        &self,
        rec: &BoxRecord,
        stop: &crate::code::procs::Stop,
    ) -> Option<Result<(), AgentError>> {
        let path = match stop {
            crate::code::procs::Stop::Session(n) => format!("/v1/sessions/{n}/stop"),
            crate::code::procs::Stop::Process(p) => format!("/v1/processes/{p}/stop"),
        };
        let sock = self.socket_route(rec, "POST", &path).ok()?;
        let (status, body) = request(&sock, "POST", &path).ok()?;
        match status {
            200..=299 => Some(Ok(())),
            _ => {
                let msg = serde_json::from_slice::<Value>(&body)
                    .ok()
                    .and_then(|v| v.get("error").and_then(Value::as_str).map(str::to_string));
                // An agent from before these endpoints answers 405, or 404 "not found" for the path itself.
                if status == 405 || (status == 404 && msg.as_deref() == Some("not found")) {
                    return None;
                }
                let msg = msg.unwrap_or_else(|| "it could not be stopped".into());
                Some(Err(AgentError::Unsupported(
                    msg.chars().filter(|c| !c.is_control()).take(160).collect(),
                )))
            }
        }
    }

    fn get(&self, rec: &BoxRecord, path: &str) -> Result<Value, AgentError> {
        let sock = self.socket_route(rec, "GET", path)?;
        let (status, body) = request(&sock, "GET", path)?;
        parse_answer(status, &body)
    }

    fn guard(&self, name: &str) -> Option<ActiveGuard> {
        let t = self.tunnels.lock().ok()?;
        t.get(name)
            .map(|tun| ActiveGuard::new(Arc::clone(&tun.active)))
    }

    fn close(&self, name: &str) {
        if let Ok(mut t) = self.tunnels.lock() {
            if let Some(mut tun) = t.remove(name) {
                tun.proc.kill();
            }
        }
    }

    /// How many forwards are open (for tests and the status line).
    #[cfg(test)]
    fn open_count(&self) -> usize {
        self.tunnels.lock().map(|t| t.len()).unwrap_or(0)
    }
}

impl Drop for SshAgent {
    fn drop(&mut self) {
        if let Ok(mut r) = self.reverses.lock() {
            for rev in r.values_mut() {
                rev.proc.kill();
            }
            r.clear();
        }
        if let Ok(mut t) = self.tunnels.lock() {
            for tun in t.values_mut() {
                tun.proc.kill();
            }
            t.clear();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn poisoned() -> AgentError {
    AgentError::Unreachable("the agent connection state is unavailable".into())
}

fn write_private(path: &Path, text: &str) -> std::io::Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(text.as_bytes())?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

/// One HTTP/1.1 request over a Unix socket. Returns the status and the body.
fn request(sock: &Path, method: &str, path: &str) -> Result<(u16, Vec<u8>), AgentError> {
    request_with_body(sock, method, path, &[])
}

/// The same, with a JSON body (the tool installer's POSTs).
fn request_with_body(
    sock: &Path,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<(u16, Vec<u8>), AgentError> {
    request_with_cap(sock, method, path, body, None)
}

/// One request to the box daemon; with `capability`, it carries a controlled run's capability in its header.
fn request_with_cap(
    sock: &Path,
    method: &str,
    path: &str,
    body: &[u8],
    capability: Option<&str>,
) -> Result<(u16, Vec<u8>), AgentError> {
    let unreachable = |m: &str| AgentError::Unreachable(m.to_string());
    let mut s = UnixStream::connect(sock)
        .map_err(|_| unreachable("the box's agent socket did not accept a connection"))?;
    let _ = s.set_read_timeout(Some(REQUEST_TIMEOUT));
    let _ = s.set_write_timeout(Some(REQUEST_TIMEOUT));
    let cap_line = match capability {
        Some(c) if !c.is_empty() && c.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') => {
            format!("X-Ozbox-Run-Capability: {c}\r\n")
        }
        Some(_) => {
            return Err(AgentError::Unsupported(
                "that capability is not valid".into(),
            ))
        }
        None => String::new(),
    };
    let head = format!("{method} {path} HTTP/1.1\r\nHost: ozboxd\r\nAccept: application/json\r\nContent-Type: application/json\r\nConnection: close\r\n{cap_line}Content-Length: {}\r\n\r\n", body.len());
    s.write_all(head.as_bytes())
        .and_then(|_| s.write_all(body))
        .map_err(|_| unreachable("the box's agent did not accept the request"))?;
    let mut raw = Vec::new();
    let mut buf = [0u8; 16 * 1024];
    loop {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&buf[..n]);
                if raw.len() > MAX_ANSWER {
                    return Err(unreachable("the box's agent answered with too much data"));
                }
            }
            Err(_) => return Err(unreachable("the box's agent did not answer in time")),
        }
    }
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| unreachable("the box's agent answered with something that is not HTTP"))?;
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let mut lines = head.lines();
    let status: u16 = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| unreachable("the box's agent answered with something that is not HTTP"))?;
    let mut length = None;
    for l in lines {
        let l = l.to_ascii_lowercase();
        if let Some(v) = l.strip_prefix("content-length:") {
            length = v.trim().parse::<usize>().ok();
        }
        if l.starts_with("transfer-encoding:") && l.contains("chunked") {
            return Err(unreachable(
                "the box's agent answered in a format this version does not read",
            ));
        }
    }
    let mut body = raw[split + 4..].to_vec();
    if let Some(n) = length {
        body.truncate(n);
    }
    Ok((status, body))
}

fn encode_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~/".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `path?k=v&...` with every key and value percent-encoded.
fn with_query(path: &str, query: &BTreeMap<String, String>) -> String {
    if query.is_empty() {
        return path.to_string();
    }
    let q: Vec<String> = query
        .iter()
        .map(|(k, v)| format!("{}={}", encode_component(k), encode_component(v)))
        .collect();
    format!("{path}?{}", q.join("&"))
}

/// Idle time allowed on a file transfer's socket before it is given up.
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(60);

/// One file-API call over the forward: send the request (streaming any body), read the answer head, and hand back the
/// body as a stream (or in memory for a JSON answer). The body is never held in memory, so a large file costs no RAM here.
fn files_request(
    sock: &Path,
    method: &str,
    target: &str,
    input: FileInput<'_>,
    guard: Option<ActiveGuard>,
) -> Result<FileReply, AgentError> {
    use super::agent::FileBody;
    let unreachable = |m: &str| AgentError::Unreachable(m.to_string());
    let mut s = UnixStream::connect(sock)
        .map_err(|_| unreachable("the box's agent socket did not accept a connection"))?;
    let _ = s.set_read_timeout(Some(TRANSFER_TIMEOUT));
    let _ = s.set_write_timeout(Some(TRANSFER_TIMEOUT));
    let len = match &input {
        FileInput::None => 0,
        FileInput::Bytes(b) => b.len() as u64,
        FileInput::Stream { len, .. } => *len,
    };
    let head = format!("{method} {target} HTTP/1.1\r\nHost: ozboxd\r\nConnection: close\r\nContent-Length: {len}\r\n\r\n");
    s.write_all(head.as_bytes())
        .map_err(|_| unreachable("the box's agent did not accept the request"))?;
    match input {
        FileInput::None => {}
        FileInput::Bytes(b) => {
            s.write_all(b)
                .map_err(|_| unreachable("the box's agent did not accept the request"))?;
        }
        FileInput::Stream { reader, len } => {
            // The daemon may answer early (a refused upload) and stop reading: that is its answer, not an error.
            let mut limited = reader.take(len);
            let _ = std::io::copy(&mut limited, &mut s);
        }
    }
    // Read the answer head byte-wise up to the blank line, so no body bytes are consumed.
    let mut raw = Vec::new();
    let mut one = [0u8; 1];
    while !raw.ends_with(b"\r\n\r\n") {
        match s.read(&mut one) {
            Ok(1) => raw.push(one[0]),
            _ => return Err(unreachable("the box's agent did not answer in time")),
        }
        if raw.len() > 16 * 1024 {
            return Err(unreachable(
                "the box's agent answered with something that is not HTTP",
            ));
        }
    }
    let text = String::from_utf8_lossy(&raw).into_owned();
    let mut lines = text.split("\r\n");
    let status: u16 = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| unreachable("the box's agent answered with something that is not HTTP"))?;
    let mut headers = Vec::new();
    let mut length: Option<u64> = None;
    for l in lines {
        let Some((k, v)) = l.split_once(':') else {
            continue;
        };
        let (k, v) = (k.trim(), v.trim());
        if k.eq_ignore_ascii_case("content-length") {
            length = v.parse().ok();
        } else if !k.eq_ignore_ascii_case("connection") && !k.eq_ignore_ascii_case("cache-control")
        {
            headers.push((k.to_string(), v.to_string()));
        }
    }
    let length = length.ok_or_else(|| {
        unreachable("the box's agent answered in a format this version does not read")
    })?;
    let json = headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("content-type") && v.starts_with("application/json"));
    let body = if json {
        if length as usize > MAX_ANSWER {
            return Err(unreachable("the box's agent answered with too much data"));
        }
        let mut b = Vec::new();
        s.take(length)
            .read_to_end(&mut b)
            .map_err(|_| unreachable("the box's agent did not answer in time"))?;
        FileBody::Bytes(b)
    } else {
        let inner = s.take(length);
        match guard {
            Some(g) => FileBody::Stream {
                reader: Box::new(GuardedReader { inner, _guard: g }),
                len: length,
            },
            None => FileBody::Stream {
                reader: Box::new(inner),
                len: length,
            },
        }
    };
    Ok(FileReply {
        status,
        headers,
        body,
    })
}

/// A local-AI answer as the dashboard's server reads it: `ok`, and a message when it was refused.
fn local_ai_reply(status: u16, body: &[u8]) -> Value {
    let v: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    if (200..300).contains(&status) {
        let mut out = serde_json::json!({ "ok": true });
        if let Some(s) = v["state"].as_str() {
            out["state"] = Value::from(s);
        }
        return out;
    }
    let m: String = v["message"]
        .as_str()
        .or_else(|| v["error"].as_str())
        .unwrap_or("the box could not do that")
        .chars()
        .filter(|c| !c.is_control())
        .take(160)
        .collect();
    serde_json::json!({ "ok": false, "message": m })
}

fn parse_answer(status: u16, body: &[u8]) -> Result<Value, AgentError> {
    if !(200..300).contains(&status) {
        let msg = serde_json::from_slice::<Value>(body)
            .ok()
            .and_then(|v| v.get("error").and_then(Value::as_str).map(str::to_string))
            .unwrap_or_default();
        let msg: String = msg.chars().filter(|c| !c.is_control()).take(160).collect();
        return Err(AgentError::Unreachable(format!(
            "the box's agent answered HTTP {status}{}",
            if msg.is_empty() {
                String::new()
            } else {
                format!(": {msg}")
            }
        )));
    }
    serde_json::from_slice(body).map_err(|_| {
        AgentError::Unreachable("the box's agent answered with data that is not understood".into())
    })
}

#[derive(Deserialize)]
struct Agg {
    mean: f64,
    last: f64,
}

#[derive(Deserialize)]
struct Point {
    ts_ms: u64,
    fields: BTreeMap<String, Agg>,
}

/// A rollup point as a sample: means for rates and gauges, and the last value for free disk space.
fn sample_of(p: &Point) -> MetricsSample {
    let m = |k: &str| p.fields.get(k).map_or(0.0, |a| a.mean);
    let l = |k: &str| p.fields.get(k).map_or(0.0, |a| a.last);
    MetricsSample {
        ts_ms: p.ts_ms,
        cpu_pct: m("cpu_pct"),
        mem_total_bytes: l("mem_total_bytes") as u64,
        mem_available_bytes: m("mem_available_bytes") as u64,
        swap_total_bytes: l("swap_total_bytes") as u64,
        swap_free_bytes: m("swap_free_bytes") as u64,
        psi_cpu_some_avg10: m("psi_cpu_some_avg10"),
        psi_mem_some_avg10: m("psi_mem_some_avg10"),
        psi_io_some_avg10: m("psi_io_some_avg10"),
        disk_total_bytes: l("disk_total_bytes") as u64,
        disk_free_bytes: l("disk_free_bytes") as u64,
        disk_read_bps: m("disk_read_bps"),
        disk_write_bps: m("disk_write_bps"),
        net_rx_bps: m("net_rx_bps"),
        net_tx_bps: m("net_tx_bps"),
        gpus: Vec::new(),
        runs: Vec::new(),
    }
}

fn step_label(step_ms: u64) -> &'static str {
    match step_ms {
        0..=5_000 => "5s",
        5_001..=60_000 => "1m",
        _ => "1h",
    }
}

impl BoxAgent for SshAgent {
    fn connect_tcp(&self, rec: &BoxRecord, port: u16) -> Result<super::agent::Conn, AgentError> {
        if self.local.is_some() {
            let s = std::net::TcpStream::connect_timeout(
                &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
                Duration::from_secs(3),
            )
            .map_err(|_| {
                AgentError::Unreachable("nothing on this box is listening on that port".into())
            })?;
            return super::agent::Conn::from_tcp(s)
                .map_err(|_| AgentError::Unreachable("the connection could not be used".into()));
        }
        let sock = self.socket_for(rec, Some(port))?;
        let s = UnixStream::connect(&sock).map_err(|_| {
            AgentError::Unreachable("the connection to the box did not accept a connection".into())
        })?;
        let key = Self::key_of(rec.spec.name.as_str(), Some(port));
        // Held while the connection lives, so the forward is not closed as idle under a person working.
        let hold = self.guard(&key).map(|g| Box::new(g) as Box<dyn Send>);
        super::agent::Conn::from_unix(s, hold).map_err(|_| {
            AgentError::Unreachable("the connection to the box could not be used".into())
        })
    }

    fn code_status(&self, rec: &BoxRecord) -> Result<crate::code::BoxCode, AgentError> {
        let (_, out) = self.exec_stdin(
            rec,
            "bash -s",
            crate::code::status_script(),
            Duration::from_secs(40),
        )?;
        crate::code::parse_status(&out.1).ok_or_else(|| {
            AgentError::Unreachable("the box answered, but not with what was asked".into())
        })
    }

    fn code_procs(&self, rec: &BoxRecord) -> Result<crate::code::procs::Procs, AgentError> {
        // The box's own agent answers (GET /v1/sessions and /v1/processes). A box whose agent is not reachable, or is an
        // older one that does not know these, is read with the fixed script over SSH as before.
        if let Some(p) = self.daemon_procs(rec) {
            return Ok(p);
        }
        let (_, out) = self.exec_stdin(
            rec,
            "bash -s",
            crate::code::procs::ps_script(),
            Duration::from_secs(40),
        )?;
        crate::code::procs::parse_ps(&out.1).ok_or_else(|| {
            AgentError::Unreachable("the box answered, but not with what was asked".into())
        })
    }

    fn code_stop(
        &self,
        rec: &BoxRecord,
        stop: &crate::code::procs::Stop,
    ) -> Result<(), AgentError> {
        if let Some(r) = self.daemon_stop(rec, stop) {
            return r;
        }
        let (status, (_, out)) =
            self.exec_stdin(rec, "bash -s", stop.script(), Duration::from_secs(40))?;
        if status == Some(0) && out.lines().any(|l| l.trim() == "ok") {
            Ok(())
        } else {
            Err(AgentError::Unsupported(match status {
                Some(30) => "that process is not yours or is already gone".into(),
                Some(31) => "that is not a coding agent or a server, so it was left alone".into(),
                _ => "it could not be stopped".into(),
            }))
        }
    }

    fn code_change(&self, rec: &BoxRecord, change: &crate::code::Change) -> Result<(), AgentError> {
        let script = crate::code::change_script(change).map_err(AgentError::Unsupported)?;
        let (status, (_, out)) =
            self.exec_stdin(rec, "bash -s", script, Duration::from_secs(90))?;
        if status == Some(0) && out.lines().any(|l| l.trim() == "ok") {
            Ok(())
        } else {
            Err(AgentError::Unsupported(crate::messages::t(
                crate::code::failure_key(status),
                &[],
            )))
        }
    }

    fn terminal(
        &self,
        rec: &BoxRecord,
        cols: u16,
        rows: u16,
        session: Option<&str>,
    ) -> Result<super::terminal::Conn, AgentError> {
        let sock = self.socket_route(rec, "GET", "/v1/terminal")?;
        let mut s = UnixStream::connect(&sock).map_err(|_| {
            AgentError::Unreachable("the box's agent socket did not accept a connection".into())
        })?;
        let _ = s.set_write_timeout(Some(REQUEST_TIMEOUT));
        s.write_all(super::terminal::request_line(cols, rows, session).as_bytes())
            .map_err(|_| {
                AgentError::Unreachable("the box's agent did not accept the request".into())
            })?;
        super::terminal::handshake(&mut s)?;
        let _ = s.set_write_timeout(None);
        // Held while the session lives, so the forward is not closed as idle under a person typing.
        let hold = self
            .guard(rec.spec.name.as_str())
            .map(|g| Box::new(g) as Box<dyn Send>);
        Ok(super::terminal::Conn { stream: s, hold })
    }

    fn agent_call(
        &self,
        rec: &BoxRecord,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> Result<(u16, Value), AgentError> {
        // built by this program from a box, a pane id and a few numbers; anything else is refused before it is a path
        let known = path == "/v1/agent-sessions"
            || path == "/v1/agent-events"
            || path.starts_with("/v1/agent-sessions/")
            || path.starts_with("/v1/agent-events");
        if !known
            || !path.bytes().all(|b| {
                b.is_ascii_alphanumeric()
                    || matches!(b, b'/' | b'?' | b'=' | b'&' | b'_' | b'-' | b'%')
            })
        {
            return Err(AgentError::Unsupported(
                "that agent request is not valid".into(),
            ));
        }
        let sock = self.socket_route(rec, method, path)?;
        let (status, raw) = request_with_body(&sock, method, path, body)?;
        let v = serde_json::from_slice(&raw).map_err(|_| {
            AgentError::Unreachable(
                "the box's agent answered with data that is not understood".into(),
            )
        })?;
        Ok((status, v))
    }

    fn runs(
        &self,
        rec: &BoxRecord,
        method: &str,
        sub: &str,
        body: &[u8],
    ) -> Result<(u16, Value), AgentError> {
        // `sub` is built by this program from a run id and a byte offset; refuse anything else before it is a path
        if !sub.is_empty()
            && !sub.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'/' | b'?' | b'=' | b'&' | b'_' | b'-')
            })
        {
            return Err(AgentError::Unsupported(
                "that run request is not valid".into(),
            ));
        }
        let sock = self.socket_route(rec, method, &format!("/v1/runs{sub}"))?;
        let (status, raw) = request_with_body(&sock, method, &format!("/v1/runs{sub}"), body)?;
        let v = serde_json::from_slice(&raw).map_err(|_| {
            AgentError::Unreachable(
                "the box's agent answered with data that is not understood".into(),
            )
        })?;
        Ok((status, v))
    }

    fn quiesce_call(
        &self,
        rec: &BoxRecord,
        method: &str,
        body: &[u8],
    ) -> Result<(u16, Value), AgentError> {
        if !matches!(method, "GET" | "POST" | "DELETE") {
            return Err(AgentError::Unsupported(
                "that quiesce request is not valid".into(),
            ));
        }
        let sock = self.socket_route(rec, method, "/v1/quiesce")?;
        let (status, raw) = request_with_body(&sock, method, "/v1/quiesce", body)?;
        let v = serde_json::from_slice(&raw).map_err(|_| {
            AgentError::Unreachable(
                "the box's agent answered with data that is not understood".into(),
            )
        })?;
        Ok((status, v))
    }

    fn runs_controlled(
        &self,
        rec: &BoxRecord,
        method: &str,
        sub: &str,
        body: &[u8],
        capability: &str,
    ) -> Result<(u16, Value), AgentError> {
        if !sub.is_empty()
            && !sub.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'/' | b'?' | b'=' | b'&' | b'_' | b'-')
            })
        {
            return Err(AgentError::Unsupported(
                "that run request is not valid".into(),
            ));
        }
        let sock = self.socket_route(rec, method, &format!("/v1/runs{sub}"))?;
        let (status, raw) = request_with_cap(
            &sock,
            method,
            &format!("/v1/runs{sub}"),
            body,
            Some(capability),
        )?;
        let v = serde_json::from_slice(&raw).map_err(|_| {
            AgentError::Unreachable(
                "the box's agent answered with data that is not understood".into(),
            )
        })?;
        Ok((status, v))
    }

    fn reverse_forward(&self, rec: &BoxRecord, port: u16) -> Result<(), AgentError> {
        if port < 1024 {
            return Err(AgentError::Unsupported(
                "only ports from 1024 up can be forwarded to a box".into(),
            ));
        }
        // A dashboard on the box itself already shares the loopback with the box's agents: the servers a run is pointed at
        // (the broker, the tool host) are reachable at 127.0.0.1 as they are, so there is nothing to forward.
        if self.local.is_some() {
            return Ok(());
        }
        let key = format!("{}#R{port}", rec.spec.name.as_str());
        {
            let mut r = self.reverses.lock().map_err(|_| poisoned())?;
            if let Some(rev) = r.get_mut(&key) {
                if rev.instance == rec.provider_id && rev.proc.alive() {
                    rev.last_used = Instant::now();
                    return Ok(());
                }
                rev.proc.kill();
                r.remove(&key);
            }
        }
        let spec = self.command_for_reverse(rec, port)?;
        let log = self.dir.join(format!("r{}.log", short_hash(&key)));
        let mut proc = self.spawner.spawn(&spec, &log).map_err(|_| {
            AgentError::Unreachable(
                "the ssh program could not be started; is OpenSSH installed?".into(),
            )
        })?;
        // a port already taken on the box, or a forward the box refuses, ends ssh within moments of connecting
        let start = Instant::now();
        while start.elapsed() < self.reverse_settle {
            if !proc.alive() {
                let why = proc.last_words();
                return Err(AgentError::Unreachable(format!(
                    "the connection that lets the box reach the model broker could not be made{}",
                    if why.is_empty() {
                        String::new()
                    } else {
                        format!(": {why}")
                    }
                )));
            }
            std::thread::sleep(Duration::from_millis(40));
        }
        let mut r = self.reverses.lock().map_err(|_| poisoned())?;
        r.insert(
            key,
            Reverse {
                proc,
                instance: rec.provider_id.clone(),
                last_used: Instant::now(),
            },
        );
        Ok(())
    }

    fn local_ai(&self, rec: &BoxRecord, request: &Value) -> Result<Value, AgentError> {
        let sock = self.socket(rec)?;
        let rt = request["runtime"].as_str().unwrap_or_default();
        // An agent from before local models answers "not found" for the route itself; a model that is not on the box is a
        // 404 with its own message, and that one is the caller's to read.
        let old = |status: u16, body: &[u8]| {
            let v: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
            let gone = (status == 404 && v["error"] == "not found")
                || (status == 503 && v["code"] == "local_ai_unavailable");
            gone.then(|| {
                serde_json::json!({ "ok": false, "message": "this box's agent does not manage local models; upgrade the box" })
            })
        };
        match request["action"].as_str() {
            Some("list") | Some("status") => {
                let (status, body) = request_with_body(&sock, "GET", "/v1/local-ai", &[])?;
                if let Some(v) = old(status, &body) {
                    return Ok(v);
                }
                let v = parse_answer(status, &body)?;
                if request["action"] == "status" {
                    return Ok(serde_json::json!({ "ok": true, "status": v }));
                }
                let models: Vec<Value> = v["runtimes"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .find(|r| r["id"] == rt)
                    .and_then(|r| r["models"].as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|m| m["name"].as_str().map(Value::from))
                            .collect()
                    })
                    .unwrap_or_default();
                Ok(serde_json::json!({ "ok": true, "models": models }))
            }
            Some("pull") => {
                let body =
                    serde_json::json!({ "runtime": rt, "model": request["model"] }).to_string();
                let (status, raw) =
                    request_with_body(&sock, "POST", "/v1/local-ai/pull", body.as_bytes())?;
                if let Some(v) = old(status, &raw) {
                    return Ok(v);
                }
                Ok(local_ai_reply(status, &raw))
            }
            Some("remove") => {
                let model = request["model"].as_str().unwrap_or_default();
                let path = format!(
                    "/v1/local-ai/{}?runtime={}",
                    encode_component(model).replace('/', "%2F"),
                    encode_component(rt)
                );
                let (status, raw) = request_with_body(&sock, "DELETE", &path, &[])?;
                if let Some(v) = old(status, &raw) {
                    return Ok(v);
                }
                Ok(local_ai_reply(status, &raw))
            }
            _ => Ok(serde_json::json!({ "ok": false, "message": "unknown request" })),
        }
    }

    fn tools(
        &self,
        rec: &BoxRecord,
        method: &str,
        segments: &[&str],
        body: &[u8],
    ) -> Result<(u16, Value), AgentError> {
        let sock = self.socket(rec)?;
        let mut path = String::from("/v1/tools");
        for s in segments {
            path.push('/');
            path.push_str(s);
        }
        let (status, raw) = request_with_body(&sock, method, &path, body)?;
        let v = serde_json::from_slice(&raw).map_err(|_| {
            AgentError::Unreachable(
                "the box's agent answered with data that is not understood".into(),
            )
        })?;
        Ok((status, v))
    }

    fn restic(
        &self,
        rec: &BoxRecord,
        method: &str,
        sub: &str,
        body: &[u8],
    ) -> Result<(u16, Value), AgentError> {
        let sock = self.socket(rec)?;
        let (status, raw) = request_with_body(&sock, method, &format!("/v1/backup{sub}"), body)?;
        let v = serde_json::from_slice(&raw).map_err(|_| {
            AgentError::Unreachable(
                "the box's agent answered with data that is not understood".into(),
            )
        })?;
        Ok((status, v))
    }

    fn skills(
        &self,
        rec: &BoxRecord,
        method: &str,
        sub: &str,
        body: &[u8],
    ) -> Result<(u16, Value), AgentError> {
        // On a box's own dashboard this goes through the table of routes its scoped socket carries (`skills_read`, `skill_push`,
        // `skill_remove`), like a run or a file write; a path off the table is refused there.
        let path = format!("/v1/skills{sub}");
        let sock = self.socket_route(rec, method, &path)?;
        let (status, raw) = request_with_body(&sock, method, &path, body)?;
        let v: Value = serde_json::from_slice(&raw).map_err(|_| {
            AgentError::Unreachable(
                "the box's agent answered with data that is not understood".into(),
            )
        })?;
        // A daemon from before skills existed answers "not found" for the route itself; a skill that is not there answers
        // with its own code.
        if status == 404 && v["error"] == "not found" {
            return Ok((
                501,
                serde_json::json!({ "code": "agent_too_old", "message": "this box's agent does not manage skills yet; upgrade the box", "error": "this box's agent does not manage skills yet; upgrade the box" }),
            ));
        }
        Ok((status, v))
    }

    fn metrics_now(&self, rec: &BoxRecord, _now_ms: u64) -> Result<MetricsSample, AgentError> {
        let v = self.get(rec, "/v1/metrics/now")?;
        serde_json::from_value(v).map_err(|_| {
            AgentError::Unreachable(
                "the box's agent sent a sample this version does not understand".into(),
            )
        })
    }

    fn metrics_series(
        &self,
        rec: &BoxRecord,
        from_ms: u64,
        to_ms: u64,
        step_ms: u64,
    ) -> Result<Vec<MetricsSample>, AgentError> {
        let q = format!(
            "/v1/metrics?since={}&until={}&step={}",
            format_rfc3339(from_ms).replace(':', "%3A"),
            format_rfc3339(to_ms).replace(':', "%3A"),
            step_label(step_ms)
        );
        let v = self.get(rec, &q)?;
        let points: Vec<Point> = serde_json::from_value(
            v.get("points").cloned().unwrap_or(Value::Null),
        )
        .map_err(|_| {
            AgentError::Unreachable(
                "the box's agent sent a series this version does not understand".into(),
            )
        })?;
        Ok(points.iter().map(sample_of).collect())
    }

    fn checkpoint(&self, rec: &BoxRecord) -> Result<super::agent::CheckpointOutcome, AgentError> {
        let sock = self.socket(rec)?;
        let (status, body) = request(&sock, "POST", "/v1/checkpoint")?;
        let v = parse_answer(status, &body)?;
        serde_json::from_value(v).map_err(|_| {
            AgentError::Unreachable(
                "the box's agent sent a checkpoint report this version does not understand".into(),
            )
        })
    }

    fn checkpoint_for_run(
        &self,
        rec: &BoxRecord,
    ) -> Result<super::agent::CheckpointOutcome, AgentError> {
        let sock = self.socket(rec)?;
        let (status, body) = request(&sock, "POST", "/v1/checkpoint?for_run=1")?;
        let v = parse_answer(status, &body)?;
        serde_json::from_value(v).map_err(|_| {
            AgentError::Unreachable(
                "the box's agent sent a checkpoint report this version does not understand".into(),
            )
        })
    }

    fn selftest(&self, rec: &BoxRecord, _now_ms: u64) -> Result<SelfTest, AgentError> {
        let sock = self.socket_route(rec, "POST", "/v1/selftest")?;
        let (status, body) = request(&sock, "POST", "/v1/selftest")?;
        let v = parse_answer(status, &body)?;
        serde_json::from_value(v).map_err(|_| {
            AgentError::Unreachable(
                "the box's agent sent a self-test this version does not understand".into(),
            )
        })
    }

    fn image_agent(&self, rec: &BoxRecord) -> Result<ImageAgent, AgentError> {
        let (_, out) = self.exec(rec, IMAGE_AGENT_COMMAND, Duration::from_secs(40))?;
        parse_image_agent(&out).ok_or_else(|| {
            AgentError::Unreachable("the box answered, but not with what was asked".into())
        })
    }

    fn secrets_state(
        &self,
        rec: &BoxRecord,
    ) -> Result<(Option<crate::secrets_state::State>, bool), AgentError> {
        let (_, out) = self.exec(
            rec,
            crate::secrets_state::STATE_COMMAND,
            Duration::from_secs(40),
        )?;
        if !out.contains("ozbox-secrets-active=") {
            return Err(AgentError::Unreachable(
                "the box answered, but not with what was asked".into(),
            ));
        }
        Ok(crate::secrets_state::parse_remote(&out))
    }

    fn admin(&self, rec: &BoxRecord, request: &str) -> Result<(bool, String), AgentError> {
        // Plain words only, checked again here: the text becomes part of the remote command.
        if request.is_empty()
            || request
                .chars()
                .any(|c| !(c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | '_' | '-')))
        {
            return Err(AgentError::Unsupported(
                "an admin request is plain words only".into(),
            ));
        }
        let (_, out) = self.exec(
            rec,
            &format!("/usr/local/bin/ozbox-admin-request {request}"),
            Duration::from_secs(180),
        )?;
        let ok = out.lines().next() == Some("status=ok");
        let body: String = out
            .lines()
            .skip(1)
            .map(|l| {
                l.chars()
                    .filter(|c| !c.is_control() || *c == '\t')
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        Ok((ok, body))
    }

    fn selftest_last(&self, rec: &BoxRecord, _now_ms: u64) -> Result<Option<SelfTest>, AgentError> {
        let v = self.get(rec, "/v1/selftest")?;
        match v.get("result") {
            None | Some(Value::Null) => Ok(None),
            Some(r) => serde_json::from_value(r.clone()).map(Some).map_err(|_| {
                AgentError::Unreachable(
                    "the box's agent sent a self-test this version does not understand".into(),
                )
            }),
        }
    }

    fn incidents(
        &self,
        rec: &BoxRecord,
        since_ms: u64,
        _now_ms: u64,
    ) -> Result<Vec<Incident>, AgentError> {
        let q = format!(
            "/v1/incidents?since={}",
            format_rfc3339(since_ms).replace(':', "%3A")
        );
        let v = self.get(rec, &q)?;
        serde_json::from_value(v.get("incidents").cloned().unwrap_or(Value::Null)).map_err(|_| {
            AgentError::Unreachable(
                "the box's agent sent incidents this version does not understand".into(),
            )
        })
    }

    fn files(
        &self,
        rec: &BoxRecord,
        method: &str,
        path: &str,
        query: &BTreeMap<String, String>,
        input: FileInput<'_>,
    ) -> Result<FileReply, AgentError> {
        let sock = self.socket_route(rec, method, path)?;
        let guard = self.guard(rec.spec.name.as_str());
        let target = with_query(path, query);
        files_request(&sock, method, &target, input, guard)
    }

    fn housekeeping(&self, _now_ms: u64) {
        let stale: Vec<String> = match self.tunnels.lock() {
            Ok(mut t) => t
                .iter_mut()
                .filter_map(|(n, tun)| {
                    (!tun.proc.alive()
                        || (tun.last_used.elapsed() > self.idle
                            && tun.active.load(Ordering::SeqCst) == 0))
                        .then(|| n.clone())
                })
                .collect(),
            Err(_) => return,
        };
        for n in stale {
            self.close(&n);
        }
        if let Ok(mut r) = self.reverses.lock() {
            let gone: Vec<String> = r
                .iter_mut()
                .filter_map(|(n, rev)| {
                    (!rev.proc.alive() || rev.last_used.elapsed() > self.idle).then(|| n.clone())
                })
                .collect();
            for n in gone {
                if let Some(mut rev) = r.remove(&n) {
                    rev.proc.kill();
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    #[test]
    fn the_dashboard_writes_its_own_line_for_changes_and_for_the_terminal_attach_but_not_for_other_reads(
    ) {
        assert_eq!(
            super::dashboard_audit_line("GET", "terminal_attach").as_deref(),
            Some("ozbox: audit via=dashboard-socket route=terminal_attach method=GET")
        );
        assert!(super::dashboard_audit_line("POST", "run_start").is_some());
        assert!(super::dashboard_audit_line("GET", "health").is_none());
        assert!(super::dashboard_audit_line("HEAD", "runs_list").is_none());
    }

    use super::*;
    use ozbox_core::{BoxName, BoxSpec, BoxState, Size};
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn aws_box(name: &str) -> Result<BoxRecord, ozbox_core::Error> {
        let mut spec = BoxSpec::new(BoxName::new(name)?, Size::M);
        spec.region = Some("us-east-1".into());
        Ok(BoxRecord {
            spec,
            state: BoxState::Running,
            provider: "aws".into(),
            provider_id: Some("i-0abc123def456".into()),
            machine_type: Some("m7i.4xlarge".into()),
            snapshots: vec![],
            created_at: None,
            last_activity_at: None,
        })
    }

    /// Serves the daemon's API on the socket path an `ssh -L` was asked to bind.
    struct FakeForward {
        stop: Arc<AtomicBool>,
        dead: Arc<AtomicBool>,
        words: String,
        /// The thread serving the socket. `kill` waits for it, so the socket file it removes on its way out is gone
        /// before a replacement forward binds the same path (the replacement must not lose its socket to a slow old thread).
        server: Option<std::thread::JoinHandle<()>>,
    }

    impl Forward for FakeForward {
        fn alive(&mut self) -> bool {
            !self.dead.load(Ordering::SeqCst)
        }
        fn kill(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            self.dead.store(true, Ordering::SeqCst);
            if let Some(t) = self.server.take() {
                let _ = t.join();
            }
        }
        fn last_words(&self) -> String {
            self.words.clone()
        }
    }

    #[derive(Default)]
    struct FakeSsh {
        spawned: Mutex<Vec<CommandSpec>>,
        count: AtomicUsize,
        /// Exit at once, with these last words, instead of serving.
        fail_with: Mutex<Option<String>>,
        last_dead: Mutex<Option<Arc<AtomicBool>>>,
    }

    fn daemon_answer(path_and_query: &str) -> (u16, String) {
        let path = path_and_query.split('?').next().unwrap_or("");
        match path {
            "/v1/metrics/now" => (200, serde_json::json!({
                "ts_ms": 1_000, "cpu_pct": 42.5, "mem_total_bytes": 1000, "mem_available_bytes": 250,
                "swap_total_bytes": 0, "swap_free_bytes": 0, "psi_cpu_some_avg10": 0.0, "psi_mem_some_avg10": 0.0,
                "psi_io_some_avg10": 0.0, "disk_total_bytes": 100, "disk_free_bytes": 40, "disk_read_bps": 0.0,
                "disk_write_bps": 0.0, "net_rx_bps": 0.0, "net_tx_bps": 0.0
            }).to_string()),
            "/v1/metrics" => (200, serde_json::json!({ "step": "1m", "points": [
                { "ts_ms": 60_000, "n": 12, "fields": {
                    "cpu_pct": { "min": 1.0, "max": 9.0, "mean": 5.0, "last": 4.0 },
                    "mem_total_bytes": { "min": 1000.0, "max": 1000.0, "mean": 1000.0, "last": 1000.0 },
                    "mem_available_bytes": { "min": 100.0, "max": 300.0, "mean": 200.0, "last": 150.0 } } }
            ]}).to_string()),
            "/v1/selftest" => (200, serde_json::json!({ "result": { "ts_ms": 5, "ok": false, "all_verified": true, "checks": [
                { "name": "tunnels up", "outcome": "fail", "step": "tunnels up", "reason": "not running" },
                { "name": "work disk mounted", "outcome": "pass" } ] } }).to_string()),
            "/v1/incidents" => (200, serde_json::json!({ "incidents": [ { "ts_ms": 7, "kind": "oom_kill", "detail": "a run was killed" } ] }).to_string()),
            "/v1/sessions" => (200, serde_json::json!({ "tmux": true, "sessions": [
                { "name": "term-1", "created_s": 10, "activity_s": 20, "attached": false, "command": "claude" } ] }).to_string()),
            "/v1/processes" => (200, serde_json::json!({
                "agents": [ { "pid": 4242, "program": "claude", "age_s": 60 } ],
                "servers": [ { "port": 3000, "pid": 777, "program": "node" } ] }).to_string()),
            "/v1/runs" => (200, serde_json::json!({ "runs": [], "id": "r1", "state": "running" }).to_string()),
            "/v1/runs/r1/log" => (200, serde_json::json!({ "id": "r1", "log": { "text": "hello\n", "next": 6, "state": "exited", "exit_code": 0 } }).to_string()),
            "/v1/runs/r1" => (200, serde_json::json!({ "id": "r1", "state": "running" }).to_string()),
            "/v1/local-ai" => (200, serde_json::json!({ "runtimes": [
                { "id": "ollama", "installed": true, "running": true, "models": [ { "name": "llama3.1:8b", "size_bytes": 1 } ] },
                { "id": "vllm", "installed": false, "running": false, "models": [] } ], "pulls": [] }).to_string()),
            "/v1/local-ai/pull" => (202, serde_json::json!({ "ok": true, "state": "pulling" }).to_string()),
            "/v1/local-ai/llama3.1%3A8b" => (200, serde_json::json!({ "ok": true }).to_string()),
            "/v1/local-ai/gone%3A1b" => (404, serde_json::json!({ "error": "that model is not on this box", "message": "that model is not on this box" }).to_string()),
            "/v1/skills" => (200, serde_json::json!({ "agents": [], "skills": [], "others": {} }).to_string()),
            "/v1/skills/demo" => (200, serde_json::json!({ "ok": true, "name": "demo", "results": [] }).to_string()),
            "/v1/skills/gone" => (404, serde_json::json!({ "error": "no such skill here", "message": "no such skill here", "code": "not_found" }).to_string()),
            "/v1/sessions/term-1/stop" => (200, serde_json::json!({ "stopped": true }).to_string()),
            "/v1/sessions/gone/stop" => (404, serde_json::json!({ "error": "that is not running, or it is not yours" }).to_string()),
            "/v1/processes/900/stop" => (403, serde_json::json!({ "error": "that is not a coding agent or a server, so it was left alone" }).to_string()),
            _ => (404, serde_json::json!({ "error": "not found" }).to_string()),
        }
    }

    impl Spawn for FakeSsh {
        fn spawn(
            &self,
            spec: &CommandSpec,
            _stderr_to: &Path,
        ) -> std::io::Result<Box<dyn Forward>> {
            self.count.fetch_add(1, Ordering::SeqCst);
            if let Ok(mut s) = self.spawned.lock() {
                s.push(spec.clone());
            }
            let dead = Arc::new(AtomicBool::new(false));
            if let Ok(mut l) = self.last_dead.lock() {
                *l = Some(dead.clone());
            }
            if let Some(words) = self.fail_with.lock().ok().and_then(|f| f.clone()) {
                dead.store(true, Ordering::SeqCst);
                return Ok(Box::new(FakeForward {
                    stop: Arc::new(AtomicBool::new(true)),
                    dead,
                    words,
                    server: None,
                }));
            }
            if spec.args.iter().any(|a| a == "-R") {
                // a reverse forward has no local socket to serve: it is alive until it is killed
                return Ok(Box::new(FakeForward {
                    stop: Arc::new(AtomicBool::new(false)),
                    dead,
                    words: String::new(),
                    server: None,
                }));
            }
            let local = spec
                .args
                .iter()
                .skip_while(|a| *a != "-L")
                .nth(1)
                .and_then(|a| a.split(':').next())
                .map(PathBuf::from)
                .ok_or_else(|| std::io::Error::other("no -L"))?;
            let listener = UnixListener::bind(&local)?;
            listener.set_nonblocking(true)?;
            let stop = Arc::new(AtomicBool::new(false));
            let stop2 = stop.clone();
            let server = std::thread::spawn(move || {
                while !stop2.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((mut c, _)) => {
                            let _ = c.set_nonblocking(false);
                            let _ = c.set_read_timeout(Some(Duration::from_secs(2)));
                            let mut buf = [0u8; 4096];
                            let n = c.read(&mut buf).unwrap_or(0);
                            let text = String::from_utf8_lossy(&buf[..n]).into_owned();
                            let first = text.lines().next().unwrap_or("").to_string();
                            let mut parts = first.split_whitespace();
                            let (method, target) =
                                (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
                            let (status, body) = if method == "POST" && target == "/v1/selftest" {
                                (200, serde_json::json!({ "ts_ms": 9, "ok": true, "all_verified": true, "checks": [ { "name": "x", "outcome": "pass" } ] }).to_string())
                            } else {
                                daemon_answer(target)
                            };
                            let resp = format!("HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                            let _ = c.write_all(resp.as_bytes());
                        }
                        Err(_) => std::thread::sleep(Duration::from_millis(5)),
                    }
                }
                let _ = std::fs::remove_file(&local);
            });
            Ok(Box::new(FakeForward {
                stop,
                dead,
                words: String::new(),
                server: Some(server),
            }))
        }
    }

    fn agent(ssh: &Arc<FakeSsh>) -> Result<SshAgent, String> {
        SshAgent::new(ssh.clone(), RouteInputs::default())
    }

    #[test]
    fn a_forward_is_opened_once_and_reused() -> TestResult {
        let ssh = Arc::new(FakeSsh::default());
        let a = agent(&ssh)?;
        let rec = aws_box("dev")?;
        let m = a.metrics_now(&rec, 0)?;
        assert_eq!((m.cpu_pct, m.mem_total_bytes), (42.5, 1000));
        a.metrics_now(&rec, 0)?;
        a.incidents(&rec, 0, 0)?;
        assert_eq!(ssh.count.load(Ordering::SeqCst), 1, "reused, not reopened");
        assert_eq!(a.open_count(), 1);
        Ok(())
    }

    #[test]
    fn readers_that_arrive_together_share_one_forward_and_none_is_left_running() -> TestResult {
        let ssh = Arc::new(FakeSsh::default());
        let a = Arc::new(agent(&ssh)?);
        let rec = aws_box("dev")?;
        let threads: Vec<_> = (0..6)
            .map(|_| {
                let (a, rec) = (Arc::clone(&a), rec.clone());
                std::thread::spawn(move || a.metrics_now(&rec, 0).map(|m| m.mem_total_bytes))
            })
            .collect();
        for t in threads {
            assert!(matches!(t.join().map_err(|_| "panicked")?, Ok(1000)));
        }
        assert_eq!(
            ssh.count.load(Ordering::SeqCst),
            1,
            "one ssh for one key, however many arrive together"
        );
        assert_eq!(a.open_count(), 1);
        Ok(())
    }

    #[test]
    fn run_calls_go_to_the_daemons_run_api_and_the_answer_is_returned_whatever_its_status(
    ) -> TestResult {
        let ssh = Arc::new(FakeSsh::default());
        let a = agent(&ssh)?;
        let rec = aws_box("dev")?;
        let (st, v) = a.runs(&rec, "POST", "", b"{}")?;
        assert_eq!((st, v["id"].as_str()), (200, Some("r1")));
        let (st, v) = a.runs(&rec, "GET", "/r1/log?from=0", &[])?;
        assert_eq!((st, v["log"]["exit_code"].as_i64()), (200, Some(0)));
        let (st, _) = a.runs(&rec, "DELETE", "/r1", &[])?;
        assert_eq!(st, 200);
        let (st, _) = a.runs(&rec, "GET", "/nope", &[])?;
        assert_eq!(st, 404, "an older daemon's answer is the caller's to read");
        // one forward carried all of it
        assert_eq!(ssh.count.load(Ordering::SeqCst), 1);
        // the path is built here from an id and an offset: anything else is refused before it is sent
        for bad in ["/r1/../x", "/r1 HTTP/1.1", "/r1\r\nx"] {
            assert!(a.runs(&rec, "GET", bad, &[]).is_err(), "{bad:?}");
        }
        Ok(())
    }

    #[test]
    fn a_reverse_forward_is_loopback_to_loopback_reused_rebuilt_for_a_new_machine_and_closed_when_idle(
    ) -> TestResult {
        let ssh = Arc::new(FakeSsh::default());
        let a = agent(&ssh)?.tuned(Duration::from_millis(30), Duration::from_secs(2));
        let rec = aws_box("dev")?;
        a.reverse_forward(&rec, 45678)?;
        let spec = ssh.spawned.lock().map_err(|_| "lock")?[0].clone();
        let text = spec.args.join(" ");
        assert!(
            text.contains("-R 127.0.0.1:45678:127.0.0.1:45678"),
            "{text}"
        );
        assert!(text.contains("ExitOnForwardFailure=yes") && text.contains("-N"));
        // both ends are loopback: no wildcard, no other address
        assert!(!text.contains("0.0.0.0") && !text.contains("*:") && !text.contains(" -L "));
        assert_eq!(spec.program, "ssh");
        // asked again, it is the same forward
        a.reverse_forward(&rec, 45678)?;
        assert_eq!(ssh.count.load(Ordering::SeqCst), 1);
        // another port is another forward; a replaced machine gets its own
        a.reverse_forward(&rec, 45679)?;
        let mut after = aws_box("dev")?;
        after.provider_id = Some("i-0fedcba987654".into());
        a.reverse_forward(&after, 45678)?;
        assert_eq!(ssh.count.load(Ordering::SeqCst), 3);
        // unused for a while, they are closed with the rest
        std::thread::sleep(Duration::from_millis(80));
        a.housekeeping(0);
        assert_eq!(a.reverses.lock().map_err(|_| "lock")?.len(), 0);
        Ok(())
    }

    #[test]
    fn a_reverse_forward_the_box_refuses_says_so_and_a_privileged_port_is_never_forwarded(
    ) -> TestResult {
        let ssh = Arc::new(FakeSsh::default());
        *ssh.fail_with.lock().map_err(|_| "lock")? =
            Some("Error: remote port forwarding failed for listen port 45678".into());
        let a = agent(&ssh)?;
        let rec = aws_box("dev")?;
        let e = a.reverse_forward(&rec, 45678).unwrap_err().to_string();
        assert!(e.contains("remote port forwarding failed"), "{e}");
        assert!(
            a.reverses.lock().map_err(|_| "lock")?.is_empty(),
            "a failed forward is not kept"
        );
        assert!(a.reverse_forward(&rec, 80).is_err());
        Ok(())
    }

    #[test]
    fn local_ai_calls_map_onto_the_daemons_routes_and_say_so_when_the_agent_is_too_old(
    ) -> TestResult {
        let ssh = Arc::new(FakeSsh::default());
        let a = agent(&ssh)?;
        let rec = aws_box("dev")?;
        let v = a.local_ai(
            &rec,
            &serde_json::json!({ "action": "list", "runtime": "ollama" }),
        )?;
        assert_eq!(v["models"], serde_json::json!(["llama3.1:8b"]));
        let v = a.local_ai(
            &rec,
            &serde_json::json!({ "action": "list", "runtime": "vllm" }),
        )?;
        assert_eq!(v["models"], serde_json::json!([]));
        let v = a.local_ai(
            &rec,
            &serde_json::json!({ "action": "pull", "runtime": "ollama", "model": "llama3.1:8b" }),
        )?;
        assert_eq!(
            (v["ok"].as_bool(), v["state"].as_str()),
            (Some(true), Some("pulling"))
        );
        let v = a.local_ai(
            &rec,
            &serde_json::json!({ "action": "remove", "runtime": "ollama", "model": "llama3.1:8b" }),
        )?;
        assert_eq!(v["ok"], true);
        let v = a.local_ai(
            &rec,
            &serde_json::json!({ "action": "remove", "runtime": "ollama", "model": "gone:1b" }),
        )?;
        assert_eq!(v["ok"], false);
        assert!(v["message"]
            .as_str()
            .unwrap_or("")
            .contains("not on this box"));
        let v = a.local_ai(
            &rec,
            &serde_json::json!({ "action": "status", "runtime": "ollama" }),
        )?;
        assert_eq!(v["status"]["runtimes"][0]["running"], true);
        let v = a.local_ai(&rec, &serde_json::json!({ "action": "nonsense" }))?;
        assert_eq!(v["ok"], false);
        Ok(())
    }

    #[test]
    fn skills_calls_map_onto_the_daemons_routes_and_an_old_daemon_says_to_upgrade() -> TestResult {
        let ssh = Arc::new(FakeSsh::default());
        let a = agent(&ssh)?;
        let rec = aws_box("dev")?;
        let (st, v) = a.skills(&rec, "GET", "", &[])?;
        assert_eq!((st, v["skills"].is_array()), (200, true));
        let (st, v) = a.skills(&rec, "PUT", "/demo", b"{}")?;
        assert_eq!((st, v["ok"].as_bool()), (200, Some(true)));
        // a skill that is not there is the daemon's own answer, passed on
        let (st, v) = a.skills(&rec, "DELETE", "/gone", &[])?;
        assert_eq!((st, v["code"].as_str()), (404, Some("not_found")));
        // a daemon from before skills answers "not found" for the route itself
        let (st, v) = a.skills(&rec, "GET", "/older", &[])?;
        assert_eq!((st, v["code"].as_str()), (501, Some("agent_too_old")));
        Ok(())
    }

    #[test]
    fn on_a_boxs_own_dashboard_skills_go_through_the_scoped_sockets_table() -> TestResult {
        let ssh = Arc::new(FakeSsh::default());
        let a = SshAgent::local_at(
            ssh.clone(),
            RouteInputs::default(),
            PathBuf::from("/nonexistent/ozbox-test-daemon.sock"),
        )?;
        let rec = aws_box("dev")?;
        // the three routes of the table are tried on the socket (which is not there, and says so)...
        for (m, sub) in [("GET", ""), ("PUT", "/demo"), ("DELETE", "/demo")] {
            let e = a.skills(&rec, m, sub, b"{}").unwrap_err().to_string();
            assert!(!e.contains(NOT_ON_A_BOX), "{m} {sub}: {e}");
        }
        // ...and anything else is "not available on a box's dashboard", never sent anywhere
        for (m, sub) in [("POST", ""), ("PUT", ""), ("GET", "/demo")] {
            let e = a.skills(&rec, m, sub, b"{}").unwrap_err().to_string();
            assert!(e.contains(NOT_ON_A_BOX), "{m} {sub}: {e}");
        }
        Ok(())
    }

    #[test]
    fn a_forward_to_a_replaced_machine_is_never_reused() -> TestResult {
        let ssh = Arc::new(FakeSsh::default());
        let a = agent(&ssh)?;
        let rec = aws_box("dev")?;
        a.metrics_now(&rec, 0)?;
        // the box was upgraded: same name, new machine, and the old forward still looks alive
        let mut after = aws_box("dev")?;
        after.provider_id = Some("i-0fedcba987654".into());
        a.metrics_now(&after, 0)?;
        assert_eq!(
            ssh.count.load(Ordering::SeqCst),
            2,
            "reopened for the new machine"
        );
        let spawned = ssh.spawned.lock().map_err(|_| "lock")?;
        let conf = spawned[1]
            .args
            .iter()
            .skip_while(|x| *x != "-F")
            .nth(1)
            .cloned()
            .unwrap_or_default();
        let text = std::fs::read_to_string(&conf)?;
        assert!(text.contains("HostName i-0fedcba987654") && !text.contains("i-0abc123def456"));
        Ok(())
    }

    #[test]
    fn a_one_shot_command_uses_the_same_route_with_a_fixed_remote_command() -> TestResult {
        let ssh = Arc::new(FakeSsh::default());
        let a = agent(&ssh)?;
        let rec = aws_box("dev")?;
        let spec = a.exec_command(&rec, IMAGE_AGENT_COMMAND)?;
        assert_eq!(spec.program, "ssh");
        assert_eq!(
            spec.args.last().map(String::as_str),
            Some(IMAGE_AGENT_COMMAND)
        );
        assert!(spec.args.contains(&"ozbox-dev".to_string()));
        assert!(!spec.args.iter().any(|x| x == "-L" || x == "-N"));
        Ok(())
    }

    #[test]
    fn the_ssh_command_is_an_argv_array_with_a_private_config_and_no_secrets() -> TestResult {
        let ssh = Arc::new(FakeSsh::default());
        let a = agent(&ssh)?;
        let rec = aws_box("dev")?;
        a.metrics_now(&rec, 0)?;
        let spec = ssh.spawned.lock().map_err(|_| "lock")?[0].clone();
        assert_eq!(spec.program, "ssh");
        let args = spec.args.join(" ");
        assert!(
            args.contains("-N")
                && args.contains("BatchMode=yes")
                && args.contains("ExitOnForwardFailure=yes")
        );
        assert!(args.contains(&format!(":{DAEMON_SOCKET}")));
        assert_eq!(spec.args.last().map(String::as_str), Some("ozbox-dev"));
        let conf = spec
            .args
            .iter()
            .skip_while(|x| *x != "-F")
            .nth(1)
            .cloned()
            .unwrap_or_default();
        let text = std::fs::read_to_string(&conf)?;
        assert!(
            text.contains("Host ozbox-dev")
                && text.contains("aws ssm start-session")
                && text.contains("i-0abc123def456")
        );
        let mode = |p: &Path| std::fs::metadata(p).map(|m| m.permissions().mode() & 0o777);
        assert_eq!(mode(Path::new(&conf))?, 0o600);
        assert_eq!(mode(&a.dir)?, 0o700);
        let sock_len = a
            .sock_path("a-very-long-box-name-indeed-yes")
            .as_os_str()
            .len();
        assert!(sock_len < 100, "{sock_len}");
        assert!(spec.env.is_empty());
        Ok(())
    }

    #[test]
    fn series_selftest_and_incidents_read_the_daemon_shapes() -> TestResult {
        let ssh = Arc::new(FakeSsh::default());
        let a = agent(&ssh)?;
        let rec = aws_box("dev")?;
        let s = a.metrics_series(&rec, 0, 120_000, 60_000)?;
        assert_eq!(s.len(), 1);
        assert_eq!(
            (s[0].ts_ms, s[0].cpu_pct, s[0].mem_available_bytes),
            (60_000, 5.0, 200)
        );
        let last = a.selftest_last(&rec, 0)?.ok_or("no result")?;
        assert!(!last.ok);
        assert!(
            matches!(&last.checks[0].outcome, super::super::agent::Outcome::Fail { step, .. } if step == "tunnels up")
        );
        let now = a.selftest(&rec, 0)?;
        assert!(now.ok && now.ts_ms == 9, "POST runs it now");
        let inc = a.incidents(&rec, 0, 0)?;
        assert_eq!(
            inc,
            vec![Incident {
                ts_ms: 7,
                kind: "oom_kill".into(),
                detail: "a run was killed".into()
            }]
        );
        Ok(())
    }

    #[test]
    fn sessions_processes_and_stops_go_through_the_box_agent_and_an_older_agent_falls_back(
    ) -> TestResult {
        use crate::code::procs::Stop;
        let ssh = Arc::new(FakeSsh::default());
        let a = agent(&ssh)?;
        let rec = aws_box("dev")?;
        let p = a.code_procs(&rec)?;
        assert!(p.tmux);
        assert_eq!(p.sessions[0].name, "term-1");
        assert_eq!(p.agents[0].pid, 4242);
        assert_eq!(p.servers[0].port, 3000);
        // no SSH command was needed for the read
        assert!(ssh
            .spawned
            .lock()
            .map_err(|_| "lock")?
            .iter()
            .all(|c| !c.args.iter().any(|x| x == "bash -s")));
        assert!(matches!(
            a.daemon_stop(&rec, &Stop::session("term-1")?),
            Some(Ok(()))
        ));
        // a real refusal is the agent's answer, shown as it is
        match a.daemon_stop(&rec, &Stop::session("gone")?) {
            Some(Err(e)) => assert!(e.to_string().contains("not running")),
            other => panic!("{other:?}"),
        }
        match a.daemon_stop(&rec, &Stop::process(900)?) {
            Some(Err(e)) => assert!(e.to_string().contains("left alone")),
            other => panic!("{other:?}"),
        }
        // an agent that does not know the path (404 "not found") is the cue to use SSH
        assert!(a.daemon_stop(&rec, &Stop::process(901)?).is_none());
        Ok(())
    }

    #[test]
    fn a_dead_forward_is_replaced_and_idle_forwards_are_closed() -> TestResult {
        let ssh = Arc::new(FakeSsh::default());
        // The wait for the fake ssh is only a ceiling (it returns the moment the forward is up), so it is generous: a
        // loaded CI machine once took longer than five seconds to start a thread and failed the test for no reason.
        let a = agent(&ssh)?.tuned(Duration::from_millis(20), Duration::from_secs(60));
        let rec = aws_box("dev")?;
        a.metrics_now(&rec, 0)?;
        if let Some(d) = ssh.last_dead.lock().map_err(|_| "lock")?.clone() {
            d.store(true, Ordering::SeqCst); // ssh died
        }
        a.metrics_now(&rec, 0)?;
        assert_eq!(
            ssh.count.load(Ordering::SeqCst),
            2,
            "a new forward replaced the dead one"
        );
        // Idle is measured from the last use, so waiting longer than the idle time can only make the forward more idle:
        // load makes this wait longer, never wrong.
        std::thread::sleep(Duration::from_millis(60));
        a.housekeeping(0);
        assert_eq!(a.open_count(), 0, "closed on idle");
        a.metrics_now(&rec, 0)?;
        assert_eq!(a.open_count(), 1, "and reopened on demand");
        Ok(())
    }

    #[test]
    fn an_ssh_that_exits_gives_its_last_words_as_the_reason() -> TestResult {
        let ssh = Arc::new(FakeSsh::default());
        if let Ok(mut f) = ssh.fail_with.lock() {
            *f = Some("Permission denied (publickey).".into());
        }
        let a = agent(&ssh)?;
        let rec = aws_box("dev")?;
        let e = a.metrics_now(&rec, 0).err().ok_or("expected an error")?;
        match e {
            AgentError::Unreachable(m) => assert!(
                m.contains("closed before it was ready") && m.contains("Permission denied"),
                "{m}"
            ),
            other => return Err(format!("{other:?}").into()),
        }
        assert_eq!(a.open_count(), 0);
        Ok(())
    }

    #[test]
    fn a_box_with_no_route_is_unreachable_with_the_reason() -> TestResult {
        let ssh = Arc::new(FakeSsh::default());
        let a = agent(&ssh)?;
        let mut rec = aws_box("dev")?;
        rec.provider_id = None;
        let e = a.metrics_now(&rec, 0).err().ok_or("expected an error")?;
        assert!(matches!(e, AgentError::Unreachable(m) if m.contains("no SSH route")));
        assert_eq!(ssh.count.load(Ordering::SeqCst), 0);
        Ok(())
    }

    #[test]
    fn a_daemon_error_status_is_reported_without_crashing() -> TestResult {
        let (status, body) = (
            404u16,
            serde_json::json!({ "error": "not found" }).to_string(),
        );
        let e = parse_answer(status, body.as_bytes())
            .err()
            .ok_or("expected an error")?;
        assert!(
            matches!(e, AgentError::Unreachable(m) if m.contains("HTTP 404") && m.contains("not found"))
        );
        assert!(parse_answer(200, b"not json").is_err());
        Ok(())
    }

    /// A daemon double: reads one request (head and body), answers with `reply`, returns what it received.
    fn daemon_double(sock: &Path, reply: Vec<u8>) -> std::thread::JoinHandle<(String, Vec<u8>)> {
        let l = UnixListener::bind(sock).unwrap();
        std::thread::spawn(move || {
            let (mut c, _) = l.accept().unwrap();
            let mut raw = Vec::new();
            let mut b = [0u8; 1];
            while !raw.ends_with(b"\r\n\r\n") {
                c.read_exact(&mut b).unwrap();
                raw.push(b[0]);
            }
            let head = String::from_utf8_lossy(&raw).into_owned();
            let n: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("Content-Length: "))
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0);
            let mut body = vec![0u8; n];
            c.read_exact(&mut body).unwrap();
            c.write_all(&reply).unwrap();
            (head, body)
        })
    }

    #[test]
    fn a_dashboard_on_the_box_reads_its_own_daemon_directly_and_never_starts_ssh() -> TestResult {
        let d = tempfile::tempdir()?;
        let sock = d.path().join("d.sock");
        let json = br#"{"cpu_pct":1.5,"mem_bytes":1,"mem_total_bytes":2,"disk_used_bytes":1,"disk_total_bytes":2,"net_rx_bps":0,"net_tx_bps":0,"ts_ms":5}"#;
        let reply = [
            format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", json.len()).into_bytes(),
            json.to_vec(),
        ]
        .concat();
        let h = daemon_double(&sock, reply);
        let ssh = Arc::new(FakeSsh::default());
        let a = SshAgent::local_at(ssh.clone(), RouteInputs::default(), sock.clone())?;
        let mut rec = aws_box("main")?;
        rec.provider_id = None; // a box's own record has no cloud id, and no SSH route
        let got = a.get(&rec, "/v1/metrics/now");
        let (head, _) = h.join().map_err(|_| "daemon double panicked")?;
        assert!(head.starts_with("GET /v1/metrics/now "), "{head}");
        assert!(got.is_ok(), "{got:?}");
        assert_eq!(ssh.count.load(Ordering::SeqCst), 0);
        // an action that needs a route from outside says why instead of reaching for ssh
        let e = a
            .exec_command(&rec, "true")
            .err()
            .ok_or("expected an error")?;
        assert!(matches!(e, AgentError::Unreachable(m) if m.contains("runs on the box itself")));
        Ok(())
    }

    #[test]
    fn a_dashboard_on_the_box_with_no_daemon_says_so() -> TestResult {
        let d = tempfile::tempdir()?;
        let ssh = Arc::new(FakeSsh::default());
        let a = SshAgent::local_at(ssh, RouteInputs::default(), d.path().join("none.sock"))?;
        let mut rec = aws_box("main")?;
        rec.provider_id = None;
        let e = a
            .get(&rec, "/v1/metrics/now")
            .err()
            .ok_or("expected an error")?;
        assert!(matches!(e, AgentError::Unreachable(m) if m.contains("socket is missing")));
        Ok(())
    }

    fn ok_reply() -> Vec<u8> {
        let json = br#"{"cpu_pct":1.5,"mem_bytes":1,"mem_total_bytes":2,"disk_used_bytes":1,"disk_total_bytes":2,"net_rx_bps":0,"net_tx_bps":0,"ts_ms":5}"#;
        [
            format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", json.len()).into_bytes(),
            json.to_vec(),
        ]
        .concat()
    }

    /// ADR 0040, decision 3: a dashboard on a box talks to the dashboard user's own socket for the routes of the table, and a
    /// route off the table is "not available on a box's dashboard": it is not tried anywhere, even where another socket
    /// exists and is open.
    #[test]
    fn a_dashboard_on_a_box_uses_its_own_socket_and_never_falls_back_to_another() -> TestResult {
        let d = tempfile::tempdir()?;
        let (boxs, sup) = (d.path().join("box.sock"), d.path().join("sup.sock"));
        let hs = daemon_double(&sup, ok_reply());
        // a stand-in for the box user's socket, open and answering: nothing must reach it
        let hb = daemon_double(&boxs, ok_reply());
        let a = SshAgent::local_at(
            Arc::new(FakeSsh::default()),
            RouteInputs::default(),
            sup.clone(),
        )?;
        let mut rec = aws_box("main")?;
        rec.provider_id = None;
        assert!(a.get(&rec, "/v1/metrics/now").is_ok());
        let (head, _) = hs.join().map_err(|_| "double panicked")?;
        assert!(head.starts_with("GET /v1/metrics/now "), "{head}");
        // every call off the table is refused before a socket is chosen
        let off = |e: AgentError| matches!(e, AgentError::Unsupported(m) if m.contains("not available on a box's dashboard"));
        assert!(off(a
            .restic(&rec, "GET", "/status", b"")
            .err()
            .ok_or("backup")?));
        assert!(off(a
            .local_ai(&rec, &serde_json::json!({ "action": "list" }))
            .err()
            .ok_or("local ai")?));
        assert!(off(a.tools(&rec, "GET", &[], b"").err().ok_or("tools")?));
        assert!(off(a
            .agent_call(&rec, "POST", "/v1/agent-events", b"{}")
            .err()
            .ok_or("agent events")?));
        assert!(off(a
            .agent_call(
                &rec,
                "POST",
                "/v1/agent-events/permission/p1",
                b"{\"decision\":\"allow\"}"
            )
            .err()
            .ok_or("decide")?));
        // the box user's socket was never connected to: its stand-in is still waiting for a first connection
        assert!(!hb.is_finished());
        drop(UnixStream::connect(&boxs));
        let _ = hb.join();
        Ok(())
    }

    #[test]
    fn the_dashboards_socket_must_be_the_one_the_box_set_up() -> TestResult {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        use std::os::unix::net::UnixListener;
        let d = tempfile::tempdir()?;
        let dir = d.path().join("api");
        std::fs::create_dir(&dir)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))?;
        let p = dir.join("daemon.sock");
        let me = std::fs::metadata(&dir)?;
        let (uid, gid) = (me.uid(), me.gid());
        assert_eq!(check_scoped_socket(&p, uid, gid), Err(SocketCheck::Missing));
        let _l = UnixListener::bind(&p)?;
        // wrong mode (a box user's `chmod`, or a daemon that bound it itself with a umask mode)
        for mode in [0o666, 0o600, 0o664, 0o770] {
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode))?;
            assert_eq!(
                check_scoped_socket(&p, uid, gid),
                Err(SocketCheck::NotTrusted),
                "{mode:o}"
            );
        }
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o660))?;
        assert_eq!(check_scoped_socket(&p, uid, gid), Ok(()));
        // owned by someone else, or in another group
        assert_eq!(
            check_scoped_socket(&p, uid.wrapping_add(1), gid),
            Err(SocketCheck::NotTrusted)
        );
        assert_eq!(
            check_scoped_socket(&p, uid, gid.wrapping_add(1)),
            Err(SocketCheck::NotTrusted)
        );
        // a link to a socket is never followed, whoever made it
        let link = dir.join("link.sock");
        std::os::unix::fs::symlink(&p, &link)?;
        assert_eq!(
            check_scoped_socket(&link, uid, gid),
            Err(SocketCheck::NotTrusted)
        );
        // a folder others can write to lets them replace the socket
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o775))?;
        assert_eq!(
            check_scoped_socket(&p, uid, gid),
            Err(SocketCheck::NotTrusted)
        );
        // not a socket at all
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))?;
        let f = dir.join("file");
        std::fs::write(&f, b"x")?;
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o660))?;
        assert_eq!(
            check_scoped_socket(&f, uid, gid),
            Err(SocketCheck::NotTrusted)
        );
        Ok(())
    }

    #[test]
    fn a_socket_that_is_not_trusted_is_not_connected_to() -> TestResult {
        use std::os::unix::net::UnixListener;
        let d = tempfile::tempdir()?;
        let p = d.path().join("daemon.sock");
        let l = UnixListener::bind(&p)?;
        let mut a = SshAgent::local_at(Arc::new(FakeSsh::default()), RouteInputs::default(), p)?;
        // required to be root's: the test's own socket is not
        a.local_trust = Some((0, u32::MAX));
        let mut rec = aws_box("main")?;
        rec.provider_id = None;
        let e = a
            .get(&rec, "/v1/metrics/now")
            .err()
            .ok_or("expected an error")?;
        assert!(
            matches!(e, AgentError::Unreachable(m) if m.contains("not the one the box set up"))
        );
        l.set_nonblocking(true)?;
        assert!(l.accept().is_err(), "nothing connected");
        Ok(())
    }

    #[test]
    fn a_dashboard_on_the_box_has_nothing_to_forward_to_its_own_loopback() -> TestResult {
        let d = tempfile::tempdir()?;
        let ssh = Arc::new(FakeSsh::default());
        let a = SshAgent::local_at(ssh.clone(), RouteInputs::default(), d.path().join("a.sock"))?;
        let mut rec = aws_box("main")?;
        rec.provider_id = None;
        assert!(a.reverse_forward(&rec, 4321).is_ok());
        assert_eq!(ssh.count.load(Ordering::SeqCst), 0);
        Ok(())
    }

    #[test]
    fn a_box_where_the_dashboards_socket_is_missing_says_so_in_one_message() -> TestResult {
        let d = tempfile::tempdir()?;
        let a = SshAgent::local_at(
            Arc::new(FakeSsh::default()),
            RouteInputs::default(),
            d.path().join("a.sock"),
        )?;
        let mut rec = aws_box("main")?;
        rec.provider_id = None;
        let e = a.get(&rec, "/v1/runs").err().ok_or("expected an error")?;
        assert!(matches!(e, AgentError::Unreachable(m) if m.contains("not running")));
        Ok(())
    }

    #[test]
    fn file_calls_stream_a_body_up_and_an_answer_down() -> TestResult {
        let d = tempfile::tempdir()?;
        let sock = d.path().join("d.sock");
        let json = b"{\"ok\":true}";
        let reply = [
            format!("HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", json.len()).into_bytes(),
            json.to_vec(),
        ]
        .concat();
        let h = daemon_double(&sock, reply);
        let data = vec![9u8; 300_000];
        let mut r: &[u8] = &data;
        let mut q = BTreeMap::new();
        q.insert("path".to_string(), "/work/a b&c.txt".to_string());
        let target = with_query("/v1/files/upload", &q);
        assert_eq!(target, "/v1/files/upload?path=/work/a%20b%26c.txt");
        let out = files_request(
            &sock,
            "PUT",
            &target,
            FileInput::Stream {
                reader: &mut r,
                len: data.len() as u64,
            },
            None,
        )?;
        assert_eq!(out.status, 201);
        assert_eq!(out.bytes(), Some(&json[..]));
        let (head, body) = h.join().unwrap();
        assert!(head.starts_with("PUT /v1/files/upload?path=/work/a%20b%26c.txt HTTP/1.1"));
        assert_eq!(body, data);

        // a download: the body is handed back as a stream, not read into memory here
        let payload = vec![7u8; 200_000];
        let reply = [
            format!("HTTP/1.1 200 OK\r\nContent-Type: application/zip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", payload.len()).into_bytes(),
            payload.clone(),
        ]
        .concat();
        let sock2 = d.path().join("e.sock");
        let _h = daemon_double(&sock2, reply);
        let out = files_request(
            &sock2,
            "GET",
            "/v1/files/download?token=x",
            FileInput::None,
            None,
        )?;
        assert_eq!(out.header("content-type"), Some("application/zip"));
        let super::super::agent::FileBody::Stream { mut reader, len } = out.body else {
            return Err("expected a stream".into());
        };
        let mut got = Vec::new();
        reader.read_to_end(&mut got)?;
        assert_eq!((len as usize, got), (payload.len(), payload));
        Ok(())
    }

    #[test]
    fn a_forward_carrying_a_transfer_is_not_closed_as_idle() -> TestResult {
        let ssh = Arc::new(FakeSsh::default());
        let agent = agent(&ssh)?.tuned(Duration::from_millis(0), Duration::from_secs(2));
        let rec = aws_box("dev")?;
        agent.metrics_now(&rec, 0)?;
        assert_eq!(agent.open_count(), 1);
        let guard = agent.guard("dev").ok_or("no forward")?;
        std::thread::sleep(Duration::from_millis(5));
        agent.housekeeping(0);
        assert_eq!(agent.open_count(), 1, "busy forward stays open");
        drop(guard);
        agent.housekeeping(0);
        assert_eq!(agent.open_count(), 0, "idle forward closes");
        Ok(())
    }

    #[test]
    fn dropping_the_agent_closes_forwards_and_removes_the_directory() -> TestResult {
        let ssh = Arc::new(FakeSsh::default());
        let a = agent(&ssh)?;
        let dir = a.dir.clone();
        a.metrics_now(&aws_box("dev")?, 0)?;
        let dead = ssh
            .last_dead
            .lock()
            .map_err(|_| "lock")?
            .clone()
            .ok_or("none")?;
        drop(a);
        assert!(dead.load(Ordering::SeqCst), "the forward was killed");
        assert!(!dir.exists());
        Ok(())
    }
}
