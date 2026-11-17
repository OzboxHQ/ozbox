//! Where a project's commands may send data (ADR 0023). A command that holds a project's keys is the likeliest thing to be
//! poisoned (a test, a postinstall script), so its network is closed except for what the project's declaration names.
//!
//! The kernel half is `IPAddressDeny=any` on the command's unit: it can reach this machine's loopback and nothing else, so
//! a program that ignores a proxy setting simply cannot connect, and it cannot ask a name server anything (so DNS is not a
//! way out). The other half is this proxy, which the root launcher runs for the length of one command, on loopback, behind
//! a password that exists only in that command's environment (the agent shares loopback with the command, not its
//! environment). It answers `CONNECT host:port` for a declared host and port, resolves the name itself and refuses every
//! non-public address (the cloud metadata service, the box's own network), and then checks that the TLS hello the command
//! sends names the same host and does not hide it (encrypted hello). That last check is what stops a request to a shared
//! address (a content network) from asking for someone else's site once past the front door.
//!
//! The proxy carries HTTPS. A program that speaks a wire protocol of its own (Postgres, Redis, SMTP submission) cannot use
//! a proxy, so a project declares each such destination (`tcp`: host, port, and a name for the environment variables) and
//! the launcher opens a **loopback listener for exactly that destination** for the length of the command and tells the
//! command where it is (`<NAME>_HOST`, `<NAME>_PORT`, `<NAME>_ADDR`, and the declared host as `<NAME>_REMOTE_HOST`). Each
//! connection is resolved by the launcher and every address must be public, so a name that is pointed inward (or is
//! flipped inward between two connections) is refused. See ADR 0023 for why a listener and not a proxy command.

use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::netguard::ip_is_public;
use crate::peer_uid::PeerCheck;
use crate::serve::auth::b64::{ct_eq_bytes, encode_std};

/// One declared destination: `host` or `host:port` (port 443 by default), or `*.suffix` for every name under it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub host: String,
    pub wildcard: bool,
    pub port: u16,
}

pub const MAX_RULES: usize = 32;

fn label_ok(l: &str) -> bool {
    !l.is_empty()
        && l.len() <= 63
        && !l.starts_with('-')
        && !l.ends_with('-')
        && l.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Parse one entry of a declaration. A bare address is refused: names are what a policy is about, and a literal address
/// would let a declaration point at the box's own network.
pub fn parse_rule(text: &str) -> Result<Rule, &'static str> {
    let bad = "an egress entry is a host name like api.example.com, optionally *.example.com, optionally :port";
    let (host, port) = match text.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().map_err(|_| bad)?),
        None => (text, 443),
    };
    if port == 0 {
        return Err(bad);
    }
    let (wildcard, name) = match host.strip_prefix("*.") {
        Some(rest) => (true, rest),
        None => (false, host),
    };
    if name.len() > 253 || !name.contains('.') || !name.split('.').all(label_ok) {
        return Err(bad);
    }
    // a name that is all digits and dots is an address
    if name
        .split('.')
        .all(|l| l.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(bad);
    }
    Ok(Rule {
        host: name.to_string(),
        wildcard,
        port,
    })
}

pub fn parse_rules(entries: &[String]) -> Result<Vec<Rule>, &'static str> {
    if entries.len() > MAX_RULES {
        return Err("declare at most 32 egress entries");
    }
    entries.iter().map(|e| parse_rule(e)).collect()
}

/// Whether a CONNECT target is allowed. The match is on whole labels: `*.example.com` covers `a.example.com` and
/// `a.b.example.com`, never `example.com` itself and never `evilexample.com`.
pub fn allowed(rules: &[Rule], host: &str, port: u16) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    rules.iter().any(|r| {
        r.port == port
            && if r.wildcard {
                host.strip_suffix(&r.host)
                    .is_some_and(|pre| pre.ends_with('.') && pre.len() > 1)
            } else {
                host == r.host
            }
    })
}

/// Turns a name into addresses. The real one asks the system; a test gives a fixed answer.
pub trait Resolver: Send + Sync {
    fn resolve(&self, host: &str, port: u16) -> Vec<IpAddr>;
}

pub struct SystemResolver;
impl Resolver for SystemResolver {
    fn resolve(&self, host: &str, port: u16) -> Vec<IpAddr> {
        (host, port)
            .to_socket_addrs()
            .map(|a| a.map(|s| s.ip()).collect())
            .unwrap_or_default()
    }
}

/// What a TLS client hello says about where it is going.
#[derive(Debug, PartialEq, Eq)]
pub struct Hello {
    pub sni: Option<String>,
    /// The hello carries an encrypted inner name, which this proxy cannot read and so does not let through.
    pub hides_name: bool,
}

fn take<'a>(b: &'a [u8], at: &mut usize, n: usize) -> Option<&'a [u8]> {
    let s = b.get(*at..at.checked_add(n)?)?;
    *at += n;
    Some(s)
}

fn be16(s: &[u8]) -> usize {
    (usize::from(s[0]) << 8) | usize::from(s[1])
}

/// Read the server name out of the first TLS record. `None` when it is not a complete client hello.
pub fn parse_client_hello(b: &[u8]) -> Option<Hello> {
    let mut i = 0;
    let rec = take(b, &mut i, 5)?;
    if rec[0] != 22 {
        return None;
    }
    let rec_len = be16(&rec[3..5]);
    let body = take(b, &mut i, rec_len)?;
    let mut j = 0;
    let hs = take(body, &mut j, 4)?;
    if hs[0] != 1 {
        return None;
    }
    let hs_len = (usize::from(hs[1]) << 16) | (usize::from(hs[2]) << 8) | usize::from(hs[3]);
    let hello = take(body, &mut j, hs_len)?;
    let mut k = 0;
    take(hello, &mut k, 2 + 32)?;
    let sid = take(hello, &mut k, 1)?[0];
    take(hello, &mut k, usize::from(sid))?;
    let cs = be16(take(hello, &mut k, 2)?);
    take(hello, &mut k, cs)?;
    let comp = take(hello, &mut k, 1)?[0];
    take(hello, &mut k, usize::from(comp))?;
    let ext_len = be16(take(hello, &mut k, 2)?);
    let exts = take(hello, &mut k, ext_len)?;
    let mut e = 0;
    let (mut sni, mut hides) = (None, false);
    while e < exts.len() {
        let head = take(exts, &mut e, 4)?;
        let (ty, len) = (be16(&head[0..2]), be16(&head[2..4]));
        let data = take(exts, &mut e, len)?;
        match ty {
            0 => {
                let mut d = 0;
                let list_len = be16(take(data, &mut d, 2)?);
                let list = take(data, &mut d, list_len)?;
                let mut l = 0;
                while l < list.len() {
                    let h = take(list, &mut l, 3)?;
                    let name = take(list, &mut l, be16(&h[1..3]))?;
                    if h[0] == 0 && sni.is_none() {
                        sni = Some(String::from_utf8_lossy(name).to_ascii_lowercase());
                    }
                }
            }
            0xfe0d | 0xff02 => hides = true,
            _ => {}
        }
    }
    Some(Hello {
        sni,
        hides_name: hides,
    })
}

/// A raw TCP destination a project declares: the wire-protocol counterpart of an `egress` entry.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TcpDest {
    pub host: String,
    pub port: u16,
    /// The prefix of the environment variables that tell the command where its listener is (`DATABASE` gives
    /// `DATABASE_HOST`, `DATABASE_PORT`, `DATABASE_ADDR`, `DATABASE_REMOTE_HOST`).
    pub env: String,
}

pub const MAX_TCP: usize = 16;

fn env_prefix_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && !s.as_bytes()[0].is_ascii_digit()
        && s.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

/// Refuse a declaration that could not be followed safely: a name (never an address, never a wildcard), a real port, a
/// variable prefix, and no two destinations that share one.
pub fn validate_tcp(dests: &[TcpDest]) -> Result<(), &'static str> {
    if dests.len() > MAX_TCP {
        return Err("declare at most 16 tcp destinations");
    }
    let bad = "a tcp destination is a host name, a port and an environment prefix like DATABASE";
    let mut seen = std::collections::BTreeSet::new();
    for d in dests {
        if d.port == 0 || !env_prefix_ok(&d.env) || d.host.starts_with('*') {
            return Err(bad);
        }
        // the same rules a host has in `egress`
        parse_rule(&format!("{}:{}", d.host, d.port)).map_err(|_| bad)?;
        if !seen.insert(d.env.clone()) {
            return Err("two tcp destinations use the same environment prefix");
        }
    }
    Ok(())
}

/// The most connections one route carries at once. A connection past it is closed unread. A thread is made per connection, so this
/// is also what keeps a flood of requests from using up the unit's tasks and starving the accept loop.
pub const MAX_CONNECTIONS: usize = 256;

/// What every accept loop applies to a connection before anything is read from it, and what it does when it ends.
#[derive(Clone)]
pub struct Guard {
    /// Who may connect (a service's proxy: only the service's own user, see `peer_uid`). `None`: anyone on loopback, which is the
    /// one-shot proxy's case (a password keeps others off).
    pub peer_ok: Option<PeerCheck>,
    active: Arc<AtomicUsize>,
    max: usize,
    /// Told when an accept loop ends for any reason but the proxy being dropped: a route whose listener is gone is not a route, so
    /// the program that owns it must end (its unit then stops the service it is bound to).
    lost: Option<std::sync::mpsc::Sender<&'static str>>,
}

impl Guard {
    pub fn open() -> Self {
        Self::with(None, MAX_CONNECTIONS, None)
    }

    pub fn with(
        peer_ok: Option<PeerCheck>,
        max: usize,
        lost: Option<std::sync::mpsc::Sender<&'static str>>,
    ) -> Self {
        Guard {
            peer_ok,
            active: Arc::new(AtomicUsize::new(0)),
            max,
            lost,
        }
    }
}

/// What an accept loop does with a connection that passed its checks.
type ConnHandler = Arc<dyn Fn(TcpStream, &AtomicBool) + Send + Sync>;

/// One connection's slot in the cap, given back on drop.
struct Slot(Arc<AtomicUsize>);

impl Slot {
    fn take(active: &Arc<AtomicUsize>, max: usize) -> Option<Slot> {
        if active.fetch_add(1, Ordering::SeqCst) >= max {
            active.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(Slot(active.clone()))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Sends "the listener is gone" when an accept loop ends without its proxy having been dropped, a panic included.
struct LostOnExit {
    stop: Arc<AtomicBool>,
    tx: Option<std::sync::mpsc::Sender<&'static str>>,
}

impl Drop for LostOnExit {
    fn drop(&mut self) {
        if !self.stop.load(Ordering::SeqCst) {
            if let Some(tx) = &self.tx {
                let _ = tx.send("a listener of the route ended");
            }
        }
    }
}

/// An accept error that leaves the listener itself fine: a peer that gave up, a signal, and running out of descriptors or memory
/// for a moment (ENOMEM, ENFILE, EMFILE, ENOBUFS).
fn accept_error_is_transient(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::{ConnectionAborted, Interrupted, TimedOut, WouldBlock};
    matches!(
        e.kind(),
        ConnectionAborted | Interrupted | WouldBlock | TimedOut
    ) || matches!(e.raw_os_error(), Some(12 | 23 | 24 | 55 | 105))
}

/// Serve `listener` until `stop` is set: for each connection, take a slot (or close it unread), run the peer check, and hand it to
/// `handle` on a thread of its own. A thread that cannot be made drops the connection and nothing else (the old `thread::spawn`
/// panicked, which ended the loop and dropped the listener while the unit stayed up). A loop that ends for any other reason than
/// `stop` reports it through the guard.
fn spawn_accept_loop(
    listener: TcpListener,
    stop: Arc<AtomicBool>,
    guard: Guard,
    handle: ConnHandler,
) -> Result<(), String> {
    let lost = LostOnExit {
        stop: stop.clone(),
        tx: guard.lost.clone(),
    };
    std::thread::Builder::new()
        .name("egress-accept".into())
        .spawn(move || {
            let _lost = lost;
            for c in listener.incoming() {
                if stop.load(Ordering::SeqCst) {
                    return;
                }
                let c = match c {
                    Ok(c) => c,
                    Err(e) if accept_error_is_transient(&e) => {
                        std::thread::sleep(Duration::from_millis(20));
                        continue;
                    }
                    Err(_) => return,
                };
                let Some(slot) = Slot::take(&guard.active, guard.max) else {
                    continue; // closed unread: over the cap
                };
                let (handle, stop, peer_ok) = (handle.clone(), stop.clone(), guard.peer_ok.clone());
                // on a failed spawn the closure, and with it the connection and the slot, is dropped
                let _ = std::thread::Builder::new()
                    .name("egress-conn".into())
                    .spawn(move || {
                        let _slot = slot;
                        if peer_ok.as_ref().is_some_and(|ok| !ok(&c)) {
                            return; // not the service's user: closed unread
                        }
                        handle(c, &stop);
                    });
            }
        })
        .map(|_| ())
        .map_err(|_| "the proxy could not start a listener thread".to_string())
}

/// One loopback listener for one declared destination. Dropping it stops it.
pub struct TcpTunnel {
    pub port: u16,
    stop: Arc<AtomicBool>,
}

impl Drop for TcpTunnel {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
    }
}

/// Listen on a free loopback port and carry each connection to `host:port` and nowhere else. The name is resolved for every
/// connection by `resolver`, every address it returns must pass `public`, and the connection goes to one of those very
/// addresses (there is no second lookup to race).
pub fn start_tunnel(
    host: String,
    port: u16,
    resolver: Arc<dyn Resolver>,
    public: fn(IpAddr) -> bool,
) -> Result<TcpTunnel, String> {
    let l = TcpListener::bind(("127.0.0.1", 0))
        .map_err(|_| "a tcp tunnel could not start".to_string())?;
    start_tunnel_on(l, host, port, resolver, public, Guard::open())
}

/// [`start_tunnel`] on a listener the caller made (a service's route: the port is held by systemd, and the proxy is handed the
/// socket) and under the caller's [`Guard`].
pub fn start_tunnel_on(
    l: TcpListener,
    host: String,
    port: u16,
    resolver: Arc<dyn Resolver>,
    public: fn(IpAddr) -> bool,
    guard: Guard,
) -> Result<TcpTunnel, String> {
    let local = l
        .local_addr()
        .map_err(|_| "a tcp tunnel could not start".to_string())?
        .port();
    let stop = Arc::new(AtomicBool::new(false));
    let handle: ConnHandler = Arc::new(move |c, stop| {
        let addrs = resolver.resolve(&host, port);
        if addrs.is_empty() || !addrs.iter().all(|a| public(*a)) {
            return; // refused: closed without a byte forwarded
        }
        let up = addrs.iter().find_map(|a| {
            TcpStream::connect_timeout(&SocketAddr::new(*a, port), Duration::from_secs(10)).ok()
        });
        if let Some(up) = up {
            pump(c, up, stop);
        }
    });
    spawn_accept_loop(l, stop.clone(), guard, handle)?;
    Ok(TcpTunnel { port: local, stop })
}

/// The variables that make a runtime use the proxy address, set wherever `HTTPS_PROXY` is set and reserved like it.
///
/// Node's built-in `fetch` (undici, and so supabase-js and most SDKs) ignores `HTTPS_PROXY` unless `NODE_USE_ENV_PROXY=1`
/// (Node 22.21 and 24.5 onward; an older Node ignores the flag and goes direct, so it is refused by the closed network rather
/// than quietly using the proxy). Without it every https call from a Node command went direct and failed, while the raw `tcp`
/// tunnels worked. Python (`requests`, `httpx`, `urllib`), Go `net/http`, Deno, Bun, curl and Rust `reqwest` read
/// `HTTPS_PROXY` by themselves.
pub const PROXY_OPT_INS: [(&str, &str); 1] = [("NODE_USE_ENV_PROXY", "1")];

/// The environment lines that tell a command where its tunnels are.
pub fn tunnel_env(dest: &TcpDest, port: u16) -> Vec<(String, String)> {
    vec![
        (format!("{}_HOST", dest.env), "127.0.0.1".to_string()),
        (format!("{}_PORT", dest.env), port.to_string()),
        (format!("{}_ADDR", dest.env), format!("127.0.0.1:{port}")),
        (format!("{}_REMOTE_HOST", dest.env), dest.host.clone()),
    ]
}

/// A running proxy. Dropping it stops it and closes what it is carrying.
pub struct EgressProxy {
    pub port: u16,
    /// The password the command presents, `run:<password>` in the proxy address.
    pub password: String,
    stop: Arc<AtomicBool>,
}

impl EgressProxy {
    /// The value for the proxy variables of the command's environment. A proxy with no password (a service's, which the kernel
    /// limits to one user: see `runner_egress`) is a plain address.
    pub fn url(&self) -> String {
        if self.password.is_empty() {
            format!("http://127.0.0.1:{}", self.port)
        } else {
            format!("http://run:{}@127.0.0.1:{}", self.password, self.port)
        }
    }
}

impl Drop for EgressProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // wake the accept loop
        let _ = TcpStream::connect(("127.0.0.1", self.port));
    }
}

const IO_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_HEAD: usize = 8 * 1024;
const MAX_HELLO: usize = 16 * 1024 + 5;

/// Start a proxy on a free loopback port for these rules.
pub fn start(rules: Vec<Rule>, resolver: Arc<dyn Resolver>) -> Result<EgressProxy, String> {
    start_with(rules, resolver, ip_is_public)
}

/// `public` decides which addresses a name may resolve to; the real one is `ip_is_public`, a test passes its own so a
/// listener on loopback can stand for the declared host.
pub fn start_with(
    rules: Vec<Rule>,
    resolver: Arc<dyn Resolver>,
    public: fn(IpAddr) -> bool,
) -> Result<EgressProxy, String> {
    let mut raw = [0u8; 24];
    getrandom::getrandom(&mut raw).map_err(|_| "no random numbers are available".to_string())?;
    let password = crate::serve::auth::b64::encode_url(&raw);
    let l = TcpListener::bind(("127.0.0.1", 0))
        .map_err(|_| "the egress proxy could not start".to_string())?;
    start_inner(l, rules, resolver, public, password, Guard::open())
}

/// A proxy on a listener the caller made, with no password: for a service's route, where a program cannot be handed a secret in an
/// environment variable (a unit's properties are readable by every user of the box) and what keeps everyone else off the port is a
/// kernel rule on the connecting user and the proxy's own check of the same (`runner_egress`, `peer_uid`). The rules, the address
/// check and the hello check are exactly the one-shot proxy's: this only changes how a caller is recognised.
pub fn start_open_on(
    l: TcpListener,
    rules: Vec<Rule>,
    resolver: Arc<dyn Resolver>,
    guard: Guard,
) -> Result<EgressProxy, String> {
    start_open_with_on(l, rules, resolver, ip_is_public, guard)
}

pub fn start_open_with_on(
    l: TcpListener,
    rules: Vec<Rule>,
    resolver: Arc<dyn Resolver>,
    public: fn(IpAddr) -> bool,
    guard: Guard,
) -> Result<EgressProxy, String> {
    start_inner(l, rules, resolver, public, String::new(), guard)
}

fn start_inner(
    l: TcpListener,
    rules: Vec<Rule>,
    resolver: Arc<dyn Resolver>,
    public: fn(IpAddr) -> bool,
    password: String,
    guard: Guard,
) -> Result<EgressProxy, String> {
    let port = l
        .local_addr()
        .map_err(|_| "the egress proxy could not start".to_string())?
        .port();
    let stop = Arc::new(AtomicBool::new(false));
    // an empty password means no `Proxy-Authorization` is asked for
    let expect = (!password.is_empty())
        .then(|| format!("Basic {}", encode_std(format!("run:{password}").as_bytes())));
    let rules = Arc::new(rules);
    let handle: ConnHandler = Arc::new(move |c, stop| {
        let _ = serve(
            c,
            &rules,
            resolver.as_ref(),
            public,
            expect.as_deref(),
            stop,
        );
    });
    spawn_accept_loop(l, stop.clone(), guard, handle)?;
    Ok(EgressProxy {
        port,
        password,
        stop,
    })
}

fn reply(c: &mut TcpStream, status: &str) {
    let _ = c.write_all(
        format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes(),
    );
}

fn read_head(c: &mut TcpStream) -> Option<String> {
    let mut buf = Vec::new();
    let mut b = [0u8; 1];
    while buf.len() < MAX_HEAD {
        if c.read(&mut b).ok()? == 0 {
            return None;
        }
        buf.push(b[0]);
        if buf.ends_with(b"\r\n\r\n") {
            return String::from_utf8(buf).ok();
        }
    }
    None
}

/// Split `host:port`, with `[v6]:port` refused (an address is not a declared name).
fn split_target(t: &str) -> Option<(String, u16)> {
    let (h, p) = t.rsplit_once(':')?;
    Some((h.to_ascii_lowercase(), p.parse().ok()?))
}

fn serve(
    mut c: TcpStream,
    rules: &[Rule],
    resolver: &dyn Resolver,
    public: fn(IpAddr) -> bool,
    expect: Option<&str>,
    stop: &AtomicBool,
) -> Option<()> {
    c.set_read_timeout(Some(IO_TIMEOUT)).ok()?;
    c.set_write_timeout(Some(IO_TIMEOUT)).ok()?;
    let head = read_head(&mut c)?;
    let mut lines = head.split("\r\n");
    let first = lines.next()?;
    let auth = lines
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.eq_ignore_ascii_case("proxy-authorization"))
        .map(|(_, v)| v.trim().to_string())
        .unwrap_or_default();
    if expect.is_some_and(|e| !ct_eq_bytes(auth.as_bytes(), e.as_bytes())) {
        reply(&mut c, "407 Proxy Authentication Required");
        return None;
    }
    let mut parts = first.split(' ');
    let (method, target) = (parts.next()?, parts.next()?);
    if method != "CONNECT" {
        reply(&mut c, "405 Method Not Allowed");
        return None;
    }
    let Some((host, port)) = split_target(target) else {
        reply(&mut c, "400 Bad Request");
        return None;
    };
    if !allowed(rules, &host, port) {
        reply(&mut c, "403 Forbidden");
        return None;
    }
    // Resolved here, by the proxy, and every address must be public: a declared name that points inward is refused.
    let addrs: Vec<IpAddr> = resolver.resolve(&host, port);
    if addrs.is_empty() || !addrs.iter().all(|a| public(*a)) {
        reply(&mut c, "502 Bad Gateway");
        return None;
    }
    let up = addrs.iter().find_map(|a| {
        TcpStream::connect_timeout(&SocketAddr::new(*a, port), Duration::from_secs(10)).ok()
    });
    let Some(mut up) = up else {
        reply(&mut c, "502 Bad Gateway");
        return None;
    };
    let _ = up.set_read_timeout(Some(IO_TIMEOUT));
    c.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .ok()?;
    // The first thing the command sends must be a TLS hello for the same host, not hidden.
    let mut first = vec![0u8; 5];
    c.read_exact(&mut first).ok()?;
    let want = be16(&first[3..5]).min(MAX_HELLO);
    let mut rest = vec![0u8; want];
    c.read_exact(&mut rest).ok()?;
    first.extend(rest);
    match parse_client_hello(&first) {
        Some(h) if !h.hides_name && h.sni.as_deref() == Some(host.as_str()) => {}
        _ => return None,
    }
    up.write_all(&first).ok()?;
    pump(c, up, stop);
    Some(())
}

fn pump(c: TcpStream, up: TcpStream, stop: &AtomicBool) {
    let _ = c.set_read_timeout(None);
    let _ = up.set_read_timeout(None);
    let (Ok(mut c2), Ok(mut up2)) = (c.try_clone(), up.try_clone()) else {
        return;
    };
    let (mut c1, mut up1) = (c, up);
    // no thread to carry the other direction: the connection is dropped, never a panic
    let Ok(t) = std::thread::Builder::new().spawn(move || {
        let _ = std::io::copy(&mut up2, &mut c2);
        let _ = c2.shutdown(Shutdown::Both);
    }) else {
        return;
    };
    let _ = std::io::copy(&mut c1, &mut up1);
    let _ = up1.shutdown(Shutdown::Both);
    let _ = t.join();
    let _ = stop.load(Ordering::SeqCst);
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// A minimal TLS client hello for `sni`, with an optional hidden-name extension.
    pub fn hello(sni: &str, ech: bool) -> Vec<u8> {
        let mut ext = Vec::new();
        let name = sni.as_bytes();
        let mut sn = vec![0u8];
        sn.extend((name.len() as u16).to_be_bytes());
        sn.extend(name);
        let mut list = (sn.len() as u16).to_be_bytes().to_vec();
        list.extend(sn);
        ext.extend(0u16.to_be_bytes());
        ext.extend((list.len() as u16).to_be_bytes());
        ext.extend(list);
        if ech {
            ext.extend(0xfe0du16.to_be_bytes());
            ext.extend(2u16.to_be_bytes());
            ext.extend([0, 0]);
        }
        let mut h = vec![3, 3];
        h.extend([7u8; 32]);
        h.push(0);
        h.extend(2u16.to_be_bytes());
        h.extend([0x13, 0x01]);
        h.extend([1, 0]);
        h.extend((ext.len() as u16).to_be_bytes());
        h.extend(ext);
        let mut hs = vec![1u8];
        hs.extend([(h.len() >> 16) as u8, (h.len() >> 8) as u8, h.len() as u8]);
        hs.extend(h);
        let mut rec = vec![22u8, 3, 1];
        rec.extend((hs.len() as u16).to_be_bytes());
        rec.extend(hs);
        rec
    }

    #[test]
    fn rules_parse_names_ports_and_wildcards_and_refuse_addresses() {
        assert_eq!(
            parse_rule("api.example.com").unwrap(),
            Rule {
                host: "api.example.com".into(),
                wildcard: false,
                port: 443
            }
        );
        assert_eq!(parse_rule("*.example.com:8443").unwrap().port, 8443);
        for bad in [
            "10.0.0.1",
            "169.254.169.254:80",
            "localhost",
            "a b.example.com",
            "*.com.",
            "x.example.com:0",
            "x.example.com:99999",
            "",
            "-a.example.com",
            "*example.com",
        ] {
            assert!(parse_rule(bad).is_err(), "{bad}");
        }
        assert!(parse_rules(&vec!["a.example.com".to_string(); 33]).is_err());
    }

    #[test]
    fn a_wildcard_covers_names_under_it_and_nothing_that_merely_ends_alike() {
        let r = parse_rules(&[
            "*.supabase.co".into(),
            "registry.npmjs.org".into(),
            "db.example.com:5432".into(),
        ])
        .unwrap();
        assert!(allowed(&r, "abc.supabase.co", 443));
        assert!(allowed(&r, "A.B.SUPABASE.CO.", 443));
        assert!(!allowed(&r, "supabase.co", 443));
        assert!(!allowed(&r, "evilsupabase.co", 443));
        assert!(!allowed(&r, "abc.supabase.co.evil.com", 443));
        assert!(allowed(&r, "registry.npmjs.org", 443));
        assert!(!allowed(&r, "registry.npmjs.org", 80));
        assert!(allowed(&r, "db.example.com", 5432) && !allowed(&r, "db.example.com", 443));
    }

    #[test]
    fn the_hello_parser_reads_the_name_and_notices_a_hidden_one() {
        assert_eq!(
            parse_client_hello(&hello("api.example.com", false)).unwrap(),
            Hello {
                sni: Some("api.example.com".into()),
                hides_name: false
            }
        );
        assert!(
            parse_client_hello(&hello("api.example.com", true))
                .unwrap()
                .hides_name
        );
        assert!(parse_client_hello(b"GET / HTTP/1.1\r\n\r\n").is_none());
        let h = hello("a.example.com", false);
        assert!(parse_client_hello(&h[..h.len() - 3]).is_none());
    }

    struct Fixed(HashMap<String, Vec<IpAddr>>);
    impl Resolver for Fixed {
        fn resolve(&self, host: &str, _: u16) -> Vec<IpAddr> {
            self.0.get(host).cloned().unwrap_or_default()
        }
    }

    fn connect(p: &EgressProxy, target: &str, auth: Option<&str>) -> (String, TcpStream) {
        let mut s = TcpStream::connect(("127.0.0.1", p.port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let a = auth
            .map(|x| {
                format!(
                    "Proxy-Authorization: Basic {}\r\n",
                    encode_std(x.as_bytes())
                )
            })
            .unwrap_or_default();
        s.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{a}\r\n").as_bytes())
            .unwrap();
        let mut buf = [0u8; 512];
        let n = s.read(&mut buf).unwrap_or(0);
        (String::from_utf8_lossy(&buf[..n]).to_string(), s)
    }

    fn any_address(_: IpAddr) -> bool {
        true
    }

    fn resolver(pairs: &[(&str, [u8; 4])]) -> Arc<dyn Resolver> {
        Arc::new(Fixed(
            pairs
                .iter()
                .map(|(h, a)| (h.to_string(), vec![IpAddr::from(*a)]))
                .collect(),
        ))
    }

    #[test]
    fn the_proxy_carries_a_declared_host_and_refuses_everything_else() {
        // a listener on loopback stands for the declared host
        let up = TcpListener::bind("127.0.0.1:0").unwrap();
        let up_port = up.local_addr().unwrap().port();
        let seen = std::thread::spawn(move || {
            let (mut c, _) = up.accept().unwrap();
            let mut b = vec![0u8; 4096];
            let n = c.read(&mut b).unwrap();
            c.write_all(b"pong").unwrap();
            b.truncate(n);
            b
        });
        let rules = parse_rules(&[format!("api.example.com:{up_port}")]).unwrap();
        let p = start_with(
            rules,
            resolver(&[("api.example.com", [127, 0, 0, 1])]),
            any_address,
        )
        .unwrap();
        let pw = format!("run:{}", p.password);
        let (r, mut s) = connect(&p, &format!("api.example.com:{up_port}"), Some(&pw));
        assert!(r.starts_with("HTTP/1.1 200"), "{r}");
        let h = hello("api.example.com", false);
        s.write_all(&h).unwrap();
        let mut back = [0u8; 4];
        s.read_exact(&mut back).unwrap();
        assert_eq!(&back, b"pong");
        assert_eq!(seen.join().unwrap(), h);
    }

    #[test]
    fn an_open_proxy_on_a_given_listener_applies_the_same_rules_without_a_password() {
        // a listener made by the caller (a service's route: systemd holds the port and hands the socket over)
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let up = TcpListener::bind("127.0.0.1:0").unwrap();
        let up_port = up.local_addr().unwrap().port();
        let seen = std::thread::spawn(move || {
            let (mut c, _) = up.accept().unwrap();
            let mut b = vec![0u8; 4096];
            let n = c.read(&mut b).unwrap();
            c.write_all(b"pong").unwrap();
            b.truncate(n);
            b
        });
        let rules = parse_rules(&[format!("api.example.com:{up_port}")]).unwrap();
        let p = start_open_with_on(
            l,
            rules,
            resolver(&[("api.example.com", [127, 0, 0, 1])]),
            any_address,
            Guard::open(),
        )
        .unwrap();
        assert_eq!(p.port, port);
        assert_eq!(
            p.url(),
            format!("http://127.0.0.1:{port}"),
            "no credentials in the address"
        );
        // an undeclared host is refused exactly as in the one-shot proxy, with no password asked for
        let (r, _s) = connect(&p, "other.example.com:443", None);
        assert!(r.starts_with("HTTP/1.1 403"), "{r}");
        // the declared one is carried, and a hello for another name is still cut off by the same check
        let (r, mut s) = connect(&p, &format!("api.example.com:{up_port}"), None);
        assert!(r.starts_with("HTTP/1.1 200"), "{r}");
        let h = hello("api.example.com", false);
        s.write_all(&h).unwrap();
        let mut back = [0u8; 4];
        s.read_exact(&mut back).unwrap();
        assert_eq!(&back, b"pong");
        assert_eq!(seen.join().unwrap(), h);
        // the port is held by the proxy's socket: nobody else binds it
        assert!(TcpListener::bind(("127.0.0.1", port)).is_err());
    }

    /// A proxy for `api.example.com` on `up_port`, on its own listener, under `guard`.
    fn guarded_proxy(guard: Guard, up_port: u16) -> EgressProxy {
        let rules = parse_rules(&[format!("api.example.com:{up_port}")]).unwrap();
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        start_open_with_on(
            l,
            rules,
            resolver(&[("api.example.com", [127, 0, 0, 1])]),
            any_address,
            guard,
        )
        .unwrap()
    }

    fn deny_all() -> PeerCheck {
        Arc::new(|_| false)
    }

    #[test]
    fn a_connection_the_peer_check_refuses_is_closed_before_a_byte_is_read() {
        let seen = Arc::new(AtomicUsize::new(0));
        let s2 = seen.clone();
        let check: PeerCheck = Arc::new(move |_| {
            s2.fetch_add(1, Ordering::SeqCst);
            false
        });
        let p = guarded_proxy(Guard::with(Some(check), 8, None), 1);
        let mut s = TcpStream::connect(("127.0.0.1", p.port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.write_all(b"CONNECT api.example.com:1 HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        let mut b = [0u8; 64];
        // closed, with no answer at all (not even a 403): it is not the service
        assert_eq!(s.read(&mut b).unwrap_or(0), 0);
        assert_eq!(seen.load(Ordering::SeqCst), 1);
        // a check that says yes lets the same request through to the rules
        let p = guarded_proxy(Guard::with(Some(Arc::new(|_| true)), 8, None), 1);
        let (r, _s) = connect(&p, "other.example.com:443", None);
        assert!(r.starts_with("HTTP/1.1 403"), "{r}");
    }

    #[test]
    fn a_tunnel_refuses_a_peer_the_check_refuses_and_forwards_nothing() {
        let up = TcpListener::bind("127.0.0.1:0").unwrap();
        let up_port = up.local_addr().unwrap().port();
        up.set_nonblocking(true).unwrap();
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let t = start_tunnel_on(
            l,
            "db.example.com".into(),
            up_port,
            resolver(&[("db.example.com", [127, 0, 0, 1])]),
            any_address,
            Guard::with(Some(deny_all()), 8, None),
        )
        .unwrap();
        let mut s = TcpStream::connect(("127.0.0.1", t.port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut b = [0u8; 8];
        assert_eq!(s.read(&mut b).unwrap_or(0), 0);
        std::thread::sleep(Duration::from_millis(200));
        assert!(up.accept().is_err(), "nothing reached the destination");
    }

    #[test]
    fn connections_past_the_cap_are_closed_unread_and_a_slot_comes_back() {
        let up = TcpListener::bind("127.0.0.1:0").unwrap();
        let up_port = up.local_addr().unwrap().port();
        let p = guarded_proxy(Guard::with(None, 1, None), up_port);
        // the first connection holds the only slot: a CONNECT it never finishes
        let mut first = TcpStream::connect(("127.0.0.1", p.port)).unwrap();
        std::thread::sleep(Duration::from_millis(200));
        let mut second = TcpStream::connect(("127.0.0.1", p.port)).unwrap();
        second
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut b = [0u8; 8];
        assert_eq!(
            second.read(&mut b).unwrap_or(0),
            0,
            "over the cap: closed unread"
        );
        // the first is finished: its slot returns and a new connection is served
        first.write_all(b"junk\r\n\r\n").unwrap();
        std::thread::sleep(Duration::from_millis(300));
        let (r, _s) = connect(&p, "other.example.com:443", None);
        assert!(r.starts_with("HTTP/1.1 403"), "{r}");
    }

    #[test]
    fn a_listener_that_ends_is_reported_and_a_stopped_proxy_is_not() {
        let (tx, rx) = std::sync::mpsc::channel();
        let p = guarded_proxy(Guard::with(None, 8, Some(tx)), 1);
        assert!(rx.try_recv().is_err(), "a running listener says nothing");
        drop(p);
        std::thread::sleep(Duration::from_millis(300));
        assert!(
            rx.try_recv().is_err(),
            "ending because the proxy was dropped is not a loss"
        );
        // an accept loop that dies for any other reason says so (a panic in the loop is how the old code lost its listener)
        let (tx, rx) = std::sync::mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let lost = LostOnExit { stop, tx: Some(tx) };
        let _ = std::thread::spawn(move || {
            let _lost = lost;
            panic!("the loop died");
        })
        .join();
        assert!(rx.recv_timeout(Duration::from_secs(2)).is_ok());
    }

    #[test]
    fn a_transient_accept_error_is_not_a_lost_listener_and_a_broken_one_is() {
        use std::io::{Error, ErrorKind};
        assert!(accept_error_is_transient(&Error::from(
            ErrorKind::ConnectionAborted
        )));
        assert!(accept_error_is_transient(&Error::from_raw_os_error(24)));
        assert!(!accept_error_is_transient(&Error::from_raw_os_error(9)));
        assert!(!accept_error_is_transient(&Error::from(
            ErrorKind::InvalidInput
        )));
    }

    #[test]
    fn a_hello_for_another_name_or_a_hidden_one_is_cut_off_before_anything_reaches_the_host() {
        for (sni, ech) in [("evil.example.net", false), ("api.example.com", true)] {
            let up = TcpListener::bind("127.0.0.1:0").unwrap();
            let up_port = up.local_addr().unwrap().port();
            up.set_nonblocking(false).unwrap();
            let seen = std::thread::spawn(move || {
                let (mut c, _) = up.accept().unwrap();
                c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                let mut b = [0u8; 64];
                c.read(&mut b).unwrap_or(0)
            });
            let rules = parse_rules(&[format!("api.example.com:{up_port}")]).unwrap();
            let p = start_with(
                rules,
                resolver(&[("api.example.com", [127, 0, 0, 1])]),
                any_address,
            )
            .unwrap();
            let pw = format!("run:{}", p.password);
            let (r, mut s) = connect(&p, &format!("api.example.com:{up_port}"), Some(&pw));
            assert!(r.starts_with("HTTP/1.1 200"), "{r}");
            s.write_all(&hello(sni, ech)).unwrap();
            let mut b = [0u8; 8];
            // the proxy closes without forwarding
            assert_eq!(s.read(&mut b).unwrap_or(0), 0);
            assert_eq!(seen.join().unwrap(), 0, "{sni} {ech}");
        }
    }

    #[test]
    fn policy_refusals_and_the_address_check() {
        let res = || {
            resolver(&[
                ("api.example.com", [93, 184, 216, 34]),
                ("evil.example.net", [93, 184, 216, 34]),
                ("meta.example.com", [169, 254, 169, 254]),
            ])
        };
        let p = start(
            parse_rules(&["api.example.com".into(), "meta.example.com".into()]).unwrap(),
            res(),
        )
        .unwrap();
        let pw = format!("run:{}", p.password);
        // no password, a wrong one, and the agent's guess
        assert!(connect(&p, "api.example.com:443", None)
            .0
            .starts_with("HTTP/1.1 407"));
        assert!(connect(&p, "api.example.com:443", Some("run:guess"))
            .0
            .starts_with("HTTP/1.1 407"));
        // an undeclared host, an undeclared port, an address
        assert!(connect(&p, "evil.example.net:443", Some(&pw))
            .0
            .starts_with("HTTP/1.1 403"));
        assert!(connect(&p, "api.example.com:22", Some(&pw))
            .0
            .starts_with("HTTP/1.1 403"));
        assert!(connect(&p, "169.254.169.254:443", Some(&pw))
            .0
            .starts_with("HTTP/1.1 403"));
        // a declared name that resolves inward (the metadata address) is refused with the real check
        assert!(connect(&p, "meta.example.com:443", Some(&pw))
            .0
            .starts_with("HTTP/1.1 502"));
        // a plain request is not proxied
        let mut s = TcpStream::connect(("127.0.0.1", p.port)).unwrap();
        s.write_all(
            format!(
                "GET http://api.example.com/ HTTP/1.1\r\nProxy-Authorization: Basic {}\r\n\r\n",
                encode_std(pw.as_bytes())
            )
            .as_bytes(),
        )
        .unwrap();
        let mut b = [0u8; 64];
        let n = s.read(&mut b).unwrap();
        assert!(String::from_utf8_lossy(&b[..n]).starts_with("HTTP/1.1 405"));
        assert!(p.url().contains(&p.password));
    }

    #[test]
    fn tcp_declarations_are_names_ports_and_distinct_prefixes() {
        let d = |h: &str, p: u16, e: &str| TcpDest {
            host: h.into(),
            port: p,
            env: e.into(),
        };
        assert!(validate_tcp(&[
            d("db.staging.example.com", 5432, "DATABASE"),
            d("cache.example.com", 6379, "REDIS")
        ])
        .is_ok());
        for bad in [
            vec![d("10.0.0.5", 5432, "DB")],
            vec![d("*.example.com", 5432, "DB")],
            vec![d("localhost", 5432, "DB")],
            vec![d("db.example.com", 0, "DB")],
            vec![d("db.example.com", 5432, "db")],
            vec![d("db.example.com", 5432, "1DB")],
            vec![
                d("db.example.com", 5432, "DB"),
                d("other.example.com", 25, "DB"),
            ],
        ] {
            assert!(validate_tcp(&bad).is_err());
        }
        assert!(validate_tcp(&vec![d("a.example.com", 1, "A"); 17]).is_err());
        let e = tunnel_env(&d("db.example.com", 5432, "DATABASE"), 41000);
        assert!(e.contains(&("DATABASE_ADDR".to_string(), "127.0.0.1:41000".to_string())));
        assert!(e.contains(&(
            "DATABASE_REMOTE_HOST".to_string(),
            "db.example.com".to_string()
        )));
    }

    /// Answers differently each time it is asked, the way a name under an attacker's control does.
    struct Flipping(std::sync::Mutex<Vec<Vec<IpAddr>>>);
    impl Resolver for Flipping {
        fn resolve(&self, _: &str, _: u16) -> Vec<IpAddr> {
            let mut v = self.0.lock().unwrap();
            if v.len() > 1 {
                v.remove(0)
            } else {
                v[0].clone()
            }
        }
    }

    #[test]
    fn a_declared_tcp_destination_is_reachable_and_carries_a_raw_protocol_both_ways() {
        let up = TcpListener::bind("127.0.0.1:0").unwrap();
        let up_port = up.local_addr().unwrap().port();
        let seen = std::thread::spawn(move || {
            let (mut c, _) = up.accept().unwrap();
            let mut b = [0u8; 5];
            c.read_exact(&mut b).unwrap();
            c.write_all(b"+PONG").unwrap();
            b
        });
        let t = start_tunnel(
            "db.example.com".into(),
            up_port,
            resolver(&[("db.example.com", [127, 0, 0, 1])]),
            any_address,
        )
        .unwrap();
        let mut s = TcpStream::connect(("127.0.0.1", t.port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.write_all(b"PING\n").unwrap();
        let mut back = [0u8; 5];
        s.read_exact(&mut back).unwrap();
        assert_eq!(&back, b"+PONG");
        assert_eq!(&seen.join().unwrap(), b"PING\n");
    }

    fn refused(t: &TcpTunnel) -> bool {
        let mut s = TcpStream::connect(("127.0.0.1", t.port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let _ = s.write_all(b"hello");
        let mut b = [0u8; 8];
        s.read(&mut b).unwrap_or(0) == 0
    }

    #[test]
    fn a_tcp_destination_that_resolves_inward_is_refused_with_the_real_address_check() {
        // the metadata address, a private one, loopback, link-local v6 and an empty answer: all refused, nothing forwarded
        for ip in [
            [169, 254, 169, 254],
            [10, 0, 0, 9],
            [127, 0, 0, 1],
            [192, 168, 1, 1],
        ] {
            let t = start_tunnel(
                "db.example.com".into(),
                5432,
                resolver(&[("db.example.com", ip)]),
                ip_is_public,
            )
            .unwrap();
            assert!(refused(&t), "{ip:?}");
        }
        let t = start_tunnel("db.example.com".into(), 5432, resolver(&[]), ip_is_public).unwrap();
        assert!(refused(&t));
        // one inward address among public ones refuses the lot
        let mixed = Arc::new(Fixed(HashMap::from([(
            "db.example.com".to_string(),
            vec![
                IpAddr::from([93, 184, 216, 34]),
                IpAddr::from([169, 254, 169, 254]),
            ],
        )])));
        assert!(refused(
            &start_tunnel("db.example.com".into(), 5432, mixed, ip_is_public).unwrap()
        ));
    }

    #[test]
    fn a_name_that_flips_inward_between_two_connections_is_refused_the_second_time() {
        let up = TcpListener::bind("127.0.0.1:0").unwrap();
        let up_port = up.local_addr().unwrap().port();
        std::thread::spawn(move || {
            while let Ok((mut c, _)) = up.accept() {
                let _ = c.write_all(b"hi");
            }
        });
        // first answer: the declared (here: loopback standing for public) host; then the metadata address
        let r: Arc<dyn Resolver> = Arc::new(Flipping(std::sync::Mutex::new(vec![
            vec![IpAddr::from([127, 0, 0, 1])],
            vec![IpAddr::from([169, 254, 169, 254])],
        ])));
        fn only_loopback(ip: IpAddr) -> bool {
            ip.is_loopback()
        }
        let t = start_tunnel("db.example.com".into(), up_port, r, only_loopback).unwrap();
        let mut first = TcpStream::connect(("127.0.0.1", t.port)).unwrap();
        first
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut b = [0u8; 2];
        first.read_exact(&mut b).unwrap();
        assert_eq!(&b, b"hi");
        assert!(refused(&t), "the rebound name is refused");
    }

    #[test]
    fn a_tunnel_stops_when_it_is_dropped() {
        let t = start_tunnel("db.example.com".into(), 5432, resolver(&[]), ip_is_public).unwrap();
        let port = t.port;
        drop(t);
        std::thread::sleep(Duration::from_millis(200));
        assert!(TcpStream::connect(("127.0.0.1", port)).is_err());
    }
}
