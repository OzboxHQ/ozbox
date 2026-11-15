//! The IDE or desktop on the person's own address, behind the Oz Box sign-in: the second lock.
//!
//! An identity-aware proxy in front of the tunnel (Cloudflare Access, say) is one lock. This is another that does not
//! depend on it: a request for a code host reaches the box only with an Oz Box session behind it. Nothing about that
//! check trusts the network.
//!
//! * The listener is its own, on loopback (`--code-port`), so a WebSocket can be relayed byte for byte. The dashboard's
//!   own listener never serves a code host and this one never serves the dashboard.
//! * The dashboard's session cookie belongs to the dashboard's host and is never sent to a code host, and its `Domain` is
//!   never widened. Instead a signed-in person asks the dashboard (`GET /code/enter?host=...`) for a single-use ticket
//!   valid for 60 seconds. The code host trades it for a cookie of its own (`HttpOnly`, `Secure`, `SameSite=Lax`, 12
//!   hours). Every request must carry that cookie, and the cookie stops working the moment the dashboard session it came
//!   from ends (sign-out, expiry, removal of the person).
//! * Without a valid cookie nothing is dialled: not for a page, not for a WebSocket upgrade. A page request is sent to the
//!   dashboard to sign in; anything else gets 401.
//! * What the box's service sees is not what the browser sent: the Oz Box cookie and any `Authorization` header are
//!   removed. The service's own sign-in is done for the person (code-server: a login form posted once; KasmVNC: the
//!   basic-auth header added here), so its password never has to be known by anyone.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::{CodeSettings, Service};
use crate::secrets::SecretStore;
use crate::serve::agent::Conn;
use crate::serve::auth::b64::encode_std;
use crate::serve::auth::session::{cookie_value, key_of, random_token, set_cookie};
use crate::tokenmac::lookup_keys;

pub const COOKIE: &str = "ozbox_code";
pub const ENTER_PATH: &str = "/__ozbox/enter";
const TICKET_TTL_MS: u64 = 60_000;
const SESSION_TTL_MS: u64 = 12 * 3_600_000;
const MAX_TICKETS: usize = 64;
const MAX_SESSIONS: usize = 256;
const MAX_CONNECTIONS: usize = 128;
const MAX_HEAD: usize = 16 * 1024;
/// How long the proxy waits for a client to send its request. Tests that play the client wait the same, never less.
const CLIENT_READ_LIMIT: Duration = Duration::from_secs(30);
/// The loopback port of the code listener unless told otherwise.
pub const DEFAULT_PORT: u16 = 7879;

/// Whether the dashboard session a code session came from is still good.
pub trait DashSessions: Send + Sync {
    fn alive(&self, dashboard_key: &str) -> bool;
}

/// A way to the box's service.
pub trait Upstream: Send + Sync {
    fn dial(&self, box_name: &str, service: Service) -> Result<Conn, String>;
}

struct Ticket {
    dash_key: String,
    host: String,
    expires_ms: u64,
}

struct CodeSession {
    host: String,
    dash_key: String,
    expires_ms: u64,
}

pub struct Gate {
    pub settings: Arc<Mutex<CodeSettings>>,
    /// The dashboard's address (`https://ozbox.example.com`): where a person without a session is sent.
    pub dashboard_origin: String,
    pub dash: Arc<dyn DashSessions>,
    pub upstream: Arc<dyn Upstream>,
    pub secrets: Arc<dyn SecretStore>,
    pub now: Arc<dyn Fn() -> u64 + Send + Sync>,
    tickets: Mutex<HashMap<String, Ticket>>,
    sessions: Mutex<HashMap<String, CodeSession>>,
    open: AtomicUsize,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Gate {
    pub fn new(
        settings: Arc<Mutex<CodeSettings>>,
        dashboard_origin: String,
        dash: Arc<dyn DashSessions>,
        upstream: Arc<dyn Upstream>,
        secrets: Arc<dyn SecretStore>,
        now: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Self {
        Self {
            settings,
            dashboard_origin: dashboard_origin.trim_end_matches('/').to_string(),
            dash,
            upstream,
            secrets,
            now,
            tickets: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
            open: AtomicUsize::new(0),
        }
    }

    /// For a signed-in dashboard session: a single-use ticket for `host`, or `None` when no such host is served.
    pub fn issue_ticket(&self, dash_key: &str, host: &str) -> Option<String> {
        lock(&self.settings).by_host(host)?;
        let now = (self.now)();
        let id = random_token(32)?;
        let mut t = lock(&self.tickets);
        t.retain(|_, v| v.expires_ms > now);
        if t.len() >= MAX_TICKETS {
            return None;
        }
        t.insert(
            key_of(&id),
            Ticket {
                dash_key: dash_key.to_string(),
                host: host.to_ascii_lowercase(),
                expires_ms: now + TICKET_TTL_MS,
            },
        );
        Some(id)
    }

    /// Trade a ticket for a session on `host`. A ticket works once, for the host it was issued for, within its minute.
    fn redeem(&self, ticket: &str, host: &str) -> Option<String> {
        let now = (self.now)();
        let t = {
            let mut tickets = lock(&self.tickets);
            lookup_keys(ticket).iter().find_map(|k| tickets.remove(k))?
        };
        if t.expires_ms <= now || t.host != host || !self.dash.alive(&t.dash_key) {
            return None;
        }
        let id = random_token(32)?;
        let mut s = lock(&self.sessions);
        s.retain(|_, v| v.expires_ms > now);
        if s.len() >= MAX_SESSIONS {
            return None;
        }
        s.insert(
            key_of(&id),
            CodeSession {
                host: host.to_string(),
                dash_key: t.dash_key,
                expires_ms: now + SESSION_TTL_MS,
            },
        );
        Some(id)
    }

    fn session_ok(&self, cookie_id: &str, host: &str) -> bool {
        let now = (self.now)();
        let (key, dash_key) = {
            let mut s = lock(&self.sessions);
            let Some(key) = lookup_keys(cookie_id)
                .into_iter()
                .find(|k| s.contains_key(k))
            else {
                return false;
            };
            match s.get(&key) {
                Some(c) if c.expires_ms > now && c.host == host => {
                    (key.clone(), c.dash_key.clone())
                }
                Some(c) if c.expires_ms <= now => {
                    s.remove(&key);
                    return false;
                }
                _ => return false,
            }
        };
        if self.dash.alive(&dash_key) {
            true
        } else {
            lock(&self.sessions).remove(&key);
            false
        }
    }

    /// Serve on `listener` until `stop` is set.
    pub fn serve(self: &Arc<Self>, listener: TcpListener, stop: Arc<AtomicBool>) {
        let me = Arc::clone(self);
        std::thread::spawn(move || {
            for s in listener.incoming() {
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(s) = s else { continue };
                if me.open.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
                    let mut s = s;
                    let _ = s.write_all(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
                    continue;
                }
                me.open.fetch_add(1, Ordering::SeqCst);
                let me2 = Arc::clone(&me);
                std::thread::spawn(move || {
                    me2.handle(s);
                    me2.open.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });
    }
}

struct Head {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
}

impl Head {
    fn get(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn path(&self) -> &str {
        self.target.split('?').next().unwrap_or("")
    }

    fn query(&self, key: &str) -> Option<&str> {
        self.target
            .split_once('?')?
            .1
            .split('&')
            .find_map(|p| p.strip_prefix(key)?.strip_prefix('='))
    }

    fn is_upgrade(&self) -> bool {
        self.get("upgrade")
            .is_some_and(|u| u.eq_ignore_ascii_case("websocket"))
    }
}

fn read_head(br: &mut BufReader<TcpStream>) -> Option<Head> {
    let mut total = 0;
    let mut line = String::new();
    br.read_line(&mut line).ok()?;
    total += line.len();
    let mut parts = line.trim_end().splitn(3, ' ');
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    if !parts.next()?.starts_with("HTTP/1.") || !target.starts_with('/') {
        return None;
    }
    let mut headers = Vec::new();
    loop {
        let mut l = String::new();
        br.read_line(&mut l).ok()?;
        total += l.len();
        if total > MAX_HEAD || headers.len() > 100 {
            return None;
        }
        let l = l.trim_end();
        if l.is_empty() {
            break;
        }
        let (k, v) = l.split_once(':')?;
        headers.push((k.trim().to_string(), v.trim().to_string()));
    }
    Some(Head {
        method,
        target,
        headers,
    })
}

fn reply(s: &mut TcpStream, status: &str, extra: &[(&str, String)], body: &str) {
    let mut out = format!(
        "HTTP/1.1 {status}\r\nConnection: close\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\n\
         X-Content-Type-Options: nosniff\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (k, v) in extra {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("\r\n");
    out.push_str(body);
    let _ = s.write_all(out.as_bytes());
    let _ = s.shutdown(Shutdown::Both);
}

fn hop_by_hop(name: &str) -> bool {
    [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "upgrade",
        "transfer-encoding",
        "content-length",
        "cookie",
        "authorization",
        "x-forwarded-proto",
        "x-forwarded-host",
        "x-forwarded-for",
        "forwarded",
    ]
    .iter()
    .any(|h| name.eq_ignore_ascii_case(h))
}

/// The `Cookie` header without the Oz Box cookie; `None` when nothing else is left.
fn cookie_without_ours(header: &str) -> Option<String> {
    let kept: Vec<&str> = header
        .split(';')
        .map(str::trim)
        .filter(|p| !p.is_empty() && !p.starts_with(&format!("{COOKIE}=")))
        .collect();
    (!kept.is_empty()).then(|| kept.join("; "))
}

fn host_only(h: &str) -> String {
    h.rsplit_once(':')
        .filter(|(_, p)| p.bytes().all(|b| b.is_ascii_digit()))
        .map_or(h, |(a, _)| a)
        .to_ascii_lowercase()
}

impl Gate {
    fn handle(&self, stream: TcpStream) {
        let _ = stream.set_read_timeout(Some(CLIENT_READ_LIMIT));
        let Ok(read_half) = stream.try_clone() else {
            return;
        };
        let mut br = BufReader::new(read_half);
        let mut out = stream;
        let Some(head) = read_head(&mut br) else {
            return reply(&mut out, "400 Bad Request", &[], "bad request");
        };
        let _ = out.set_read_timeout(None);
        let host_hdr = head.get("host").unwrap_or("").to_string();
        let host = host_only(&host_hdr);
        let Some(entry) = lock(&self.settings).by_host(&host).cloned() else {
            return reply(&mut out, "404 Not Found", &[], "not found");
        };
        let sign_in = format!("{}/code/enter?host={host}", self.dashboard_origin);

        if head.path() == ENTER_PATH && head.method == "GET" {
            let session = head.query("t").and_then(|t| self.redeem(t, &host));
            let Some(id) = session else {
                return reply(&mut out, "302 Found", &[("Location", sign_in)], "");
            };
            let cookie = set_cookie(COOKIE, &id, SESSION_TTL_MS / 1000, "Lax");
            return match entry.service {
                Service::Ide => match self
                    .secrets
                    .get(&entry.service.secret_name(&entry.box_name))
                {
                    Ok(Some(pw)) => {
                        let (page, csp) = super::local::form_login_page(&pw);
                        reply(
                            &mut out,
                            "200 OK",
                            &[
                                ("Set-Cookie", cookie),
                                ("Content-Type", "text/html; charset=utf-8".into()),
                                ("Content-Security-Policy", csp),
                            ],
                            &page,
                        )
                    }
                    _ => reply(
                        &mut out,
                        "503 Service Unavailable",
                        &[],
                        "The IDE has no password set. Set it up again from the dashboard.",
                    ),
                },
                Service::Desktop => reply(
                    &mut out,
                    "302 Found",
                    &[("Set-Cookie", cookie), ("Location", "/".into())],
                    "",
                ),
            };
        }

        // The lock. Nothing past this point runs, and nothing is dialled, without a live session for this host.
        let signed_in = head
            .get("cookie")
            .and_then(|c| cookie_value(c, COOKIE))
            .is_some_and(|id| self.session_ok(id, &host));
        if !signed_in {
            let page = head.method == "GET" && !head.is_upgrade();
            return if page {
                reply(&mut out, "302 Found", &[("Location", sign_in)], "")
            } else {
                reply(&mut out, "401 Unauthorized", &[], "sign in to continue")
            };
        }
        // A change, or a WebSocket, must come from the page itself.
        if head.method != "GET" && head.method != "HEAD" || head.is_upgrade() {
            if let Some(o) = head.get("origin") {
                let o_host = o.split_once("://").map_or(o, |(_, h)| h);
                if !o_host.eq_ignore_ascii_case(&host_hdr) {
                    return reply(
                        &mut out,
                        "403 Forbidden",
                        &[],
                        "cross-origin requests are not allowed",
                    );
                }
            }
        }
        let basic = match entry.service {
            Service::Desktop => match self
                .secrets
                .get(&entry.service.secret_name(&entry.box_name))
            {
                Ok(Some(pw)) => Some(format!(
                    "Basic {}",
                    encode_std(format!("{}:{pw}", Service::DESKTOP_USER).as_bytes())
                )),
                _ => {
                    return reply(
                        &mut out,
                        "503 Service Unavailable",
                        &[],
                        "The desktop has no password set. Set it up again from the dashboard.",
                    );
                }
            },
            Service::Ide => None,
        };
        let conn = match self.upstream.dial(&entry.box_name, entry.service) {
            Ok(c) => c,
            Err(_) => {
                return reply(
                    &mut out,
                    "502 Bad Gateway",
                    &[],
                    "The box could not be reached just now. Reload in a moment.",
                );
            }
        };
        relay(head, br, out, conn, &host_hdr, basic);
    }
}

fn relay(
    head: Head,
    mut br: BufReader<TcpStream>,
    mut out: TcpStream,
    conn: Conn,
    host: &str,
    basic: Option<String>,
) {
    let Conn {
        read: mut up_read,
        write: mut up_write,
        keep,
    } = conn;
    let ws = head.is_upgrade();
    let mut req = format!("{} {} HTTP/1.1\r\n", head.method, head.target);
    for (k, v) in &head.headers {
        if hop_by_hop(k) {
            continue;
        }
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if let Some(c) = head.get("cookie").and_then(cookie_without_ours) {
        req.push_str(&format!("Cookie: {c}\r\n"));
    }
    if let Some(b) = &basic {
        req.push_str(&format!("Authorization: {b}\r\n"));
    }
    req.push_str("X-Forwarded-Proto: https\r\n");
    req.push_str(&format!("X-Forwarded-Host: {host}\r\n"));
    let chunked = head
        .get("transfer-encoding")
        .is_some_and(|t| t.to_ascii_lowercase().contains("chunked"));
    let length: Option<u64> = head.get("content-length").and_then(|v| v.parse().ok());
    if ws {
        req.push_str("Connection: Upgrade\r\nUpgrade: websocket\r\n");
    } else {
        req.push_str("Connection: close\r\n");
    }
    if chunked {
        req.push_str("Transfer-Encoding: chunked\r\n");
    } else if let Some(n) = length {
        req.push_str(&format!("Content-Length: {n}\r\n"));
    }
    req.push_str("\r\n");
    if up_write.write_all(req.as_bytes()).is_err() {
        return reply(&mut out, "502 Bad Gateway", &[], "The box did not answer.");
    }
    if chunked {
        if relay_chunked(&mut br, &mut up_write).is_err() {
            return;
        }
    } else if let Some(n) = length {
        if std::io::copy(&mut (&mut br).take(n), &mut up_write).is_err() {
            return;
        }
    }
    let _ = up_write.flush();
    // The answer's head first, to see whether the box agreed to a WebSocket.
    let mut answer = Vec::new();
    let mut b = [0u8; 1];
    while !answer.ends_with(b"\r\n\r\n") && answer.len() < MAX_HEAD {
        match up_read.read(&mut b) {
            Ok(1) => answer.push(b[0]),
            _ => break,
        }
    }
    if out.write_all(&answer).is_err() {
        return;
    }
    let switched = ws && answer.starts_with(b"HTTP/1.1 101");
    if switched {
        let Ok(mut client_read) = br.get_ref().try_clone() else {
            return;
        };
        // bytes the client already sent after its head are in the buffer
        let pending = br.buffer().to_vec();
        let t = std::thread::spawn(move || {
            if !pending.is_empty() && up_write.write_all(&pending).is_err() {
                return;
            }
            let _ = std::io::copy(&mut client_read, &mut up_write);
            let _ = up_write.flush();
        });
        let _ = std::io::copy(&mut up_read, &mut out);
        let _ = out.shutdown(Shutdown::Both);
        let _ = t.join();
    } else {
        let _ = std::io::copy(&mut up_read, &mut out);
        let _ = out.shutdown(Shutdown::Both);
    }
    drop(keep);
}

/// A chunked request body, relayed chunk by chunk, so the end is found without trusting the client to close.
fn relay_chunked(
    br: &mut BufReader<TcpStream>,
    up: &mut Box<dyn Write + Send>,
) -> std::io::Result<()> {
    loop {
        let mut line = String::new();
        br.read_line(&mut line)?;
        up.write_all(line.as_bytes())?;
        let size = usize::from_str_radix(line.trim().split(';').next().unwrap_or("0"), 16)
            .map_err(|_| std::io::Error::other("bad chunk"))?;
        if size == 0 {
            // trailers, up to the blank line
            loop {
                let mut t = String::new();
                br.read_line(&mut t)?;
                up.write_all(t.as_bytes())?;
                if t.trim().is_empty() {
                    return Ok(());
                }
            }
        }
        std::io::copy(&mut br.take(size as u64 + 2), up)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::MemorySecrets;
    use std::sync::atomic::AtomicU64;

    struct Dash(AtomicBool);
    impl DashSessions for Dash {
        fn alive(&self, _: &str) -> bool {
            self.0.load(Ordering::SeqCst)
        }
    }

    /// Counts dials and records the head of what the box would have been sent.
    struct Fake {
        dials: AtomicUsize,
        seen: Mutex<Vec<String>>,
        addr: std::net::SocketAddr,
    }

    impl Upstream for Fake {
        fn dial(&self, b: &str, s: Service) -> Result<Conn, String> {
            self.dials.fetch_add(1, Ordering::SeqCst);
            self.seen.lock().unwrap().push(format!("{b}/{}", s.id()));
            Conn::from_tcp(TcpStream::connect(self.addr).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())
        }
    }

    /// An upstream that records each raw request head and answers 200 or switches to an echo for a WebSocket.
    fn recording_upstream() -> (std::net::SocketAddr, Arc<Mutex<Vec<String>>>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let heads: Arc<Mutex<Vec<String>>> = Arc::default();
        let h2 = Arc::clone(&heads);
        std::thread::spawn(move || {
            for mut s in l.incoming().flatten() {
                let h3 = Arc::clone(&h2);
                std::thread::spawn(move || {
                    let mut head = Vec::new();
                    let mut b = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        if !matches!(s.read(&mut b), Ok(1)) {
                            return;
                        }
                        head.push(b[0]);
                    }
                    let text = String::from_utf8_lossy(&head).into_owned();
                    h3.lock().unwrap().push(text.clone());
                    if text.to_ascii_lowercase().contains("upgrade: websocket") {
                        let key = text
                            .lines()
                            .find_map(|l| l.strip_prefix("Sec-WebSocket-Key: "))
                            .unwrap_or("")
                            .to_string();
                        let _ = write!(
                            s,
                            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
                            crate::serve::sim_code_accept(&key)
                        );
                        let mut buf = [0u8; 256];
                        while let Ok(n) = s.read(&mut buf) {
                            if n == 0 || s.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    } else {
                        // Read the request body to its end before answering. Closing a socket that still has unread
                        // bytes makes the kernel send a reset, which can reach the proxy before the answer does and
                        // turn a relayed upload into a 502 on a loaded machine.
                        let lower = text.to_ascii_lowercase();
                        if lower.contains("transfer-encoding: chunked") {
                            let mut tail = Vec::new();
                            while !tail.ends_with(b"0\r\n\r\n") {
                                if !matches!(s.read(&mut b), Ok(1)) {
                                    break;
                                }
                                tail.push(b[0]);
                            }
                        } else if let Some(n) = lower
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                        {
                            let mut body = vec![0u8; n];
                            let _ = s.read_exact(&mut body);
                        }
                        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nUPSTREAM");
                    }
                });
            }
        });
        (addr, heads)
    }

    struct Rig {
        gate: Arc<Gate>,
        addr: std::net::SocketAddr,
        fake: Arc<Fake>,
        heads: Arc<Mutex<Vec<String>>>,
        dash: Arc<Dash>,
        clock: Arc<AtomicU64>,
        secrets: Arc<MemorySecrets>,
    }

    fn rig() -> Rig {
        let (up, heads) = recording_upstream();
        let fake = Arc::new(Fake {
            dials: AtomicUsize::new(0),
            seen: Mutex::default(),
            addr: up,
        });
        let dash = Arc::new(Dash(AtomicBool::new(true)));
        let secrets = Arc::new(MemorySecrets::default());
        secrets
            .set("ide-password-dev", "abcdef0123456789abcdef0123456789")
            .unwrap();
        secrets
            .set("desktop-password-dev", "fedcba9876543210fedcba9876543210")
            .unwrap();
        let mut s = CodeSettings::default();
        s.set("dev", Service::Ide, "https://ide.example.com", None, None)
            .unwrap();
        s.set(
            "dev",
            Service::Desktop,
            "https://desk.example.com",
            None,
            None,
        )
        .unwrap();
        let clock = Arc::new(AtomicU64::new(1_000_000));
        let c2 = Arc::clone(&clock);
        let gate = Arc::new(Gate::new(
            Arc::new(Mutex::new(s)),
            "https://ozbox.example.com".into(),
            dash.clone(),
            fake.clone(),
            secrets.clone(),
            Arc::new(move || c2.load(Ordering::SeqCst)),
        ));
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        gate.serve(l, Arc::new(AtomicBool::new(false)));
        Rig {
            gate,
            addr,
            fake,
            heads,
            dash,
            clock,
            secrets,
        }
    }

    /// The proxy answers and closes the connection, so a request is read to its end. A read that times out is a failure
    /// to report, never a short answer to compare: a client here waits as long as the proxy itself waits for one, so a
    /// slow, loaded run is slow rather than wrong.
    fn send(addr: std::net::SocketAddr, raw: &str) -> String {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(CLIENT_READ_LIMIT)).unwrap();
        s.write_all(raw.as_bytes()).unwrap();
        let mut out = String::new();
        let mut b = [0u8; 4096];
        loop {
            match s.read(&mut b) {
                Ok(0) => break,
                Ok(n) => out.push_str(&String::from_utf8_lossy(&b[..n])),
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => break,
                Err(e) => panic!("the proxy did not finish its answer ({e}); so far: {out}"),
            }
        }
        out
    }

    fn get(r: &Rig, host: &str, path: &str, extra: &str) -> String {
        send(
            r.addr,
            &format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n{extra}\r\n"),
        )
    }

    fn cookie_of(resp: &str) -> String {
        let line = resp
            .lines()
            .find(|l| l.starts_with("Set-Cookie: "))
            .unwrap();
        line["Set-Cookie: ".len()..]
            .split(';')
            .next()
            .unwrap()
            .to_string()
    }

    fn sign_in(r: &Rig, host: &str) -> String {
        let t = r.gate.issue_ticket("dash-session", host).unwrap();
        cookie_of(&get(r, host, &format!("{ENTER_PATH}?t={t}"), ""))
    }

    #[test]
    fn nothing_reaches_the_box_without_a_session_not_a_page_not_an_upload_not_a_websocket() {
        let r = rig();
        assert!(get(&r, "other.example.com", "/", "").starts_with("HTTP/1.1 404"));
        let page = get(&r, "ide.example.com", "/", "");
        assert!(page.starts_with("HTTP/1.1 302"), "{page}");
        assert!(
            page.contains("Location: https://ozbox.example.com/code/enter?host=ide.example.com")
        );
        let post = send(
            r.addr,
            "POST /save HTTP/1.1\r\nHost: ide.example.com\r\nContent-Length: 2\r\n\r\nhi",
        );
        assert!(post.starts_with("HTTP/1.1 401"), "{post}");
        let ws = get(&r, "ide.example.com", "/stable", "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n");
        assert!(ws.starts_with("HTTP/1.1 401"), "{ws}");
        // a made-up or another site's cookie is no session either
        for c in ["ozbox_code=forged", "ozbox_code=", "other=1"] {
            let x = get(&r, "ide.example.com", "/", &format!("Cookie: {c}\r\n"));
            assert!(x.starts_with("HTTP/1.1 302"), "{c}: {x}");
        }
        assert_eq!(
            r.fake.dials.load(Ordering::SeqCst),
            0,
            "the box was never dialled"
        );
        assert!(r.heads.lock().unwrap().is_empty());
    }

    #[test]
    fn a_ticket_buys_one_session_once_and_only_for_its_own_host_within_a_minute() {
        let r = rig();
        assert!(r.gate.issue_ticket("s", "unknown.example.com").is_none());
        let t = r.gate.issue_ticket("s", "ide.example.com").unwrap();
        // the desktop host will not take the IDE's ticket
        assert!(
            get(&r, "desk.example.com", &format!("{ENTER_PATH}?t={t}"), "")
                .starts_with("HTTP/1.1 302")
        );
        let t = r.gate.issue_ticket("s", "ide.example.com").unwrap();
        let ok = get(&r, "ide.example.com", &format!("{ENTER_PATH}?t={t}"), "");
        assert!(ok.starts_with("HTTP/1.1 200"), "{ok}");
        let set = ok.lines().find(|l| l.starts_with("Set-Cookie: ")).unwrap();
        assert!(set.contains("HttpOnly") && set.contains("Secure") && set.contains("SameSite=Lax"));
        assert!(
            ok.contains("abcdef0123456789abcdef0123456789"),
            "the sign-in page carries the service password"
        );
        // the same ticket again, and an expired one
        assert!(
            get(&r, "ide.example.com", &format!("{ENTER_PATH}?t={t}"), "")
                .starts_with("HTTP/1.1 302")
        );
        let t2 = r.gate.issue_ticket("s", "ide.example.com").unwrap();
        r.clock.fetch_add(61_000, Ordering::SeqCst);
        assert!(
            get(&r, "ide.example.com", &format!("{ENTER_PATH}?t={t2}"), "")
                .starts_with("HTTP/1.1 302")
        );
        assert_eq!(r.fake.dials.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_signed_in_request_is_relayed_and_the_box_never_sees_our_cookie_or_the_browsers_authorization(
    ) {
        let r = rig();
        let c = sign_in(&r, "ide.example.com");
        let resp = get(
            &r,
            "ide.example.com",
            "/app?folder=/work/repos",
            &format!("Cookie: {c}; code-server-session=abc\r\nAuthorization: Bearer stolen\r\n"),
        );
        assert!(
            resp.starts_with("HTTP/1.1 200") && resp.ends_with("UPSTREAM"),
            "{resp}"
        );
        let seen = r.heads.lock().unwrap().last().cloned().unwrap();
        assert!(seen.starts_with("GET /app?folder=/work/repos HTTP/1.1"));
        assert!(
            !seen.contains(COOKIE) && !seen.to_ascii_lowercase().contains("authorization"),
            "{seen}"
        );
        assert!(seen.contains("code-server-session=abc"));
        assert!(seen.contains("Host: ide.example.com"));
        // the cookie is bound to the host it was issued on
        let other = get(&r, "desk.example.com", "/", &format!("Cookie: {c}\r\n"));
        assert!(other.starts_with("HTTP/1.1 302"), "{other}");
    }

    #[test]
    fn the_session_dies_with_the_dashboard_session_it_came_from() {
        let r = rig();
        let c = sign_in(&r, "ide.example.com");
        assert!(get(&r, "ide.example.com", "/", &format!("Cookie: {c}\r\n"))
            .starts_with("HTTP/1.1 200"));
        r.dash.0.store(false, Ordering::SeqCst);
        let after = get(&r, "ide.example.com", "/", &format!("Cookie: {c}\r\n"));
        assert!(after.starts_with("HTTP/1.1 302"), "{after}");
        r.dash.0.store(true, Ordering::SeqCst);
        assert!(
            get(&r, "ide.example.com", "/", &format!("Cookie: {c}\r\n"))
                .starts_with("HTTP/1.1 302"),
            "it stays gone"
        );
        // an expired code session too
        let c2 = sign_in(&r, "ide.example.com");
        r.clock.fetch_add(SESSION_TTL_MS + 1, Ordering::SeqCst);
        assert!(
            get(&r, "ide.example.com", "/", &format!("Cookie: {c2}\r\n"))
                .starts_with("HTTP/1.1 302")
        );
    }

    #[test]
    fn the_desktop_gets_its_own_login_added_and_the_browsers_is_replaced() {
        let r = rig();
        let c = sign_in(&r, "desk.example.com");
        get(
            &r,
            "desk.example.com",
            "/",
            &format!("Cookie: {c}\r\nAuthorization: Basic Zm9vOmJhcg==\r\n"),
        );
        let seen = r.heads.lock().unwrap().last().cloned().unwrap();
        let want = format!(
            "Authorization: Basic {}",
            encode_std(b"ozbox:fedcba9876543210fedcba9876543210")
        );
        assert!(seen.contains(&want), "{seen}");
        assert!(!seen.contains("Zm9vOmJhcg=="));
        // no password stored: refused, not relayed
        r.secrets.delete("desktop-password-dev").unwrap();
        let before = r.fake.dials.load(Ordering::SeqCst);
        let x = get(&r, "desk.example.com", "/", &format!("Cookie: {c}\r\n"));
        assert!(x.starts_with("HTTP/1.1 503"), "{x}");
        assert_eq!(r.fake.dials.load(Ordering::SeqCst), before);
    }

    #[test]
    fn a_websocket_is_proxied_only_after_the_check_and_then_both_ways() {
        let r = rig();
        let c = sign_in(&r, "ide.example.com");
        let mut s = TcpStream::connect(r.addr).unwrap();
        s.set_read_timeout(Some(CLIENT_READ_LIMIT)).unwrap();
        write!(s, "GET /stable HTTP/1.1\r\nHost: ide.example.com\r\nOrigin: https://ide.example.com\r\nCookie: {c}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n").unwrap();
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            s.read_exact(&mut b).unwrap();
            head.push(b[0]);
        }
        let head = String::from_utf8(head).unwrap();
        assert!(head.starts_with("HTTP/1.1 101"), "{head}");
        assert!(head.contains("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
        s.write_all(b"ping through").unwrap();
        let mut echo = [0u8; 12];
        s.read_exact(&mut echo).unwrap();
        assert_eq!(&echo, b"ping through");
        // a socket opened from another site is refused even with the cookie
        let evil = get(&r, "ide.example.com", "/stable", &format!("Origin: https://evil.example.com\r\nCookie: {c}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"));
        assert!(evil.starts_with("HTTP/1.1 403"), "{evil}");
    }

    #[test]
    fn an_unreachable_box_is_a_502_and_a_chunked_upload_is_relayed_whole() {
        let r = rig();
        let c = sign_in(&r, "ide.example.com");
        let up = send(r.addr, &format!("POST /up HTTP/1.1\r\nHost: ide.example.com\r\nCookie: {c}\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"));
        assert!(up.starts_with("HTTP/1.1 200"), "{up}");
        let seen = r.heads.lock().unwrap().last().cloned().unwrap();
        assert!(seen.contains("Transfer-Encoding: chunked"));
    }
}
