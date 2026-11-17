//! The worker channel on a network: workers **dial out** to the hub; the transport carries sealed envelopes and nothing else
//! (ADR 0042 sections 2 and 3, ADR 0005).
//!
//! * **Who connects.** A worker connects to the hub's address on its tailnet or private network ([`NetWorker::start`]); nothing
//!   on a worker listens. The hub listens on one address that is **loopback or private** ([`bind_allowed`]): never a wildcard and
//!   never a public address. The route that brings a worker's connection there is the one the fleet already has (the tailnet's
//!   forward to a loopback port, as ADR 0030 does for SSH, or the private network's one rule from the workers' group, ADR 0042
//!   section 3), so the transport adds no inbound rule of its own.
//! * **What it proves.** Each connection starts with a handshake under its own domain tag (`ozbox-hub-handshake-v1`): the worker
//!   proves its roster key first (the hub spends one check on a peer that says a roster name, and nothing on one that does not),
//!   then the hub proves its pinned key. Each side signs both random nonces, both names and the numbers it resumes from, so a
//!   handshake cannot be replayed or moved to another pair. A connection that fails it is closed and counted, per source.
//! * **What it carries.** Frames of sealed envelopes ([`frame`]). The transport never opens, signs or reads a body; it checks
//!   only what it can without a key (the envelope names the proved peer and this end, is well formed and still valid, and was not
//!   passed on before) and leaves the guarantee to the channel, which checks all of it again end to end.
//! * **Order, loss and replay** at this layer are [`link`]'s: a window of 64 frames, retransmission after a timeout and after a
//!   reconnect, duplicates dropped by number, an envelope passed on once refused by its id and nonce while it is valid.
//! * **Back-pressure.** A link holds at most [`link::OUTBOX_FRAMES`] frames and [`link::OUTBOX_BYTES`] for a peer that is not
//!   taking them; past that `send` refuses, and the channel's outbox keeps the message for its next round. A receiver whose owner
//!   has not taken [`link::INBOX_FRAMES`] envelopes stops reading the connection, so the sender's link fills in turn.
//! * **Honest reachability.** [`Reach`] per peer: never connected, connected since a time, or not answering since a time. A
//!   connection that hears nothing for three heartbeats (90 seconds) is closed and the peer shown as not answering.
//! * **Reconnect.** A worker reconnects with backoff from 1 to 30 seconds, with jitter, and resumes from what the hub says it has.
//!
//! Light dependencies (ADR 0008): standard library threads and sockets only, no async runtime. The threads poll with short read
//! timeouts, so one worker costs the hub one thread.

pub mod frame;
pub mod link;

use std::collections::{BTreeMap, VecDeque};
use std::io::{ErrorKind, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

use self::frame::{
    encode, Frame, FrameError, FrameReader, MAX_FRAME, MAX_HANDSHAKE_FRAME, T_ACCEPT, T_CHALLENGE,
    T_HELLO, T_PROOF,
};
pub use self::link::Reach;
use self::link::{LinkState, Resume, Stats, INBOX_FRAMES};
use super::engine::RosterEntry;
use super::wire::{Transport, WireError};
use crate::approval_subject::{from_hex, to_hex, Encoder};
use crate::channel::wire::{word_ok, Sealed, Signer, Verifier};

/// The handshake's domain tag. A handshake signature is never an envelope's, and the reverse.
pub const HANDSHAKE_TAG: &str = "ozbox-hub-handshake-v1";

/// The handshake's own version.
pub const HANDSHAKE_VERSION: u64 = 1;

/// A heartbeat is sent after this long with nothing written, and a connection that hears nothing for three is closed.
pub const HEARTBEAT_MS: u64 = 30_000;
pub const SILENT_MS: u64 = 3 * HEARTBEAT_MS;

/// How long a peer has to complete the handshake.
pub const HANDSHAKE_MS: u64 = 10_000;

/// A worker's reconnect backoff.
pub const BACKOFF_MIN_MS: u64 = 1_000;
pub const BACKOFF_MAX_MS: u64 = 30_000;

/// How many handshakes one source address may fail in a minute before the hub stops answering it for the rest of the minute.
pub const FAILS_PER_MINUTE: u32 = 20;

/// How many connections the hub holds at once, authenticated or not.
pub const MAX_CONNECTIONS: usize = 256;

/// How long a write may block before the connection is taken as dead.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long one read waits, so a connection's loop also writes, acknowledges and checks for stop.
const POLL: Duration = Duration::from_millis(20);
/// How long a connection's reader waits for a frame before it checks for stop, silence and replacement.
const READ_TICK: Duration = Duration::from_millis(200);
/// The longest a connection's writer sleeps without a wake-up (retransmissions fall due on this tick or sooner).
const WRITER_TICK_MS: u64 = 200;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn random_u64() -> u64 {
    let mut b = [0u8; 8];
    loop {
        if SystemRandom::new().fill(&mut b).is_ok() {
            let n = u64::from_be_bytes(b);
            if n != 0 {
                return n;
            }
        }
    }
}

fn nonce() -> [u8; 16] {
    let mut b = [0u8; 16];
    while SystemRandom::new().fill(&mut b).is_err() {}
    b
}

// ---- the address rule ---------------------------------------------------------------------------------------------

/// Whether the hub may listen on this address: loopback, or a private range (RFC 1918, the shared range 100.64.0.0/10 a tailnet
/// uses, IPv6 unique-local fc00::/7). Never the wildcard and never a public address, so a mistake in a setting cannot open the
/// hub to the internet (ADR 0005; the one rule of ADR 0042 section 3).
pub fn bind_allowed(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            v.is_loopback()
                || o[0] == 10
                || (o[0] == 172 && (16..=31).contains(&o[1]))
                || (o[0] == 192 && o[1] == 168)
                || (o[0] == 100 && (64..=127).contains(&o[1]))
        }
        IpAddr::V6(v) => v.is_loopback() || (v.segments()[0] & 0xfe00) == 0xfc00,
    }
}

// ---- the handshake ------------------------------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Hello {
    v: u64,
    hub: String,
    worker: String,
    nonce: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Challenge {
    nonce: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Proof {
    resume: Resume,
    sig: String,
}

/// The bytes one side signs: the role, both names, both nonces, and the numbers both sides resume from (the hub's are absent from
/// the worker's proof, which comes first, and so are zero there).
fn handshake_bytes(
    role: &str,
    hub: &str,
    worker: &str,
    wn: &[u8],
    hn: &[u8],
    worker_resume: &Resume,
    hub_resume: Option<&Resume>,
) -> Vec<u8> {
    let mut e = Encoder::new(HANDSHAKE_TAG);
    e.u64(HANDSHAKE_VERSION)
        .text(role)
        .text(hub)
        .text(worker)
        .field(wn)
        .field(hn);
    for r in [Some(worker_resume), hub_resume] {
        let r = r.copied().unwrap_or(Resume {
            tx_session: 0,
            tx_base: 0,
            rx_session: 0,
            rx_upto: 0,
        });
        e.u64(r.tx_session)
            .u64(r.tx_base)
            .u64(r.rx_session)
            .u64(r.rx_upto);
    }
    e.bytes().to_vec()
}

fn send_frame(s: &mut TcpStream, f: &Frame) -> Result<(), FrameError> {
    s.write_all(&encode(f)).map_err(|_| FrameError::Io)
}

fn send_json<T: Serialize>(s: &mut TcpStream, t: u8, v: &T) -> Result<(), FrameError> {
    let p = serde_json::to_vec(v).map_err(|_| FrameError::Malformed)?;
    send_frame(s, &Frame::Handshake(t, p))
}

/// Wait for one handshake frame of type `want`, until the deadline.
fn read_handshake<T: for<'de> Deserialize<'de>>(
    s: &mut TcpStream,
    rd: &mut FrameReader,
    want: u8,
    deadline_ms: u64,
) -> Result<T, FrameError> {
    loop {
        if now_ms() > deadline_ms {
            return Err(FrameError::Closed);
        }
        match rd.next(s, MAX_HANDSHAKE_FRAME)? {
            None => continue,
            Some(Frame::Handshake(t, p)) if t == want => {
                return serde_json::from_slice(&p).map_err(|_| FrameError::Malformed)
            }
            Some(_) => return Err(FrameError::Malformed),
        }
    }
}

fn hex16(s: &str) -> Option<Vec<u8>> {
    from_hex(s).filter(|b| b.len() == 16)
}

// ---- the shared part of both ends ---------------------------------------------------------------------------------

struct Inner {
    me: String,
    links: BTreeMap<String, LinkState>,
    inbox: VecDeque<Sealed>,
    /// Handshake failures per source address, in the current minute.
    fails: BTreeMap<IpAddr, (u64, u32)>,
    open: usize,
}

struct Shared {
    inner: Mutex<Inner>,
    /// Wakes a connection's writer: something was queued, an acknowledgement is owed, or the end is stopping.
    cv: Condvar,
    /// The workers this hub end admits and the keys their enrolment attested (empty on a worker). It grows as workers enrol.
    roster: std::sync::RwLock<BTreeMap<String, RosterEntry>>,
    stop: AtomicBool,
}

impl Shared {
    fn new(me: &str) -> Arc<Shared> {
        Arc::new(Shared {
            inner: Mutex::new(Inner {
                me: me.to_string(),
                links: BTreeMap::new(),
                inbox: VecDeque::new(),
                fails: BTreeMap::new(),
                open: 0,
            }),
            cv: Condvar::new(),
            roster: std::sync::RwLock::new(BTreeMap::new()),
            stop: AtomicBool::new(false),
        })
    }

    fn stopped(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    fn send(&self, to: &str, msg: Sealed) -> Result<(), WireError> {
        let mut g = self.inner.lock().map_err(|_| WireError::SendFailed)?;
        // a fabric endpoint (`<box>.fabric`) is carried on the connection of the box it names
        let peer = to.strip_suffix(".fabric").unwrap_or(to);
        let link = g.links.get_mut(peer).ok_or(WireError::SendFailed)?;
        link.queue(&msg, now_ms())
            .map_err(|_| WireError::SendFailed)?;
        drop(g);
        self.cv.notify_all();
        Ok(())
    }

    fn recv(&self, who: &str) -> Option<Sealed> {
        let mut g = self.inner.lock().ok()?;
        // the worker channel's endpoint is this end's name, the fabric's is `<name>.fabric`; each takes only its own
        if g.me != who && who.strip_suffix(".fabric") != Some(g.me.as_str()) {
            return None;
        }
        let at = g.inbox.iter().position(|m| m.envelope.to == who)?;
        g.inbox.remove(at)
    }

    fn reach(&self, peer: &str) -> Option<Reach> {
        self.inner
            .lock()
            .ok()?
            .links
            .get(peer)
            .map(LinkState::reach)
    }

    fn stats(&self, peer: &str) -> Option<Stats> {
        self.inner
            .lock()
            .ok()?
            .links
            .get(peer)
            .map(|l| l.stats.clone())
    }

    /// Run one authenticated connection until it fails, goes silent, is replaced or the end stops. A reader takes frames as they
    /// arrive; a writer sleeps until there is something to write (a `send`, an acknowledgement owed, a retransmission or a
    /// heartbeat falling due), so a message goes out as soon as it is queued, not at the next tick.
    fn run(&self, s: TcpStream, rd: FrameReader, peer: &str, gen: u64) -> FrameError {
        // small frames (an acknowledgement, a status) go out at once rather than waiting for the peer's delayed acknowledgement
        let _ = s.set_nodelay(true);
        let _ = s.set_read_timeout(Some(READ_TICK));
        let _ = s.set_write_timeout(Some(WRITE_TIMEOUT));
        let Ok(ws) = s.try_clone() else {
            return self.lost(peer, gen, FrameError::Io);
        };
        let done = AtomicBool::new(false);
        let why = std::thread::scope(|sc| {
            let writer = sc.spawn(|| self.writer(ws, peer, gen, &done));
            let why = self.reader(&s, rd, peer, gen, &done);
            done.store(true, Ordering::SeqCst);
            self.cv.notify_all();
            let _ = s.shutdown(std::net::Shutdown::Both);
            let _ = writer.join();
            why
        });
        self.lost(peer, gen, why)
    }

    fn reader(
        &self,
        s: &TcpStream,
        mut rd: FrameReader,
        peer: &str,
        gen: u64,
        done: &AtomicBool,
    ) -> FrameError {
        let mut s = s;
        loop {
            if self.stopped() || done.load(Ordering::SeqCst) {
                return FrameError::Closed;
            }
            let now = now_ms();
            let room = {
                let Ok(mut g) = self.inner.lock() else {
                    return FrameError::Io;
                };
                let room = g.inbox.len() < INBOX_FRAMES;
                let Some(l) = g.links.get_mut(peer) else {
                    return FrameError::Closed;
                };
                if l.gen != gen {
                    return FrameError::Closed;
                }
                // silence counts only while this end is reading: a full inbox is this end's back-pressure, not the peer's silence
                if room && l.last_heard().is_some_and(|h| now > h + SILENT_MS) {
                    return FrameError::Closed;
                }
                if !room {
                    l.heard(now);
                }
                room
            };
            if !room {
                // the owner has not taken what it was given: stop reading, so the peer's link fills and its `send` refuses
                std::thread::sleep(POLL);
                continue;
            }
            match rd.next(&mut s, MAX_FRAME) {
                Ok(None) => {}
                Ok(Some(f)) => {
                    let Ok(mut g) = self.inner.lock() else {
                        return FrameError::Io;
                    };
                    let Inner { links, inbox, .. } = &mut *g;
                    let Some(l) = links.get_mut(peer) else {
                        return FrameError::Closed;
                    };
                    l.heard(now);
                    match f {
                        Frame::Data(n, m) => l.on_data(n, *m, now, inbox),
                        Frame::Ack(n) => l.on_ack(n),
                        Frame::Ping => l.pong_owed = true,
                        Frame::Pong => {}
                        Frame::Handshake(..) => return FrameError::Malformed,
                    }
                    drop(g);
                    self.cv.notify_all();
                }
                Err(e) => return e,
            }
        }
    }

    fn writer(&self, mut s: TcpStream, peer: &str, gen: u64, done: &AtomicBool) {
        let mut last_write = now_ms();
        let Ok(mut g) = self.inner.lock() else {
            return;
        };
        loop {
            if self.stopped() || done.load(Ordering::SeqCst) {
                return;
            }
            let now = now_ms();
            let Some(l) = g.links.get_mut(peer) else {
                return;
            };
            if l.gen != gen {
                return;
            }
            let mut writes = Vec::new();
            if std::mem::take(&mut l.pong_owed) {
                writes.push(encode(&Frame::Pong));
            }
            if let Some(upto) = l.take_ack() {
                writes.push(encode(&Frame::Ack(upto)));
            }
            writes.extend(l.due(now));
            if writes.is_empty() && now >= last_write + HEARTBEAT_MS {
                writes.push(encode(&Frame::Ping));
            }
            if writes.is_empty() {
                let wait = Duration::from_millis(
                    (last_write + HEARTBEAT_MS)
                        .saturating_sub(now)
                        .clamp(1, WRITER_TICK_MS),
                );
                g = match self.cv.wait_timeout(g, wait) {
                    Ok((g, _)) => g,
                    Err(_) => return,
                };
                continue;
            }
            drop(g);
            for b in &writes {
                if s.write_all(b).is_err() {
                    done.store(true, Ordering::SeqCst);
                    let _ = s.shutdown(std::net::Shutdown::Both);
                    return;
                }
            }
            last_write = now;
            g = match self.inner.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
        }
    }

    fn lost(&self, peer: &str, gen: u64, why: FrameError) -> FrameError {
        if let Ok(mut g) = self.inner.lock() {
            if let Some(l) = g.links.get_mut(peer) {
                if l.gen == gen {
                    l.on_disconnected();
                }
            }
        }
        why
    }
}

// ---- the hub's end ------------------------------------------------------------------------------------------------

/// What the hub's end needs: its own name, the roster (the worker names and the keys their enrolment attested), the key the
/// handshake signs with and a verifier for the roster's keys.
pub struct HubNetConfig {
    /// The address to listen on: loopback or private only ([`bind_allowed`]).
    pub listen: SocketAddr,
    pub me: String,
    pub roster: BTreeMap<String, RosterEntry>,
    /// The handshake's signer (ADR 0042 section 1: `ozbox-hubd`'s one private operation, a handshake signature).
    pub signer: Arc<dyn Signer>,
    pub verifier: Arc<dyn Verifier>,
}

/// Why the hub's end could not start. Words, never a key or a body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetError {
    /// The address is a wildcard or a public address.
    AddressNotAllowed,
    /// A name is not a box name.
    BadName,
    /// The socket could not be made (in use, no permission).
    Bind,
}

impl std::fmt::Display for NetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetError::AddressNotAllowed => f.write_str(
                "the hub listens only on a loopback or private address, never on every address or a public one",
            ),
            NetError::BadName => f.write_str("a box name is not valid"),
            NetError::Bind => f.write_str("the hub's address could not be listened on"),
        }
    }
}

/// The hub's end: one listener, a thread per worker connection. A [`Transport`] for [`crate::hub::engine::Hub`].
pub struct NetHub {
    shared: Arc<Shared>,
    addr: SocketAddr,
    accept: Mutex<Option<JoinHandle<()>>>,
}

impl NetHub {
    /// Listen and accept workers. The roster is fixed for this value's life; a changed roster is a new `NetHub` (its links start
    /// new sessions, and each worker resumes from what this end says it has).
    pub fn start(cfg: HubNetConfig) -> Result<NetHub, NetError> {
        if !bind_allowed(cfg.listen.ip()) {
            return Err(NetError::AddressNotAllowed);
        }
        if !word_ok(&cfg.me) || !cfg.roster.keys().all(|w| word_ok(w)) {
            return Err(NetError::BadName);
        }
        let listener = TcpListener::bind(cfg.listen).map_err(|_| NetError::Bind)?;
        let addr = listener.local_addr().map_err(|_| NetError::Bind)?;
        listener.set_nonblocking(true).map_err(|_| NetError::Bind)?;
        let shared = Shared::new(&cfg.me);
        if let Ok(mut g) = shared.inner.lock() {
            for w in cfg.roster.keys() {
                g.links
                    .insert(w.clone(), LinkState::new(&cfg.me, w, random_u64()));
            }
        }
        if let Ok(mut r) = shared.roster.write() {
            *r = cfg.roster.clone();
        }
        let cfg = Arc::new(cfg);
        let sh = shared.clone();
        let accept = std::thread::spawn(move || accept_loop(listener, sh, cfg));
        Ok(NetHub {
            shared,
            addr,
            accept: Mutex::new(Some(accept)),
        })
    }

    /// Admit a worker that has just enrolled, or take a new key for one: no restart, and the links of the others are untouched.
    /// Refused for a name that is not a box name.
    pub fn enrol(&self, worker: &str, entry: RosterEntry) -> Result<(), NetError> {
        if !word_ok(worker) {
            return Err(NetError::BadName);
        }
        let me = self
            .shared
            .inner
            .lock()
            .map_err(|_| NetError::Bind)?
            .me
            .clone();
        let replaced = self
            .shared
            .roster
            .write()
            .map_err(|_| NetError::Bind)?
            .insert(worker.to_string(), entry.clone())
            .is_some_and(|old| old != entry);
        let mut g = self.shared.inner.lock().map_err(|_| NetError::Bind)?;
        if replaced || !g.links.contains_key(worker) {
            // a new key is a new session: the old connection's link is dropped and the worker is proved afresh
            g.links.insert(
                worker.to_string(),
                LinkState::new(&me, worker, random_u64()),
            );
        }
        Ok(())
    }

    /// Stop admitting a worker (it was removed from the roster): its link is dropped and its connection closes.
    pub fn remove(&self, worker: &str) {
        if let Ok(mut r) = self.shared.roster.write() {
            r.remove(worker);
        }
        if let Ok(mut g) = self.shared.inner.lock() {
            g.links.remove(worker);
        }
        self.shared.cv.notify_all();
    }

    /// The address actually listened on (the port, when 0 was asked).
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Whether a worker can be reached. `None` for a box that is not in the roster.
    pub fn reach(&self, worker: &str) -> Option<Reach> {
        self.shared.reach(worker)
    }

    /// Every roster worker's reachability and counters, for the hub's status.
    pub fn status(&self) -> Vec<(String, Reach, Stats)> {
        self.shared.inner.lock().map_or_else(
            |_| Vec::new(),
            |g| {
                g.links
                    .iter()
                    .map(|(w, l)| (w.clone(), l.reach(), l.stats.clone()))
                    .collect()
            },
        )
    }

    pub fn stats(&self, worker: &str) -> Option<Stats> {
        self.shared.stats(worker)
    }

    /// Stop listening and close every connection.
    pub fn stop(&self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        self.shared.cv.notify_all();
        if let Some(h) = self.accept.lock().ok().and_then(|mut a| a.take()) {
            let _ = h.join();
        }
    }
}

impl Drop for NetHub {
    fn drop(&mut self) {
        self.stop();
    }
}

impl Transport for NetHub {
    fn send(&self, to: &str, msg: Sealed) -> Result<(), WireError> {
        self.shared.send(to, msg)
    }
    fn recv(&self, who: &str) -> Option<Sealed> {
        self.shared.recv(who)
    }
}

fn accept_loop(listener: TcpListener, sh: Arc<Shared>, cfg: Arc<HubNetConfig>) {
    let mut conns: Vec<JoinHandle<()>> = Vec::new();
    while !sh.stopped() {
        conns.retain(|h| !h.is_finished());
        match listener.accept() {
            Ok((s, from)) => {
                let admitted = sh.inner.lock().is_ok_and(|mut g| {
                    let now = now_ms();
                    let limited = g
                        .fails
                        .get(&from.ip())
                        .is_some_and(|(at, n)| now < at + 60_000 && *n >= FAILS_PER_MINUTE);
                    if limited || g.open >= MAX_CONNECTIONS {
                        return false;
                    }
                    g.open += 1;
                    true
                });
                if !admitted {
                    drop(s);
                    continue;
                }
                let (sh2, cfg2) = (sh.clone(), cfg.clone());
                conns.push(std::thread::spawn(move || {
                    hub_conn(s, from.ip(), &sh2, &cfg2);
                    if let Ok(mut g) = sh2.inner.lock() {
                        g.open -= 1;
                    }
                }));
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => std::thread::sleep(POLL),
            Err(_) => std::thread::sleep(POLL),
        }
    }
    for h in conns {
        let _ = h.join();
    }
}

fn hub_conn(mut s: TcpStream, from: IpAddr, sh: &Shared, cfg: &HubNetConfig) {
    let _ = s.set_nonblocking(false);
    let _ = s.set_read_timeout(Some(POLL));
    let _ = s.set_write_timeout(Some(WRITE_TIMEOUT));
    let mut rd = FrameReader::default();
    match hub_handshake(&mut s, &mut rd, sh, cfg) {
        Ok((worker, gen)) => {
            sh.run(s, rd, &worker, gen);
        }
        Err(worker) => {
            if let Ok(mut g) = sh.inner.lock() {
                let now = now_ms();
                g.fails.retain(|_, (at, _)| now < *at + 60_000);
                let e = g.fails.entry(from).or_insert((now, 0));
                if now >= e.0 + 60_000 {
                    *e = (now, 0);
                }
                e.1 += 1;
                if let Some(l) = worker.and_then(|w| g.links.get_mut(&w)) {
                    l.stats.handshake_failures += 1;
                }
            }
        }
    }
}

/// The hub's side of the handshake. On failure, the roster name the peer claimed (if it was one), for the count.
fn hub_handshake(
    s: &mut TcpStream,
    rd: &mut FrameReader,
    sh: &Shared,
    cfg: &HubNetConfig,
) -> Result<(String, u64), Option<String>> {
    let deadline = now_ms() + HANDSHAKE_MS;
    let hello: Hello = read_handshake(s, rd, T_HELLO, deadline).map_err(|_| None)?;
    let Some(entry) = sh
        .roster
        .read()
        .ok()
        .and_then(|r| r.get(&hello.worker).cloned())
    else {
        return Err(None);
    };
    let claimed = Some(hello.worker.clone());
    let wn = hex16(&hello.nonce).ok_or_else(|| claimed.clone())?;
    if hello.v != HANDSHAKE_VERSION || hello.hub != cfg.me {
        return Err(claimed);
    }
    let hn = nonce();
    send_json(s, T_CHALLENGE, &Challenge { nonce: to_hex(&hn) }).map_err(|_| claimed.clone())?;
    let proof: Proof = read_handshake(s, rd, T_PROOF, deadline).map_err(|_| claimed.clone())?;
    let sig = from_hex(&proof.sig).ok_or_else(|| claimed.clone())?;
    let signed = handshake_bytes(
        "worker",
        &cfg.me,
        &hello.worker,
        &wn,
        &hn,
        &proof.resume,
        None,
    );
    if !cfg.verifier.verify(&entry.key_fp, &signed, &sig) {
        return Err(claimed);
    }
    // the worker is who it says: take the link over from any older connection, and say where this end resumes from
    let now = now_ms();
    let (mine, gen) = {
        let mut g = sh.inner.lock().map_err(|_| claimed.clone())?;
        let l = g
            .links
            .get_mut(&hello.worker)
            .ok_or_else(|| claimed.clone())?;
        l.gen += 1;
        (l.resume(now), l.gen)
    };
    let hub_signed = handshake_bytes(
        "hub",
        &cfg.me,
        &hello.worker,
        &wn,
        &hn,
        &proof.resume,
        Some(&mine),
    );
    let hub_sig = cfg.signer.sign(&hub_signed).map_err(|_| claimed.clone())?;
    send_json(
        s,
        T_ACCEPT,
        &Proof {
            resume: mine,
            sig: to_hex(&hub_sig),
        },
    )
    .map_err(|_| claimed.clone())?;
    let mut g = sh.inner.lock().map_err(|_| claimed.clone())?;
    let l = g
        .links
        .get_mut(&hello.worker)
        .ok_or_else(|| claimed.clone())?;
    if l.gen != gen {
        return Err(claimed);
    }
    l.on_connected(proof.resume, now);
    Ok((hello.worker, gen))
}

// ---- the worker's end ---------------------------------------------------------------------------------------------

/// How a worker reaches the hub. The real one is [`TcpDialer`]; a test can put a hostile network in between.
pub trait Dialer: Send + Sync {
    fn dial(&self) -> std::io::Result<TcpStream>;
}

/// Dial the hub's address on the tailnet or the private network (`host:port`; a name is resolved on every attempt).
pub struct TcpDialer {
    pub addr: String,
    pub timeout: Duration,
}

impl Dialer for TcpDialer {
    fn dial(&self) -> std::io::Result<TcpStream> {
        let mut last = std::io::Error::from(ErrorKind::NotFound);
        for a in self.addr.to_socket_addrs()? {
            match TcpStream::connect_timeout(&a, self.timeout) {
                Ok(s) => return Ok(s),
                Err(e) => last = e,
            }
        }
        Err(last)
    }
}

/// What the worker's end needs: its own name, the hub's name and pinned key, the key it proves itself with and the route.
pub struct WorkerNetConfig {
    pub me: String,
    pub hub: String,
    /// The hub's key as the worker pinned it at enrolment (the fingerprint the verifier knows).
    pub hub_key: String,
    pub signer: Arc<dyn Signer>,
    pub verifier: Arc<dyn Verifier>,
    pub dialer: Arc<dyn Dialer>,
}

/// The worker's end: one thread that dials out, proves who it is, checks the hub, and carries frames, reconnecting with backoff.
/// A [`Transport`] for [`crate::hub::worker::WorkerEnd`]. Nothing on the worker listens.
pub struct NetWorker {
    shared: Arc<Shared>,
    hub: String,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl NetWorker {
    pub fn start(cfg: WorkerNetConfig) -> Result<NetWorker, NetError> {
        if !word_ok(&cfg.me) || !word_ok(&cfg.hub) {
            return Err(NetError::BadName);
        }
        let shared = Shared::new(&cfg.me);
        if let Ok(mut g) = shared.inner.lock() {
            g.links.insert(
                cfg.hub.clone(),
                LinkState::new(&cfg.me, &cfg.hub, random_u64()),
            );
        }
        let hub = cfg.hub.clone();
        let sh = shared.clone();
        let thread = std::thread::spawn(move || dial_loop(&sh, &cfg));
        Ok(NetWorker {
            shared,
            hub,
            thread: Mutex::new(Some(thread)),
        })
    }

    /// Whether the hub can be reached. The worker's service deletes every key it holds when this stops being `Connected` for
    /// longer than a reconnect (ADR 0042 section 5.3, "at once on loss of the hub").
    pub fn reach(&self) -> Reach {
        self.shared.reach(&self.hub).unwrap_or(Reach::Never)
    }

    pub fn stats(&self) -> Stats {
        self.shared.stats(&self.hub).unwrap_or_default()
    }

    pub fn stop(&self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        self.shared.cv.notify_all();
        if let Some(h) = self.thread.lock().ok().and_then(|mut t| t.take()) {
            let _ = h.join();
        }
    }
}

impl Drop for NetWorker {
    fn drop(&mut self) {
        self.stop();
    }
}

impl Transport for NetWorker {
    fn send(&self, to: &str, msg: Sealed) -> Result<(), WireError> {
        self.shared.send(to, msg)
    }
    fn recv(&self, who: &str) -> Option<Sealed> {
        self.shared.recv(who)
    }
}

/// The next backoff: doubled, capped, with up to a quarter of jitter so a fleet does not reconnect in step.
pub fn next_backoff(cur_ms: u64) -> u64 {
    let base = cur_ms
        .saturating_mul(2)
        .clamp(BACKOFF_MIN_MS, BACKOFF_MAX_MS);
    base - (random_u64() % (base / 4 + 1))
}

fn dial_loop(sh: &Shared, cfg: &WorkerNetConfig) {
    let mut backoff = 0;
    while !sh.stopped() {
        let ok = match cfg.dialer.dial() {
            Ok(mut s) => {
                let _ = s.set_read_timeout(Some(POLL));
                let _ = s.set_write_timeout(Some(WRITE_TIMEOUT));
                let mut rd = FrameReader::default();
                match worker_handshake(&mut s, &mut rd, sh, cfg) {
                    Ok(gen) => {
                        backoff = 0;
                        sh.run(s, rd, &cfg.hub, gen);
                        true
                    }
                    Err(()) => {
                        if let Ok(mut g) = sh.inner.lock() {
                            if let Some(l) = g.links.get_mut(&cfg.hub) {
                                l.stats.handshake_failures += 1;
                            }
                        }
                        false
                    }
                }
            }
            Err(_) => false,
        };
        if ok {
            continue;
        }
        backoff = next_backoff(backoff);
        let until = now_ms() + backoff;
        while now_ms() < until && !sh.stopped() {
            std::thread::sleep(POLL);
        }
    }
}

fn worker_handshake(
    s: &mut TcpStream,
    rd: &mut FrameReader,
    sh: &Shared,
    cfg: &WorkerNetConfig,
) -> Result<u64, ()> {
    let deadline = now_ms() + HANDSHAKE_MS;
    let wn = nonce();
    send_json(
        s,
        T_HELLO,
        &Hello {
            v: HANDSHAKE_VERSION,
            hub: cfg.hub.clone(),
            worker: cfg.me.clone(),
            nonce: to_hex(&wn),
        },
    )
    .map_err(|_| ())?;
    let ch: Challenge = read_handshake(s, rd, T_CHALLENGE, deadline).map_err(|_| ())?;
    let hn = hex16(&ch.nonce).ok_or(())?;
    let now = now_ms();
    let (mine, gen) = {
        let mut g = sh.inner.lock().map_err(|_| ())?;
        let l = g.links.get_mut(&cfg.hub).ok_or(())?;
        l.gen += 1;
        (l.resume(now), l.gen)
    };
    let signed = handshake_bytes("worker", &cfg.hub, &cfg.me, &wn, &hn, &mine, None);
    let sig = cfg.signer.sign(&signed).map_err(|_| ())?;
    send_json(
        s,
        T_PROOF,
        &Proof {
            resume: mine,
            sig: to_hex(&sig),
        },
    )
    .map_err(|_| ())?;
    let acc: Proof = read_handshake(s, rd, T_ACCEPT, deadline).map_err(|_| ())?;
    let hub_sig = from_hex(&acc.sig).ok_or(())?;
    let hub_signed = handshake_bytes("hub", &cfg.hub, &cfg.me, &wn, &hn, &mine, Some(&acc.resume));
    if !cfg.verifier.verify(&cfg.hub_key, &hub_signed, &hub_sig) {
        // not the hub this worker pinned: it is given nothing, not even an acknowledgement
        return Err(());
    }
    let mut g = sh.inner.lock().map_err(|_| ())?;
    let l = g.links.get_mut(&cfg.hub).ok_or(())?;
    if l.gen != gen {
        return Err(());
    }
    l.on_connected(acc.resume, now_ms());
    Ok(gen)
}

#[cfg(test)]
mod tests;
