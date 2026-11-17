#![allow(clippy::unwrap_used, clippy::expect_used)]
//! The network transport over a loopback network: the conformance suite, a hostile network in the middle (drop, duplicate,
//! reorder, cut), the handshake's refusals, back-pressure, honest reachability, the address rule, and sentinels.

use std::collections::BTreeMap;
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::frame::{encode, Frame, FrameReader, MAX_FRAME};
use super::*;
use crate::channel::wire::{Envelope, VERSION};
use crate::hub::conformance::{self, keys, now_ms, Keys, Nets, HUB, HUB_FP, W1, W1_FP, W2};
use crate::hub::mem::{MemTransport, TestKey, TestRoster};
use crate::hub::wire::Ext;

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

fn hub_net(k: &Keys) -> NetHub {
    NetHub::start(HubNetConfig {
        listen: loopback(),
        me: HUB.into(),
        roster: k.roster.clone(),
        signer: Arc::new(TestKey(k.hub.0.clone())),
        verifier: Arc::new(TestRoster(k.roster_keys.0.clone())),
    })
    .unwrap()
}

fn worker_net(k: &Keys, me: &str, key: &TestKey, addr: SocketAddr) -> NetWorker {
    NetWorker::start(WorkerNetConfig {
        me: me.into(),
        hub: HUB.into(),
        hub_key: HUB_FP.into(),
        signer: Arc::new(TestKey(key.0.clone())),
        verifier: Arc::new(TestRoster(k.roster_keys.0.clone())),
        dialer: Arc::new(TcpDialer {
            addr: addr.to_string(),
            timeout: Duration::from_secs(2),
        }),
    })
    .unwrap()
}

fn wait(what: &str, mut ok: impl FnMut() -> bool) {
    for _ in 0..2_000 {
        if ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("{what} did not happen");
}

/// An envelope the transport can carry: well formed, valid now. The body is whatever the test says (the transport never opens it).
fn sealed(from: &str, to: &str, id: &str, body: &[u8]) -> Sealed {
    let now = now_ms();
    let mut nonce = [0u8; 16];
    nonce[..8].copy_from_slice(&random_u64().to_be_bytes());
    Sealed {
        envelope: Envelope {
            version: VERSION,
            kind: "status".into(),
            from: from.into(),
            to: to.into(),
            receiver_fp: "aa01".into(),
            sender_epoch: 1,
            receiver_epoch: 7,
            sender_inc: 5,
            receiver_inc: 6,
            seq: 1,
            ack_seq: 0,
            id: id.into(),
            ts_ms: now,
            valid_until_ms: now + 300_000,
            nonce: nonce.to_vec(),
            ext: Ext::at(1).encode(),
            body: body.to_vec(),
        },
        signature: vec![9; 32],
    }
}

// ---- conformance --------------------------------------------------------------------------------------------------

#[test]
fn the_in_memory_transport_passes_the_conformance_suite() {
    let k = keys();
    let m = MemTransport::default();
    conformance::run_all(
        &k,
        &Nets {
            hub: &m,
            w1: &m,
            w2: &m,
        },
    );
}

#[test]
fn the_network_transport_passes_the_same_conformance_suite_over_loopback() {
    let k = keys();
    let hub = hub_net(&k);
    let w1 = worker_net(&k, W1, &k.w1, hub.local_addr());
    let w2 = worker_net(&k, W2, &k.w2, hub.local_addr());
    conformance::run_all(
        &k,
        &Nets {
            hub: &hub,
            w1: &w1,
            w2: &w2,
        },
    );
    assert!(matches!(hub.reach(W1), Some(Reach::Connected { .. })));
    assert!(matches!(w1.reach(), Reach::Connected { .. }));
}

// ---- a hostile network --------------------------------------------------------------------------------------------

/// What the network in the middle does to data frames, worker to hub. Handshake frames pass untouched (a damaged handshake only
/// costs a reconnect, which `cut_every` covers).
#[derive(Clone, Copy, Default)]
struct Faults {
    drop_every: u64,
    dup_every: u64,
    swap_every: u64,
    cut_every: u64,
}

/// A loopback proxy between the worker and the hub that applies `Faults` to the worker's data frames.
struct Chaos {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    pub cuts: Arc<AtomicU64>,
}

impl Chaos {
    fn start(to: SocketAddr, f: Faults) -> Chaos {
        let l = TcpListener::bind(loopback()).unwrap();
        let addr = l.local_addr().unwrap();
        l.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let cuts = Arc::new(AtomicU64::new(0));
        let (st, cu) = (stop.clone(), cuts.clone());
        std::thread::spawn(move || {
            let count = Arc::new(AtomicU64::new(0));
            while !st.load(Ordering::SeqCst) {
                let Ok((a, _)) = l.accept() else {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                };
                a.set_nonblocking(false).unwrap();
                let Ok(b) = TcpStream::connect(to) else {
                    continue;
                };
                let (a2, b2) = (a.try_clone().unwrap(), b.try_clone().unwrap());
                std::thread::spawn(move || {
                    let mut src = b2;
                    let mut dst = a2;
                    let _ = std::io::copy(&mut src, &mut dst);
                    let _ = dst.shutdown(Shutdown::Both);
                });
                let (count, cu) = (count.clone(), cu.clone());
                std::thread::spawn(move || pump_with_faults(a, b, f, &count, &cu));
            }
        });
        Chaos { addr, stop, cuts }
    }
}

impl Drop for Chaos {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn pump_with_faults(
    mut a: TcpStream,
    mut b: TcpStream,
    f: Faults,
    n: &AtomicU64,
    cuts: &AtomicU64,
) {
    let mut rd = FrameReader::default();
    let mut held: Option<Vec<u8>> = None;
    loop {
        let frame = match rd.next(&mut a, MAX_FRAME) {
            Ok(Some(fr)) => fr,
            Ok(None) => continue,
            Err(_) => break,
        };
        let bytes = encode(&frame);
        let Frame::Data(..) = frame else {
            if b.write_all(&bytes).is_err() {
                break;
            }
            continue;
        };
        let i = n.fetch_add(1, Ordering::SeqCst) + 1;
        if f.cut_every > 0 && i.is_multiple_of(f.cut_every) {
            cuts.fetch_add(1, Ordering::SeqCst);
            break;
        }
        if f.drop_every > 0 && i.is_multiple_of(f.drop_every) {
            continue;
        }
        let mut out = Vec::new();
        if f.swap_every > 0 && i.is_multiple_of(f.swap_every) && held.is_none() {
            held = Some(bytes);
            continue;
        }
        out.push(bytes.clone());
        if let Some(h) = held.take() {
            out.push(h);
        }
        if f.dup_every > 0 && i.is_multiple_of(f.dup_every) {
            out.push(bytes);
        }
        if out.iter().any(|o| b.write_all(o).is_err()) {
            break;
        }
    }
    let _ = a.shutdown(Shutdown::Both);
    let _ = b.shutdown(Shutdown::Both);
}

/// Send `n` envelopes worker to hub and return the ids the hub's owner took, in the order taken.
fn carry(w: &NetWorker, hub: &NetHub, n: usize) -> Vec<String> {
    let mut sent = 0;
    let mut got = Vec::new();
    for _ in 0..12_000 {
        while sent < n
            && w.send(HUB, sealed(W1, HUB, &format!("m{sent}"), b"c"))
                .is_ok()
        {
            sent += 1;
        }
        while let Some(m) = hub.recv(HUB) {
            got.push(m.envelope.id);
        }
        if got.len() >= n {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    got
}

#[test]
fn dropped_duplicated_and_reordered_frames_arrive_once_and_in_order() {
    let k = keys();
    let hub = hub_net(&k);
    let chaos = Chaos::start(
        hub.local_addr(),
        Faults {
            drop_every: 7,
            dup_every: 5,
            swap_every: 4,
            ..Faults::default()
        },
    );
    let w = worker_net(&k, W1, &k.w1, chaos.addr);
    let got = carry(&w, &hub, 200);
    let want: Vec<String> = (0..200).map(|i| format!("m{i}")).collect();
    assert_eq!(got, want);
    let s = hub.stats(W1).unwrap();
    assert!(s.duplicates > 0, "duplicates were dropped by number: {s:?}");
    assert!(
        w.stats().retransmitted > 0,
        "drops were recovered by resending"
    );
}

#[test]
fn a_cut_connection_is_redialled_and_resumes_without_loss_or_repeat() {
    let k = keys();
    let hub = hub_net(&k);
    let chaos = Chaos::start(
        hub.local_addr(),
        Faults {
            cut_every: 37,
            ..Faults::default()
        },
    );
    let w = worker_net(&k, W1, &k.w1, chaos.addr);
    let got = carry(&w, &hub, 150);
    let want: Vec<String> = (0..150).map(|i| format!("m{i}")).collect();
    assert_eq!(got, want);
    assert!(chaos.cuts.load(Ordering::SeqCst) >= 2);
    assert!(hub.stats(W1).unwrap().connections >= 3);
}

#[test]
fn the_hub_and_worker_engines_work_through_a_hostile_network() {
    let k = keys();
    let hub = hub_net(&k);
    let chaos = Chaos::start(
        hub.local_addr(),
        Faults {
            drop_every: 6,
            dup_every: 4,
            swap_every: 3,
            cut_every: 29,
        },
    );
    let w1 = worker_net(&k, W1, &k.w1, chaos.addr);
    let w2 = worker_net(&k, W2, &k.w2, hub.local_addr());
    conformance::an_assignment_is_accepted_and_the_reports_are_read(
        &k,
        &Nets {
            hub: &hub,
            w1: &w1,
            w2: &w2,
        },
    );
    conformance::many_reports_arrive_and_the_last_one_wins(
        &k,
        &Nets {
            hub: &hub,
            w1: &w1,
            w2: &w2,
        },
    );
}

// ---- the handshake ------------------------------------------------------------------------------------------------

#[test]
fn a_worker_with_the_wrong_key_is_never_connected_and_is_counted() {
    let k = keys();
    let hub = hub_net(&k);
    let w = worker_net(&k, W1, &TestKey("not-w1".into()), hub.local_addr());
    wait("a failed handshake", || {
        hub.stats(W1).is_some_and(|s| s.handshake_failures >= 1)
    });
    assert_eq!(hub.reach(W1), Some(Reach::Never));
    assert!(
        w.send(HUB, sealed(W1, HUB, "x", b"c")).is_ok(),
        "queued, not delivered"
    );
    std::thread::sleep(Duration::from_millis(100));
    assert!(hub.recv(HUB).is_none());
}

#[test]
fn a_box_not_in_the_roster_is_refused_before_any_check_is_spent() {
    let k = keys();
    let hub = hub_net(&k);
    let w = worker_net(&k, "stranger", &k.w1, hub.local_addr());
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(w.reach(), Reach::Never);
    assert!(hub.status().iter().all(|(_, r, _)| *r == Reach::Never));
}

/// A hub that answers with a key the worker did not pin: it proves nothing, so the worker sends it no data frame, ever.
#[test]
fn a_hub_with_another_key_is_given_nothing() {
    let k = keys();
    let mut fake_keys = k.roster_keys.0.clone();
    fake_keys.insert("ff99".into(), "k-impostor".into());
    let impostor = NetHub::start(HubNetConfig {
        listen: loopback(),
        me: HUB.into(),
        roster: k.roster.clone(),
        signer: Arc::new(TestKey("k-impostor".into())),
        verifier: Arc::new(TestRoster(fake_keys)),
    })
    .unwrap();
    let w = worker_net(&k, W1, &k.w1, impostor.local_addr());
    w.send(HUB, sealed(W1, HUB, "secretish", b"c")).unwrap();
    wait("the worker refusing the hub", || {
        w.stats().handshake_failures >= 1
    });
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(w.reach(), Reach::Never);
    assert!(impostor.recv(HUB).is_none());
    assert_eq!(impostor.stats(W1).unwrap().delivered, 0);
}

#[test]
fn a_handshake_signature_is_bound_to_the_names_the_nonces_and_the_role() {
    let r = Resume {
        tx_session: 1,
        tx_base: 0,
        rx_session: 2,
        rx_upto: 3,
    };
    let base = handshake_bytes("worker", HUB, W1, &[1; 16], &[2; 16], &r, None);
    assert_ne!(
        base,
        handshake_bytes("hub", HUB, W1, &[1; 16], &[2; 16], &r, None)
    );
    assert_ne!(
        base,
        handshake_bytes("worker", HUB, W2, &[1; 16], &[2; 16], &r, None)
    );
    assert_ne!(
        base,
        handshake_bytes("worker", HUB, W1, &[3; 16], &[2; 16], &r, None)
    );
    assert_ne!(
        base,
        handshake_bytes("worker", HUB, W1, &[1; 16], &[3; 16], &r, None)
    );
    let mut r2 = r;
    r2.rx_upto = 4;
    assert_ne!(
        base,
        handshake_bytes("worker", HUB, W1, &[1; 16], &[2; 16], &r2, None)
    );
    // the handshake's domain is not the envelope's
    assert!(base
        .windows(HANDSHAKE_TAG.len())
        .any(|w| w == HANDSHAKE_TAG.as_bytes()));
    assert!(!base
        .windows(crate::hub::wire::ENVELOPE_TAG.len())
        .any(|w| w == crate::hub::wire::ENVELOPE_TAG.as_bytes()));
}

#[test]
fn a_source_that_keeps_failing_the_handshake_is_stopped_for_the_minute() {
    let k = keys();
    let hub = hub_net(&k);
    for _ in 0..(FAILS_PER_MINUTE + 3) {
        let mut s = TcpStream::connect(hub.local_addr()).unwrap();
        let _ = s.write_all(&encode(&Frame::Handshake(
            frame::T_HELLO,
            b"not json".to_vec(),
        )));
        let _ = s.shutdown(Shutdown::Write);
        std::thread::sleep(Duration::from_millis(15));
    }
    std::thread::sleep(Duration::from_millis(100));
    // the next connection from the same source, even with an honest hello, is closed without a challenge
    let mut s = TcpStream::connect(hub.local_addr()).unwrap();
    let hello = serde_json::to_vec(&Hello {
        v: HANDSHAKE_VERSION,
        hub: HUB.into(),
        worker: W1.into(),
        nonce: crate::approval_subject::to_hex(&[1u8; 16]),
    })
    .unwrap();
    let _ = s.write_all(&encode(&Frame::Handshake(frame::T_HELLO, hello)));
    s.set_read_timeout(Some(Duration::from_millis(800)))
        .unwrap();
    let mut buf = [0u8; 1];
    let n = std::io::Read::read(&mut s, &mut buf).unwrap_or(0);
    assert_eq!(n, 0, "the hub closed the connection without a challenge");
}

// ---- back-pressure and reachability -------------------------------------------------------------------------------

#[test]
fn an_owner_that_does_not_take_its_messages_stops_the_sender_and_nothing_is_lost() {
    let k = keys();
    let hub = hub_net(&k);
    let w = worker_net(&k, W1, &k.w1, hub.local_addr());
    wait("connected", || matches!(w.reach(), Reach::Connected { .. }));
    let mut sent = 0usize;
    let mut refused = false;
    for _ in 0..4_000 {
        match w.send(HUB, sealed(W1, HUB, &format!("m{sent}"), &[7u8; 4096])) {
            Ok(()) => sent += 1,
            Err(_) => {
                refused = true;
                break;
            }
        }
        if sent.is_multiple_of(64) {
            std::thread::sleep(Duration::from_millis(30));
        }
    }
    assert!(
        refused,
        "the worker's link refused once the hub stopped taking"
    );
    assert!(w.stats().refused_full >= 1);
    let mut got = 0;
    wait("everything sent, taken", || {
        while hub.recv(HUB).is_some() {
            got += 1;
        }
        got == sent
    });
}

#[test]
fn reachability_is_said_as_it_is() {
    let k = keys();
    // nothing listens here: the worker has never reached a hub
    let nowhere = TcpListener::bind(loopback()).unwrap().local_addr().unwrap();
    let w = worker_net(&k, W1, &k.w1, nowhere);
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(w.reach(), Reach::Never);
    drop(w);

    let hub = hub_net(&k);
    assert_eq!(hub.reach(W1), Some(Reach::Never));
    assert_eq!(hub.reach("not-a-worker"), None);
    let w = worker_net(&k, W1, &k.w1, hub.local_addr());
    wait("connected", || {
        matches!(hub.reach(W1), Some(Reach::Connected { .. }))
    });
    drop(w);
    wait("not answering", || {
        matches!(hub.reach(W1), Some(Reach::NotAnswering { .. }))
    });
    // a message for a worker that is away is queued, not claimed as delivered
    hub.send(W1, sealed(HUB, W1, "later", b"c")).unwrap();
    assert!(matches!(hub.reach(W1), Some(Reach::NotAnswering { .. })));
    assert!(hub
        .send("not-a-worker", sealed(HUB, W1, "x", b"c"))
        .is_err());
}

#[test]
fn backoff_doubles_with_jitter_between_one_and_thirty_seconds() {
    let mut b = 0;
    for _ in 0..12 {
        b = next_backoff(b);
        assert!(
            (BACKOFF_MIN_MS * 3 / 4..=BACKOFF_MAX_MS).contains(&b),
            "{b}"
        );
    }
    assert!(b >= BACKOFF_MAX_MS * 3 / 4);
}

// ---- no inbound port: the address rule, and the worker has no listener --------------------------------------------

#[test]
fn the_hub_never_listens_on_every_address_or_a_public_one() {
    for ip in [
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        IpAddr::V4(Ipv4Addr::new(172, 32, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(100, 128, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
        "2001:db8::1".parse().unwrap(),
    ] {
        assert!(!bind_allowed(ip), "{ip}");
        let e = NetHub::start(HubNetConfig {
            listen: SocketAddr::new(ip, 0),
            me: HUB.into(),
            roster: BTreeMap::new(),
            signer: Arc::new(TestKey("k".into())),
            verifier: Arc::new(TestRoster::default()),
        })
        .err();
        assert_eq!(e, Some(NetError::AddressNotAllowed), "{ip}");
    }
    for ip in [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V4(Ipv4Addr::new(10, 0, 1, 2)),
        IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(100, 64, 0, 7)),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        "fd7a:115c:a1e0::1".parse().unwrap(),
    ] {
        assert!(bind_allowed(ip), "{ip}");
    }
}

#[test]
fn nothing_on_the_workers_side_listens() {
    let src = include_str!("../net.rs");
    let (_, worker) = src
        .split_once("// ---- the worker's end")
        .expect("the worker's section");
    let code: String = worker
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    for needle in ["TcpListener", "UdpSocket", ".bind(", "UnixListener"] {
        assert!(!code.contains(needle), "the worker's end uses {needle}");
    }
    // and the hub's one listener is behind the address rule
    let (hub_part, _) = src.split_once("// ---- the worker's end").unwrap();
    let bind_at = hub_part.find("TcpListener::bind(").expect("one listener");
    let rule_at = hub_part
        .find("bind_allowed(cfg.listen.ip())")
        .expect("the rule");
    assert!(rule_at < bind_at);
    assert_eq!(hub_part.matches("TcpListener::bind(").count(), 1);
}

// ---- sentinels ----------------------------------------------------------------------------------------------------

const SENTINEL: &str = "SENTINEL-net-key-4b1d77e0c2a9";

#[test]
fn a_body_is_never_in_a_count_a_reach_an_error_or_a_status() {
    let k = keys();
    let hub = hub_net(&k);
    let w = worker_net(&k, W1, &k.w1, hub.local_addr());
    w.send(HUB, sealed(W1, HUB, "a", SENTINEL.as_bytes()))
        .unwrap();
    // misaddressed (names another sender): dropped by the hub's end, counted, its body nowhere
    w.send(HUB, sealed(W2, HUB, "b", SENTINEL.as_bytes()))
        .unwrap();
    wait("the first, delivered", || hub.recv(HUB).is_some());
    wait("the second, counted", || {
        hub.stats(W1).is_some_and(|s| s.misaddressed == 1)
    });
    let hex = crate::approval_subject::to_hex(SENTINEL.as_bytes());
    let mut seen = format!(
        "{:?}{:?}{:?}{:?}",
        hub.status(),
        w.stats(),
        w.reach(),
        serde_json::to_string(
            &hub.status()
                .into_iter()
                .map(|(_, r, s)| (r, s))
                .collect::<Vec<_>>()
        )
        .unwrap()
    );
    for e in [
        NetError::AddressNotAllowed,
        NetError::BadName,
        NetError::Bind,
    ] {
        seen.push_str(&format!("{e}{e:?}"));
    }
    for e in [
        FrameError::Closed,
        FrameError::Io,
        FrameError::TooBig,
        FrameError::Malformed,
    ] {
        seen.push_str(&format!("{e}{e:?}"));
    }
    assert!(!seen.contains(SENTINEL) && !seen.contains(&hex));
}

#[test]
fn the_roster_is_fixed_and_a_name_that_is_not_a_box_name_is_refused() {
    let k = keys();
    let mut roster = k.roster.clone();
    roster.insert(
        "bad name".into(),
        RosterEntry {
            key_fp: W1_FP.into(),
        },
    );
    let e = NetHub::start(HubNetConfig {
        listen: loopback(),
        me: HUB.into(),
        roster,
        signer: Arc::new(TestKey("k".into())),
        verifier: Arc::new(TestRoster::default()),
    })
    .err();
    assert_eq!(e, Some(NetError::BadName));
}

// ---- the network path's cost (ADR 0042 section 13: under 30 ms p50 added per message) ------------------------------

/// A 1 KB message there and back over loopback, 300 times: the writer wakes on `send`, so the median is far below a read tick.
/// This is a guard against a regression to tick-paced writes, not a benchmark result: the figure that counts is two boxes of the
/// benchmark's shape (ADR 0042 section 13), which is an owner run.
#[test]
fn a_round_trip_over_loopback_is_not_paced_by_a_tick() {
    let k = keys();
    let hub = hub_net(&k);
    let w = worker_net(&k, W1, &k.w1, hub.local_addr());
    wait("connected", || {
        matches!(w.reach(), Reach::Connected { .. })
            && matches!(hub.reach(W1), Some(Reach::Connected { .. }))
    });
    let body = vec![5u8; 1024];
    let mut rtt = Vec::new();
    for i in 0..300 {
        let t = std::time::Instant::now();
        w.send(HUB, sealed(W1, HUB, &format!("p{i}"), &body))
            .unwrap();
        let m = loop {
            if let Some(m) = hub.recv(HUB) {
                break m;
            }
            std::thread::yield_now();
        };
        hub.send(W1, sealed(HUB, W1, &format!("r{}", m.envelope.id), &body))
            .unwrap();
        loop {
            if w.recv(W1).is_some() {
                break;
            }
            std::thread::yield_now();
        }
        rtt.push(t.elapsed());
    }
    rtt.sort();
    let p50 = rtt[rtt.len() / 2];
    let p99 = rtt[rtt.len() * 99 / 100];
    eprintln!("loopback round trip, 1 KB each way: p50 {p50:?}, p99 {p99:?}");
    assert!(p50 < Duration::from_millis(10), "p50 {p50:?}");
}
