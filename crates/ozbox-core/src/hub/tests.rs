#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;

use super::engine::{Assign, Hub, HubError, HubState, RosterEntry};
use super::mem::{MemTransport, TestKey, TestRoster, TestSealer};
use super::refusal::{refuse_production, KeyDeclaration, CODE_PRODUCTION};
use super::wire::{Envelope, Kind, Link, Transport, ENVELOPE_VERSION};
use super::worker::{WorkerEnd, WorkerState};

const HUB_FP: &str = "aa00000000000000000000000000000000000000000000000000000000000001";
const W1_FP: &str = "bb00000000000000000000000000000000000000000000000000000000000001";
const W2_FP: &str = "bb00000000000000000000000000000000000000000000000000000000000002";

fn sample() -> Envelope {
    Envelope {
        kind: Kind::TaskAssign,
        from: "main".into(),
        to: "worker-1".into(),
        receiver_fp: W1_FP.into(),
        epoch: 7,
        seq: 3,
        id: "main-worker-1-3".into(),
        ts_ms: 1_700_000_000_000,
        level: 0,
        via: Vec::new(),
        body: b"hello".to_vec(),
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ---- the frozen schema ---------------------------------------------------------------------------------------------

#[test]
fn the_message_kinds_are_frozen_in_name_and_order() {
    let names: Vec<&str> = Kind::ALL.iter().map(|k| k.name()).collect();
    assert_eq!(
        names,
        [
            "task.assign",
            "question",
            "answer",
            "status",
            "blocked",
            "contract.changed",
            "result",
            "approval.request",
            "approval.decision",
            "keys.deliver",
            "keys.revoke",
            "lease.renew",
            "pins.set",
            "laptop.relay",
            "shard.assign",
            "shard.result",
            "artifact.offer",
            "artifact.pull",
            "audit.head",
            "audit.segments",
            "hello",
            "heartbeat",
            "bye",
        ]
    );
    for k in Kind::ALL {
        assert_eq!(Kind::parse(k.name()), Some(k));
    }
    assert_eq!(ENVELOPE_VERSION, 1);
}

#[test]
fn golden_vector_of_the_canonical_envelope() {
    // Frozen. If this fails the wire format changed: that needs a new version byte and a new tag, never an edit here.
    let e = sample();
    assert_eq!(hex(&e.canonical()), GOLDEN_CANONICAL);
    assert_eq!(e.digest_hex(), GOLDEN_DIGEST);
}

#[test]
fn golden_vector_with_a_relay_hop() {
    let mut e = sample();
    e.level = 2;
    e.via = vec![super::wire::Hop {
        box_id: "worker-a".into(),
        key_fp: W2_FP.into(),
    }];
    assert_eq!(hex(&e.canonical()), GOLDEN_CANONICAL_VIA);
}

#[test]
fn every_field_changes_the_canonical_bytes() {
    let base = sample().canonical();
    let mut seen = vec![base.clone()];
    let mut change = |f: &dyn Fn(&mut Envelope)| {
        let mut e = sample();
        f(&mut e);
        let c = e.canonical();
        assert!(!seen.contains(&c));
        seen.push(c);
    };
    change(&|e| e.kind = Kind::Status);
    change(&|e| e.from = "other".into());
    change(&|e| e.to = "worker-2".into());
    change(&|e| e.receiver_fp = W2_FP.into());
    change(&|e| e.epoch = 8);
    change(&|e| e.seq = 4);
    change(&|e| e.id = "x".into());
    change(&|e| e.ts_ms = 1);
    change(&|e| e.level = 1);
    change(&|e| e.body = b"hellp".to_vec());
}

#[test]
fn a_field_cannot_run_into_the_next() {
    let mut a = sample();
    a.from = "ab".into();
    a.to = "c".into();
    let mut b = sample();
    b.from = "a".into();
    b.to = "bc".into();
    assert_ne!(a.canonical(), b.canonical());
}

#[test]
fn shape_checks() {
    let mut e = sample();
    e.level = 3;
    assert!(e.check().is_err());
    let mut e = sample();
    e.body = vec![0; super::wire::MAX_BODY + 1];
    assert!(e.check().is_err());
    let mut e = sample();
    e.from = "Bad Name".into();
    assert!(e.check().is_err());
    let mut e = sample();
    e.receiver_fp = "xyz".into();
    assert!(e.check().is_err());
}

// ---- decision D2: Production is refused ----------------------------------------------------------------------------

fn decl(env: &str, names: &[&str]) -> KeyDeclaration {
    KeyDeclaration {
        env: env.into(),
        names: names.iter().map(|s| (*s).to_string()).collect(),
    }
}

#[test]
fn production_is_refused_by_environment_and_by_name() {
    for env in [
        "production",
        "prod",
        "live",
        "Production",
        "qa",
        "",
        "preprod",
        "main",
    ] {
        let r = refuse_production(&decl(env, &["API_KEY"])).unwrap_err();
        assert_eq!(r.code, CODE_PRODUCTION, "env {env:?}");
    }
    for name in [
        "STRIPE_LIVE_KEY",
        "prod_db_url",
        "MyProdToken",
        "LIVE_TOKEN",
    ] {
        let r = refuse_production(&decl("staging", &[name])).unwrap_err();
        assert_eq!(r.code, CODE_PRODUCTION, "name {name}");
    }
}

#[test]
fn an_unknown_environment_counts_as_production() {
    assert!(refuse_production(&decl("sandbox-two", &["A"])).is_err());
}

#[test]
fn development_and_staging_pass_and_so_does_no_keys() {
    for env in ["dev", "development", "staging", "test", "e2e"] {
        assert!(refuse_production(&decl(env, &["SUPABASE_URL", "SUPABASE_ANON_KEY"])).is_ok());
    }
    assert!(refuse_production(&KeyDeclaration::default()).is_ok());
}

#[test]
fn a_malformed_declaration_is_refused_not_passed() {
    assert!(refuse_production(&decl("staging", &[""])).is_err());
    assert!(refuse_production(&decl("staging", &["has space"])).is_err());
    let many: Vec<String> = (0..65).map(|i| format!("K{i}")).collect();
    assert!(refuse_production(&KeyDeclaration {
        env: "staging".into(),
        names: many
    })
    .is_err());
}

#[test]
fn the_refusal_has_no_switch() {
    // built by concatenation so this file does not contain what it forbids
    let src = include_str!("refusal.rs");
    for needle in [
        ["std::", "env"].concat(),
        ["cfg(", "feature"].concat(),
        ["option_", "env"].concat(),
        ["Environment", "Variable"].concat(),
    ] {
        assert!(
            !src.contains(&needle),
            "refusal.rs reads a switch: {needle}"
        );
    }
    // one argument: the function cannot be told to relax
    let _f: fn(&KeyDeclaration) -> Result<(), super::refusal::Refusal> = refuse_production;
}

// ---- the hand-off over the in-memory channel -----------------------------------------------------------------------

struct Fx {
    net: MemTransport,
    signers: BTreeMap<String, TestKey>,
    roster_keys: TestRoster,
    roster: BTreeMap<String, RosterEntry>,
    hub_sealer: TestSealer,
    w1_sealer: TestSealer,
}

fn fx() -> Fx {
    let mut keys = BTreeMap::new();
    keys.insert("main".to_string(), "k-main".to_string());
    keys.insert("worker-1".to_string(), "k-w1".to_string());
    keys.insert("worker-2".to_string(), "k-w2".to_string());
    let mut signers = BTreeMap::new();
    for (n, k) in &keys {
        signers.insert(n.clone(), TestKey(k.clone()));
    }
    let mut roster = BTreeMap::new();
    roster.insert(
        "worker-1".to_string(),
        RosterEntry {
            key_fp: W1_FP.into(),
        },
    );
    roster.insert(
        "worker-2".to_string(),
        RosterEntry {
            key_fp: W2_FP.into(),
        },
    );
    Fx {
        net: MemTransport::default(),
        signers,
        roster_keys: TestRoster(keys),
        roster,
        hub_sealer: TestSealer { me: "main".into() },
        w1_sealer: TestSealer {
            me: "worker-1".into(),
        },
    }
}

impl Fx {
    fn hub(&self) -> Hub<'_> {
        Hub {
            me: "main",
            my_fp: HUB_FP,
            epoch: 7,
            roster: &self.roster,
            signer: &self.signers["main"],
            verifier: &self.roster_keys,
            sealer: &self.hub_sealer,
            net: &self.net,
        }
    }

    fn worker(&self) -> WorkerEnd<'_> {
        WorkerEnd {
            link: Link {
                me: "worker-1",
                peer: "main",
                peer_fp: HUB_FP,
                my_fp: W1_FP,
                epoch: 7,
                level: 1,
                signer: &self.signers["worker-1"],
                verifier: &self.roster_keys,
                sealer: &self.w1_sealer,
                net: &self.net,
            },
        }
    }
}

fn assign(feature: &str, keys: KeyDeclaration) -> Assign {
    Assign {
        orchestration: "orch-1".into(),
        feature: feature.into(),
        title: "Add the thing".into(),
        brief: "Build the thing.".into(),
        branch: format!("feat/{feature}"),
        repo: Some("app".into()),
        claims: vec!["src/thing/**".into()],
        contracts: Vec::new(),
        keys,
        lease_expiry_ms: 9_000_000,
    }
}

#[test]
fn main_hands_a_task_to_a_worker_and_reads_its_reports() {
    let f = fx();
    let (hub, w) = (f.hub(), f.worker());
    let (mut hs, mut ws) = (HubState::default(), WorkerState::default());
    hub.assign(
        &mut hs,
        "worker-1",
        &assign("f1", decl("staging", &["SUPABASE_URL"])),
        10,
    )
    .unwrap();
    assert_eq!(w.poll(&mut ws, 11), 1);
    assert_eq!(ws.tasks.len(), 1);
    assert_eq!(ws.tasks[0].feature, "f1");
    w.report(&mut ws, 12, "f1", "halfway");
    w.finish(&mut ws, 13, "f1", "abc123", "done");
    assert_eq!(hub.poll(&mut hs, 14), 3);
    let rep = &hs.peers["worker-1"].report;
    assert_eq!(rep.status["f1"].state, "working");
    assert_eq!(rep.results["f1"].commit, "abc123");
    assert_eq!(rep.last_seen_ms, 14);
    // the hub's audit says what it did, with names and no values
    let audit = hs.take_audit();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].action, "hub.assign");
    assert!(audit[0].detail.contains("worker=worker-1") && audit[0].detail.contains("keys=1"));
    assert!(!audit[0].detail.contains("SUPABASE_URL"));
}

#[test]
fn a_box_that_is_not_in_the_roster_is_never_sent_anything() {
    let f = fx();
    let hub = f.hub();
    let mut hs = HubState::default();
    let e = hub
        .assign(
            &mut hs,
            "laptop-box",
            &assign("f1", KeyDeclaration::default()),
            1,
        )
        .unwrap_err();
    assert!(matches!(e, HubError::NotAWorker(_)));
    assert!(f.net.capture.lock().unwrap().is_empty());
}

#[test]
fn the_hub_refuses_production_and_audits_before_returning() {
    let f = fx();
    let hub = f.hub();
    let mut hs = HubState::default();
    let e = hub
        .assign(
            &mut hs,
            "worker-1",
            &assign("f1", decl("production", &["DB_URL"])),
            5,
        )
        .unwrap_err();
    assert!(matches!(&e, HubError::Refused(r) if r.code == CODE_PRODUCTION));
    assert!(f.net.capture.lock().unwrap().is_empty(), "nothing was sent");
    let audit = hs.take_audit();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].action, "hub.keys.refused");
    assert!(
        audit[0].detail.contains("side=hub")
            && audit[0].detail.contains("production-to-worker-refused")
    );
    assert!(!audit[0].detail.contains("DB_URL"));
    // and the worker's sequence did not move: the next legitimate task is number 1
    hub.assign(
        &mut hs,
        "worker-1",
        &assign("f2", KeyDeclaration::default()),
        6,
    )
    .unwrap();
    assert_eq!(f.net.capture.lock().unwrap()[0].envelope.seq, 1);
}

#[test]
fn a_taken_over_hub_still_cannot_hand_a_worker_production() {
    // the hub's check is bypassed: the assignment is sent straight on the link. The worker refuses it on its own.
    let f = fx();
    let w = f.worker();
    let hub = f.hub();
    let (mut hs, mut ws) = (HubState::default(), WorkerState::default());
    let bad = assign("f9", decl("live", &["STRIPE_LIVE_KEY"]));
    let link = Link {
        me: "main",
        peer: "worker-1",
        peer_fp: W1_FP,
        my_fp: HUB_FP,
        epoch: 7,
        level: 0,
        signer: &f.signers["main"],
        verifier: &f.roster_keys,
        sealer: &f.hub_sealer,
        net: &f.net,
    };
    link.send(
        Kind::TaskAssign,
        1,
        "x-1".into(),
        1,
        &serde_json::to_vec(&bad).unwrap(),
    )
    .unwrap();
    w.poll(&mut ws, 2);
    assert!(ws.tasks.is_empty(), "the task was not accepted");
    assert_eq!(ws.audit.len(), 1);
    assert_eq!(ws.audit[0].action, "hub.keys.refused");
    assert!(ws.audit[0].detail.contains("side=worker"));
    hub.poll(&mut hs, 3);
    assert_eq!(hs.peers["worker-1"].report.status["f9"].state, "refused");
}

#[test]
fn a_message_sealed_for_another_worker_is_not_opened() {
    let f = fx();
    let hub = f.hub();
    let mut hs = HubState::default();
    hub.assign(
        &mut hs,
        "worker-2",
        &assign("f1", KeyDeclaration::default()),
        1,
    )
    .unwrap();
    // worker-2's message lands in worker-1's queue (the network is not trusted)
    let m = f.net.recv("worker-2").unwrap();
    f.net.send("worker-1", m);
    let mut ws = WorkerState::default();
    assert_eq!(f.worker().poll(&mut ws, 2), 0);
    assert!(ws.tasks.is_empty());
    assert_eq!(ws.audit[0].action, "worker.rejected");
}

#[test]
fn a_forged_or_damaged_report_is_rejected_and_quarantines_nobody() {
    let f = fx();
    let (hub, w) = (f.hub(), f.worker());
    let (mut hs, mut ws) = (HubState::default(), WorkerState::default());
    w.report(&mut ws, 1, "f1", "x");
    let mut m = f.net.recv("main").unwrap();
    m.signature[0] ^= 1;
    f.net.send("main", m);
    assert_eq!(hub.poll(&mut hs, 2), 0);
    assert_eq!(hs.take_audit()[0].action, "hub.rejected");
    assert!(hs
        .peers
        .get("worker-1")
        .is_none_or(|p| p.quarantined.is_none()));
}

#[test]
fn a_duplicate_is_dropped_and_a_gap_is_not_taken() {
    let f = fx();
    let (hub, w) = (f.hub(), f.worker());
    let (mut hs, mut ws) = (HubState::default(), WorkerState::default());
    w.report(&mut ws, 1, "f1", "one");
    let first = f.net.recv("main").unwrap();
    f.net.send("main", first.clone());
    f.net.send("main", first);
    assert_eq!(hub.poll(&mut hs, 2), 1);
    assert_eq!(hs.duplicates, 1);
    // a gap: number 3 arrives before number 2
    w.report(&mut ws, 3, "f1", "two");
    w.report(&mut ws, 4, "f1", "three");
    let _lost = f.net.recv("main").unwrap();
    assert_eq!(hub.poll(&mut hs, 5), 0);
    assert_eq!(hs.peers["worker-1"].in_seq, 1);
}

#[test]
fn a_worker_that_sends_a_hub_only_kind_is_quarantined_and_sent_nothing() {
    let f = fx();
    let (hub, w) = (f.hub(), f.worker());
    let (mut hs, mut ws) = (HubState::default(), WorkerState::default());
    w.say_raw(&mut ws, 1, Kind::KeysDeliver, b"x");
    hub.poll(&mut hs, 2);
    assert!(hs.peers["worker-1"].quarantined.is_some());
    let e = hub
        .assign(
            &mut hs,
            "worker-1",
            &assign("f1", KeyDeclaration::default()),
            3,
        )
        .unwrap_err();
    assert!(matches!(e, HubError::Quarantined(_)));
}

#[test]
fn key_delivery_is_not_supported_and_the_worker_says_so() {
    let f = fx();
    let (hub, w) = (f.hub(), f.worker());
    let (mut hs, mut ws) = (HubState::default(), WorkerState::default());
    let link = Link {
        me: "main",
        peer: "worker-1",
        peer_fp: W1_FP,
        my_fp: HUB_FP,
        epoch: 7,
        level: 0,
        signer: &f.signers["main"],
        verifier: &f.roster_keys,
        sealer: &f.hub_sealer,
        net: &f.net,
    };
    link.send(Kind::KeysDeliver, 1, "k-1".into(), 1, b"sealed-value")
        .unwrap();
    w.poll(&mut ws, 2);
    assert_eq!(ws.audit[0].action, "worker.unsupported");
    hub.poll(&mut hs, 3);
    assert_eq!(hs.peers["worker-1"].report.status["-"].state, "unsupported");
}

#[test]
fn a_relayed_message_is_refused_in_this_release() {
    let f = fx();
    let mut hs = HubState::default();
    let mut e = sample();
    e.from = "worker-1".into();
    e.to = "main".into();
    e.receiver_fp = HUB_FP.into();
    e.level = 2;
    e.via = vec![super::wire::Hop {
        box_id: "worker-a".into(),
        key_fp: W2_FP.into(),
    }];
    let sealed =
        super::wire::seal_and_sign(e, b"{}", &f.w1_sealer, &f.signers["worker-1"]).unwrap();
    f.net.send("main", sealed);
    assert_eq!(f.hub().poll(&mut hs, 1), 0);
}

const GOLDEN_CANONICAL: &str = "01000000156f7a626f782d6875622d656e76656c6f70652d763100000040626230303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030310000000800000000000000070000000b7461736b2e61737369676e000000046d61696e00000008776f726b65722d310000000800000000000000030000000f6d61696e2d776f726b65722d312d33000000080000018bcfe568000000000800000000000000000000000800000000000000000000000568656c6c6f";
const GOLDEN_DIGEST: &str = "ce7107c4613b5f16dc5d417a699911c3142f117a49847c509011032de60f2c93";
const GOLDEN_CANONICAL_VIA: &str = "01000000156f7a626f782d6875622d656e76656c6f70652d763100000040626230303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030310000000800000000000000070000000b7461736b2e61737369676e000000046d61696e00000008776f726b65722d310000000800000000000000030000000f6d61696e2d776f726b65722d312d33000000080000018bcfe5680000000008000000000000000200000008000000000000000100000008776f726b65722d6100000040626230303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030320000000568656c6c6f";
