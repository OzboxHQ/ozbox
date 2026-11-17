#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;

use super::engine::{Assign, Hub, HubError, HubState, RosterEntry};
use super::mem::{MemTransport, TestKey, TestRoster, TestSealer};
use super::refusal::{
    refuse_production, KeyDeclaration, CODE_PRODUCTION, CODE_VALUE_IN_DECLARATION,
};
use super::wire::{Ext, Hop, Kind, Transport, ENVELOPE_TAG, PROFILE};
use super::worker::{WorkerEnd, WorkerState};
use crate::channel::wire::{
    hex, seal_and_sign, Crypto, Envelope, Sealed, Sealer, Signer, WireError as ChannelError,
    VERSION,
};

pub(super) const HUB_FP: &str = "aa00000000000000000000000000000000000000000000000000000000000001";
pub(super) const W1_FP: &str = "bb00000000000000000000000000000000000000000000000000000000000001";
pub(super) const W2_FP: &str = "bb00000000000000000000000000000000000000000000000000000000000002";

fn sample() -> Envelope {
    Envelope {
        version: VERSION,
        kind: "task.assign".into(),
        from: "main".into(),
        to: "worker-1".into(),
        receiver_fp: W1_FP.into(),
        sender_epoch: 7,
        receiver_epoch: 1,
        sender_inc: 0x1111,
        receiver_inc: 0x2222,
        seq: 3,
        ack_seq: 2,
        id: "main-worker-1-3".into(),
        ts_ms: 1_700_000_000_000,
        valid_until_ms: 1_700_000_600_000,
        nonce: (0u8..16).collect(),
        ext: Ext::at(0).encode(),
        body: b"hello".to_vec(),
    }
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
            "ack",
            "resync",
            "task.stop",
            "task.end",
        ]
    );
    for k in Kind::ALL {
        assert_eq!(Kind::parse(k.name()), Some(k));
    }
    assert_eq!(VERSION, 1);
}

#[test]
fn the_profile_lists_every_kind_but_the_channels_own_two() {
    let want: Vec<&str> = Kind::ALL
        .iter()
        .filter(|k| !matches!(k, Kind::Hello | Kind::Ack))
        .map(|k| k.name())
        .collect();
    assert_eq!(PROFILE.kinds, want.as_slice());
    assert_eq!(PROFILE.tag, ENVELOPE_TAG);
}

#[test]
fn golden_vector_of_the_canonical_envelope() {
    // Frozen once a transport ships. A change here is a wire change: a new version and a new vector, never an edit to fit.
    let e = sample();
    assert_eq!(hex(&Ext::at(0).encode()), GOLDEN_EXT);
    assert_eq!(hex(&e.canonical(&PROFILE)), GOLDEN_CANONICAL);
    assert_eq!(e.digest_hex(&PROFILE), GOLDEN_DIGEST);
}

#[test]
fn the_leading_byte_is_the_encoding_version_then_the_tag_then_the_envelope_version() {
    let c = sample().canonical(&PROFILE);
    assert_eq!(c[0], crate::approval_subject::ENCODING_VERSION);
    let tag = ENVELOPE_TAG.as_bytes();
    assert_eq!(&c[5..5 + tag.len()], tag);
    // the envelope's version is the first field after the tag: length 8, then the number
    let at = 5 + tag.len();
    assert_eq!(&c[at..at + 12], &[0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 1]);
}

#[test]
fn a_receiver_accepts_exactly_the_current_envelope_version() {
    // there is no version before this one, so there is no "one before" to accept
    for v in [0, VERSION + 1] {
        let mut e = sample();
        e.version = v;
        assert_eq!(e.check(&PROFILE), Err(ChannelError::Version), "version {v}");
    }
    assert!(sample().check(&PROFILE).is_ok());
}

#[test]
fn the_new_kinds_are_directed_and_acknowledged_as_designed() {
    for k in [Kind::Resync, Kind::TaskStop, Kind::TaskEnd] {
        assert!(k.hub_to_worker() && k.acknowledged(), "{k:?}");
    }
    assert!(!Kind::Ack.acknowledged() && !Kind::Ack.hub_to_worker());
}

#[test]
fn a_signer_that_fails_is_reported_not_swallowed() {
    struct NoSign;
    impl Signer for NoSign {
        fn sign(&self, _: &[u8]) -> Result<Vec<u8>, ChannelError> {
            Err(ChannelError::SignFailed)
        }
    }
    let f = fx();
    let cx = Crypto {
        signer: &NoSign,
        verifier: &f.roster_keys,
        sealer: &f.hub_sealer,
    };
    let r = seal_and_sign(&PROFILE, sample(), W1_FP, b"x", &cx);
    assert_eq!(r.unwrap_err(), ChannelError::SignFailed);
}

#[test]
fn golden_vector_with_a_relay_hop() {
    let mut e = sample();
    e.ext = Ext {
        level: 2,
        via: vec![Hop {
            box_id: "worker-a".into(),
            key_fp: W2_FP.into(),
        }],
    }
    .encode();
    assert_eq!(hex(&e.ext), GOLDEN_EXT_VIA);
    assert_eq!(hex(&e.canonical(&PROFILE)), GOLDEN_CANONICAL_VIA);
    assert!(
        e.check(&PROFILE).is_ok(),
        "the schema carries hops; a receiver at level 1 refuses them"
    );
}

#[test]
fn the_ext_round_trips_and_nothing_else_decodes() {
    let x = Ext {
        level: 1,
        via: vec![Hop {
            box_id: "w".into(),
            key_fp: W1_FP.into(),
        }],
    };
    assert_eq!(Ext::decode(&x.encode()), Some(x));
    assert_eq!(Ext::decode(&[]), None);
    assert_eq!(Ext::decode(&Ext::at(3).encode()), None, "no level past 2");
    let mut long = Ext::at(1).encode();
    long.push(0);
    assert_eq!(Ext::decode(&long), None, "trailing bytes");
}

#[test]
fn every_field_changes_the_canonical_bytes() {
    let mut seen = vec![sample().canonical(&PROFILE)];
    let mut change = |f: &dyn Fn(&mut Envelope)| {
        let mut e = sample();
        f(&mut e);
        let c = e.canonical(&PROFILE);
        assert!(!seen.contains(&c));
        seen.push(c);
    };
    change(&|e| e.kind = "status".into());
    change(&|e| e.from = "other".into());
    change(&|e| e.to = "worker-2".into());
    change(&|e| e.receiver_fp = W2_FP.into());
    change(&|e| e.sender_epoch = 8);
    change(&|e| e.receiver_epoch = 2);
    change(&|e| e.seq = 4);
    change(&|e| e.ack_seq = 3);
    change(&|e| e.sender_inc = 1);
    change(&|e| e.receiver_inc = 1);
    change(&|e| e.valid_until_ms = 1);
    change(&|e| e.version = 0);
    change(&|e| e.ext = Ext::at(1).encode());
    change(&|e| e.id = "x".into());
    change(&|e| e.ts_ms = 1);
    change(&|e| e.nonce = vec![7; 16]);
    change(&|e| e.body = b"hellp".to_vec());
}

#[test]
fn shape_checks() {
    let mut e = sample();
    e.ext = Ext::at(3).encode();
    assert!(e.check(&PROFILE).is_err(), "a level past the tree");
    let mut e = sample();
    e.body = vec![0; super::wire::MAX_BODY + 1];
    assert!(e.check(&PROFILE).is_err());
    let mut e = sample();
    e.from = "Bad Name".into();
    assert!(e.check(&PROFILE).is_err());
    let mut e = sample();
    e.receiver_fp = "xyz".into();
    assert!(e.check(&PROFILE).is_err());
}

// ---- decision D2: Production is refused ----------------------------------------------------------------------------

pub(super) fn decl(env: &str, names: &[&str]) -> KeyDeclaration {
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

pub(super) struct Fx {
    pub(super) net: MemTransport,
    pub(super) signers: BTreeMap<String, TestKey>,
    pub(super) roster_keys: TestRoster,
    pub(super) roster: BTreeMap<String, RosterEntry>,
    pub(super) hub_sealer: TestSealer,
    pub(super) w1_sealer: TestSealer,
}

pub(super) fn fx() -> Fx {
    let mut keys = BTreeMap::new();
    keys.insert(HUB_FP.to_string(), "k-main".to_string());
    keys.insert(W1_FP.to_string(), "k-w1".to_string());
    keys.insert(W2_FP.to_string(), "k-w2".to_string());
    let mut signers = BTreeMap::new();
    for (n, k) in [
        ("main", "k-main"),
        ("worker-1", "k-w1"),
        ("worker-2", "k-w2"),
    ] {
        signers.insert(n.to_string(), TestKey(k.to_string()));
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
        hub_sealer: TestSealer {
            my_fp: HUB_FP.into(),
        },
        w1_sealer: TestSealer {
            my_fp: W1_FP.into(),
        },
    }
}

impl Fx {
    pub(super) fn hub(&self) -> Hub<'_> {
        Hub {
            me: "main",
            my_fp: HUB_FP,
            roster: &self.roster,
            signer: &self.signers["main"],
            verifier: &self.roster_keys,
            sealer: &self.hub_sealer,
            net: &self.net,
            deferred: false,
        }
    }

    pub(super) fn worker(&self) -> WorkerEnd<'_> {
        WorkerEnd {
            me: "worker-1",
            hub: "main",
            signer: &self.signers["worker-1"],
            verifier: &self.roster_keys,
            sealer: &self.w1_sealer,
            net: &self.net,
        }
    }

    pub(super) fn hub_state(&self) -> HubState {
        HubState::new("main", HUB_FP, 7)
    }

    pub(super) fn worker_state(&self) -> WorkerState {
        WorkerState::new("worker-1", W1_FP, "main", HUB_FP, 7)
    }

    /// An envelope the hub's key signed, built by hand as a taken-over hub would: every field honest except what the test sets.
    /// `seq` and the times are the caller's; the incarnations are those the session `connect` made.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn hub_message(
        &self,
        hs: &HubState,
        ws: &WorkerState,
        kind: &str,
        seq: u64,
        ts: u64,
        valid_until: u64,
        plain: &[u8],
    ) -> Sealed {
        let env = Envelope {
            version: VERSION,
            kind: kind.into(),
            from: "main".into(),
            to: "worker-1".into(),
            receiver_fp: W1_FP.into(),
            sender_epoch: 7,
            receiver_epoch: 1,
            sender_inc: hs.inc(),
            receiver_inc: ws.inc(),
            seq,
            ack_seq: 0,
            id: format!("x-{seq}"),
            ts_ms: ts,
            valid_until_ms: valid_until,
            nonce: vec![seq as u8 + 100; 16],
            ext: Ext::at(0).encode(),
            body: Vec::new(),
        };
        let cx = Crypto {
            signer: &self.signers["main"],
            verifier: &self.roster_keys,
            sealer: &self.hub_sealer,
        };
        seal_and_sign(&PROFILE, env, W1_FP, plain, &cx).unwrap()
    }
}

pub(super) fn assign(feature: &str, keys: KeyDeclaration) -> Assign {
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

/// Run the two-step `hello` both ways until both ends hold each other's incarnation.
pub(super) fn connect(f: &Fx, hs: &mut HubState, ws: &mut WorkerState, now: u64) {
    let (hub, w) = (f.hub(), f.worker());
    w.hello(ws, now);
    for _ in 0..6 {
        hub.poll(hs, now);
        w.poll(ws, now);
    }
    assert_eq!(hs.peer_inc("worker-1"), ws.inc());
    assert_eq!(ws.hub_inc(), hs.inc());
}

pub(super) fn actions(a: &[crate::audit::NewEvent]) -> Vec<&str> {
    a.iter().map(|l| l.action.as_str()).collect()
}

/// A taken-over hub sends a message outside its own queue: the worker will acknowledge it, so the hub's count must have moved.
pub(super) fn claim_seq(hs: &mut HubState) {
    hs.core.links.get_mut("worker-1").unwrap().out_seq += 1;
}

pub(super) fn captured(f: &Fx, kind: &str) -> Vec<Sealed> {
    f.net
        .capture
        .lock()
        .unwrap()
        .iter()
        .filter(|m| m.envelope.kind == kind)
        .cloned()
        .collect()
}

#[test]
fn main_hands_a_task_to_a_worker_and_reads_its_reports() {
    let f = fx();
    let (hub, w) = (f.hub(), f.worker());
    let (mut hs, mut ws) = (f.hub_state(), f.worker_state());
    connect(&f, &mut hs, &mut ws, 9);
    hs.take_audit();
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
    w.report(&mut ws, 12, "orch-1", "f1", "halfway");
    w.finish(&mut ws, 13, "orch-1", "f1", "abc123", "done");
    // accepted, working, result
    assert_eq!(hub.poll(&mut hs, 14), 3);
    let rep = &hs.peers["worker-1"].report;
    assert_eq!(rep.status["orch-1"]["f1"].state, "working");
    assert_eq!(rep.results["orch-1"]["f1"].commit, "abc123");
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
    let mut hs = f.hub_state();
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
    let (mut hs, mut ws) = (f.hub_state(), f.worker_state());
    connect(&f, &mut hs, &mut ws, 1);
    hs.take_audit();
    let sent_before = f.net.capture.lock().unwrap().len();
    let e = hub
        .assign(
            &mut hs,
            "worker-1",
            &assign("f1", decl("production", &["DB_URL"])),
            5,
        )
        .unwrap_err();
    assert!(matches!(&e, HubError::Refused(r) if r.code == CODE_PRODUCTION));
    assert_eq!(
        f.net.capture.lock().unwrap().len(),
        sent_before,
        "nothing was sent"
    );
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
    assert_eq!(captured(&f, "task.assign").last().unwrap().envelope.seq, 1);
}

#[test]
fn a_taken_over_hub_still_cannot_hand_a_worker_production() {
    // the hub's check is bypassed: the assignment is signed by hand and sent straight on. The worker refuses it on its own.
    let f = fx();
    let w = f.worker();
    let hub = f.hub();
    let (mut hs, mut ws) = (f.hub_state(), f.worker_state());
    connect(&f, &mut hs, &mut ws, 1);
    ws.take_audit();
    let bad = assign("f9", decl("live", &["STRIPE_LIVE_KEY"]));
    claim_seq(&mut hs);
    let m = f.hub_message(
        &hs,
        &ws,
        "task.assign",
        1,
        1,
        100,
        &serde_json::to_vec(&bad).unwrap(),
    );
    f.net.send("worker-1", m).unwrap();
    w.poll(&mut ws, 2);
    assert!(ws.tasks.is_empty(), "the task was not accepted");
    let audit = ws.take_audit();
    let refused: Vec<_> = audit
        .iter()
        .filter(|a| a.action == "hub.keys.refused")
        .collect();
    assert_eq!(refused.len(), 1);
    assert!(refused[0].detail.contains("side=worker"));
    // the hub never assigned f9, so its refusal report is itself refused as unassigned (and audited)
    hub.poll(&mut hs, 3);
    assert!(!hs
        .peers
        .get("worker-1")
        .is_some_and(|p| p.report.status.contains_key("orch-1")));
}

#[test]
fn a_message_sealed_for_another_worker_is_not_opened() {
    let f = fx();
    let (mut hs, mut ws) = (f.hub_state(), f.worker_state());
    connect(&f, &mut hs, &mut ws, 1);
    ws.take_audit();
    // the hub's message for worker-2 lands in worker-1's queue (the network is not trusted)
    let env = Envelope {
        to: "worker-2".into(),
        receiver_fp: W2_FP.into(),
        ..sample()
    };
    let cx = Crypto {
        signer: &f.signers["main"],
        verifier: &f.roster_keys,
        sealer: &f.hub_sealer,
    };
    let m = seal_and_sign(&PROFILE, env, W2_FP, b"{}", &cx).unwrap();
    f.net.send("worker-1", m).unwrap();
    assert_eq!(f.worker().poll(&mut ws, 2), 0);
    assert!(ws.tasks.is_empty());
    let a = ws.take_audit();
    assert_eq!(a[0].action, "hub.unverified");
    assert!(a[0].detail.contains("not-for-me=1"));
}

#[test]
fn a_forged_or_damaged_report_is_rejected_and_quarantines_nobody() {
    let f = fx();
    let (hub, w) = (f.hub(), f.worker());
    let (mut hs, mut ws) = (f.hub_state(), f.worker_state());
    connect(&f, &mut hs, &mut ws, 1);
    hs.take_audit();
    w.report(&mut ws, 1, "-", "-", "x");
    let mut m = f.net.recv("main").unwrap();
    m.signature[0] ^= 1;
    f.net.send("main", m).unwrap();
    assert_eq!(hub.poll(&mut hs, 2), 0);
    let a = hs.take_audit();
    assert_eq!(a[0].action, "hub.unverified");
    assert!(a[0].detail.contains("bad-signature=1"));
    assert!(hs
        .peers
        .get("worker-1")
        .is_none_or(|p| p.quarantined.is_none()));
}

#[test]
fn a_duplicate_is_dropped_and_counted_once_and_a_gap_is_not_taken() {
    let f = fx();
    let (hub, w) = (f.hub(), f.worker());
    let (mut hs, mut ws) = (f.hub_state(), f.worker_state());
    connect(&f, &mut hs, &mut ws, 1);
    hs.take_audit();
    w.report(&mut ws, 1, "-", "-", "one");
    let first = f.net.recv("main").unwrap();
    f.net.send("main", first.clone()).unwrap();
    f.net.send("main", first.clone()).unwrap();
    f.net.send("main", first).unwrap();
    assert_eq!(hub.poll(&mut hs, 2), 1);
    // two duplicates in one round are one counted audit line, not two
    let a = hs.take_audit();
    assert_eq!(actions(&a), ["hub.duplicate"]);
    assert!(a[0].detail.contains("n=2"));
    // a gap: number 3 arrives before number 2
    w.report(&mut ws, 3, "-", "-", "two");
    w.report(&mut ws, 4, "-", "-", "three");
    let _lost = f.net.recv("main").unwrap();
    assert_eq!(hub.poll(&mut hs, 5), 0);
    assert_eq!(hs.core.links["worker-1"].next_in, 2);
}

#[test]
fn a_worker_that_sends_a_hub_only_kind_is_quarantined_and_sent_nothing() {
    let f = fx();
    let (hub, w) = (f.hub(), f.worker());
    let (mut hs, mut ws) = (f.hub_state(), f.worker_state());
    connect(&f, &mut hs, &mut ws, 1);
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
    let (mut hs, mut ws) = (f.hub_state(), f.worker_state());
    connect(&f, &mut hs, &mut ws, 1);
    ws.take_audit();
    claim_seq(&mut hs);
    let m = f.hub_message(&hs, &ws, "keys.deliver", 1, 1, 100, b"sealed-value");
    f.net.send("worker-1", m).unwrap();
    w.poll(&mut ws, 2);
    assert_eq!(ws.take_audit()[0].action, "worker.unsupported");
    hub.poll(&mut hs, 3);
    assert_eq!(
        hs.peers["worker-1"].report.status["-"]["-"].state,
        "unsupported"
    );
}

// ---- sentinels: a value the channel could carry is never kept, reported or audited ---------------------------------

/// A value no test or code path makes up by accident.
const SENTINEL: &str = "SENTINEL-hub-value-7f3c9a0e51d2";

/// Whether the state, as it is written to disk, holds the needle as text or as the hex a held body is kept in.
fn state_holds(json: &str, needle: &str) -> bool {
    json.contains(needle) || json.contains(&hex(needle.as_bytes()))
}

fn worker_keeps(ws: &WorkerState, needle: &str) -> bool {
    state_holds(&serde_json::to_string(ws).unwrap(), needle)
}

fn hub_keeps(hs: &HubState, needle: &str) -> bool {
    state_holds(&serde_json::to_string(hs).unwrap(), needle)
}

#[test]
fn a_delivered_key_value_is_never_kept_reported_or_audited_by_the_worker_even_while_it_waits_for_a_gap(
) {
    // A taken-over hub sends a value. The worker builds no key delivery in this release, so it must keep nothing of it: not in
    // its state while the message waits for an earlier one (state is a file on the worker's disk), not after, not in its audit
    // and not in what it reports back.
    let f = fx();
    let (hub, w) = (f.hub(), f.worker());
    let (mut hs, mut ws) = (f.hub_state(), f.worker_state());
    connect(&f, &mut hs, &mut ws, 1);
    ws.take_audit();
    let body = serde_json::to_vec(&serde_json::json!({
        "env": "staging",
        "values": { "API_KEY": SENTINEL },
    }))
    .unwrap();
    claim_seq(&mut hs);
    claim_seq(&mut hs);
    // number 2 first: it is held until number 1 arrives
    let held = f.hub_message(&hs, &ws, "keys.deliver", 2, 1, 100, &body);
    f.net.send("worker-1", held).unwrap();
    w.poll(&mut ws, 2);
    assert!(
        !worker_keeps(&ws, SENTINEL),
        "a key value waiting for a gap is in the worker's state"
    );
    let first = f.hub_message(&hs, &ws, "keys.deliver", 1, 1, 100, &body);
    f.net.send("worker-1", first).unwrap();
    w.poll(&mut ws, 3);
    assert!(
        !worker_keeps(&ws, SENTINEL),
        "a key value is in the worker's state"
    );
    let audit = ws.take_audit();
    assert!(audit.iter().any(|a| a.action == "worker.unsupported"));
    assert!(audit.iter().all(|a| !a.detail.contains(SENTINEL)));
    // what the worker said back never echoes it, on the wire or at the hub
    hub.poll(&mut hs, 4);
    assert!(
        !hub_keeps(&hs, SENTINEL),
        "a key value reached the hub's state"
    );
    assert!(hs.take_audit().iter().all(|a| !a.detail.contains(SENTINEL)));
    for m in f
        .net
        .capture
        .lock()
        .unwrap()
        .iter()
        .filter(|m| m.envelope.from == "worker-1")
    {
        let plain = f
            .hub_sealer
            .open(&m.envelope.aad(&PROFILE), &m.envelope.body)
            .unwrap_or_default();
        assert!(!String::from_utf8_lossy(&plain).contains(SENTINEL));
    }
}

#[test]
fn an_assignment_that_smuggles_a_value_beside_the_key_names_is_refused_and_nothing_of_it_is_kept() {
    // The declaration is names only. A body that puts a value next to them (a taken-over hub, or a later sender's mistake) is
    // refused before it is held or applied, so the value is never on the worker's disk, and the hub hears it was refused.
    let f = fx();
    let (hub, w) = (f.hub(), f.worker());
    let (mut hs, mut ws) = (f.hub_state(), f.worker_state());
    connect(&f, &mut hs, &mut ws, 1);
    ws.take_audit();
    let mut v = serde_json::to_value(assign("f7", decl("staging", &["API_KEY"]))).unwrap();
    v["keys"]["values"] = serde_json::json!({ "API_KEY": SENTINEL });
    let body = serde_json::to_vec(&v).unwrap();
    claim_seq(&mut hs);
    claim_seq(&mut hs);
    let held = f.hub_message(&hs, &ws, "task.assign", 2, 1, 100, &body);
    f.net.send("worker-1", held).unwrap();
    w.poll(&mut ws, 2);
    assert!(
        !worker_keeps(&ws, SENTINEL),
        "a smuggled value waiting for a gap is in the worker's state"
    );
    let first = f.hub_message(&hs, &ws, "task.assign", 1, 1, 100, &body);
    f.net.send("worker-1", first).unwrap();
    w.poll(&mut ws, 3);
    assert!(
        ws.tasks.is_empty(),
        "an assignment carrying a value is not accepted"
    );
    assert!(!worker_keeps(&ws, SENTINEL));
    let audit = ws.take_audit();
    assert!(audit.iter().all(|a| !a.detail.contains(SENTINEL)));
    assert!(audit
        .iter()
        .any(|a| a.detail.contains(CODE_VALUE_IN_DECLARATION)));
    hub.poll(&mut hs, 4);
    assert!(!hub_keeps(&hs, SENTINEL));
}

#[test]
fn a_refused_production_declaration_leaves_its_key_names_nowhere_but_the_hubs_own_refusal() {
    // the names in a refused declaration are not values, but they say what Production holds: neither end keeps them
    let f = fx();
    let (hub, w) = (f.hub(), f.worker());
    let (mut hs, mut ws) = (f.hub_state(), f.worker_state());
    connect(&f, &mut hs, &mut ws, 1);
    let name = "SENTINEL_PROD_NAME_51D2";
    assert!(hub
        .assign(
            &mut hs,
            "worker-1",
            &assign("f1", decl("production", &[name])),
            5
        )
        .is_err());
    assert!(!hub_keeps(&hs, name));
    assert!(hs.take_audit().iter().all(|a| !a.detail.contains(name)));
    // past the hub, by hand: the worker refuses it and keeps nothing of it
    claim_seq(&mut hs);
    let m = f.hub_message(
        &hs,
        &ws,
        "task.assign",
        1,
        1,
        100,
        &serde_json::to_vec(&assign("f2", decl("production", &[name]))).unwrap(),
    );
    f.net.send("worker-1", m).unwrap();
    w.poll(&mut ws, 6);
    assert!(ws.tasks.is_empty());
    assert!(!worker_keeps(&ws, name));
    assert!(ws.take_audit().iter().all(|a| !a.detail.contains(name)));
}

// ---- incarnations, expiry and the session (ADR 0042) --------------------------------------------------------

#[test]
fn the_hub_offers_no_task_before_a_session_exists_and_starts_one() {
    let f = fx();
    let hub = f.hub();
    let mut hs = f.hub_state();
    let e = hub
        .assign(
            &mut hs,
            "worker-1",
            &assign("f1", KeyDeclaration::default()),
            1,
        )
        .unwrap_err();
    assert!(matches!(e, HubError::NoSession(_)));
    let sent = f.net.capture.lock().unwrap();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].envelope.kind, "hello");
    assert_eq!(sent[0].envelope.receiver_inc, 0);
}

#[test]
fn a_captured_assignment_does_not_verify_again_after_the_worker_state_is_lost() {
    let f = fx();
    let (hub, w) = (f.hub(), f.worker());
    let (mut hs, mut ws) = (f.hub_state(), f.worker_state());
    connect(&f, &mut hs, &mut ws, 1);
    hub.assign(
        &mut hs,
        "worker-1",
        &assign("f1", KeyDeclaration::default()),
        2,
    )
    .unwrap();
    assert_eq!(w.poll(&mut ws, 3), 1);
    let cap = captured(&f, "task.assign").remove(0);
    // the worker's state is lost: a fresh incarnation, nothing applied
    let mut fresh = f.worker_state();
    f.net.send("worker-1", cap).unwrap();
    assert_eq!(w.poll(&mut fresh, 4), 0);
    assert!(fresh.tasks.is_empty(), "the replay was not accepted");
    let a = fresh.take_audit();
    assert!(
        a.iter()
            .any(|l| l.action == "hub.stale" && l.detail.contains("incarnation=1")),
        "{a:?}"
    );
}

#[test]
fn a_replay_inside_the_same_incarnation_is_a_duplicate_and_is_audited() {
    let f = fx();
    let (hub, w) = (f.hub(), f.worker());
    let (mut hs, mut ws) = (f.hub_state(), f.worker_state());
    connect(&f, &mut hs, &mut ws, 1);
    hub.assign(
        &mut hs,
        "worker-1",
        &assign("f1", KeyDeclaration::default()),
        2,
    )
    .unwrap();
    let first = captured(&f, "task.assign").remove(0);
    w.poll(&mut ws, 3);
    f.net.send("worker-1", first).unwrap();
    assert_eq!(w.poll(&mut ws, 4), 0);
    assert_eq!(ws.tasks.len(), 1);
    assert!(actions(&ws.core.audit).contains(&"hub.duplicate"));
}

#[test]
fn a_hub_restart_is_learned_by_a_hello_and_the_next_assignment_is_delivered() {
    let f = fx();
    let (hub, w) = (f.hub(), f.worker());
    let (mut hs, mut ws) = (f.hub_state(), f.worker_state());
    connect(&f, &mut hs, &mut ws, 1);
    hub.assign(
        &mut hs,
        "worker-1",
        &assign("f1", KeyDeclaration::default()),
        2,
    )
    .unwrap();
    assert_eq!(w.poll(&mut ws, 3), 1);
    // the hub restarts: a new state, a new incarnation, counters back to 0. The worker is still at next_in 2.
    let mut hs2 = f.hub_state();
    assert_ne!(hs2.inc(), hs.inc());
    // before a session the hub starts a hello instead of sending a task the worker would drop as a "duplicate"
    let e = hub
        .assign(
            &mut hs2,
            "worker-1",
            &assign("f2", KeyDeclaration::default()),
            10,
        )
        .unwrap_err();
    assert!(matches!(e, HubError::NoSession(_)));
    for _ in 0..6 {
        w.poll(&mut ws, 11);
        hub.poll(&mut hs2, 11);
    }
    assert_eq!(ws.hub_inc(), hs2.inc());
    hub.assign(
        &mut hs2,
        "worker-1",
        &assign("f2", KeyDeclaration::default()),
        12,
    )
    .unwrap();
    assert_eq!(w.poll(&mut ws, 13), 1);
    assert_eq!(ws.tasks.last().unwrap().feature, "f2");
}

#[test]
fn a_message_naming_the_old_hub_incarnation_starts_a_fresh_hello_not_a_silent_drop() {
    let f = fx();
    let (hub, w) = (f.hub(), f.worker());
    let (mut hs, mut ws) = (f.hub_state(), f.worker_state());
    connect(&f, &mut hs, &mut ws, 1);
    // the worker restarts (new state) but the hub still holds the old incarnation, and the worker speaks with its new one
    let mut ws2 = f.worker_state();
    ws2.core.links.get_mut("main").unwrap().peer_inc = hs.inc();
    w.report(&mut ws2, 5, "-", "-", "hi");
    hs.take_audit();
    assert_eq!(hub.poll(&mut hs, 6), 0);
    let a = hs.take_audit();
    // stale, not the peer's act: counted once for the round and named by peer and code
    assert_eq!(a[0].action, "hub.stale");
    assert!(a[0].detail.contains("from=worker-1") && a[0].detail.contains("incarnation=1"));
    // and the hub asked for a fresh hello, which the worker answers: both ends settle
    for _ in 0..6 {
        // past the one-second limit on unsolicited hellos
        w.poll(&mut ws2, 3000);
        hub.poll(&mut hs, 3000);
    }
    assert_eq!(hs.peer_inc("worker-1"), ws2.inc());
}

#[test]
fn an_expired_or_far_future_message_is_refused_after_its_signature_verifies() {
    let f = fx();
    let w = f.worker();
    let (mut hs, mut ws) = (f.hub_state(), f.worker_state());
    connect(&f, &mut hs, &mut ws, 1_000_000);
    ws.take_audit();
    // sent at 1_000_000, lives 10 minutes; read 11 minutes later
    let m = f.hub_message(
        &hs,
        &ws,
        "heartbeat",
        1,
        1_000_000,
        1_000_000 + 600_000,
        b"{}",
    );
    f.net.send("worker-1", m).unwrap();
    assert_eq!(w.poll(&mut ws, 1_000_000 + 11 * 60 * 1000), 0);
    assert!(ws
        .take_audit()
        .iter()
        .any(|l| l.action == "hub.stale" && l.detail.contains("expired=1")));
    // stamped in the far future
    let m = f.hub_message(
        &hs,
        &ws,
        "heartbeat",
        1,
        1_000_000 + 600_000,
        1_000_000 + 1_200_000,
        b"{}",
    );
    f.net.send("worker-1", m).unwrap();
    assert_eq!(w.poll(&mut ws, 1_000_000), 0);
    assert!(ws
        .take_audit()
        .iter()
        .any(|l| l.action == "hub.stale" && l.detail.contains("skew=1")));
}

#[test]
fn a_worker_refuses_an_assignment_whose_lease_has_passed() {
    let f = fx();
    let (hub, w) = (f.hub(), f.worker());
    let (mut hs, mut ws) = (f.hub_state(), f.worker_state());
    connect(&f, &mut hs, &mut ws, 1);
    let mut a = assign("f1", KeyDeclaration::default());
    a.lease_expiry_ms = 5;
    hub.assign(&mut hs, "worker-1", &a, 2).unwrap();
    assert_eq!(w.poll(&mut ws, 6), 1);
    assert!(ws.tasks.is_empty());
    assert!(ws
        .core
        .audit
        .iter()
        .any(|l| l.detail.contains("lease-expired")));
}

#[test]
fn a_report_for_a_feature_the_hub_did_not_assign_is_refused_and_audited() {
    let f = fx();
    let (hub, w) = (f.hub(), f.worker());
    let (mut hs, mut ws) = (f.hub_state(), f.worker_state());
    connect(&f, &mut hs, &mut ws, 1);
    hub.assign(
        &mut hs,
        "worker-1",
        &assign("f1", KeyDeclaration::default()),
        2,
    )
    .unwrap();
    w.poll(&mut ws, 3);
    hs.take_audit();
    w.report(&mut ws, 4, "orch-1", "f-other", "x");
    w.report(
        &mut ws,
        5,
        "orch-2",
        "f1",
        "same feature id, another orchestration",
    );
    w.report(&mut ws, 6, "orch-1", "f1", "mine");
    hub.poll(&mut hs, 7);
    let rep = &hs.peers["worker-1"].report;
    assert_eq!(rep.status["orch-1"]["f1"].text, "mine");
    assert!(!rep.status.contains_key("orch-2"));
    assert!(!rep.status["orch-1"].contains_key("f-other"));
    let refused = hs
        .take_audit()
        .iter()
        .filter(|l| l.detail.contains("unassigned-feature"))
        .count();
    assert_eq!(refused, 2);
}

#[test]
fn a_relayed_message_is_refused_in_this_release() {
    let f = fx();
    let (hub, w) = (f.hub(), f.worker());
    let (mut hs, mut ws) = (f.hub_state(), f.worker_state());
    connect(&f, &mut hs, &mut ws, 1);
    hs.take_audit();
    // a worker-signed message whose ext names a relay hop: well formed, signed, in order, and refused by the hub
    let ext = Ext {
        level: 2,
        via: vec![Hop {
            box_id: "worker-a".into(),
            key_fp: W2_FP.into(),
        }],
    }
    .encode();
    let env = Envelope {
        from: "worker-1".into(),
        to: "main".into(),
        receiver_fp: HUB_FP.into(),
        sender_epoch: 1,
        receiver_epoch: 7,
        sender_inc: ws.inc(),
        receiver_inc: hs.inc(),
        seq: 1,
        ack_seq: 0,
        ext,
        kind: "status".into(),
        ..sample()
    };
    let cx = Crypto {
        signer: &f.signers["worker-1"],
        verifier: &f.roster_keys,
        sealer: &f.w1_sealer,
    };
    let sealed = seal_and_sign(
        &PROFILE,
        Envelope {
            valid_until_ms: 400,
            ts_ms: 1,
            ..env
        },
        HUB_FP,
        b"{}",
        &cx,
    )
    .unwrap();
    f.net.send("main", sealed).unwrap();
    assert_eq!(hub.poll(&mut hs, 2), 0);
    assert!(hs
        .take_audit()
        .iter()
        .any(|l| l.detail.contains("reason=relay")));
    let _ = w;
}

#[test]
fn the_hub_state_persists_and_a_restart_keeps_its_counters_and_unacknowledged_messages() {
    use crate::channel::store::Store;
    let f = fx();
    let (hub, w) = (f.hub(), f.worker());
    let (mut hs, mut ws) = (f.hub_state(), f.worker_state());
    connect(&f, &mut hs, &mut ws, 1);
    hub.assign(
        &mut hs,
        "worker-1",
        &assign("f1", KeyDeclaration::default()),
        2,
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let store: Store<HubState> = Store::new(dir.path().join("hub"));
    store.create(&hs).unwrap();
    let back = store.read().unwrap();
    assert_eq!(back, hs, "what the hub keeps survives a restart");
    assert_eq!(
        back.inc(),
        hs.inc(),
        "the incarnation is the same life, not a new one"
    );
    // the worker never saw the assignment (it was dropped): the restarted hub still holds it and sends it again
    let mut hs2 = back;
    f.net.recv("worker-1");
    while f.net.recv("worker-1").is_some() {}
    hub.flush(&mut hs2, "worker-1", 10_000).unwrap();
    assert_eq!(w.poll(&mut ws, 10_001), 1);
    assert_eq!(ws.tasks.len(), 1);
}

// Computed by `testdata/channel_golden_vectors.py` (HUB_EXT, HUB_CANONICAL, HUB_DIGEST, HUB_EXT_VIA, HUB_CANONICAL_VIA), not by the
// crate's encoder.
const GOLDEN_EXT: &str =
    "01000000106f7a626f782d6875622d6578742d7631000000080000000000000000000000080000000000000000";
const GOLDEN_EXT_VIA: &str = "01000000106f7a626f782d6875622d6578742d763100000008000000000000000200000008000000000000000100000008776f726b65722d610000004062623030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303032";
const GOLDEN_CANONICAL: &str = "01000000156f7a626f782d6875622d656e76656c6f70652d76310000000800000000000000010000000b7461736b2e61737369676e000000046d61696e00000008776f726b65722d3100000040626230303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030310000000800000000000000070000000800000000000000010000000800000000000011110000000800000000000022220000000800000000000000030000000800000000000000020000000f6d61696e2d776f726b65722d312d33000000080000018bcfe56800000000080000018bcfee8fc000000010000102030405060708090a0b0c0d0e0f0000002d01000000106f7a626f782d6875622d6578742d76310000000800000000000000000000000800000000000000000000000568656c6c6f";
const GOLDEN_DIGEST: &str = "afd2ef9686ad687b1c7fdd03fcbe679eeb53d9f5b522e781d3b84b05081699ca";
const GOLDEN_CANONICAL_VIA: &str = "01000000156f7a626f782d6875622d656e76656c6f70652d76310000000800000000000000010000000b7461736b2e61737369676e000000046d61696e00000008776f726b65722d3100000040626230303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030310000000800000000000000070000000800000000000000010000000800000000000011110000000800000000000022220000000800000000000000030000000800000000000000020000000f6d61696e2d776f726b65722d312d33000000080000018bcfe56800000000080000018bcfee8fc000000010000102030405060708090a0b0c0d0e0f0000007d01000000106f7a626f782d6875622d6578742d763100000008000000000000000200000008000000000000000100000008776f726b65722d6100000040626230303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030320000000568656c6c6f";
