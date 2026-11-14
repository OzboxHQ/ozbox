#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::audit::{change, drain, guard, restore};
use super::session::{Core, Link, Received, HALT_ACK_AHEAD, NOTICE_SEQ_CONFLICT};
use super::testkit::{pair, End, Faults, Net, T0, TEST_PROFILE};
use super::wire::{fingerprint, hex, unhex, Envelope, Sealed, Signer, WINDOW};
use crate::audit::AuditLog;
use std::cell::Cell;
use std::rc::Rc;

fn texts(e: &End) -> Vec<String> {
    e.state().applied
}

fn sample() -> Envelope {
    Envelope {
        version: 1,
        kind: "note".into(),
        from: "laptop".into(),
        to: "main".into(),
        receiver_fp: "0123abcd-0123abcd-0123abcd-0123abcd".into(),
        sender_epoch: 3,
        receiver_epoch: 2,
        sender_inc: 0x1111,
        receiver_inc: 0x2222,
        seq: 5,
        ack_seq: 4,
        id: "5-aabbccddeeff".into(),
        ts_ms: 1_700_000_000_000,
        valid_until_ms: 1_700_000_600_000,
        nonce: (0u8..16).collect(),
        ext: b"task-1".to_vec(),
        body: b"hello".to_vec(),
    }
}

// ---- the wire form ------------------------------------------------------------------------------------------------

// Computed by the independent script `testdata/channel_golden_vectors.py` (TEST_CANONICAL), not by this crate's encoder: the ADR 0041 encoding-version byte,
// the profile's tag, then the fields in the order of `Envelope::canonical`, each as a 4-byte big-endian length and its bytes.
const GOLDEN_CANONICAL: &str = "01000000126f7a626f782d746573742d6368616e6e656c000000080000000000000001000000046e6f7465000000066c6170746f70000000046d61696e0000002330313233616263642d30313233616263642d30313233616263642d30313233616263640000000800000000000000030000000800000000000000020000000800000000000011110000000800000000000022220000000800000000000000050000000800000000000000040000000e352d616162626363646465656666000000080000018bcfe56800000000080000018bcfee8fc000000010000102030405060708090a0b0c0d0e0f000000067461736b2d310000000568656c6c6f";
const GOLDEN_DIGEST: &str = "30d6ec58b97bf3974f76e206a9aea8e490cec38da37450ce3ff8a07b82b00881";
const GOLDEN_FP: &str = "02ed1623-c0bda9e0-bc681d61-ab72c79e";

#[test]
fn golden_vector_of_the_canonical_envelope() {
    // Frozen once a transport ships. A change here is a wire change: a new version and a new vector, never an edit to fit.
    let e = sample();
    assert_eq!(hex(&e.canonical(&TEST_PROFILE)), GOLDEN_CANONICAL);
    assert_eq!(e.digest_hex(&TEST_PROFILE), GOLDEN_DIGEST);
}

#[test]
fn one_fingerprint_over_the_key_bytes_and_it_is_the_one_ozbox_seal_computes() {
    let key: Vec<u8> = (0u8..32).collect();
    assert_eq!(fingerprint(&key), GOLDEN_FP);
    let arr: [u8; 32] = key.as_slice().try_into().unwrap();
    assert_eq!(ozbox_seal::fingerprint(&arr), GOLDEN_FP);
}

#[test]
fn every_field_changes_the_canonical_bytes() {
    let mut seen = vec![sample().canonical(&TEST_PROFILE)];
    let mut change = |f: &dyn Fn(&mut Envelope)| {
        let mut e = sample();
        f(&mut e);
        let c = e.canonical(&TEST_PROFILE);
        assert!(!seen.contains(&c));
        seen.push(c);
    };
    change(&|e| e.version = 2);
    change(&|e| e.kind = "ask".into());
    change(&|e| e.from = "other".into());
    change(&|e| e.to = "elsewhere".into());
    change(&|e| e.receiver_fp = "ffff".into());
    change(&|e| e.sender_epoch = 9);
    change(&|e| e.receiver_epoch = 9);
    change(&|e| e.sender_inc = 1);
    change(&|e| e.receiver_inc = 1);
    change(&|e| e.seq = 6);
    change(&|e| e.ack_seq = 3);
    change(&|e| e.id = "x".into());
    change(&|e| e.ts_ms = 1);
    change(&|e| e.valid_until_ms = 1_700_000_500_000);
    change(&|e| e.nonce = vec![9; 16]);
    change(&|e| e.ext = b"task-2".to_vec());
    change(&|e| e.body = b"hellp".to_vec());
    // another profile's tag
    let other = super::wire::Profile {
        tag: "ozbox-other",
        ..super::wire::Profile {
            tag: "",
            audit: "x",
            kinds: &["note", "ask"],
            max_body: 4096,
            check_ext: |_, _| true,
        }
    };
    assert_ne!(
        sample().canonical(&other),
        sample().canonical(&TEST_PROFILE)
    );
}

#[test]
fn a_field_cannot_run_into_the_next() {
    let (mut a, mut b) = (sample(), sample());
    a.from = "ab".into();
    a.to = "c".into();
    b.from = "a".into();
    b.to = "bc".into();
    assert_ne!(a.canonical(&TEST_PROFILE), b.canonical(&TEST_PROFILE));
}

#[test]
fn a_receiver_accepts_exactly_the_current_version() {
    for v in [0, 2, 99] {
        let mut e = sample();
        e.version = v;
        assert_eq!(
            e.check(&TEST_PROFILE),
            Err(super::wire::WireError::Version),
            "version {v}"
        );
    }
    assert!(sample().check(&TEST_PROFILE).is_ok());
}

#[test]
fn shape_checks() {
    let bad: [&dyn Fn(&mut Envelope); 9] = [
        &|e| e.kind = "unknown".into(),
        &|e| e.from = "Bad Name".into(),
        &|e| e.receiver_fp = "xyz".into(),
        &|e| e.sender_inc = 0,
        &|e| e.nonce = vec![1; 3],
        &|e| e.valid_until_ms = e.ts_ms + super::wire::MAX_VALIDITY_MS + 1,
        &|e| e.seq = 0,
        &|e| e.receiver_inc = 0,
        &|e| e.body = vec![0; 5000],
    ];
    for f in bad {
        let mut e = sample();
        f(&mut e);
        assert!(e.check(&TEST_PROFILE).is_err());
    }
    let mut e = sample();
    e.kind = "hello".into();
    e.seq = 0;
    e.ext = Vec::new();
    e.receiver_inc = 0;
    assert!(
        e.check(&TEST_PROFILE).is_ok(),
        "a hello may name no receiver incarnation"
    );
}

// ---- delivery -----------------------------------------------------------------------------------------------------

#[test]
fn messages_go_over_in_order_and_the_acknowledgement_empties_the_outbox() {
    let (a, b, _) = pair(false);
    let net = Net::new();
    for t in ["one", "two", "three"] {
        a.send("main", t);
    }
    net.settle(&a, &b);
    assert_eq!(texts(&b), ["one", "two", "three"]);
    assert!(a.state().core.links["main"].outbox.is_empty());
    b.send("laptop", "back");
    net.settle(&a, &b);
    assert_eq!(texts(&a), ["back"]);
}

#[test]
fn a_duplicated_and_reordered_network_gives_the_same_result() {
    let (a, b, _) = pair(false);
    let net = Net::new();
    net.settle(&a, &b);
    for t in ["1", "2", "3", "4"] {
        a.send("main", t);
    }
    let f = Faults {
        duplicate: true,
        reverse: true,
        ..Faults::default()
    };
    for _ in 0..4 {
        net.round(&a, &b, f);
    }
    net.settle(&a, &b);
    assert_eq!(texts(&b), ["1", "2", "3", "4"]);
}

#[test]
fn nothing_is_lost_when_the_network_drops_and_a_drop_resends() {
    let (a, b, _) = pair(false);
    let net = Net::new();
    net.settle(&a, &b);
    a.send("main", "keep me");
    net.round(
        &a,
        &b,
        Faults {
            drop_out: true,
            ..Faults::default()
        },
    );
    assert!(texts(&b).is_empty());
    net.round(
        &a,
        &b,
        Faults {
            drop_back: true,
            ..Faults::default()
        },
    );
    net.settle(&a, &b);
    assert_eq!(texts(&b), ["keep me"], "applied once, not twice");
    assert!(a.state().core.links["main"].outbox.is_empty());
}

#[test]
fn a_long_queue_drains_a_window_at_a_time_and_one_round_takes_at_most_window_plus_two() {
    let (a, b, _) = pair(false);
    let net = Net::new();
    net.settle(&a, &b);
    for i in 0..150 {
        a.send("main", &format!("m{i}"));
    }
    let out = a.outbound("main");
    assert_eq!(out.len() as u64, WINDOW + 1, "a hello and one window");
    for _ in 0..12 {
        net.round(&a, &b, Faults::default());
    }
    assert_eq!(texts(&b).len(), 150);
    assert_eq!(texts(&b)[0], "m0");
    assert_eq!(texts(&b)[149], "m149");
    // a reply of junk: the surplus is never looked at
    let junk: Vec<Sealed> = (0..70).map(|_| out[0].clone()).collect();
    let r = b.take(&junk);
    assert!(r.refused.contains(&"round-too-large".to_string()));
}

// ---- replay, incarnations, epochs ----------------------------------------------------------------------------------

#[test]
fn a_captured_envelope_replayed_is_a_duplicate_then_expired() {
    let (a, b, clock) = pair(false);
    let net = Net::new();
    net.settle(&a, &b);
    a.send("main", "once");
    net.settle(&a, &b);
    let captured: Vec<Sealed> = net
        .captured
        .borrow()
        .iter()
        .filter(|m| m.envelope.kind == "note")
        .cloned()
        .collect();
    assert!(!captured.is_empty());
    let r = b.take(&captured);
    assert_eq!(r.duplicates, captured.len());
    assert_eq!(texts(&b), ["once"]);
    clock.set(T0 + 11 * 60 * 1000);
    let r = b.take(&captured);
    assert!(r.refused.iter().all(|c| c == "expired"), "{:?}", r.refused);
}

#[test]
fn replaying_captured_stale_envelopes_costs_one_audit_event_a_round_and_no_state_write_per_envelope(
) {
    let (a, b, clock) = pair(false);
    let net = Net::new();
    net.settle(&a, &b);
    for i in 0..5 {
        a.send("main", &format!("m{i}"));
    }
    net.settle(&a, &b);
    let captured: Vec<Sealed> = net
        .captured
        .borrow()
        .iter()
        .filter(|m| m.envelope.sender_epoch != 0)
        .cloned()
        .collect();
    assert!(captured.len() >= 5);
    clock.set(T0 + 11 * 60 * 1000);
    let before = b.sink.actions().len();
    let mut flood = Vec::new();
    for _ in 0..30 {
        flood.extend(captured.iter().cloned());
    }
    let r = b.take(&flood);
    assert!(r.refused.len() > 60);
    let added: Vec<String> = b.sink.actions().split_off(before);
    assert_eq!(
        added.iter().filter(|x| x.ends_with(".stale")).count(),
        1,
        "{added:?}"
    );
    assert!(added.iter().all(|x| !x.ends_with(".refused")), "{added:?}");
    assert!(added.len() <= 3, "{added:?}");
}

#[test]
fn an_envelope_that_never_reached_a_receiver_that_was_restored_is_refused_by_incarnation() {
    let (a, b, _) = pair(false);
    let net = Net::new();
    net.settle(&a, &b);
    a.send("main", "never delivered");
    // captured on the wire, never delivered: its nonce was never seen, so only the incarnation can refuse it
    let captured = a.outbound("main");
    b.store
        .update(|s| s.core.restored(a.now()))
        .expect("restore");
    a.store
        .update(|s| {
            if let Some(l) = s.core.links.get_mut("main") {
                l.epoch += 1;
            }
        })
        .expect("repin");
    let r = b.take(&captured);
    assert!(texts(&b).is_empty(), "nothing was applied");
    // the epoch changed too, so it is refused there first; prove the incarnation check alone with an epoch-preserving restore
    assert!(!r.refused.is_empty());
}

#[test]
fn the_incarnation_check_stands_alone_when_the_epoch_is_unchanged() {
    let (a, b, _) = pair(false);
    let net = Net::new();
    net.settle(&a, &b);
    a.send("main", "never delivered");
    let captured = a.outbound("main");
    // b loses its state and starts again with the same epoch: a fresh incarnation, no session
    b.store
        .update(|s| {
            let fresh = Core::new(
                "main",
                &b.sign_public,
                &b.seal_public,
                &fingerprint(&unhex(&b.seal_public).unwrap()),
                1,
            );
            let mut link = s.core.links["laptop"].clone();
            link.peer_inc = 0;
            link.next_in = 1;
            s.core.incarnation = fresh.incarnation;
            s.core.links.insert("laptop".into(), link);
            s.core.nonces.clear();
        })
        .expect("reset");
    let r = b.take(&captured);
    assert!(texts(&b).is_empty());
    assert!(
        r.refused.iter().any(|c| c == "incarnation"),
        "{:?}",
        r.refused
    );
    // and the session is rebuilt by hellos, after which the same message is delivered from the outbox
    net.settle(&a, &b);
    assert_eq!(texts(&b), ["never delivered"]);
}

#[test]
fn a_captured_hello_from_an_earlier_life_cannot_roll_a_session_back() {
    let (a, b, clock) = pair(false);
    let net = Net::new();
    net.settle(&a, &b);
    let first_inc = a.state().core.incarnation;
    let old_hello = a
        .outbound("main")
        .into_iter()
        .find(|m| m.envelope.kind == "hello")
        .unwrap();
    // the laptop starts over with a fresh incarnation and the same epoch, and the session is rebuilt
    clock.set(T0 + 1000);
    a.restart_same_epoch();
    net.settle(&a, &b);
    let adopted = b.state().core.links["laptop"].peer_inc;
    assert_eq!(adopted, a.state().core.incarnation);
    assert_ne!(adopted, first_inc);
    // the captured hello names the earlier life: valid in every way but its age, and it never reached main
    let r = b.take(&[old_hello]);
    assert_eq!(r.refused, ["stale-hello"]);
    assert_eq!(
        b.state().core.links["laptop"].peer_inc,
        adopted,
        "the session was not rolled back"
    );
}

// ---- a store rolled back without saying so -------------------------------------------------------------------------

#[test]
fn a_store_rolled_back_without_restored_acknowledges_nothing_it_did_not_apply() {
    let (a, b, _) = pair(false);
    let net = Net::new();
    net.settle(&a, &b);
    a.send("main", "m1");
    net.settle(&a, &b);
    let backup = std::fs::read(a.store.dir().join("state.json")).unwrap();
    a.send("main", "m2");
    net.settle(&a, &b);
    assert_eq!(texts(&b), ["m1", "m2"]);
    // the laptop's disk is restored to the backup and nobody runs `restored`
    std::fs::write(a.store.dir().join("state.json"), backup).unwrap();
    a.send("main", "m2-but-different");
    net.settle(&a, &b);
    assert_eq!(texts(&b), ["m1", "m2"], "the reused number was not applied");
    let bs = b.state();
    assert_eq!(
        bs.core.links["laptop"].notice.as_deref(),
        Some(NOTICE_SEQ_CONFLICT)
    );
    let st = a.state();
    let l = &st.core.links["main"];
    assert!(l.halted.is_some(), "the rolled-back end stops sending");
    assert_eq!(l.outbox.len(), 1, "and keeps what was never applied");
    let acts: Vec<String> = b.sink.actions();
    assert!(acts.contains(&"test.alert".to_string()), "{acts:?}");
    // acknowledging the restore is the way out
    a.store
        .update(|s| s.core.restored(a.now()))
        .expect("restored");
    b.store
        .update(|s| {
            if let Some(l) = s.core.links.get_mut("laptop") {
                l.epoch = 2;
            }
        })
        .expect("repin");
    a.store
        .update(|s| {
            if let Some(l) = s.core.links.get_mut("main") {
                l.epoch = 1;
            }
        })
        .expect("peer epoch unchanged");
    a.send("main", "after restore");
    net.settle(&a, &b);
    assert_eq!(texts(&b), ["m1", "m2", "after restore"]);
}

#[test]
fn an_acknowledgement_ahead_of_what_this_end_sent_halts_it() {
    let (a, b, _) = pair(false);
    let net = Net::new();
    net.settle(&a, &b);
    for t in ["x", "y", "z"] {
        a.send("main", t);
    }
    net.settle(&a, &b);
    // a's store goes back to before it sent anything, b did not
    a.store
        .update(|s| {
            let l = s.core.links.get_mut("main").unwrap();
            l.out_seq = 0;
            l.outbox.clear();
        })
        .expect("rollback");
    b.send("laptop", "hello?");
    net.settle(&a, &b);
    assert_eq!(
        a.state().core.links["main"].halted.as_deref(),
        Some(HALT_ACK_AHEAD)
    );
    assert!(a.sink.actions().contains(&"test.halted".to_string()));
}

// ---- screening, limits ---------------------------------------------------------------------------------------------

#[test]
fn a_refused_body_is_never_written_to_the_state_even_while_it_waits_for_a_gap() {
    let (a, b, _) = pair(false);
    let net = Net::new();
    net.settle(&a, &b);
    a.send("main", "first");
    a.send("main", "carries sk_live_SECRET");
    let batch = a.outbound("main");
    // deliver the hello and seq 2 only: seq 2 is held, waiting for seq 1
    let held_only: Vec<Sealed> = batch
        .iter()
        .filter(|m| m.envelope.kind == "hello" || m.envelope.seq == 2)
        .cloned()
        .collect();
    b.take(&held_only);
    let raw = std::fs::read_to_string(b.store.dir().join("state.json")).unwrap();
    assert!(
        !raw.contains("SECRET") && !hex_contains(&raw, b"SECRET"),
        "the key reached the disk"
    );
    net.settle(&a, &b);
    assert_eq!(texts(&b), ["first", "REFUSED:key-shaped-content"]);
}

fn hex_contains(raw: &str, needle: &[u8]) -> bool {
    raw.contains(&hex(needle))
}

#[test]
fn a_flood_of_unverifiable_envelopes_is_one_counted_event_and_nothing_is_stored() {
    let (a, b, _) = pair(false);
    let net = Net::new();
    net.settle(&a, &b);
    let hello = a.outbound("main").remove(0);
    let junk: Vec<Sealed> = (0..60)
        .map(|_| {
            let mut m = hello.clone();
            m.signature = vec![0; 64];
            m
        })
        .collect();
    let before = b.state().core.audit_n;
    b.take(&junk);
    let after = b.state();
    assert_eq!(
        after.core.audit_n,
        before + 1,
        "one event for sixty refusals"
    );
    let ev = b.sink.events.lock().unwrap();
    let last = ev.last().unwrap();
    assert_eq!(last.action, "test.unverified");
    assert!(last.detail.contains("n=60") && last.detail.contains("bad-signature=60"));
}

#[test]
fn a_mutated_header_with_a_valid_signature_cannot_open_the_body_real_hpke() {
    let (a, b, _) = pair(true);
    let net = Net::new();
    net.settle(&a, &b);
    a.send("main", "secret-ish");
    let mut batch = a.outbound("main");
    // the sender signs a header that differs from the one the body was sealed to: the AAD no longer matches
    let m = batch
        .iter_mut()
        .find(|m| m.envelope.kind == "note")
        .unwrap();
    m.envelope.ext = b"other".to_vec();
    m.signature = a.signer.sign(&m.envelope.canonical(&TEST_PROFILE)).unwrap();
    let r = b.take(&batch);
    assert!(
        r.refused.contains(&"unopenable".to_string()),
        "{:?}",
        r.refused
    );
    assert!(texts(&b).is_empty());
}

#[test]
fn a_body_sealed_to_another_receiver_or_another_key_is_unopenable_real_hpke() {
    let (a, b, clock) = pair(true);
    let c = End::new("third", &clock, true);
    let net = Net::new();
    net.settle(&a, &b);
    a.send("main", "for main only");
    // sealed to a key that is not main's: validly signed, addressed to main, but main cannot open it
    let mut batch = a.outbound("main");
    let m = batch
        .iter_mut()
        .find(|m| m.envelope.kind == "note")
        .unwrap();
    let mut env = m.envelope.clone();
    env.body = Vec::new();
    let aad = env.aad(&TEST_PROFILE);
    env.body = c
        .sealer
        .seal(&c.seal_public, &aad, b"for main only")
        .unwrap();
    m.signature = a.signer.sign(&env.canonical(&TEST_PROFILE)).unwrap();
    m.envelope = env;
    let r = b.take(&batch);
    assert!(r.refused.contains(&"unopenable".to_string()));
    // and an envelope naming another receiver's fingerprint is refused before the signature
    let mut other = a.outbound("main").remove(0);
    other.envelope.receiver_fp = fingerprint(&unhex(&c.seal_public).unwrap());
    other.signature = a
        .signer
        .sign(&other.envelope.canonical(&TEST_PROFILE))
        .unwrap();
    let r = b.take(&[other]);
    assert_eq!(r.refused, ["wrong-receiver"]);
    assert!(texts(&b).is_empty());
}

#[test]
fn real_hpke_round_trips_a_message() {
    let (a, b, _) = pair(true);
    let net = Net::new();
    a.send("main", "over hpke");
    net.settle(&a, &b);
    net.settle(&a, &b);
    assert_eq!(texts(&b), ["over hpke"]);
}

// ---- the audit trail -----------------------------------------------------------------------------------------------

#[test]
fn two_drainers_and_a_writer_at_once_lose_nothing_and_log_nothing_twice() {
    let (a, _b, _) = pair(false);
    let store = &a.store;
    let sink = &a.sink;
    std::thread::scope(|s| {
        for _ in 0..2 {
            s.spawn(|| {
                for _ in 0..40 {
                    drain(store, sink).expect("drain");
                }
            });
        }
        s.spawn(|| {
            for i in 0..60 {
                change(store, sink, |st| {
                    st.core.note(T0, "test.event", None, format!("n={i}"));
                })
                .expect("change");
            }
        });
    });
    drain(store, sink).expect("final drain");
    let ev = sink.events.lock().unwrap();
    let mut seen: Vec<u64> = ev
        .iter()
        .filter(|e| e.action == "test.event")
        .map(|e| e.detail.trim_start_matches("n=").parse().unwrap())
        .collect();
    let want: Vec<u64> = (0..60).collect();
    seen.sort_unstable();
    assert_eq!(seen, want, "every event exactly once");
}

#[test]
fn a_restore_from_a_backup_with_the_log_kept_starts_a_new_source_epoch_and_is_not_blank() {
    let (a, _b, _) = pair(false);
    for i in 0..5 {
        change(&a.store, &a.sink, |s| {
            s.core.note(T0, "test.before", None, format!("{i}"))
        })
        .unwrap();
    }
    let backup = std::fs::read(a.store.dir().join("state.json")).unwrap();
    for i in 0..5 {
        change(&a.store, &a.sink, |s| {
            s.core.note(T0, "test.after", None, format!("{i}"))
        })
        .unwrap();
    }
    drain(&a.store, &a.sink).unwrap();
    assert!(guard(&a.state().core, &a.sink).is_ok());
    // the disk comes back from the backup, but the log was kept
    std::fs::write(a.store.dir().join("state.json"), backup).unwrap();
    assert!(
        guard(&a.state().core, &a.sink).is_err(),
        "the log is ahead of the restored store: refuse to go on"
    );
    restore(&a.store, &a.sink, |s| s.core.restored(T0)).unwrap();
    assert!(guard(&a.state().core, &a.sink).is_ok());
    drain(&a.store, &a.sink).unwrap();
    assert!(
        a.sink.actions().contains(&"channel.restored".to_string()),
        "the restore itself is in the log"
    );
}

#[test]
fn after_a_restore_the_real_audit_log_holds_every_source_record_once() {
    // the real log, not the test sink: its own de-duplication is what decides
    let (a, _b, _) = pair(false);
    let log = AuditLog::beside(&a.dir.path().join("tasks.json"));
    for i in 0..5 {
        change(&a.store, &log, |s| {
            s.core.note(T0, "test.before", None, format!("{i}"))
        })
        .unwrap();
        drain(&a.store, &log).unwrap();
    }
    // the backup carries events the log already holds (they are dropped from the state only at the next change)
    let backup = std::fs::read(a.store.dir().join("state.json")).unwrap();
    for i in 0..5 {
        change(&a.store, &log, |s| {
            s.core.note(T0, "test.after", None, format!("{i}"))
        })
        .unwrap();
        drain(&a.store, &log).unwrap();
    }
    std::fs::write(a.store.dir().join("state.json"), backup).unwrap();
    assert!(guard(&a.state().core, &log).is_err());
    // acknowledging the restore is allowed while the guard refuses everything else
    restore(&a.store, &log, |s| s.core.restored(T0)).unwrap();
    assert!(guard(&a.state().core, &log).is_ok());
    assert!(
        a.state().core.audit.iter().all(|e| e
            .src
            .as_ref()
            .is_some_and(|(ep, _)| *ep == a.state().core.store_id)),
        "no event of the old numbering is left pending"
    );
    for i in 0..3 {
        change(&a.store, &log, |s| {
            s.core.note(T0, "test.new", None, format!("{i}"))
        })
        .unwrap();
        drain(&a.store, &log).unwrap();
        drain(&a.store, &log).unwrap();
    }
    let entries = log.entries().unwrap();
    let srcs: Vec<String> = entries.iter().filter_map(|e| e.src.clone()).collect();
    let unique: std::collections::BTreeSet<&String> = srcs.iter().collect();
    assert_eq!(srcs.len(), unique.len(), "no source record twice: {srcs:?}");
    assert_eq!(entries.iter().filter(|e| e.action == "test.new").count(), 3);
    assert_eq!(
        entries
            .iter()
            .filter(|e| e.action == "channel.restored")
            .count(),
        1
    );
    assert_eq!(entries.len(), 5 + 5 + 1 + 3);
}

#[test]
fn a_restore_that_cannot_write_the_log_changes_nothing() {
    struct Broken;
    impl super::audit::AuditSink for Broken {
        fn record_many(&self, _: Vec<crate::audit::NewEvent>) -> std::io::Result<()> {
            Err(std::io::Error::other("full"))
        }
        fn last_src(&self) -> std::io::Result<Option<(String, u64)>> {
            Ok(None)
        }
    }
    let (a, _b, _) = pair(false);
    a.store
        .update(|s| s.core.note(T0, "test.pending", None, String::new()))
        .unwrap();
    let before = a.state();
    assert!(restore(&a.store, &Broken, |s| s.core.restored(T0)).is_err());
    assert_eq!(a.state(), before);
}

// ---- bytes, not only a count ------------------------------------------------------------------------------------

static BIG: super::wire::Profile = super::wire::Profile {
    tag: "ozbox-test-big",
    audit: "big",
    kinds: &["note"],
    max_body: 600 * 1024,
    check_ext: |_, _| true,
};

#[test]
fn a_window_of_large_messages_is_cut_by_bytes_and_still_drains_over_rounds() {
    use super::wire::{wire_size, ROUND_BYTES};
    let mut c = Core::new("a", "sp", "kp", "fp", 1);
    let mut l = Link::new("b", "sk", "pk", "pfp", 1);
    l.peer_inc = 7;
    c.pin(l);
    for _ in 0..64 {
        c.enqueue(&BIG, "b", "note", Vec::new(), vec![7u8; 500 * 1024])
            .unwrap();
    }
    let mut rounds = 0;
    while !c.links["b"].outbox.is_empty() {
        let d = c.drafts(
            "b",
            T0,
            super::session::DraftOpts {
                hello: false,
                ack: false,
                resend: true,
            },
        );
        assert!(!d.is_empty(), "every round makes progress");
        let total: usize = d
            .iter()
            .map(|x| wire_size(x.env.ext.len(), x.plain.len()))
            .sum();
        assert!(total <= ROUND_BYTES, "a round of {total} bytes");
        let top = d.iter().map(|x| x.env.seq).max().unwrap();
        // the peer applied what was offered and said so
        c.links.get_mut("b").unwrap().outbox.retain(|o| o.seq > top);
        rounds += 1;
        assert!(rounds <= 64);
    }
    assert!(rounds > 1, "64 messages of 500 KiB do not fit one round");
}

#[test]
fn one_message_too_big_for_a_round_is_refused_when_it_is_queued() {
    let mut c = Core::new("a", "sp", "kp", "fp", 1);
    c.pin(Link::new("b", "sk", "pk", "pfp", 1));
    static HUGE: super::wire::Profile = super::wire::Profile {
        tag: "ozbox-test-huge",
        audit: "huge",
        kinds: &["note"],
        max_body: 8 * 1024 * 1024,
        check_ext: |_, _| true,
    };
    assert_eq!(
        c.enqueue(&HUGE, "b", "note", Vec::new(), vec![0u8; 3 * 1024 * 1024]),
        Err("too-big-for-a-round")
    );
    // a body that leaves no room for what sealing adds is refused too, not failed later at seal time
    assert_eq!(
        c.enqueue(&TEST_PROFILE, "b", "note", Vec::new(), vec![0u8; 4096]),
        Err("too-big")
    );
    assert!(c
        .enqueue(&TEST_PROFILE, "b", "note", Vec::new(), vec![0u8; 4096 - 48])
        .is_ok());
}

#[test]
fn the_size_estimate_is_never_below_what_goes_on_the_wire() {
    let (a, b, _) = pair(true);
    let net = Net::new();
    net.settle(&a, &b);
    a.send("main", &"x".repeat(4000));
    for m in a.outbound("main") {
        let real = serde_json::to_vec(&m).unwrap().len();
        let est = super::wire::wire_size(
            m.envelope.ext.len(),
            m.envelope.body.len().saturating_sub(48),
        );
        assert!(est >= real, "estimate {est} is below the real {real}");
    }
}

// ---- a reused number below the window ------------------------------------------------------------------------------

#[test]
fn a_store_rolled_back_by_more_than_the_window_is_caught_by_the_running_digest_not_acknowledged() {
    let (a, b, _) = pair(false);
    let net = Net::new();
    net.settle(&a, &b);
    let backup = std::fs::read(a.store.dir().join("state.json")).unwrap();
    for i in 0..100 {
        a.send("main", &format!("old{i}"));
    }
    for _ in 0..4 {
        net.settle(&a, &b);
    }
    assert_eq!(texts(&b).len(), 100);
    // the laptop's disk comes back from before, and nobody says so: it queues 150 messages of its own, numbered from 1 again
    std::fs::write(a.store.dir().join("state.json"), backup).unwrap();
    for i in 0..150 {
        a.send("main", &format!("new{i}"));
    }
    // the peer says it applied 100; the window (the last 64 numbers) cannot see a reuse of number 3, the digest can
    a.take(&b.outbound("laptop"));
    let st = a.state();
    let l = &st.core.links["main"];
    assert_eq!(l.halted.as_deref(), Some("applied-differs"));
    assert_eq!(l.outbox.len(), 150, "nothing was acknowledged away");
    assert!(
        a.outbound("main")
            .iter()
            .all(|m| m.envelope.kind == "hello"),
        "a halted link sends nothing sequenced"
    );
}

#[test]
fn the_running_digest_agrees_after_a_normal_conversation_in_both_directions() {
    let (a, b, _) = pair(false);
    let net = Net::new();
    net.settle(&a, &b);
    for i in 0..70 {
        a.send("main", &format!("a{i}"));
        b.send("laptop", &format!("b{i}"));
    }
    for _ in 0..6 {
        net.settle(&a, &b);
    }
    for e in [&a, &b] {
        let st = e.state();
        assert!(
            st.core
                .links
                .values()
                .all(|l| l.halted.is_none() && l.outbox.is_empty()),
            "{}",
            e.name
        );
    }
    assert_eq!(texts(&b).len(), 70);
    assert_eq!(texts(&a).len(), 70);
}

#[test]
fn the_audit_backlog_is_bounded_and_a_full_one_refuses_a_change_rather_than_dropping() {
    let (a, _b, _) = pair(false);
    a.store
        .update(|s| {
            for _ in 0..super::session::MAX_PENDING_AUDIT {
                s.core.note(T0, "test.fill", None, String::new());
            }
        })
        .unwrap();
    let r = change(&a.store, &a.sink, |s| {
        s.core
            .enqueue(&TEST_PROFILE, "main", "note", Vec::new(), b"x".to_vec())
    })
    .unwrap();
    assert_eq!(r, Err("audit-backlog"));
}

// ---- one write per round --------------------------------------------------------------------------------------

#[test]
fn a_round_that_took_thirty_messages_cost_one_write_and_a_quiet_round_none() {
    let (a, b, _) = pair(false);
    let net = Net::new();
    net.settle(&a, &b);
    for i in 0..30 {
        a.send("main", &format!("m{i}"));
    }
    let batch = a.outbound("main");
    let before = b.store.writes();
    let r = b.take(&batch);
    assert_eq!(r.deliveries.len(), 30);
    assert_eq!(b.store.writes() - before, 1, "thirty messages, one write");
    net.settle(&a, &b);
    // nothing is left to say: a hello each way changes nothing, so it writes nothing
    let (wa, wb) = (a.store.writes(), b.store.writes());
    let (sa, sb) = (
        std::fs::read(a.store.dir().join("state.json")).unwrap(),
        std::fs::read(b.store.dir().join("state.json")).unwrap(),
    );
    net.round(&a, &b, Faults::default());
    net.round(&b, &a, Faults::default());
    assert_eq!(
        (a.store.writes(), b.store.writes()),
        (wa, wb),
        "a quiet round wrote"
    );
    assert_eq!(sa, std::fs::read(a.store.dir().join("state.json")).unwrap());
    assert_eq!(sb, std::fs::read(b.store.dir().join("state.json")).unwrap());
}

// ---- the store ---------------------------------------------------------------------------------------------------

#[test]
fn state_survives_closing_and_reopening_the_store() {
    let (a, b, _) = pair(false);
    a.send("main", "before the crash");
    let reopened: super::store::Store<super::testkit::TState> =
        super::store::Store::new(a.store.dir());
    let st = reopened.read().unwrap();
    assert_eq!(st.core.links["main"].outbox.len(), 1);
    let net = Net::new();
    net.settle(&a, &b);
    assert_eq!(texts(&b), ["before the crash"]);
}

#[test]
fn two_processes_updating_the_store_at_once_never_lose_an_update() {
    let (a, _b, _) = pair(false);
    let store = &a.store;
    std::thread::scope(|s| {
        for t in 0..4 {
            s.spawn(move || {
                for _ in 0..25 {
                    store
                        .update(|st| st.applied.push(format!("t{t}")))
                        .expect("update");
                }
            });
        }
    });
    assert_eq!(a.state().applied.len(), 100);
}

#[test]
fn received_and_core_types_are_shaped_for_callers() {
    assert_eq!(Received::Duplicate, Received::Duplicate);
    let rc = Rc::new(Cell::new(T0));
    let e = End::new("x", &rc, false);
    let l = Link::new("p", "k", "s", "ab-cd", 1);
    assert!(!l.session_ready());
    assert_eq!(e.state().core.me, "x");
}
