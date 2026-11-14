use super::model::{code, Act, Body, Label, Part, State as TState, TaskKind};
use super::state::{NewTask, Outgoing, Verdict, WINDOW};
use super::testkit::*;
use super::wire::{Envelope, Kind, Sealed, ENVELOPE_VERSION};
use super::{printable, Screen};

fn text(s: &str) -> Vec<Part> {
    vec![Part::Text {
        text: s.to_string(),
    }]
}

fn round(a: &End, b: &End) -> super::node::Round {
    let net = Net::new(b, &a.name);
    a.node().sync(&b.name, &net).expect("sync")
}

fn settle(a: &End, b: &End) {
    for _ in 0..3 {
        round(a, b);
    }
}

fn act(env: &str) -> Act {
    Act::PushRef {
        repo: "example/repo".into(),
        remote: "origin".into(),
        r#ref: "release/x".into(),
        sha: "0123456789abcdef0123456789abcdef01234567".into(),
        env: env.into(),
    }
}

fn new_act(to: &str, env: &str) -> NewTask {
    NewTask {
        to: to.into(),
        kind: TaskKind::LaptopAct,
        title: "push".into(),
        parts: text("push it"),
        label: Label::Fleet,
        act: Some(act(env)),
        parent: None,
        deadline_ms: None,
    }
}

// ---- the channel works ------------------------------------------------------------------------------------------

#[test]
fn a_question_goes_over_and_the_answer_comes_back_in_order() {
    let (laptop, main, _) = pair();
    let id = main.ask("laptop", "run the check", "please run the check");
    assert_eq!(main.state().tasks[&id].state, TState::Held);
    settle(&main, &laptop);
    assert_eq!(
        main.state().tasks[&id].state,
        TState::Submitted,
        "the acknowledgement moved it"
    );
    let t = laptop.state().tasks[&id].clone();
    assert_eq!(
        (t.state, t.from.as_str(), t.unread),
        (TState::Submitted, "main", true)
    );
    laptop
        .node()
        .reply(
            &id,
            text("on it"),
            Label::Person,
            Some((TState::Working, None)),
        )
        .expect("reply");
    laptop
        .node()
        .reply(
            &id,
            text("done, all green"),
            Label::Person,
            Some((TState::Completed, None)),
        )
        .expect("reply");
    settle(&laptop, &main);
    let t = main.state().tasks[&id].clone();
    assert_eq!(t.state, TState::Completed);
    let said: Vec<String> = t
        .messages
        .iter()
        .filter_map(|m| m.parts.first().map(|p| p.strings()[0].clone()))
        .collect();
    assert_eq!(said, ["please run the check", "on it", "done, all green"]);
    assert!(
        main.state().peers["laptop"].outbox.is_empty(),
        "everything acknowledged is gone from the outbox"
    );
}

#[test]
fn a_duplicated_and_reordered_network_gives_the_same_result() {
    let (laptop, main, _) = pair();
    let id = main.ask("laptop", "t", "one");
    for w in ["two", "three", "four"] {
        main.node()
            .reply(&id, text(w), Label::Person, None)
            .expect("reply");
    }
    let net = Net::new(&laptop, "main");
    *net.faults.borrow_mut() = Faults {
        duplicate: true,
        reverse: true,
        ..Faults::default()
    };
    main.node().sync("laptop", &net).expect("sync");
    let t = laptop.state().tasks[&id].clone();
    let said: Vec<String> = t
        .messages
        .iter()
        .map(|m| m.parts[0].strings()[0].clone())
        .collect();
    assert_eq!(
        said,
        ["one", "two", "three", "four"],
        "applied once each, in sequence order"
    );
    assert_eq!(laptop.state().tasks.len(), 1);
}

#[test]
fn nothing_is_lost_when_the_network_is_down_and_a_drop_resends() {
    let (laptop, main, _) = pair();
    let id = main.ask("laptop", "t", "hello");
    let net = Net::new(&laptop, "main");
    *net.faults.borrow_mut() = Faults {
        fail: true,
        ..Faults::default()
    };
    assert!(main.node().sync("laptop", &net).is_err());
    *net.faults.borrow_mut() = Faults {
        drop_out: true,
        ..Faults::default()
    };
    main.node().sync("laptop", &net).expect("sync");
    assert!(laptop.state().tasks.is_empty());
    assert_eq!(main.state().tasks[&id].state, TState::Held);
    *net.faults.borrow_mut() = Faults {
        drop_back: true,
        ..Faults::default()
    };
    main.node().sync("laptop", &net).expect("sync");
    assert_eq!(
        laptop.state().tasks.len(),
        1,
        "delivered, but the acknowledgement was lost"
    );
    assert_eq!(main.state().tasks[&id].state, TState::Held);
    *net.faults.borrow_mut() = Faults::default();
    main.node().sync("laptop", &net).expect("sync");
    assert_eq!(main.state().tasks[&id].state, TState::Submitted);
    assert_eq!(
        laptop.state().tasks.len(),
        1,
        "the resend did not make a second task"
    );
    assert_eq!(laptop.state().tasks[&id].messages.len(), 1);
}

#[test]
fn state_survives_closing_and_reopening_the_store_and_a_crash_before_sending() {
    let (laptop, main, _) = pair();
    let id = main.ask("laptop", "t", "queued while nothing was running");
    // a new Store over the same files: nothing was in memory
    let reopened = super::store::Store::new(main.store.dir());
    assert!(reopened.read().expect("read").peers["laptop"]
        .outbox
        .iter()
        .any(|o| o.task_id == id));
    settle(&main, &laptop);
    assert_eq!(laptop.state().tasks.len(), 1);
}

// ---- replay, restore, restart ------------------------------------------------------------------------------------

#[test]
fn a_captured_envelope_replayed_is_refused_as_a_duplicate_then_as_expired() {
    let (laptop, main, clock) = pair();
    main.ask("laptop", "t", "once");
    let net = Net::new(&laptop, "main");
    main.node().sync("laptop", &net).expect("sync");
    let captured: Vec<Sealed> = net
        .captured
        .borrow()
        .iter()
        .filter(|s| s.envelope.from == "main")
        .cloned()
        .collect();
    let r = laptop.node().receive_all(&captured).expect("receive");
    assert_eq!((r.applied, r.refused.len()), (0, 0));
    assert!(r.duplicates > 0);
    assert_eq!(laptop.state().tasks.len(), 1);
    clock.set(T0 + 11 * 60 * 1000);
    let r = laptop.node().receive_all(&captured).expect("receive");
    assert!(
        r.refused.iter().all(|c| c == "envelope-expired"),
        "{:?}",
        r.refused
    );
}

#[test]
fn a_receiver_that_lost_its_state_and_was_restored_refuses_what_was_captured_before() {
    let (laptop, main, _) = pair();
    main.ask("laptop", "t", "secret-free");
    let net = Net::new(&laptop, "main");
    main.node().sync("laptop", &net).expect("sync");
    let captured: Vec<Sealed> = net
        .captured
        .borrow()
        .iter()
        .filter(|s| s.envelope.from == "main")
        .cloned()
        .collect();
    // the laptop's store is restored from an older copy: it says so, which moves its epoch
    laptop
        .store
        .update(|s| {
            s.tasks.clear();
            s.nonces.clear();
            s.restored(T0 + 1);
        })
        .expect("restore");
    let r = laptop.node().receive_all(&captured).expect("receive");
    assert_eq!(r.applied, 0);
    assert!(r.refused.iter().all(|c| c == "epoch"), "{:?}", r.refused);
    assert!(laptop.state().tasks.is_empty());
}

#[test]
fn a_sender_that_restarts_with_new_state_is_heard_again_and_an_old_incarnation_is_not() {
    let (laptop, main, clock) = pair();
    main.ask("laptop", "t", "before");
    let net = Net::new(&laptop, "main");
    main.node().sync("laptop", &net).expect("sync");
    let old: Vec<Sealed> = net
        .captured
        .borrow()
        .iter()
        .filter(|s| s.envelope.from == "main")
        .cloned()
        .collect();
    settle(&main, &laptop);
    // main's state is lost and recreated with the same keys and pins, later
    clock.set(T0 + 120_000);
    let fresh = super::state::State::new("main", &main.sign_public, &main.seal_public, clock.get());
    std::fs::remove_file(main.store.dir().join("state.json")).expect("rm");
    main.store.create(&fresh).expect("create");
    main.pin(&laptop);
    let id2 = main.ask("laptop", "t2", "after the restart");
    settle(&main, &laptop);
    assert_eq!(
        laptop.state().tasks.len(),
        2,
        "delivery did not silently stop"
    );
    assert_eq!(main.state().tasks[&id2].state, TState::Submitted);
    // what the old life sent is refused, whatever its age
    let r = laptop.node().receive_all(&old).expect("receive");
    assert_eq!(r.applied, 0);
}

#[test]
fn the_same_task_id_with_another_body_is_refused_and_raised() {
    let (laptop, main, _) = pair();
    let id = main.ask("laptop", "t", "original");
    settle(&main, &laptop);
    // craft a second task with the same id and different content, as a sender would
    main.store
        .update(|s| {
            let p = s.peers.get_mut("laptop").expect("peer");
            p.out_seq += 1;
            let seq = p.out_seq;
            let mut t = s.tasks[&id].clone();
            t.title = "other".into();
            let body = Body::Task {
                kind: TaskKind::Question,
                title: "other".into(),
                context_id: None,
                parent: None,
                deadline_ms: t.deadline_ms,
                act: None,
                approval_ref: None,
                message: t.messages[0].clone(),
            };
            s.peers
                .get_mut("laptop")
                .expect("peer")
                .outbox
                .push(Outgoing {
                    seq,
                    kind: Kind::Task,
                    task_id: id.clone(),
                    body,
                });
        })
        .expect("inject");
    settle(&main, &laptop);
    assert_eq!(
        laptop.state().tasks[&id].title,
        "t",
        "the first content stands"
    );
    assert!(laptop
        .sink
        .actions()
        .contains(&"mesh.task.conflict".to_string()));
}

#[test]
fn a_gap_beyond_the_window_is_refused_and_a_resync_is_asked_for() {
    let (laptop, main, _) = pair();
    main.ask("laptop", "t", "x");
    main.store
        .update(|s| {
            let p = s.peers.get_mut("laptop").expect("peer");
            p.out_seq += WINDOW + 5;
            let seq = p.out_seq;
            p.outbox.push(Outgoing {
                seq,
                kind: Kind::Cancel,
                task_id: "x".into(),
                body: Body::Cancel,
            });
        })
        .expect("inject");
    let r = round(&main, &laptop);
    assert!(laptop.state().peers["main"].resync_wanted, "{r:?}");
    let sent = laptop.node().outbound("main").expect("out");
    assert!(sent.iter().any(|s| s.envelope.kind == Kind::Resync));
}

// ---- checks refuse by name ---------------------------------------------------------------------------------------

fn first_task_envelope(main: &End) -> Sealed {
    main.node()
        .outbound("laptop")
        .expect("out")
        .into_iter()
        .find(|s| s.envelope.kind == Kind::Task)
        .expect("task")
}

#[test]
fn checks_refuse_by_name() {
    let (laptop, main, _) = pair();
    main.ask("laptop", "t", "x");
    let good = first_task_envelope(&main);
    let try_it = |m: Sealed| laptop.node().receive_all(&[m]).expect("receive").refused;
    assert!(
        try_it(main.forge("laptop", Kind::Hello, |_| {})).is_empty(),
        "the hello is taken first"
    );
    let mut m = good.clone();
    m.signature[0] ^= 1;
    assert_eq!(try_it(m), ["bad-signature"]);
    let mut m = good.clone();
    m.envelope.version = ENVELOPE_VERSION + 1;
    assert_eq!(try_it(m), ["version"]);
    let mut m = good.clone();
    m.envelope.to = "someone".into();
    assert_eq!(try_it(m), ["not-for-me"]);
    let mut m = good.clone();
    m.envelope.from = "stranger".into();
    assert_eq!(try_it(m), ["unknown-sender"]);
    let mut m = good.clone();
    m.envelope.receiver_fp = "0".repeat(32);
    assert_eq!(try_it(m), ["wrong-receiver"]);
    // a body tampered after signing breaks the signature
    let mut m = good.clone();
    m.envelope.body[3] ^= 1;
    assert_eq!(try_it(m), ["bad-signature"]);
    let forged = |f: &dyn Fn(&mut Envelope)| main.forge("laptop", Kind::Task, |e| f(e));
    assert_eq!(try_it(forged(&|e| e.receiver_epoch = 9)), ["epoch"]);
    assert_eq!(try_it(forged(&|e| e.ack_seq = 99)), ["ack-ahead"]);
    assert_eq!(
        try_it(forged(&|e| {
            e.ts_ms += 10 * 60 * 1000;
            e.valid_until_ms = e.ts_ms + 1000;
        })),
        ["from-the-future"]
    );
    assert_eq!(
        try_it(forged(&|e| e.valid_until_ms = e.ts_ms.saturating_sub(1))),
        ["shape:validity"]
    );
    assert_eq!(
        try_it(forged(&|e| e.kind = Kind::Message)),
        ["kind-mismatch"]
    );
    // edited after sealing and re-signed: the seal is bound to the fields, so it does not open
    let mut e = good.envelope.clone();
    e.ack_seq = 0;
    e.id = "other-id".into();
    let sig = {
        use super::wire::Signer;
        main.signer.sign(&e.canonical()).expect("sign")
    };
    assert_eq!(
        try_it(Sealed {
            envelope: e,
            signature: sig
        }),
        ["unopenable"]
    );
    assert!(
        laptop.state().tasks.is_empty(),
        "nothing was applied by any of them"
    );
    // and the untouched one still goes through
    assert_eq!(
        laptop.node().receive_all(&[good]).expect("receive").applied,
        1
    );
}

#[test]
fn a_non_hello_from_a_newer_incarnation_is_not_taken() {
    let (laptop, main, _) = pair();
    main.ask("laptop", "t", "x");
    let m = main.forge("laptop", Kind::Task, |e| e.incarnation += 5);
    let r = laptop.node().receive_all(&[m]).expect("receive");
    assert_eq!(r.refused, ["hello-needed"]);
}

// ---- a message can ask and never grant ---------------------------------------------------------------------------

#[test]
fn key_shaped_content_never_leaves_and_is_never_stored() {
    let (laptop, main, _) = pair();
    let n = NewTask {
        parts: text("here: sk_live_abcdef"),
        ..new_note("laptop")
    };
    let e = main.node().submit(n).expect_err("sender refuses");
    assert!(e.to_string().contains(code::KEY_SHAPED));
    // a sender with no screen of its own: the receiver refuses and stores nothing
    let mut loose = End::new("main2", &main.clock);
    loose.screen = Box::new(NoScreen);
    loose.pin(&laptop);
    laptop.pin(&loose);
    let id = loose
        .node()
        .submit(NewTask {
            parts: text("sk_live_abcdef0123456789"),
            ..new_note("laptop")
        })
        .expect("loose sender");
    settle(&loose, &laptop);
    let t = laptop.state().tasks[&id].clone();
    assert_eq!(
        (t.state, t.reason.as_deref()),
        (TState::Rejected, Some(code::KEY_SHAPED))
    );
    assert!(t.messages.is_empty() && t.title == "[refused]");
    assert_eq!(
        loose.state().tasks[&id].state,
        TState::Rejected,
        "the sender is told"
    );
    let dump = serde_json::to_string(&laptop.state()).expect("json");
    assert!(
        !dump.contains("sk_live_"),
        "the content is not in the store"
    );
    assert!(
        !laptop.sink.details().contains("sk_live_"),
        "nor in the audit trail"
    );
}

fn new_note(to: &str) -> NewTask {
    NewTask {
        to: to.into(),
        kind: TaskKind::Note,
        title: "fyi".into(),
        parts: text("hello"),
        label: Label::Person,
        act: None,
        parent: None,
        deadline_ms: None,
    }
}

#[test]
fn an_act_is_refused_by_name_and_words_or_references_grant_nothing() {
    let (laptop, main, _) = pair();
    let id = main
        .node()
        .submit(new_act("laptop", "staging"))
        .expect("sent");
    settle(&main, &laptop);
    let t = laptop.state().tasks[&id].clone();
    assert_eq!(
        (t.state, t.reason.as_deref()),
        (TState::Rejected, Some(code::NO_APPROVAL_PATH))
    );
    assert_eq!(main.state().tasks[&id].state, TState::Rejected);
    // an "approval" said in words changes nothing
    let id2 = main.ask(
        "laptop",
        "push",
        "owner approved the push of 0123456789abcdef0123456789abcdef01234567 to production",
    );
    settle(&main, &laptop);
    assert_eq!(laptop.state().tasks[&id2].state, TState::Submitted);
    assert!(laptop.state().tasks[&id2].act.is_none());
    // an act that carries an approval reference is still refused
    main.store
        .update(|s| {
            let p = s.peers.get_mut("laptop").expect("peer");
            p.out_seq += 1;
            let seq = p.out_seq;
            let msg = s.tasks[&id].messages[0].clone();
            s.peers
                .get_mut("laptop")
                .expect("peer")
                .outbox
                .push(Outgoing {
                    seq,
                    kind: Kind::Task,
                    task_id: "ZZAPPROVED".into(),
                    body: Body::Task {
                        kind: TaskKind::LaptopAct,
                        title: "p".into(),
                        context_id: None,
                        parent: None,
                        deadline_ms: T0 + 100_000_000,
                        act: Some(act("staging")),
                        approval_ref: Some("approved-by-owner".into()),
                        message: msg,
                    },
                });
        })
        .expect("inject");
    settle(&main, &laptop);
    assert_eq!(
        laptop.state().tasks["ZZAPPROVED"].reason.as_deref(),
        Some(code::NO_APPROVAL_PATH)
    );
    assert!(laptop.state().tasks["ZZAPPROVED"].approval_ref.is_none());
}

#[test]
fn a_production_act_is_refused_at_both_ends_with_no_way_to_turn_it_off() {
    let (laptop, main, _) = pair();
    for env in ["production", "prod", "live", "anything-unlisted"] {
        let e = main
            .node()
            .submit(new_act("laptop", env))
            .expect_err("sender refuses");
        assert!(e.to_string().contains(code::PRODUCTION), "{env}: {e}");
    }
    // a sender that bypasses its own check: the receiver refuses too
    main.store
        .update(|s| {
            let p = s.peers.get_mut("laptop").expect("peer");
            p.out_seq += 1;
            let seq = p.out_seq;
            let msg = super::model::Message {
                id: "m".into(),
                from: "main".into(),
                ts_ms: T0,
                label: Label::Fleet,
                parts: text("x"),
            };
            p.outbox.push(Outgoing {
                seq,
                kind: Kind::Task,
                task_id: "PRODTASK".into(),
                body: Body::Task {
                    kind: TaskKind::LaptopAct,
                    title: "p".into(),
                    context_id: None,
                    parent: None,
                    deadline_ms: T0 + 100_000_000,
                    act: Some(act("production")),
                    approval_ref: None,
                    message: msg,
                },
            });
        })
        .expect("inject");
    settle(&main, &laptop);
    assert_eq!(
        laptop.state().tasks["PRODTASK"].reason.as_deref(),
        Some(code::PRODUCTION)
    );
}

#[test]
fn only_the_receiver_moves_a_state_and_a_finished_task_stays_finished() {
    let (laptop, main, _) = pair();
    let id = main.ask("laptop", "t", "x");
    settle(&main, &laptop);
    // the sender cannot say the task is completed
    let e = main
        .node()
        .reply(
            &id,
            Vec::new(),
            Label::Person,
            Some((TState::Completed, None)),
        )
        .expect_err("refused");
    assert!(e.to_string().contains("state-not-yours-to-move"));
    // the receiver cannot move backwards
    laptop
        .node()
        .reply(
            &id,
            text("ok"),
            Label::Person,
            Some((TState::Completed, None)),
        )
        .expect("complete");
    assert!(laptop
        .node()
        .reply(
            &id,
            text("more"),
            Label::Person,
            Some((TState::Working, None))
        )
        .is_err());
    // a forged Status from the sender side is ignored by the receiver
    main.store
        .update(|s| {
            let p = s.peers.get_mut("laptop").expect("peer");
            p.out_seq += 1;
            let seq = p.out_seq;
            p.outbox.push(Outgoing {
                seq,
                kind: Kind::Status,
                task_id: id.clone(),
                body: Body::Status {
                    state: TState::Working,
                    reason: None,
                },
            });
        })
        .expect("inject");
    settle(&main, &laptop);
    settle(&laptop, &main);
    assert_eq!(laptop.state().tasks[&id].state, TState::Completed);
    assert_eq!(main.state().tasks[&id].state, TState::Completed);
}

#[test]
fn cancel_before_delivery_and_after() {
    let (laptop, main, _) = pair();
    let id = main.ask("laptop", "t", "x");
    main.node().cancel(&id).expect("cancel");
    assert_eq!(main.state().tasks[&id].state, TState::Canceled);
    settle(&main, &laptop);
    assert_eq!(
        laptop.state().tasks[&id].state,
        TState::Canceled,
        "the request reached the receiver"
    );
    // a running task: the receiver decides
    let id2 = main.ask("laptop", "t2", "y");
    settle(&main, &laptop);
    laptop
        .node()
        .reply(
            &id2,
            Vec::new(),
            Label::Person,
            Some((TState::Working, None)),
        )
        .expect("working");
    settle(&laptop, &main);
    main.node().cancel(&id2).expect("cancel");
    assert_eq!(
        main.state().tasks[&id2].state,
        TState::Working,
        "a cancel is a request"
    );
    settle(&main, &laptop);
    settle(&laptop, &main);
    assert_eq!(main.state().tasks[&id2].state, TState::Canceled);
}

#[test]
fn limits_stop_a_flood_and_a_deadline_ends_a_task() {
    let (laptop, main, clock) = pair();
    for i in 0..25 {
        main.ask("laptop", &format!("t{i}"), "x");
    }
    settle(&main, &laptop);
    let rejected = laptop
        .state()
        .tasks
        .values()
        .filter(|t| t.reason.as_deref() == Some(code::RATE))
        .count();
    assert_eq!(rejected, 5, "20 a minute, the rest refused by name");
    let id = main
        .node()
        .submit(NewTask {
            deadline_ms: Some(T0 + 1000),
            ..new_note("laptop")
        })
        .expect("sent");
    clock.set(T0 + 3_000_000);
    let net = Net::new(&laptop, "main");
    *net.faults.borrow_mut() = Faults {
        fail: true,
        ..Faults::default()
    };
    let _ = main.node().sync("laptop", &net);
    let t = main.state().tasks[&id].clone();
    assert_eq!(
        (t.state, t.reason.as_deref()),
        (TState::Failed, Some(code::EXPIRED))
    );
}

#[test]
fn the_audit_trail_names_acts_and_never_carries_text_and_is_written_once() {
    let (laptop, main, _) = pair();
    main.ask("laptop", "a private title", "private body text");
    settle(&main, &laptop);
    settle(&laptop, &main);
    for e in [&laptop, &main] {
        let d = e.sink.details();
        assert!(!d.contains("private"), "{d}");
        assert!(
            e.state().audit.is_empty(),
            "pending events were handed over"
        );
    }
    assert!(main.sink.actions().contains(&"mesh.task.sent".to_string()));
    assert!(laptop
        .sink
        .actions()
        .contains(&"mesh.task.received".to_string()));
    let n = laptop.sink.actions().len();
    laptop.node().drain_audit().expect("drain");
    assert_eq!(laptop.sink.actions().len(), n);
}

#[test]
fn why_names_the_state_and_the_next_actor() {
    let (laptop, main, clock) = pair();
    let id = main.ask("laptop", "t", "x");
    let w = main.state().why(&id, clock.get()).join(" ");
    assert!(w.contains("held") && w.contains("ozbox tasks sync"), "{w}");
    settle(&main, &laptop);
    let w = laptop.state().why(&id, clock.get()).join(" ");
    assert!(w.contains("waiting for you"), "{w}");
    let rid = main
        .node()
        .submit(new_act("laptop", "staging"))
        .expect("sent");
    settle(&main, &laptop);
    let w = main.state().why(&rid, clock.get()).join(" ");
    assert!(w.contains("passkey"), "{w}");
}

#[test]
fn text_from_a_peer_is_made_printable() {
    assert_eq!(printable("ok\u{1b}[31mred\r\nline"), "ok[31mred\nline");
}

#[test]
fn the_wire_form_is_pinned_while_it_is_in_preview() {
    let e = Envelope {
        version: ENVELOPE_VERSION,
        kind: Kind::Task,
        from: "a".into(),
        to: "b".into(),
        receiver_fp: "fp".into(),
        sender_epoch: 1,
        receiver_epoch: 2,
        incarnation: 3,
        seq: 4,
        ack_seq: 5,
        id: "id".into(),
        task_id: "t".into(),
        ts_ms: 6,
        valid_until_ms: 7,
        nonce: vec![9; 16],
        body: vec![1, 2, 3],
    };
    assert_eq!(e.digest_hex(), GOLDEN);
    // every field is covered by the signature
    let mut f = e.clone();
    f.receiver_epoch = 3;
    assert_ne!(f.canonical(), e.canonical());
    let mut f = e.clone();
    f.incarnation = 4;
    assert_ne!(f.canonical(), e.canonical());
    assert_eq!(Kind::ALL.len(), 7);
    let names: Vec<_> = Kind::ALL.iter().map(|k| k.name()).collect();
    assert_eq!(
        names,
        ["hello", "task", "message", "status", "artifact", "cancel", "resync"]
    );
}

const GOLDEN: &str = "9c8e4a37f6baf905ef70c661c745a00b12215b0824a1b634ecbc4369820c014b";

#[test]
fn a_verdict_is_shaped_for_callers() {
    assert_eq!(Verdict::Duplicate, Verdict::Duplicate);
    let _: &dyn Screen = &TestScreen;
}
