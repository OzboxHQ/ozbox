use super::*;
use crate::approval_subject::{
    BoxSecrets, Challenge, Classification, EnrolAction, GuardHook, GuardMatch, HostGuard, Import,
    ImportName, PolicyChange, SignerEnroll, TunnelToken, RULE_PRODUCTION_LOOKING,
};

use crate::approval_verify::tests::{key_for, laptop_evidence, passkey_evidence, Signer};

const T0: u64 = 1_000_000_000;

thread_local! {
    /// The real signing key behind each test KeyView, by its public half.
    static SIGNERS: std::cell::RefCell<std::collections::HashMap<String, Signer>> = std::cell::RefCell::new(std::collections::HashMap::new());
}

fn ids() -> Ids {
    Ids {
        box_id: "box-1".into(),
        store_id: "store-1".into(),
    }
}

fn ctx() -> Ctx {
    Ctx {
        ids: ids(),
        enrolled: true,
        ever_key: false,
        ever_presence_key: false,
    }
}

fn hex64(c: char) -> String {
    std::iter::repeat_n(c, 64).collect()
}

fn guard(tree: char, matches: Vec<GuardMatch>) -> Subject {
    Subject::GuardOverride(GuardHook::Commit {
        repo_path_hash: hex64('1'),
        hook_kind: "pre-commit".into(),
        tree_id: tree.to_string().repeat(40),
        matches,
        scanned_text_hash: hex64('2'),
    })
}

fn tunnel(token: char) -> Subject {
    Subject::TunnelToken(TunnelToken {
        kind: "ide".into(),
        token_sha256: hex64(token),
        account_tag: "acct1".into(),
        tunnel_id: "tun1".into(),
    })
}

fn import(env: &str, class: Classification) -> Subject {
    Subject::Import(Import {
        project: "app".into(),
        environment: env.into(),
        production: false,
        names: vec![ImportName {
            name: "API_KEY".into(),
            classification: class,
            value_digest: hex64('a'),
        }],
        store_generation: 1,
    })
}

fn policy(s: PolicySensitivity) -> Subject {
    Subject::Policy(PolicyChange {
        policy_sha256: hex64('d'),
        predecessor_sha256: hex64('e'),
        sensitivity: s,
    })
}

fn enrol(action: EnrolAction) -> Subject {
    Subject::SignerEnroll(SignerEnroll {
        action,
        key_name: "laptop-2".into(),
        key_type: "ed25519".into(),
        public_half: hex64('9'),
        attestation_digest: String::new(),
    })
}

fn box_user(uid: u32) -> Requester {
    Requester::new(RequesterKind::BoxUser, Some(uid))
}
fn root_helper() -> Requester {
    Requester::new(RequesterKind::RootHelper, Some(0))
}
fn laptop(key: &str) -> Requester {
    let mut r = Requester::new(RequesterKind::LaptopKey, None);
    r.key_id = Some(key.into());
    r
}

fn book() -> RequestBook {
    RequestBook::new("epoch-1".into())
}

fn filing(id: &str, subject: Subject, requester: Requester) -> Filing<'static> {
    // the service works a policy's sensitivity out itself; a test that files one plays that part
    let derived = Derived {
        policy_sensitivity: match &subject {
            Subject::Policy(p) => Some(p.sensitivity),
            _ => None,
        },
        ..Derived::default()
    };
    Filing {
        id: id.into(),
        subject,
        requester,
        reason: None,
        derived,
    }
}

/// A filing with other derived facts, keeping the policy sensitivity the helper above worked out.
fn with(f: Filing<'static>, d: Derived) -> Filing<'static> {
    Filing {
        derived: Derived {
            policy_sensitivity: f.derived.policy_sensitivity,
            ..d
        },
        ..f
    }
}

fn file(b: &mut RequestBook, now: u64, f: Filing<'static>) -> Request {
    b.file(&ctx(), now, f).unwrap().request
}

fn root_decide(outcome: Outcome) -> DecideInput {
    DecideInput {
        class: SocketClass::Admin,
        outcome,
        surface: Surface::Root,
        factor: Factor::Root,
        decider: "root".into(),
        role: None,
        evidence: Evidence::default(),
        key: None,
        passkey_rp: None,
        via_fleet: None,
    }
}

#[allow(clippy::too_many_arguments)]
fn passkey_decide(
    b: &RequestBook,
    c: &Ctx,
    id: &str,
    role: Role,
    person: &str,
    cred: &str,
    sig: &str,
    counter: u32,
) -> DecideInput {
    DecideInput {
        class: SocketClass::Supervisor,
        outcome: Outcome::Approve,
        surface: Surface::Dashboard,
        factor: Factor::Passkey,
        decider: person.into(),
        role: Some(role),
        evidence: Evidence {
            passkey: Some(passkey_evidence(
                cred,
                sig,
                0x05, // a touch and user verification, as the dashboard requires
                counter,
                &b.challenge_for(c, id, Outcome::Approve).unwrap(),
            )),
            laptop: None,
        },
        key: None,
        passkey_rp: Some(crate::approval_verify::tests::test_rp()),
        via_fleet: None,
    }
}

fn key(id: &str, t: KeyType, proved: bool) -> KeyView {
    let signer = Signer::new(t);
    let k = key_for(id, t, &signer, proved);
    SIGNERS.with(|m| m.borrow_mut().insert(k.public_half.clone(), signer));
    k
}

/// A laptop decision with a REAL signature in the key type's format, over this request's own message.
fn laptop_decide(
    b: &RequestBook,
    c: &Ctx,
    id: &str,
    k: &KeyView,
    up: bool,
    uv: bool,
    counter: Option<u32>,
) -> DecideInput {
    laptop_decide_as(b, c, id, k, Outcome::Approve, "approve", up, uv, counter)
}

/// The same for any outcome: `word` is the outcome word the signature covers, `outcome` what the caller says it is.
#[allow(clippy::too_many_arguments)]
fn laptop_decide_as(
    b: &RequestBook,
    c: &Ctx,
    id: &str,
    k: &KeyView,
    outcome: Outcome,
    word: &str,
    up: bool,
    uv: bool,
    counter: Option<u32>,
) -> DecideInput {
    let digest = from_hex(&b.get(id).unwrap().subject_digest).unwrap();
    let mut d32 = [0u8; 32];
    d32.copy_from_slice(&digest);
    let flags = u8::from(up) | if uv { 0x04 } else { 0 };
    let ev = SIGNERS.with(|m| {
        laptop_evidence(
            k,
            m.borrow().get(&k.public_half).unwrap(),
            &c.ids,
            id,
            &d32,
            word,
            flags,
            counter.unwrap_or(0),
        )
    });
    DecideInput {
        class: SocketClass::Ingress,
        outcome,
        surface: Surface::Laptop,
        factor: Factor::LaptopKey,
        decider: "claimed-by-the-caller".into(),
        role: None,
        evidence: Evidence {
            passkey: None,
            laptop: Some(ev),
        },
        key: Some(k.clone()),
        passkey_rp: None,
        via_fleet: None,
    }
}

fn spend_box(
    b: &mut RequestBook,
    now: u64,
    id: &str,
    uid: u32,
    s: &Subject,
) -> Result<Request, SpendRefusal> {
    b.begin_spend(
        &ctx(),
        now,
        id,
        SpendVia::Socket {
            class: SocketClass::Box,
            uid: Some(uid),
        },
        s,
        &|_| true,
    )
}

// ---- the table ----------------------------------------------------------------------------------------------------

#[test]
fn the_table_has_a_row_for_every_scope_and_an_unknown_scope_has_none() {
    for s in Scope::ALL {
        assert!(rule_for(s.as_str()).is_some(), "{}", s.as_str());
        assert_eq!(Scope::parse(s.as_str()), Some(s));
    }
    assert!(rule_for("something-new").is_none());
    assert_eq!(Scope::parse("agent-action"), None);
    // the three agent rows are for the inbox, not the journal
    assert!(!rule_for("agent-action").unwrap().journal);
    assert_eq!(
        rule_for("agent-action").unwrap().telegram,
        Telegram::NotifyOnly
    );
    assert_eq!(
        rule_for("agent-action-protected").unwrap().telegram,
        Telegram::NotifyOnly
    );
    // a chat decides nothing, on any row, the ordinary agent action included
    for r in RULES.iter() {
        assert_eq!(r.telegram, Telegram::NotifyOnly, "{}", r.key);
    }
    // the nine gated scopes of the ADR plus worker-keys are the journal's
    let journal: Vec<&str> = RULES.iter().filter(|r| r.journal).map(|r| r.key).collect();
    assert_eq!(journal.len(), 10);
    assert!(!journal.contains(&"secret-use"));
}

#[test]
fn a_software_key_never_decides_tunnel_host_guard_enrol_or_the_two_laptop_only_scopes() {
    for k in [
        "tunnel-token",
        "host-guard",
        "signer-enroll",
        "setup-code",
        "kek-export",
        "secret-use",
    ] {
        assert_eq!(rule_for(k).unwrap().software, Soft::Never, "{k}");
    }
    // the box socket may only file a guard override
    for r in RULES.iter().filter(|r| r.journal) {
        assert_eq!(
            r.filers.contains(&RequesterKind::BoxUser),
            r.key == "guard-override",
            "{}",
            r.key
        );
    }
    // the dashboard cannot decide the two laptop-only scopes
    assert_eq!(
        rule_for("kek-export").unwrap().dashboard,
        Dash::NotDecidable
    );
    assert_eq!(
        rule_for("setup-code").unwrap().dashboard,
        Dash::NotDecidable
    );
}

#[test]
fn the_sockets_offer_exactly_the_operations_of_the_adr() {
    use Op::*;
    use SocketClass::*;
    // the box socket never decides, and spends only through the hook
    assert!(!op_allowed(Box, Decide));
    assert!(!op_allowed(Box, DecideChallenge));
    assert!(!op_allowed(Box, Cancel));
    assert!(!op_allowed(Box, NewEpoch));
    for o in [File, Get, List, Await, Spend, Finish] {
        assert!(op_allowed(Box, o));
    }
    // the supervisor decides, and neither files nor spends
    for o in [List, Get, DecideChallenge, Decide, Cancel, DeciderRevoked] {
        assert!(op_allowed(Supervisor, o));
    }
    for o in [File, Spend, Await, NewEpoch] {
        assert!(!op_allowed(Supervisor, o));
    }
    // the hub agent lists, reads and relays
    for o in [File, Spend, Await, Cancel, DecideChallenge] {
        assert!(!op_allowed(HubAgent, o));
    }
    assert!(op_allowed(HubAgent, Decide));
    assert!(op_allowed(Admin, NewEpoch));
}

#[test]
fn the_typescript_export_has_every_row_and_the_journal_scopes() {
    let ts = rule_table_ts();
    for r in RULES {
        assert!(ts.contains(&format!("scope: '{}'", r.key)), "{}", r.key);
    }
    assert!(ts.contains("export const APPROVAL_REQUEST_SCOPES = ['import', 'policy'"));
    assert!(!ts.contains("APPROVAL_REQUEST_SCOPES = ['import', 'policy', 'tunnel-token', 'guard-override', 'signer-enroll', 'box-secrets', 'host-guard', 'setup-code', 'kek-export', 'worker-keys', 'secret-use'"));
}

// ---- filing, slots, dedup ------------------------------------------------------------------------------------------

#[test]
fn a_request_is_pending_for_thirty_minutes_then_expires() {
    let mut b = book();
    let r = file(&mut b, T0, filing("r1", guard('a', vec![]), box_user(1000)));
    assert_eq!(r.state, State::Pending);
    assert_eq!(r.expires_at_ms, T0 + 30 * 60_000);
    b.sweep(T0 + 30 * 60_000 - 1);
    assert_eq!(b.get("r1").unwrap().state, State::Pending);
    let gone = b.sweep(T0 + 30 * 60_000);
    assert_eq!(gone, vec!["r1".to_string()]);
    assert_eq!(b.get("r1").unwrap().state, State::Expired);
    // decide after expiry is refused
    let e = b
        .decide(
            &ctx(),
            T0 + 30 * 60_000 + 1,
            "r1",
            root_decide(Outcome::Approve),
        )
        .unwrap_err();
    assert!(e.contains("expired"), "{e}");
}

#[test]
fn only_the_scopes_filers_may_file_it() {
    let mut b = book();
    let e = b
        .file(
            &ctx(),
            T0,
            filing(
                "r1",
                import("staging", Classification::Secret),
                box_user(1000),
            ),
        )
        .unwrap_err();
    assert!(e.contains("cannot be filed by the box-user"), "{e}");
    let e = b
        .file(&ctx(), T0, filing("r2", tunnel('c'), box_user(1000)))
        .unwrap_err();
    assert!(e.contains("cannot be filed"), "{e}");
    assert!(b.requests.is_empty());
    // a scope kept by its own gate is not filed here: secret-use has no subject at all
    assert!(rule_for("secret-use").is_some_and(|r| !r.journal));
}

#[test]
fn the_same_change_in_the_same_slot_is_the_same_request_and_never_across_requester_kinds() {
    let mut b = book();
    let a = file(&mut b, T0, filing("r1", guard('a', vec![]), box_user(1000)));
    let again = b
        .file(
            &ctx(),
            T0 + 5,
            filing("r2", guard('a', vec![]), box_user(1000)),
        )
        .unwrap();
    assert!(again.existing);
    assert_eq!(again.request.id, a.id);
    assert_eq!(b.requests.len(), 1);
    // another uid is another slot: its own request
    let other = b
        .file(
            &ctx(),
            T0 + 6,
            filing("r3", guard('a', vec![]), box_user(1001)),
        )
        .unwrap();
    assert!(!other.existing);
    assert_ne!(other.request.slot, a.slot);
}

#[test]
fn a_lookalike_in_the_slot_supersedes_a_pending_one_but_never_burns_or_swaps_an_approved_one() {
    let mut b = book();
    let a = file(&mut b, T0, filing("r1", guard('a', vec![]), box_user(1000)));
    // an agent files a second, different change in the same slot while the first is pending: the first is superseded
    let second = file(
        &mut b,
        T0 + 10,
        filing("r2", guard('b', vec![]), box_user(1000)),
    );
    assert_eq!(b.get(&a.id).unwrap().state, State::Superseded);
    assert_eq!(b.get(&a.id).unwrap().superseded_by.as_deref(), Some("r2"));
    assert_eq!(second.replaces, None);

    // the person approves the second; a lookalike then arrives
    b.decide(&ctx(), T0 + 20, "r2", root_decide(Outcome::Approve))
        .unwrap();
    let look = file(
        &mut b,
        T0 + 30,
        filing("r3", guard('c', vec![]), box_user(1000)),
    );
    // the approved request is neither burned nor swapped: it stays approved and is spendable for its own digest
    assert_eq!(b.get("r2").unwrap().state, State::Approved);
    assert_eq!(look.replaces.as_deref(), Some("r2"));
    assert_eq!(look.state, State::Pending);
    let spent = spend_box(&mut b, T0 + 40, "r2", 1000, &guard('b', vec![])).unwrap();
    assert_eq!(spent.state, State::Spending);
    // the lookalike's approval would have superseded the old one: approving r3 supersedes any approved sibling
}

#[test]
fn approving_the_replacement_supersedes_the_old_approval() {
    let mut b = book();
    file(&mut b, T0, filing("r1", guard('a', vec![]), box_user(1000)));
    b.decide(&ctx(), T0 + 1, "r1", root_decide(Outcome::Approve))
        .unwrap();
    file(
        &mut b,
        T0 + 2,
        filing("r2", guard('b', vec![]), box_user(1000)),
    );
    assert_eq!(b.get("r1").unwrap().state, State::Approved);
    b.decide(&ctx(), T0 + 3, "r2", root_decide(Outcome::Approve))
        .unwrap();
    assert_eq!(b.get("r1").unwrap().state, State::Superseded);
    assert_eq!(b.get("r2").unwrap().state, State::Approved);
}

#[test]
fn a_flood_from_the_box_socket_is_bounded_and_a_person_filing_is_outside_the_budget() {
    let mut b = book();
    // eight pending of one scope from different uids is the cap
    for i in 0..MAX_PENDING_PER_SCOPE as u32 {
        file(
            &mut b,
            T0,
            filing(&format!("r{i}"), guard('a', vec![]), box_user(2000 + i)),
        );
    }
    let e = b
        .file(&ctx(), T0, filing("rx", guard('a', vec![]), box_user(3000)))
        .unwrap_err();
    assert!(e.contains("too many requests of this kind"), "{e}");
    // a person's path (the laptop) is not counted against it: tunnel-token is another scope, by the root helper
    assert!(b
        .file(&ctx(), T0, filing("ry", tunnel('c'), root_helper()))
        .is_ok());

    // thirty filings an hour from one uid, then refused
    let mut b = book();
    for i in 0..FILINGS_PER_HOUR {
        // each in its own slot (a different tree is a different digest in one slot, which supersedes the last pending one)
        let t = format!("{i:040x}");
        let s = Subject::GuardOverride(GuardHook::Commit {
            repo_path_hash: hex64('1'),
            hook_kind: "pre-commit".into(),
            tree_id: t,
            matches: vec![],
            scanned_text_hash: hex64('2'),
        });
        b.file(
            &ctx(),
            T0 + i as u64,
            filing(&format!("r{i}"), s, box_user(1000)),
        )
        .unwrap();
    }
    let s = guard('f', vec![]);
    let e = b
        .file(&ctx(), T0 + 100, filing("late", s.clone(), box_user(1000)))
        .unwrap_err();
    assert!(e.contains("last hour"), "{e}");
    // an hour later it can file again
    assert!(b
        .file(&ctx(), T0 + 3_700_000, filing("later", s, box_user(1000)))
        .is_ok());
}

#[test]
fn the_reason_is_plain_capped_text_and_a_card_is_derived_from_the_subject() {
    let mut b = book();
    let long = format!("ship it\u{202e}{}", "x".repeat(400));
    let f = Filing {
        reason: Some(&long),
        ..filing("r1", guard('a', vec![]), box_user(1000))
    };
    let r = b.file(&ctx(), T0, f).unwrap().request;
    let reason = r.reason.unwrap();
    assert!(reason.chars().count() <= MAX_REASON);
    assert!(!reason.contains('\u{202e}'));
    assert!(r.display.iter().any(|d| d.label == "Change"));
}

// ---- bootstrap -----------------------------------------------------------------------------------------------------

#[test]
fn before_a_second_factor_exists_the_scopes_rule_decides_and_the_record_says_bootstrap() {
    let mut c = ctx();
    c.enrolled = false;
    let mut b = book();
    let r = b
        .file(&c, T0, filing("r1", tunnel('a'), root_helper()))
        .unwrap()
        .request;
    assert_eq!(r.state, State::Approved);
    let d = r.decision.unwrap();
    assert_eq!(d.factor, Factor::Bootstrap);
    // a guard override is refused too: the box user would be approving its own
    let e = b
        .file(&c, T0, filing("r0", guard('a', vec![]), box_user(1000)))
        .unwrap_err();
    assert!(e.contains("no second factor"), "{e}");
    assert_eq!(d.factor_label, "bootstrap");
    assert_eq!(d.surface, Surface::Bootstrap);
    // host-guard and signer-enroll are refused with no approver
    let hg = Subject::HostGuard(HostGuard {
        action: "open-port".into(),
        loosening: true,
        fields: vec![("port".into(), "8080".into())],
    });
    let e = b.file(&c, T0, filing("r2", hg, root_helper())).unwrap_err();
    assert!(e.contains("no second factor"), "{e}");
    assert!(b
        .file(
            &c,
            T0,
            filing("r3", enrol(EnrolAction::Enrol), root_helper())
        )
        .is_err());
    // box-secrets: a first setting only
    let bs = |first: bool| {
        Subject::BoxSecrets(BoxSecrets {
            address: "a1".into(),
            action: "set".into(),
            change_digest: hex64('3'),
            first_setting: first,
        })
    };
    assert!(b
        .file(&c, T0, filing("r4", bs(false), root_helper()))
        .is_err());
    assert_eq!(
        b.file(&c, T0, filing("r5", bs(true), root_helper()))
            .unwrap()
            .request
            .state,
        State::Approved
    );
}

// ---- deciding ------------------------------------------------------------------------------------------------------

#[test]
fn the_box_socket_cannot_decide_so_a_request_is_never_approved_by_its_requester() {
    let mut b = book();
    file(&mut b, T0, filing("r1", guard('a', vec![]), box_user(1000)));
    let mut i = root_decide(Outcome::Approve);
    i.class = SocketClass::Box;
    let e = b.decide(&ctx(), T0 + 1, "r1", i).unwrap_err();
    assert!(e.contains("cannot decide"), "{e}");
    assert_eq!(b.get("r1").unwrap().state, State::Pending);
    // not by a laptop key that filed it either
    let mut b = book();
    file(
        &mut b,
        T0,
        filing("s1", enrol(EnrolAction::Revoke), laptop("kk")),
    );
    let k = key("kk", KeyType::SkEd25519, true);
    let e = b
        .decide(
            &ctx(),
            T0 + 1,
            "s1",
            laptop_decide(&b, &ctx(), "s1", &k, true, true, Some(1)),
        )
        .unwrap_err();
    assert!(e.contains("never approves its own"), "{e}");
}

#[test]
fn two_people_at_once_the_first_wins_and_the_second_is_told_who_and_how() {
    let mut b = book();
    let c = ctx();
    file(&mut b, T0, filing("r1", guard('a', vec![]), box_user(1000)));
    let i = passkey_decide(&b, &c, "r1", Role::Member, "alice", "cred-a", "sig-a", 5);
    b.decide(&c, T0 + 1, "r1", i).unwrap();
    let i2 = passkey_decide(&b, &c, "r1", Role::Owner, "bob", "cred-b", "sig-b", 3);
    let e = b.decide(&c, T0 + 2, "r1", i2).unwrap_err();
    assert!(
        e.contains("already approved by alice on the dashboard (passkey)"),
        "{e}"
    );
    // a deny racing an approve: the first wins (here the approve), and the deny of an approved one is a revoke
    let d = b.get("r1").unwrap().decision.clone().unwrap();
    assert_eq!(d.decider, "alice");
    assert_eq!(d.presence, PresenceClass::NotApplicable);
}

#[test]
fn a_dashboard_decision_needs_the_assertion_for_this_request_box_and_digest_once() {
    let mut b = book();
    let c = ctx();
    file(&mut b, T0, filing("r1", guard('a', vec![]), box_user(1000)));
    file(&mut b, T0, filing("r2", guard('b', vec![]), box_user(1001)));
    // an assertion made for r2 does not decide r1
    let mut wrong = passkey_decide(&b, &c, "r2", Role::Member, "alice", "cred-a", "sig-a", 0);
    let e = b.decide(&c, T0 + 1, "r1", wrong.clone()).unwrap_err();
    assert!(e.contains("another request"), "{e}");
    // nor on another box
    let other = Ctx {
        ids: Ids {
            box_id: "box-2".into(),
            store_id: "store-1".into(),
        },
        ..ctx()
    };
    wrong = passkey_decide(
        &b,
        &other,
        "r1",
        Role::Member,
        "alice",
        "cred-a",
        "sig-a",
        0,
    );
    assert!(b.decide(&c, T0 + 1, "r1", wrong).is_err());
    // the right one decides r1; an assertion is for one request, so the same credential's assertion over r1's challenge does
    // not decide r2 (the challenge names the request), while its own assertion over r2's does
    let ok = passkey_decide(&b, &c, "r1", Role::Member, "alice", "cred-a", "sig-a", 0);
    b.decide(&c, T0 + 2, "r1", ok.clone()).unwrap();
    let e = b.decide(&c, T0 + 3, "r2", ok).unwrap_err();
    assert!(e.contains("another request"), "{e}");
    // and what is remembered is the request and the credential, never the signature bytes
    assert_eq!(
        b.seen,
        vec![assertion_hash("cred-a", "r1", Outcome::Approve)]
    );
    b.decide(
        &c,
        T0 + 3,
        "r2",
        passkey_decide(&b, &c, "r2", Role::Member, "alice", "cred-a", "sig-b", 0),
    )
    .unwrap();
    // a request filed after a challenge was issued cannot be decided by it: the challenge names the request id
    assert_ne!(
        b.challenge_for(&c, "r1", Outcome::Approve).unwrap(),
        b.challenge_for(&c, "r2", Outcome::Approve).unwrap()
    );
    // the challenge names the outcome: an assertion made to deny is not one that approves
    assert_ne!(
        b.challenge_for(&c, "r1", Outcome::Approve).unwrap(),
        b.challenge_for(&c, "r1", Outcome::Deny).unwrap()
    );
    assert_ne!(
        b.challenge_for(&c, "r1", Outcome::Deny).unwrap(),
        b.challenge_for(&c, "r1", Outcome::Revoke).unwrap()
    );
}

#[test]
fn the_counter_is_checked_when_non_zero_and_a_zero_counter_is_accepted() {
    let mut b = book();
    let c = ctx();
    for (i, u) in (1..=4u32).zip(1000..) {
        file(
            &mut b,
            T0,
            filing(
                &format!("r{i}"),
                guard((b'a' + i as u8) as char, vec![]),
                box_user(u),
            ),
        );
    }
    b.decide(
        &c,
        T0 + 1,
        "r1",
        passkey_decide(&b, &c, "r1", Role::Member, "a", "cred", "s1", 7),
    )
    .unwrap();
    // goes back: refused
    let e = b
        .decide(
            &c,
            T0 + 2,
            "r2",
            passkey_decide(&b, &c, "r2", Role::Member, "a", "cred", "s2", 7),
        )
        .unwrap_err();
    assert!(e.contains("counter went back"), "{e}");
    let e = b
        .decide(
            &c,
            T0 + 2,
            "r2",
            passkey_decide(&b, &c, "r2", Role::Member, "a", "cred", "s3", 6),
        )
        .unwrap_err();
    assert!(e.contains("counter went back"), "{e}");
    // forward: accepted; zero (a synced passkey): accepted, and does not reset the stored counter
    b.decide(
        &c,
        T0 + 3,
        "r2",
        passkey_decide(&b, &c, "r2", Role::Member, "a", "cred", "s4", 8),
    )
    .unwrap();
    b.decide(
        &c,
        T0 + 4,
        "r3",
        passkey_decide(&b, &c, "r3", Role::Member, "a", "cred", "s5", 0),
    )
    .unwrap();
    assert_eq!(b.counters.get("passkey:cred"), Some(&8));
    // a wrong answer never burns the request
    assert_eq!(b.get("r4").unwrap().state, State::Pending);
}

#[test]
fn a_viewer_never_decides_telegram_never_approves_and_an_authenticator_code_is_not_a_factor() {
    let mut b = book();
    let c = ctx();
    file(&mut b, T0, filing("r1", guard('a', vec![]), box_user(1000)));
    let v = passkey_decide(&b, &c, "r1", Role::Viewer, "vic", "cv", "sv", 0);
    assert!(b
        .decide(&c, T0 + 1, "r1", v)
        .unwrap_err()
        .contains("viewer"));
    let mut t = passkey_decide(&b, &c, "r1", Role::Owner, "olga", "co", "so", 0);
    t.surface = Surface::Telegram;
    assert!(b
        .decide(&c, T0 + 1, "r1", t)
        .unwrap_err()
        .contains("Telegram never approves"));
    // there is no factor for a code: the only ways to approve are the passkey, a laptop key and root
    let mut x = root_decide(Outcome::Approve);
    x.factor = Factor::ChatDeny;
    assert!(b.decide(&c, T0 + 1, "r1", x).is_err());
    let mut x = root_decide(Outcome::Approve);
    x.factor = Factor::Bootstrap;
    assert!(b.decide(&c, T0 + 1, "r1", x).is_err());
    // a deny from a chat is allowed (fail safe), by a member
    let mut d = root_decide(Outcome::Deny);
    d.class = SocketClass::Supervisor;
    d.surface = Surface::Telegram;
    d.factor = Factor::ChatDeny;
    d.role = Some(Role::Member);
    d.decider = "mia".into();
    assert_eq!(b.decide(&c, T0 + 2, "r1", d).unwrap().state, State::Denied);
}

#[test]
fn members_decide_overrides_and_new_non_production_names_and_the_owner_the_rest() {
    let c = ctx();
    let cases: Vec<(Subject, Derived, bool)> = vec![
        (guard('a', vec![]), Derived::default(), true),
        (
            import("staging", Classification::Secret),
            Derived::default(),
            true,
        ),
        // a replacement, a public mark and Production are the owner's
        (
            import("staging", Classification::Secret),
            Derived {
                replaces_existing: true,
                ..Derived::default()
            },
            false,
        ),
        (
            import("staging", Classification::Public),
            Derived::default(),
            false,
        ),
        (
            import("production", Classification::Secret),
            Derived::default(),
            false,
        ),
        (
            policy(PolicySensitivity::Ordinary),
            Derived::default(),
            false,
        ),
        (tunnel('c'), Derived::default(), false),
        (enrol(EnrolAction::Revoke), Derived::default(), false),
    ];
    for (n, (s, d, member_ok)) in cases.into_iter().enumerate() {
        let who = match s.scope() {
            "guard-override" => box_user(1000),
            "tunnel-token" => root_helper(),
            "policy" | "signer-enroll" => root_helper(),
            _ => laptop("lap"),
        };
        let mut b = book();
        let id = format!("r{n}");
        b.file(&c, T0, with(filing(&id, s.clone(), who), d))
            .unwrap();
        let m = passkey_decide(&b, &c, &id, Role::Member, "mia", "cm", &format!("sm{n}"), 0);
        let r = b.decide(&c, T0 + 1, &id, m);
        assert_eq!(r.is_ok(), member_ok, "member on {n} {s:?}: {r:?}");
        if !member_ok {
            let o = passkey_decide(&b, &c, &id, Role::Owner, "olga", "co", &format!("so{n}"), 0);
            assert!(b.decide(&c, T0 + 2, &id, o).is_ok(), "owner on {n}");
        }
    }
}

#[test]
fn the_dashboard_does_not_decide_setup_code_or_kek_export() {
    for s in [
        Subject::SetupCode(Challenge {
            challenge: "ab".repeat(16),
        }),
        Subject::KekExport(Challenge {
            challenge: "cd".repeat(16),
        }),
    ] {
        let c = ctx();
        let mut b = book();
        b.file(&c, T0, filing("r1", s, laptop("lap"))).unwrap();
        let o = passkey_decide(&b, &c, "r1", Role::Owner, "olga", "co", "so", 0);
        let e = b.decide(&c, T0 + 1, "r1", o).unwrap_err();
        assert!(e.contains("never on the dashboard"), "{e}");
        // root decides it
        assert!(b
            .decide(&c, T0 + 2, "r1", root_decide(Outcome::Approve))
            .is_ok());
    }
}

#[test]
fn once_a_presence_key_has_ever_existed_the_dashboard_no_longer_decides_tunnel_host_guard_or_widening(
) {
    let mut c = ctx();
    let mut b = book();
    b.file(&c, T0, filing("r1", tunnel('c'), root_helper()))
        .unwrap();
    // before: the owner decides it on the dashboard
    let o = passkey_decide(&b, &c, "r1", Role::Owner, "olga", "co", "s1", 0);
    assert!(b.decide(&c, T0 + 1, "r1", o).is_ok());
    // after: refused, and the marker is the sticky one (it is a Ctx field, never a policy field)
    c.ever_presence_key = true;
    b.file(&c, T0 + 2, filing("r2", tunnel('d'), root_helper()))
        .unwrap();
    let o = passkey_decide(&b, &c, "r2", Role::Owner, "olga", "co", "s2", 0);
    let e = b.decide(&c, T0 + 3, "r2", o).unwrap_err();
    assert!(
        e.contains("laptop key with presence has been enrolled"),
        "{e}"
    );
    // root still decides it
    assert!(b
        .decide(&c, T0 + 4, "r2", root_decide(Outcome::Approve))
        .is_ok());
    // a policy that widens a guarded scope: dashboard before, not after
    let mut c2 = ctx();
    let mut b = book();
    b.file(
        &c2,
        T0,
        filing(
            "p1",
            policy(PolicySensitivity::WidensGuarded),
            root_helper(),
        ),
    )
    .unwrap();
    assert!(b
        .decide(
            &c2,
            T0 + 1,
            "p1",
            passkey_decide(&b, &c2, "p1", Role::Owner, "olga", "co", "p1s", 0)
        )
        .is_ok());
    c2.ever_presence_key = true;
    b.file(
        &c2,
        T0 + 2,
        filing(
            "p2",
            policy(PolicySensitivity::WidensGuarded),
            laptop("lap"),
        ),
    )
    .unwrap();
    assert!(b
        .decide(
            &c2,
            T0 + 3,
            "p2",
            passkey_decide(&b, &c2, "p2", Role::Owner, "olga", "co", "p2s", 0)
        )
        .is_err());
}

#[test]
fn a_laptop_key_enrolled_from_the_dashboard_waits_a_day_unless_it_is_the_first_ever() {
    // the first key ever: no wait
    let c = ctx();
    let mut b = book();
    b.file(
        &c,
        T0,
        filing("e1", enrol(EnrolAction::Enrol), laptop("kk")),
    )
    .unwrap();
    let r = b
        .decide(
            &c,
            T0 + 1,
            "e1",
            passkey_decide(&b, &c, "e1", Role::Owner, "olga", "co", "s1", 0),
        )
        .unwrap();
    assert_eq!(r.not_before_ms, 0);
    // a later key (the box has had one): the dashboard decision starts a 24-hour cooling-off
    let c2 = Ctx {
        ever_key: true,
        ..ctx()
    };
    let mut b = book();
    b.file(
        &c2,
        T0,
        filing("e2", enrol(EnrolAction::Enrol), laptop("kk2")),
    )
    .unwrap();
    let r = b
        .decide(
            &c2,
            T0 + 1,
            "e2",
            passkey_decide(&b, &c2, "e2", Role::Owner, "olga", "co", "s2", 0),
        )
        .unwrap();
    assert_eq!(r.not_before_ms, T0 + 1 + COOLING_OFF_MS);
    assert_eq!(r.expires_at_ms, r.not_before_ms + APPROVED_MS);
    // it cannot be spent in the wait, and any approver can cancel it in the wait
    let e = b
        .begin_spend(
            &c2,
            T0 + 1000,
            "e2",
            SpendVia::Inside,
            &enrol(EnrolAction::Enrol),
            &|_| true,
        )
        .unwrap_err();
    assert!(e.message.contains("cannot approve until"), "{}", e.message);
    assert_eq!(b.get("e2").unwrap().state, State::Approved);
    // after the wait it is spendable
    assert!(b
        .begin_spend(
            &c2,
            r.not_before_ms + 1,
            "e2",
            SpendVia::Inside,
            &enrol(EnrolAction::Enrol),
            &|_| true
        )
        .is_ok());
    // revoking a key is the owner's any time, with no wait
    let mut b = book();
    b.file(
        &c2,
        T0,
        filing("e3", enrol(EnrolAction::Revoke), root_helper()),
    )
    .unwrap();
    let r = b
        .decide(
            &c2,
            T0 + 1,
            "e3",
            passkey_decide(&b, &c2, "e3", Role::Owner, "olga", "co", "s3", 0),
        )
        .unwrap();
    assert_eq!(r.not_before_ms, 0);
    // cancelling during the wait
    let mut b = book();
    b.file(
        &c2,
        T0,
        filing("e4", enrol(EnrolAction::Enrol), laptop("kk4")),
    )
    .unwrap();
    b.decide(
        &c2,
        T0 + 1,
        "e4",
        passkey_decide(&b, &c2, "e4", Role::Owner, "olga", "co", "s4", 0),
    )
    .unwrap();
    assert_eq!(
        b.cancel(T0 + 2, "e4", SocketClass::Supervisor)
            .unwrap()
            .state,
        State::Cancelled
    );
    assert!(b.cancel(T0 + 2, "e4", SocketClass::Box).is_err());
}

// ---- laptop keys ---------------------------------------------------------------------------------------------------

#[test]
fn a_software_key_decides_member_level_changes_but_never_an_owner_only_scope_or_production() {
    let c = ctx();
    let sw = key("soft", KeyType::Ed25519, false);
    // guard override: yes
    let mut b = book();
    file(&mut b, T0, filing("g", guard('a', vec![]), box_user(1000)));
    let r = b
        .decide(
            &c,
            T0 + 1,
            "g",
            laptop_decide(&b, &c, "g", &sw, false, false, None),
        )
        .unwrap();
    assert_eq!(
        r.decision.as_ref().unwrap().factor_label,
        "laptop-key:soft (no user presence)"
    );
    assert_eq!(r.decision.unwrap().presence, PresenceClass::NoPresence);
    // a new non-Production import: yes
    let mut b = book();
    b.file(
        &c,
        T0,
        filing(
            "i",
            import("staging", Classification::Secret),
            laptop("lap"),
        ),
    )
    .unwrap();
    assert!(b
        .decide(
            &c,
            T0 + 1,
            "i",
            laptop_decide(&b, &c, "i", &sw, false, false, None)
        )
        .is_ok());
    // a Production import, a public mark, a replacement, tunnel, host guard, enrol, setup, kek: refused
    let refuse = |s: Subject, who: Requester, d: Derived| {
        let mut b = book();
        b.file(&c, T0, with(filing("x", s, who), d)).unwrap();
        let e = b
            .decide(
                &c,
                T0 + 1,
                "x",
                laptop_decide(&b, &c, "x", &sw, false, false, None),
            )
            .unwrap_err();
        assert_eq!(b.get("x").unwrap().state, State::Pending);
        e
    };
    assert!(refuse(
        import("production", Classification::Secret),
        laptop("lap"),
        Derived::default()
    )
    .contains("Production"));
    assert!(refuse(
        import("staging", Classification::Public),
        laptop("lap"),
        Derived::default()
    )
    .contains("does not decide"));
    assert!(refuse(
        import("staging", Classification::Secret),
        laptop("lap"),
        Derived {
            replaces_existing: true,
            ..Derived::default()
        }
    )
    .contains("does not decide"));
    assert!(refuse(tunnel('c'), root_helper(), Derived::default()).contains("does not decide"));
    assert!(
        refuse(enrol(EnrolAction::Enrol), root_helper(), Derived::default())
            .contains("does not decide")
    );
    assert!(refuse(
        policy(PolicySensitivity::Ordinary),
        root_helper(),
        Derived::default()
    )
    .contains("does not decide"));
    assert!(refuse(
        Subject::KekExport(Challenge {
            challenge: "ab".repeat(16)
        }),
        laptop("lap"),
        Derived::default()
    )
    .contains("does not decide"));
    let hg = Subject::HostGuard(HostGuard {
        action: "open-port".into(),
        loosening: true,
        fields: vec![],
    });
    assert!(refuse(hg, root_helper(), Derived::default()).contains("does not decide"));
}

/// Owner decision B: a software key NEVER decides an owner-only scope. There is no opt-in (the review asked whether root
/// could turn one on; it cannot, because nothing in the box says so any more).
#[test]
fn a_software_key_never_decides_an_owner_only_scope_and_nothing_opts_it_in() {
    let c = ctx();
    let sw = key("soft", KeyType::Ed25519, false);
    let bs = Subject::BoxSecrets(BoxSecrets {
        address: "a1".into(),
        action: "set".into(),
        change_digest: hex64('3'),
        first_setting: false,
    });
    let wk = Subject::WorkerKeys(crate::approval_subject::WorkerKeys {
        orchestration_id: "orch-1".into(),
        names: vec!["A".into()],
        environment: "staging".into(),
        max_workers: 4,
        ttl_s: 3600,
    });
    for (n, (s, who)) in [
        (policy(PolicySensitivity::Ordinary), root_helper()),
        (policy(PolicySensitivity::WidensGuarded), root_helper()),
        (bs, root_helper()),
        (wk, Requester::new(RequesterKind::HubAgent, None)),
        (tunnel('c'), root_helper()),
        (enrol(EnrolAction::Enrol), root_helper()),
    ]
    .into_iter()
    .enumerate()
    {
        let mut b = book();
        let id = format!("o{n}");
        let f = Filing {
            derived: Derived {
                policy_sensitivity: policy_of(&s),
                ..Derived::default()
            },
            ..filing(&id, s, who)
        };
        let Ok(_) = b.file(&c, T0, f) else { continue };
        let e = b
            .decide(
                &c,
                T0 + 1,
                &id,
                laptop_decide(&b, &c, &id, &sw, false, false, None),
            )
            .unwrap_err();
        assert!(e.contains("does not decide"), "{n}: {e}");
    }
    // and never Production
    let mut b = book();
    b.file(
        &c,
        T0,
        filing(
            "p",
            import("production", Classification::Secret),
            laptop("lap"),
        ),
    )
    .unwrap();
    assert!(b
        .decide(
            &c,
            T0 + 1,
            "p",
            laptop_decide(&b, &c, "p", &sw, false, false, None)
        )
        .is_err());
}

fn policy_of(s: &Subject) -> Option<PolicySensitivity> {
    match s {
        Subject::Policy(p) => Some(p.sensitivity),
        _ => None,
    }
}

#[test]
fn a_secure_enclave_style_key_is_a_software_key_and_presence_is_never_declared() {
    // a P-256 WebAuthn key without a verified attestation is not presence, however the evidence reads
    let c = ctx();
    let fake = key("mac", KeyType::WebauthnP256, false);
    let mut b = book();
    b.file(&c, T0, filing("t", tunnel('c'), root_helper()))
        .unwrap();
    let e = b
        .decide(
            &c,
            T0 + 1,
            "t",
            laptop_decide(&b, &c, "t", &fake, true, true, Some(1)),
        )
        .unwrap_err();
    assert!(e.contains("does not decide"), "{e}");
    // an Ed25519 key can never be presence even if a record says so
    let mut lie = key("lie", KeyType::Ed25519, false);
    lie.presence_proved = true;
    let r = {
        let mut b = book();
        b.file(&c, T0, filing("t", tunnel('c'), root_helper()))
            .unwrap();
        b.decide(
            &c,
            T0 + 1,
            "t",
            laptop_decide(&b, &c, "t", &lie, true, true, Some(1)),
        )
    };
    assert!(r.is_err());
}

#[test]
fn a_presence_key_needs_a_touch_on_every_decision_verification_for_owner_scopes_and_a_forward_counter(
) {
    let c = ctx();
    let sk = key("yubi", KeyType::SkEd25519, true);
    let mk = |b: &mut RequestBook, id: &str, s: Subject, who: Requester, uid: u64| {
        b.file(&c, T0 + uid, filing(id, s, who)).unwrap();
    };
    let mut b = book();
    mk(&mut b, "t1", tunnel('c'), root_helper(), 0);
    // made with no touch (an `sk` key made with no-touch-required): refused though the attestation was fine
    let e = b
        .decide(
            &c,
            T0 + 1,
            "t1",
            laptop_decide(&b, &c, "t1", &sk, false, true, Some(1)),
        )
        .unwrap_err();
    assert!(e.contains("without a touch"), "{e}");
    // touch but no verification, on an owner-only scope: refused
    let e = b
        .decide(
            &c,
            T0 + 1,
            "t1",
            laptop_decide(&b, &c, "t1", &sk, true, false, Some(1)),
        )
        .unwrap_err();
    assert!(e.contains("user verification"), "{e}");
    // the data the signature covers is required
    let mut no_ad = laptop_decide(&b, &c, "t1", &sk, true, true, Some(1));
    no_ad.evidence.laptop.as_mut().unwrap().authenticator_data = None;
    assert!(b
        .decide(&c, T0 + 1, "t1", no_ad)
        .unwrap_err()
        .contains("flags and counter"));
    // touch and verification: decided, and the record carries the evidence and the presence class
    let r = b
        .decide(
            &c,
            T0 + 2,
            "t1",
            laptop_decide(&b, &c, "t1", &sk, true, true, Some(10)),
        )
        .unwrap();
    let d = r.decision.unwrap();
    assert_eq!(d.factor_label, "laptop-key:yubi");
    assert_eq!(
        d.decider, "yubi",
        "the key's own id, never what the caller named"
    );
    assert_eq!(d.presence, PresenceClass::Proved);
    let e = d.evidence.laptop.unwrap();
    assert_eq!(e.signature_format, SignatureFormat::SshSk);
    assert_eq!(e.key_type, KeyType::SkEd25519);
    assert!(e.authenticator_data.is_some());
    assert_eq!(e.attestation_digest, Some(hex64('7')));
    assert_eq!(
        d.proven,
        Some(Proven {
            up: true,
            uv: true,
            counter: Some(10)
        }),
        "read from the signed bytes"
    );
    // a member-level change needs a touch but not verification
    mk(&mut b, "g1", guard('a', vec![]), box_user(1000), 3);
    assert!(b
        .decide(
            &c,
            T0 + 4,
            "g1",
            laptop_decide(&b, &c, "g1", &sk, true, false, Some(11))
        )
        .is_ok());
    // a counter that goes back is refused
    mk(&mut b, "g2", guard('b', vec![]), box_user(1001), 5);
    let e = b
        .decide(
            &c,
            T0 + 6,
            "g2",
            laptop_decide(&b, &c, "g2", &sk, true, false, Some(11)),
        )
        .unwrap_err();
    assert!(e.contains("counter went back"), "{e}");
    assert_eq!(b.get("g2").unwrap().state, State::Pending);
}

#[test]
fn a_revoked_key_decides_nothing_and_an_approval_it_gave_dies_at_spend() {
    let c = ctx();
    let mut b = book();
    file(&mut b, T0, filing("g", guard('a', vec![]), box_user(1000)));
    let k = key("lap", KeyType::SkEd25519, true);
    b.decide(
        &c,
        T0 + 1,
        "g",
        laptop_decide(&b, &c, "g", &k, true, false, None),
    )
    .unwrap();
    // the key was revoked since: the spend finds the decider invalid and the approval is void
    let e = b
        .begin_spend(
            &c,
            T0 + 2,
            "g",
            SpendVia::Socket {
                class: SocketClass::Box,
                uid: Some(1000),
            },
            &guard('a', vec![]),
            &|d| d.decider != "lap",
        )
        .unwrap_err();
    assert!(e.message.contains("no longer valid"), "{}", e.message);
    assert_eq!(b.get("g").unwrap().state, State::Denied);
    // and a revoked key cannot decide
    let mut b = book();
    file(&mut b, T0, filing("g", guard('a', vec![]), box_user(1000)));
    let mut gone = k.clone();
    gone.active = false;
    assert!(b
        .decide(
            &c,
            T0 + 1,
            "g",
            laptop_decide(&b, &c, "g", &gone, true, false, None)
        )
        .is_err());
}

#[test]
fn the_supervisor_pushing_a_removed_person_voids_what_they_approved() {
    let mut b = book();
    let c = ctx();
    file(&mut b, T0, filing("r1", guard('a', vec![]), box_user(1000)));
    file(&mut b, T0, filing("r2", guard('b', vec![]), box_user(1001)));
    b.decide(
        &c,
        T0 + 1,
        "r1",
        passkey_decide(&b, &c, "r1", Role::Member, "mia", "cm", "s1", 0),
    )
    .unwrap();
    b.decide(
        &c,
        T0 + 1,
        "r2",
        passkey_decide(&b, &c, "r2", Role::Owner, "olga", "co", "s2", 0),
    )
    .unwrap();
    let voided = b.decider_revoked("mia");
    assert_eq!(voided, vec!["r1".to_string()]);
    assert_eq!(b.get("r1").unwrap().state, State::Denied);
    assert!(b.get("r1").unwrap().void_reason.is_some());
    assert_eq!(b.get("r2").unwrap().state, State::Approved);
}

// ---- revoke and deny -----------------------------------------------------------------------------------------------

#[test]
fn an_approved_request_is_revoked_only_by_the_same_or_higher_authority() {
    let c = ctx();
    let mut b = book();
    file(&mut b, T0, filing("r1", tunnel('c'), root_helper()));
    b.decide(
        &c,
        T0 + 1,
        "r1",
        passkey_decide(&b, &c, "r1", Role::Owner, "olga", "co", "s1", 0),
    )
    .unwrap();
    // a member's deny cannot revoke an owner's approval
    let mut d = root_decide(Outcome::Deny);
    d.class = SocketClass::Supervisor;
    d.surface = Surface::Dashboard;
    d.factor = Factor::Passkey;
    d.role = Some(Role::Member);
    d.decider = "mia".into();
    assert!(b
        .decide(&c, T0 + 2, "r1", d)
        .unwrap_err()
        .contains("same or higher authority"));
    // a chat Deny cannot revoke either (a revoke needs its credential)
    let mut ch = root_decide(Outcome::Deny);
    ch.class = SocketClass::Supervisor;
    ch.surface = Surface::Telegram;
    ch.factor = Factor::ChatDeny;
    ch.role = Some(Role::Owner);
    assert!(b.decide(&c, T0 + 2, "r1", ch).is_err());
    // root can
    let r = b
        .decide(&c, T0 + 3, "r1", root_decide(Outcome::Deny))
        .unwrap();
    assert_eq!(r.state, State::Denied);
    assert_eq!(r.decision.unwrap().outcome, Outcome::Revoke);
    // a revoked approval cannot be spent
    assert!(b
        .begin_spend(
            &c,
            T0 + 4,
            "r1",
            SpendVia::Socket {
                class: SocketClass::Admin,
                uid: None
            },
            &tunnel('c'),
            &|_| true
        )
        .is_err());
}

#[test]
fn a_hub_agent_relays_a_deny_without_a_credential_but_cannot_approve_or_revoke() {
    let c = ctx();
    let mut b = book();
    file(&mut b, T0, filing("r1", guard('a', vec![]), box_user(1000)));
    let mut d = root_decide(Outcome::Approve);
    d.class = SocketClass::HubAgent;
    assert!(b
        .decide(&c, T0 + 1, "r1", d.clone())
        .unwrap_err()
        .contains("another box"));
    d.outcome = Outcome::Deny;
    d.factor = Factor::ChatDeny;
    d.surface = Surface::HubRelay;
    assert_eq!(
        b.decide(&c, T0 + 2, "r1", d.clone()).unwrap().state,
        State::Denied
    );
    // an approved one: the relay cannot revoke it
    file(
        &mut b,
        T0 + 3,
        filing("r2", guard('b', vec![]), box_user(1001)),
    );
    b.decide(&c, T0 + 4, "r2", root_decide(Outcome::Approve))
        .unwrap();
    assert!(b.decide(&c, T0 + 5, "r2", d).is_err());
}

// ---- spend ---------------------------------------------------------------------------------------------------------

#[test]
fn an_approval_is_good_for_fifteen_minutes_and_one_use() {
    let c = ctx();
    let mut b = book();
    file(&mut b, T0, filing("r1", guard('a', vec![]), box_user(1000)));
    let r = b
        .decide(&c, T0 + 1000, "r1", root_decide(Outcome::Approve))
        .unwrap();
    assert_eq!(r.expires_at_ms, T0 + 1000 + 15 * 60_000);
    let s = spend_box(&mut b, T0 + 2000, "r1", 1000, &guard('a', vec![])).unwrap();
    assert_eq!(s.state, State::Spending);
    // a crash here: the request is `spending`, refused and shown, never spent twice
    let e = spend_box(&mut b, T0 + 2001, "r1", 1000, &guard('a', vec![])).unwrap_err();
    assert!(e.message.contains("interrupted"), "{}", e.message);
    assert_eq!(b.finish_spend("r1").unwrap().state, State::Spent);
    // double spend
    let e = spend_box(&mut b, T0 + 2002, "r1", 1000, &guard('a', vec![])).unwrap_err();
    assert!(e.message.contains("already used"), "{}", e.message);
    // an approved request expires after its 15 minutes
    file(
        &mut b,
        T0 + 3000,
        filing("r2", guard('b', vec![]), box_user(1000)),
    );
    b.decide(&c, T0 + 3000, "r2", root_decide(Outcome::Approve))
        .unwrap();
    let e = spend_box(
        &mut b,
        T0 + 3000 + 15 * 60_000,
        "r2",
        1000,
        &guard('b', vec![]),
    )
    .unwrap_err();
    assert!(e.message.contains("expired"), "{}", e.message);
}

#[test]
fn a_spend_that_finds_a_changed_subject_is_refused_names_the_field_and_keeps_the_approval() {
    let c = ctx();
    let mut b = book();
    file(&mut b, T0, filing("r1", guard('a', vec![]), box_user(1000)));
    b.decide(&c, T0 + 1, "r1", root_decide(Outcome::Approve))
        .unwrap();
    // the commit was edited after approval: a different tree
    let e = spend_box(&mut b, T0 + 2, "r1", 1000, &guard('b', vec![])).unwrap_err();
    assert!(e.digest_mismatch);
    assert_eq!(e.differs, vec!["tree"]);
    assert!(
        !e.message.contains('b'.to_string().repeat(40).as_str()),
        "no value in the message"
    );
    let r = b.get("r1").unwrap();
    assert_eq!(
        r.state,
        State::Approved,
        "the approval is kept for what it was for"
    );
    assert_eq!(r.wrong_answers, 1);
    // and the right one still spends
    assert!(spend_box(&mut b, T0 + 3, "r1", 1000, &guard('a', vec![])).is_ok());
}

#[test]
fn a_spend_comes_only_from_the_socket_class_that_recomputes() {
    let c = ctx();
    let mut b = book();
    b.file(&c, T0, filing("t", tunnel('c'), root_helper()))
        .unwrap();
    b.decide(&c, T0 + 1, "t", root_decide(Outcome::Approve))
        .unwrap();
    // a root scope from the box socket: refused, the approval kept
    let e = spend_box(&mut b, T0 + 2, "t", 1000, &tunnel('c')).unwrap_err();
    assert!(
        e.message.contains("not spent from this socket"),
        "{}",
        e.message
    );
    assert_eq!(b.get("t").unwrap().state, State::Approved);
    // from the admin socket: spent
    assert!(b
        .begin_spend(
            &c,
            T0 + 3,
            "t",
            SpendVia::Socket {
                class: SocketClass::Admin,
                uid: Some(0)
            },
            &tunnel('c'),
            &|_| true
        )
        .is_ok());
    // a service scope is spent only inside its own operation, never as a separate spend
    b.file(
        &c,
        T0,
        filing(
            "i",
            import("staging", Classification::Secret),
            laptop("lap"),
        ),
    )
    .unwrap();
    b.decide(&c, T0 + 1, "i", root_decide(Outcome::Approve))
        .unwrap();
    for class in [
        SocketClass::Box,
        SocketClass::Admin,
        SocketClass::Supervisor,
        SocketClass::Ingress,
    ] {
        let e = b
            .begin_spend(
                &c,
                T0 + 2,
                "i",
                SpendVia::Socket {
                    class,
                    uid: Some(1000),
                },
                &import("staging", Classification::Secret),
                &|_| true,
            )
            .unwrap_err();
        assert!(
            e.message.contains("not spent from this socket"),
            "{class:?} {}",
            e.message
        );
    }
    assert!(b
        .begin_spend(
            &c,
            T0 + 3,
            "i",
            SpendVia::Inside,
            &import("staging", Classification::Secret),
            &|_| true
        )
        .is_ok());
    // and an inside spend cannot spend a hook's scope
    file(
        &mut b,
        T0 + 4,
        filing("g", guard('a', vec![]), box_user(1000)),
    );
    b.decide(&c, T0 + 5, "g", root_decide(Outcome::Approve))
        .unwrap();
    assert!(b
        .begin_spend(
            &c,
            T0 + 6,
            "g",
            SpendVia::Inside,
            &guard('a', vec![]),
            &|_| true
        )
        .is_err());
}

#[test]
fn a_box_user_spends_only_a_request_its_own_uid_filed() {
    let c = ctx();
    let mut b = book();
    file(&mut b, T0, filing("g", guard('a', vec![]), box_user(1000)));
    b.decide(&c, T0 + 1, "g", root_decide(Outcome::Approve))
        .unwrap();
    let e = spend_box(&mut b, T0 + 2, "g", 1001, &guard('a', vec![])).unwrap_err();
    assert_eq!(e.message, NOT_FOUND);
    assert_eq!(b.get("g").unwrap().state, State::Approved);
}

/// An id of the shape the service makes (26 characters of lowercase base32).
const RID: &str = "abcdefghijklmnopqrstuvwxyz";

fn fresh_id(n: usize) -> String {
    // 26 characters from the service's alphabet, different for every n
    let a = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::new();
    let mut x = n + 1;
    for _ in 0..26 {
        out.push(a[x % 32] as char);
        x = x / 32 + 7;
    }
    out
}

#[test]
fn refused_spends_are_counted_so_a_flood_of_them_stops_being_answered() {
    let c = ctx();
    let mut b = book();
    file(&mut b, T0, filing(RID, guard('a', vec![]), box_user(1000)));
    b.decide(&c, T0 + 1, RID, root_decide(Outcome::Approve))
        .unwrap();
    for i in 0..REFUSED_SPENDS_PER_HOUR {
        let _ = spend_box(&mut b, T0 + 2 + i as u64, RID, 1000, &guard('b', vec![]));
    }
    let e = spend_box(&mut b, T0 + 100, RID, 1000, &guard('a', vec![])).unwrap_err();
    assert!(
        e.message.contains("too many refused spends"),
        "{}",
        e.message
    );
    // the approval is still there, and another uid is not slowed by it
    assert_eq!(b.get(RID).unwrap().state, State::Approved);
    // an hour later it works
    assert!(spend_box(&mut b, T0 + 3_700_000, RID, 1000, &guard('a', vec![])).is_err());
    // expired by then, but not throttled
}

#[test]
fn a_flood_of_fresh_request_ids_from_one_uid_leaves_the_refused_list_bounded() {
    let mut b = book();
    for n in 0..2_000 {
        let _ = spend_box(
            &mut b,
            T0 + n as u64,
            &fresh_id(n),
            1000,
            &guard('a', vec![]),
        );
    }
    assert!(
        b.refused_spends.len() <= REFUSED_SPENDS_PER_UID_PER_HOUR,
        "{}",
        b.refused_spends.len()
    );
    // past the ceiling the answer is still "no such request", and nothing more is kept
    let e = spend_box(
        &mut b,
        T0 + 3_000,
        &fresh_id(9_999),
        1000,
        &guard('a', vec![]),
    )
    .unwrap_err();
    assert_eq!(e.message, NOT_FOUND);
    assert!(!e.changed);
    // another uid has a budget of its own
    let e = spend_box(&mut b, T0 + 3_001, &fresh_id(1), 1001, &guard('a', vec![])).unwrap_err();
    assert_eq!(e.message, NOT_FOUND);
    // an hour on, the list empties
    let _ = spend_box(
        &mut b,
        T0 + 3_700_000,
        &fresh_id(5),
        1000,
        &guard('a', vec![]),
    );
    assert!(b.refused_spends.len() <= 2);
}

#[test]
fn two_thousand_refusals_with_fresh_ids_do_not_lock_the_same_uid_out_of_its_approved_request() {
    let c = ctx();
    let mut b = book();
    file(&mut b, T0, filing(RID, guard('a', vec![]), box_user(1000)));
    b.decide(&c, T0 + 1, RID, root_decide(Outcome::Approve))
        .unwrap();
    for n in 0..2_000 {
        let _ = spend_box(
            &mut b,
            T0 + 2 + n as u64,
            &fresh_id(n),
            1000,
            &guard('a', vec![]),
        );
    }
    assert!(b.refused_spends.len() <= REFUSED_SPENDS_PER_UID_PER_HOUR);
    let r = spend_box(&mut b, T0 + 3_000, RID, 1000, &guard('a', vec![])).unwrap();
    assert_eq!(r.state, State::Spending);
}

#[test]
fn an_id_of_another_shape_is_never_counted_and_changes_nothing() {
    let mut b = book();
    for id in ["g", "", &"x".repeat(100_000), "ABCDEFGHIJKLMNOPQRSTUVWXYZ"] {
        let e = spend_box(&mut b, T0, id, 1000, &guard('a', vec![])).unwrap_err();
        assert_eq!(e.message, NOT_FOUND);
        assert!(!e.changed);
    }
    assert!(b.refused_spends.is_empty());
    assert!(request_id_ok(RID));
    assert!(!request_id_ok("abcdefghijklmnopqrstuvwxy1"));
}

// ---- epoch and restore ---------------------------------------------------------------------------------------------

#[test]
fn a_restore_voids_pending_and_approved_requests_of_the_old_epoch() {
    let c = ctx();
    let mut b = book();
    file(&mut b, T0, filing("p", guard('a', vec![]), box_user(1000)));
    file(&mut b, T0, filing("a", guard('b', vec![]), box_user(1001)));
    b.decide(&c, T0 + 1, "a", root_decide(Outcome::Approve))
        .unwrap();
    // the journal comes back from a backup after a restore, which made a new epoch
    let restored = b.clone();
    let mut b2 = restored;
    b2.new_epoch("epoch-2".into(), T0 + 2);
    assert_eq!(b2.get("a").unwrap().state, State::Expired);
    assert!(b2
        .get("a")
        .unwrap()
        .void_reason
        .as_ref()
        .unwrap()
        .contains("restore"));
    let e = spend_box(&mut b2, T0 + 3, "a", 1001, &guard('b', vec![])).unwrap_err();
    assert!(
        e.message.contains("expired") || e.message.contains("reset"),
        "{}",
        e.message
    );
    assert_eq!(b2.get("p").unwrap().state, State::Expired);
    // a new request in the new epoch works
    assert!(b2
        .file(&c, T0 + 4, filing("n", guard('a', vec![]), box_user(1000)))
        .is_ok());
}

#[test]
fn a_journal_copied_back_in_the_same_epoch_cannot_revive_what_the_ledger_says_was_spent() {
    let c = ctx();
    let mut b = book();
    file(&mut b, T0, filing("g", guard('a', vec![]), box_user(1000)));
    b.decide(&c, T0 + 1, "g", root_decide(Outcome::Approve))
        .unwrap();
    let backup = b.clone(); // taken while approved
    spend_box(&mut b, T0 + 2, "g", 1000, &guard('a', vec![])).unwrap();
    b.finish_spend("g").unwrap();
    // the backup is restored; the ledger kept outside the journal still holds the id
    let mut restored = backup;
    assert_eq!(restored.get("g").unwrap().state, State::Approved);
    assert_eq!(restored.apply_spent_ledger(["g"].into_iter()), 1);
    let e = spend_box(&mut restored, T0 + 3, "g", 1000, &guard('a', vec![])).unwrap_err();
    assert!(e.message.contains("already used"), "{}", e.message);
}

// ---- guard override facts ------------------------------------------------------------------------------------------

fn production_looking_guard() -> Subject {
    guard(
        'a',
        vec![GuardMatch {
            path: "src/a.rs".into(),
            line: 3,
            rule: RULE_PRODUCTION_LOOKING.into(),
            key_id: "k1".into(),
        }],
    )
}

/// the rule held only in `decide`, which a bootstrap approval never reaches, so a box with no approver approved
/// its own Production-looking override. It is refused at filing now, whoever files and whether or not a factor exists.
#[test]
fn a_production_looking_match_is_not_filed_or_decided_by_anyone_here_bootstrap_or_not() {
    let enrolled = ctx();
    let bare = Ctx {
        enrolled: false,
        ..ctx()
    };
    for c in [&enrolled, &bare] {
        let mut b = book();
        let e = b
            .file(
                c,
                T0,
                filing("g", production_looking_guard(), box_user(1000)),
            )
            .unwrap_err();
        assert!(e.contains("Production"), "enrolled={}: {e}", c.enrolled);
        assert!(b.requests.is_empty());
    }
    // the decide-time check still stands behind it for a record that somehow exists
    let mut b = book();
    b.file(
        &enrolled,
        T0,
        filing("ok", guard('b', vec![]), box_user(1000)),
    )
    .unwrap();
    b.requests[0].subject = production_looking_guard();
    let e = b
        .decide(&enrolled, T0 + 1, "ok", root_decide(Outcome::Approve))
        .unwrap_err();
    assert!(e.contains("Production"), "{e}");
}

/// Bootstrap approvals filed just before the owner enrols a factor are void once it exists.
#[test]
fn a_bootstrap_approval_is_void_once_a_second_factor_is_enrolled() {
    let bare = Ctx {
        enrolled: false,
        ..ctx()
    };
    let mut b = book();
    b.file(&bare, T0, filing("g", tunnel('a'), root_helper()))
        .unwrap();
    b.file(&bare, T0, filing("h", tunnel('b'), root_helper()))
        .unwrap();
    assert_eq!(b.get("g").unwrap().state, State::Approved);
    let enrolled = ctx();
    // the spend (the only thing that uses an approval) finds it void
    let e = b
        .begin_spend(
            &enrolled,
            T0 + 1,
            "g",
            SpendVia::Socket {
                class: SocketClass::Admin,
                uid: None,
            },
            &tunnel('a'),
            &|_| true,
        )
        .unwrap_err();
    assert!(e.message.contains("not") || !e.message.is_empty());
    assert_eq!(b.get("g").unwrap().state, State::Denied);
    assert!(b
        .get("g")
        .unwrap()
        .void_reason
        .as_deref()
        .unwrap()
        .contains("second factor"));
    assert_eq!(
        b.get("h").unwrap().state,
        State::Denied,
        "every outstanding one, not only the one spent"
    );
    // an approval a person gave is not touched
    let mut b = book();
    b.file(
        &enrolled,
        T0,
        filing("p", guard('c', vec![]), box_user(1000)),
    )
    .unwrap();
    b.decide(&enrolled, T0 + 1, "p", root_decide(Outcome::Approve))
        .unwrap();
    assert!(b.void_bootstrap_if_enrolled(&enrolled).is_empty());
    assert_eq!(b.get("p").unwrap().state, State::Approved);
}

/// the label is never the filer's. A filing whose label is not the service's own reading is refused, and the
/// service's reading comes from the two policies.
#[test]
fn a_policy_sensitivity_is_the_services_reading_never_the_filers_label() {
    use crate::approval_subject::{policy_sensitivity, GuardedSettings, PolicyChange};
    let c = ctx();
    let set = |h: &[&str], t: &[&str]| GuardedSettings {
        host_guard: h.iter().map(|x| x.to_string()).collect(),
        tunnel_token: t.iter().map(|x| x.to_string()).collect(),
    };
    let old = set(&["a"], &["t"]);
    assert_eq!(
        policy_sensitivity(&old, &set(&["a"], &["t"])),
        PolicySensitivity::Ordinary
    );
    assert_eq!(
        policy_sensitivity(&old, &set(&[], &["t"])),
        PolicySensitivity::Ordinary,
        "narrowing is ordinary"
    );
    assert_eq!(
        policy_sensitivity(&old, &set(&["a", "b"], &["t"])),
        PolicySensitivity::WidensGuarded
    );
    assert_eq!(
        policy_sensitivity(&old, &set(&["a"], &["t", "u"])),
        PolicySensitivity::WidensGuarded
    );
    let honest = PolicyChange::derive(hex64('d'), hex64('e'), &old, &set(&["a", "b"], &["t"]));
    assert_eq!(honest.sensitivity, PolicySensitivity::WidensGuarded);
    // a compromised supervisor labels a widening "ordinary": nothing the filer can say makes the service agree
    let mut lie = honest.clone();
    lie.sensitivity = PolicySensitivity::Ordinary;
    let mut b = book();
    for derived in [
        Derived::default(),
        Derived {
            policy_sensitivity: Some(PolicySensitivity::WidensGuarded),
            ..Derived::default()
        },
    ] {
        let f = Filing {
            derived,
            ..filing("p", Subject::Policy(lie.clone()), root_helper())
        };
        let e = b.file(&c, T0, f).unwrap_err();
        assert!(e.contains("worked out by the service"), "{e}");
    }
    // the honest filing, with the service's own reading, is accepted
    let f = Filing {
        derived: Derived {
            policy_sensitivity: Some(honest.sensitivity),
            ..Derived::default()
        },
        ..filing("p", Subject::Policy(honest), root_helper())
    };
    assert!(b.file(&c, T0, f).is_ok());
}

/// cancel follows the revoke-authority rule.
#[test]
fn cancel_of_an_approved_request_follows_the_revoke_rule_and_names_who() {
    let c = ctx();
    let mut b = book();
    b.file(&c, T0, filing("g", guard('a', vec![]), box_user(1000)))
        .unwrap();
    b.decide(&c, T0 + 1, "g", root_decide(Outcome::Approve))
        .unwrap();
    // the supervisor cannot withdraw what root approved by calling it a cancel
    assert!(b
        .cancel(T0 + 2, "g", SocketClass::Supervisor)
        .unwrap_err()
        .contains("revoke"));
    assert_eq!(b.get("g").unwrap().state, State::Approved);
    // root may, and the record says from where
    let r = b.cancel(T0 + 3, "g", SocketClass::Admin).unwrap();
    assert_eq!(r.state, State::Cancelled);
    assert!(r.void_reason.unwrap().contains("Admin"));
    // a pending request is the person's to withdraw
    b.file(&c, T0, filing("h", guard('b', vec![]), box_user(1001)))
        .unwrap();
    assert!(b.cancel(T0 + 4, "h", SocketClass::Supervisor).is_ok());
}

// ---- what the box user sees ----------------------------------------------------------------------------------------

#[test]
fn the_box_user_sees_only_its_own_requests_and_only_the_narrow_view() {
    let mut b = book();
    file(&mut b, T0, filing("g1", guard('a', vec![]), box_user(1000)));
    file(&mut b, T0, filing("g2", guard('b', vec![]), box_user(1001)));
    file(&mut b, T0, filing("t", tunnel('c'), root_helper()));
    let mine = b.box_list(Some(1000));
    assert_eq!(mine.len(), 1);
    assert_eq!(mine[0].id, "g1");
    assert!(b.box_get(Some(1000), "g2").is_none());
    assert!(
        b.box_get(Some(1000), "t").is_none(),
        "nothing the root helper filed"
    );
    assert!(
        b.box_get(None, "g1").is_none(),
        "an unnamed peer sees nothing"
    );
    let v = serde_json::to_value(&mine[0]).unwrap();
    let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        vec!["expires_at_ms", "id", "scope", "state", "subject_digest"]
    );
}

#[test]
fn the_record_round_trips_through_json_with_every_field_of_the_decision() {
    let c = ctx();
    let sk = key("yubi", KeyType::EcdsaSk, true);
    let mut b = book();
    file(&mut b, T0, filing("t", tunnel('c'), root_helper()));
    b.decide(
        &c,
        T0 + 1,
        "t",
        laptop_decide(&b, &c, "t", &sk, true, true, Some(4)),
    )
    .unwrap();
    let j = serde_json::to_string(&b).unwrap();
    let back: RequestBook = serde_json::from_str(&j).unwrap();
    assert_eq!(b, back);
    for field in [
        "key_type",
        "signature_format",
        "authenticator_data",
        "proven",
        "up",
        "uv",
        "counter",
        "attestation_digest",
        "presence",
        "factor_label",
    ] {
        assert!(j.contains(field), "the decision record has {field}");
    }
}

// ---- the signed envelope -------------------------------------------------------------------------------

mod envelope {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn signed(b: &RequestBook, id: &str) -> (SignedEnvelope, String, Ed25519KeyPair) {
        let rng = ring::rand::SystemRandom::new();
        let pk = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = Ed25519KeyPair::from_pkcs8(pk.as_ref()).unwrap();
        let env = b.get(id).unwrap().envelope(&ids());
        let canonical = SignedEnvelope::canonical_of(&env).unwrap();
        let sig = to_hex(
            kp.sign(SignedEnvelope::signed_message(&canonical).as_bytes())
                .as_ref(),
        );
        let key = to_hex(kp.public_key().as_ref());
        (
            SignedEnvelope {
                canonical,
                alg: "ed25519".into(),
                signature: sig,
            },
            key,
            kp,
        )
    }

    #[test]
    fn a_verifier_reads_only_the_signed_text_against_its_own_pin_and_the_box_it_is_for() {
        let mut b = book();
        file(&mut b, T0, filing("g", guard('a', vec![]), box_user(1000)));
        let (se, key, _) = signed(&b, "g");
        let env = se.verify(&key, &ids()).unwrap();
        assert_eq!(
            (env.box_id.as_str(), env.store_id.as_str(), env.id.as_str()),
            ("box-1", "store-1", "g")
        );
        assert_eq!(env.origin, "local");
        // the digest is recomputed from the signed subject and the signed ids: nothing is taken from outside the text
        assert_eq!(
            env.subject
                .digest_hex(&Ids {
                    box_id: env.box_id.clone(),
                    store_id: env.store_id.clone()
                })
                .unwrap(),
            env.subject_digest
        );
        // a key the envelope does not vouch for: any other signer is refused (there is no carried key to be fooled by)
        let (_, other_key, _) = signed(&b, "g");
        assert!(se
            .verify(&other_key, &ids())
            .unwrap_err()
            .contains("signature"));
        // another box, another store
        assert!(se
            .verify(
                &key,
                &Ids {
                    box_id: "box-2".into(),
                    store_id: "store-1".into()
                }
            )
            .unwrap_err()
            .contains("another box"));
        assert!(se
            .verify(
                &key,
                &Ids {
                    box_id: "box-1".into(),
                    store_id: "store-2".into()
                }
            )
            .unwrap_err()
            .contains("another box"));
        // a swapped body: the text no longer matches the signature
        let mut swapped = se.clone();
        swapped.canonical = se.canonical.replace("\"g\"", "\"h\"");
        assert!(swapped.verify(&key, &ids()).is_err());
        // an envelope has no unsigned copy of its body or key to read instead: unknown fields are refused outright
        let mut v = serde_json::to_value(&se).unwrap();
        v["envelope"] = serde_json::json!({"id": "OTHER"});
        v["key"] = serde_json::json!("00");
        assert!(serde_json::from_value::<SignedEnvelope>(v).is_err());
        assert!(serde_json::from_str::<Envelope>(
            &se.canonical
                .replace("\"origin\":\"local\"", "\"origin\":\"local\",\"extra\":1")
        )
        .is_err());
        // an algorithm it does not know
        let mut alg = se.clone();
        alg.alg = "rsa".into();
        assert!(alg.verify(&key, &ids()).is_err());
    }

    #[test]
    fn a_signature_over_a_digest_that_is_not_the_subjects_is_refused() {
        let mut b = book();
        file(&mut b, T0, filing("g", guard('a', vec![]), box_user(1000)));
        let rng = ring::rand::SystemRandom::new();
        let pk = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = Ed25519KeyPair::from_pkcs8(pk.as_ref()).unwrap();
        let mut env = b.get("g").unwrap().envelope(&ids());
        env.subject_digest = "0".repeat(64);
        let canonical = SignedEnvelope::canonical_of(&env).unwrap();
        let se = SignedEnvelope {
            signature: to_hex(
                kp.sign(SignedEnvelope::signed_message(&canonical).as_bytes())
                    .as_ref(),
            ),
            canonical,
            alg: "ed25519".into(),
        };
        assert!(se
            .verify(&to_hex(kp.public_key().as_ref()), &ids())
            .unwrap_err()
            .contains("digest"));
    }
}

// ---- phase 2: signed deny and revoke, the seen-set, the relying party ------------------------------------------------

#[test]
fn a_laptop_deny_and_revoke_are_signed_over_their_own_outcome_word() {
    let c = ctx();
    let sk = key("sk", KeyType::SkEd25519, true);
    let mut b = book();
    file(&mut b, T0, filing("d1", guard('a', vec![]), box_user(1000)));
    // naming a key is not a deny: an unsigned deny is refused, and the request is untouched
    let mut bare = laptop_decide_as(
        &b,
        &c,
        "d1",
        &sk,
        Outcome::Deny,
        "deny",
        true,
        false,
        Some(1),
    );
    bare.evidence = Evidence::default();
    assert!(b
        .decide(&c, T0 + 1, "d1", bare)
        .unwrap_err()
        .contains("carries its signature"));
    assert_eq!(b.get("d1").unwrap().state, State::Pending);
    // a signature made to approve does not deny
    let e = b
        .decide(
            &c,
            T0 + 1,
            "d1",
            laptop_decide_as(
                &b,
                &c,
                "d1",
                &sk,
                Outcome::Deny,
                "approve",
                true,
                false,
                Some(1),
            ),
        )
        .unwrap_err();
    assert!(e.contains("another request, another outcome"), "{e}");
    // the right word does
    let r = b
        .decide(
            &c,
            T0 + 2,
            "d1",
            laptop_decide_as(
                &b,
                &c,
                "d1",
                &sk,
                Outcome::Deny,
                "deny",
                true,
                false,
                Some(2),
            ),
        )
        .unwrap();
    assert_eq!(r.state, State::Denied);
    assert_eq!(r.decision.unwrap().factor_label, "laptop-key:sk");

    // a revoke is its own word: neither an approve nor a deny signature revokes
    file(
        &mut b,
        T0 + 3,
        filing("d2", guard('b', vec![]), box_user(1001)),
    );
    b.decide(
        &c,
        T0 + 4,
        "d2",
        laptop_decide(&b, &c, "d2", &sk, true, false, Some(3)),
    )
    .unwrap();
    for word in ["approve", "deny"] {
        let e = b
            .decide(
                &c,
                T0 + 5,
                "d2",
                laptop_decide_as(&b, &c, "d2", &sk, Outcome::Deny, word, true, false, Some(4)),
            )
            .unwrap_err();
        assert!(
            e.contains("another request, another outcome"),
            "{word}: {e}"
        );
    }
    assert_eq!(b.get("d2").unwrap().state, State::Approved);
    let r = b
        .decide(
            &c,
            T0 + 6,
            "d2",
            laptop_decide_as(
                &b,
                &c,
                "d2",
                &sk,
                Outcome::Revoke,
                "revoke",
                true,
                false,
                Some(5),
            ),
        )
        .unwrap();
    assert_eq!(r.state, State::Denied);
    assert_eq!(r.decision.unwrap().outcome, Outcome::Revoke);
    // and the reverse: a revoke signature does not approve
    file(
        &mut b,
        T0 + 7,
        filing("d3", guard('c', vec![]), box_user(1002)),
    );
    let e = b
        .decide(
            &c,
            T0 + 8,
            "d3",
            laptop_decide_as(
                &b,
                &c,
                "d3",
                &sk,
                Outcome::Approve,
                "revoke",
                true,
                false,
                Some(6),
            ),
        )
        .unwrap_err();
    assert!(e.contains("another request, another outcome"), "{e}");
}

#[test]
fn a_laptop_revoke_made_without_a_touch_has_the_authority_of_a_software_key() {
    let c = ctx();
    let sk = key("sk", KeyType::SkEd25519, true);
    let soft = key("soft", KeyType::Ed25519, false);
    let mut b = book();
    // a presence key approved something the software key now tries to revoke: it may not (lower authority)
    file(&mut b, T0, filing("r1", guard('a', vec![]), box_user(1000)));
    b.decide(
        &c,
        T0 + 1,
        "r1",
        laptop_decide(&b, &c, "r1", &sk, true, false, Some(1)),
    )
    .unwrap();
    let e = b
        .decide(
            &c,
            T0 + 2,
            "r1",
            laptop_decide_as(
                &b,
                &c,
                "r1",
                &soft,
                Outcome::Revoke,
                "revoke",
                false,
                false,
                None,
            ),
        )
        .unwrap_err();
    assert!(e.contains("same or higher authority"), "{e}");
    // the same presence key, signing with UP = 0, counts as a key with no presence: still not enough to revoke itself
    // when the approver had authority 4 (a touch)... it is the same key, so a revoke with a touch is
    let r = b
        .decide(
            &c,
            T0 + 3,
            "r1",
            laptop_decide_as(
                &b,
                &c,
                "r1",
                &sk,
                Outcome::Revoke,
                "revoke",
                true,
                false,
                Some(2),
            ),
        )
        .unwrap();
    assert_eq!(r.decision.unwrap().factor_label, "laptop-key:sk");
    file(
        &mut b,
        T0 + 4,
        filing("r2", guard('b', vec![]), box_user(1001)),
    );
    b.decide(
        &c,
        T0 + 5,
        "r2",
        laptop_decide(&b, &c, "r2", &sk, true, false, Some(3)),
    )
    .unwrap();
    let e = b
        .decide(
            &c,
            T0 + 6,
            "r2",
            laptop_decide_as(
                &b,
                &c,
                "r2",
                &sk,
                Outcome::Revoke,
                "revoke",
                false,
                false,
                Some(4),
            ),
        )
        .unwrap_err();
    assert!(e.contains("same or higher authority"), "{e}");
}

#[test]
fn the_seen_set_is_keyed_by_the_request_and_the_key_never_by_the_signature_bytes() {
    let c = ctx();
    let k = key("ec", KeyType::EcdsaSk, true);
    let mut b = book();
    file(&mut b, T0, filing("n1", guard('a', vec![]), box_user(1000)));
    b.decide(
        &c,
        T0 + 1,
        "n1",
        laptop_decide(&b, &c, "n1", &k, true, false, Some(1)),
    )
    .unwrap();
    assert_eq!(b.seen, vec![assertion_hash("ec", "n1", Outcome::Approve)]);
    // an ECDSA signature rewritten as (r, n - s) still verifies; it must still read as the same decision
    let mut c2 = book();
    file(
        &mut c2,
        T0,
        filing("n1", guard('a', vec![]), box_user(1000)),
    );
    c2.seen = b.seen.clone();
    let mut again = laptop_decide(&c2, &c, "n1", &k, true, false, Some(2));
    let ev = again.evidence.laptop.as_mut().unwrap();
    ev.signature = crate::approval_verify::tests::malleate_ecdsa_der(&ev.signature);
    // the rewrite verifies on its own...
    let digest = from_hex(&c2.get("n1").unwrap().subject_digest).unwrap();
    let mut d32 = [0u8; 32];
    d32.copy_from_slice(&digest);
    let want = crate::approval_verify::Expected::new(&c.ids, "n1", &d32, "approve");
    assert!(verify_laptop(&k, again.evidence.laptop.as_ref().unwrap(), &want).is_ok());
    // ...and is refused as already used
    assert!(c2
        .decide(&c, T0 + 2, "n1", again)
        .unwrap_err()
        .contains("already used"));
}

/// B4-28: a software key never decides Production on the request path, in any environment the rules call Production or for a
/// key whose name says production, and the refusal names what does approve it. Every row of the table is classified, so a new
/// row (or a new kind of software cell) cannot leave Production open to a software key without this test saying so.
#[test]
fn a_software_key_never_decides_production_in_any_row_and_is_told_what_does() {
    // every software cell this version knows means "never Production"; a new variant must be added here on purpose
    for r in RULES {
        let never_production = match r.software {
            Soft::MemberLevel | Soft::NewNonProductionNames | Soft::Never | Soft::NotApplicable => {
                true
            }
        };
        assert!(never_production, "{}", r.key);
    }
    let c = ctx();
    let sw = key("soft", KeyType::Ed25519, false);
    let mut subjects: Vec<(String, Subject)> = ["production", "prod", "live", "qa", "uat"]
        .iter()
        .map(|e| (e.to_string(), import(e, Classification::Secret)))
        .collect();
    let mut named = import("staging", Classification::Secret);
    if let Subject::Import(i) = &mut named {
        i.names[0].name = "STRIPE_LIVE_KEY".into();
    }
    subjects.push(("staging with a live name".into(), named));
    let mut flagged = import("staging", Classification::Secret);
    if let Subject::Import(i) = &mut flagged {
        i.production = true;
    }
    subjects.push(("staging marked production".into(), flagged));
    for (n, (what, s)) in subjects.into_iter().enumerate() {
        assert!(s.production(), "{what}");
        let mut b = book();
        let id = format!("p{n}");
        b.file(&c, T0, filing(&id, s, laptop("lap"))).unwrap();
        let e = b
            .decide(
                &c,
                T0 + 1,
                &id,
                laptop_decide(&b, &c, &id, &sw, false, false, None),
            )
            .unwrap_err();
        assert!(
            e.contains("never decides Production")
                && e.contains("dashboard")
                && e.contains("passkey"),
            "{what}: {e}"
        );
    }
    // a non-Production import of a new name is still a software key's to decide
    let mut b = book();
    b.file(
        &c,
        T0,
        filing(
            "s",
            import("staging", Classification::Secret),
            laptop("lap"),
        ),
    )
    .unwrap();
    b.decide(
        &c,
        T0 + 1,
        "s",
        laptop_decide(&b, &c, "s", &sw, false, false, None),
    )
    .unwrap();
}
