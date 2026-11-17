//! The approval path over the channel: a worker asks, `main` shows the card, the person decides on `main`, and the worker's own
//! service verifies. And the negative side: a message can ask and never grant, and a worker never approves.

#![allow(clippy::unwrap_used)]

use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

use super::approvals::{
    ApprovalService, Approver, ApproverSet, DecisionBody, MemApprovals, AUDIT_REJECTED,
    AUDIT_RELAYED, AUDIT_SHOWN, AUDIT_WORKER_DECIDED, AUDIT_WORKER_REFUSED,
};
use super::engine::{HubError, HubState};
use super::tests::{actions, claim_seq, connect, fx, Fx};
use super::wire::{Kind, Transport};
use super::worker::WorkerState;
use crate::approval::{Outcome, PasskeyEvidence, Requester, RequesterKind, Role, State};
use crate::approval_subject::{
    decide_challenge, from_hex, to_hex, GuardHook, Ids, Subject, WorkerKeys,
};
use crate::approval_verify::ExpectedRp;

pub(super) const NOW: u64 = 1_000_000;

pub(super) fn rp() -> ExpectedRp {
    ExpectedRp {
        rp_id: "dash.example.com".into(),
        origin: "https://dash.example.com".into(),
    }
}

fn worker_ids() -> Ids {
    Ids {
        box_id: "worker-1".into(),
        store_id: "store-w1".into(),
    }
}

/// A WebAuthn credential, as the owner's authenticator holds it.
pub(super) struct Passkey {
    pub(super) id: String,
    key: EcdsaKeyPair,
}

impl Passkey {
    pub(super) fn new(id: &str) -> Passkey {
        let rng = SystemRandom::new();
        let pk = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        Passkey {
            id: id.into(),
            key: EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pk.as_ref(), &rng)
                .unwrap(),
        }
    }

    pub(super) fn public_hex(&self) -> String {
        to_hex(self.key.public_key().as_ref())
    }

    /// What a browser makes for `challenge` on `rp`: authenticator data with the flags and counter, client data, a signature.
    pub(super) fn assert(
        &self,
        rp: &ExpectedRp,
        challenge: &[u8; 32],
        flags: u8,
        counter: u32,
    ) -> PasskeyEvidence {
        let mut ad = ring::digest::digest(&ring::digest::SHA256, rp.rp_id.as_bytes())
            .as_ref()
            .to_vec();
        ad.push(flags);
        ad.extend_from_slice(&counter.to_be_bytes());
        let cd = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"{}"}}"#,
            b64url(challenge),
            rp.origin
        )
        .into_bytes();
        let mut payload = ad.clone();
        payload.extend_from_slice(ring::digest::digest(&ring::digest::SHA256, &cd).as_ref());
        let sig = self.key.sign(&SystemRandom::new(), &payload).unwrap();
        PasskeyEvidence {
            credential_id: self.id.clone(),
            authenticator_data: to_hex(&ad),
            client_data: to_hex(&cd),
            signature: to_hex(sig.as_ref()),
        }
    }
}

fn b64url(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for c in b.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..=c.len() {
            out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

fn hex64(c: char) -> String {
    std::iter::repeat_n(c, 64).collect()
}

pub(super) fn guard(tree: char) -> Subject {
    Subject::GuardOverride(GuardHook::Commit {
        // one repository per tree, so two asks are two slots (a second filing in one slot replaces the first)
        repo_path_hash: hex64(tree),
        hook_kind: "pre-commit".into(),
        tree_id: tree.to_string().repeat(40),
        matches: Vec::new(),
        scanned_text_hash: hex64('2'),
    })
}

/// A worker with its own approval service, an approver set holding the owner's passkey, and a session with `main`.
struct World {
    f: Fx,
    hs: HubState,
    ws: WorkerState,
    svc: MemApprovals,
    owner: Passkey,
}

fn world() -> World {
    let f = fx();
    let (mut hs, mut ws) = (f.hub_state(), f.worker_state());
    connect(&f, &mut hs, &mut ws, NOW - 10);
    let mut svc = MemApprovals::new(worker_ids()).unwrap();
    let owner = Passkey::new("cred-owner");
    svc.approvers = Some(ApproverSet {
        seq: 1,
        expires_ms: NOW + 7 * 86_400_000,
        rp: rp(),
        approvers: vec![Approver {
            credential_id: owner.id.clone(),
            public_key_hex: owner.public_hex(),
            person: "owner".into(),
            role: Role::Owner,
        }],
    });
    hs.pin_service("worker-1", svc.pin());
    hs.take_audit();
    ws.take_audit();
    World {
        f,
        hs,
        ws,
        svc,
        owner,
    }
}

impl World {
    /// The worker's agent files a request on its own box and the worker announces it to `main`.
    fn ask(&mut self, id: &str, tree: char) -> String {
        let r = self
            .svc
            .file(
                NOW,
                id,
                guard(tree),
                Requester::new(RequesterKind::BoxUser, Some(1000)),
            )
            .unwrap();
        let w = self.f.worker();
        assert_eq!(w.announce_approvals(&mut self.ws, &self.svc, NOW + 1), 1);
        self.f.hub().poll(&mut self.hs, NOW + 2);
        r.subject_digest
    }

    fn challenge(&self, id: &str, digest: &str, outcome: &str) -> [u8; 32] {
        let d: [u8; 32] = from_hex(digest).unwrap().try_into().unwrap();
        decide_challenge(&worker_ids(), id, &d, outcome)
    }

    /// The worker takes what `main` sent and its service decides.
    fn worker_round(&mut self, at: u64) -> Vec<(String, Result<String, String>)> {
        let w = self.f.worker();
        w.poll(&mut self.ws, at);
        w.apply_decisions(&mut self.ws, &mut self.svc, at)
    }

    fn decision(
        &self,
        id: &str,
        digest: &str,
        outcome: Outcome,
        ev: Option<PasskeyEvidence>,
    ) -> DecisionBody {
        DecisionBody {
            request_id: id.into(),
            subject_digest: digest.into(),
            outcome,
            claimed_person: "owner".into(),
            passkey: ev,
        }
    }
}

#[test]
fn a_worker_asks_main_shows_the_card_the_owner_approves_on_main_and_the_worker_verifies() {
    let mut w = world();
    let digest = w.ask("r1", 'a');
    // the card on main is derived from the signed envelope, and its challenge is the worker's own
    let inbox = w.hs.inbox(NOW + 3);
    assert_eq!(inbox.len(), 1);
    let card = &inbox[0];
    assert_eq!(
        (card.worker.as_str(), card.request_id.as_str()),
        ("worker-1", "r1")
    );
    assert!(card.decidable_here);
    let want = w.challenge("r1", &digest, "approve");
    assert_eq!(card.approve_challenge, to_hex(&want));
    assert_eq!(
        (card.box_id.as_str(), card.store_id.as_str()),
        ("worker-1", "store-w1")
    );
    assert!(actions(&w.hs.take_audit()).contains(&AUDIT_SHOWN));
    // the owner signs that challenge with a passkey on main's dashboard; main relays the assertion
    let ev = w.owner.assert(&rp(), &want, 0x05, 7);
    let d = w.decision("r1", &digest, Outcome::Approve, Some(ev));
    w.f.hub()
        .relay_decision(&mut w.hs, "worker-1", &d, NOW + 4)
        .unwrap();
    assert!(actions(&w.hs.take_audit()).contains(&AUDIT_RELAYED));
    // nothing is approved until the worker's own service has verified it
    assert_eq!(w.svc.state_of("r1"), Some(State::Pending));
    let out = w.worker_round(NOW + 5);
    assert_eq!(out, vec![("r1".to_string(), Ok("approved".to_string()))]);
    assert_eq!(w.svc.state_of("r1"), Some(State::Approved));
    let dec = w.svc.book.get("r1").unwrap().decision.clone().unwrap();
    assert_eq!(dec.via_fleet.as_deref(), Some("fleet:main"));
    assert_eq!(dec.decider, "owner");
    assert!(actions(&w.ws.take_audit()).contains(&AUDIT_WORKER_DECIDED));
    // the worker's answer comes back to main as the worker's own status
    w.f.hub().poll(&mut w.hs, NOW + 6);
    let s = &w.hs.peers["worker-1"].report.status["-"]["-"];
    assert_eq!(s.state, "approval");
    assert!(s.text.contains("r1 is approved"));
    // the same assertion cannot be used twice
    w.f.hub()
        .relay_decision(&mut w.hs, "worker-1", &d, NOW + 7)
        .unwrap();
    let again = w.worker_round(NOW + 8);
    assert!(again[0].1.is_err());
}

#[test]
fn main_cannot_approve_without_the_persons_assertion_and_a_forged_relay_is_refused_by_the_worker() {
    let mut w = world();
    let digest = w.ask("r1", 'a');
    let d = w.decision("r1", &digest, Outcome::Approve, None);
    // the hub will not relay it...
    assert!(matches!(
        w.f.hub().relay_decision(&mut w.hs, "worker-1", &d, NOW + 3),
        Err(HubError::Refused(_))
    ));
    // ...and a taken-over hub that sends it anyway gets nothing: the worker's service refuses
    claim_seq(&mut w.hs);
    let seq = w.hs.core.links["worker-1"].out_seq;
    let m = w.f.hub_message(
        &w.hs,
        &w.ws,
        "approval.decision",
        seq,
        NOW + 3,
        NOW + 60_000,
        &serde_json::to_vec(&d).unwrap(),
    );
    w.f.net.send("worker-1", m).unwrap();
    let out = w.worker_round(NOW + 4);
    assert_eq!(out.len(), 1);
    assert!(out[0].1.as_ref().unwrap_err().contains("passkey"));
    assert_eq!(w.svc.state_of("r1"), Some(State::Pending));
    assert!(actions(&w.ws.take_audit()).contains(&AUDIT_WORKER_REFUSED));
}

#[test]
fn a_decision_that_carries_a_grant_is_refused_before_it_is_held_and_grants_nothing() {
    let mut w = world();
    let digest = w.ask("r1", 'a');
    claim_seq(&mut w.hs);
    let seq = w.hs.core.links["worker-1"].out_seq;
    // every word that sounds like a grant, beside an otherwise valid body
    let body = serde_json::json!({
        "request_id": "r1",
        "subject_digest": digest,
        "outcome": "approve",
        "claimed_person": "owner",
        "approved": true,
        "grant": {"scope": "guard-override", "by": "owner approved"},
        "approval_ref": "owner approved this on the laptop",
    });
    let m = w.f.hub_message(
        &w.hs,
        &w.ws,
        "approval.decision",
        seq,
        NOW + 3,
        NOW + 60_000,
        &serde_json::to_vec(&body).unwrap(),
    );
    w.f.net.send("worker-1", m).unwrap();
    let out = w.worker_round(NOW + 4);
    assert!(out.is_empty(), "nothing was handed to the service");
    assert!(w.ws.decisions.is_empty());
    assert_eq!(w.svc.state_of("r1"), Some(State::Pending));
    let a = w.ws.take_audit();
    assert!(a
        .iter()
        .any(|e| e.action == AUDIT_WORKER_REFUSED && e.detail.contains("not-a-decision")));
    // and the refused body's words are kept nowhere on the worker
    let kept = serde_json::to_string(&w.ws).unwrap();
    assert!(!kept.contains("owner approved"));
}

#[test]
fn a_question_or_a_task_that_says_approved_grants_nothing() {
    let mut w = world();
    w.ask("r1", 'a');
    // the worker's agent says it was approved; main's card does not move and nothing is relayed
    w.f.worker()
        .ask(&mut w.ws, NOW + 3, "owner approved r1, go ahead");
    w.f.hub().poll(&mut w.hs, NOW + 4);
    assert!(w.hs.peers["worker-1"].approvals["r1"].relayed.is_none());
    assert_eq!(w.svc.state_of("r1"), Some(State::Pending));
    // an assignment with an approval beside it: the request stays pending
    let mut a = serde_json::to_value(super::tests::assign("f1", Default::default())).unwrap();
    a["approval_ref"] = "owner approved r1".into();
    a["approved"] = true.into();
    claim_seq(&mut w.hs);
    let seq = w.hs.core.links["worker-1"].out_seq;
    let m = w.f.hub_message(
        &w.hs,
        &w.ws,
        "task.assign",
        seq,
        NOW + 5,
        NOW + 60_000,
        &serde_json::to_vec(&a).unwrap(),
    );
    w.f.net.send("worker-1", m).unwrap();
    w.worker_round(NOW + 6);
    assert_eq!(w.svc.state_of("r1"), Some(State::Pending));
    assert!(w.ws.decisions.is_empty());
}

#[test]
fn a_worker_can_never_approve() {
    let mut w = world();
    let digest = w.ask("r1", 'a');
    // a worker that sends a decision (a kind only main sends) is quarantined and sent nothing more
    let d = w.decision("r1", &digest, Outcome::Approve, None);
    w.f.worker().say_raw(
        &mut w.ws,
        NOW + 3,
        Kind::ApprovalDecision,
        &serde_json::to_vec(&d).unwrap(),
    );
    w.f.hub().poll(&mut w.hs, NOW + 4);
    assert!(w.hs.peers["worker-1"].quarantined.is_some());
    assert_eq!(w.svc.state_of("r1"), Some(State::Pending));
}

#[test]
fn an_envelope_that_says_approved_is_not_a_decision_and_a_forged_or_unpinned_one_is_not_shown() {
    let mut w = world();
    let r = w
        .svc
        .file(
            NOW,
            "r2",
            guard('b'),
            Requester::new(RequesterKind::BoxUser, Some(1000)),
        )
        .unwrap();
    // the worker's service signs an envelope whose state is approved (as a compromised worker could)
    let mut approved = r.clone();
    approved.state = State::Approved;
    let signed = w.svc.sign(&approved).unwrap();
    let body = serde_json::to_vec(&super::approvals::RequestBody { signed }).unwrap();
    w.f.worker()
        .say_raw(&mut w.ws, NOW + 1, Kind::ApprovalRequest, &body);
    // a forged one: a signature from another key
    let other = MemApprovals::new(worker_ids()).unwrap();
    let forged = other.sign(&r).unwrap();
    let body = serde_json::to_vec(&super::approvals::RequestBody { signed: forged }).unwrap();
    w.f.worker()
        .say_raw(&mut w.ws, NOW + 1, Kind::ApprovalRequest, &body);
    w.f.hub().poll(&mut w.hs, NOW + 2);
    assert!(w.hs.inbox(NOW + 3).is_empty());
    let a = w.hs.take_audit();
    let rej: Vec<_> = a
        .iter()
        .filter(|e| e.action == AUDIT_REJECTED)
        .map(|e| e.detail.clone())
        .collect();
    assert!(rej.iter().any(|d| d.contains("not-pending")), "{rej:?}");
    assert!(rej.iter().any(|d| d.contains("signature")), "{rej:?}");
    // a worker whose service was never pinned shows nothing at all
    w.hs.service_pins.clear();
    w.ws.announced.clear();
    w.f.worker().announce_approvals(&mut w.ws, &w.svc, NOW + 4);
    w.f.hub().poll(&mut w.hs, NOW + 5);
    assert!(w
        .hs
        .take_audit()
        .iter()
        .any(|e| e.detail.contains("unpinned")));
}

#[test]
fn an_assertion_from_another_key_or_over_another_boxs_challenge_is_refused() {
    let mut w = world();
    let digest = w.ask("r1", 'a');
    let want = w.challenge("r1", &digest, "approve");
    // the same credential id from another key: the signature cannot verify
    let stranger = Passkey::new("cred-owner");
    let other_key = stranger.assert(&rp(), &want, 0x05, 1);
    // main's own ids: an assertion made for main's box is not one for the worker
    let main_ids = Ids {
        box_id: "main".into(),
        store_id: "store-main".into(),
    };
    let d32: [u8; 32] = from_hex(&digest).unwrap().try_into().unwrap();
    let wrong_box = w.owner.assert(
        &rp(),
        &decide_challenge(&main_ids, "r1", &d32, "approve"),
        0x05,
        2,
    );
    // another origin
    let other_rp = ExpectedRp {
        rp_id: "evil.example.com".into(),
        origin: "https://evil.example.com".into(),
    };
    let wrong_origin = w.owner.assert(&other_rp, &want, 0x05, 3);
    // a touch without user verification
    let no_uv = w.owner.assert(&rp(), &want, 0x01, 4);
    // a deny's assertion offered as an approval
    let deny_sig = w
        .owner
        .assert(&rp(), &w.challenge("r1", &digest, "deny"), 0x05, 5);
    for (i, ev) in [other_key, wrong_box, wrong_origin, no_uv, deny_sig]
        .into_iter()
        .enumerate()
    {
        let d = w.decision("r1", &digest, Outcome::Approve, Some(ev));
        w.f.hub()
            .relay_decision(&mut w.hs, "worker-1", &d, NOW + 10 + i as u64)
            .unwrap();
        let out = w.worker_round(NOW + 11 + i as u64);
        assert!(out[0].1.is_err(), "case {i}");
        assert_eq!(w.svc.state_of("r1"), Some(State::Pending), "case {i}");
    }
}

#[test]
fn a_relayed_deny_needs_no_assertion_and_an_expired_set_decides_nothing() {
    let mut w = world();
    let d1 = w.ask("r1", 'a');
    let d2 = w.ask("r2", 'b');
    let deny = w.decision("r1", &d1, Outcome::Deny, None);
    w.f.hub()
        .relay_decision(&mut w.hs, "worker-1", &deny, NOW + 3)
        .unwrap();
    assert_eq!(w.worker_round(NOW + 4)[0].1, Ok("denied".to_string()));
    // the set expires: a correct assertion is refused until the laptop renews it
    w.svc.approvers.as_mut().unwrap().expires_ms = NOW + 5;
    let want = w.challenge("r2", &d2, "approve");
    let ev = w.owner.assert(&rp(), &want, 0x05, 9);
    let d = w.decision("r2", &d2, Outcome::Approve, Some(ev));
    w.f.hub()
        .relay_decision(&mut w.hs, "worker-1", &d, NOW + 6)
        .unwrap();
    let out = w.worker_round(NOW + 7);
    assert!(out[0].1.as_ref().unwrap_err().contains("expired"));
    assert_eq!(w.svc.state_of("r2"), Some(State::Pending));
}

#[test]
fn production_and_laptop_only_scopes_are_never_decided_from_main() {
    let mut w = world();
    let r = w
        .svc
        .file(
            NOW,
            "r9",
            guard('c'),
            Requester::new(RequesterKind::BoxUser, Some(1000)),
        )
        .unwrap();
    let mk = |names: &[&str]| {
        Subject::WorkerKeys(WorkerKeys {
            orchestration_id: "orch-1".into(),
            names: names.iter().map(|n| n.to_string()).collect(),
            environment: "staging".into(),
            max_workers: 1,
            ttl_s: 600,
        })
    };
    for (names, want_word) in [
        (&["STRIPE_LIVE_KEY"][..], "Production"),
        (&["SUPABASE_URL"][..], "laptop key"),
    ] {
        let mut req = r.clone();
        let s = mk(names);
        req.scope = crate::approval::Scope::WorkerKeys;
        req.subject_digest = s.digest_hex(&worker_ids()).unwrap();
        req.subject = s;
        let d32: [u8; 32] = from_hex(&req.subject_digest).unwrap().try_into().unwrap();
        let ev = w.owner.assert(
            &rp(),
            &decide_challenge(&worker_ids(), &req.id, &d32, "approve"),
            0x05,
            1,
        );
        let d = w.decision(&req.id, &req.subject_digest, Outcome::Approve, Some(ev));
        let e = super::approvals::verify_fleet_decision(
            w.svc.approvers.as_ref(),
            &worker_ids(),
            &req,
            &d,
            "main",
            NOW,
        )
        .unwrap_err();
        assert!(e.contains(want_word), "{e}");
        // and main's card says it cannot be decided there
        let env = req.envelope(&worker_ids());
        assert!(super::approvals::not_decidable_here(&env).is_some());
    }
}

#[test]
fn a_pending_request_is_announced_again_after_thirty_seconds_and_not_before() {
    let mut w = world();
    let digest = w.ask("r1", 'a');
    let wk = w.f.worker();
    assert_eq!(wk.announce_approvals(&mut w.ws, &w.svc, NOW + 10_000), 0);
    assert_eq!(wk.announce_approvals(&mut w.ws, &w.svc, NOW + 31_000), 1);
    // once it is decided it is no longer announced
    let deny = w.decision("r1", &digest, Outcome::Deny, None);
    w.svc
        .decide_from_fleet("main", &deny, NOW + 32_000)
        .unwrap();
    assert_eq!(wk.announce_approvals(&mut w.ws, &w.svc, NOW + 90_000), 0);
    let _: &dyn Transport = &w.f.net;
}
