//! The owner's approvers, carried to a worker: signed by the owner's computer, verified by the worker's own service before it is
//! written, versioned so an older list is never taken, and unable to be changed by `main` alone.

#![allow(clippy::unwrap_used)]

use ring::signature::{Ed25519KeyPair, KeyPair};

use super::approvals::{ApprovalService, DecisionBody, MemApprovals};
use super::approver_sync::{
    build_set, signed_bytes, CredentialRecord, SetBody, SignedApprovers, APPROVERS_TAG, AUDIT_SENT,
    AUDIT_WORKER_REFUSED, AUDIT_WORKER_SET, CODE_APPROVERS_REFUSED, MAX_VALID_MS,
};
use super::engine::{HubError, HubState};
use super::testkit::Passkey;
use super::tests::{actions, claim_seq, connect, fx, Fx};
use super::tests_approvals::{guard, rp, NOW};
use super::wire::Transport;
use super::worker::WorkerState;
use crate::approval::{Outcome, Requester, RequesterKind, Role, State};
use crate::approval_subject::{decide_challenge, from_hex, to_hex, Ids};

const DAY: u64 = 86_400_000;

fn ids() -> Ids {
    Ids {
        box_id: "worker-1".into(),
        store_id: "store-w1".into(),
    }
}

/// The owner's computer: an Ed25519 approval key.
struct Laptop(Ed25519KeyPair);

impl Laptop {
    fn new() -> Laptop {
        let rng = ring::rand::SystemRandom::new();
        let pk = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        Laptop(Ed25519KeyPair::from_pkcs8(pk.as_ref()).unwrap())
    }
    fn public(&self) -> String {
        to_hex(self.0.public_key().as_ref())
    }
    fn sign_with_tag(&self, tag: &str, body: &str) -> SignedApprovers {
        let mut m = tag.as_bytes().to_vec();
        m.push(b'\n');
        m.extend_from_slice(body.as_bytes());
        SignedApprovers {
            body: body.to_string(),
            signature: to_hex(self.0.sign(&m).as_ref()),
        }
    }
    fn sign(&self, b: &SetBody) -> SignedApprovers {
        let text = b.to_text().unwrap();
        SignedApprovers {
            signature: to_hex(self.0.sign(&signed_bytes(&text)).as_ref()),
            body: text,
        }
    }
}

fn record(p: &Passkey, person: &str, role: Role) -> CredentialRecord {
    CredentialRecord {
        credential_id: p.id.clone(),
        person: person.into(),
        role,
        public_key: p.public_hex(),
        rp: rp(),
    }
}

fn body(records: &[CredentialRecord], seq: u64, issued: u64, valid: u64) -> SetBody {
    build_set(&ids(), records, seq, valid, issued).unwrap()
}

struct World {
    f: Fx,
    hs: HubState,
    ws: WorkerState,
    svc: MemApprovals,
    laptop: Laptop,
}

fn world() -> World {
    let f = fx();
    let (mut hs, mut ws) = (f.hub_state(), f.worker_state());
    connect(&f, &mut hs, &mut ws, NOW - 10);
    let mut svc = MemApprovals::new(ids()).unwrap();
    let laptop = Laptop::new();
    svc.trusted = vec![laptop.public()];
    hs.pin_service("worker-1", svc.pin());
    hs.take_audit();
    ws.take_audit();
    World {
        f,
        hs,
        ws,
        svc,
        laptop,
    }
}

impl World {
    fn send(&mut self, s: &SignedApprovers, at: u64) -> Result<u64, HubError> {
        self.f.hub().send_approvers(&mut self.hs, "worker-1", s, at)
    }

    /// The worker takes what main sent; its service verifies.
    fn worker_takes(&mut self, at: u64) -> Vec<Result<u64, String>> {
        let w = self.f.worker();
        w.poll(&mut self.ws, at);
        w.apply_approver_sets(&mut self.ws, &mut self.svc, at)
    }

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
        w.announce_approvals(&mut self.ws, &self.svc, NOW + 1);
        self.f.hub().poll(&mut self.hs, NOW + 2);
        r.subject_digest
    }

    fn approve(
        &mut self,
        p: &Passkey,
        id: &str,
        digest: &str,
        counter: u32,
        at: u64,
    ) -> Result<String, String> {
        let d: [u8; 32] = from_hex(digest).unwrap().try_into().unwrap();
        let ch = decide_challenge(&ids(), id, &d, "approve");
        let ev = p.assert(&rp(), &ch, 0x05, counter).unwrap();
        let body = DecisionBody {
            request_id: id.into(),
            subject_digest: digest.into(),
            outcome: Outcome::Approve,
            claimed_person: "owner".into(),
            passkey: Some(ev),
        };
        self.f
            .hub()
            .relay_decision(&mut self.hs, "worker-1", &body, at)
            .unwrap();
        let w = self.f.worker();
        w.poll(&mut self.ws, at + 1);
        let mut out = w.apply_decisions(&mut self.ws, &mut self.svc, at + 1);
        out.remove(0).1
    }
}

#[test]
fn a_set_signed_by_the_owner_lets_the_worker_decide_a_relayed_ask_and_nothing_did_before() {
    let mut w = world();
    let owner = Passkey::new("cred-owner").unwrap();
    let digest = w.ask("r1", 'a');
    // before any set, the worker decides nothing from main
    let before = w.approve(&owner, "r1", &digest, 1, NOW + 3);
    assert!(before.unwrap_err().contains("no approver set"));
    // the owner's computer signs a list; main carries it; the worker's service verifies and writes
    let set = w.laptop.sign(&body(
        &[record(&owner, "owner", Role::Owner)],
        1,
        NOW,
        30 * DAY,
    ));
    assert_eq!(w.send(&set, NOW + 10).unwrap(), 1);
    assert!(actions(&w.hs.take_audit()).contains(&AUDIT_SENT));
    assert_eq!(w.worker_takes(NOW + 11), vec![Ok(1)]);
    assert!(actions(&w.ws.take_audit()).contains(&AUDIT_WORKER_SET));
    assert_eq!(w.svc.approvers.as_ref().unwrap().seq, 1);
    // and now the owner's passkey, relayed through main, decides
    let r = w.approve(&owner, "r1", &digest, 2, NOW + 20);
    assert_eq!(r, Ok("approved".to_string()));
    assert_eq!(w.svc.state_of("r1"), Some(State::Approved));
    // main sees the worker's own account of the version it holds
    w.f.hub().poll(&mut w.hs, NOW + 30);
    assert_eq!(w.hs.peers["worker-1"].approvers.sent_seq, 1);
    assert_eq!(w.hs.peers["worker-1"].approvers.held_seq, 1);
}

#[test]
fn an_unsigned_forged_wrong_tag_or_member_signed_set_is_refused_and_nothing_is_written() {
    let mut w = world();
    let owner = Passkey::new("cred-owner").unwrap();
    let rec = [record(&owner, "owner", Role::Owner)];
    let b = body(&rec, 1, NOW, 30 * DAY);
    let text = b.to_text().unwrap();
    let stranger = Laptop::new();
    let member_key = Laptop::new(); // a member's key: not one this box trusts
    let cases: Vec<(&str, SignedApprovers)> = vec![
        (
            "unsigned",
            SignedApprovers {
                body: text.clone(),
                signature: String::new(),
            },
        ),
        (
            "zeros",
            SignedApprovers {
                body: text.clone(),
                signature: "00".repeat(64),
            },
        ),
        ("forged by a stranger", stranger.sign(&b)),
        ("member-signed", member_key.sign(&b)),
        (
            "the fleet tag, not this one",
            w.laptop.sign_with_tag("ozbox-fleet-approvers-v1", &text),
        ),
        (
            "signed, then the body changed",
            SignedApprovers {
                body: text.replace("\"person\":\"owner\"", "\"person\":\"mallory\""),
                signature: w.laptop.sign(&b).signature,
            },
        ),
    ];
    for (name, s) in cases {
        w.send(&s, NOW + 10)
            .unwrap_or_else(|e| panic!("{name}: the hub only carries: {e}"));
        let out = w.worker_takes(NOW + 11);
        assert_eq!(out.len(), 1, "{name}");
        assert!(out[0].is_err(), "{name} was taken");
        assert!(w.svc.approvers.is_none(), "{name} wrote a set");
        // the hub's own early check does not stop a re-send of the same version here, so reset what it remembers
        w.hs.peers.get_mut("worker-1").unwrap().approvers.sent_seq = 0;
    }
    let a = w.ws.take_audit();
    assert!(
        actions(&a)
            .iter()
            .filter(|x| **x == AUDIT_WORKER_REFUSED)
            .count()
            >= 6
    );
    // main learns the worker refused, in the worker's words
    w.f.hub().poll(&mut w.hs, NOW + 12);
    assert!(w.hs.peers["worker-1"].approvers.refused.is_some());
    assert_eq!(w.hs.peers["worker-1"].approvers.held_seq, 0);
}

#[test]
fn an_older_or_equal_set_is_never_taken_and_a_set_for_another_box_or_an_expired_one_is_refused() {
    let mut w = world();
    let owner = Passkey::new("cred-owner").unwrap();
    let rec = [record(&owner, "owner", Role::Owner)];
    let v2 = w.laptop.sign(&body(&rec, 2, NOW, 30 * DAY));
    w.send(&v2, NOW + 1).unwrap();
    assert_eq!(w.worker_takes(NOW + 2), vec![Ok(2)]);
    w.f.hub().poll(&mut w.hs, NOW + 2);
    // the hub's own early check says so at once
    let v1 = w.laptop.sign(&body(&rec, 1, NOW, 30 * DAY));
    assert!(
        matches!(w.send(&v1, NOW + 3), Err(HubError::Refused(r)) if r.code == CODE_APPROVERS_REFUSED)
    );
    // and a hub that sends it anyway (a taken-over one) gets nothing: the worker's service refuses a rollback
    claim_seq(&mut w.hs);
    let seq = w.hs.core.links["worker-1"].out_seq;
    let m = w.f.hub_message(
        &w.hs,
        &w.ws,
        "pins.set",
        seq,
        NOW + 3,
        NOW + 60_000,
        &serde_json::to_vec(&v1).unwrap(),
    );
    w.f.net.send("worker-1", m).unwrap();
    let out = w.worker_takes(NOW + 4);
    assert!(out[0].as_ref().unwrap_err().contains("not newer"));
    assert_eq!(w.svc.approvers.as_ref().unwrap().seq, 2);
    // another box's set (signed by the owner, for other ids) is no use here
    let mut other = body(&rec, 9, NOW, 30 * DAY);
    other.box_id = "worker-2".into();
    other.store_id = "store-w2".into();
    let s = w.laptop.sign(&other);
    assert!(matches!(w.send(&s, NOW + 5), Err(HubError::Refused(_))));
    let mut svc_direct = MemApprovals::new(ids()).unwrap();
    svc_direct.trusted = vec![w.laptop.public()];
    assert!(svc_direct
        .set_approvers(&s, NOW)
        .unwrap_err()
        .contains("another box"));
    // expired, dated in the future, valid for too long, empty
    let old = w.laptop.sign(&body(&rec, 9, 1, DAY));
    assert!(svc_direct
        .set_approvers(&old, 3 * DAY)
        .unwrap_err()
        .contains("expired"));
    let future = w.laptop.sign(&body(&rec, 9, NOW + 2 * DAY, 30 * DAY));
    assert!(svc_direct
        .set_approvers(&future, NOW)
        .unwrap_err()
        .contains("expired"));
    let mut long = body(&rec, 9, NOW, 30 * DAY);
    long.set.expires_ms = NOW + MAX_VALID_MS + DAY;
    assert!(svc_direct
        .set_approvers(&w.laptop.sign(&long), NOW)
        .is_err());
    let mut empty = body(&rec, 9, NOW, 30 * DAY);
    empty.set.approvers.clear();
    assert!(svc_direct
        .set_approvers(&w.laptop.sign(&empty), NOW)
        .is_err());
    assert!(svc_direct.approvers.is_none());
    // a box with no trusted computer key takes nothing
    svc_direct.trusted.clear();
    let ok = w.laptop.sign(&body(&rec, 1, NOW, 30 * DAY));
    assert!(svc_direct
        .set_approvers(&ok, NOW)
        .unwrap_err()
        .contains("no trusted"));
}

#[test]
fn main_alone_cannot_change_who_approves_a_body_that_is_not_a_signed_list_is_refused_before_it_is_held(
) {
    let mut w = world();
    claim_seq(&mut w.hs);
    let seq = w.hs.core.links["worker-1"].out_seq;
    // an approver set in the service's own shape, with no signature, and one with a grant beside the fields
    let plain = serde_json::json!({"seq": 5, "expires_ms": NOW + DAY, "rp": rp(), "approvers": []});
    let extra = serde_json::json!({"body": "{}", "signature": "00", "approved": true});
    for (i, b) in [plain, extra].iter().enumerate() {
        let m = w.f.hub_message(
            &w.hs,
            &w.ws,
            "pins.set",
            seq + i as u64,
            NOW + 3,
            NOW + 60_000,
            &serde_json::to_vec(b).unwrap(),
        );
        w.f.net.send("worker-1", m).unwrap();
    }
    w.worker_takes(NOW + 4);
    assert!(w.ws.approver_sets.is_empty(), "nothing was held");
    assert!(w.svc.approvers.is_none());
}

#[test]
fn an_approver_removed_by_a_newer_set_can_no_longer_approve() {
    let mut w = world();
    let owner = Passkey::new("cred-owner").unwrap();
    let other = Passkey::new("cred-second").unwrap();
    let both = [
        record(&owner, "owner", Role::Owner),
        record(&other, "second", Role::Owner),
    ];
    let s1 = w.laptop.sign(&body(&both, 1, NOW, 30 * DAY));
    w.send(&s1, NOW + 1).unwrap();
    assert_eq!(w.worker_takes(NOW + 2), vec![Ok(1)]);
    // the owner's key is lost: the new list names only the second person
    let s2 = w.laptop.sign(&body(&both[1..], 2, NOW + 3, 30 * DAY));
    w.send(&s2, NOW + 4).unwrap();
    assert_eq!(w.worker_takes(NOW + 5), vec![Ok(2)]);
    let digest = w.ask("r1", 'a');
    let gone = w.approve(&owner, "r1", &digest, 3, NOW + 10);
    assert!(gone
        .unwrap_err()
        .contains("not in this worker's approver set"));
    assert_eq!(w.svc.state_of("r1"), Some(State::Pending));
    let kept = w.approve(&other, "r1", &digest, 3, NOW + 20);
    assert_eq!(kept, Ok("approved".to_string()));
}

#[test]
fn no_key_or_signature_value_is_in_the_hubs_state_the_workers_state_its_audit_or_its_answers() {
    let mut w = world();
    let owner = Passkey::new("cred-owner").unwrap();
    let rec = [record(&owner, "owner", Role::Owner)];
    let s = w.laptop.sign(&body(&rec, 1, NOW, 30 * DAY));
    // refused once (a stranger's), taken once
    let bad = Laptop::new().sign(&body(&rec, 7, NOW, 30 * DAY));
    w.send(&bad, NOW + 1).unwrap();
    let r = w.worker_takes(NOW + 2);
    assert!(r[0].is_err());
    w.hs.peers.get_mut("worker-1").unwrap().approvers.sent_seq = 0;
    w.send(&s, NOW + 3).unwrap();
    assert_eq!(w.worker_takes(NOW + 4), vec![Ok(1)]);
    w.f.hub().poll(&mut w.hs, NOW + 5);
    let mut seen = serde_json::to_string(&w.hs).unwrap();
    seen.push_str(&serde_json::to_string(&w.ws).unwrap());
    seen.push_str(
        &serde_json::to_string(
            &w.hs
                .take_audit()
                .iter()
                .map(|e| e.detail.clone())
                .collect::<Vec<_>>(),
        )
        .unwrap(),
    );
    seen.push_str(
        &serde_json::to_string(
            &w.ws
                .take_audit()
                .iter()
                .map(|e| e.detail.clone())
                .collect::<Vec<_>>(),
        )
        .unwrap(),
    );
    seen.push_str(&serde_json::to_string(&w.hs.peers["worker-1"].report).unwrap());
    for sentinel in [
        s.signature.clone(),
        bad.signature.clone(),
        w.laptop.public(),
        owner.public_hex(),
    ] {
        assert!(!seen.contains(&sentinel), "a key value or signature leaked");
    }
}

#[test]
fn building_a_set_refuses_a_mixed_dashboard_a_zero_version_and_an_unbounded_life() {
    let p = Passkey::new("c").unwrap();
    let a = record(&p, "x", Role::Owner);
    let mut b = a.clone();
    b.rp.origin = "https://other.example.com".into();
    assert!(build_set(&ids(), &[a.clone(), b], 1, DAY, NOW).is_err());
    assert!(build_set(&ids(), &[], 1, DAY, NOW).is_err());
    assert!(build_set(&ids(), std::slice::from_ref(&a), 0, DAY, NOW).is_err());
    assert!(build_set(&ids(), std::slice::from_ref(&a), 1, 0, NOW).is_err());
    assert!(build_set(&ids(), std::slice::from_ref(&a), 1, MAX_VALID_MS + 1, NOW).is_err());
    let ok = build_set(&ids(), &[a], 4, DAY, NOW).unwrap();
    assert_eq!((ok.set.seq, ok.set.expires_ms), (4, NOW + DAY));
    assert_eq!(APPROVERS_TAG, "ozbox-hub-approvers-v1");
}
