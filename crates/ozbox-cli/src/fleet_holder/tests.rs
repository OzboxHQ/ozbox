#![allow(clippy::unwrap_used)]
use super::*;
use crate::approval_key as ak;
use crate::fleet_gate::FleetCredentials;
use ozbox_core::approval_subject::to_hex;
use ozbox_core::approval_verify::ExpectedRp;
use ozbox_core::fleet_approvers::{signed_bytes, Approver};
use ozbox_core::roles::Role;
use ozbox_core::{BoxName, BoxSpec, Operation, Size};
use ring::digest::{digest, SHA256};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use std::sync::{Arc, Mutex};

const SENTINEL: &str = "SENTINEL-CHANGE-SESSION-SECRET";
const NOW: u64 = 1_800_000_000_000;
const BOX: &str = "box-1";
const STORE: &str = "store-1";
const DASH: u32 = 4001;
const INGRESS: u32 = 4002;
const BOX_USER: u32 = 1000;

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

/// The owner's laptop approval key and a passkey, both real.
struct World {
    seed: Zeroizing<String>,
    laptop_pub: String,
    pass: EcdsaKeyPair,
    dir: tempfile::TempDir,
    fake: tempfile::TempDir,
}

fn rp() -> ExpectedRp {
    ExpectedRp {
        rp_id: "x.test".into(),
        origin: "https://x.test".into(),
    }
}

impl World {
    fn new() -> World {
        let (seed, public) = ak::generate().unwrap();
        let rng = SystemRandom::new();
        let pk = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let pass =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pk.as_ref(), &rng).unwrap();
        World {
            seed,
            laptop_pub: public,
            pass,
            dir: tempfile::tempdir().unwrap(),
            fake: tempfile::tempdir().unwrap(),
        }
    }

    fn cfg(&self) -> HolderConfig {
        HolderConfig {
            box_id: BOX.into(),
            store_id: STORE.into(),
            this_box: "main".into(),
            laptop_public_hex: self.laptop_pub.clone(),
            dir: self.dir.path().join("holder"),
        }
    }

    fn holder(&self) -> Holder {
        Holder::new(
            self.cfg(),
            ServiceKey::generate().unwrap(),
            Box::new(FixedRead),
        )
        .unwrap()
    }

    fn approver_set(&self, version: u64, role: Role) -> SignedApproverSet {
        let set = ApproverSet {
            version,
            box_id: BOX.into(),
            store_id: STORE.into(),
            issued_at_ms: NOW,
            approvers: vec![Approver {
                credential_id: "cred-1".into(),
                person: "owner".into(),
                role,
                public_key: to_hex(self.pass.public_key().as_ref()),
                rp: rp(),
            }],
        };
        let text = set.to_text().unwrap();
        let sig = ak::sign(&self.seed, &String::from_utf8(signed_bytes(&text)).unwrap()).unwrap();
        SignedApproverSet {
            set: text,
            signature: sig,
        }
    }

    /// The owner's computer opens a window for a plan.
    fn window(
        &self,
        h: &Holder,
        plan_id: &str,
        plan: &Plan,
        expires_ms: u64,
    ) -> (String, Vec<u8>, Vec<u8>) {
        self.window_with(
            h,
            plan_id,
            plan,
            expires_ms,
            &self.seed,
            plan.operation.box_name().as_str(),
        )
    }

    fn window_with(
        &self,
        h: &Holder,
        plan_id: &str,
        plan: &Plan,
        expires_ms: u64,
        signing_seed: &str,
        window_box: &str,
    ) -> (String, Vec<u8>, Vec<u8>) {
        let hash = ozbox_core::audit::hex(&plan_hash(plan));
        let msg = window_message(BOX, STORE, plan_id, &hash, window_box, expires_ms);
        let payload = WindowPayload {
            plan_id: plan_id.into(),
            plan_hash: hash.clone(),
            window_box: window_box.into(),
            expires_at_ms: expires_ms,
            signature: ak::sign(signing_seed, &msg).unwrap(),
            session: SessionCreds::new(
                "AKIAEXAMPLE",
                SENTINEL,
                "tok-SENTINEL-TOKEN",
                NOW + 900_000,
            ),
        };
        let (enc, ct) = seal_window(&h.public_key(), BOX, STORE, &payload).unwrap();
        (hash, enc, ct)
    }

    fn assertion(&self, cred: &str, flags: u8, counter: u32, ch: &[u8; 32]) -> PasskeyEvidence {
        let mut ad = digest(&SHA256, b"x.test").as_ref().to_vec();
        ad.push(flags);
        ad.extend_from_slice(&counter.to_be_bytes());
        let cd = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://x.test"}}"#,
            b64url(ch)
        )
        .into_bytes();
        let mut payload = ad.clone();
        payload.extend_from_slice(digest(&SHA256, &cd).as_ref());
        let sig = self.pass.sign(&SystemRandom::new(), &payload).unwrap();
        PasskeyEvidence {
            credential_id: cred.into(),
            authenticator_data: to_hex(&ad),
            client_data: to_hex(&cd),
            signature: to_hex(sig.as_ref()),
        }
    }

    fn owner_assertion(&self, plan_id: &str, plan: &Plan, counter: u32) -> PasskeyEvidence {
        let ch = challenge(BOX, STORE, plan_id, &plan_hash(plan));
        self.assertion("cred-1", 0x05, counter, &ch)
    }

    fn provider(&self) -> ozbox_core::Engine<ozbox_provider_fake::FakeBackend> {
        ozbox_provider_fake::open(self.fake.path())
    }
}

struct FixedRead;
impl ReadSessionSource for FixedRead {
    fn assume_read(&self, now_ms: u64) -> Result<SessionCreds, String> {
        Ok(SessionCreds::new(
            "AKIAREAD",
            "read-secret",
            "read-token",
            now_ms + 900_000,
        ))
    }
}

/// The apply unit of a test: the real input path (JSON on standard input), applied through the fake provider.
struct FakeUnit {
    dir: PathBuf,
    saw: Mutex<Vec<String>>,
}
impl ApplyUnit for FakeUnit {
    fn run(&self, ticket: ApplyTicket) -> Result<Value, String> {
        let input = ApplyInput {
            plan: ticket.plan,
            session: ticket.session,
            region: None,
        };
        let stdin = serde_json::to_vec(&input).unwrap();
        // the unit really received the change session
        self.saw
            .lock()
            .unwrap()
            .push(input.session.secret().to_string());
        let dir = self.dir.clone();
        run_apply_unit(&stdin, &move |_| {
            Ok(Box::new(ozbox_provider_fake::open(&dir)) as Box<dyn Provider>)
        })
    }
}

fn peers() -> Peers {
    Peers {
        dashboard_uid: DASH,
        ingress_uid: INGRESS,
    }
}

fn create_plan(w: &World, name: &str) -> Plan {
    w.provider()
        .plan(&Operation::Create {
            spec: BoxSpec::new(BoxName::new(name).unwrap(), Size::S),
        })
        .unwrap()
}

fn call(h: &mut Holder, w: &World, uid: u32, req: Value, now: u64) -> Value {
    let unit = FakeUnit {
        dir: w.fake.path().to_path_buf(),
        saw: Mutex::default(),
    };
    handle(h, &peers(), Some(uid), &unit, &req, now)
}

fn send_window(h: &mut Holder, w: &World, id: &str, plan: &Plan, expires: u64) {
    let (hash, enc, ct) = w.window(h, id, plan, expires);
    h.receive_window(id, &hash, &enc, &ct, NOW).unwrap();
}

fn apply_req(id: &str, plan: &Plan, ev: &PasskeyEvidence) -> Value {
    json!({"op": "apply", "plan_id": id, "plan": plan, "evidence": ev})
}

#[test]
fn plan_then_passkey_then_window_then_a_plan_scoped_session_applies_once_through_the_provider() {
    let w = World::new();
    let mut h = w.holder();
    h.accept_approvers(&w.approver_set(1, Role::Owner)).unwrap();
    let plan = create_plan(&w, "dev");
    send_window(&mut h, &w, "p1", &plan, NOW + 1_800_000);
    assert!(h.window_for("p1", NOW).is_some());
    let ev = w.owner_assertion("p1", &plan, 5);
    let unit = FakeUnit {
        dir: w.fake.path().to_path_buf(),
        saw: Mutex::default(),
    };
    let r = handle(
        &mut h,
        &peers(),
        Some(DASH),
        &unit,
        &apply_req("p1", &plan, &ev),
        NOW + 10,
    );
    assert_eq!(r["ok"], true, "{r}");
    // the unit was handed the change session; the answer is not
    assert_eq!(unit.saw.lock().unwrap().as_slice(), [SENTINEL]);
    assert!(!r.to_string().contains(SENTINEL));
    // the box exists in the fake provider
    assert!(w
        .provider()
        .get(&BoxName::new("dev").unwrap())
        .unwrap()
        .is_some());
    // the window is used up and the plan is spent, durably
    assert!(h.window_for("p1", NOW + 11).is_none());
    assert!(h.is_spent("p1"));
    assert!(std::fs::read_to_string(w.dir.path().join("holder/spent"))
        .unwrap()
        .contains("p1"));
    // a replay of the same assertion is refused, and so after a restart
    let again = call(&mut h, &w, DASH, apply_req("p1", &plan, &ev), NOW + 20);
    assert_eq!(again["code"], "fleet_plan_spent");
    let mut restarted = w.holder();
    assert!(restarted.is_spent("p1"));
    let (hash, enc, ct) = w.window(&restarted, "p1", &plan, NOW + 1_800_000);
    assert_eq!(
        restarted
            .receive_window("p1", &hash, &enc, &ct, NOW + 30)
            .unwrap_err()
            .code,
        "plan_spent",
        "a spent plan gets no new window after a restart"
    );
}

#[test]
fn no_window_means_nothing_is_changed() {
    let w = World::new();
    let mut h = w.holder();
    h.accept_approvers(&w.approver_set(1, Role::Owner)).unwrap();
    let plan = create_plan(&w, "dev");
    let ev = w.owner_assertion("p1", &plan, 1);
    let r = call(&mut h, &w, DASH, apply_req("p1", &plan, &ev), NOW);
    assert_eq!(r["code"], "change_window_required");
    assert!(w
        .provider()
        .get(&BoxName::new("dev").unwrap())
        .unwrap()
        .is_none());
    assert!(!h.is_spent("p1"), "a refusal spends nothing");
}

#[test]
fn an_expired_window_is_refused_and_forgotten() {
    let w = World::new();
    let mut h = w.holder();
    h.accept_approvers(&w.approver_set(1, Role::Owner)).unwrap();
    let plan = create_plan(&w, "dev");
    send_window(&mut h, &w, "p1", &plan, NOW + 60_000);
    let ev = w.owner_assertion("p1", &plan, 1);
    let r = call(&mut h, &w, DASH, apply_req("p1", &plan, &ev), NOW + 60_000);
    assert_eq!(r["code"], "change_window_required");
    assert!(h.window_for("p1", NOW + 61_000).is_none());
    // a window already past its end is not even kept
    let (hash, enc, ct) = w.window(&h, "p2", &plan, NOW - 1);
    assert_eq!(
        h.receive_window("p2", &hash, &enc, &ct, NOW)
            .unwrap_err()
            .code,
        "window_expired"
    );
    assert!(w
        .provider()
        .get(&BoxName::new("dev").unwrap())
        .unwrap()
        .is_none());
}

#[test]
fn a_window_longer_than_the_roles_session_or_for_another_box_or_signed_by_anyone_else_is_refused() {
    let w = World::new();
    let mut h = w.holder();
    let plan = create_plan(&w, "dev");
    // longer than an hour
    let (hash, enc, ct) = w.window(&h, "p1", &plan, NOW + MAX_WINDOW_MS + 1);
    assert!(h.receive_window("p1", &hash, &enc, &ct, NOW).is_err());
    // signed by a key the holder did not pin (a compromised box makes its own)
    let (other_seed, _) = ak::generate().unwrap();
    let (hash, enc, ct) = w.window_with(&h, "p2", &plan, NOW + 60_000, &other_seed, "dev");
    assert_eq!(
        h.receive_window("p2", &hash, &enc, &ct, NOW)
            .unwrap_err()
            .code,
        "window_refused"
    );
    // a window sealed for one plan id cannot be delivered as another
    let (hash, enc, ct) = w.window(&h, "p3", &plan, NOW + 60_000);
    assert!(h.receive_window("p4", &hash, &enc, &ct, NOW).is_err());
    // a window sealed to another holder's key
    let other = w.holder();
    let (hash, enc, ct) = w.window(&other, "p5", &plan, NOW + 60_000);
    assert!(h.receive_window("p5", &hash, &enc, &ct, NOW).is_err());
    assert!(h.window_for("p1", NOW).is_none() && h.window_for("p2", NOW).is_none());
}

#[test]
fn a_window_opened_for_another_plans_content_or_another_box_is_no_window_for_this_plan() {
    let w = World::new();
    let mut h = w.holder();
    h.accept_approvers(&w.approver_set(1, Role::Owner)).unwrap();
    let approved = create_plan(&w, "dev");
    let other = create_plan(&w, "other");
    send_window(&mut h, &w, "p1", &approved, NOW + 600_000);
    // the dashboard asks to apply a different plan under the same id
    let ev = w.owner_assertion("p1", &other, 1);
    let r = call(&mut h, &w, DASH, apply_req("p1", &other, &ev), NOW);
    assert_eq!(r["code"], "change_window_required");
    // a window whose box is not the plan's box
    let (hash, enc, ct) = w.window_with(&h, "p2", &approved, NOW + 600_000, &w.seed, "elsewhere");
    h.receive_window("p2", &hash, &enc, &ct, NOW).unwrap();
    let ev = w.owner_assertion("p2", &approved, 1);
    let r = call(&mut h, &w, DASH, apply_req("p2", &approved, &ev), NOW);
    assert_eq!(r["code"], "change_window_required");
    assert!(w
        .provider()
        .get(&BoxName::new("other").unwrap())
        .unwrap()
        .is_none());
}

#[test]
fn the_passkey_is_checked_against_the_set_the_owners_computer_signed_and_nothing_else() {
    let w = World::new();
    let mut h = w.holder();
    let plan = create_plan(&w, "dev");
    send_window(&mut h, &w, "p1", &plan, NOW + 600_000);
    let ev = w.owner_assertion("p1", &plan, 1);
    // no signed set yet: no confirmation can count
    assert_eq!(
        call(&mut h, &w, DASH, apply_req("p1", &plan, &ev), NOW)["code"],
        "fleet_passkey_required"
    );
    // a set a compromised dashboard made itself (signed with its own key) is not accepted
    let (mallory, _) = ak::generate().unwrap();
    let forged = World {
        seed: mallory,
        ..World::new()
    };
    let mut f = w.approver_set(1, Role::Owner);
    f.signature = ak::sign(
        &forged.seed,
        &String::from_utf8(signed_bytes(&f.set)).unwrap(),
    )
    .unwrap();
    assert_eq!(
        h.accept_approvers(&f).unwrap_err().code,
        "approvers_refused"
    );
    assert_eq!(
        call(&mut h, &w, DASH, apply_req("p1", &plan, &ev), NOW)["code"],
        "fleet_passkey_required"
    );
    // the owner's computer signs a set with the passkey as a MEMBER: refused
    h.accept_approvers(&w.approver_set(1, Role::Member))
        .unwrap();
    assert_eq!(
        call(&mut h, &w, DASH, apply_req("p1", &plan, &ev), NOW)["code"],
        "fleet_passkey_required"
    );
    // an older or equal set never replaces a newer one (a rollback to a list that held a removed passkey)
    assert_eq!(
        h.accept_approvers(&w.approver_set(1, Role::Owner))
            .unwrap_err()
            .code,
        "approvers_old"
    );
    h.accept_approvers(&w.approver_set(2, Role::Owner)).unwrap();
    // another plan's assertion, a credential nobody listed, no check by the authenticator
    let other = create_plan(&w, "other");
    for bad in [
        w.owner_assertion("p1", &other, 1),
        w.assertion(
            "cred-9",
            0x05,
            1,
            &challenge(BOX, STORE, "p1", &plan_hash(&plan)),
        ),
        w.assertion(
            "cred-1",
            0x01,
            1,
            &challenge(BOX, STORE, "p1", &plan_hash(&plan)),
        ),
        w.assertion(
            "cred-1",
            0x05,
            1,
            &challenge("other-box", STORE, "p1", &plan_hash(&plan)),
        ),
    ] {
        assert_eq!(
            call(&mut h, &w, DASH, apply_req("p1", &plan, &bad), NOW)["code"],
            "fleet_passkey_required"
        );
    }
    assert!(!h.is_spent("p1"));
    // the owner's passkey over this plan goes through
    let ok = call(&mut h, &w, DASH, apply_req("p1", &plan, &ev), NOW);
    assert_eq!(ok["ok"], true, "{ok}");
    // the accepted set is read again after a restart, and checked again
    let restarted = w.holder();
    assert!(restarted.approvers.is_some());
}

#[test]
fn an_authenticators_counter_never_goes_back() {
    let w = World::new();
    let mut h = w.holder();
    h.accept_approvers(&w.approver_set(1, Role::Owner)).unwrap();
    let a = create_plan(&w, "a");
    let b = create_plan(&w, "b");
    send_window(&mut h, &w, "p1", &a, NOW + 600_000);
    send_window(&mut h, &w, "p2", &b, NOW + 600_000);
    let ea = w.owner_assertion("p1", &a, 10);
    assert_eq!(
        call(&mut h, &w, DASH, apply_req("p1", &a, &ea), NOW)["ok"],
        true
    );
    let eb = w.owner_assertion("p2", &b, 9);
    assert_eq!(
        call(&mut h, &w, DASH, apply_req("p2", &b, &eb), NOW)["code"],
        "fleet_passkey_required"
    );
    let eb = w.owner_assertion("p2", &b, 11);
    assert_eq!(
        call(&mut h, &w, DASH, apply_req("p2", &b, &eb), NOW)["ok"],
        true
    );
}

#[test]
fn what_a_dashboard_may_not_do_is_refused_by_the_holder_too() {
    let w = World::new();
    let mut h = w.holder();
    h.accept_approvers(&w.approver_set(1, Role::Owner)).unwrap();
    let p = w.provider();
    let plan = p
        .plan(&Operation::Create {
            spec: BoxSpec::new(BoxName::new("main").unwrap(), Size::S),
        })
        .unwrap();
    send_window(&mut h, &w, "p1", &plan, NOW + 600_000);
    let ev = w.owner_assertion("p1", &plan, 1);
    assert_eq!(
        call(&mut h, &w, DASH, apply_req("p1", &plan, &ev), NOW)["code"],
        "fleet_this_box"
    );
}

#[test]
fn a_ledger_that_cannot_be_written_stops_the_apply_before_it_starts() {
    let w = World::new();
    let mut h = w.holder();
    h.accept_approvers(&w.approver_set(1, Role::Owner)).unwrap();
    let plan = create_plan(&w, "dev");
    send_window(&mut h, &w, "p1", &plan, NOW + 600_000);
    // the ledger's path becomes a folder: it cannot be appended to
    std::fs::create_dir(w.dir.path().join("holder/spent")).unwrap();
    let ev = w.owner_assertion("p1", &plan, 1);
    let r = call(&mut h, &w, DASH, apply_req("p1", &plan, &ev), NOW);
    assert_eq!(r["code"], "holder_storage");
    assert!(w
        .provider()
        .get(&BoxName::new("dev").unwrap())
        .unwrap()
        .is_none());
    assert!(!h.is_spent("p1"));
}

#[test]
fn nobody_but_the_two_named_users_gets_anything_and_no_answer_carries_the_change_session() {
    let w = World::new();
    let mut h = w.holder();
    h.accept_approvers(&w.approver_set(1, Role::Owner)).unwrap();
    let plan = create_plan(&w, "dev");
    send_window(&mut h, &w, "p1", &plan, NOW + 600_000);
    let ev = w.owner_assertion("p1", &plan, 1);
    let (hash, enc, ct) = w.window(&h, "p9", &plan, NOW + 600_000);
    let reqs = vec![
        json!({"op": "read_session"}),
        json!({"op": "window_for", "plan_id": "p1"}),
        apply_req("p1", &plan, &ev),
        json!({"op": "window", "plan_id": "p9", "plan_hash": hash, "enc": to_hex(&enc), "ct": to_hex(&ct)}),
        json!({"op": "approvers", "signed": w.approver_set(7, Role::Owner)}),
        json!({"op": "give_me_the_session"}),
    ];
    let unit = FakeUnit {
        dir: w.fake.path().to_path_buf(),
        saw: Mutex::default(),
    };
    let mut said = String::new();
    // the box user, an agent's user, nobody (a kernel that cannot say) and root are refused every operation, alike
    for uid in [Some(BOX_USER), Some(0), Some(65534), None] {
        for r in &reqs {
            let a = handle(&mut h, &peers(), uid, &unit, r, NOW);
            assert_eq!(a["ok"], false, "{uid:?} {r}");
            assert_eq!(a["code"], "not_you", "{uid:?}");
            said.push_str(&a.to_string());
        }
    }
    // the dashboard may not feed a window or a list; the ingress may not read or apply
    for r in &reqs[3..5] {
        assert_eq!(
            handle(&mut h, &peers(), Some(DASH), &unit, r, NOW)["code"],
            "not_you"
        );
    }
    for r in &reqs[..3] {
        assert_eq!(
            handle(&mut h, &peers(), Some(INGRESS), &unit, r, NOW)["code"],
            "not_you"
        );
    }
    // nothing was applied, spent or taken
    assert!(h.window_for("p1", NOW).is_some() && !h.is_spent("p1"));
    assert!(unit.saw.lock().unwrap().is_empty());
    // what the dashboard is allowed to hear never holds the change session, at any point of the flow
    let rs = handle(&mut h, &peers(), Some(DASH), &unit, &reqs[0], NOW);
    assert_eq!(rs["ok"], true);
    said.push_str(&rs.to_string());
    said.push_str(&handle(&mut h, &peers(), Some(DASH), &unit, &reqs[1], NOW).to_string());
    said.push_str(&handle(&mut h, &peers(), Some(DASH), &unit, &reqs[2], NOW).to_string());
    said.push_str(&format!("{h:?}"));
    // and nowhere on disk
    for e in std::fs::read_dir(w.dir.path().join("holder")).unwrap() {
        let text = std::fs::read_to_string(e.unwrap().path()).unwrap_or_default();
        said.push_str(&text);
    }
    assert!(
        !said.contains(SENTINEL) && !said.contains("SENTINEL-TOKEN"),
        "{said}"
    );
    // the ticket and the session print nothing
    let s = SessionCreds::new("AK", SENTINEL, "t", 1);
    assert!(!format!("{s:?}").contains(SENTINEL));
}

#[test]
fn the_read_session_is_renewed_before_it_ends_and_sts_answers_parse() {
    let w = World::new();
    let mut h = w.holder();
    let a = h.read_session(NOW).unwrap();
    assert_eq!(
        h.read_session(NOW + 1000).unwrap().expires_at_ms,
        a.expires_at_ms
    );
    let b = h.read_session(NOW + 800_000).unwrap();
    assert!(b.expires_at_ms > a.expires_at_ms);
    let s = SessionCreds::from_sts_json(
        r#"{"Credentials":{"AccessKeyId":"ASIA","SecretAccessKey":"s","SessionToken":"t","Expiration":"2027-01-15T08:00:00Z"}}"#,
    )
    .unwrap();
    assert_eq!(s.expires_at_ms, 1_800_000_000_000);
    assert_eq!(
        parse_rfc3339_ms("2027-01-15T08:00:00.500+00:00"),
        Some(1_800_000_000_500)
    );
    assert!(SessionCreds::from_sts_json("{}").is_err());
}

struct Capture(Mutex<Vec<CommandSpec>>, String);
impl CommandRunner for Capture {
    fn run(&self, c: &CommandSpec) -> ozbox_core::Result<ozbox_core::Output> {
        self.0.lock().unwrap().push(c.clone());
        Ok(ozbox_core::Output {
            status: Some(0),
            stdout: self.1.clone(),
            stderr: String::new(),
        })
    }
}

#[test]
fn the_read_session_is_asked_for_by_role_with_a_source_identity_and_the_apply_gets_its_session_on_stdin_only(
) {
    let r = Capture(Mutex::default(), r#"{"Credentials":{"AccessKeyId":"ASIA","SecretAccessKey":"s","SessionToken":"t","Expiration":"2027-01-15T08:00:00Z"}}"#.into());
    let src = AwsCliReadSource {
        runner: &r,
        role_arn: "arn:aws:iam::123456789012:role/obx/obx-fleet-read".into(),
        box_name: "main".into(),
    };
    src.assume_read(NOW).unwrap();
    let c = r.0.lock().unwrap()[0].clone();
    assert!(c.args.contains(&"--source-identity".to_string()));
    assert!(c.args.contains(&"900".to_string()));
    assert!(c.env.is_empty());

    let w = World::new();
    let plan = create_plan(&w, "dev");
    let apply = Capture(Mutex::default(), r#"{"applied":true}"#.into());
    let unit = ProcessApplyUnit {
        runner: &apply,
        uid: "ozbox-fleetapply".into(),
        program: "/usr/bin/ozbox".into(),
        region: None,
    };
    unit.run(ApplyTicket {
        plan_id: "p1".into(),
        plan,
        person: "owner".into(),
        session: SessionCreds::new("AKIAEXAMPLE", SENTINEL, "tok", NOW),
    })
    .unwrap();
    let c = apply.0.lock().unwrap()[0].clone();
    assert!(c.args.iter().any(|a| a == "--uid=ozbox-fleetapply"));
    assert!(!c.args.join(" ").contains(SENTINEL), "never in argv");
    assert!(c.env.is_empty(), "never in the environment");
    assert!(
        String::from_utf8(c.stdin.unwrap())
            .unwrap()
            .contains(SENTINEL),
        "on stdin"
    );
}

#[test]
fn the_session_env_runner_adds_the_session_to_each_call_without_keeping_it() {
    let r = Capture(Mutex::default(), String::new());
    let s = SessionCreds::new("AKIAEXAMPLE", SENTINEL, "tok", NOW);
    let er = SessionEnvRunner {
        inner: &r,
        session: &s,
    };
    er.run(&CommandSpec::new("aws").args(["ec2".to_string()]))
        .unwrap();
    let c = r.0.lock().unwrap()[0].clone();
    assert_eq!(
        c.env.get("AWS_SECRET_ACCESS_KEY").map(String::as_str),
        Some(SENTINEL)
    );
    assert!(!c.args.join(" ").contains(SENTINEL));
}

#[test]
fn the_gate_asks_the_holders_durable_ledger_as_well_as_its_own_memory() {
    struct Creds(Arc<Mutex<Holder>>);
    impl FleetCredentials for Creds {
        fn window_for(&self, id: &str) -> Option<WindowStatus> {
            self.0.lock().unwrap().window_for(id, NOW)
        }
        fn is_spent(&self, id: &str) -> bool {
            self.0.lock().unwrap().is_spent(id)
        }
    }
    let w = World::new();
    let mut h = w.holder();
    h.accept_approvers(&w.approver_set(1, Role::Owner)).unwrap();
    let plan = create_plan(&w, "dev");
    send_window(&mut h, &w, "p1", &plan, NOW + 600_000);
    let ev = w.owner_assertion("p1", &plan, 1);
    let shared = Arc::new(Mutex::new(h));
    let gate = crate::fleet_gate::FleetGate::new("main", STORE, Box::new(Creds(shared.clone())));
    // (the gate's own challenge uses its box id; the holder's ledger is what this test is about)
    gate.precheck("p1", &plan, NOW).unwrap();
    let unit = FakeUnit {
        dir: w.fake.path().to_path_buf(),
        saw: Mutex::default(),
    };
    {
        let mut g = shared.lock().unwrap();
        assert_eq!(
            handle(
                &mut g,
                &peers(),
                Some(DASH),
                &unit,
                &apply_req("p1", &plan, &ev),
                NOW
            )["ok"],
            true
        );
    }
    // a fresh gate (a restarted dashboard) still refuses the used plan
    let fresh = crate::fleet_gate::FleetGate::new("main", STORE, Box::new(Creds(shared)));
    assert_eq!(
        fresh.precheck("p1", &plan, NOW).unwrap_err().code,
        "fleet_plan_spent"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn over_a_real_socket_the_kernel_names_the_caller_and_only_that_user_is_served() {
    use std::os::unix::net::UnixListener;
    let w = World::new();
    let mut h = w.holder();
    h.accept_approvers(&w.approver_set(1, Role::Owner)).unwrap();
    let plan = create_plan(&w, "dev");
    send_window(&mut h, &w, "p1", &plan, NOW + 600_000);
    let me = rustix::process::getuid().as_raw();
    let sock = w.dir.path().join("holder.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let stopped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let unit = FakeUnit {
        dir: w.fake.path().to_path_buf(),
        saw: Mutex::default(),
    };
    let (stop2, now) = (stopped.clone(), NOW + 5);
    let client = HolderClient { sock: sock.clone() };
    // this process is the named dashboard user: served
    let t = std::thread::scope(|s| {
        s.spawn(|| {
            let p = Peers {
                dashboard_uid: me,
                ingress_uid: me.wrapping_add(1),
            };
            let stop = move || stop2.load(std::sync::atomic::Ordering::SeqCst);
            serve(&mut h, &p, &unit, &listener, &move || now, &stop);
        });
        let status = client.window_for("p1");
        let spent = client.is_spent("p1");
        // the same user is not the ingress: a window sent by the dashboard is refused
        let r = client
            .call(&json!({"op": "window", "plan_id": "p1", "plan_hash": "x", "enc": "", "ct": ""}))
            .unwrap();
        // an apply with nothing the holder accepts is refused with its reason, and spends nothing
        let refused = client
            .apply("p1", &plan, &PasskeyEvidence::default())
            .unwrap_err();
        stopped.store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = std::os::unix::net::UnixStream::connect(&sock);
        (status, spent, r, refused)
    });
    assert!(t.0.is_some());
    assert!(!t.1);
    assert_eq!(t.2["code"], "not_you");
    assert_eq!(t.3.code, "holder_refused");
    assert!(!t.3.message.is_empty());
    // with another user named, this process is refused everything
    let _ = std::fs::remove_file(&sock);
}
