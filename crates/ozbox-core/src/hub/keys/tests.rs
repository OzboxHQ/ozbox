#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Keys by name: delivered sealed to the attested key, refused for Production in three places, never a value anywhere but the
//! worker's service.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::hub::conformance::{keys, now_ms, Keys, HUB, HUB_FP, W1, W1_FP, W2};
use crate::hub::engine::{Assign, HubState};
use crate::hub::mem::{MemTransport, TestSealer};
use crate::hub::worker::{WorkerEnd, WorkerState};

/// A value no code path makes up by accident.
const SENTINEL: &str = "SENTINEL-staging-key-value-6e2f90b4d31a";

fn seal_info(worker: &str) -> Vec<u8> {
    ozbox_seal::info(DELIVERY_PURPOSE, worker)
}

/// The issuer's stand-in: `main`'s secrets service reads the value and seals it to the attested key, with the delivery's labels as
/// authenticated data. Counts its calls, so a test can show it was never asked.
struct FakeIssuer {
    calls: AtomicUsize,
    /// What it answers instead of the honest labels (a lying issuer), if set.
    lie_env: Option<String>,
}

impl FakeIssuer {
    fn honest() -> FakeIssuer {
        FakeIssuer {
            calls: AtomicUsize::new(0),
            lie_env: None,
        }
    }
}

impl KeyIssuer for FakeIssuer {
    fn release(&self, r: &ReleaseRequest<'_>) -> Result<Released, &'static str> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        issuer_guard(r).map_err(|_| "production-refused")?;
        let public = ozbox_seal::public_from_hex(&r.to.public).map_err(|_| "bad-key")?;
        let aad = delivery_aad(
            r.request_id,
            r.worker,
            r.orchestration,
            r.feature,
            r.env,
            r.names,
        );
        let values: BTreeMap<&String, &str> = r.names.iter().map(|n| (n, SENTINEL)).collect();
        let plain = serde_json::to_vec(&values).unwrap();
        let (enc, ct) = ozbox_seal::seal(&public, &seal_info(r.worker), &aad, &plain)
            .map_err(|_| "seal-failed")?;
        let mut sealed = enc;
        sealed.extend(ct);
        Ok(Released {
            env: self.lie_env.clone().unwrap_or_else(|| r.env.to_string()),
            names: r.names.to_vec(),
            sealed,
        })
    }
}

struct FakeAttest(Option<AttestedKey>);

impl Attestations for FakeAttest {
    fn delivery_key(&self, worker: &str) -> Option<AttestedKey> {
        (worker == W1).then(|| self.0.clone()).flatten()
    }
}

/// The worker's service: it alone holds the key-delivery key, opens a delivery and keeps the values.
struct FakeStore {
    key: ozbox_seal::ServiceKey,
    held: RefCell<BTreeMap<String, BTreeMap<String, String>>>,
    deleted_all: RefCell<u32>,
}

impl DeliveryStore for FakeStore {
    fn store_delivery(&self, d: &KeyDelivery) -> Result<(), &'static str> {
        if d.key_fp != self.key.fingerprint() || d.sealed.len() < 32 {
            return Err("not-for-this-key");
        }
        let aad = delivery_aad(
            &d.request_id,
            W1,
            &d.orchestration,
            &d.feature,
            &d.env,
            &d.names,
        );
        let plain = self
            .key
            .open(&seal_info(W1), &aad, &d.sealed[..32], &d.sealed[32..])
            .map_err(|_| "cannot-open")?;
        let v: BTreeMap<String, String> =
            serde_json::from_slice(&plain).map_err(|_| "malformed")?;
        self.held
            .borrow_mut()
            .insert(task_key(&d.orchestration, &d.feature), v);
        Ok(())
    }
    fn delete_task(&self, orchestration: &str, feature: &str) {
        self.held
            .borrow_mut()
            .remove(&task_key(orchestration, feature));
    }
    fn delete_all(&self) {
        self.held.borrow_mut().clear();
        *self.deleted_all.borrow_mut() += 1;
    }
}

struct Fx {
    k: Keys,
    net: MemTransport,
    hub_sealer: TestSealer,
    w1_sealer: TestSealer,
    store: FakeStore,
    attest: FakeAttest,
}

fn fx() -> Fx {
    let key = ozbox_seal::ServiceKey::generate().unwrap();
    let attest = FakeAttest(Some(AttestedKey {
        public: ozbox_seal::public_to_hex(&key.public()),
        fp: key.fingerprint(),
    }));
    Fx {
        k: keys(),
        net: MemTransport::default(),
        hub_sealer: TestSealer {
            my_fp: HUB_FP.into(),
        },
        w1_sealer: TestSealer {
            my_fp: W1_FP.into(),
        },
        store: FakeStore {
            key,
            held: RefCell::new(BTreeMap::new()),
            deleted_all: RefCell::new(0),
        },
        attest,
    }
}

impl Fx {
    fn hub(&self) -> Hub<'_> {
        Hub {
            me: HUB,
            my_fp: HUB_FP,
            roster: &self.k.roster,
            signer: &self.k.hub,
            verifier: &self.k.roster_keys,
            sealer: &self.hub_sealer,
            net: &self.net,
            deferred: false,
        }
    }
    fn worker(&self) -> WorkerEnd<'_> {
        WorkerEnd {
            me: W1,
            hub: HUB,
            signer: &self.k.w1,
            verifier: &self.k.roster_keys,
            sealer: &self.w1_sealer,
            net: &self.net,
        }
    }
    fn rounds(&self, hs: &mut HubState, ws: &mut WorkerState) {
        for _ in 0..4 {
            self.hub().poll(hs, now_ms());
            self.worker().poll_keys(ws, now_ms(), &self.store);
        }
    }
    /// Hello both ways, then a task assigned with a staging declaration and accepted.
    fn ready(&self, names: &[&str]) -> (HubState, WorkerState) {
        let mut hs = HubState::new(HUB, HUB_FP, 7);
        let mut ws = WorkerState::new(W1, W1_FP, HUB, HUB_FP, 7);
        self.worker().hello(&mut ws, now_ms());
        self.rounds(&mut hs, &mut ws);
        self.hub()
            .assign(&mut hs, W1, &assign(names), now_ms())
            .unwrap();
        self.rounds(&mut hs, &mut ws);
        assert_eq!(ws.tasks.len(), 1);
        (hs, ws)
    }
}

fn assign(names: &[&str]) -> Assign {
    Assign {
        orchestration: "orch-1".into(),
        feature: "f1".into(),
        title: "t".into(),
        brief: "b".into(),
        branch: "feat/f1".into(),
        repo: None,
        claims: Vec::new(),
        contracts: Vec::new(),
        keys: KeyDeclaration {
            env: "staging".into(),
            names: names.iter().map(|s| s.to_string()).collect(),
        },
        lease_expiry_ms: now_ms() + 3_600_000,
    }
}

fn names(n: &[&str]) -> Vec<String> {
    n.iter().map(|s| s.to_string()).collect()
}

fn actions(evs: &[crate::audit::NewEvent]) -> Vec<String> {
    evs.iter().map(|e| e.action.clone()).collect()
}

/// Everything the hub and the worker keep or record, and every message that crossed, as text.
fn everything(f: &Fx, hs: &HubState, ws: &WorkerState) -> String {
    let captured = f.net.capture.lock().unwrap().clone();
    format!(
        "{}{}{}",
        serde_json::to_string(hs).unwrap(),
        serde_json::to_string(ws).unwrap(),
        serde_json::to_string(&captured).unwrap()
    )
}

fn holds_sentinel(s: &str) -> bool {
    s.contains(SENTINEL) || s.contains(&to_hex(SENTINEL.as_bytes()))
}

#[test]
fn a_worker_asks_by_name_and_gets_the_value_sealed_to_its_attested_key_and_nowhere_else() {
    let f = fx();
    let (mut hs, mut ws) = f.ready(&["STRIPE_TEST_KEY", "DB_URL"]);
    f.worker()
        .ask_keys(&mut ws, now_ms(), "orch-1", "f1", &names(&["DB_URL"]))
        .unwrap();
    f.rounds(&mut hs, &mut ws);
    assert_eq!(hs.peers[W1].key_asks.len(), 1);
    let issuer = FakeIssuer::honest();
    assert_eq!(
        f.hub()
            .serve_key_asks(&mut hs, &f.attest, &issuer, now_ms()),
        1
    );
    f.rounds(&mut hs, &mut ws);
    let held = f.store.held.borrow();
    assert_eq!(
        held["orch-1/f1"]["DB_URL"], SENTINEL,
        "opened by the worker's service"
    );
    assert_eq!(held["orch-1/f1"].len(), 1, "only the name asked");
    drop(held);
    let (ha, wa) = (hs.take_audit(), ws.take_audit());
    assert!(actions(&ha).contains(&AUDIT_DELIVERED.to_string()));
    assert!(actions(&wa).contains(&AUDIT_STORED.to_string()));
    let line = ha.iter().find(|e| e.action == AUDIT_DELIVERED).unwrap();
    assert!(line.detail.contains("names=DB_URL") && line.detail.contains("env=staging"));
    // the value: in the worker's service only. Not in either state, either audit, or anything that crossed
    let all = format!(
        "{}{}{}",
        everything(&f, &hs, &ws),
        serde_json::to_string(&ha).unwrap(),
        serde_json::to_string(&wa).unwrap()
    );
    assert!(!holds_sentinel(&all));
}

#[test]
fn a_name_the_task_did_not_declare_is_refused_and_the_issuer_is_never_asked() {
    let f = fx();
    let (mut hs, mut ws) = f.ready(&["DB_URL"]);
    // the worker's own check refuses first
    assert_eq!(
        f.worker()
            .ask_keys(&mut ws, now_ms(), "orch-1", "f1", &names(&["OTHER"]))
            .unwrap_err()
            .code,
        CODE_NOT_DECLARED
    );
    // a hostile worker sends it anyway
    let issuer = FakeIssuer::honest();
    let e = f
        .hub()
        .deliver_keys(
            &mut hs,
            W1,
            &KeyAsk::new("orch-1", "f1", &names(&["OTHER"])),
            &f.attest,
            &issuer,
            now_ms(),
        )
        .unwrap_err();
    assert!(matches!(
        e,
        HubError::Refused(Refusal {
            code: CODE_NOT_DECLARED,
            ..
        })
    ));
    assert_eq!(issuer.calls.load(Ordering::SeqCst), 0);
    assert!(hs
        .take_audit()
        .iter()
        .any(|e| e.action == AUDIT_REFUSED && e.detail.contains(CODE_NOT_DECLARED)));
}

#[test]
fn a_production_key_by_name_is_refused_on_the_hub_at_the_issuer_and_on_the_worker() {
    let f = fx();
    let (mut hs, mut ws) = f.ready(&["DB_URL"]);
    // a taken-over hub's state says the task declared a production-named key under staging, and Production itself
    for decl in [
        KeyDeclaration {
            env: "staging".into(),
            names: names(&["PRODUCTION_DB_URL"]),
        },
        KeyDeclaration {
            env: "production".into(),
            names: names(&["DB_URL"]),
        },
    ] {
        let asked = decl.names.clone();
        hs.peers
            .get_mut(W1)
            .unwrap()
            .declared
            .insert("orch-1/f1".into(), decl);
        let issuer = FakeIssuer::honest();
        let e = f
            .hub()
            .deliver_keys(
                &mut hs,
                W1,
                &KeyAsk::new("orch-1", "f1", &asked),
                &f.attest,
                &issuer,
                now_ms(),
            )
            .unwrap_err();
        assert!(
            matches!(
                e,
                HubError::Refused(Refusal {
                    code: crate::hub::refusal::CODE_PRODUCTION,
                    ..
                })
            ),
            "{e}"
        );
        assert_eq!(
            issuer.calls.load(Ordering::SeqCst),
            0,
            "the issuer is never asked"
        );
    }

    // at the issuer: its own guard, with no hub in front of it
    let key = f.attest.0.clone().unwrap();
    let prod_names = names(&["LIVE_STRIPE_KEY"]);
    for (env, ns) in [("staging", &prod_names), ("production", &names(&["X"]))] {
        let r = ReleaseRequest {
            request_id: "r1",
            worker: W1,
            orchestration: "o",
            feature: "f",
            env,
            names: ns,
            to: &key,
        };
        assert!(issuer_guard(&r).is_err());
        assert!(FakeIssuer::honest().release(&r).is_err());
    }

    // on the worker: a delivery a taken-over hub signed, labelled Production, is refused by the screen and never stored
    for (env, ns) in [
        ("production", vec!["DB_URL"]),
        ("staging", vec!["PROD_DB_URL"]),
    ] {
        let body = KeyDelivery {
            orchestration: "orch-1".into(),
            feature: "f1".into(),
            env: env.into(),
            names: names(&ns),
            request_id: "r".into(),
            key_fp: key.fp.clone(),
            sealed: vec![1; 64],
        };
        send_from_hub(
            &f,
            &mut hs,
            &ws,
            Kind::KeysDeliver,
            &serde_json::to_vec(&body).unwrap(),
        );
        f.worker().poll_keys(&mut ws, now_ms(), &f.store);
        assert!(f.store.held.borrow().is_empty());
        assert!(ws.take_audit().iter().any(|e| e.action == AUDIT_REFUSED
            && e.detail.contains(crate::hub::refusal::CODE_PRODUCTION)));
    }
}

/// Queue a message in the hub's own outbox, as a taken-over hub would (it signs with the hub's key), and push it.
fn send_from_hub(f: &Fx, hs: &mut HubState, _ws: &WorkerState, kind: Kind, plain: &[u8]) {
    hs.core
        .enqueue(
            &PROFILE,
            W1,
            kind.name(),
            Ext::at(0).encode(),
            plain.to_vec(),
        )
        .unwrap();
    f.hub().flush(hs, W1, now_ms()).unwrap();
}

#[test]
fn a_lying_issuer_that_answers_production_or_other_labels_is_not_relayed() {
    let f = fx();
    let (mut hs, mut ws) = f.ready(&["DB_URL"]);
    let issuer = FakeIssuer {
        calls: AtomicUsize::new(0),
        lie_env: Some("production".into()),
    };
    let e = f
        .hub()
        .deliver_keys(
            &mut hs,
            W1,
            &KeyAsk::new("orch-1", "f1", &names(&["DB_URL"])),
            &f.attest,
            &issuer,
            now_ms(),
        )
        .unwrap_err();
    assert!(matches!(
        e,
        HubError::Refused(Refusal {
            code: CODE_ISSUER_MISMATCH,
            ..
        })
    ));
    f.rounds(&mut hs, &mut ws);
    assert!(f.store.held.borrow().is_empty());
}

#[test]
fn nothing_is_sealed_to_a_key_without_an_attestation_or_for_an_unassigned_task() {
    let f = fx();
    let (mut hs, _ws) = f.ready(&["DB_URL"]);
    let issuer = FakeIssuer::honest();
    let ask = KeyAsk::new("orch-1", "f1", &names(&["DB_URL"]));
    let e = f
        .hub()
        .deliver_keys(&mut hs, W1, &ask, &FakeAttest(None), &issuer, now_ms())
        .unwrap_err();
    assert!(matches!(
        e,
        HubError::Refused(Refusal {
            code: CODE_NOT_ATTESTED,
            ..
        })
    ));
    let e = f
        .hub()
        .deliver_keys(
            &mut hs,
            W1,
            &KeyAsk::new("orch-1", "not-mine", &names(&["DB_URL"])),
            &f.attest,
            &issuer,
            now_ms(),
        )
        .unwrap_err();
    assert!(matches!(
        e,
        HubError::Refused(Refusal {
            code: CODE_NOT_ASSIGNED,
            ..
        })
    ));
    // another worker's task is not this worker's to ask for
    let e = f
        .hub()
        .deliver_keys(&mut hs, W2, &ask, &f.attest, &issuer, now_ms())
        .unwrap_err();
    assert!(matches!(
        e,
        HubError::Refused(Refusal {
            code: CODE_NOT_ASSIGNED,
            ..
        })
    ));
    for bad in [names(&[]), names(&["A", "A"]), names(&["has space"])] {
        let e = f
            .hub()
            .deliver_keys(
                &mut hs,
                W1,
                &KeyAsk::new("orch-1", "f1", &bad),
                &f.attest,
                &issuer,
                now_ms(),
            )
            .unwrap_err();
        assert!(matches!(
            e,
            HubError::Refused(Refusal {
                code: CODE_ASK_INVALID,
                ..
            })
        ));
    }
    assert_eq!(issuer.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn keys_are_deleted_on_revoke_on_task_end_and_at_once_on_loss_of_the_hub() {
    let f = fx();
    let (mut hs, mut ws) = f.ready(&["DB_URL"]);
    let issuer = FakeIssuer::honest();
    let ask = KeyAsk::new("orch-1", "f1", &names(&["DB_URL"]));
    f.hub()
        .deliver_keys(&mut hs, W1, &ask, &f.attest, &issuer, now_ms())
        .unwrap();
    f.rounds(&mut hs, &mut ws);
    assert_eq!(f.store.held.borrow().len(), 1);
    f.hub()
        .revoke_keys(&mut hs, W1, "orch-1", "f1", now_ms())
        .unwrap();
    f.rounds(&mut hs, &mut ws);
    assert!(f.store.held.borrow().is_empty());

    f.hub()
        .deliver_keys(&mut hs, W1, &ask, &f.attest, &issuer, now_ms())
        .unwrap();
    f.rounds(&mut hs, &mut ws);
    assert_eq!(f.store.held.borrow().len(), 1);
    f.worker().hub_lost(&mut ws, now_ms(), &f.store);
    assert!(f.store.held.borrow().is_empty());
    assert_eq!(*f.store.deleted_all.borrow(), 1);

    f.hub()
        .deliver_keys(&mut hs, W1, &ask, &f.attest, &issuer, now_ms())
        .unwrap();
    f.rounds(&mut hs, &mut ws);
    let end = serde_json::to_vec(&KeyRevoke {
        orchestration: "orch-1".into(),
        feature: "f1".into(),
    })
    .unwrap();
    send_from_hub(&f, &mut hs, &ws, Kind::TaskEnd, &end);
    f.rounds(&mut hs, &mut ws);
    assert!(f.store.held.borrow().is_empty());
    assert!(ws.tasks.is_empty(), "the task ended");
}

#[test]
fn a_delivery_body_with_anything_beside_its_labels_is_refused_and_not_held() {
    let f = fx();
    let (mut hs, mut ws) = f.ready(&["DB_URL"]);
    let body = format!(
        "{{\"orchestration\":\"orch-1\",\"feature\":\"f1\",\"env\":\"staging\",\"names\":[\"DB_URL\"],\
         \"request_id\":\"r\",\"key_fp\":\"x\",\"sealed\":\"00\",\"value\":\"{SENTINEL}\"}}"
    );
    send_from_hub(&f, &mut hs, &ws, Kind::KeysDeliver, body.as_bytes());
    f.worker().poll_keys(&mut ws, now_ms(), &f.store);
    assert!(f.store.held.borrow().is_empty());
    assert!(!holds_sentinel(&serde_json::to_string(&ws).unwrap()));
    assert!(ws
        .take_audit()
        .iter()
        .any(|e| e.detail.contains(CODE_DELIVERY_INVALID)));
}

#[test]
fn a_worker_without_a_store_still_answers_unsupported() {
    let f = fx();
    let (mut hs, mut ws) = f.ready(&["DB_URL"]);
    let issuer = FakeIssuer::honest();
    f.hub()
        .deliver_keys(
            &mut hs,
            W1,
            &KeyAsk::new("orch-1", "f1", &names(&["DB_URL"])),
            &f.attest,
            &issuer,
            now_ms(),
        )
        .unwrap();
    f.worker().poll(&mut ws, now_ms());
    assert!(ws
        .take_audit()
        .iter()
        .any(|e| e.action == "worker.unsupported"));
}

#[test]
fn the_debug_form_of_a_release_and_a_delivery_carries_no_bytes() {
    let r = Released {
        env: "staging".into(),
        names: names(&["A"]),
        sealed: SENTINEL.as_bytes().to_vec(),
    };
    let d = KeyDelivery {
        orchestration: "o".into(),
        feature: "f".into(),
        env: "staging".into(),
        names: names(&["A"]),
        request_id: "r".into(),
        key_fp: "k".into(),
        sealed: SENTINEL.as_bytes().to_vec(),
    };
    let s = format!("{r:?}{d:?}");
    assert!(!holds_sentinel(&s), "{s}");
}

#[test]
fn the_delivery_is_bound_to_its_worker_task_request_and_names() {
    let base = delivery_aad("r", W1, "o", "f", "staging", &names(&["A"]));
    for other in [
        delivery_aad("r2", W1, "o", "f", "staging", &names(&["A"])),
        delivery_aad("r", W2, "o", "f", "staging", &names(&["A"])),
        delivery_aad("r", W1, "o", "g", "staging", &names(&["A"])),
        delivery_aad("r", W1, "o", "f", "development", &names(&["A"])),
        delivery_aad("r", W1, "o", "f", "staging", &names(&["A", "B"])),
    ] {
        assert_ne!(base, other);
    }
}

// ---- over the network ---------------------------------------------------------------------------------------------

/// The same delivery, end to end, over the network transport on loopback: the worker dials out, asks by name, and its service
/// opens the value; the hub's end never holds it.
#[test]
fn a_key_is_delivered_by_name_over_the_network_transport() {
    use crate::hub::mem::{TestKey, TestRoster};
    use crate::hub::net::{HubNetConfig, NetHub, NetWorker, TcpDialer, WorkerNetConfig};
    let f = fx();
    let hub_net = NetHub::start(HubNetConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        me: HUB.into(),
        roster: f.k.roster.clone(),
        signer: Arc::new(TestKey(f.k.hub.0.clone())),
        verifier: Arc::new(TestRoster(f.k.roster_keys.0.clone())),
    })
    .unwrap();
    let w_net = NetWorker::start(WorkerNetConfig {
        me: W1.into(),
        hub: HUB.into(),
        hub_key: HUB_FP.into(),
        signer: Arc::new(TestKey(f.k.w1.0.clone())),
        verifier: Arc::new(TestRoster(f.k.roster_keys.0.clone())),
        dialer: Arc::new(TcpDialer {
            addr: hub_net.local_addr().to_string(),
            timeout: Duration::from_secs(2),
        }),
    })
    .unwrap();
    let hub = Hub {
        net: &hub_net,
        ..f.hub()
    };
    let w = WorkerEnd {
        net: &w_net,
        ..f.worker()
    };
    let mut hs = HubState::new(HUB, HUB_FP, 7);
    let mut ws = WorkerState::new(W1, W1_FP, HUB, HUB_FP, 7);
    let issuer = FakeIssuer::honest();
    let step = |hs: &mut HubState, ws: &mut WorkerState| {
        hub.poll(hs, now_ms());
        hub.serve_key_asks(hs, &f.attest, &issuer, now_ms());
        w.poll_keys(ws, now_ms(), &f.store);
        std::thread::sleep(Duration::from_millis(4));
    };
    w.hello(&mut ws, now_ms());
    for _ in 0..1_000 {
        step(&mut hs, &mut ws);
        if hs.peer_inc(W1) == ws.inc() && ws.hub_inc() == hs.inc() {
            break;
        }
    }
    hub.assign(&mut hs, W1, &assign(&["DB_URL"]), now_ms())
        .unwrap();
    for _ in 0..1_000 {
        step(&mut hs, &mut ws);
        if !ws.tasks.is_empty() {
            break;
        }
    }
    w.ask_keys(&mut ws, now_ms(), "orch-1", "f1", &names(&["DB_URL"]))
        .unwrap();
    for _ in 0..1_000 {
        step(&mut hs, &mut ws);
        if !f.store.held.borrow().is_empty() {
            break;
        }
    }
    assert_eq!(f.store.held.borrow()["orch-1/f1"]["DB_URL"], SENTINEL);
    let status = format!("{:?}", hub_net.status());
    assert!(!holds_sentinel(&serde_json::to_string(&hs).unwrap()) && !holds_sentinel(&status));
}
