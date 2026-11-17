#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

use ozbox_core::approval_subject::{Encoder, ENVELOPE_TAG as APPROVAL_ENVELOPE_TAG, SUBJECT_TAG};
use ozbox_core::channel::wire::{
    hex, seal_and_sign, Crypto, Envelope, Sealed, Sealer, Signer, Verifier, VERSION,
};
use ozbox_core::hub::engine::{Assign, Hub, HubState};
use ozbox_core::hub::refusal::KeyDeclaration;
use ozbox_core::hub::wire::{Ext, Transport, WireError, ENVELOPE_TAG, PROFILE};
use ozbox_core::hub::worker::{WorkerEnd, WorkerState};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use zeroize::Zeroizing;

use crate::crypto::{Directory, DirectoryVerifier, ServiceSealer, ServiceSigner};
use crate::daemon::{ask, bind, verify_handshake, Config, Hubd, Rejected, SpoolTransport};
use crate::enrol::*;
use crate::identity::{tag_prefix, Identity, DELIVERY_PURPOSE};
use crate::keys::{
    channel_info, delivery_info, handle, is_reserved, Caller, HubKeys, KeyStore, SignPurpose, NAMES,
};
use crate::ops::{KeyOps, LocalKeyOps};
use crate::seams::{hub_seams, worker_seams};

// ---- fixtures -------------------------------------------------------------------------------------------------------

#[derive(Default)]
pub(crate) struct MemStore(Mutex<BTreeMap<String, String>>);

impl KeyStore for MemStore {
    fn get(&self, name: &str) -> Result<Option<Zeroizing<String>>, String> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .get(name)
            .cloned()
            .map(Zeroizing::new))
    }
    fn set(&self, name: &str, value: &str) -> Result<(), String> {
        self.0.lock().unwrap().insert(name.into(), value.into());
        Ok(())
    }
}

impl MemStore {
    /// Every private value the store holds, for the sentinel checks.
    fn values(&self) -> Vec<String> {
        self.0.lock().unwrap().values().cloned().collect()
    }
}

pub(crate) struct End {
    pub(crate) store: MemStore,
    pub(crate) keys: Arc<HubKeys>,
}

pub(crate) fn end() -> End {
    let store = MemStore::default();
    let keys = Arc::new(HubKeys::load_or_create(&store).unwrap());
    End { store, keys }
}

impl End {
    pub(crate) fn ops(&self, caller: Caller) -> Arc<dyn KeyOps> {
        Arc::new(LocalKeyOps {
            keys: self.keys.clone(),
            caller,
        })
    }
    pub(crate) fn id(&self) -> Identity {
        self.keys.identity().clone()
    }
}

struct Registrar {
    pair: Ed25519KeyPair,
    reg: crate::enrol::Registrar,
}

fn registrar(provider: Provider) -> Registrar {
    let doc = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap();
    let reg = crate::enrol::Registrar {
        provider,
        public: hex(pair.public_key().as_ref()),
    };
    Registrar { pair, reg }
}

pub(crate) const NOW: u64 = 1_800_000_000_000;
pub(crate) const HUB_BOX: &str = "main-box";

struct World {
    _tmp: tempfile::TempDir,
    hub: End,
    hubd: Arc<Hubd>,
    aws: Registrar,
    cfg: Config,
}

fn world() -> World {
    let tmp = tempfile::tempdir().unwrap();
    let hub = end();
    let aws = registrar(Provider::Aws);
    let regs = Registrars {
        registrars: vec![aws.reg.clone()],
    };
    let rp = tmp.path().join("registrars.json");
    std::fs::write(&rp, serde_json::to_vec(&regs).unwrap()).unwrap();
    let cfg = Config {
        dir: tmp.path().join("state"),
        socket: tmp.path().join("run/hubd.sock"),
        registrars: rp,
        box_id: HUB_BOX.into(),
        name: "main".into(),
    };
    let hubd = Hubd::open(cfg.clone(), hub.ops(Caller::Hub)).unwrap();
    World {
        _tmp: tmp,
        hub,
        hubd,
        aws,
        cfg,
    }
}

fn spec(worker: &str, box_id: &str, machine: &str) -> InviteSpec {
    InviteSpec {
        worker: worker.into(),
        box_id: box_id.into(),
        provider: Provider::Aws,
        machine: machine.into(),
        private_address: String::new(),
        orchestration: "orch-1".into(),
    }
}

fn nonce() -> String {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).unwrap();
    hex(&b)
}

impl World {
    fn invite(&self, worker: &str, box_id: &str, machine: &str) -> Zeroizing<String> {
        let plan = self
            .hubd
            .plan_invite(&spec(worker, box_id, machine))
            .unwrap();
        self.hubd.apply_invite(&plan, NOW).unwrap()
    }

    fn attest(
        &self,
        by: &Registrar,
        w: &Identity,
        box_id: &str,
        machine: &str,
        env: &str,
        class: &str,
    ) -> Attestation {
        let mut a = Attestation {
            provider: by.reg.provider,
            machine: machine.into(),
            box_id: box_id.into(),
            class: class.into(),
            environment: env.into(),
            orchestration: "orch-1".into(),
            hub_identity_fp: self.hub.id().identity_fp(),
            identity_fp: w.identity_fp(),
            channel_fp: w.channel_fp(),
            delivery_fp: w.delivery_fp(),
            private_address: String::new(),
            issued_ms: NOW - 1000,
            nonce: nonce(),
            registrar_fp: by.reg.fingerprint(),
            signature: String::new(),
        };
        a.signature = hex(by.pair.sign(&a.signing_bytes()).as_ref());
        a
    }

    fn request(&self, w: &End, worker: &str, token: &str, a: Attestation) -> EnrolRequest {
        make_request(
            w.ops(Caller::Supervisor).as_ref(),
            worker,
            token,
            a,
            &self.hub.id().identity_fp(),
            NOW,
        )
        .unwrap()
    }

    /// The whole join: invite, request, plan, apply.
    fn enrol(&self, w: &End, worker: &str, box_id: &str, machine: &str) -> RosterRecord {
        let token = self.invite(worker, box_id, machine);
        let a = self.attest(&self.aws, &w.id(), box_id, machine, "staging", WORKER_CLASS);
        let req = self.request(w, worker, &token, a);
        self.hubd.receive_enrolment(&req, NOW).unwrap();
        let plan = self.hubd.plan_enrol(worker).unwrap();
        self.hubd.apply_enrol(&plan, NOW).unwrap()
    }
}

fn code(r: Result<(), Refusal>) -> &'static str {
    r.unwrap_err().code
}

// ---- the keys and the service's operations --------------------------------------------------------------------------

#[test]
fn the_keys_are_made_once_kept_in_the_store_and_reloaded_unchanged() {
    let store = MemStore::default();
    let a = HubKeys::load_or_create(&store).unwrap();
    let b = HubKeys::load_or_create(&store).unwrap();
    assert_eq!(a.identity(), b.identity());
    assert_eq!(store.0.lock().unwrap().len(), NAMES.len());
    assert!(NAMES.iter().all(|n| is_reserved(n)));
    // four purposes, four different keys
    assert!(a.identity().checked().is_some());
}

#[test]
fn a_store_holding_some_of_the_keys_is_damaged_and_is_never_filled_in() {
    let store = MemStore::default();
    HubKeys::load_or_create(&store).unwrap();
    store.0.lock().unwrap().remove(NAMES[1]);
    let e = HubKeys::load_or_create(&store).unwrap_err();
    assert!(e.contains("damaged"));
    assert_eq!(store.0.lock().unwrap().len(), NAMES.len() - 1);
}

#[test]
fn each_socket_gets_only_its_own_operations() {
    let e = end();
    let mut env = tag_prefix(ENVELOPE_TAG);
    env.extend_from_slice(b"x");
    let mut hs = tag_prefix(crate::identity::HANDSHAKE_TAG);
    hs.extend_from_slice(b"x");
    let ask = |caller, op: &str, purpose: &str, data: &[u8]| {
        handle(
            &e.keys,
            caller,
            &serde_json::json!({"op": op, "purpose": purpose, "data": hex(data), "aad": "", "sealed": hex(&[0u8; 64])}),
        )
    };
    // the supervisor signs envelopes, never the handshake, never a token tag
    assert!(ask(Caller::Supervisor, "hub_sign", "envelope", &env).is_ok());
    assert!(ask(Caller::Supervisor, "hub_sign", "handshake", &hs).is_err());
    assert!(ask(Caller::Supervisor, "hub_mac", "", b"t").is_err());
    // the daemon signs the handshake and tags tokens, never an envelope, never opens a body
    assert!(ask(Caller::Hub, "hub_sign", "handshake", &hs).is_ok());
    assert!(ask(Caller::Hub, "hub_mac", "", b"t").is_ok());
    assert!(ask(Caller::Hub, "hub_sign", "envelope", &env).is_err());
    assert!(ask(Caller::Hub, "hub_sign", "enrol-proof", &env).is_err());
    assert!(ask(Caller::Hub, "hub_open", "", b"").is_err());
    // root sees the public identity only; any other socket nothing
    assert!(ask(Caller::Admin, "hub_identity", "", b"").is_ok());
    assert!(ask(Caller::Admin, "hub_sign", "envelope", &env).is_err());
    for op in ["hub_identity", "hub_sign", "hub_open", "hub_mac"] {
        assert!(ask(Caller::Other, op, "envelope", &env).is_err(), "{op}");
    }
}

#[test]
fn the_channel_key_signs_nothing_but_its_own_domains() {
    let e = end();
    // an approval subject, an approval envelope, a mesh message and bare bytes are all refused
    for tag in [SUBJECT_TAG, APPROVAL_ENVELOPE_TAG, "ozbox-mesh-envelope-v1"] {
        let mut b = Encoder::new(tag).bytes().to_vec();
        b.extend_from_slice(b"payload");
        assert!(e.keys.sign(SignPurpose::Envelope, &b).is_err(), "{tag}");
        assert!(e.keys.sign(SignPurpose::EnrolProof, &b).is_err(), "{tag}");
    }
    assert!(e.keys.sign(SignPurpose::Envelope, b"plain bytes").is_err());
    // a handshake tag under the envelope purpose is refused, and the reverse
    let mut hs = tag_prefix(crate::identity::HANDSHAKE_TAG);
    hs.push(1);
    assert!(e.keys.sign(SignPurpose::Envelope, &hs).is_err());
    let mut env = tag_prefix(ENVELOPE_TAG);
    env.push(1);
    assert!(e.keys.sign(SignPurpose::Handshake, &env).is_err());
    // the signer refuses before it asks the service
    let s = ServiceSigner {
        ops: e.ops(Caller::Supervisor),
    };
    assert!(s.sign(b"plain").is_err());
}

#[test]
fn the_handshake_and_the_envelope_are_signed_by_different_keys() {
    let e = end();
    let id = e.id();
    let mut hs = tag_prefix(crate::identity::HANDSHAKE_TAG);
    hs.push(1);
    let sig = e.keys.sign(SignPurpose::Handshake, &hs).unwrap();
    assert!(crate::crypto::verify_ed25519(
        &id.handshake_public,
        &hs,
        &sig
    ));
    assert!(!crate::crypto::verify_ed25519(&id.sign_public, &hs, &sig));
}

// ---- the real signer and sealer, on the frozen golden vectors --------------------------------------------------------

// The same vectors as `ozbox_core::hub`'s tests (computed by `testdata/channel_golden_vectors.py`), added here as ADR 0042 says.
const GOLDEN_EXT: &str =
    "01000000106f7a626f782d6875622d6578742d7631000000080000000000000000000000080000000000000000";
const GOLDEN_CANONICAL: &str = "01000000156f7a626f782d6875622d656e76656c6f70652d76310000000800000000000000010000000b7461736b2e61737369676e000000046d61696e00000008776f726b65722d3100000040626230303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030310000000800000000000000070000000800000000000000010000000800000000000011110000000800000000000022220000000800000000000000030000000800000000000000020000000f6d61696e2d776f726b65722d312d33000000080000018bcfe56800000000080000018bcfee8fc000000010000102030405060708090a0b0c0d0e0f0000002d01000000106f7a626f782d6875622d6578742d76310000000800000000000000000000000800000000000000000000000568656c6c6f";
const GOLDEN_DIGEST: &str = "afd2ef9686ad687b1c7fdd03fcbe679eeb53d9f5b522e781d3b84b05081699ca";

fn sample() -> Envelope {
    Envelope {
        version: VERSION,
        kind: "task.assign".into(),
        from: "main".into(),
        to: "worker-1".into(),
        receiver_fp: "bb00000000000000000000000000000000000000000000000000000000000001".into(),
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

#[test]
fn the_golden_vector_is_the_same_here_and_signs_and_verifies_through_the_real_service() {
    let e = sample();
    assert_eq!(hex(&Ext::at(0).encode()), GOLDEN_EXT);
    let canonical = e.canonical(&PROFILE);
    assert_eq!(hex(&canonical), GOLDEN_CANONICAL);
    assert_eq!(e.digest_hex(&PROFILE), GOLDEN_DIGEST);
    let hub = end();
    let dir = Directory::default();
    dir.insert(&hub.id());
    let signer = ServiceSigner {
        ops: hub.ops(Caller::Supervisor),
    };
    let sig = signer.sign(&canonical).unwrap();
    let v = DirectoryVerifier { dir: dir.clone() };
    assert!(v.verify(&hub.id().channel_fp(), &canonical, &sig));
    // one bit of the frozen bytes changed, or another key named, and it does not verify
    let mut bad = canonical.clone();
    bad[canonical.len() - 1] ^= 1;
    assert!(!v.verify(&hub.id().channel_fp(), &bad, &sig));
    let other = end();
    dir.insert(&other.id());
    assert!(!v.verify(&other.id().channel_fp(), &canonical, &sig));
    // a fingerprint the directory does not hold verifies nothing
    assert!(!v.verify(
        "bb00000000000000000000000000000000000000000000000000000000000001",
        &canonical,
        &sig
    ));
}

#[test]
fn the_golden_body_seals_with_hpke_to_the_attested_key_and_opens_only_there() {
    let hub = end();
    let worker = end();
    let dir = Directory::default();
    dir.insert(&worker.id());
    let mut e = sample();
    e.receiver_fp = worker.id().channel_fp();
    let sealer = ServiceSealer {
        ops: hub.ops(Caller::Supervisor),
        dir: dir.clone(),
    };
    let cx = Crypto {
        signer: &ServiceSigner {
            ops: hub.ops(Caller::Supervisor),
        },
        verifier: &DirectoryVerifier { dir: dir.clone() },
        sealer: &sealer,
    };
    let sealed = seal_and_sign(
        &PROFILE,
        e.clone(),
        &worker.id().channel_fp(),
        b"hello",
        &cx,
    )
    .unwrap();
    assert_ne!(sealed.envelope.body, b"hello");
    assert!(!sealed.envelope.body.windows(5).any(|w| w == b"hello"));
    let aad = sealed.envelope.aad(&PROFILE);
    // the worker's service opens it
    let w_open = ServiceSealer {
        ops: worker.ops(Caller::Supervisor),
        dir: Directory::default(),
    };
    assert_eq!(w_open.open(&aad, &sealed.envelope.body).unwrap(), b"hello");
    // a changed header, another key, or the daemon's socket: none opens it
    let mut moved = sealed.envelope.clone();
    moved.seq += 1;
    assert!(w_open
        .open(&moved.aad(&PROFILE), &sealed.envelope.body)
        .is_err());
    let h_open = ServiceSealer {
        ops: hub.ops(Caller::Supervisor),
        dir: Directory::default(),
    };
    assert!(h_open.open(&aad, &sealed.envelope.body).is_err());
    let daemon_side = ServiceSealer {
        ops: worker.ops(Caller::Hub),
        dir: Directory::default(),
    };
    assert!(daemon_side.open(&aad, &sealed.envelope.body).is_err());
    // the signature over the sealed envelope verifies with the hub's attested key
    let hd = Directory::default();
    hd.insert(&hub.id());
    assert!(DirectoryVerifier { dir: hd }.verify(
        &hub.id().channel_fp(),
        &sealed.envelope.canonical(&PROFILE),
        &sealed.signature
    ));
    // a receiver the directory does not hold is sealed nothing
    assert!(sealer
        .seal(
            "bb00000000000000000000000000000000000000000000000000000000000001",
            &aad,
            b"x"
        )
        .is_err());
}

#[test]
fn a_delivered_key_ciphertext_never_opens_as_a_message_body() {
    let w = end();
    let pk = w.keys.delivery_public();
    let fp = w.id().delivery_fp();
    let (enc, ct) = ozbox_seal::seal(
        &pk,
        &delivery_info(&fp),
        b"aad",
        b"SENTINEL-delivered-value",
    )
    .unwrap();
    let mut sealed = enc;
    sealed.extend(ct);
    assert!(w.keys.open_channel(b"aad", &sealed).is_err());
    // even sealed to the channel key, the delivery purpose does not open as a body
    let cpk = ozbox_seal::public_from_hex(&w.id().seal_public).unwrap();
    let info = ozbox_seal::info(DELIVERY_PURPOSE, &w.id().channel_fp());
    let (enc, ct) = ozbox_seal::seal(&cpk, &info, b"aad", b"x").unwrap();
    let mut s2 = enc;
    s2.extend(ct);
    assert!(w.keys.open_channel(b"aad", &s2).is_err());
    // and the operation refuses the delivery purpose by name
    let r = handle(
        &w.keys,
        Caller::Supervisor,
        &serde_json::json!({"op": "hub_open", "purpose": DELIVERY_PURPOSE, "aad": "", "sealed": hex(&sealed)}),
    );
    assert!(r.is_err());
    // a body made for the channel purpose opens
    let (enc, ct) =
        ozbox_seal::seal(&cpk, &channel_info(&w.id().channel_fp()), b"aad", b"ok").unwrap();
    let mut s3 = enc;
    s3.extend(ct);
    assert_eq!(&w.keys.open_channel(b"aad", &s3).unwrap()[..], b"ok");
}

// ---- enrolment -------------------------------------------------------------------------------------------------------

#[test]
fn a_worker_joins_by_invite_attested_request_plan_and_apply() {
    let w = world();
    let wk = end();
    let token = w.invite("worker-1", "box-w1", "i-0001");
    // the plan never carried the token, and the state keeps only its MAC
    let state = std::fs::read_to_string(w.cfg.dir.join("state.json")).unwrap_or_default();
    let all = state_text(&w);
    assert!(!all.contains(token.as_str()) && !state.contains(token.as_str()));
    let a = w.attest(
        &w.aws,
        &wk.id(),
        "box-w1",
        "i-0001",
        "staging",
        WORKER_CLASS,
    );
    let req = w.request(&wk, "worker-1", &token, a);
    w.hubd.receive_enrolment(&req, NOW).unwrap();
    // pending is not enrolled: nothing in the roster yet
    assert!(w.hubd.roster().unwrap().is_empty());
    let plan = w.hubd.plan_enrol("worker-1").unwrap();
    assert_eq!(plan.channel_fp, wk.id().channel_fp());
    assert_eq!(plan.registrar_fp, w.aws.reg.fingerprint());
    let rec = w.hubd.apply_enrol(&plan, NOW).unwrap();
    assert_eq!(rec.identity, wk.id());
    assert_eq!(w.hubd.roster().unwrap().len(), 1);
    assert!(w.hubd.directory().get(&wk.id().channel_fp()).is_some());
    // the token is burnt: the invite is gone
    let st = w.hubd.state().unwrap();
    assert!(st.enrol.invites.is_empty() && st.enrol.pending.is_empty());
    let audit: Vec<String> = st.audit.iter().map(|e| e.action.clone()).collect();
    assert!(audit.contains(&"hub.invite".into()) && audit.contains(&"hub.enrol".into()));
}

fn state_text(w: &World) -> String {
    let mut s = String::new();
    for e in std::fs::read_dir(&w.cfg.dir).unwrap().flatten() {
        if let Ok(t) = std::fs::read_to_string(e.path()) {
            s.push_str(&t);
        }
    }
    s
}

#[test]
fn an_unknown_box_is_refused() {
    let w = world();
    let wk = end();
    // never invited
    let a = w.attest(&w.aws, &wk.id(), "box-x", "i-x", "staging", WORKER_CLASS);
    let req = w.request(&wk, "worker-x", &"ab".repeat(24), a);
    assert_eq!(code(w.hubd.receive_enrolment(&req, NOW)), CODE_UNKNOWN_BOX);
    // invited as another box
    let token = w.invite("worker-1", "box-w1", "i-0001");
    let a = w.attest(
        &w.aws,
        &wk.id(),
        "box-other",
        "i-0001",
        "staging",
        WORKER_CLASS,
    );
    let req = w.request(&wk, "worker-1", &token, a);
    assert_eq!(code(w.hubd.receive_enrolment(&req, NOW)), CODE_UNKNOWN_BOX);
    assert!(w.hubd.roster().unwrap().is_empty());
}

#[test]
fn a_wrong_or_expired_token_is_refused() {
    let w = world();
    let wk = end();
    let _token = w.invite("worker-1", "box-w1", "i-0001");
    let a = w.attest(
        &w.aws,
        &wk.id(),
        "box-w1",
        "i-0001",
        "staging",
        WORKER_CLASS,
    );
    let req = w.request(&wk, "worker-1", &"cd".repeat(24), a.clone());
    let r = w.hubd.receive_enrolment(&req, NOW).unwrap_err();
    assert_eq!(r.code, CODE_BAD_TOKEN);
    // the refusal names nothing secret
    assert!(!r.message.contains(&"cd".repeat(24)));
    let token = w.invite("worker-1", "box-w1", "i-0001");
    let req = w.request(&wk, "worker-1", &token, a);
    assert_eq!(
        code(w.hubd.receive_enrolment(&req, NOW + TOKEN_TTL_MS + 1)),
        CODE_TOKEN_EXPIRED
    );
}

#[test]
fn a_key_that_is_not_the_attested_one_is_refused() {
    let w = world();
    let wk = end();
    let thief = end();
    let token = w.invite("worker-1", "box-w1", "i-0001");
    // the attestation names the worker's keys; the thief presents its own keys with it
    let a = w.attest(
        &w.aws,
        &wk.id(),
        "box-w1",
        "i-0001",
        "staging",
        WORKER_CLASS,
    );
    let req = w.request(&thief, "worker-1", &token, a.clone());
    assert_eq!(code(w.hubd.receive_enrolment(&req, NOW)), CODE_WRONG_KEY);
    // the right public keys, but the proof signed by another key
    let mut req = w.request(&wk, "worker-1", &token, a);
    let other = w.request(&thief, "worker-1", &token, req.attestation.clone());
    req.proof_sig = other.proof_sig;
    req.proof_nonce = other.proof_nonce;
    assert_eq!(code(w.hubd.receive_enrolment(&req, NOW)), CODE_WRONG_KEY);
    assert!(w.hubd.roster().unwrap().is_empty());
}

#[test]
fn a_replayed_attestation_is_refused() {
    let w = world();
    let wk = end();
    let token = w.invite("worker-1", "box-w1", "i-0001");
    let a = w.attest(
        &w.aws,
        &wk.id(),
        "box-w1",
        "i-0001",
        "staging",
        WORKER_CLASS,
    );
    let req = w.request(&wk, "worker-1", &token, a.clone());
    w.hubd.receive_enrolment(&req, NOW).unwrap();
    // the same request again while pending is a retry, not a replay
    w.hubd.receive_enrolment(&req, NOW).unwrap();
    let plan = w.hubd.plan_enrol("worker-1").unwrap();
    w.hubd.apply_enrol(&plan, NOW).unwrap();
    // the worker is removed, then invited again: the captured attestation does not enrol it a second time
    w.hubd.remove_worker("worker-1", NOW).unwrap();
    let token2 = w.invite("worker-1", "box-w1", "i-0001");
    let req2 = w.request(&wk, "worker-1", &token2, a);
    assert_eq!(code(w.hubd.receive_enrolment(&req2, NOW)), CODE_REPLAYED);
    // and a captured request for a pending worker cannot be taken under another worker's invite
    let other = end();
    let t3 = w.invite("worker-3", "box-w3", "i-0003");
    let a3 = w.attest(
        &w.aws,
        &other.id(),
        "box-w3",
        "i-0003",
        "staging",
        WORKER_CLASS,
    );
    let r3 = w.request(&other, "worker-3", &t3, a3.clone());
    w.hubd.receive_enrolment(&r3, NOW).unwrap();
    let t4 = w.invite("worker-4", "box-w3", "i-0003");
    let r4 = w.request(&other, "worker-4", &t4, a3);
    assert_eq!(code(w.hubd.receive_enrolment(&r4, NOW)), CODE_REPLAYED);
}

#[test]
fn a_production_box_is_never_a_worker() {
    let w = world();
    let wk = end();
    for (env, class) in [
        ("production", WORKER_CLASS),
        ("prod", WORKER_CLASS),
        // an environment nobody knows counts as Production
        ("somewhere", WORKER_CLASS),
        ("staging", "main"),
        ("staging", "unclassified"),
    ] {
        let token = w.invite("worker-1", "box-w1", "i-0001");
        let a = w.attest(&w.aws, &wk.id(), "box-w1", "i-0001", env, class);
        let req = w.request(&wk, "worker-1", &token, a);
        assert_eq!(
            code(w.hubd.receive_enrolment(&req, NOW)),
            CODE_PRODUCTION_BOX,
            "{env} {class}"
        );
    }
    // main itself: refused at the invite, so it can never be planned
    assert_eq!(
        w.hubd
            .plan_invite(&spec("me", HUB_BOX, "i-main"))
            .unwrap_err()
            .code,
        CODE_PRODUCTION_BOX
    );
    assert!(w.hubd.roster().unwrap().is_empty());
}

#[test]
fn an_attestation_from_an_unpinned_registrar_or_a_forged_one_is_refused() {
    let w = world();
    let wk = end();
    let rogue = registrar(Provider::Aws);
    let token = w.invite("worker-1", "box-w1", "i-0001");
    let a = w.attest(
        &rogue,
        &wk.id(),
        "box-w1",
        "i-0001",
        "staging",
        WORKER_CLASS,
    );
    let req = w.request(&wk, "worker-1", &token, a);
    assert_eq!(
        code(w.hubd.receive_enrolment(&req, NOW)),
        CODE_UNKNOWN_REGISTRAR
    );
    // the pinned registrar's fingerprint over a record it did not sign
    let mut a = w.attest(
        &w.aws,
        &wk.id(),
        "box-w1",
        "i-0001",
        "staging",
        WORKER_CLASS,
    );
    a.signature = hex(rogue.pair.sign(&a.signing_bytes()).as_ref());
    let req = w.request(&wk, "worker-1", &token, a);
    assert_eq!(
        code(w.hubd.receive_enrolment(&req, NOW)),
        CODE_BAD_ATTESTATION
    );
    // a Hetzner registrar cannot attest an AWS worker
    let hz = registrar(Provider::Hetzner);
    let regs = Registrars {
        registrars: vec![w.aws.reg.clone(), hz.reg.clone()],
    };
    std::fs::write(&w.cfg.registrars, serde_json::to_vec(&regs).unwrap()).unwrap();
    let mut a = w.attest(&hz, &wk.id(), "box-w1", "i-0001", "staging", WORKER_CLASS);
    a.provider = Provider::Aws;
    a.signature = hex(hz.pair.sign(&a.signing_bytes()).as_ref());
    let req = w.request(&wk, "worker-1", &token, a);
    assert_eq!(
        code(w.hubd.receive_enrolment(&req, NOW)),
        CODE_UNKNOWN_REGISTRAR
    );
}

#[test]
fn an_attestation_for_another_hub_or_another_machine_is_refused() {
    let w = world();
    let wk = end();
    let token = w.invite("worker-1", "box-w1", "i-0001");
    let mut a = w.attest(
        &w.aws,
        &wk.id(),
        "box-w1",
        "i-0001",
        "staging",
        WORKER_CLASS,
    );
    a.hub_identity_fp = end().id().identity_fp();
    a.signature = hex(w.aws.pair.sign(&a.signing_bytes()).as_ref());
    assert_eq!(
        code(
            w.hubd
                .receive_enrolment(&w.request(&wk, "worker-1", &token, a), NOW)
        ),
        CODE_WRONG_HUB
    );
    // the instance the hub created is i-0001; the attestation is for another instance
    let a = w.attest(
        &w.aws,
        &wk.id(),
        "box-w1",
        "i-9999",
        "staging",
        WORKER_CLASS,
    );
    assert_eq!(
        code(
            w.hubd
                .receive_enrolment(&w.request(&wk, "worker-1", &token, a), NOW)
        ),
        CODE_BINDING
    );
    // an old attestation
    let mut a = w.attest(
        &w.aws,
        &wk.id(),
        "box-w1",
        "i-0001",
        "staging",
        WORKER_CLASS,
    );
    a.issued_ms = NOW - ATTESTATION_MAX_AGE_MS - 10;
    a.signature = hex(w.aws.pair.sign(&a.signing_bytes()).as_ref());
    assert_eq!(
        code(
            w.hubd
                .receive_enrolment(&w.request(&wk, "worker-1", &token, a), NOW)
        ),
        CODE_STALE
    );
}

#[test]
fn an_enrolled_worker_cannot_swap_its_key_and_another_cannot_take_its_key_or_box() {
    let w = world();
    let wk = end();
    w.enrol(&wk, "worker-1", "box-w1", "i-0001");
    // a second enrolment of the same worker is refused at the invite
    assert_eq!(
        w.hubd
            .plan_invite(&spec("worker-1", "box-w2", "i-0002"))
            .unwrap_err()
            .code,
        CODE_ALREADY
    );
    // the same box under another name
    assert_eq!(
        w.hubd
            .plan_invite(&spec("worker-2", "box-w1", "i-0002"))
            .unwrap_err()
            .code,
        CODE_DUPLICATE
    );
    // the same key under another name and box
    let token = w.invite("worker-2", "box-w2", "i-0002");
    let a = w.attest(
        &w.aws,
        &wk.id(),
        "box-w2",
        "i-0002",
        "staging",
        WORKER_CLASS,
    );
    let req = w.request(&wk, "worker-2", &token, a);
    assert_eq!(code(w.hubd.receive_enrolment(&req, NOW)), CODE_DUPLICATE);
}

#[test]
fn a_plan_made_before_the_roster_changed_is_not_applied() {
    let w = world();
    let (w1, w2) = (end(), end());
    let t1 = w.invite("worker-1", "box-w1", "i-0001");
    let req = w.request(
        &w1,
        "worker-1",
        &t1,
        w.attest(
            &w.aws,
            &w1.id(),
            "box-w1",
            "i-0001",
            "staging",
            WORKER_CLASS,
        ),
    );
    w.hubd.receive_enrolment(&req, NOW).unwrap();
    let plan = w.hubd.plan_enrol("worker-1").unwrap();
    // something else changed the roster's inputs in between
    w.enrol(&w2, "worker-2", "box-w2", "i-0002");
    assert_eq!(
        w.hubd.apply_enrol(&plan, NOW).unwrap_err().code,
        CODE_STALE_PLAN
    );
    let again = w.hubd.plan_enrol("worker-1").unwrap();
    w.hubd.apply_enrol(&again, NOW).unwrap();
    // a stale invite plan is not applied either
    let p = w
        .hubd
        .plan_invite(&spec("worker-3", "box-w3", "i-0003"))
        .unwrap();
    w.invite("worker-4", "box-w4", "i-0004");
    assert_eq!(
        w.hubd.apply_invite(&p, NOW).unwrap_err().code,
        CODE_STALE_PLAN
    );
}

#[test]
fn a_registrar_unpinned_before_apply_stops_the_enrolment() {
    let w = world();
    let wk = end();
    let t = w.invite("worker-1", "box-w1", "i-0001");
    let req = w.request(
        &wk,
        "worker-1",
        &t,
        w.attest(
            &w.aws,
            &wk.id(),
            "box-w1",
            "i-0001",
            "staging",
            WORKER_CLASS,
        ),
    );
    w.hubd.receive_enrolment(&req, NOW).unwrap();
    let plan = w.hubd.plan_enrol("worker-1").unwrap();
    std::fs::write(&w.cfg.registrars, br#"{"registrars":[]}"#).unwrap();
    assert_eq!(
        w.hubd.apply_enrol(&plan, NOW).unwrap_err().code,
        CODE_UNKNOWN_REGISTRAR
    );
}

// ---- the daemon: verify, spool, handshake, socket --------------------------------------------------------------------

/// The worker's transport straight into the daemon; the hub's through it. What H3's network transport does over a connection.
struct WorkerNet(Arc<Hubd>, Mutex<VecDeque<Sealed>>);
impl Transport for WorkerNet {
    fn send(&self, _to: &str, msg: Sealed) -> Result<(), WireError> {
        self.0.accept(msg, NOW).map_err(|_| WireError::SendFailed)
    }
    fn recv(&self, who: &str) -> Option<Sealed> {
        let mut b = self.1.lock().unwrap();
        if b.is_empty() {
            b.extend(self.0.take_outbound(who));
        }
        b.pop_front()
    }
}

struct HubNet(Arc<Hubd>, Mutex<VecDeque<Sealed>>);
impl Transport for HubNet {
    fn send(&self, to: &str, msg: Sealed) -> Result<(), WireError> {
        self.0
            .put_outbound(to, vec![msg], NOW)
            .map(|_| ())
            .map_err(|_| WireError::SendFailed)
    }
    fn recv(&self, _who: &str) -> Option<Sealed> {
        let mut b = self.1.lock().unwrap();
        if b.is_empty() {
            b.extend(self.0.take_inbound().unwrap());
        }
        b.pop_front()
    }
}

fn assign(feature: &str) -> Assign {
    Assign {
        orchestration: "orch-1".into(),
        feature: feature.into(),
        title: "Add the thing".into(),
        brief: "SENTINEL-brief-body".into(),
        branch: format!("feat/{feature}"),
        repo: None,
        claims: vec![],
        contracts: vec![],
        keys: KeyDeclaration {
            env: "staging".into(),
            names: vec!["SUPABASE_URL".into()],
        },
        lease_expiry_ms: NOW + 3_600_000,
        engine: None,
        model: None,
    }
}

#[test]
fn a_task_goes_to_an_enrolled_worker_and_its_report_comes_back_through_the_daemon_on_real_keys() {
    let w = world();
    let wk = end();
    w.enrol(&wk, "worker-1", "box-w1", "i-0001");
    // main: the supervisor's seams from the attested roster
    let (hs_seams, roster) =
        hub_seams(w.hub.ops(Caller::Supervisor), &w.hubd.roster().unwrap()).unwrap();
    // the worker: its seams from the handshake it verified against the pinned identity fingerprint
    let challenge = [9u8; 32];
    let h = w.hubd.handshake(&challenge, NOW).unwrap();
    let hub_id = verify_handshake(&w.hub.id().identity_fp(), &challenge, &h, NOW).unwrap();
    let (ws_seams, hub_fp) = worker_seams(wk.ops(Caller::Supervisor), &hub_id).unwrap();
    let hub_net = HubNet(w.hubd.clone(), Mutex::new(VecDeque::new()));
    let w_net = WorkerNet(w.hubd.clone(), Mutex::new(VecDeque::new()));
    let hub = Hub {
        me: "main",
        my_fp: &hs_seams.my_fp,
        roster: &roster,
        signer: hs_seams.signer.as_ref(),
        verifier: hs_seams.verifier.as_ref(),
        sealer: hs_seams.sealer.as_ref(),
        net: &hub_net,
        deferred: false,
    };
    let worker = WorkerEnd {
        me: "worker-1",
        hub: "main",
        signer: ws_seams.signer.as_ref(),
        verifier: ws_seams.verifier.as_ref(),
        sealer: ws_seams.sealer.as_ref(),
        net: &w_net,
    };
    let mut hs = HubState::new("main", &hs_seams.my_fp, 7);
    let mut ws = WorkerState::new("worker-1", &ws_seams.my_fp, "main", &hub_fp, 7);
    worker.hello(&mut ws, NOW);
    for _ in 0..6 {
        hub.poll(&mut hs, NOW);
        worker.poll(&mut ws, NOW);
    }
    assert_eq!(hs.peer_inc("worker-1"), ws.inc());
    hub.assign(&mut hs, "worker-1", &assign("f1"), NOW).unwrap();
    assert_eq!(worker.poll(&mut ws, NOW), 1);
    assert_eq!(ws.tasks[0].feature, "f1");
    worker.finish(&mut ws, NOW, "orch-1", "f1", "abc123", "done");
    hub.poll(&mut hs, NOW);
    assert_eq!(
        hs.peers["worker-1"].report.results["orch-1"]["f1"].commit,
        "abc123"
    );
    // the daemon's state never held a plaintext body
    assert!(!state_text(&w).contains("SENTINEL-brief-body"));
}

#[test]
fn the_daemon_spools_only_what_an_enrolled_worker_signed_for_this_hubs_key() {
    let w = world();
    let wk = end();
    let stranger = end();
    w.enrol(&wk, "worker-1", "box-w1", "i-0001");
    let hub_dir = Directory::default();
    hub_dir.insert(&w.hub.id());
    let msg = |from: &End, name: &str, to_fp: &str| {
        let mut e = sample();
        e.from = name.into();
        e.to = "main".into();
        e.kind = "status".into();
        e.ext = Ext::at(1).encode();
        e.receiver_fp = to_fp.into();
        e.ts_ms = NOW;
        e.valid_until_ms = NOW + 60_000;
        let cx = Crypto {
            signer: &ServiceSigner {
                ops: from.ops(Caller::Supervisor),
            },
            verifier: &DirectoryVerifier {
                dir: hub_dir.clone(),
            },
            sealer: &ServiceSealer {
                ops: from.ops(Caller::Supervisor),
                dir: hub_dir.clone(),
            },
        };
        seal_and_sign(&PROFILE, e, to_fp, b"{}", &cx).unwrap()
    };
    let hub_fp = w.hub.id().channel_fp();
    assert_eq!(
        w.hubd.accept(msg(&stranger, "worker-9", &hub_fp), NOW),
        Err(Rejected("not-enrolled"))
    );
    // a stranger signing as an enrolled worker
    assert_eq!(
        w.hubd.accept(msg(&stranger, "worker-1", &hub_fp), NOW),
        Err(Rejected("bad-signature"))
    );
    let good = msg(&wk, "worker-1", &hub_fp);
    let mut wrong_key = good.clone();
    wrong_key.envelope.receiver_fp = wk.id().channel_fp();
    assert_eq!(
        w.hubd.accept(wrong_key, NOW),
        Err(Rejected("sealed-for-another-key"))
    );
    w.hubd.accept(good.clone(), NOW).unwrap();
    // spooled durably: a new daemon over the same directory has it
    let again = Hubd::open(w.cfg.clone(), w.hub.ops(Caller::Hub)).unwrap();
    assert_eq!(again.take_inbound().unwrap(), vec![good]);
    // refusals are audited by code, at most once a minute each
    let st = again.state().unwrap();
    assert!(st
        .audit
        .iter()
        .any(|e| e.action == "hub.refused" && e.detail.contains("not-enrolled")));
    // the supervisor cannot queue a message that is not sealed for the worker's attested key
    assert_eq!(
        again.put_outbound("worker-1", vec![msg(&w.hub, "main", &hub_fp)], NOW),
        Err(Rejected("outbound-misaddressed"))
    );
    assert_eq!(
        again.put_outbound("worker-9", vec![], NOW),
        Err(Rejected("not-enrolled"))
    );
}

#[test]
fn a_worker_accepts_only_the_hub_identity_it_pinned() {
    let w = world();
    let challenge = [3u8; 32];
    let h = w.hubd.handshake(&challenge, NOW).unwrap();
    assert!(verify_handshake(&w.hub.id().identity_fp(), &challenge, &h, NOW).is_some());
    // another pin, another challenge, a late answer, or an identity swapped in beside the signature
    assert!(verify_handshake(&end().id().identity_fp(), &challenge, &h, NOW).is_none());
    assert!(verify_handshake(&w.hub.id().identity_fp(), &[4u8; 32], &h, NOW).is_none());
    assert!(
        verify_handshake(&w.hub.id().identity_fp(), &challenge, &h, NOW + 10 * 60_000).is_none()
    );
    let mut swapped = h.clone();
    swapped.identity = end().id();
    assert!(verify_handshake(&swapped.identity.identity_fp(), &challenge, &swapped, NOW).is_none());
    assert!(w.hubd.handshake(&[1u8; 4], NOW).is_err());
}

#[test]
fn the_daemon_starts_on_its_socket_answers_and_stops() {
    let w = world();
    let l = bind(&w.cfg.socket, 0o750).unwrap();
    let running = w.hubd.serve(l, Some(w.cfg.socket.clone())).unwrap();
    let v = ask(&w.cfg.socket, &serde_json::json!({"op": "status"})).unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["result"]["identity_fp"], w.hub.id().identity_fp());
    // the invite over the socket: plan, then apply; the token comes back once
    let p = ask(
        &w.cfg.socket,
        &serde_json::json!({"op": "invite_plan", "spec": spec("worker-1", "box-w1", "i-0001")}),
    )
    .unwrap();
    assert_eq!(p["ok"], true, "{p}");
    assert!(p["result"]["plan"].get("token").is_none());
    let a = ask(
        &w.cfg.socket,
        &serde_json::json!({"op": "invite_apply", "plan": p["result"]["plan"]}),
    )
    .unwrap();
    let token = a["result"]["token"].as_str().unwrap().to_string();
    assert_eq!(token.len(), TOKEN_BYTES * 2);
    assert!(!state_text(&w).contains(&token));
    // a refusal comes back with its code
    let r = ask(
        &w.cfg.socket,
        &serde_json::json!({"op": "enrol_plan", "worker": "nobody"}),
    )
    .unwrap();
    assert_eq!(r["code"], CODE_NOTHING_PENDING);
    // the supervisor's transport works over the socket
    let t = SpoolTransport::new(&w.cfg.socket);
    assert!(t.recv("main").is_none());
    running.stop();
    // stopped: nothing answers on the path any more
    assert!(ask(&w.cfg.socket, &serde_json::json!({"op": "status"})).is_err());
}

#[test]
fn the_self_test_passes_on_the_daemons_socket_and_fails_on_the_wrong_one() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let w = world();
    bind(&w.cfg.socket, 0o750).unwrap();
    std::fs::set_permissions(&w.cfg.registrars, std::fs::Permissions::from_mode(0o644)).unwrap();
    let uid = std::fs::metadata(&w.cfg.registrars).unwrap().uid();
    let checks = crate::selftest::self_test(&w.cfg, w.hub.ops(Caller::Hub).as_ref(), uid, NOW);
    assert!(checks.iter().all(|c| c.ok), "{checks:?}");
    // the supervisor's socket is the wrong one for the daemon: it can sign envelopes
    let wrong =
        crate::selftest::self_test(&w.cfg, w.hub.ops(Caller::Supervisor).as_ref(), uid, NOW);
    assert!(wrong
        .iter()
        .any(|c| c.name == "no-body-operations" && !c.ok));
    // a registrars file another user owns, or that is group-writable, fails
    let other = crate::selftest::self_test(&w.cfg, w.hub.ops(Caller::Hub).as_ref(), uid + 1, NOW);
    assert!(other.iter().any(|c| c.name == "registrars" && !c.ok));
    std::fs::set_permissions(&w.cfg.registrars, std::fs::Permissions::from_mode(0o664)).unwrap();
    let gw = crate::selftest::self_test(&w.cfg, w.hub.ops(Caller::Hub).as_ref(), uid, NOW);
    assert!(gw.iter().any(|c| c.name == "registrars" && !c.ok));
    // a state directory others can enter fails
    std::fs::set_permissions(&w.cfg.dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let open = crate::selftest::self_test(&w.cfg, w.hub.ops(Caller::Hub).as_ref(), uid, NOW);
    assert!(open.iter().any(|c| c.name == "state-dir" && !c.ok));
}

// ---- sentinels ---------------------------------------------------------------------------------------------------------

#[test]
fn no_private_key_token_or_mac_leaves_the_store_in_any_output() {
    let w = world();
    let wk = end();
    let token = w.invite("worker-1", "box-w1", "i-0001");
    let a = w.attest(
        &w.aws,
        &wk.id(),
        "box-w1",
        "i-0001",
        "staging",
        WORKER_CLASS,
    );
    let req = w.request(&wk, "worker-1", &token, a);
    // a refused one first, then the real one
    let mut bad = req.clone();
    bad.token = Zeroizing::new("ee".repeat(24));
    let refusal = w.hubd.receive_enrolment(&bad, NOW).unwrap_err();
    w.hubd.receive_enrolment(&req, NOW).unwrap();
    let plan = w.hubd.plan_enrol("worker-1").unwrap();
    w.hubd.apply_enrol(&plan, NOW).unwrap();
    let st = w.hubd.state().unwrap();
    let mut outputs = vec![
        state_text(&w),
        format!("{req:?}"),
        format!("{:?}", w.hub.keys),
        format!("{:?}", wk.keys),
        format!("{refusal} {refusal:?}"),
        serde_json::to_string(&plan).unwrap(),
        serde_json::to_string(&st.audit).unwrap(),
        serde_json::to_string(&w.hub.id()).unwrap(),
        w.hubd.handle_line(r#"{"op":"status"}"#, NOW),
        w.hubd.handle_line(r#"{"op":"identity"}"#, NOW),
        w.hubd.handle_line(r#"{"op":"roster"}"#, NOW),
        w.hubd.handle_line(r#"{"op":"enrol_pending"}"#, NOW),
        w.hubd.handle_line(r#"{"op":"audit_since","after":0}"#, NOW),
    ];
    for c in crate::selftest::self_test(&w.cfg, w.hub.ops(Caller::Hub).as_ref(), 0, NOW) {
        outputs.push(format!("{c:?}"));
    }
    let secrets: Vec<String> = w
        .hub
        .store
        .values()
        .into_iter()
        .chain(wk.store.values())
        .chain([token.to_string(), "ee".repeat(24)])
        .collect();
    for out in &outputs {
        for s in &secrets {
            assert!(
                !out.contains(s.as_str()),
                "a secret appeared in: {}",
                &out[..out.len().min(80)]
            );
        }
    }
    // the token's MAC is not kept once the token is burnt
    assert!(st.enrol.invites.is_empty());
}
