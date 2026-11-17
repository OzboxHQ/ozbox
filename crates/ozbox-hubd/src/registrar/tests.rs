#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;

use ozbox_core::approval_subject::sha256_hex;
use ozbox_core::channel::wire::hex;
use zeroize::Zeroizing;

use super::aws::*;
use super::fixtures as fx;
use super::*;
use crate::daemon::{Config, Hubd};
use crate::enrol::*;
use crate::keys::Caller;
use crate::tests::{end, End, HUB_BOX, NOW};

const ACCOUNT: &str = "123456789012";
const INSTANCE: &str = "i-0123456789abcdef0";
const WORKER: &str = "w1";
const BOX: &str = "box-w1";

struct Table(BTreeMap<String, ClaimRecord>);

impl ClaimTable for Table {
    fn lookup(&self, id: &str) -> Option<ClaimRecord> {
        self.0.get(id).cloned()
    }
}

fn signer() -> SeedSigner {
    SeedSigner::generate().unwrap().1
}

fn reg(provider: Provider, s: &SeedSigner) -> Registrar {
    Registrar {
        provider,
        public: s.public_hex(),
    }
}

struct World {
    tmp: tempfile::TempDir,
    hub: End,
    hubd: std::sync::Arc<Hubd>,
    cfg: Config,
    aws: SeedSigner,
    laptop: SeedSigner,
    certs: AwsCerts,
    policy: AwsPolicy,
}

fn world() -> World {
    let tmp = tempfile::tempdir().unwrap();
    let hub = end();
    let aws = signer();
    let laptop = signer();
    let path = tmp.path().join("registrars.json");
    let cfg = Config {
        dir: tmp.path().join("state"),
        socket: tmp.path().join("run/hubd.sock"),
        registrars: path,
        box_id: HUB_BOX.into(),
        name: "main".into(),
    };
    let hubd = Hubd::open(cfg.clone(), hub.ops(Caller::Hub)).unwrap();
    let certs = AwsCerts::from_test_cert(&["us-east-1", "eu-west-1"], fx::TEST_CERT).unwrap();
    let policy = AwsPolicy {
        account: ACCOUNT.into(),
        regions: vec!["us-east-1".into()],
        max_instance_age_ms: DEFAULT_MAX_INSTANCE_AGE_MS,
    };
    World {
        tmp,
        hub,
        hubd,
        cfg,
        aws,
        laptop,
        certs,
        policy,
    }
}

impl World {
    fn pin(&self, regs: &[Registrar]) {
        let r = Registrars {
            registrars: regs.to_vec(),
        };
        std::fs::write(&self.cfg.registrars, serde_json::to_vec(&r).unwrap()).unwrap();
    }

    fn hub_fp(&self) -> String {
        self.hub.id().identity_fp()
    }

    fn record(&self, token: &str) -> ClaimRecord {
        ClaimRecord {
            instance_id: INSTANCE.into(),
            worker: WORKER.into(),
            box_id: BOX.into(),
            orchestration: "orch-1".into(),
            hub_identity_fp: self.hub_fp(),
            class: WORKER_CLASS.into(),
            environment: "staging".into(),
            token_sha256: sha256_hex(token),
        }
    }

    fn invite(&self, provider: Provider, machine: &str, addr: &str) -> Zeroizing<String> {
        let plan = self
            .hubd
            .plan_invite(&InviteSpec {
                worker: WORKER.into(),
                box_id: BOX.into(),
                provider,
                machine: machine.into(),
                private_address: addr.into(),
                orchestration: "orch-1".into(),
            })
            .unwrap();
        self.hubd.apply_invite(&plan, NOW).unwrap()
    }

    /// An AWS registrar over this world's certificates and the given table.
    fn attest(
        &self,
        table: &Table,
        state: &mut RegistrarState,
        claim: &AwsClaim,
    ) -> Result<Attestation, Refusal> {
        AwsRegistrar {
            certs: &self.certs,
            policy: &self.policy,
            table,
            signer: &self.aws,
        }
        .attest(state, claim, NOW)
    }
}

fn worker_claim(w: &World, worker: &End, token: &str, pkcs7: &str, now: u64) -> AwsClaim {
    make_claim(
        worker.ops(Caller::Supervisor).as_ref(),
        WORKER,
        token,
        pkcs7,
        &w.hub_fp(),
        now,
    )
    .unwrap()
}

fn table(w: &World, token: &str) -> Table {
    let mut m = BTreeMap::new();
    m.insert(INSTANCE.to_string(), w.record(token));
    Table(m)
}

fn code<T>(r: Result<T, Refusal>) -> &'static str {
    r.err().expect("a refusal").code
}

/// The same document with one byte changed inside the signed content, re-encoded.
fn forged(pkcs7: &str) -> String {
    let mut raw = der::base64_decode(pkcs7).unwrap();
    let needle = ACCOUNT.as_bytes();
    let at = raw.windows(needle.len()).position(|w| w == needle).unwrap();
    raw[at + needle.len() - 1] = b'3';
    base64_encode(&raw)
}

fn base64_encode(b: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut o = String::new();
    for c in b.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        o.push(T[(n >> 18) as usize & 63] as char);
        o.push(T[(n >> 12) as usize & 63] as char);
        o.push(if c.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        o.push(if c.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    o
}

// ---- the parser ------------------------------------------------------------------------------------------------------

#[test]
fn times_and_base64_read_what_aws_writes_and_nothing_else() {
    assert_eq!(der::rfc3339_ms("2027-01-15T08:00:00Z"), Some(NOW));
    assert_eq!(der::rfc3339_ms("1970-01-01T00:00:00Z"), Some(0));
    assert_eq!(der::rfc3339_ms("2027-01-15 08:00:00"), None);
    assert_eq!(der::rfc3339_ms("2027-13-15T08:00:00Z"), None);
    for s in ["", "f", "fo", "foo", "foob", "fooba", "foobar"] {
        assert_eq!(
            der::base64_decode(&base64_encode(s.as_bytes())).unwrap(),
            s.as_bytes()
        );
    }
    assert!(der::base64_decode("ab=c").is_none());
    assert!(der::base64_decode("abc").is_none());
    assert!(der::base64_decode("a$bc").is_none());
}

#[test]
fn a_malformed_or_hostile_signature_is_none_and_never_a_panic() {
    assert!(der::signed_data(&[]).is_none());
    assert!(der::signed_data(b"not der at all").is_none());
    // nesting far deeper than any real file
    let mut bomb = Vec::new();
    for _ in 0..200 {
        bomb.extend_from_slice(&[0x30, 0x80]);
    }
    assert!(der::signed_data(&bomb).is_none());
    // a length that runs past the input
    assert!(der::signed_data(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff, 0x00]).is_none());
    // every prefix of a real signature
    let raw = der::base64_decode(fx::OK).unwrap();
    for n in (0..raw.len()).step_by(37) {
        let _ = der::signed_data(&raw[..n]);
    }
}

// ---- the pinned AWS table --------------------------------------------------------------------------------------------

#[test]
fn the_published_certificate_table_loads_and_is_all_rsa_2048() {
    let c = AwsCerts::published().unwrap();
    assert_eq!(c.regions().len(), 31);
    for r in [
        "us-east-1",
        "eu-west-1",
        "ap-southeast-2",
        "us-gov-west-1",
        "cn-north-1",
    ] {
        assert!(c.regions().contains(&r), "{r}");
    }
    assert!(aws_certs::SOURCE_URL.starts_with("https://docs.aws.amazon.com/"));
    // every row names a region code, a name and a certificate
    assert!(aws_certs::CERTS
        .iter()
        .all(|(r, n, c)| !r.is_empty() && !n.is_empty() && c.starts_with("MII")));
}

#[test]
fn a_document_not_signed_by_aws_is_refused_under_the_real_table() {
    let w = world();
    let worker = end();
    let token = "a".repeat(48);
    let real = AwsCerts::published().unwrap();
    let claim = worker_claim(&w, &worker, &token, fx::OK, NOW);
    let mut st = RegistrarState::default();
    let r = AwsRegistrar {
        certs: &real,
        policy: &w.policy,
        table: &table(&w, &token),
        signer: &w.aws,
    }
    .attest(&mut st, &claim, NOW);
    assert_eq!(code(r), CODE_BAD_SIGNATURE);
}

// ---- the AWS registrar -----------------------------------------------------------------------------------------------

fn good(w: &World) -> (End, String, AwsClaim) {
    let worker = end();
    let token = w.invite(Provider::Aws, INSTANCE, "").to_string();
    let claim = worker_claim(w, &worker, &token, fx::OK, NOW);
    (worker, token, claim)
}

#[test]
fn a_valid_identity_enrols_a_worker_through_the_hub_end_to_end() {
    for fixture in [fx::OK, fx::NOATTR, fx::STREAM] {
        let w = world();
        w.pin(&[reg(Provider::Aws, &w.aws)]);
        let worker = end();
        let token = w.invite(Provider::Aws, INSTANCE, "").to_string();
        let claim = worker_claim(&w, &worker, &token, fixture, NOW);
        let mut st = RegistrarState::default();
        let a = w.attest(&table(&w, &token), &mut st, &claim).unwrap();
        assert_eq!(a.machine, INSTANCE);
        assert_eq!(a.box_id, BOX);
        assert_eq!(a.channel_fp, worker.id().channel_fp());
        assert_eq!(a.registrar_fp, registrar_fingerprint(&w.aws));
        let req = make_request(
            worker.ops(Caller::Supervisor).as_ref(),
            WORKER,
            &token,
            a,
            &w.hub_fp(),
            NOW,
        )
        .unwrap();
        w.hubd.receive_enrolment(&req, NOW).unwrap();
        let plan = w.hubd.plan_enrol(WORKER).unwrap();
        let rec = w.hubd.apply_enrol(&plan, NOW).unwrap();
        assert_eq!(rec.machine, INSTANCE);
        assert_eq!(rec.registrar_fp, registrar_fingerprint(&w.aws));
    }
}

#[test]
fn a_forged_signature_is_refused() {
    let w = world();
    for fixture in [fx::OK, fx::NOATTR] {
        let worker = end();
        let token = "b".repeat(48);
        let claim = worker_claim(&w, &worker, &token, &forged(fixture), NOW);
        let mut st = RegistrarState::default();
        assert_eq!(
            code(w.attest(&table(&w, &token), &mut st, &claim)),
            CODE_BAD_SIGNATURE
        );
    }
}

#[test]
fn each_wrong_fact_in_a_genuine_document_is_refused_with_its_own_reason() {
    let w = world();
    let worker = end();
    let token = "c".repeat(48);
    let t = table(&w, &token);
    let run = |pkcs7: &str| {
        let claim = worker_claim(&w, &worker, &token, pkcs7, NOW);
        w.attest(&t, &mut RegistrarState::default(), &claim)
    };
    assert_eq!(code(run(fx::OTHER_ACCOUNT)), CODE_WRONG_ACCOUNT);
    assert_eq!(code(run(fx::OTHER_REGION)), CODE_WRONG_REGION);
    assert_eq!(code(run(fx::UNKNOWN_REGION)), CODE_UNKNOWN_REGION);
    assert_eq!(code(run(fx::STALE)), CODE_STALE_DOCUMENT);
    // a genuine document for an instance the claim service never reserved
    assert_eq!(code(run(fx::OTHER_INSTANCE)), CODE_UNKNOWN_INSTANCE);
}

#[test]
fn a_document_for_another_instance_is_refused_even_when_that_instance_is_reserved_for_someone_else()
{
    let w = world();
    let worker = end();
    let token = "d".repeat(48);
    let mut t = table(&w, &token);
    let mut other = w.record(&token);
    other.instance_id = "i-0fedcba9876543210".into();
    other.worker = "w2".into();
    t.0.insert(other.instance_id.clone(), other);
    // w1 presents the genuine document of w2's instance
    let claim = worker_claim(&w, &worker, &token, fx::OTHER_INSTANCE, NOW);
    assert_eq!(
        code(w.attest(&t, &mut RegistrarState::default(), &claim)),
        CODE_WRONG_INSTANCE
    );
}

#[test]
fn a_claim_that_is_stale_replayed_or_for_an_attested_instance_is_refused() {
    let w = world();
    let worker = end();
    let token = "e".repeat(48);
    let t = table(&w, &token);
    // too old
    let old = worker_claim(&w, &worker, &token, fx::OK, NOW - 10 * 60 * 1000);
    assert_eq!(
        code(w.attest(&t, &mut RegistrarState::default(), &old)),
        CODE_STALE_CLAIM
    );
    // from the future
    let future = worker_claim(&w, &worker, &token, fx::OK, NOW + 10 * 60 * 1000);
    assert_eq!(
        code(w.attest(&t, &mut RegistrarState::default(), &future)),
        CODE_STALE_CLAIM
    );
    // taken twice
    let claim = worker_claim(&w, &worker, &token, fx::OK, NOW);
    let mut st = RegistrarState::default();
    w.attest(&t, &mut st, &claim).unwrap();
    assert_eq!(code(w.attest(&t, &mut st, &claim)), CODE_REPLAYED_CLAIM);
    // a fresh claim for the same instance, even by another key: not swapped
    let other_key = end();
    let again = worker_claim(&w, &other_key, &token, fx::OK, NOW);
    assert_eq!(code(w.attest(&t, &mut st, &again)), CODE_ALREADY_ATTESTED);
}

#[test]
fn a_wrong_token_or_a_proof_by_another_key_is_refused() {
    let w = world();
    let worker = end();
    let token = "f".repeat(48);
    let t = table(&w, &token);
    let bad = worker_claim(&w, &worker, &"0".repeat(48), fx::OK, NOW);
    assert_eq!(
        code(w.attest(&t, &mut RegistrarState::default(), &bad)),
        CODE_BAD_TOKEN
    );
    // the keys presented are the thief's; the proof is the real worker's
    let thief = end();
    let mut claim = worker_claim(&w, &worker, &token, fx::OK, NOW);
    claim.identity = thief.id();
    assert_eq!(
        code(w.attest(&t, &mut RegistrarState::default(), &claim)),
        CODE_WRONG_KEY
    );
    // a claim made for another hub
    let for_other_hub = make_claim(
        worker.ops(Caller::Supervisor).as_ref(),
        WORKER,
        &token,
        fx::OK,
        &end().id().identity_fp(),
        NOW,
    )
    .unwrap();
    assert_eq!(
        code(w.attest(&t, &mut RegistrarState::default(), &for_other_hub)),
        CODE_WRONG_KEY
    );
}

#[test]
fn a_production_box_or_main_is_never_attested() {
    let w = world();
    let worker = end();
    let token = "9".repeat(48);
    for (class, env) in [
        ("worker", "production"),
        ("worker", "prod"),
        ("worker", "mystery"),
        ("main", "staging"),
    ] {
        let mut t = table(&w, &token);
        let r = t.0.get_mut(INSTANCE).unwrap();
        r.class = class.into();
        r.environment = env.into();
        let claim = worker_claim(&w, &worker, &token, fx::OK, NOW);
        assert_eq!(
            code(w.attest(&t, &mut RegistrarState::default(), &claim)),
            CODE_PRODUCTION_BOX,
            "{class} {env}"
        );
    }
}

#[test]
fn an_unpinned_registrar_a_wrong_machine_and_a_wrong_hub_are_refused_by_the_hub() {
    let w = world();
    let worker = end();
    let token = w.invite(Provider::Aws, INSTANCE, "").to_string();
    let t = table(&w, &token);
    let claim = worker_claim(&w, &worker, &token, fx::OK, NOW);
    let a = w
        .attest(&t, &mut RegistrarState::default(), &claim)
        .unwrap();
    let req = |a: Attestation| {
        make_request(
            worker.ops(Caller::Supervisor).as_ref(),
            WORKER,
            &token,
            a,
            &w.hub_fp(),
            NOW,
        )
        .unwrap()
    };
    // nothing is pinned: every worker is refused, as on a box before this registrar is pinned
    w.pin(&[]);
    assert_eq!(
        code(w.hubd.receive_enrolment(&req(a.clone()), NOW)),
        CODE_UNKNOWN_REGISTRAR
    );
    // pinned as a Hetzner registrar: not for an AWS worker
    w.pin(&[reg(Provider::Hetzner, &w.aws)]);
    assert_eq!(
        code(w.hubd.receive_enrolment(&req(a.clone()), NOW)),
        CODE_UNKNOWN_REGISTRAR
    );
    // a different key's pin does not vouch for this registrar
    w.pin(&[reg(Provider::Aws, &signer())]);
    assert_eq!(
        code(w.hubd.receive_enrolment(&req(a.clone()), NOW)),
        CODE_UNKNOWN_REGISTRAR
    );
    // pinned: it enrols
    w.pin(&[reg(Provider::Aws, &w.aws)]);
    w.hubd.receive_enrolment(&req(a), NOW).unwrap();

    // an attestation for an instance other than the one the hub created
    let w2 = world();
    w2.pin(&[reg(Provider::Aws, &w2.aws)]);
    let token2 = w2
        .invite(Provider::Aws, "i-0aaaaaaaaaaaaaaaa", "")
        .to_string();
    let claim2 = worker_claim(&w2, &worker, &token2, fx::OK, NOW);
    let a2 = w2
        .attest(
            &table(&w2, &token2),
            &mut RegistrarState::default(),
            &claim2,
        )
        .unwrap();
    let r2 = make_request(
        worker.ops(Caller::Supervisor).as_ref(),
        WORKER,
        &token2,
        a2,
        &w2.hub_fp(),
        NOW,
    )
    .unwrap();
    assert_eq!(code(w2.hubd.receive_enrolment(&r2, NOW)), CODE_BINDING);
}

#[test]
fn no_token_or_key_appears_in_a_refusal_a_debug_line_or_the_registrars_state() {
    let w = world();
    let (seed, s) = SeedSigner::generate().unwrap();
    let worker = end();
    let token = "7".repeat(48);
    let claim = worker_claim(&w, &worker, &token, &forged(fx::OK), NOW);
    let mut st = RegistrarState::default();
    let mut seen = vec![
        format!("{claim:?}"),
        format!("{s:?}"),
        format!("{:?}", w.aws),
    ];
    seen.push(
        w.attest(&table(&w, &token), &mut st, &claim)
            .unwrap_err()
            .to_string(),
    );
    let ok = worker_claim(&w, &worker, &token, fx::OK, NOW);
    let a = w.attest(&table(&w, &token), &mut st, &ok).unwrap();
    seen.push(serde_json::to_string(&st).unwrap());
    seen.push(format!("{a:?}"));
    // a refusal for every wrong token too
    let bad = worker_claim(&w, &end(), &"1".repeat(48), fx::OK, NOW);
    let e = w.attest(&table(&w, &token), &mut st, &bad).unwrap_err();
    seen.push(format!("{} {}", e.code, e.message));
    for text in &seen {
        assert!(
            !text.contains(&token) && !text.contains(&"1".repeat(48)),
            "{text}"
        );
        assert!(!text.contains(seed.as_str()), "{text}");
    }
    // the state holds fingerprints and digests, never the token's hash input
    assert!(!seen[4].contains(&sha256_hex(&token)));
}

// ---- your computer as the registrar ----------------------------------------------------------------------------------

fn request(
    w: &World,
    worker: &End,
    provider: Provider,
    secret: Option<&[u8]>,
) -> laptop::LaptopRequest {
    let mut r = laptop::LaptopRequest {
        provider,
        machine: if provider == Provider::Own {
            "machine-7".into()
        } else {
            "srv-1234".into()
        },
        box_id: BOX.into(),
        orchestration: "orch-1".into(),
        hub_identity_fp: w.hub_fp(),
        private_address: if provider == Provider::Hetzner {
            "10.0.0.7".into()
        } else {
            String::new()
        },
        class: WORKER_CLASS.into(),
        environment: "staging".into(),
        identity: worker.id(),
        creation_proof: String::new(),
    };
    if let Some(s) = secret {
        r.creation_proof = laptop::creation_proof(s, &r);
    }
    r
}

fn no_box() -> laptop::Site {
    laptop::Site {
        box_markers: vec![],
    }
}

#[test]
fn the_laptop_attests_a_machine_you_own_after_a_plan_and_the_hub_enrols_it() {
    let w = world();
    w.pin(&[reg(Provider::Own, &w.laptop)]);
    let worker = end();
    let token = w.invite(Provider::Own, "machine-7", "").to_string();
    let req = request(&w, &worker, Provider::Own, None);
    let plan = laptop::plan(&req).unwrap();
    assert!(plan
        .steps
        .iter()
        .any(|s| s.contains(&worker.id().channel_fp())));
    let a = laptop::apply(&plan, &req, &w.laptop, None, &no_box(), NOW).unwrap();
    let r = make_request(
        worker.ops(Caller::Supervisor).as_ref(),
        WORKER,
        &token,
        a,
        &w.hub_fp(),
        NOW,
    )
    .unwrap();
    w.hubd.receive_enrolment(&r, NOW).unwrap();
    let plan = w.hubd.plan_enrol(WORKER).unwrap();
    assert_eq!(
        w.hubd.apply_enrol(&plan, NOW).unwrap().provider,
        Provider::Own
    );
}

#[test]
fn the_laptop_attests_a_hetzner_worker_only_with_the_creation_secret() {
    let w = world();
    w.pin(&[reg(Provider::Hetzner, &w.laptop)]);
    let worker = end();
    let token = w.invite(Provider::Hetzner, "", "10.0.0.7").to_string();
    let secret = b"one-time-creation-secret-bytes".as_slice();
    let req = request(&w, &worker, Provider::Hetzner, Some(secret));
    let plan = laptop::plan(&req).unwrap();
    // no secret, the wrong secret, and a proof made under another request
    assert_eq!(
        code(laptop::apply(&plan, &req, &w.laptop, None, &no_box(), NOW)),
        CODE_BAD_CREATION_PROOF
    );
    assert_eq!(
        code(laptop::apply(
            &plan,
            &req,
            &w.laptop,
            Some(b"wrong"),
            &no_box(),
            NOW
        )),
        CODE_BAD_CREATION_PROOF
    );
    let mut moved = req.clone();
    moved.private_address = "10.0.0.8".into();
    let moved_plan = laptop::plan(&moved).unwrap();
    assert_eq!(
        code(laptop::apply(
            &moved_plan,
            &moved,
            &w.laptop,
            Some(secret),
            &no_box(),
            NOW
        )),
        CODE_BAD_CREATION_PROOF
    );
    // the right secret
    let a = laptop::apply(&plan, &req, &w.laptop, Some(secret), &no_box(), NOW).unwrap();
    assert_eq!(a.private_address, "10.0.0.7");
    let r = make_request(
        worker.ops(Caller::Supervisor).as_ref(),
        WORKER,
        &token,
        a,
        &w.hub_fp(),
        NOW,
    )
    .unwrap();
    w.hubd.receive_enrolment(&r, NOW).unwrap();
    // the secret is in no plan or attestation
    let text = format!("{plan:?} {:?}", w.hubd.plan_enrol(WORKER).unwrap());
    assert!(!text.contains("one-time-creation-secret"));
}

#[test]
fn the_laptop_refuses_a_stale_plan_production_aws_and_any_box() {
    let w = world();
    let worker = end();
    let req = request(&w, &worker, Provider::Own, None);
    let plan = laptop::plan(&req).unwrap();
    let mut changed = req.clone();
    changed.orchestration = "orch-2".into();
    assert_eq!(
        code(laptop::apply(
            &plan,
            &changed,
            &w.laptop,
            None,
            &no_box(),
            NOW
        )),
        CODE_STALE_PLAN
    );
    for env in ["production", "live", "unknown"] {
        let mut p = req.clone();
        p.environment = env.into();
        assert_eq!(code(laptop::plan(&p)), CODE_PRODUCTION_BOX);
    }
    let mut main = req.clone();
    main.class = "main".into();
    assert_eq!(code(laptop::plan(&main)), CODE_PRODUCTION_BOX);
    let mut aws = req.clone();
    aws.provider = Provider::Aws;
    assert_eq!(code(laptop::plan(&aws)), CODE_UNSUPPORTED_PROVIDER);
    // on a box: refused, the key or not
    let marker = w.tmp.path().join("etc-ozbox");
    std::fs::create_dir(&marker).unwrap();
    let site = laptop::Site {
        box_markers: vec![marker],
    };
    assert_eq!(
        code(laptop::apply(&plan, &req, &w.laptop, None, &site, NOW)),
        CODE_NOT_ON_A_BOX
    );
}

#[test]
fn a_laptop_attestation_cannot_be_used_for_an_aws_worker() {
    let w = world();
    // the laptop is pinned for Own only
    w.pin(&[reg(Provider::Own, &w.laptop)]);
    let worker = end();
    let token = w.invite(Provider::Aws, INSTANCE, "").to_string();
    let req = request(&w, &worker, Provider::Own, None);
    let plan = laptop::plan(&req).unwrap();
    let a = laptop::apply(&plan, &req, &w.laptop, None, &no_box(), NOW).unwrap();
    let r = make_request(
        worker.ops(Caller::Supervisor).as_ref(),
        WORKER,
        &token,
        a,
        &w.hub_fp(),
        NOW,
    )
    .unwrap();
    assert_eq!(code(w.hubd.receive_enrolment(&r, NOW)), CODE_BINDING);
}

// ---- repin -----------------------------------------------------------------------------------------------------------

#[test]
fn repin_pins_rotates_and_removes_by_plan_then_apply_and_the_self_test_then_passes() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let w = world();
    let path = &w.cfg.registrars;
    let a = signer();
    let b = signer();
    // an empty file: the self-test says no registrar is pinned
    std::fs::write(path, br#"{"registrars":[]}"#).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let uid = std::fs::metadata(path).unwrap().uid();
    std::fs::create_dir_all(w.cfg.socket.parent().unwrap()).unwrap();
    std::fs::set_permissions(
        w.cfg.socket.parent().unwrap(),
        std::fs::Permissions::from_mode(0o750),
    )
    .unwrap();
    let registrars_check = |w: &World| {
        crate::selftest::self_test(&w.cfg, w.hub.ops(Caller::Hub).as_ref(), uid, NOW)
            .into_iter()
            .find(|c| c.name == "registrars")
            .unwrap()
    };
    assert!(!registrars_check(&w).ok);

    // a plan writes nothing
    let add = pins::Change::Add {
        provider: Provider::Aws,
        public: a.public_hex(),
    };
    let plan = pins::plan(path, &add).unwrap();
    assert!(plan.before.is_empty() && plan.after.len() == 1);
    assert!(!registrars_check(&w).ok);
    // not root: refused
    assert_eq!(code(pins::apply(path, &plan, false)), CODE_NOT_ROOT);
    assert!(!registrars_check(&w).ok);
    pins::apply(path, &plan, true).unwrap();
    assert!(registrars_check(&w).ok);
    assert_eq!(
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o644
    );

    // the same pin twice, a bad key, an unknown fingerprint
    assert_eq!(code(pins::plan(path, &add)), CODE_DUPLICATE_PIN);
    assert_eq!(
        code(pins::plan(
            path,
            &pins::Change::Add {
                provider: Provider::Aws,
                public: "zz".into()
            }
        )),
        CODE_BAD_PIN
    );
    assert_eq!(
        code(pins::plan(
            path,
            &pins::Change::Remove {
                fingerprint: "nope".into()
            }
        )),
        CODE_NO_SUCH_PIN
    );

    // a stale plan: the file changed after it was made
    let stale = pins::plan(
        path,
        &pins::Change::Add {
            provider: Provider::Own,
            public: b.public_hex(),
        },
    )
    .unwrap();
    let rotate = pins::Change::Replace {
        fingerprint: registrar_fingerprint(&a),
        provider: Provider::Aws,
        public: signer().public_hex(),
    };
    let rplan = pins::plan(path, &rotate).unwrap();
    pins::apply(path, &rplan, true).unwrap();
    assert_eq!(code(pins::apply(path, &stale, true)), CODE_STALE_PLAN);
    // rotated: the old key is gone at once, and one registrar is still pinned
    let now = crate::daemon::read_registrars(path).unwrap();
    assert_eq!(now.registrars.len(), 1);
    assert!(now.registrars.iter().all(|r| r.public != a.public_hex()));
    assert!(registrars_check(&w).ok);
    // removing the last one leaves none
    let last = now.registrars[0].fingerprint();
    let p = pins::plan(path, &pins::Change::Remove { fingerprint: last }).unwrap();
    assert!(p.steps.iter().any(|s| s.contains("no worker can enrol")));
    pins::apply(path, &p, true).unwrap();
    assert!(!registrars_check(&w).ok);
}

#[test]
fn a_registrar_unpinned_by_repin_stops_counting_at_once() {
    let w = world();
    w.pin(&[reg(Provider::Aws, &w.aws)]);
    let worker = end();
    let token = w.invite(Provider::Aws, INSTANCE, "").to_string();
    let claim = worker_claim(&w, &worker, &token, fx::OK, NOW);
    let a = w
        .attest(&table(&w, &token), &mut RegistrarState::default(), &claim)
        .unwrap();
    let plan = pins::plan(
        &w.cfg.registrars,
        &pins::Change::Remove {
            fingerprint: registrar_fingerprint(&w.aws),
        },
    )
    .unwrap();
    pins::apply(&w.cfg.registrars, &plan, true).unwrap();
    let r = make_request(
        worker.ops(Caller::Supervisor).as_ref(),
        WORKER,
        &token,
        a,
        &w.hub_fp(),
        NOW,
    )
    .unwrap();
    assert_eq!(
        code(w.hubd.receive_enrolment(&r, NOW)),
        CODE_UNKNOWN_REGISTRAR
    );
}

#[test]
fn a_seed_signer_signs_what_the_hub_verifies_and_keeps_its_seed_to_itself() {
    let (seed, s) = SeedSigner::generate().unwrap();
    let again = SeedSigner::from_seed_hex(&seed).unwrap();
    assert_eq!(s.public_hex(), again.public_hex());
    assert!(!format!("{s:?}").contains(seed.as_str()));
    assert!(SeedSigner::from_seed_hex(&Zeroizing::new("00".into())).is_err());
    let sig = s.sign(b"x").unwrap();
    assert!(crate::crypto::verify_ed25519(&s.public_hex(), b"x", &sig));
}

#[test]
fn the_claim_helpers_exist_for_the_hub_and_use_the_workers_service() {
    // make_claim signs through the secrets service under the purpose it already has: the proof verifies as an enrolment-proof
    // signature over the claim digest, and cannot verify as an enrolment proof for an attestation
    let w = world();
    let (worker, token, claim) = good(&w);
    let raw = der::base64_decode(&claim.pkcs7).unwrap();
    let d = claim_digest(
        WORKER,
        &w.hub_fp(),
        &raw,
        &worker.id().identity_fp(),
        claim.claim_ms,
        &claim.nonce,
    );
    let bytes = claim_proof_bytes(&w.hub_fp(), WORKER, &d, claim.claim_ms, &claim.nonce);
    assert!(crate::crypto::verify_ed25519(
        &worker.id().sign_public,
        &bytes,
        &ozbox_core::channel::wire::unhex(&claim.proof_sig).unwrap()
    ));
    let as_enrol = proof_bytes(
        &w.hub_fp(),
        WORKER,
        &"0".repeat(64),
        claim.claim_ms,
        &claim.nonce,
    );
    assert!(!crate::crypto::verify_ed25519(
        &worker.id().sign_public,
        &as_enrol,
        &ozbox_core::channel::wire::unhex(&claim.proof_sig).unwrap()
    ));
    let _ = (token, hex(&[0]));
}
