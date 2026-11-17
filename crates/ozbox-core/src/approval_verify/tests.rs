use super::*;
use crate::approval_subject::to_hex;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, Ed25519KeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

/// A real signing key of any of the four types, for tests that must be checked cryptographically.
pub(crate) enum Signer {
    Ed(Ed25519KeyPair),
    P256(EcdsaKeyPair),
}

impl Signer {
    pub(crate) fn new(t: KeyType) -> Signer {
        let rng = SystemRandom::new();
        match t {
            KeyType::Ed25519 | KeyType::SkEd25519 => {
                let pk = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
                Signer::Ed(Ed25519KeyPair::from_pkcs8(pk.as_ref()).unwrap())
            }
            KeyType::EcdsaSk | KeyType::WebauthnP256 => {
                let pk =
                    EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
                Signer::P256(
                    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pk.as_ref(), &rng)
                        .unwrap(),
                )
            }
        }
    }

    pub(crate) fn public_hex(&self) -> String {
        match self {
            Signer::Ed(k) => to_hex(k.public_key().as_ref()),
            Signer::P256(k) => to_hex(k.public_key().as_ref()),
        }
    }

    pub(crate) fn sign(&self, payload: &[u8]) -> Vec<u8> {
        match self {
            Signer::Ed(k) => k.sign(payload).as_ref().to_vec(),
            Signer::P256(k) => k
                .sign(&SystemRandom::new(), payload)
                .unwrap()
                .as_ref()
                .to_vec(),
        }
    }
}

pub(crate) fn key_for(id: &str, t: KeyType, s: &Signer, proved: bool) -> KeyView {
    KeyView {
        id: id.into(),
        key_type: t,
        presence_proved: proved,
        attestation_digest: proved.then(|| "7".repeat(64)),
        public_half: s.public_hex(),
        active: true,
        application: None,
        rp: (t == KeyType::WebauthnP256).then(test_rp),
    }
}

/// The relying party the test assertions are for.
pub(crate) fn test_rp() -> ExpectedRp {
    ExpectedRp {
        rp_id: "x.test".into(),
        origin: "https://x.test".into(),
    }
}

pub(crate) fn test_ids() -> Ids {
    Ids {
        box_id: "box-1".into(),
        store_id: "store-1".into(),
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

/// WebAuthn authenticator data: a made-up rpIdHash, the flags and a counter.
pub(crate) fn auth_data(flags: u8, counter: u32) -> Vec<u8> {
    let mut ad = sha(test_rp().rp_id.as_bytes());
    ad.push(flags);
    ad.extend_from_slice(&counter.to_be_bytes());
    ad
}

pub(crate) fn client_data(challenge: &[u8; 32]) -> Vec<u8> {
    format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://x.test"}}"#,
        b64url(challenge)
    )
    .into_bytes()
}

/// A passkey's evidence, as the dashboard would send it (the signature is the supervisor's to check).
pub(crate) fn passkey_evidence(
    cred: &str,
    sig: &str,
    flags: u8,
    counter: u32,
    challenge: &[u8; 32],
) -> PasskeyEvidence {
    PasskeyEvidence {
        credential_id: cred.into(),
        authenticator_data: to_hex(&auth_data(flags, counter)),
        client_data: to_hex(&client_data(challenge)),
        signature: sig.into(),
    }
}

/// What a laptop would send to decide `request` with outcome `outcome`: a real signature in the key type's own format.
#[allow(clippy::too_many_arguments)]
pub(crate) fn laptop_evidence(
    key: &KeyView,
    s: &Signer,
    ids: &Ids,
    request: &str,
    digest: &[u8; 32],
    outcome: &str,
    flags: u8,
    counter: u32,
) -> LaptopEvidence {
    let want = Expected::new(ids, request, digest, outcome);
    let (format, signed_message, authenticator_data, signature) = match key.key_type {
        KeyType::Ed25519 => (
            SignatureFormat::Ed25519Message,
            want.message().as_bytes().to_vec(),
            None,
            s.sign(want.message().as_bytes()),
        ),
        KeyType::SkEd25519 | KeyType::EcdsaSk => {
            let mut ad = vec![flags];
            ad.extend_from_slice(&counter.to_be_bytes());
            let mut payload = sha(SSH_SK_APPLICATION.as_bytes());
            payload.extend_from_slice(&ad);
            payload.extend_from_slice(&sha(want.message().as_bytes()));
            (
                SignatureFormat::SshSk,
                want.message().as_bytes().to_vec(),
                Some(to_hex(&ad)),
                s.sign(&payload),
            )
        }
        KeyType::WebauthnP256 => {
            let ad = auth_data(flags, counter);
            let cd = client_data(want.challenge());
            let mut payload = ad.clone();
            payload.extend_from_slice(&sha(&cd));
            (
                SignatureFormat::WebauthnAssertion,
                cd,
                Some(to_hex(&ad)),
                s.sign(&payload),
            )
        }
    };
    LaptopEvidence {
        key_id: key.id.clone(),
        key_type: key.key_type,
        signature_format: format,
        signed_message: to_hex(&signed_message),
        signature: to_hex(&signature),
        authenticator_data,
        attestation_digest: key.attestation_digest.clone(),
    }
}

const TYPES: [KeyType; 4] = [
    KeyType::Ed25519,
    KeyType::SkEd25519,
    KeyType::EcdsaSk,
    KeyType::WebauthnP256,
];

fn digest7() -> [u8; 32] {
    [7u8; 32]
}

#[test]
fn every_key_type_verifies_and_the_flags_and_counter_come_from_the_signed_bytes() {
    for t in TYPES {
        let s = Signer::new(t);
        let k = key_for("k", t, &s, t.is_fido2());
        let want = Expected::new(&test_ids(), "REQ1", &digest7(), "approve");
        let e = laptop_evidence(
            &k,
            &s,
            &test_ids(),
            "REQ1",
            &digest7(),
            "approve",
            FLAG_UP | FLAG_UV,
            41,
        );
        let v = verify_laptop(&k, &e, &want).unwrap_or_else(|x| panic!("{t:?}: {x}"));
        if t.is_fido2() {
            assert!(v.up() && v.uv(), "{t:?}");
            assert_eq!(v.counter(), Some(41), "{t:?}");
        } else {
            assert!(!v.up() && !v.uv() && v.counter().is_none());
        }
        // up without uv: the flags read back as they were signed
        if t.is_fido2() {
            let e = laptop_evidence(
                &k,
                &s,
                &test_ids(),
                "REQ1",
                &digest7(),
                "approve",
                FLAG_UP,
                2,
            );
            let v = verify_laptop(&k, &e, &want).unwrap();
            assert!(v.up() && !v.uv());
            let e = laptop_evidence(&k, &s, &test_ids(), "REQ1", &digest7(), "approve", 0, 2);
            assert!(!verify_laptop(&k, &e, &want).unwrap().up());
        }
    }
}

#[test]
fn a_correct_signature_over_another_requests_message_is_refused_for_every_key_type() {
    for t in TYPES {
        let s = Signer::new(t);
        let k = key_for("k", t, &s, t.is_fido2());
        let want = Expected::new(&test_ids(), "REQ1", &digest7(), "approve");
        for (what, e) in [
            (
                "another request",
                laptop_evidence(&k, &s, &test_ids(), "REQ2", &digest7(), "approve", 5, 1),
            ),
            (
                "another digest",
                laptop_evidence(&k, &s, &test_ids(), "REQ1", &[8u8; 32], "approve", 5, 1),
            ),
            (
                "another outcome",
                laptop_evidence(&k, &s, &test_ids(), "REQ1", &digest7(), "deny", 5, 1),
            ),
            (
                "another box",
                laptop_evidence(
                    &k,
                    &s,
                    &Ids {
                        box_id: "box-2".into(),
                        store_id: "store-1".into(),
                    },
                    "REQ1",
                    &digest7(),
                    "approve",
                    5,
                    1,
                ),
            ),
            (
                "another store",
                laptop_evidence(
                    &k,
                    &s,
                    &Ids {
                        box_id: "box-1".into(),
                        store_id: "store-2".into(),
                    },
                    "REQ1",
                    &digest7(),
                    "approve",
                    5,
                    1,
                ),
            ),
        ] {
            assert!(verify_laptop(&k, &e, &want).is_err(), "{t:?} {what}");
        }
    }
}

#[test]
fn a_flag_the_signature_did_not_cover_is_not_believed() {
    // UP = 0 in the signed authenticator data, and the caller rewrites the data to say UP = 1: the signature fails
    for t in [KeyType::SkEd25519, KeyType::EcdsaSk, KeyType::WebauthnP256] {
        let s = Signer::new(t);
        let k = key_for("k", t, &s, true);
        let want = Expected::new(&test_ids(), "REQ1", &digest7(), "approve");
        let mut e = laptop_evidence(&k, &s, &test_ids(), "REQ1", &digest7(), "approve", 0, 9);
        assert!(!verify_laptop(&k, &e, &want).unwrap().up());
        let forged = if t == KeyType::WebauthnP256 {
            to_hex(&auth_data(FLAG_UP | FLAG_UV, 9))
        } else {
            to_hex(&[FLAG_UP | FLAG_UV, 0, 0, 0, 9])
        };
        e.authenticator_data = Some(forged);
        assert!(
            verify_laptop(&k, &e, &want).is_err(),
            "{t:?}: a forged UP/UV flag"
        );
        // and a forged counter
        let mut e = laptop_evidence(
            &k,
            &s,
            &test_ids(),
            "REQ1",
            &digest7(),
            "approve",
            FLAG_UP,
            9,
        );
        let fc = if t == KeyType::WebauthnP256 {
            to_hex(&auth_data(FLAG_UP, 10))
        } else {
            to_hex(&[FLAG_UP, 0, 0, 0, 10])
        };
        e.authenticator_data = Some(fc);
        assert!(
            verify_laptop(&k, &e, &want).is_err(),
            "{t:?}: a forged counter"
        );
    }
}

#[test]
fn another_key_a_wrong_format_and_garbage_are_refused() {
    let s = Signer::new(KeyType::Ed25519);
    let other = Signer::new(KeyType::Ed25519);
    let want = Expected::new(&test_ids(), "REQ1", &digest7(), "approve");
    let k = key_for("k", KeyType::Ed25519, &s, false);
    let e = laptop_evidence(&k, &other, &test_ids(), "REQ1", &digest7(), "approve", 0, 0);
    assert!(
        verify_laptop(&k, &e, &want).is_err(),
        "signed by another key"
    );
    // a format that does not belong to the type
    let mut e = laptop_evidence(&k, &s, &test_ids(), "REQ1", &digest7(), "approve", 0, 0);
    e.signature_format = SignatureFormat::WebauthnAssertion;
    assert!(verify_laptop(&k, &e, &want).unwrap_err().contains("format"));
    // an ECDSA key's record that is not a point, and a non-hex signature
    let mut bad = k.clone();
    bad.public_half = "zz".into();
    let e = laptop_evidence(&k, &s, &test_ids(), "REQ1", &digest7(), "approve", 0, 0);
    assert!(verify_laptop(&bad, &e, &want).is_err());
    let mut e2 = e.clone();
    e2.signature = "not hex".into();
    assert!(verify_laptop(&k, &e2, &want).is_err());
    e2.signature = String::new();
    assert!(verify_laptop(&k, &e2, &want).is_err());
    // a webauthn assertion whose client data is a creation, not a sign-in
    let ws = Signer::new(KeyType::WebauthnP256);
    let wk = key_for("w", KeyType::WebauthnP256, &ws, false);
    let mut e = laptop_evidence(
        &wk,
        &ws,
        &test_ids(),
        "REQ1",
        &digest7(),
        "approve",
        FLAG_UP,
        1,
    );
    let cd = String::from_utf8(from_hex(&e.signed_message).unwrap())
        .unwrap()
        .replace("webauthn.get", "webauthn.create");
    e.signed_message = to_hex(cd.as_bytes());
    assert!(verify_laptop(&wk, &e, &want).is_err());
}

#[test]
fn a_passkeys_challenge_flags_and_counter_are_read_from_its_bytes() {
    let ch = *Expected::new(&test_ids(), "REQ1", &digest7(), "approve").challenge();
    let p = passkey_evidence("c", "s", FLAG_UP | FLAG_UV, 12, &ch);
    let v = verify_passkey_bytes(&p, &ch, &test_rp()).unwrap();
    assert!(v.up() && v.uv());
    assert_eq!(v.counter(), 12);
    // another request's challenge, another outcome's, no touch, and short data are refused
    let other = *Expected::new(&test_ids(), "REQ2", &digest7(), "approve").challenge();
    assert!(verify_passkey_bytes(&p, &other, &test_rp()).is_err());
    let deny = *Expected::new(&test_ids(), "REQ1", &digest7(), "deny").challenge();
    assert!(
        verify_passkey_bytes(&p, &deny, &test_rp()).is_err(),
        "a deny assertion is not an approve assertion"
    );
    assert!(
        verify_passkey_bytes(&passkey_evidence("c", "s", 0, 1, &ch), &ch, &test_rp())
            .unwrap_err()
            .contains("touch")
    );
    let mut short = p.clone();
    short.authenticator_data = "aabb".into();
    assert!(verify_passkey_bytes(&short, &ch, &test_rp()).is_err());
}

#[test]
fn base64url_decodes_what_a_client_data_challenge_is() {
    assert_eq!(base64url_decode("AAEC").unwrap(), vec![0, 1, 2]);
    assert_eq!(base64url_decode("-_8").unwrap(), vec![0xfb, 0xff]);
    assert!(
        base64url_decode("a+b").is_none(),
        "standard base64 is not the url alphabet"
    );
    assert!(base64url_decode("ab=").is_none(), "no padding");
}

/// The same ECDSA signature rewritten as `(r, n - s)`: it verifies as well as the original does (ECDSA is malleable).
pub(crate) fn malleate_ecdsa_der(sig_hex: &str) -> String {
    // P-256's group order
    const N: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];
    let der = from_hex(sig_hex).unwrap();
    // 30 len 02 rl r 02 sl s
    assert_eq!(der[0], 0x30);
    let mut i = 2;
    assert_eq!(der[i], 0x02);
    let rl = der[i + 1] as usize;
    let r = der[i + 2..i + 2 + rl].to_vec();
    i += 2 + rl;
    assert_eq!(der[i], 0x02);
    let sl = der[i + 1] as usize;
    let s_raw = &der[i + 2..i + 2 + sl];
    let mut s32 = [0u8; 32];
    let s_trim: Vec<u8> = s_raw.iter().copied().skip_while(|b| *b == 0).collect();
    s32[32 - s_trim.len()..].copy_from_slice(&s_trim);
    // n - s
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for k in (0..32).rev() {
        let d = i16::from(N[k]) - i16::from(s32[k]) - borrow;
        if d < 0 {
            out[k] = (d + 256) as u8;
            borrow = 1;
        } else {
            out[k] = d as u8;
            borrow = 0;
        }
    }
    let mut s_enc: Vec<u8> = out.iter().copied().skip_while(|b| *b == 0).collect();
    if s_enc[0] & 0x80 != 0 {
        s_enc.insert(0, 0);
    }
    let mut body = vec![0x02, r.len() as u8];
    body.extend_from_slice(&r);
    body.push(0x02);
    body.push(s_enc.len() as u8);
    body.extend_from_slice(&s_enc);
    let mut full = vec![0x30, body.len() as u8];
    full.extend_from_slice(&body);
    to_hex(&full)
}

#[test]
fn a_webauthn_assertion_must_be_for_the_relying_party_on_record() {
    use crate::approval::PasskeyEvidence;
    let ch = [3u8; 32];
    let good = passkey_evidence("c", "s", 1, 5, &ch);
    assert!(verify_passkey_bytes(&good, &ch, &test_rp()).is_ok());
    // another rp id: the hash in the authenticator data is for x.test
    let other_id = ExpectedRp {
        rp_id: "evil.test".into(),
        origin: "https://x.test".into(),
    };
    assert!(verify_passkey_bytes(&good, &ch, &other_id)
        .unwrap_err()
        .contains("another relying party"));
    // another origin: the client data names https://x.test
    let other_origin = ExpectedRp {
        rp_id: "x.test".into(),
        origin: "https://evil.test".into(),
    };
    assert!(verify_passkey_bytes(&good, &ch, &other_origin)
        .unwrap_err()
        .contains("another origin"));
    // a cross-origin frame
    let mut cd = String::from_utf8(client_data(&ch)).unwrap();
    cd.pop();
    cd.push_str(r#","crossOrigin":true}"#);
    let framed = PasskeyEvidence {
        client_data: to_hex(cd.as_bytes()),
        ..good.clone()
    };
    assert!(verify_passkey_bytes(&framed, &ch, &test_rp())
        .unwrap_err()
        .contains("cross-origin"));
    // no relying party known is no decision
    let none = ExpectedRp {
        rp_id: String::new(),
        origin: String::new(),
    };
    assert!(verify_passkey_bytes(&good, &ch, &none).is_err());
}

#[test]
fn a_webauthn_laptop_key_is_held_to_the_relying_party_recorded_at_enrolment() {
    let s = Signer::new(KeyType::WebauthnP256);
    let mut k = key_for("w", KeyType::WebauthnP256, &s, true);
    let want = Expected::new(&test_ids(), "REQ1", &digest7(), "approve");
    let e = laptop_evidence(
        &k,
        &s,
        &test_ids(),
        "REQ1",
        &digest7(),
        "approve",
        FLAG_UP,
        1,
    );
    assert!(verify_laptop(&k, &e, &want).is_ok());
    // a key with no relying party on record decides nothing
    k.rp = None;
    assert!(verify_laptop(&k, &e, &want)
        .unwrap_err()
        .contains("no relying party"));
    // a key recorded for another origin refuses the assertion the same signature carried
    k.rp = Some(ExpectedRp {
        rp_id: "x.test".into(),
        origin: "https://other.test".into(),
    });
    assert!(verify_laptop(&k, &e, &want)
        .unwrap_err()
        .contains("another origin"));
}

#[test]
fn an_sk_key_made_with_another_application_signs_over_that_one() {
    let s = Signer::new(KeyType::SkEd25519);
    let mut k = key_for("k", KeyType::SkEd25519, &s, true);
    let want = Expected::new(&test_ids(), "REQ1", &digest7(), "approve");
    // the test signer hashes `ssh:`; a record that says `ssh:work` must not verify it
    let e = laptop_evidence(
        &k,
        &s,
        &test_ids(),
        "REQ1",
        &digest7(),
        "approve",
        FLAG_UP,
        1,
    );
    assert!(verify_laptop(&k, &e, &want).is_ok());
    k.application = Some("ssh:work".into());
    assert!(verify_laptop(&k, &e, &want).is_err());
}

// ---- vectors made by real tools ------------------------------------------------------------------------------
//
// `testdata/real_tool_vectors.json` holds signatures that OpenSSH's own `ssh-agent` (through `ssh-sk-helper` and its
// `sk-dummy` provider, a software stand-in for a token) and Google Chrome (its CDP virtual authenticator) made. None is made
// by the code that checks it. How they were made, and what they are not (no physical token), is in
// `testdata/real_tool_vectors.txt` and the scripts beside it.

fn vectors() -> serde_json::Value {
    serde_json::from_str(include_str!("../../testdata/real_tool_vectors.json")).unwrap()
}

fn s<'a>(v: &'a serde_json::Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or_else(|| panic!("no {k}"))
}

#[test]
fn signatures_made_by_openssh_for_sk_keys_verify_in_the_layout_the_verifier_checks() {
    let v = vectors();
    let mut n = 0;
    for (group, t) in [
        ("ssh_sk_ed25519", KeyType::SkEd25519),
        ("ssh_ecdsa_sk", KeyType::EcdsaSk),
    ] {
        for e in v[group].as_array().unwrap() {
            let blob = from_hex(s(e, "agent_signature_blob")).unwrap();
            let parsed = parse_agent_sk_signature(t, &blob).unwrap();
            assert_eq!(u64::from(parsed.flags), e["flags"].as_u64().unwrap());
            assert_eq!(u64::from(parsed.counter), e["counter"].as_u64().unwrap());
            if t == KeyType::EcdsaSk {
                assert_eq!(
                    to_hex(&parsed.sig),
                    s(e, "der_signature"),
                    "mpint r,s become the same DER"
                );
            } else {
                assert_eq!(to_hex(&parsed.sig), s(e, "raw_signature"));
            }
            let public = from_hex(s(e, "public_key_raw")).unwrap();
            let message = from_hex(s(e, "message")).unwrap();
            let app = s(e, "application");
            verify_sk_payload(
                t,
                &public,
                app,
                parsed.flags,
                parsed.counter,
                &message,
                &parsed.sig,
            )
            .unwrap_or_else(|x| panic!("{group} {}: {x}", s(e, "label")));
            // another application, message, flags or counter: refused (the key was made for `app`)
            assert!(verify_sk_payload(
                t,
                &public,
                "ssh:other",
                parsed.flags,
                parsed.counter,
                &message,
                &parsed.sig
            )
            .is_err());
            assert!(verify_sk_payload(
                t,
                &public,
                app,
                parsed.flags,
                parsed.counter,
                b"another message",
                &parsed.sig
            )
            .is_err());
            assert!(verify_sk_payload(
                t,
                &public,
                app,
                parsed.flags ^ 4,
                parsed.counter,
                &message,
                &parsed.sig
            )
            .is_err());
            assert!(verify_sk_payload(
                t,
                &public,
                app,
                parsed.flags,
                parsed.counter + 1,
                &message,
                &parsed.sig
            )
            .is_err());
            // the flags the real provider set are the ones the label says
            let label = s(e, "label");
            if label == "verify-required" {
                assert_eq!(parsed.flags & (FLAG_UP | FLAG_UV), FLAG_UP | FLAG_UV);
            } else if label == "no-touch-required" {
                assert_eq!(
                    parsed.flags & FLAG_UP,
                    0,
                    "UP is clear: the per-decision check is what catches it"
                );
            }
            n += 1;
        }
    }
    assert_eq!(n, 16);
}

#[test]
fn an_sk_vector_goes_through_verify_laptop_with_the_application_the_key_was_made_with() {
    let v = vectors();
    let e = v["ssh_sk_ed25519"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| s(e, "application") == "ssh:work")
        .unwrap();
    let parsed = parse_agent_sk_signature(
        KeyType::SkEd25519,
        &from_hex(s(e, "agent_signature_blob")).unwrap(),
    )
    .unwrap();
    // the real signature is over its own message, not a decide message; the layout check is what is under test here
    let public = from_hex(s(e, "public_key_raw")).unwrap();
    assert!(verify_sk_payload(
        KeyType::SkEd25519,
        &public,
        "ssh:work",
        parsed.flags,
        parsed.counter,
        &from_hex(s(e, "message")).unwrap(),
        &parsed.sig
    )
    .is_ok());
    assert!(verify_sk_payload(
        KeyType::SkEd25519,
        &public,
        SSH_SK_APPLICATION,
        parsed.flags,
        parsed.counter,
        &from_hex(s(e, "message")).unwrap(),
        &parsed.sig
    )
    .is_err());
}

#[test]
fn a_malformed_agent_signature_is_refused() {
    let v = vectors();
    let e = &v["ssh_ecdsa_sk"][0];
    let blob = from_hex(s(e, "agent_signature_blob")).unwrap();
    for cut in [0, 4, 20, 50, blob.len() - 1] {
        assert!(
            parse_agent_sk_signature(KeyType::EcdsaSk, &blob[..cut]).is_err(),
            "{cut}"
        );
    }
    // the right bytes for the other key type are not accepted
    assert!(parse_agent_sk_signature(KeyType::SkEd25519, &blob).is_err());
    let mut extra = blob.clone();
    extra.push(0);
    assert!(parse_agent_sk_signature(KeyType::EcdsaSk, &extra).is_err());
}

#[test]
fn assertions_made_by_chrome_verify_and_are_held_to_their_relying_party_and_challenge() {
    let v = vectors();
    let mut n = 0;
    for e in v["webauthn_assertion"].as_array().unwrap() {
        let mut public = vec![4u8];
        public.extend(from_hex(s(e, "public_key_x")).unwrap());
        public.extend(from_hex(s(e, "public_key_y")).unwrap());
        let rp = ExpectedRp {
            rp_id: s(e, "rpId").into(),
            origin: s(e, "origin").into(),
        };
        let mut ch = [0u8; 32];
        ch.copy_from_slice(&from_hex(s(e, "challenge")).unwrap());
        let ad = from_hex(s(e, "authenticatorData")).unwrap();
        let cd = from_hex(s(e, "clientDataJSON_hex")).unwrap();
        let sig = from_hex(s(e, "signature")).unwrap();
        let (flags, counter) =
            verify_webauthn_assertion(&public, &rp, &ch, &ad, &cd, &sig).unwrap();
        assert_eq!(u64::from(flags), e["flags"].as_u64().unwrap());
        assert_eq!(u64::from(counter), e["counter"].as_u64().unwrap());
        // this relying party and no other, this challenge and no other
        let other = ExpectedRp {
            rp_id: "evil.test".into(),
            ..rp.clone()
        };
        assert!(
            verify_webauthn_assertion(&public, &other, &ch, &ad, &cd, &sig)
                .unwrap_err()
                .contains("relying party")
        );
        let other = ExpectedRp {
            origin: "http://localhost:1".into(),
            ..rp.clone()
        };
        assert!(
            verify_webauthn_assertion(&public, &other, &ch, &ad, &cd, &sig)
                .unwrap_err()
                .contains("origin")
        );
        assert!(verify_webauthn_assertion(&public, &rp, &[0u8; 32], &ad, &cd, &sig).is_err());
        // the malleated signature still verifies (so the seen-set must not be keyed by it, N5)
        let mal = from_hex(&malleate_ecdsa_der(s(e, "signature"))).unwrap();
        assert!(verify_webauthn_assertion(&public, &rp, &ch, &ad, &cd, &mal).is_ok());
        n += 1;
    }
    assert_eq!(n, 8);
}
