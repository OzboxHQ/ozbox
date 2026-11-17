use super::fixtures::*;
use super::*;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

/// 2026-11-13: after the fixtures' certificates were made, long before they end.
const NOW: i64 = 1_794_528_000;

fn unhex(s: &str) -> Vec<u8> {
    ozbox_core::approval_subject::from_hex(s).unwrap()
}

// ---- a tiny CBOR writer for the tests --------------------------------------------------------------------------------

fn head(major: u8, n: usize, out: &mut Vec<u8>) {
    let m = major << 5;
    if n < 24 {
        out.push(m | n as u8);
    } else if n < 256 {
        out.extend_from_slice(&[m | 24, n as u8]);
    } else {
        out.extend_from_slice(&[m | 25, (n >> 8) as u8, n as u8]);
    }
}
fn bytes(b: &[u8], out: &mut Vec<u8>) {
    head(2, b.len(), out);
    out.extend_from_slice(b);
}
fn text(t: &str, out: &mut Vec<u8>) {
    head(3, t.len(), out);
    out.extend_from_slice(t.as_bytes());
}
fn int(i: i64, out: &mut Vec<u8>) {
    if i >= 0 {
        head(0, i as usize, out);
    } else {
        head(1, (-1 - i) as usize, out);
    }
}

/// A credential key and the authenticator data that announces it.
struct Cred {
    public: Vec<u8>,
    auth_data: Vec<u8>,
    /// The credential's private key, so a test can make assertions with it.
    key: EcdsaKeyPair,
}

fn credential(rp_id_hash: &[u8], flags: u8) -> Cred {
    let rng = SystemRandom::new();
    let pk = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pk.as_ref(), &rng).unwrap();
    let public = kp.public_key().as_ref().to_vec();
    let mut cose = Vec::new();
    head(5, 5, &mut cose);
    int(1, &mut cose);
    int(2, &mut cose);
    int(3, &mut cose);
    int(-7, &mut cose);
    int(-1, &mut cose);
    int(1, &mut cose);
    int(-2, &mut cose);
    bytes(&public[1..33], &mut cose);
    int(-3, &mut cose);
    bytes(&public[33..65], &mut cose);
    let mut ad = rp_id_hash.to_vec();
    ad.push(flags);
    ad.extend_from_slice(&0u32.to_be_bytes());
    ad.extend_from_slice(&[0x5a; 16]);
    ad.extend_from_slice(&16u16.to_be_bytes());
    ad.extend_from_slice(&[0x77; 16]);
    ad.extend_from_slice(&cose);
    Cred {
        public,
        auth_data: ad,
        key: kp,
    }
}

fn leaf_sign(msg: &[u8]) -> Vec<u8> {
    let rng = SystemRandom::new();
    let kp = EcdsaKeyPair::from_pkcs8(
        &ECDSA_P256_SHA256_ASN1_SIGNING,
        &unhex(LEAF_KEY_PKCS8),
        &rng,
    )
    .unwrap();
    kp.sign(&rng, msg).unwrap().as_ref().to_vec()
}

fn client_data(challenge: &[u8; 32], origin: &str, kind: &str) -> Vec<u8> {
    format!(
        r#"{{"type":"{kind}","challenge":"{}","origin":"{origin}"}}"#,
        crate::serve::auth::b64::encode_url(challenge)
    )
    .into_bytes()
}

fn object(fmt: &str, sig: &[u8], x5c: &[Vec<u8>], auth_data: &[u8]) -> Vec<u8> {
    let mut o = Vec::new();
    head(5, 3, &mut o);
    text("fmt", &mut o);
    text(fmt, &mut o);
    text("attStmt", &mut o);
    head(5, if x5c.is_empty() { 2 } else { 3 }, &mut o);
    text("alg", &mut o);
    int(-7, &mut o);
    text("sig", &mut o);
    bytes(sig, &mut o);
    if !x5c.is_empty() {
        text("x5c", &mut o);
        head(4, x5c.len(), &mut o);
        for c in x5c {
            bytes(c, &mut o);
        }
    }
    text("authData", &mut o);
    bytes(auth_data, &mut o);
    o
}

const CHALLENGE: [u8; 32] = [9u8; 32];
const RP: &str = "box.example";
const ORIGIN: &str = "https://box.example";

struct Made {
    object: Vec<u8>,
    client: Vec<u8>,
    public_hex: String,
}

/// A WebAuthn `packed` attestation made by the synthetic token, over the given chain.
fn made(chain: &[&str]) -> Made {
    made_for(chain, &CHALLENGE).0
}

/// The same over a challenge the caller names, with the credential's key so it can sign decisions afterwards.
fn made_for(chain: &[&str], challenge: &[u8; 32]) -> (Made, EcdsaKeyPair) {
    let cred = credential(&sha(RP.as_bytes()), 0x45);
    let client = client_data(challenge, ORIGIN, "webauthn.create");
    let mut msg = cred.auth_data.clone();
    msg.extend_from_slice(&sha(&client));
    let x5c: Vec<Vec<u8>> = chain.iter().map(|c| unhex(c)).collect();
    (
        Made {
            object: object("packed", &leaf_sign(&msg), &x5c, &cred.auth_data),
            client,
            public_hex: hex(&cred.public),
        },
        cred.key,
    )
}

fn roots() -> Vec<Vec<u8>> {
    vec![unhex(ROOT_DER)]
}

fn check(m: &Made, roots: &[Vec<u8>], now: i64) -> Result<Attested, String> {
    verify(
        &Container::Webauthn {
            object: &m.object,
            client_data_json: &m.client,
            rp_id: RP,
            origin: ORIGIN,
        },
        &CHALLENGE,
        &m.public_hex,
        roots,
        now,
    )
}

// ---- the chain -------------------------------------------------------------------------------------------------------

#[test]
fn a_packed_attestation_from_a_chain_to_a_pinned_root_verifies_and_says_what_it_attested() {
    let m = made(&[LEAF_DER, INT_DER]);
    let a = check(&m, &roots(), NOW).unwrap();
    assert_eq!(a.public_half, m.public_hex);
    assert_eq!(a.aaguid, "5a".repeat(16));
    assert_eq!(a.credential_id, "77".repeat(16));
    assert_eq!(a.digest, hex(&sha(&m.object)));
    assert_eq!(a.root_sha256, hex(&sha(&unhex(ROOT_DER))));
}

#[test]
fn a_chain_through_an_rsa_root_verifies_too() {
    let m = made(&[LEAF_DER, RINT_DER]);
    assert!(check(&m, &[unhex(RROOT_DER)], NOW).is_ok());
    // and the EC root does not vouch for the intermediate the RSA root signed
    assert!(check(&m, &roots(), NOW).is_err());
}

#[test]
fn a_chain_that_does_not_reach_a_pinned_root_is_refused() {
    let m = made(&[LEAF_DER, INT_DER]);
    // no roots at all, or another root: a software key can make any chain of its own
    assert!(check(&m, &[], NOW)
        .unwrap_err()
        .contains("does not chain to a root"));
    assert!(check(&m, &[unhex(RROOT_DER)], NOW)
        .unwrap_err()
        .contains("does not chain to a root"));
    // the leaf alone, with the intermediate left out, is a chain with a gap
    let gap = made(&[LEAF_DER]);
    assert!(check(&gap, &roots(), NOW).is_err());
    // the root itself as the whole chain is allowed to be sent; a leaf that is a CA is not
    let ca = made(&[INT_DER]);
    assert!(check(&ca, &roots(), NOW).unwrap_err().contains("is a CA"));
    let not_ca = made(&[LEAF_DER, LEAF_DER]);
    assert!(check(&not_ca, &roots(), NOW)
        .unwrap_err()
        .contains("not a CA"));
}

#[test]
fn a_certificate_outside_its_dates_is_refused() {
    let short = made(&[LEAF_SHORT_DER, INT_DER]);
    assert!(
        check(&short, &roots(), NOW).is_ok(),
        "the day after it was made"
    );
    assert!(check(&short, &roots(), 1_794_787_200)
        .unwrap_err()
        .contains("not valid now"));
    // before it existed
    let m = made(&[LEAF_DER, INT_DER]);
    assert!(check(&m, &roots(), 1_794_500_000)
        .unwrap_err()
        .contains("not valid now"));
}

#[test]
fn a_changed_certificate_or_signature_is_refused() {
    let mut bad = unhex(LEAF_DER);
    // a byte inside the subject name: the issuer's signature no longer covers what is there
    let at = bad.len() / 3;
    bad[at] ^= 1;
    let m = made(&[LEAF_DER, INT_DER]);
    let tampered = Made {
        object: m.object.clone(),
        client: m.client.clone(),
        public_hex: m.public_hex.clone(),
    };
    let swapped = object("packed", &[1; 70], &[bad.clone(), unhex(INT_DER)], &{
        let (_, v) = (0, cbor::decode(&tampered.object).unwrap().0);
        v.get_text("authData")
            .and_then(Value::as_bytes)
            .unwrap()
            .to_vec()
    });
    let t = Made {
        object: swapped,
        client: m.client.clone(),
        public_hex: m.public_hex.clone(),
    };
    assert!(check(&t, &roots(), NOW).is_err());
    // the statement's own signature changed
    let (v, _) = cbor::decode(&m.object).unwrap();
    let ad = v
        .get_text("authData")
        .and_then(Value::as_bytes)
        .unwrap()
        .to_vec();
    let forged = object(
        "packed",
        &leaf_sign(b"something else"),
        &[unhex(LEAF_DER), unhex(INT_DER)],
        &ad,
    );
    let f = Made {
        object: forged,
        client: m.client.clone(),
        public_hex: m.public_hex.clone(),
    };
    assert!(check(&f, &roots(), NOW)
        .unwrap_err()
        .contains("signature is not valid"));
}

// ---- what is accepted at all -------------------------------------------------------------------------------------------

#[test]
fn none_and_self_attestation_are_refused() {
    let cred = credential(&sha(RP.as_bytes()), 0x45);
    let client = client_data(&CHALLENGE, ORIGIN, "webauthn.create");
    let none = object("none", &[], &[], &cred.auth_data);
    let m = Made {
        object: none,
        client: client.clone(),
        public_hex: hex(&cred.public),
    };
    assert!(check(&m, &roots(), NOW)
        .unwrap_err()
        .contains("not accepted"));
    // packed with no certificate is self attestation: the credential key signs for itself
    let selfie = object("packed", &[7; 70], &[], &cred.auth_data);
    let m = Made {
        object: selfie,
        client,
        public_hex: hex(&cred.public),
    };
    assert!(check(&m, &roots(), NOW)
        .unwrap_err()
        .contains("no certificate"));
    // formats other than the two
    let tpm = object("tpm", &[], &[], &cred.auth_data);
    let m = Made {
        object: tpm,
        client: client_data(&CHALLENGE, ORIGIN, "webauthn.create"),
        public_hex: hex(&cred.public),
    };
    assert!(check(&m, &roots(), NOW).is_err());
}

#[test]
fn an_attestation_is_bound_to_its_challenge_origin_relying_party_key_and_touch() {
    let m = made(&[LEAF_DER, INT_DER]);
    let ok = |container: Container<'_>, pk: &str, ch: &[u8; 32]| {
        verify(&container, ch, pk, &roots(), NOW)
    };
    let wc =
        |client: &'_ [u8], rp: &'static str, origin: &'static str| -> Result<Attested, String> {
            ok(
                Container::Webauthn {
                    object: &m.object,
                    client_data_json: client,
                    rp_id: rp,
                    origin,
                },
                &m.public_hex,
                &CHALLENGE,
            )
        };
    assert!(wc(&m.client, RP, ORIGIN).is_ok());
    // another enrolment's challenge (the service issues a fresh one each time)
    let other = ok(
        Container::Webauthn {
            object: &m.object,
            client_data_json: &m.client,
            rp_id: RP,
            origin: ORIGIN,
        },
        &m.public_hex,
        &[1u8; 32],
    );
    assert!(other.unwrap_err().contains("another enrolment"));
    assert!(wc(&m.client, RP, "https://evil.example")
        .unwrap_err()
        .contains("another origin"));
    assert!(wc(&m.client, "evil.example", ORIGIN)
        .unwrap_err()
        .contains("another relying party"));
    // a sign-in's client data is not a key being made
    let get = client_data(&CHALLENGE, ORIGIN, "webauthn.get");
    assert!(wc(&get, RP, ORIGIN).is_err());
    // a different key than the one being enrolled
    let e = ok(
        Container::Webauthn {
            object: &m.object,
            client_data_json: &m.client,
            rp_id: RP,
            origin: ORIGIN,
        },
        &"04".repeat(65),
        &CHALLENGE,
    );
    assert!(e.unwrap_err().contains("not the key being enrolled"));
    // made without a touch (UP clear)
    let cred = credential(&sha(RP.as_bytes()), 0x40);
    let client = client_data(&CHALLENGE, ORIGIN, "webauthn.create");
    let mut msg = cred.auth_data.clone();
    msg.extend_from_slice(&sha(&client));
    let o = object(
        "packed",
        &leaf_sign(&msg),
        &[unhex(LEAF_DER), unhex(INT_DER)],
        &cred.auth_data,
    );
    let nt = Made {
        object: o,
        client,
        public_hex: hex(&cred.public),
    };
    assert!(check(&nt, &roots(), NOW)
        .unwrap_err()
        .contains("without a touch"));
}

// ---- the FIDO certificate rules and the pinned-anchor policy -----------------------------------------

#[test]
fn a_packed_leaf_must_follow_the_fido_certificate_rules() {
    let anchors = roots();
    for (name, leaf, why) in [
        ("another OU", LEAF_NO_OU_DER, "Authenticator Attestation"),
        ("no basicConstraints", LEAF_NO_BC_DER, "basicConstraints"),
        (
            "no AAGUID extension",
            LEAF_NO_AAGUID_DER,
            "no AAGUID extension",
        ),
        (
            "another model's AAGUID",
            LEAF_WRONG_AAGUID_DER,
            "another authenticator model",
        ),
        (
            "a critical AAGUID extension",
            LEAF_CRIT_AAGUID_DER,
            "critical or not valid",
        ),
        (
            "a leaf that may sign certificates",
            LEAF_KEY_CERT_SIGN_DER,
            "may sign certificates",
        ),
    ] {
        let m = made(&[leaf, INT_DER]);
        let e = check(&m, &anchors, NOW).unwrap_err();
        assert!(e.contains(why), "{name}: {e}");
    }
    assert!(check(&made(&[LEAF_DER, INT_DER]), &anchors, NOW).is_ok());
}

#[test]
fn a_piv_shaped_chain_under_a_multi_purpose_root_is_refused() {
    // slot certificate, device CA, PIV intermediate, a root that also signs FIDO intermediates
    let m = made(&[PSLOT_DER, PDEV_DER, PINT_DER, PROOT_DER]);
    // the FIDO intermediate is pinned in place of the root: the PIV branch reaches nothing pinned
    let e = check(&m, &[unhex(FINT_DER)], NOW).unwrap_err();
    assert!(e.contains("does not chain to a root"), "{e}");
    // even with the multi-purpose root pinned (a root added by mistake), a PIV slot certificate is no authenticator's
    let e = check(&m, &[unhex(PROOT_DER)], NOW).unwrap_err();
    assert!(e.contains("Authenticator Attestation"), "{e}");
}

/// A WebAuthn `fido-u2f` attestation made by the synthetic token over the given chain.
fn made_u2f(chain: &[&str]) -> Made {
    let cred = credential(&sha(RP.as_bytes()), 0x45);
    let client = client_data(&CHALLENGE, ORIGIN, "webauthn.create");
    let mut msg = vec![0u8];
    msg.extend_from_slice(&sha(RP.as_bytes()));
    msg.extend_from_slice(&sha(&client));
    msg.extend_from_slice(&[0x77; 16]);
    msg.extend_from_slice(&cred.public);
    let x5c: Vec<Vec<u8>> = chain.iter().map(|c| unhex(c)).collect();
    Made {
        object: object("fido-u2f", &leaf_sign(&msg), &x5c, &cred.auth_data),
        client,
        public_hex: hex(&cred.public),
    }
}

#[test]
fn a_fido_u2f_statement_carries_exactly_one_certificate_and_a_piv_chain_in_that_layout_is_refused()
{
    // the one-certificate shape verifies (the pinned anchor signed the leaf directly)
    assert!(check(&made_u2f(&[LEAF_U2F_DER]), &[unhex(INT_DER)], NOW).is_ok());
    // a longer chain is not a `fido-u2f` statement, though it chains to a pinned root
    let e = check(&made_u2f(&[LEAF_U2F_DER, INT_DER]), &roots(), NOW).unwrap_err();
    assert!(e.contains("exactly one certificate"), "{e}");
    // a PIV slot chain in the u2f layout, under the multi-purpose root, with and without that root pinned
    let piv = made_u2f(&[PSLOT_DER, PDEV_DER, PINT_DER, PROOT_DER]);
    for pinned in [vec![unhex(FINT_DER)], vec![unhex(PROOT_DER)]] {
        let e = check(&piv, &pinned, NOW).unwrap_err();
        assert!(
            e.contains("does not chain to a root") || e.contains("exactly one certificate"),
            "{e}"
        );
    }
    // a PIV slot certificate with Yubico's PIV extension, one certificate signed directly by a pinned anchor: the u2f layout's own
    // shape rule refuses it
    let e = check(&made_u2f(&[PIV_EXT_LEAF_DER]), &[unhex(PIVROOT_DER)], NOW).unwrap_err();
    assert!(e.contains("PIV certificate"), "{e}");
    // the same slot certificate in the PACKED layout (not the u2f one), signed directly by a pinned anchor: the packed rules
    // refuse it, because it is not an Authenticator Attestation certificate
    let e = check(&made(&[PSLOT_DER]), &[unhex(PDEV_DER)], NOW).unwrap_err();
    assert!(e.contains("Authenticator Attestation"), "{e}");
}

#[test]
fn a_ca_below_a_path_length_zero_intermediate_is_refused_whatever_anchors_it() {
    // full FIDO leaf under a device CA under the FIDO intermediate (path length 0)
    let m = made(&[FLEAF_DER, FDEV_DER, FINT_DER]);
    let e = check(&m, &[unhex(PROOT_DER)], NOW).unwrap_err();
    assert!(e.contains("path length"), "{e}");
    // the intermediate itself as the pinned anchor: the device CA is one CA below it
    let m = made(&[FLEAF_DER, FDEV_DER]);
    let e = check(&m, &[unhex(FINT_DER)], NOW).unwrap_err();
    assert!(e.contains("path length"), "{e}");
}

#[test]
fn a_u2f_style_leaf_needs_no_ou_or_aaguid_but_is_still_no_ca() {
    let (b, pk) = blob_with(LEAF_U2F_DER, "ssh:", true);
    let pinned = vec![unhex(INT_DER)];
    assert!(verify(
        &Container::OpenSsh {
            blob: &b,
            application: "ssh:"
        },
        &CHALLENGE,
        &pk,
        &pinned,
        NOW
    )
    .is_ok());
    // the same leaf in the `packed` layout is held to the packed rules
    let (b, pk) = blob_with(LEAF_U2F_DER, "ssh:", false);
    let e = verify(
        &Container::OpenSsh {
            blob: &b,
            application: "ssh:",
        },
        &CHALLENGE,
        &pk,
        &pinned,
        NOW,
    )
    .unwrap_err();
    assert!(e.contains("Authenticator Attestation"), "{e}");
}

// ---- the OpenSSH blob ---------------------------------------------------------------------------------------------------

fn ssh_string_put(b: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

/// An `ssh-sk-attest-v01` blob as OpenSSH writes it, for a key made with `-O challenge=` and the given application.
fn blob(application: &str, u2f_style: bool, cbor_wrapped: bool) -> (Vec<u8>, String) {
    blob_of(LEAF_DER, application, u2f_style, cbor_wrapped)
}

fn blob_with(leaf: &str, application: &str, u2f_style: bool) -> (Vec<u8>, String) {
    blob_of(leaf, application, u2f_style, false)
}

fn blob_of(
    leaf: &str,
    application: &str,
    u2f_style: bool,
    cbor_wrapped: bool,
) -> (Vec<u8>, String) {
    let cred = credential(&sha(application.as_bytes()), 0x41);
    let cdh = sha(&CHALLENGE);
    let msg = if u2f_style {
        let mut m = vec![0u8];
        m.extend_from_slice(&sha(application.as_bytes()));
        m.extend_from_slice(&cdh);
        m.extend_from_slice(&[0x77; 16]);
        m.extend_from_slice(&cred.public);
        m
    } else {
        let mut m = cred.auth_data.clone();
        m.extend_from_slice(&cdh);
        m
    };
    let mut ad = cred.auth_data.clone();
    if cbor_wrapped {
        let mut w = Vec::new();
        bytes(&cred.auth_data, &mut w);
        ad = w;
    }
    let mut b = Vec::new();
    ssh_string_put(b"ssh-sk-attest-v01", &mut b);
    ssh_string_put(&unhex(leaf), &mut b);
    ssh_string_put(&leaf_sign(&msg), &mut b);
    ssh_string_put(&ad, &mut b);
    b.extend_from_slice(&0u32.to_be_bytes());
    ssh_string_put(b"", &mut b);
    (b, hex(&cred.public))
}

#[test]
fn an_openssh_attestation_blob_verifies_in_both_signature_styles_and_for_its_application() {
    // the synthetic token's own certificate is signed by the intermediate: the blob carries only the leaf, so the root
    // this test pins is the intermediate (a vendor whose attestation certificate is signed by its root directly)
    let pinned = vec![unhex(INT_DER)];
    for (u2f, wrapped) in [(false, false), (true, false), (false, true)] {
        let (b, pk) = blob("ssh:", u2f, wrapped);
        let a = verify(
            &Container::OpenSsh {
                blob: &b,
                application: "ssh:",
            },
            &CHALLENGE,
            &pk,
            &pinned,
            NOW,
        )
        .unwrap_or_else(|e| panic!("u2f={u2f} wrapped={wrapped}: {e}"));
        assert_eq!(a.public_half, pk);
        // the application is the relying party: a key made for another one is not this enrolment
        let e = verify(
            &Container::OpenSsh {
                blob: &b,
                application: "ssh:work",
            },
            &CHALLENGE,
            &pk,
            &pinned,
            NOW,
        );
        assert!(e
            .unwrap_err()
            .contains("another relying party or application"));
        // and a challenge other than the one the box issued
        let e = verify(
            &Container::OpenSsh {
                blob: &b,
                application: "ssh:",
            },
            &[0u8; 32],
            &pk,
            &pinned,
            NOW,
        );
        assert!(e.is_err());
    }
    let (b, pk) = blob("ssh:work", false, false);
    assert!(verify(
        &Container::OpenSsh {
            blob: &b,
            application: "ssh:work"
        },
        &CHALLENGE,
        &pk,
        &pinned,
        NOW
    )
    .is_ok());
}

#[test]
fn a_damaged_or_foreign_blob_is_refused_without_a_panic() {
    let pinned = vec![unhex(INT_DER)];
    let (b, pk) = blob("ssh:", false, false);
    // (the trailing flags and reserved string are not read, so the cuts stay inside what is)
    for cut in [0, 3, 10, 30, 100, b.len() - 10] {
        assert!(verify(
            &Container::OpenSsh {
                blob: &b[..cut],
                application: "ssh:"
            },
            &CHALLENGE,
            &pk,
            &pinned,
            NOW
        )
        .is_err());
    }
    let mut wrong = b.clone();
    wrong[8] ^= 0xff;
    assert!(verify(
        &Container::OpenSsh {
            blob: &wrong,
            application: "ssh:"
        },
        &CHALLENGE,
        &pk,
        &pinned,
        NOW
    )
    .is_err());
    let huge = vec![0u8; MAX_BLOB + 1];
    assert!(verify(
        &Container::OpenSsh {
            blob: &huge,
            application: "ssh:"
        },
        &CHALLENGE,
        &pk,
        &pinned,
        NOW
    )
    .is_err());
}

// ---- the shipped roots ---------------------------------------------------------------------------------------------------

#[test]
fn the_pinned_anchors_are_the_fido_roots_and_fido_intermediates_and_no_multi_purpose_root() {
    let anchors = pinned_roots();
    // Yubico's U2F root and FIDO root, then the FIDO attestation intermediates A 1, B 1 and B2 1 (SHA-256 of the DER)
    let want = [
        "0fa1386f80eb8713263ae5c1d84deb455bdf08aea50ab05503cefee82b092d42",
        "35f1a54b353bfb711e6d42adbeb76c0e9dead095018e6a94783ba2192fd6faad",
        "4ebabc9cbc964f722c985f3784d057e9ef5dcf454dcb4f767fccca58cf16a4e8",
        "4eadda86ff62cff987e111a07910d8554de42f71d5d6da7744610e09012dd319",
        "3c6fe819adbd80afe75dc90af7bba34c95b2b7ac64384816e033f63b7c93848b",
    ];
    let got: Vec<String> = anchors.iter().map(|a| hex(&sha(a))).collect();
    assert_eq!(got, want);
    // "Yubico Attestation Root 1" signs PIV, OpenPGP, secure-domain and HSM intermediates too: it is not an anchor
    assert!(
        !got.iter()
            .any(|g| g == "62760c6a6ef91679f454c8902b80fd009825b3f25da90f1fbace2ec6586cd5a8"),
        "the multi-purpose root is not pinned"
    );
    for a in &anchors {
        let c = parse_cert(a).unwrap();
        assert_eq!(c.ca, Some(true));
        assert_eq!(
            c.path_len,
            Some(0),
            "every anchor is FIDO-only and signs no other CA"
        );
    }
}

#[test]
fn dates_and_der_are_read_the_way_x509_writes_them() {
    assert_eq!(unix_of(2026, 11, 12, 16, 29, 19), 1_794_500_959);
    assert_eq!(unix_of(1970, 1, 1, 0, 0, 0), 0);
    assert_eq!(
        parse_time(0x17, b"140801000000Z"),
        Some(unix_of(2014, 8, 1, 0, 0, 0))
    );
    assert_eq!(
        parse_time(0x18, b"99991231235959Z"),
        Some(unix_of(9999, 12, 31, 23, 59, 59))
    );
    assert_eq!(parse_time(0x17, b"14080100000Z"), None);
    assert_eq!(parse_time(0x17, b"1408010000AAZ"), None);
    // a length that runs past the data, and a long form of more than three bytes
    assert!(tlv(&[0x30, 0x05, 1, 2]).is_none());
    assert!(tlv(&[0x30, 0x84, 0, 0, 0, 1, 0]).is_none());
    assert!(tlv(&[0x30]).is_none());
}

// ---- enrolment through the service ---------------------------------------------------------------------------------------

mod enrol {
    use super::*;
    use crate::approval_key::handle;
    use crate::secrets::SecretStore;
    use crate::secrets_enc::{EncryptedSecrets, KeyProvider, LocalKekProvider};
    use crate::secrets_service::{Gates, Policy};
    use ozbox_core::approval::{KeyType, SocketClass};
    use serde_json::{json, Value};
    use std::sync::Arc;

    const T: u64 = 1_794_528_000_000 + 5_000;

    struct Rig {
        store: Arc<EncryptedSecrets>,
        gates: Gates,
        dir: tempfile::TempDir,
    }

    fn rig(roots: Vec<Vec<u8>>) -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let p: Arc<dyn KeyProvider> = Arc::new(LocalKekProvider::random("local").unwrap());
        let store = Arc::new(EncryptedSecrets::new(dir.path().join("s.json"), "box-a", p).unwrap());
        let gates = Gates::default();
        let _ = gates.fido_roots.set(roots);
        let _ = gates.presence_keys.set(true);
        gates
            .enable_requests(
                &store,
                &dir.path().join("req"),
                &dir.path().join("state"),
                "box-1",
                T,
            )
            .unwrap();
        Rig { store, gates, dir }
    }

    impl Rig {
        fn call(&self, v: Value) -> Result<Value, String> {
            handle(&self.store, &self.gates, Policy::Admin, &v, T)
        }
        fn challenge(&self) -> (String, [u8; 32]) {
            let c = self
                .call(json!({"op":"approval_key_enrol_challenge"}))
                .unwrap();
            let mut ch = [0u8; 32];
            ch.copy_from_slice(&unhex(c["challenge"].as_str().unwrap()));
            (c["enrol_id"].as_str().unwrap().to_string(), ch)
        }
        fn enrol(&self, id: &str, m: &Made, enrol_id: &str) -> Result<Value, String> {
            self.call(json!({"op":"approval_key_enroll","key_id":id,"key_type":"webauthn-p256","public_key":m.public_hex,
                "rp":{"rp_id":RP,"origin":ORIGIN},
                "attestation":{"kind":"webauthn","object_hex":hex(&m.object),"client_data_hex":hex(&m.client)},
                "enrol_id":enrol_id}))
        }
    }

    #[test]
    fn a_key_with_a_verified_attestation_over_the_services_challenge_is_a_presence_key_and_marks_the_box(
    ) {
        let r = rig(vec![unhex(ROOT_DER)]);
        let (enrol_id, ch) = r.challenge();
        let (m, _) = made_for(&[LEAF_DER, INT_DER], &ch);
        let out = r.enrol("tok", &m, &enrol_id).unwrap();
        assert_eq!(out["presence"], "proved");
        let v = crate::approval_keystore::load_key_view(&*r.store, "tok")
            .unwrap()
            .unwrap();
        assert_eq!(v.key_type, KeyType::WebauthnP256);
        assert!(v.presence_proved && v.attestation_digest.is_some());
        assert_eq!(v.rp.as_ref().unwrap().rp_id, RP);
        let (ctx, _) = r.gates.requests.get().unwrap().ctx(&r.store).unwrap();
        assert!(
            ctx.ever_key && ctx.ever_presence_key,
            "the sticky marker is set by the verifier, nothing else"
        );
        // it is listed as a presence key
        let info = r.call(json!({"op":"approval_keys"})).unwrap();
        assert_eq!(info["info"][0]["presence"], "proved");
        assert_eq!(info["info"][0]["attested"], true);
    }

    #[test]
    fn an_attestation_that_does_not_verify_is_refused_and_enrols_nothing_and_a_challenge_is_used_once(
    ) {
        // a chain to a root this box does not pin: the same statement a software key could make with its own CA
        let r = rig(vec![unhex(RROOT_DER)]);
        let (enrol_id, ch) = r.challenge();
        let (m, _) = made_for(&[LEAF_DER, INT_DER], &ch);
        let e = r.enrol("tok", &m, &enrol_id).unwrap_err();
        assert!(e.contains("does not chain to a root"), "{e}");
        assert!(crate::approval_keystore::load_key_view(&*r.store, "tok")
            .unwrap()
            .is_none());
        assert!(
            !r.gates
                .requests
                .get()
                .unwrap()
                .ctx(&r.store)
                .unwrap()
                .0
                .ever_key
        );
        // the challenge was spent by the attempt: a good statement over it is refused too
        let r = rig(vec![unhex(ROOT_DER)]);
        let (enrol_id, ch) = r.challenge();
        let (m, _) = made_for(&[LEAF_DER, INT_DER], &ch);
        assert!(r.enrol("tok", &m, &enrol_id).is_ok());
        let e = r.enrol("tok2", &m, &enrol_id).unwrap_err();
        assert!(e.contains("enrolment challenge"), "{e}");
        // a statement made over another challenge (not the one this box issued for this enrolment)
        let (enrol_id, _) = r.challenge();
        let (other, _) = made_for(&[LEAF_DER, INT_DER], &[3u8; 32]);
        assert!(r
            .enrol("tok3", &other, &enrol_id)
            .unwrap_err()
            .contains("another enrolment"));
    }

    #[test]
    fn a_fido_key_enrolled_with_no_attestation_is_a_software_key_whatever_it_says() {
        let r = rig(vec![unhex(ROOT_DER)]);
        let (m, _) = made_for(&[LEAF_DER, INT_DER], &[1u8; 32]);
        // the laptop claims presence in every way it can
        let e = r.call(json!({"op":"approval_key_enroll","key_id":"liar","key_type":"webauthn-p256","public_key":m.public_hex,
            "rp":{"rp_id":RP,"origin":ORIGIN},"presence_proved":true,"presence":"proved","attested":true}));
        assert_eq!(e.unwrap()["presence"], "none");
        let v = crate::approval_keystore::load_key_view(&*r.store, "liar")
            .unwrap()
            .unwrap();
        assert!(!v.presence_proved);
        assert!(
            !r.gates
                .requests
                .get()
                .unwrap()
                .ctx(&r.store)
                .unwrap()
                .0
                .ever_presence_key
        );
        // an attestation for a key type that is not FIDO2 is refused outright
        let e = r.call(json!({"op":"approval_key_enroll","key_id":"soft","public_key":"ab".repeat(32),"attestation":{"kind":"webauthn"}}));
        assert!(e.unwrap_err().contains("only a FIDO2 key"));
    }

    #[test]
    fn a_presence_key_enrolled_this_way_decides_over_the_sealed_route_and_a_software_one_does_not_decide_owner_scopes(
    ) {
        let r = rig(vec![unhex(ROOT_DER)]);
        let (enrol_id, ch) = r.challenge();
        let (m, key) = made_for(&[LEAF_DER, INT_DER], &ch);
        r.enrol("tok", &m, &enrol_id).unwrap();
        let svc = r.gates.requests.get().unwrap().clone();
        let id = svc
            .handle(
                &r.store,
                &r.gates,
                SocketClass::Box,
                Some(1000),
                &json!({"op":"areq_file","subject":{"scope":"guard-override","hook":"commit","repo_path_hash":"1".repeat(64),
                    "hook_kind":"pre-commit","tree_id":"a".repeat(40)},
                    "scanned_text":"diff --git a/R b/R\n--- a/R\n+++ b/R\n@@ -1 +1,2 @@\n x\n+y\n"}),
                T,
            )
            .unwrap()["request"]["id"]
            .as_str()
            .unwrap()
            .to_string();
        let c = svc
            .handle(
                &r.store,
                &r.gates,
                SocketClass::Ingress,
                None,
                &json!({"op":"areq_decide_challenge","id":id}),
                T,
            )
            .unwrap();
        let mut chal = [0u8; 32];
        chal.copy_from_slice(&unhex(c["challenge"].as_str().unwrap()));
        // a real assertion by the attested credential, over this request's challenge, for the recorded relying party
        let cd = client_data(&chal, ORIGIN, "webauthn.get");
        let mut ad = sha(RP.as_bytes());
        ad.push(0x05);
        ad.extend_from_slice(&7u32.to_be_bytes());
        let mut payload = ad.clone();
        payload.extend_from_slice(&sha(&cd));
        let sig = key.sign(&SystemRandom::new(), &payload).unwrap();
        let d = svc
            .handle(
                &r.store,
                &r.gates,
                SocketClass::Ingress,
                None,
                &json!({"op":"areq_decide","id":id,"outcome":"approve","key_id":"tok","evidence":{"laptop":{
                    "key_id":"tok","key_type":"webauthn-p256","signature_format":"webauthn-assertion",
                    "signed_message":hex(&cd),"signature":hex(sig.as_ref()),"authenticator_data":hex(&ad)}}}),
                T + 1,
            )
            .unwrap();
        assert_eq!(d["request"]["decision"]["factor_label"], "laptop-key:tok");
        assert_eq!(d["request"]["decision"]["presence"], "proved");
        let _ = &r.dir;
    }

    fn rig_presence_off(roots: Vec<Vec<u8>>) -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let p: Arc<dyn KeyProvider> = Arc::new(LocalKekProvider::random("local").unwrap());
        let store = Arc::new(EncryptedSecrets::new(dir.path().join("s.json"), "box-a", p).unwrap());
        let gates = Gates::default();
        let _ = gates.fido_roots.set(roots);
        gates
            .enable_requests(
                &store,
                &dir.path().join("req"),
                &dir.path().join("state"),
                "box-1",
                T,
            )
            .unwrap();
        Rig { store, gates, dir }
    }

    #[test]
    fn presence_authority_is_off_until_root_turns_it_on_and_a_verified_key_is_a_software_key_meanwhile(
    ) {
        let r = rig_presence_off(vec![unhex(ROOT_DER)]);
        let (enrol_id, ch) = r.challenge();
        let (m, _) = made_for(&[LEAF_DER, INT_DER], &ch);
        let out = r.enrol("tok", &m, &enrol_id).unwrap();
        assert_eq!(out["presence"], "none");
        let v = crate::approval_keystore::load_key_view(&*r.store, "tok")
            .unwrap()
            .unwrap();
        assert!(
            !v.presence_proved,
            "an attestation that verified is not authority while the setting is off"
        );
        assert!(v.attestation_digest.is_some(), "but it is recorded");
        assert!(
            !r.gates
                .requests
                .get()
                .unwrap()
                .ctx(&r.store)
                .unwrap()
                .0
                .ever_presence_key
        );
    }

    fn mint_enroll_code(r: &Rig, id: &str) -> String {
        r.gates
            .approvals
            .mint("signer-enroll", id, "", &crate::secrets_signer::Signer::Dashboard, T, 60_000)
            .unwrap()
    }

    #[test]
    fn codes_are_on_by_default_with_request_ops_until_phase_3() {
        let r = rig(vec![unhex(ROOT_DER)]);
        assert!(r.gates.codes_allowed());
        r.call(json!({"op":"approval_key_enroll","key_id":"first","public_key":"ab".repeat(32)}))
            .unwrap();
        r.store
            .set(crate::secrets_approval::ENROLLED_MARKER, "1")
            .unwrap();
        // the laptop's challenge route is open (for a non-Production import: a key kept on a computer never approves
        // Production, ADR 0041 §3, and an import with no environment named is not a known non-Production one)
        assert!(handle(
            &r.store,
            &r.gates,
            Policy::Unsealed,
            &json!({"op":"approval_challenge","key_id":"first","scope":"import","env":"staging"}),
            T
        )
        .is_ok());
    }

    #[test]
    fn the_dashboard_socket_cannot_make_or_use_an_enrolment_code_whatever_the_codes_setting_says() {
        let r = rig(vec![unhex(ROOT_DER)]);
        r.call(json!({"op":"approval_key_enroll","key_id":"first","public_key":"ab".repeat(32)}))
            .unwrap();
        r.store
            .set(crate::secrets_approval::ENROLLED_MARKER, "1")
            .unwrap();
        assert!(r.gates.codes_allowed());
        assert!(crate::approval_key::dashboard_mint_refused(
            &r.gates,
            "signer-enroll"
        ));
        assert!(!crate::approval_key::dashboard_mint_refused(
            &r.gates, "import"
        ));
        let code = mint_enroll_code(&r, "evil");
        let e = handle(&r.store, &r.gates, Policy::Supervisor, &json!({"op":"approval_key_enroll","key_id":"evil","public_key":"cd".repeat(32),"approval":code}), T)
            .unwrap_err();
        assert!(e.contains("approved request"), "{e}");
        assert!(crate::approval_keystore::load_key_view(&*r.store, "evil")
            .unwrap()
            .is_none());
    }

    #[test]
    fn with_the_off_switch_a_code_is_neither_made_nor_accepted() {
        let r = rig(vec![unhex(ROOT_DER)]);
        let _ = r.gates.legacy_codes_off.set(true);
        r.call(json!({"op":"approval_key_enroll","key_id":"first","public_key":"ab".repeat(32)}))
            .unwrap();
        r.store
            .set(crate::secrets_approval::ENROLLED_MARKER, "1")
            .unwrap();
        assert!(!r.gates.codes_allowed());
        let code = mint_enroll_code(&r, "evil");
        let e = handle(&r.store, &r.gates, Policy::Unsealed, &json!({"op":"approval_key_enroll","key_id":"evil","public_key":"cd".repeat(32),"approval":code}), T)
            .unwrap_err();
        assert!(e.contains("approvals as requests"), "{e}");
        assert!(handle(
            &r.store,
            &r.gates,
            Policy::Unsealed,
            &json!({"op":"approval_challenge","key_id":"first","scope":"import"}),
            T
        )
        .is_err());
        assert!(r
            .gates
            .require(&r.store, "import", "app", "staging", &code, T)
            .is_err());
        assert!(crate::approval_keystore::load_key_view(&*r.store, "evil")
            .unwrap()
            .is_none());
    }

    #[test]
    fn a_code_enrolment_serves_the_24_hour_wait_when_the_box_has_had_a_key() {
        let r = rig(vec![unhex(ROOT_DER)]);
        r.call(json!({"op":"approval_key_enroll","key_id":"first","public_key":"ab".repeat(32)}))
            .unwrap();
        r.store
            .set(crate::secrets_approval::ENROLLED_MARKER, "1")
            .unwrap();
        let code = mint_enroll_code(&r, "second");
        handle(&r.store, &r.gates, Policy::Unsealed, &json!({"op":"approval_key_enroll","key_id":"second","public_key":"cd".repeat(32),"approval":code}), T)
            .unwrap();
        let m = crate::approval_keystore::read_meta(&*r.store, "second")
            .unwrap()
            .unwrap();
        assert_eq!(m.active_from_ms, T + 24 * 3_600_000);
    }

    /// A box with a first key, and a second enrolled by a code (so it serves the 24-hour wait). Returns its seed.
    fn box_with_a_key_in_its_wait(r: &Rig) -> String {
        r.call(json!({"op":"approval_key_enroll","key_id":"first","public_key":"ab".repeat(32)}))
            .unwrap();
        r.store
            .set(crate::secrets_approval::ENROLLED_MARKER, "1")
            .unwrap();
        let (seed, pk) = crate::approval_key::generate().unwrap();
        let code = mint_enroll_code(r, "second");
        handle(
            &r.store,
            &r.gates,
            Policy::Unsealed,
            &json!({"op":"approval_key_enroll","key_id":"second","public_key":pk,"approval":code}),
            T,
        )
        .unwrap();
        seed.to_string()
    }

    fn challenge_for(r: &Rig, key: &str, now: u64) -> Result<Value, String> {
        handle(
            &r.store,
            &r.gates,
            Policy::Unsealed,
            &json!({"op":"approval_challenge","key_id":key,"scope":"import","project":"app","env":"staging"}),
            now,
        )
    }

    fn redeem(r: &Rig, key: &str, seed: &str, ch: &Value, now: u64) -> Result<Value, String> {
        let nonce = ch["nonce"].as_str().unwrap();
        let msg = crate::approval_key::message(
            "import",
            "app",
            "staging",
            key,
            nonce,
            ch["expires_ms"].as_u64().unwrap(),
        );
        handle(
            &r.store,
            &r.gates,
            Policy::Unsealed,
            &json!({"op":"approval_redeem","key_id":key,"nonce":nonce,"signature":crate::approval_key::sign(seed, &msg).unwrap()}),
            now,
        )
    }

    #[test]
    fn a_key_in_its_24_hour_wait_can_neither_make_nor_redeem_a_code_and_can_after_the_wait() {
        let r = rig(vec![unhex(ROOT_DER)]);
        let seed = box_with_a_key_in_its_wait(&r);
        let wait = crate::approval_key::ENROL_WAIT_MS;
        // no challenge, at the start or a moment before the wait ends
        for t in [T + 1, T + wait - 1] {
            let e = challenge_for(&r, "second", t).unwrap_err();
            assert_eq!(e, crate::approval_key::IN_WAIT);
        }
        // the key that was there before is not slowed
        assert!(challenge_for(&r, "first", T + 1).is_ok());
        // a challenge made once the wait is over cannot be redeemed if the record has gone back into a wait since
        let ch = challenge_for(&r, "second", T + wait).unwrap();
        let mut m = crate::approval_keystore::read_meta(&*r.store, "second")
            .unwrap()
            .unwrap();
        m.active_from_ms = T + wait + 10_000;
        crate::approval_keystore::write_meta(&*r.store, "second", &m).unwrap();
        let e = redeem(&r, "second", &seed, &ch, T + wait + 1).unwrap_err();
        assert_eq!(e, crate::approval_key::IN_WAIT);
        // after the wait both work, and the code is a real one
        let ch = challenge_for(&r, "second", T + wait + 20_000).unwrap();
        let out = redeem(&r, "second", &seed, &ch, T + wait + 20_001).unwrap();
        assert!(out["code"].as_str().is_some_and(|c| !c.is_empty()));
    }

    #[test]
    fn when_the_request_journal_did_not_open_the_dashboard_still_makes_no_enrolment_code_and_the_wait_still_holds(
    ) {
        let dir = tempfile::tempdir().unwrap();
        let p: Arc<dyn KeyProvider> = Arc::new(LocalKekProvider::random("local").unwrap());
        let store = Arc::new(EncryptedSecrets::new(dir.path().join("s.json"), "box-a", p).unwrap());
        let gates = Gates::default();
        // the service started, the journal could not be opened, and it said so
        let _ = gates.requests_failed.set(());
        assert!(gates.requests.get().is_none());
        assert!(crate::approval_key::dashboard_mint_refused(
            &gates,
            "signer-enroll"
        ));
        handle(
            &store,
            &gates,
            Policy::Admin,
            &json!({"op":"approval_key_enroll","key_id":"first","public_key":"ab".repeat(32)}),
            T,
        )
        .unwrap();
        store
            .set(crate::secrets_approval::ENROLLED_MARKER, "1")
            .unwrap();
        // the dashboard's socket enrols by a request only, and there is no journal to hold one
        let code = gates
            .approvals
            .mint("signer-enroll", "evil", "", &crate::secrets_signer::Signer::Dashboard, T, 60_000)
            .unwrap();
        let e = handle(&store, &gates, Policy::Supervisor, &json!({"op":"approval_key_enroll","key_id":"evil","public_key":"cd".repeat(32),"approval":code}), T)
            .unwrap_err();
        assert!(e.contains("approved request"), "{e}");
        // a code enrolment through the laptop's route serves the wait, read from the store alone
        let code = gates
            .approvals
            .mint("signer-enroll", "second", "", &crate::secrets_signer::Signer::SoftwareKey("first".into()), T, 60_000)
            .unwrap();
        handle(&store, &gates, Policy::Unsealed, &json!({"op":"approval_key_enroll","key_id":"second","public_key":"cd".repeat(32),"approval":code}), T)
            .unwrap();
        let m = crate::approval_keystore::read_meta(&*store, "second")
            .unwrap()
            .unwrap();
        assert_eq!(m.active_from_ms, T + crate::approval_key::ENROL_WAIT_MS);
    }

    #[test]
    fn a_presence_key_is_listed_as_none_once_root_has_taken_the_flag_away() {
        let r = rig(vec![unhex(ROOT_DER)]);
        let (enrol_id, ch) = r.challenge();
        let (m, _) = made_for(&[LEAF_DER, INT_DER], &ch);
        assert_eq!(r.enrol("tok", &m, &enrol_id).unwrap()["presence"], "proved");
        let list = |g: &Gates| {
            handle(
                &r.store,
                g,
                Policy::Admin,
                &json!({"op":"approval_keys"}),
                T,
            )
            .unwrap()["info"][0]["presence"]
                .clone()
        };
        assert_eq!(list(&r.gates), "proved");
        // the same store, a service started without the flag
        let off = Gates::default();
        assert_eq!(list(&off), "none");
    }

    #[test]
    fn the_dashboards_revoke_is_its_own_operation_and_makes_no_code() {
        let r = rig(vec![unhex(ROOT_DER)]);
        r.call(json!({"op":"approval_key_enroll","key_id":"first","public_key":"ab".repeat(32)}))
            .unwrap();
        r.store
            .set(crate::secrets_approval::ENROLLED_MARKER, "1")
            .unwrap();
        // without the supervisor's statement that an owner just confirmed with a passkey, nothing is revoked
        assert!(handle(
            &r.store,
            &r.gates,
            Policy::Supervisor,
            &json!({"op":"approval_key_revoke","key_id":"first"}),
            T
        )
        .is_err());
        let out = handle(
            &r.store,
            &r.gates,
            Policy::Supervisor,
            &json!({"op":"approval_key_revoke","key_id":"first","dashboard_stepup":true}),
            T,
        )
        .unwrap();
        assert_eq!(out["via"], "dashboard-stepup");
        // that statement means nothing on any other socket
        r.call(json!({"op":"approval_key_enroll","key_id":"again","public_key":"ab".repeat(32)}))
            .unwrap();
        assert!(handle(
            &r.store,
            &r.gates,
            Policy::Unsealed,
            &json!({"op":"approval_key_revoke","key_id":"again","dashboard_stepup":true}),
            T
        )
        .is_err());
    }

    #[test]
    fn the_kept_verdict_of_an_enrolment_is_deleted_when_its_request_is_cancelled() {
        let r = rig(vec![unhex(ROOT_DER)]);
        let svc = r.gates.requests.get().unwrap().clone();
        r.call(json!({"op":"approval_key_enroll","key_id":"first","public_key":"ab".repeat(32)}))
            .unwrap();
        r.store
            .set(crate::secrets_approval::ENROLLED_MARKER, "1")
            .unwrap();
        let (enrol_id, ch) = r.challenge();
        let (m, _) = made_for(&[LEAF_DER, INT_DER], &ch);
        let digest = hex(&sha(&m.object));
        let att =
            json!({"kind":"webauthn","object_hex":hex(&m.object),"client_data_hex":hex(&m.client)});
        let subject = json!({"scope":"signer-enroll","action":"enrol","key_name":"tok","key_type":"webauthn-p256",
            "public_half":m.public_hex,"attestation_digest":digest});
        let f = svc
            .handle(&r.store, &r.gates, SocketClass::Admin, Some(0), &json!({"op":"areq_file","subject":subject,"attestation":att,"enrol_id":enrol_id,"rp":{"rp_id":RP,"origin":ORIGIN}}), T)
            .unwrap();
        let id = f["request"]["id"].as_str().unwrap().to_string();
        let name = format!("approval-key.pending.{digest}");
        assert!(r.store.exists(&name).unwrap());
        svc.handle(
            &r.store,
            &r.gates,
            SocketClass::Admin,
            Some(0),
            &json!({"op":"areq_cancel","id":id}),
            T + 1,
        )
        .unwrap();
        assert!(
            !r.store.exists(&name).unwrap(),
            "the verdict outlived its request"
        );
    }

    #[test]
    fn an_enrolment_filed_with_its_attestation_is_enrolled_after_the_challenge_has_expired() {
        let r = rig(vec![unhex(ROOT_DER)]);
        let svc = r.gates.requests.get().unwrap().clone();
        r.call(json!({"op":"approval_key_enroll","key_id":"first","public_key":"ab".repeat(32)}))
            .unwrap();
        r.store
            .set(crate::secrets_approval::ENROLLED_MARKER, "1")
            .unwrap();
        let (enrol_id, ch) = r.challenge();
        let (m, _) = made_for(&[LEAF_DER, INT_DER], &ch);
        let digest = hex(&sha(&m.object));
        let att =
            json!({"kind":"webauthn","object_hex":hex(&m.object),"client_data_hex":hex(&m.client)});
        let subject = json!({"scope":"signer-enroll","action":"enrol","key_name":"tok","key_type":"webauthn-p256",
            "public_half":m.public_hex,"attestation_digest":digest});
        // a filing whose attestation does not verify is refused and nothing waits for an approval
        let mut bad = att.clone();
        bad["object_hex"] = json!(hex(&[1u8; 40]));
        assert!(svc
            .handle(&r.store, &r.gates, SocketClass::Admin, Some(0), &json!({"op":"areq_file","subject":subject,"attestation":bad,"enrol_id":enrol_id,"rp":{"rp_id":RP,"origin":ORIGIN}}), T)
            .is_err());
        let (enrol_id, ch) = r.challenge();
        let (m, _) = made_for(&[LEAF_DER, INT_DER], &ch);
        let digest = hex(&sha(&m.object));
        let att =
            json!({"kind":"webauthn","object_hex":hex(&m.object),"client_data_hex":hex(&m.client)});
        let subject = json!({"scope":"signer-enroll","action":"enrol","key_name":"tok","key_type":"webauthn-p256",
            "public_half":m.public_hex,"attestation_digest":digest});
        let f = svc
            .handle(&r.store, &r.gates, SocketClass::Admin, Some(0), &json!({"op":"areq_file","subject":subject,"attestation":att,"enrol_id":enrol_id,"rp":{"rp_id":RP,"origin":ORIGIN}}), T)
            .unwrap();
        let id = f["request"]["id"].as_str().unwrap().to_string();
        svc.handle(
            &r.store,
            &r.gates,
            SocketClass::Admin,
            Some(0),
            &json!({"op":"areq_decide","id":id,"outcome":"approve"}),
            T + 1,
        )
        .unwrap();
        // eleven minutes on: the in-memory challenge is long gone, and the enrolment still completes from the kept verdict
        let later = T + 11 * 60_000;
        let out = handle(
            &r.store,
            &r.gates,
            Policy::Unsealed,
            &json!({"op":"approval_key_enroll","key_id":"tok","key_type":"webauthn-p256",
            "public_key":m.public_hex,"request_id":id,"attestation_digest":digest}),
            later,
        );
        let out = out.unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(out["presence"], "proved");
        assert!(
            crate::approval_keystore::load_key_view(&*r.store, "tok")
                .unwrap()
                .unwrap()
                .presence_proved
        );
        // and it is not spendable twice
        assert!(handle(
            &r.store,
            &r.gates,
            Policy::Unsealed,
            &json!({"op":"approval_key_enroll","key_id":"tok2","key_type":"webauthn-p256",
            "public_key":m.public_hex,"request_id":id,"attestation_digest":digest}),
            later + 1
        )
        .is_err());
    }

    #[test]
    fn each_class_of_socket_has_its_own_enrolment_challenge_pool() {
        let r = rig(vec![unhex(ROOT_DER)]);
        let ask = |p: Policy| {
            handle(
                &r.store,
                &r.gates,
                p,
                &json!({"op":"approval_key_enrol_challenge"}),
                T,
            )
        };
        for _ in 0..16 {
            assert!(ask(Policy::Supervisor).is_ok());
        }
        assert!(
            ask(Policy::Supervisor).is_err(),
            "the dashboard's pool is full"
        );
        // the laptop's and root's are untouched
        for _ in 0..16 {
            assert!(ask(Policy::Unsealed).is_ok());
        }
        assert!(ask(Policy::Unsealed).is_err());
        assert!(ask(Policy::Admin).is_ok());
    }
}
