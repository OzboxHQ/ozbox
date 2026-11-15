//! The attestation verifier for laptop keys (ADR 0041 §3).
//!
//! A laptop key counts as a **presence key** only if the service has verified, at enrolment, an attestation that says the key
//! lives in a FIDO2 authenticator: format `packed` with an `x5c` chain, or `fido-u2f`, chaining to a root **pinned in this
//! program** (plus any a root-owned file adds: add only a root or intermediate that signs FIDO authenticators and nothing
//! else, because the leaf rules below are a second line of defence, not the first), and made over the challenge the service itself issued for this enrolment.
//! `none` and self attestation (a `packed` statement with no `x5c`) are refused: a software key can make both, and most
//! synced passkeys return `none`. Without a verified attestation a key is a software key, whatever the laptop claims.
//!
//! Two containers carry a statement:
//!
//! * **A WebAuthn attestation object** (CBOR: `fmt`, `attStmt`, `authData`) with the `clientDataJSON` it was made over, for a
//!   `webauthn-p256` key. The client data must be a `webauthn.create` for this enrolment's challenge and the relying party.
//! * **An OpenSSH attestation blob** (`ssh-keygen -O write-attestation=`, `ssh-sk-attest-v01`: certificate, signature,
//!   authenticator data) for an `sk-ssh-ed25519` or `ecdsa-sk` key made with `-O challenge=<the service's challenge>`. The
//!   authenticator took `SHA-256(challenge)` as the client-data hash and the key's application as the relying party id.
//!
//! The certificate chain is checked here, with `ring` and a small DER reader, because the TLS verifiers in the tree refuse a
//! certificate that is not a server's: each certificate's validity, the issuer name against the next subject, the signature
//! (ECDSA P-256/P-384 or RSA PKCS#1, the inner and outer algorithm agreeing), that every intermediate says it is a CA (with a
//! `pathLenConstraint` that holds and a key usage that allows signing certificates), and then a pinned anchor.
//!
//! **What is pinned.** The anchors are Yubico's U2F and FIDO roots and the three Yubico FIDO attestation intermediates, **not**
//! "Yubico Attestation Root 1": that root also signs the PIV, OpenPGP, secure-domain and HSM intermediates, and a PIV slot
//! certificate is a signing key its holder can use for anything. On top of the pin, a `packed` leaf must follow the FIDO
//! certificate rules: version 3, the subject OU `Authenticator Attestation`, `CA:FALSE`, and the AAGUID extension
//! (1.3.6.1.4.1.45724.1.1.4, not critical) equal to the authenticator data's. The attestation of a presence key is **still
//! unproven against a physical key**, so presence authority is off unless the box's setting turns it on (see the build notes).
//!
//! **What this does not prove.** An attestation shows where a key lives at enrolment, not that a later signature was made with
//! a touch: every decision of a presence key still carries authenticator data, and the verifier of a decision requires user
//! presence on each one (ADR 0041 §3). Intermediates a vendor publishes separately (not sent in `x5c`) are not fetched.
//! The OpenSSH blob's layout is built from OpenSSH's own description (PROTOCOL.u2f) and is covered by synthetic fixtures; it
//! has not been checked against a physical key (see the phase 2 build notes).

use ring::digest::{digest, SHA256};
use ring::signature::{
    UnparsedPublicKey, ECDSA_P256_SHA256_ASN1, ECDSA_P384_SHA384_ASN1, RSA_PKCS1_2048_8192_SHA256,
    RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512,
};

use crate::serve::auth::b64::{decode_std, decode_url};
use crate::serve::auth::cbor::{self, Value};
use crate::serve::auth::webauthn::cose_to_key;

/// The vendor roots shipped with the program that sign FIDO and U2F authenticators and nothing else (the U2F root and the FIDO
/// root; see the file's header for where they came from).
const PINNED_ROOTS_PEM: &str = include_str!("attestation/pinned-roots.pem");
/// Yubico's FIDO attestation intermediates, pinned as trust anchors in place of "Yubico Attestation Root 1", which also vouches for
/// PIV, OpenPGP, secure-domain and HSM certificates (ADR 0041).
const PINNED_INTERMEDIATES_PEM: &str = include_str!("attestation/pinned-intermediates.pem");

/// Where root can add roots (a PEM file only root can write); read by the service, never by the box user.
pub const EXTRA_ROOTS_FILE: &str = "/etc/ozbox/fido-roots.pem";

const MAX_BLOB: usize = 16 * 1024;
const MAX_CHAIN: usize = 5;

// ---- a small DER reader ---------------------------------------------------------------------------------------------

/// One DER element from the front of `b`: its tag, its content, the whole element (header included) and the rest.
/// A DER element: its tag, its content, the whole element and what follows it.
type Tlv<'a> = (u8, &'a [u8], &'a [u8], &'a [u8]);

fn tlv(b: &[u8]) -> Option<Tlv<'_>> {
    let tag = *b.first()?;
    let l0 = *b.get(1)?;
    let (len, hdr) = if l0 < 0x80 {
        (usize::from(l0), 2)
    } else {
        let n = usize::from(l0 & 0x7f);
        if n == 0 || n > 3 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | usize::from(*b.get(2 + i)?);
        }
        (len, 2 + n)
    };
    let end = hdr.checked_add(len)?;
    let whole = b.get(..end)?;
    Some((tag, &b[hdr..end], whole, &b[end..]))
}

/// The OIDs and names this reader recognises, as their DER content bytes.
const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const OID_ECDSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
const OID_RSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
const OID_RSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
const OID_RSA_SHA512: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d];
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const OID_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
const OID_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
const OID_OU: &[u8] = &[0x55, 0x04, 0x0b];
/// `id-fido-gen-ce-aaguid`, 1.3.6.1.4.1.45724.1.1.4: the extension that names the authenticator model in its certificate.
const OID_FIDO_AAGUID: &[u8] = &[
    0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xe5, 0x1c, 0x01, 0x01, 0x04,
];
/// The subject OU the FIDO specification requires of a `packed` attestation certificate.
const FIDO_OU: &[u8] = b"Authenticator Attestation";

/// A certificate, read just far enough to check a chain.
struct Cert<'a> {
    der: &'a [u8],
    tbs: &'a [u8],
    issuer: &'a [u8],
    subject: &'a [u8],
    not_before: i64,
    not_after: i64,
    spki_alg: &'a [u8],
    spki_param: Option<&'a [u8]>,
    key: &'a [u8],
    sig_alg: &'a [u8],
    sig: &'a [u8],
    /// `Some(true)` for a CA, `Some(false)` for a basicConstraints that says not, `None` when there is none.
    ca: Option<bool>,
    /// The certificate's version number (3 for X.509 v3).
    version: i64,
    /// basicConstraints' `pathLenConstraint`, when there is one.
    path_len: Option<u32>,
    /// keyUsage's first byte (digitalSignature is 0x80, keyCertSign is 0x04), when the extension is there.
    key_usage: Option<u8>,
    /// The subject's organizational units.
    ou: Vec<&'a [u8]>,
    /// The AAGUID extension: whether it is marked critical, and the 16 bytes it holds (`None` inside when malformed).
    aaguid: Option<(bool, Option<&'a [u8]>)>,
    /// Whether the certificate carries an extension from Yubico's PIV attestation arc (1.3.6.1.4.1.41482.3): a PIV slot
    /// certificate, which is no authenticator's.
    piv_ext: bool,
}

const KU_KEY_CERT_SIGN: u8 = 0x04;
/// 1.3.6.1.4.1.41482.3, the arc of Yubico's PIV attestation extensions (firmware, serial, policies, form factor).
const OID_YUBICO_PIV_ARC: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xc4, 0x0a, 0x03];

/// Seconds since 1970 of a civil date and time (UTC), by the days-from-civil count.
fn unix_of(y: i64, mo: i64, d: i64, h: i64, mi: i64, s: i64) -> i64 {
    let y = if mo <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if mo > 2 { mo - 3 } else { mo + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    days * 86_400 + h * 3600 + mi * 60 + s
}

/// `UTCTime` (`YYMMDDHHMMSSZ`) or `GeneralizedTime` (`YYYYMMDDHHMMSSZ`), the only two forms a certificate uses.
fn parse_time(tag: u8, c: &[u8]) -> Option<i64> {
    let t = std::str::from_utf8(c).ok()?;
    if !t.ends_with('Z') || !t[..t.len() - 1].bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n = |a: usize, b: usize| -> Option<i64> { t.get(a..b)?.parse().ok() };
    match (tag, t.len()) {
        (0x17, 13) => {
            let yy = n(0, 2)?;
            let y = if yy < 50 { 2000 + yy } else { 1900 + yy };
            Some(unix_of(
                y,
                n(2, 4)?,
                n(4, 6)?,
                n(6, 8)?,
                n(8, 10)?,
                n(10, 12)?,
            ))
        }
        (0x18, 15) => Some(unix_of(
            n(0, 4)?,
            n(4, 6)?,
            n(6, 8)?,
            n(8, 10)?,
            n(10, 12)?,
            n(12, 14)?,
        )),
        _ => None,
    }
}

fn parse_cert(der: &[u8]) -> Option<Cert<'_>> {
    let (tag, body, whole, rest) = tlv(der)?;
    if tag != 0x30 || !rest.is_empty() {
        return None;
    }
    let (t, _, tbs_whole, after_tbs) = tlv(body)?;
    if t != 0x30 {
        return None;
    }
    let (t, alg_body, _, after_alg) = tlv(after_tbs)?;
    if t != 0x30 {
        return None;
    }
    let (t, sig_oid, _, _) = tlv(alg_body)?;
    if t != 0x06 {
        return None;
    }
    let (t, sig_bits, _, trailing) = tlv(after_alg)?;
    if t != 0x03 || !trailing.is_empty() || sig_bits.first() != Some(&0) {
        return None;
    }
    // the TBS: [0] version, serial, algorithm, issuer, validity, subject, spki, then optional fields
    let (_, tbs_body, _, _) = tlv(tbs_whole)?;
    let mut cur = tbs_body;
    let (tag, vbody, _, r) = tlv(cur)?;
    let mut version = 1;
    if tag == 0xa0 {
        let (t, v, _, _) = tlv(vbody)?;
        if t != 0x02 || v.len() != 1 {
            return None;
        }
        version = i64::from(v[0]) + 1;
        cur = r;
    }
    let (tag, _, _, r) = tlv(cur)?; // serial
    if tag != 0x02 {
        return None;
    }
    cur = r;
    let (tag, inner_alg, _, r) = tlv(cur)?; // signature algorithm: it must repeat the outer one, byte for byte
    if tag != 0x30 || inner_alg != alg_body {
        return None;
    }
    cur = r;
    let (tag, _, issuer, r) = tlv(cur)?;
    if tag != 0x30 {
        return None;
    }
    cur = r;
    let (tag, validity, _, r) = tlv(cur)?;
    if tag != 0x30 {
        return None;
    }
    cur = r;
    let (ta, nb, _, v2) = tlv(validity)?;
    let (tb, na, _, v3) = tlv(v2)?;
    if !v3.is_empty() {
        return None;
    }
    let (not_before, not_after) = (parse_time(ta, nb)?, parse_time(tb, na)?);
    let (tag, subject_body, subject, r) = tlv(cur)?;
    if tag != 0x30 {
        return None;
    }
    cur = r;
    // the subject's OUs: Name ::= SEQUENCE OF SET OF SEQUENCE { type OID, value }
    let mut ou = Vec::new();
    let mut names = subject_body;
    while !names.is_empty() {
        let (t, set, _, r) = tlv(names)?;
        names = r;
        if t != 0x31 {
            return None;
        }
        let mut atvs = set;
        while !atvs.is_empty() {
            let (t, atv, _, r) = tlv(atvs)?;
            atvs = r;
            let (to, oid, _, vrest) = tlv(atv)?;
            let (_, value, _, _) = tlv(vrest)?;
            if t == 0x30 && to == 0x06 && oid == OID_OU {
                ou.push(value);
            }
        }
    }
    let (tag, spki, _, r) = tlv(cur)?;
    if tag != 0x30 {
        return None;
    }
    cur = r;
    let (tag, alg, _, key_bits) = tlv(spki)?;
    if tag != 0x30 {
        return None;
    }
    let (t, spki_alg, _, alg_rest) = tlv(alg)?;
    if t != 0x06 {
        return None;
    }
    let spki_param = tlv(alg_rest).and_then(|(t, c, _, _)| (t == 0x06).then_some(c));
    let (t, kb, _, _) = tlv(key_bits)?;
    if t != 0x03 || kb.first() != Some(&0) {
        return None;
    }
    // extensions: [3] EXPLICIT SEQUENCE OF Extension; read are basicConstraints, keyUsage and the FIDO AAGUID
    let mut ca = None;
    let mut path_len = None;
    let mut key_usage = None;
    let mut aaguid = None;
    let mut piv_ext = false;
    while !cur.is_empty() {
        let (tag, body, _, r) = tlv(cur)?;
        cur = r;
        if tag != 0xa3 {
            continue;
        }
        let (_, exts, _, _) = tlv(body)?;
        let mut e = exts;
        while !e.is_empty() {
            let (_, ext, _, r) = tlv(e)?;
            e = r;
            let (t, oid, _, mut rest) = tlv(ext)?;
            if t != 0x06 {
                continue;
            }
            let mut critical = false;
            if let Some((0x01, c, _, r)) = tlv(rest) {
                critical = c.first().is_some_and(|b| *b != 0);
                rest = r;
            }
            if oid.starts_with(OID_YUBICO_PIV_ARC) {
                piv_ext = true;
            }
            if oid != OID_BASIC_CONSTRAINTS && oid != OID_KEY_USAGE && oid != OID_FIDO_AAGUID {
                continue;
            }
            let (t, octets, _, _) = tlv(rest)?;
            if t != 0x04 {
                return None;
            }
            if oid == OID_BASIC_CONSTRAINTS {
                let (t, bc, _, _) = tlv(octets)?;
                if t != 0x30 {
                    return None;
                }
                // BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLen INTEGER OPTIONAL }
                let (is_ca, after) = match tlv(bc) {
                    Some((0x01, c, _, r)) => (c.first().is_some_and(|b| *b != 0), r),
                    _ => (false, bc),
                };
                ca = Some(is_ca);
                if let Some((0x02, n, _, _)) = tlv(after) {
                    if n.len() == 1 && n[0] < 0x80 {
                        path_len = Some(u32::from(n[0]));
                    }
                }
            } else if oid == OID_KEY_USAGE {
                let (t, bits, _, _) = tlv(octets)?;
                if t != 0x03 || bits.len() < 2 {
                    return None;
                }
                key_usage = Some(bits[1]);
            } else {
                // the extension's value is an OCTET STRING of the 16 byte AAGUID
                let inner = match tlv(octets) {
                    Some((0x04, a, _, r)) if a.len() == 16 && r.is_empty() => Some(a),
                    _ => None,
                };
                aaguid = Some((critical, inner));
            }
        }
    }
    Some(Cert {
        der: whole,
        tbs: tbs_whole,
        issuer,
        subject,
        not_before,
        not_after,
        spki_alg,
        spki_param,
        key: &kb[1..],
        sig_alg: sig_oid,
        sig: &sig_bits[1..],
        ca,
        version,
        path_len,
        key_usage,
        ou,
        aaguid,
        piv_ext,
    })
}

/// Whether `child` was signed by `parent`'s key, by the algorithm `child` names.
fn signed_by(parent: &Cert<'_>, child: &Cert<'_>) -> bool {
    if parent.subject != child.issuer {
        return false;
    }
    verify_with_spki(
        parent.spki_alg,
        parent.spki_param,
        parent.key,
        child.sig_alg,
        child.tbs,
        child.sig,
    )
}

/// Verify `sig` over `msg` with a SubjectPublicKeyInfo's key, by the signature algorithm's OID.
fn verify_with_spki(
    spki_alg: &[u8],
    spki_param: Option<&[u8]>,
    key: &[u8],
    sig_alg: &[u8],
    msg: &[u8],
    sig: &[u8],
) -> bool {
    match (spki_alg, sig_alg) {
        (a, s)
            if a == OID_EC_PUBLIC_KEY && s == OID_ECDSA_SHA256 && spki_param == Some(OID_P256) =>
        {
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, key)
                .verify(msg, sig)
                .is_ok()
        }
        (a, s)
            if a == OID_EC_PUBLIC_KEY && s == OID_ECDSA_SHA384 && spki_param == Some(OID_P384) =>
        {
            UnparsedPublicKey::new(&ECDSA_P384_SHA384_ASN1, key)
                .verify(msg, sig)
                .is_ok()
        }
        (a, s) if a == OID_RSA_ENCRYPTION && s == OID_RSA_SHA256 => {
            UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, key)
                .verify(msg, sig)
                .is_ok()
        }
        (a, s) if a == OID_RSA_ENCRYPTION && s == OID_RSA_SHA384 => {
            UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA384, key)
                .verify(msg, sig)
                .is_ok()
        }
        (a, s) if a == OID_RSA_ENCRYPTION && s == OID_RSA_SHA512 => {
            UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA512, key)
                .verify(msg, sig)
                .is_ok()
        }
        _ => false,
    }
}

// ---- the roots ---------------------------------------------------------------------------------------------------------

/// The DER of every certificate in a PEM text (`# comment` lines and anything between blocks are ignored).
pub fn pem_to_ders(pem: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut cur: Option<String> = None;
    for line in pem.lines() {
        let l = line.trim();
        if l == "-----BEGIN CERTIFICATE-----" {
            cur = Some(String::new());
        } else if l == "-----END CERTIFICATE-----" {
            if let Some(b) = cur.take() {
                if let Some(d) = decode_std(&b) {
                    out.push(d);
                }
            }
        } else if let Some(b) = cur.as_mut() {
            b.push_str(l);
        }
    }
    out
}

/// The trust anchors shipped with the program: the FIDO-only roots and the FIDO attestation intermediates. No root that also
/// signs PIV or OpenPGP attestation is among them.
pub fn pinned_roots() -> Vec<Vec<u8>> {
    let mut v = pem_to_ders(PINNED_ROOTS_PEM);
    v.extend(pem_to_ders(PINNED_INTERMEDIATES_PEM));
    v
}

/// The pinned roots, and any in [`EXTRA_ROOTS_FILE`] if that is a plain file only root can write.
pub fn roots_for_service() -> Vec<Vec<u8>> {
    let mut roots = pinned_roots();
    let path = std::path::Path::new(EXTRA_ROOTS_FILE);
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        #[cfg(unix)]
        let trusted = {
            use std::os::unix::fs::MetadataExt;
            meta.is_file() && meta.uid() == 0 && meta.mode() & 0o022 == 0
        };
        #[cfg(not(unix))]
        let trusted = false;
        if trusted {
            if let Ok(text) = std::fs::read_to_string(path) {
                roots.extend(pem_to_ders(&text));
            }
        }
    }
    roots
}

fn hex(b: &[u8]) -> String {
    ozbox_core::audit::hex(b)
}

fn sha(b: &[u8]) -> Vec<u8> {
    digest(&SHA256, b).as_ref().to_vec()
}

/// Verify the chain `x5c` (leaf first) to one of `roots` at `now_s`. Returns the SHA-256 of the root it reached, in hex.
pub fn verify_chain(x5c: &[Vec<u8>], roots: &[Vec<u8>], now_s: i64) -> Result<String, String> {
    if x5c.is_empty() {
        return Err("the attestation has no certificate: a statement with none (self attestation or `none`) is a software key".into());
    }
    if x5c.len() > MAX_CHAIN {
        return Err("the attestation's certificate chain is too long".into());
    }
    let chain: Vec<Cert<'_>> = x5c
        .iter()
        .map(|d| {
            parse_cert(d).ok_or_else(|| "the attestation's certificate is not valid".to_string())
        })
        .collect::<Result<_, _>>()?;
    let valid = |c: &Cert<'_>| c.not_before <= now_s && now_s <= c.not_after;
    if !chain.iter().all(valid) {
        return Err(
            "a certificate in the attestation is not valid now (expired or not yet valid)".into(),
        );
    }
    // a leaf that says it is a CA is not an authenticator's certificate; an intermediate must say that it is one
    if chain[0].ca == Some(true) {
        return Err("the attestation's leaf certificate is a CA".into());
    }
    for c in &chain[1..] {
        if c.ca != Some(true) {
            return Err("an intermediate certificate in the attestation is not a CA".into());
        }
    }
    for w in chain.windows(2) {
        if !signed_by(&w[1], &w[0]) {
            return Err("the attestation's certificates do not chain".into());
        }
    }
    let last = &chain[chain.len() - 1];
    for r in roots {
        let Some(root) = parse_cert(r) else { continue };
        if !valid(&root) {
            continue;
        }
        // the chain's last certificate is the anchor itself, or was signed by it
        let is_last = root.der == last.der;
        if is_last || signed_by(&root, last) {
            if !is_last && root.ca != Some(true) {
                return Err(
                    "a trust anchor that is not a CA cannot vouch for a certificate".into(),
                );
            }
            check_ca_rules(&chain, (!is_last).then_some(&root))?;
            return Ok(hex(&sha(root.der)));
        }
    }
    Err("the attestation does not chain to a root this box trusts (a vendor root it does not pin, or a software key)".into())
}

/// What every CA on the path must satisfy: `pathLenConstraint` (the CAs below it, not counting the leaf) and, when it says,
/// that its key usage includes certificate signing. `anchor` is the trust anchor when it is not already the chain's last.
fn check_ca_rules(chain: &[Cert<'_>], anchor: Option<&Cert<'_>>) -> Result<(), String> {
    let cas: Vec<&Cert<'_>> = chain.iter().skip(1).chain(anchor).collect();
    for (below, c) in cas.iter().enumerate() {
        if c.path_len.is_some_and(|p| below > p as usize) {
            return Err("a certificate in the attestation has more CAs below it than its path length allows".into());
        }
        if c.key_usage.is_some_and(|k| k & KU_KEY_CERT_SIGN == 0) {
            return Err(
                "a CA in the attestation may not sign certificates (its key usage leaves that out)"
                    .into(),
            );
        }
    }
    // an anchor that is the chain's last is a CA too, unless the chain is the anchor alone
    Ok(())
}

/// The FIDO rules for an authenticator's attestation certificate (WebAuthn, "Packed attestation statement certificate
/// requirements"). A `packed` leaf is version 3, has the subject OU `Authenticator Attestation`, says `CA:FALSE`, and carries
/// the AAGUID extension (not critical) equal to the one in the authenticator data. A `fido-u2f` leaf (the older format) has no OU
/// or AAGUID, so it is held to: not a CA, and no certificate signing. This is what keeps a PIV, OpenPGP or other Yubico
/// certificate, which chains to a root that also vouches for FIDO, from passing as an authenticator.
fn check_fido_leaf(leaf: &Cert<'_>, packed: bool, aaguid: &[u8]) -> Result<(), String> {
    if leaf.ca == Some(true) || leaf.key_usage.is_some_and(|k| k & KU_KEY_CERT_SIGN != 0) {
        return Err("the attestation's certificate is a CA or may sign certificates".into());
    }
    if !packed {
        return Ok(());
    }
    if leaf.version != 3 {
        return Err("the attestation's certificate is not an X.509 version 3 certificate".into());
    }
    if !leaf.ou.contains(&FIDO_OU) {
        return Err("the attestation's certificate is not an authenticator attestation certificate (its subject OU is not `Authenticator Attestation`)".into());
    }
    if leaf.ca != Some(false) {
        return Err("the attestation's certificate does not say it is not a CA (basicConstraints is missing)".into());
    }
    match leaf.aaguid {
        Some((false, Some(a))) if a == aaguid => Ok(()),
        Some((_, Some(a))) if a != aaguid => Err("the attestation's certificate names another authenticator model than the one that made the key".into()),
        Some(_) => Err("the attestation's AAGUID extension is critical or not valid".into()),
        None => Err("the attestation's certificate has no AAGUID extension, so it does not say which authenticator model made the key".into()),
    }
}

/// The older `fido-u2f` layout carries no OU or AAGUID to hold a leaf to, so it is held to its own shape (phase 2 re-check NL3):
/// WebAuthn's `fido-u2f` statement has exactly one certificate, whose key is P-256, and a certificate from Yubico's PIV
/// attestation arc is a PIV slot certificate, which some Yubico roots also sign, and no authenticator's.
fn check_u2f_shape(x5c: &[Vec<u8>], leaf: &Cert<'_>) -> Result<(), String> {
    if x5c.len() != 1 {
        return Err("a `fido-u2f` attestation carries exactly one certificate".into());
    }
    if leaf.spki_alg != OID_EC_PUBLIC_KEY || leaf.spki_param != Some(OID_P256) {
        return Err("a `fido-u2f` attestation certificate holds a P-256 key".into());
    }
    if leaf.piv_ext {
        return Err(
            "the attestation's certificate is a PIV certificate, not an authenticator's".into(),
        );
    }
    Ok(())
}

// ---- the statement -------------------------------------------------------------------------------------------------------

/// What an authenticator data's attested credential holds.
struct Credential {
    rp_id_hash: Vec<u8>,
    flags: u8,
    aaguid: Vec<u8>,
    credential_id: Vec<u8>,
    /// The key in the form `ring` takes: an uncompressed P-256 point for ES256, 32 bytes for EdDSA.
    public: Vec<u8>,
    alg: i64,
}

fn parse_auth_data(ad: &[u8]) -> Result<Credential, String> {
    let bad = || "the attestation's authenticator data is not valid".to_string();
    if ad.len() < 55 || ad[32] & 0x40 == 0 {
        return Err("the attestation carries no credential (authenticator data without attested credential data)".into());
    }
    let id_len = usize::from(u16::from_be_bytes([ad[53], ad[54]]));
    if id_len == 0 || id_len > 1023 || ad.len() < 55 + id_len {
        return Err(bad());
    }
    let (cose, _) = cbor::decode(&ad[55 + id_len..]).ok_or_else(bad)?;
    let (alg, public) =
        cose_to_key(&cose).map_err(|_| "the attested key is not one this box reads".to_string())?;
    Ok(Credential {
        rp_id_hash: ad[..32].to_vec(),
        flags: ad[32],
        aaguid: ad[37..53].to_vec(),
        credential_id: ad[55..55 + id_len].to_vec(),
        public,
        alg,
    })
}

/// The statement of an attestation, whichever container carried it.
struct Statement {
    /// The certificates, leaf first.
    x5c: Vec<Vec<u8>>,
    sig: Vec<u8>,
    auth_data: Vec<u8>,
    /// `packed`, `fido-u2f`, or empty when the container does not say (an OpenSSH blob: both are tried).
    fmt: String,
}

/// A WebAuthn attestation object: `{fmt, attStmt: {sig, x5c, alg?}, authData}`.
fn parse_webauthn_object(obj: &[u8]) -> Result<Statement, String> {
    let bad = || "the attestation object is not valid".to_string();
    if obj.len() > MAX_BLOB {
        return Err(bad());
    }
    let (v, used) = cbor::decode(obj).ok_or_else(bad)?;
    if used != obj.len() {
        return Err(bad());
    }
    let fmt = match v.get_text("fmt") {
        Some(Value::Text(t)) => t.clone(),
        _ => return Err(bad()),
    };
    if fmt != "packed" && fmt != "fido-u2f" {
        return Err(format!(
            "attestation format `{fmt}` is not accepted: only `packed` with a certificate chain, or `fido-u2f` (`none` is what a software key sends)"
        ));
    }
    let stmt = v.get_text("attStmt").ok_or_else(bad)?;
    let auth_data = v
        .get_text("authData")
        .and_then(Value::as_bytes)
        .ok_or_else(bad)?
        .to_vec();
    let sig = stmt
        .get_text("sig")
        .and_then(Value::as_bytes)
        .ok_or_else(bad)?
        .to_vec();
    let x5c = match stmt.get_text("x5c") {
        Some(Value::Array(a)) => a
            .iter()
            .map(|c| c.as_bytes().map(<[u8]>::to_vec).ok_or_else(bad))
            .collect::<Result<Vec<_>, _>>()?,
        _ => Vec::new(),
    };
    // packed with no x5c is self attestation (or ECDAA, which is not accepted): the certificate check refuses it below
    Ok(Statement {
        x5c,
        sig,
        auth_data,
        fmt,
    })
}

fn ssh_string(b: &[u8]) -> Option<(&[u8], &[u8])> {
    let len = u32::from_be_bytes(b.get(..4)?.try_into().ok()?) as usize;
    let end = 4usize.checked_add(len)?;
    Some((b.get(4..end)?, b.get(end..)?))
}

/// An OpenSSH attestation blob (`ssh-keygen -O write-attestation=`).
fn parse_openssh_blob(blob: &[u8]) -> Result<Statement, String> {
    let bad = || "the attestation blob is not valid".to_string();
    if blob.len() > MAX_BLOB {
        return Err(bad());
    }
    let (magic, rest) = ssh_string(blob).ok_or_else(bad)?;
    if magic != b"ssh-sk-attest-v01" {
        return Err("that is not an OpenSSH attestation blob".into());
    }
    let (cert, rest) = ssh_string(rest).ok_or_else(bad)?;
    let (sig, rest) = ssh_string(rest).ok_or_else(bad)?;
    let (authdata, _) = ssh_string(rest).ok_or_else(bad)?;
    // authenticator data may arrive wrapped as a CBOR byte string (libfido2's `authdata_cbor`); unwrap it if it is one
    let auth_data = match cbor::decode(authdata) {
        Some((Value::Bytes(b), used)) if used == authdata.len() && b.len() >= 37 => b,
        _ => authdata.to_vec(),
    };
    Ok(Statement {
        x5c: vec![cert.to_vec()],
        sig: sig.to_vec(),
        auth_data,
        fmt: String::new(),
    })
}

/// Which container an attestation came in, and what it needs beside it.
pub enum Container<'a> {
    /// An OpenSSH blob, for `sk-ssh-ed25519` and `ecdsa-sk`. `application` is the key's (`ssh:` by default).
    OpenSsh {
        blob: &'a [u8],
        application: &'a str,
    },
    /// A WebAuthn attestation object and the `clientDataJSON` it was made over, for a `webauthn-p256` key.
    Webauthn {
        object: &'a [u8],
        client_data_json: &'a [u8],
        rp_id: &'a str,
        origin: &'a str,
    },
}

/// What a verified attestation says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attested {
    /// The attested key's public half in hex: an uncompressed P-256 point, or 32 bytes for Ed25519.
    pub public_half: String,
    pub credential_id: String,
    pub aaguid: String,
    /// SHA-256 of the root the chain reached.
    pub root_sha256: String,
    /// SHA-256 of the whole attestation as sent (what the `signer-enroll` subject carries).
    pub digest: String,
}

/// Verify an attestation for an enrolment: the statement's signature, its chain to a pinned root, the challenge, the relying
/// party and that the attested key is `expected_public_hex`. `challenge` is the one the service issued for this enrolment.
pub fn verify(
    container: &Container<'_>,
    challenge: &[u8; 32],
    expected_public_hex: &str,
    roots: &[Vec<u8>],
    now_s: i64,
) -> Result<Attested, String> {
    let (st, cdh, rp_hash, whole): (Statement, Vec<u8>, Vec<u8>, &[u8]) = match container {
        Container::OpenSsh { blob, application } => (
            parse_openssh_blob(blob)?,
            sha(challenge),
            sha(application.as_bytes()),
            blob,
        ),
        Container::Webauthn {
            object,
            client_data_json,
            rp_id,
            origin,
        } => {
            let cd: serde_json::Value = serde_json::from_slice(client_data_json)
                .map_err(|_| "the attestation's client data is not valid".to_string())?;
            if cd["type"].as_str() != Some("webauthn.create") {
                return Err("the attestation's client data is not for a key being made".into());
            }
            let got = cd["challenge"]
                .as_str()
                .and_then(decode_url)
                .ok_or("the client data names no challenge")?;
            if got != challenge {
                return Err("that attestation was made for another enrolment (not the challenge this box issued)".into());
            }
            if cd["origin"].as_str() != Some(origin) || cd["crossOrigin"].as_bool() == Some(true) {
                return Err("that attestation is from another origin".into());
            }
            (
                parse_webauthn_object(object)?,
                sha(client_data_json),
                sha(rp_id.as_bytes()),
                object,
            )
        }
    };
    let cred = parse_auth_data(&st.auth_data)?;
    if cred.rp_id_hash != rp_hash {
        return Err("that attestation is for another relying party or application".into());
    }
    if cred.flags & 0x01 == 0 {
        return Err("that attestation was made without a touch".into());
    }
    if hex(&cred.public) != expected_public_hex {
        return Err("the attested key is not the key being enrolled".into());
    }
    // the chain first: a statement whose certificate is not a trusted one proves nothing, whatever it signs
    let root_sha256 = verify_chain(&st.x5c, roots, now_s)?;
    let leaf = parse_cert(&st.x5c[0]).ok_or("the attestation's certificate is not valid")?;
    // what the leaf signed: `packed` is authData || clientDataHash; `fido-u2f` is 0x00 || rpIdHash || clientDataHash ||
    // credentialId || the key as a U2F point. An OpenSSH blob does not say which, so both are tried.
    let packed = {
        let mut m = st.auth_data.clone();
        m.extend_from_slice(&cdh);
        m
    };
    let u2f = (cred.alg == -7 && cred.public.len() == 65).then(|| {
        let mut m = vec![0u8];
        m.extend_from_slice(&cred.rp_id_hash);
        m.extend_from_slice(&cdh);
        m.extend_from_slice(&cred.credential_id);
        m.extend_from_slice(&cred.public);
        m
    });
    // the leaf's own signature algorithm is its key's: ECDSA over SHA-256 for a P-256 key, RSA PKCS#1 SHA-256 for RSA
    let leaf_alg: &[u8] = if leaf.spki_alg == OID_RSA_ENCRYPTION {
        OID_RSA_SHA256
    } else {
        OID_ECDSA_SHA256
    };
    let ok = |m: &[u8]| {
        verify_with_spki(
            leaf.spki_alg,
            leaf.spki_param,
            leaf.key,
            leaf_alg,
            m,
            &st.sig,
        )
    };
    let signed_packed = |f: &str| (f == "packed" || f.is_empty()) && ok(&packed);
    let signed_u2f = |f: &str| (f == "fido-u2f" || f.is_empty()) && u2f.as_deref().is_some_and(ok);
    let is_packed = if signed_packed(&st.fmt) {
        true
    } else if signed_u2f(&st.fmt) {
        false
    } else {
        return Err("the attestation's signature is not valid".into());
    };
    check_fido_leaf(&leaf, is_packed, &cred.aaguid)?;
    if !is_packed {
        check_u2f_shape(&st.x5c, &leaf)?;
    }
    Ok(Attested {
        public_half: hex(&cred.public),
        credential_id: hex(&cred.credential_id),
        aaguid: hex(&cred.aaguid),
        root_sha256,
        digest: hex(&sha(whole)),
    })
}

#[cfg(test)]
mod fixtures;
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
