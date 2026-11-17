//! A small, strict reader for the DER and BER that an instance identity document's PKCS#7 signature and its certificate use.
//!
//! It reads only what verification needs: a certificate's RSA public key, and a PKCS#7 `SignedData`'s content, signed
//! attributes, digest and signature. It never allocates from a length it has not checked against the input, refuses nesting
//! deeper than [`MAX_DEPTH`], and accepts the indefinite-length form `openssl` writes when it streams. Every failure is the same
//! `None`: a caller says "malformed", never what part, so a probe learns nothing about the parser.

/// Deeper than any certificate or PKCS#7 this reads.
pub const MAX_DEPTH: usize = 8;

pub const SEQUENCE: u8 = 0x30;
pub const SET: u8 = 0x31;
pub const INTEGER: u8 = 0x02;
pub const BIT_STRING: u8 = 0x03;
pub const OCTET_STRING: u8 = 0x04;
pub const OID: u8 = 0x06;
/// Context-specific, constructed, number 0 (EXPLICIT wrappers and IMPLICIT SETs).
pub const CTX0: u8 = 0xA0;
pub const CTX1: u8 = 0xA1;

/// One element: its tag and its content. `whole` is the encoded element, header included.
#[derive(Debug, Clone, Copy)]
pub struct Tlv<'a> {
    pub tag: u8,
    pub content: &'a [u8],
    pub whole: &'a [u8],
    pub indefinite: bool,
}

/// Read one element from the front of `input`; returns it and what follows.
pub fn read(input: &[u8]) -> Option<(Tlv<'_>, &[u8])> {
    read_depth(input, 0)
}

fn read_depth(input: &[u8], depth: usize) -> Option<(Tlv<'_>, &[u8])> {
    if depth > MAX_DEPTH {
        return None;
    }
    let tag = *input.first()?;
    // multi-byte tags are never used here
    if tag & 0x1f == 0x1f {
        return None;
    }
    let l0 = *input.get(1)?;
    if l0 == 0x80 {
        // indefinite length: only for a constructed element; children until a 00 00 marker
        if tag & 0x20 == 0 {
            return None;
        }
        let mut rest = input.get(2..)?;
        let start = rest;
        loop {
            if rest.len() >= 2 && rest[0] == 0 && rest[1] == 0 {
                let used = start.len() - rest.len();
                let content = &start[..used];
                let whole_len = 2 + used + 2;
                let whole = input.get(..whole_len)?;
                return Some((
                    Tlv {
                        tag,
                        content,
                        whole,
                        indefinite: true,
                    },
                    &input[whole_len..],
                ));
            }
            let (_, after) = read_depth(rest, depth + 1)?;
            rest = after;
        }
    }
    let (len, hdr) = if l0 < 0x80 {
        (l0 as usize, 2)
    } else {
        let n = (l0 & 0x7f) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        let bytes = input.get(2..2 + n)?;
        let mut len = 0usize;
        for b in bytes {
            len = (len << 8) | *b as usize;
        }
        (len, 2 + n)
    };
    let end = hdr.checked_add(len)?;
    let whole = input.get(..end)?;
    Some((
        Tlv {
            tag,
            content: &whole[hdr..],
            whole,
            indefinite: false,
        },
        &input[end..],
    ))
}

/// Every child of a constructed element's content.
pub fn children(content: &[u8]) -> Option<Vec<Tlv<'_>>> {
    let mut out = Vec::new();
    let mut rest = content;
    while !rest.is_empty() {
        let (t, after) = read(rest)?;
        out.push(t);
        rest = after;
    }
    Some(out)
}

/// The octets of an OCTET STRING, primitive or constructed (segments joined).
pub fn octets(t: &Tlv<'_>) -> Option<Vec<u8>> {
    match t.tag {
        OCTET_STRING => Some(t.content.to_vec()),
        0x24 => {
            let mut out = Vec::new();
            for c in children(t.content)? {
                if c.tag != OCTET_STRING {
                    return None;
                }
                out.extend_from_slice(c.content);
            }
            Some(out)
        }
        _ => None,
    }
}

/// The dotted-number-free form of an OID: its content bytes, compared against the constants below.
pub const OID_SIGNED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
pub const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
pub const OID_RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
pub const OID_SHA256_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
pub const OID_MESSAGE_DIGEST: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04];

/// The RSA public key (`RSAPublicKey` DER, what the verifier takes) inside an X.509 certificate, and its modulus size in bits.
pub fn certificate_rsa_key(cert_der: &[u8]) -> Option<(Vec<u8>, usize)> {
    let (cert, rest) = read(cert_der)?;
    if cert.tag != SEQUENCE || !rest.is_empty() {
        return None;
    }
    let tbs = children(cert.content)?.into_iter().next()?;
    if tbs.tag != SEQUENCE {
        return None;
    }
    let fields = children(tbs.content)?;
    // [0] version is optional; then serial, signature, issuer, validity, subject, subjectPublicKeyInfo
    let skip = usize::from(fields.first()?.tag == CTX0);
    let spki = fields.get(skip + 5)?;
    if spki.tag != SEQUENCE {
        return None;
    }
    let parts = children(spki.content)?;
    let alg = children(parts.first()?.content)?;
    if alg.first()?.tag != OID || alg.first()?.content != OID_RSA_ENCRYPTION {
        return None;
    }
    let bits = parts.get(1)?;
    if bits.tag != BIT_STRING || bits.content.first() != Some(&0) {
        return None;
    }
    let key = bits.content.get(1..)?.to_vec();
    // RSAPublicKey ::= SEQUENCE { modulus INTEGER, exponent INTEGER }
    let (k, tail) = read(&key)?;
    if k.tag != SEQUENCE || !tail.is_empty() {
        return None;
    }
    let ints = children(k.content)?;
    let modulus = ints.first()?;
    if modulus.tag != INTEGER {
        return None;
    }
    let m = match modulus.content.split_first() {
        Some((0, rest)) => rest,
        _ => modulus.content,
    };
    let top = *m.first()?;
    let bit_len = m.len() * 8 - top.leading_zeros() as usize;
    Some((key, bit_len))
}

/// What the verifier needs from a PKCS#7 `SignedData` with one signer and the content inside it.
#[derive(Debug)]
pub struct SignedData {
    /// The signed content (the identity document).
    pub content: Vec<u8>,
    /// The bytes the RSA signature covers: the content itself, or the DER `SET OF` signed attributes.
    pub signed_bytes: Vec<u8>,
    /// The signature.
    pub signature: Vec<u8>,
    /// With signed attributes: the digest they carry for the content, to be compared with the content's own.
    pub message_digest: Option<Vec<u8>>,
}

/// Parse a DER or BER PKCS#7 `SignedData`. Only SHA-256 with RSA, one signer, content embedded.
pub fn signed_data(pkcs7: &[u8]) -> Option<SignedData> {
    let (ci, rest) = read(pkcs7)?;
    if ci.tag != SEQUENCE || !rest.iter().all(|b| *b == 0) {
        return None;
    }
    let top = children(ci.content)?;
    if top.first()?.tag != OID || top.first()?.content != OID_SIGNED_DATA {
        return None;
    }
    let explicit = top.get(1)?;
    if explicit.tag != CTX0 {
        return None;
    }
    let (sd, _) = read(explicit.content)?;
    if sd.tag != SEQUENCE {
        return None;
    }
    let f = children(sd.content)?;
    // version, digestAlgorithms, encapContentInfo, [0] certificates?, [1] crls?, signerInfos
    let encap = f.get(2)?;
    if encap.tag != SEQUENCE {
        return None;
    }
    let ec = children(encap.content)?;
    let wrapped = ec.get(1)?;
    if wrapped.tag != CTX0 {
        return None;
    }
    let (inner, _) = read(wrapped.content)?;
    let content = octets(&inner)?;
    let signers = f.iter().rev().find(|t| t.tag == SET)?;
    let infos = children(signers.content)?;
    if infos.len() != 1 || infos[0].tag != SEQUENCE {
        return None;
    }
    let si = children(infos[0].content)?;
    // version, sid, digestAlgorithm, [0] signedAttrs?, signatureAlgorithm, signature
    let digest_alg = children(si.get(2)?.content)?;
    if digest_alg.first()?.content != OID_SHA256 {
        return None;
    }
    let mut i = 3;
    let mut signed_bytes = content.clone();
    let mut message_digest = None;
    if si.get(i)?.tag == CTX0 {
        let attrs = si[i];
        // the signature covers the attributes re-tagged as a SET OF
        let mut v = attrs.whole.to_vec();
        if attrs.indefinite {
            return None;
        }
        v[0] = SET;
        signed_bytes = v;
        for a in children(attrs.content)? {
            let parts = children(a.content)?;
            if parts.first()?.content == OID_MESSAGE_DIGEST {
                let vals = children(parts.get(1)?.content)?;
                message_digest = Some(octets(vals.first()?)?);
            }
        }
        message_digest.as_ref()?;
        i += 1;
    }
    let sig_alg = children(si.get(i)?.content)?;
    let oid = sig_alg.first()?.content;
    if oid != OID_RSA_ENCRYPTION && oid != OID_SHA256_WITH_RSA {
        return None;
    }
    let signature = octets(si.get(i + 1)?)?;
    Some(SignedData {
        content,
        signed_bytes,
        signature,
        message_digest,
    })
}

/// Standard base64, whitespace ignored, padding required. `None` for anything else.
pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut acc = 0u32;
    let mut n = 0;
    let mut pad = 0;
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => {
                pad += 1;
                continue;
            }
            b' ' | b'\n' | b'\r' | b'\t' => continue,
            _ => return None,
        };
        if pad > 0 {
            return None;
        }
        acc = (acc << 6) | u32::from(v);
        n += 1;
        if n == 4 {
            out.extend_from_slice(&[(acc >> 16) as u8, (acc >> 8) as u8, acc as u8]);
            acc = 0;
            n = 0;
        }
    }
    match (n, pad) {
        (0, 0) => {}
        (2, 2) => out.push((acc >> 4) as u8),
        (3, 1) => out.extend_from_slice(&[(acc >> 10) as u8, (acc >> 2) as u8]),
        _ => return None,
    }
    Some(out)
}

/// `YYYY-MM-DDTHH:MM:SSZ` as milliseconds since the epoch. Only the form AWS writes.
pub fn rfc3339_ms(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return None;
    }
    let num = |a: usize, z: usize| -> Option<i64> { s.get(a..z)?.parse::<i64>().ok() };
    let (y, mo, d) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (h, mi, se) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    if !(1970..=9999).contains(&y)
        || !(1..=12).contains(&mo)
        || !(1..=31).contains(&d)
        || h > 23
        || mi > 59
        || se > 60
    {
        return None;
    }
    // days from civil
    let y2 = if mo <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * (mo + if mo > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86_400 + h * 3600 + mi * 60 + se;
    u64::try_from(secs).ok()?.checked_mul(1000)
}
