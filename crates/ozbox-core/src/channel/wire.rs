//! The envelope every Oz Box channel speaks, its canonical bytes and the seams it signs and seals through.
//!
//! One envelope, two profiles today (the worker channel and the agent mesh, ADR 0042 and 0044). A [`Profile`] supplies the domain
//! tag, the closed list of kinds, the body cap and the check of the signed `ext` bytes; everything else is here once, so a fix to
//! replay, ordering or acknowledgement is made once.
//!
//! The signature covers every field, in a fixed order, each length-prefixed ([`crate::approval_subject::Encoder`]). The body is
//! sealed to the receiver with the header bytes as authenticated data, and the signature is over the envelope **as sealed**, so a
//! transport verifies without opening anything.

use serde::{Deserialize, Serialize};

use crate::approval_subject::{to_hex, Encoder};

/// The envelope's own version, the first field after the domain tag. A receiver accepts exactly this version. Until a version 2
/// exists there is no "one before"; when it does, the rule is written in the ADR before the code accepts it.
pub const VERSION: u64 = 1;

/// How far a message's `ts_ms` may be from the receiver's clock, in either direction. One value for every profile.
pub const MAX_SKEW_MS: u64 = 2 * 60 * 1000;

/// The longest an envelope stays valid. The sender re-signs on every delivery attempt, so this is not a task's deadline.
pub const MAX_VALIDITY_MS: u64 = 10 * 60 * 1000;

/// How many sequence numbers ahead of the next expected one the receiver buffers, and how many it remembers having applied
/// (the per-number hash window that tells a retry from a conflicting reuse).
pub const WINDOW: u64 = 64;

/// What sealing adds to a body (the encapsulated key and the tag).
pub const SEAL_OVERHEAD: usize = 48;

/// The most one round puts on the wire in one direction, as [`wire_size`] counts it. A round is cut at this size (always keeping at
/// least one message), so a window of large messages is sent over several rounds and never becomes one transfer larger than a
/// transport accepts. Half of [`TRANSPORT_CAP`], leaving room for the `hello`, the `ack` and the estimate's error.
pub const ROUND_BYTES: usize = 4 * 1024 * 1024;

/// The most a transport reads of one round's request or reply. The senders' budget above is sized from it, never the other way.
pub const TRANSPORT_CAP: usize = 8 * 1024 * 1024;

const _: () = assert!(ROUND_BYTES * 2 <= TRANSPORT_CAP);

/// What one sequenced message costs on the wire: its sealed body and its `ext` written as hex (twice their size), and the envelope's
/// own fields and signature. An upper estimate, used to cut a round before it is built.
pub fn wire_size(ext_len: usize, plain_len: usize) -> usize {
    2 * (plain_len + SEAL_OVERHEAD + ext_len) + 1536
}

/// The largest signed `ext` a profile may carry.
pub const MAX_EXT: usize = 1024;

/// The two control kinds every profile has. They carry `seq = 0` and are never acknowledged by number.
pub const KIND_HELLO: &str = "hello";
pub const KIND_ACK: &str = "ack";

/// What a profile supplies. A `static`, so a profile is a constant of the code that owns the protocol, never data.
pub struct Profile {
    /// The domain tag: a message of one profile never verifies as another's.
    pub tag: &'static str,
    /// The audit action prefix (`hub`, `mesh`).
    pub audit: &'static str,
    /// The application kinds, closed. Every one is sequenced, acknowledged and kept until it is. (`hello` and `ack` are the
    /// channel's own and are not listed.) Names are on the wire.
    pub kinds: &'static [&'static str],
    /// The most bytes one sealed body may be.
    pub max_body: usize,
    /// Whether the signed `ext` is well formed for the kind. The profile defines its meaning (a task id, a level and relay hops).
    pub check_ext: fn(kind: &str, ext: &[u8]) -> bool,
}

impl Profile {
    pub fn knows(&self, kind: &str) -> bool {
        kind == KIND_HELLO || kind == KIND_ACK || self.kinds.contains(&kind)
    }

    /// Sequenced kinds are ordered and de-duplicated by `seq`. The control kinds carry `seq = 0`.
    pub fn sequenced(&self, kind: &str) -> bool {
        self.kinds.contains(&kind)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    Version,
    /// A field is malformed; the word names it (and is the audit code).
    Shape(&'static str),
    TooBig,
    BadSignature,
    BadSeal,
    /// The signing seam failed (a socket to the secrets service, say).
    SignFailed,
    /// The sealing seam failed.
    SealFailed,
}

impl WireError {
    /// The audit word for this error.
    pub fn code(&self) -> String {
        match self {
            WireError::Version => "version".into(),
            WireError::Shape(w) => format!("shape:{w}"),
            WireError::TooBig => "too-big".into(),
            WireError::BadSignature => "bad-signature".into(),
            WireError::BadSeal => "unopenable".into(),
            WireError::SignFailed => "sign-failed".into(),
            WireError::SealFailed => "seal-failed".into(),
        }
    }
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WireError::Version => f.write_str("the envelope version is not supported"),
            WireError::Shape(w) => write!(f, "{w} is not valid"),
            WireError::TooBig => f.write_str("the message body is larger than one message carries"),
            WireError::BadSignature => f.write_str("the signature does not verify"),
            WireError::BadSeal => f.write_str("the message could not be opened"),
            WireError::SignFailed => f.write_str("the message could not be signed"),
            WireError::SealFailed => f.write_str("the message could not be sealed"),
        }
    }
}

/// A name: the shape of every box id, message id and task id on the wire.
pub fn word_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

fn fp_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 71
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b) || b == b'-')
}

/// An envelope with its body sealed to the receiver (or, before sealing, plain: the seam says which).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub version: u64,
    pub kind: String,
    pub from: String,
    pub to: String,
    /// The fingerprint of the receiver's sealing key ([`fingerprint`]): a message for one receiver never verifies for another.
    pub receiver_fp: String,
    /// The sender's epoch, and the epoch the sender believes the receiver is in. Both are checked. An end's epoch changes only
    /// when its state is restored or its keys are replaced; the peer then pins the new one.
    pub sender_epoch: u64,
    pub receiver_epoch: u64,
    /// The sender's incarnation: random, fresh whenever its state is created or restored, so losing state can never make an
    /// old message verify again.
    pub sender_inc: u64,
    /// The incarnation of the receiver the sender believes it is talking to. 0 is valid only in a `hello`, which is how an end
    /// learns the peer's incarnation.
    pub receiver_inc: u64,
    pub seq: u64,
    /// Cumulative: the highest `seq` the sender has applied from the receiver in this incarnation pair.
    pub ack_seq: u64,
    pub id: String,
    pub ts_ms: u64,
    pub valid_until_ms: u64,
    #[serde(with = "hex_bytes")]
    pub nonce: Vec<u8>,
    /// Profile-defined bytes that are signed with the rest (a task id; a level and relay hops).
    #[serde(with = "hex_bytes")]
    pub ext: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub body: Vec<u8>,
}

impl Envelope {
    /// Checks that hold for any envelope, sent or received.
    pub fn check(&self, p: &Profile) -> Result<(), WireError> {
        if self.version != VERSION {
            return Err(WireError::Version);
        }
        if !p.knows(&self.kind) {
            return Err(WireError::Shape("kind"));
        }
        if self.body.len() > p.max_body {
            return Err(WireError::TooBig);
        }
        for (what, v) in [("from", &self.from), ("to", &self.to), ("id", &self.id)] {
            if !word_ok(v) {
                return Err(WireError::Shape(what));
            }
        }
        if !fp_ok(&self.receiver_fp) {
            return Err(WireError::Shape("receiver_fp"));
        }
        if self.sender_inc == 0 {
            return Err(WireError::Shape("sender_inc"));
        }
        if self.nonce.len() != 16 {
            return Err(WireError::Shape("nonce"));
        }
        if self.valid_until_ms < self.ts_ms || self.valid_until_ms - self.ts_ms > MAX_VALIDITY_MS {
            return Err(WireError::Shape("validity"));
        }
        if p.sequenced(&self.kind) != (self.seq != 0) {
            return Err(WireError::Shape("seq"));
        }
        // the control kinds sign no ext; a sequenced kind's ext is the profile's to judge
        if self.ext.len() > MAX_EXT
            || (!p.sequenced(&self.kind) && !self.ext.is_empty())
            || (p.sequenced(&self.kind) && !(p.check_ext)(&self.kind, &self.ext))
        {
            return Err(WireError::Shape("ext"));
        }
        if self.kind != KIND_HELLO && self.receiver_inc == 0 {
            return Err(WireError::Shape("receiver_inc"));
        }
        Ok(())
    }

    /// The canonical bytes that are signed: ADR 0041's encoding-version byte, the profile's tag, the envelope version, then every
    /// field in this order. A new field goes at the end, under a new version.
    pub fn canonical(&self, p: &Profile) -> Vec<u8> {
        let mut e = Encoder::new(p.tag);
        e.u64(self.version)
            .text(&self.kind)
            .text(&self.from)
            .text(&self.to)
            .text(&self.receiver_fp)
            .u64(self.sender_epoch)
            .u64(self.receiver_epoch)
            .u64(self.sender_inc)
            .u64(self.receiver_inc)
            .u64(self.seq)
            .u64(self.ack_seq)
            .text(&self.id)
            .u64(self.ts_ms)
            .u64(self.valid_until_ms)
            .field(&self.nonce)
            .field(&self.ext)
            .field(&self.body);
        e.bytes().to_vec()
    }

    /// What the body is sealed to: every field except the body itself.
    pub fn aad(&self, p: &Profile) -> Vec<u8> {
        let mut bare = self.clone();
        bare.body = Vec::new();
        bare.canonical(p)
    }

    /// The digest of the canonical bytes, in hex: what a log names a message by.
    pub fn digest_hex(&self, p: &Profile) -> String {
        let mut e = Encoder::new(p.tag);
        e.field(&self.canonical(p));
        to_hex(&e.digest())
    }
}

/// What travels: the envelope (body sealed) and the signature over its canonical bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sealed {
    pub envelope: Envelope,
    #[serde(with = "hex_bytes")]
    pub signature: Vec<u8>,
}

/// Signs canonical bytes as this end. Fallible: the real one is a socket to the secrets service, never a key in this process.
pub trait Signer: Send + Sync {
    fn sign(&self, canonical: &[u8]) -> Result<Vec<u8>, WireError>;
}

/// Checks a signature against the key the pin or roster holds for the sender (never a name looked up inside the verifier). The
/// string is opaque to the channel: a public key in hex, or a key fingerprint.
pub trait Verifier: Send + Sync {
    fn verify(&self, sender_key: &str, canonical: &[u8], signature: &[u8]) -> bool;
}

/// Seals a body to the receiver's key and opens one sealed to this end. The real one is HPKE through `ozbox-seal`.
pub trait Sealer: Send + Sync {
    fn seal(&self, receiver_key: &str, aad: &[u8], plain: &[u8]) -> Result<Vec<u8>, WireError>;
    fn open(&self, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, WireError>;
}

/// The three seams, borrowed.
#[derive(Clone, Copy)]
pub struct Crypto<'a> {
    pub signer: &'a dyn Signer,
    pub verifier: &'a dyn Verifier,
    pub sealer: &'a dyn Sealer,
}

/// Seal `plain` as the body, check, and sign: the one way an envelope is made.
pub fn seal_and_sign(
    p: &Profile,
    mut env: Envelope,
    receiver_key: &str,
    plain: &[u8],
    cx: &Crypto<'_>,
) -> Result<Sealed, WireError> {
    env.body = Vec::new();
    let aad = env.aad(p);
    env.body = cx.sealer.seal(receiver_key, &aad, plain)?;
    env.check(p)?;
    let signature = cx.signer.sign(&env.canonical(p))?;
    Ok(Sealed {
        envelope: env,
        signature,
    })
}

/// The one fingerprint of a key, over the key's **bytes**: SHA-256 of a fixed tag and the key, first 16 bytes, in groups of eight
/// hex digits. `ozbox-seal` computes the same value for the same bytes (a known-vector test in each crate pins the two together),
/// so a person comparing a pin and a machine checking a header always see one string for one key.
pub fn fingerprint(key: &[u8]) -> String {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    ctx.update(b"ozbox-seal-key/1");
    ctx.update(key);
    let d = ctx.finish();
    let hex = to_hex(&d.as_ref()[..16]);
    hex.as_bytes()
        .chunks(8)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join("-")
}

/// Lower-case hex of bytes.
pub fn hex(b: &[u8]) -> String {
    to_hex(b)
}

/// Bytes from hex, either case.
pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// A key written in hex, in its one stored form: lower case.
pub fn normalize_hex(s: &str) -> Option<String> {
    unhex(s).map(|b| to_hex(&b))
}

pub mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::hex(b))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        super::unhex(&s).ok_or_else(|| serde::de::Error::custom("not hex"))
    }
}
