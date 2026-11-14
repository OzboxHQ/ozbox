//! The mesh envelope (ADR 0044 section 2.3). Preview: the format is **not frozen**.

use serde::{Deserialize, Serialize};

use crate::approval_subject::{to_hex, Encoder};

/// The envelope's own version, encoded as the first field after the tag (so a change here is visible on the wire and is
/// not confused with the shared encoder's byte). A receiver refuses any other.
pub const ENVELOPE_VERSION: u64 = 1;
pub const ENVELOPE_TAG: &str = "ozbox-mesh-envelope";
/// The longest an envelope stays valid. Separate from a task's deadline: the sender re-signs on every delivery attempt.
pub const MAX_VALIDITY_MS: u64 = 10 * 60 * 1000;
/// How far a sender's clock may run ahead of the receiver's.
pub const SKEW_MS: u64 = 60 * 1000;
/// The most bytes one sealed body may be.
pub const MAX_BODY: usize = 96 * 1024;

/// Every kind of envelope. **Closed**: a new kind is a new protocol version. Names are on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kind {
    Hello,
    Task,
    Message,
    Status,
    Artifact,
    Cancel,
    Resync,
}

impl Kind {
    pub const ALL: [Kind; 7] = [
        Kind::Hello,
        Kind::Task,
        Kind::Message,
        Kind::Status,
        Kind::Artifact,
        Kind::Cancel,
        Kind::Resync,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Kind::Hello => "hello",
            Kind::Task => "task",
            Kind::Message => "message",
            Kind::Status => "status",
            Kind::Artifact => "artifact",
            Kind::Cancel => "cancel",
            Kind::Resync => "resync",
        }
    }

    /// Sequenced kinds are ordered and de-duplicated by `seq`. The others are control and carry `seq = 0`.
    pub fn sequenced(self) -> bool {
        matches!(
            self,
            Kind::Task | Kind::Message | Kind::Status | Kind::Artifact | Kind::Cancel
        )
    }
}

/// An envelope with its body sealed to the receiver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub version: u64,
    pub kind: Kind,
    pub from: String,
    pub to: String,
    /// Fingerprint of the receiver's sealing key: a message for one receiver never verifies for another.
    pub receiver_fp: String,
    /// The sender's epoch, and the epoch the sender believes the receiver is in. Both are checked.
    pub sender_epoch: u64,
    pub receiver_epoch: u64,
    /// The sender's incarnation (a number that rises each time the sender's state is created or restored).
    pub incarnation: u64,
    pub seq: u64,
    /// The highest sequence number the sender has applied from the receiver (cumulative acknowledgement).
    pub ack_seq: u64,
    pub id: String,
    pub task_id: String,
    pub ts_ms: u64,
    pub valid_until_ms: u64,
    #[serde(with = "hex_bytes")]
    pub nonce: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    Version,
    Shape(&'static str),
    TooBig,
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WireError::Version => f.write_str("version"),
            WireError::Shape(w) => write!(f, "shape:{w}"),
            WireError::TooBig => f.write_str("too-big"),
        }
    }
}

pub fn word_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

impl Envelope {
    /// Checks that hold for any envelope, sent or received.
    pub fn check(&self) -> Result<(), WireError> {
        if self.version != ENVELOPE_VERSION {
            return Err(WireError::Version);
        }
        if self.body.len() > MAX_BODY {
            return Err(WireError::TooBig);
        }
        for (what, v) in [("from", &self.from), ("to", &self.to), ("id", &self.id)] {
            if !word_ok(v) {
                return Err(WireError::Shape(what));
            }
        }
        if !(self.task_id.is_empty() || word_ok(&self.task_id)) {
            return Err(WireError::Shape("task_id"));
        }
        if self.nonce.len() != 16 {
            return Err(WireError::Shape("nonce"));
        }
        if self.valid_until_ms < self.ts_ms || self.valid_until_ms - self.ts_ms > MAX_VALIDITY_MS {
            return Err(WireError::Shape("validity"));
        }
        if self.kind.sequenced() != (self.seq != 0) {
            return Err(WireError::Shape("seq"));
        }
        Ok(())
    }

    /// The canonical bytes that are signed: tag, then the version, then every field in a fixed order.
    pub fn canonical(&self) -> Vec<u8> {
        let mut e = Encoder::new(ENVELOPE_TAG);
        e.u64(self.version)
            .text(self.kind.name())
            .text(&self.from)
            .text(&self.to)
            .text(&self.receiver_fp)
            .u64(self.sender_epoch)
            .u64(self.receiver_epoch)
            .u64(self.incarnation)
            .u64(self.seq)
            .u64(self.ack_seq)
            .text(&self.id)
            .text(&self.task_id)
            .u64(self.ts_ms)
            .u64(self.valid_until_ms)
            .field(&self.nonce)
            .field(&self.body);
        e.bytes().to_vec()
    }

    /// What the body is sealed to: every field except the body itself.
    pub fn aad(&self) -> Vec<u8> {
        let mut bare = self.clone();
        bare.body = Vec::new();
        bare.canonical()
    }

    pub fn digest_hex(&self) -> String {
        let mut e = Encoder::new(ENVELOPE_TAG);
        e.field(&self.canonical());
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

/// Signs canonical bytes as this endpoint. Fallible: the real one may be a socket to another service.
pub trait Signer: Send + Sync {
    fn sign(&self, canonical: &[u8]) -> Result<Vec<u8>, String>;
}

/// Checks a signature against the **public key the pin holds** for the sender (never a name looked up inside the verifier).
pub trait Verifier: Send + Sync {
    fn verify(&self, signer_public_hex: &str, canonical: &[u8], signature: &[u8]) -> bool;
}

/// Seals a body to the receiver's sealing public key (hex) and opens one sealed to this endpoint.
pub trait Sealer: Send + Sync {
    fn seal(
        &self,
        receiver_seal_public_hex: &str,
        aad: &[u8],
        plain: &[u8],
    ) -> Result<Vec<u8>, String>;
    fn open(&self, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, String>;
}

/// Moves sealed envelopes between two endpoints. The network is not trusted: a transport only moves bytes. One call carries
/// what this end has for the peer and returns what the peer has for this end (a request and its reply).
pub trait Transport {
    fn exchange(&self, peer: &str, outbound: &[Sealed]) -> Result<Vec<Sealed>, String>;
}

pub mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::super::crypto::to_hex(b))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        super::super::crypto::from_hex(&s).ok_or_else(|| serde::de::Error::custom("not hex"))
    }
}
