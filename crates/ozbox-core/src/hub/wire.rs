//! The frozen envelope of the worker channel (ADR 0042 section 1, "Canonical encoding", and section 6).

use serde::{Deserialize, Serialize};

use crate::approval_subject::{to_hex, Encoder};

/// The envelope's own version. A receiver refuses any other.
pub const ENVELOPE_VERSION: u8 = 1;

/// The domain tag. The receiver's key fingerprint and the hub's epoch follow it as fields, so a message for one receiver or one
/// epoch never verifies for another.
pub const ENVELOPE_TAG: &str = "ozbox-hub-envelope-v1";

/// The depth of the tree: `main` is level 0, its workers 1, their workers 2. Nothing deeper exists (ADR 0042 section 14).
pub const MAX_LEVEL: u8 = 2;

/// The largest body one envelope carries. Bigger things travel as an artifact the hub pulls, by name, size and hash.
pub const MAX_BODY: usize = 256 * 1024;

/// Every message kind of the channel, in the order of ADR 0042 section 6. **Frozen**: a kind is added at the end, never
/// renamed, never reordered (the names are on the wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Kind {
    TaskAssign,
    Question,
    Answer,
    Status,
    Blocked,
    ContractChanged,
    Result,
    ApprovalRequest,
    ApprovalDecision,
    KeysDeliver,
    KeysRevoke,
    LeaseRenew,
    PinsSet,
    LaptopRelay,
    ShardAssign,
    ShardResult,
    ArtifactOffer,
    ArtifactPull,
    AuditHead,
    AuditSegments,
    Hello,
    Heartbeat,
    Bye,
}

impl Kind {
    pub const ALL: [Kind; 23] = [
        Kind::TaskAssign,
        Kind::Question,
        Kind::Answer,
        Kind::Status,
        Kind::Blocked,
        Kind::ContractChanged,
        Kind::Result,
        Kind::ApprovalRequest,
        Kind::ApprovalDecision,
        Kind::KeysDeliver,
        Kind::KeysRevoke,
        Kind::LeaseRenew,
        Kind::PinsSet,
        Kind::LaptopRelay,
        Kind::ShardAssign,
        Kind::ShardResult,
        Kind::ArtifactOffer,
        Kind::ArtifactPull,
        Kind::AuditHead,
        Kind::AuditSegments,
        Kind::Hello,
        Kind::Heartbeat,
        Kind::Bye,
    ];

    /// The name on the wire.
    pub fn name(self) -> &'static str {
        match self {
            Kind::TaskAssign => "task.assign",
            Kind::Question => "question",
            Kind::Answer => "answer",
            Kind::Status => "status",
            Kind::Blocked => "blocked",
            Kind::ContractChanged => "contract.changed",
            Kind::Result => "result",
            Kind::ApprovalRequest => "approval.request",
            Kind::ApprovalDecision => "approval.decision",
            Kind::KeysDeliver => "keys.deliver",
            Kind::KeysRevoke => "keys.revoke",
            Kind::LeaseRenew => "lease.renew",
            Kind::PinsSet => "pins.set",
            Kind::LaptopRelay => "laptop.relay",
            Kind::ShardAssign => "shard.assign",
            Kind::ShardResult => "shard.result",
            Kind::ArtifactOffer => "artifact.offer",
            Kind::ArtifactPull => "artifact.pull",
            Kind::AuditHead => "audit.head",
            Kind::AuditSegments => "audit.segments",
            Kind::Hello => "hello",
            Kind::Heartbeat => "heartbeat",
            Kind::Bye => "bye",
        }
    }

    pub fn parse(name: &str) -> Option<Kind> {
        Kind::ALL.into_iter().find(|k| k.name() == name)
    }

    /// Whether a message of this kind is acknowledged and kept until it is (the others are "the latest wins" or liveness).
    pub fn acknowledged(self) -> bool {
        !matches!(
            self,
            Kind::Status | Kind::Hello | Kind::Heartbeat | Kind::Bye
        )
    }

    /// Whether only the hub sends it (to a worker). A worker that receives the reverse is quarantined by the engine.
    pub fn hub_to_worker(self) -> bool {
        matches!(
            self,
            Kind::TaskAssign
                | Kind::Answer
                | Kind::ContractChanged
                | Kind::ApprovalDecision
                | Kind::KeysDeliver
                | Kind::KeysRevoke
                | Kind::LeaseRenew
                | Kind::PinsSet
                | Kind::LaptopRelay
                | Kind::ShardAssign
                | Kind::ArtifactPull
        )
    }
}

/// One hop of a relayed message (a sub-hub adds one). Present in the schema now so the envelope never changes shape when nested
/// hubs ship; this release sends none and a receiver at level 1 refuses any.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hop {
    pub box_id: String,
    pub key_fp: String,
}

/// A message, before signing and sealing. The body is opaque to the transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub kind: Kind,
    /// The sender's box id (the hub's, or the worker's).
    pub from: String,
    /// The receiver's box id.
    pub to: String,
    /// The receiver's key fingerprint (lowercase hex). Part of the domain, so a message cannot be replayed to another box.
    pub receiver_fp: String,
    /// The hub's epoch: it changes on a repin or a replace, so an old hub's messages do not verify for the new one.
    pub epoch: u64,
    /// Per worker and direction. Starts at 1 and restarts only with a new enrolment or a repin.
    pub seq: u64,
    /// A message id, for de-duplication.
    pub id: String,
    pub ts_ms: u64,
    /// The sender's level in the tree (0 for `main`).
    pub level: u8,
    pub via: Vec<Hop>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    TooBig,
    BadLevel,
    NoRelayYet,
    BadName(&'static str),
    BadKind,
    BadSignature,
    BadSeal,
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WireError::TooBig => f.write_str("the message body is larger than one message carries"),
            WireError::BadLevel => f.write_str("the level is deeper than the tree allows"),
            WireError::NoRelayYet => {
                f.write_str("relayed messages are not accepted in this release")
            }
            WireError::BadName(w) => write!(f, "{w} is not a valid name"),
            WireError::BadKind => f.write_str("that is not a message kind"),
            WireError::BadSignature => f.write_str("the signature does not verify"),
            WireError::BadSeal => f.write_str("the message could not be opened"),
        }
    }
}

fn word_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_' || b == b'.'
        })
}

impl Envelope {
    /// Shape checks that hold for any envelope, sent or received.
    pub fn check(&self) -> Result<(), WireError> {
        if self.body.len() > MAX_BODY {
            return Err(WireError::TooBig);
        }
        if self.level > MAX_LEVEL {
            return Err(WireError::BadLevel);
        }
        for (what, v) in [("from", &self.from), ("to", &self.to), ("id", &self.id)] {
            if !word_ok(v) {
                return Err(WireError::BadName(what));
            }
        }
        if self.receiver_fp.len() != 64 || !self.receiver_fp.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(WireError::BadName("receiver_fp"));
        }
        Ok(())
    }

    /// The canonical bytes: version byte, the domain tag, the receiver's key fingerprint, the epoch, then every field in the
    /// order below. A new field goes at the end, under a new version.
    pub fn canonical(&self) -> Vec<u8> {
        let mut e = Encoder::new(ENVELOPE_TAG);
        e.text(&self.receiver_fp)
            .u64(self.epoch)
            .text(self.kind.name())
            .text(&self.from)
            .text(&self.to)
            .u64(self.seq)
            .text(&self.id)
            .u64(self.ts_ms)
            .u64(u64::from(self.level))
            .count(self.via.len());
        for h in &self.via {
            e.text(&h.box_id).text(&h.key_fp);
        }
        e.field(&self.body);
        e.bytes().to_vec()
    }

    /// The digest of [`Envelope::canonical`], in hex: what a log or an acknowledgement names a message by.
    pub fn digest_hex(&self) -> String {
        let mut e = Encoder::new(ENVELOPE_TAG);
        e.field(&self.canonical());
        to_hex(&e.digest())
    }
}

/// Signs a message's canonical bytes as the sender. The real one is the secrets service's operation under the channel key
/// (ADR 0042 section 1), reached over its socket, never a key in this process.
pub trait Signer: Send + Sync {
    fn sign(&self, canonical: &[u8]) -> Vec<u8>;
}

/// Checks a signature against the key the roster pins for the sender.
pub trait Verifier: Send + Sync {
    fn verify(&self, sender: &str, canonical: &[u8], signature: &[u8]) -> bool;
}

/// Seals a body to the receiver and opens one for this end. The real one is HPKE through `ozbox-seal`, with a fixed `info` per
/// purpose; this crate holds no crypto of its own beyond the digest.
pub trait Sealer: Send + Sync {
    fn seal(&self, receiver: &str, aad: &[u8], plain: &[u8]) -> Vec<u8>;
    fn open(&self, aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>>;
}

/// What goes over the transport: the envelope's fields with the body sealed, and the signature over the canonical bytes of the
/// envelope **as sealed** (so the transport and the hub's listener verify without ever opening a body).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sealed {
    pub envelope: Envelope,
    pub signature: Vec<u8>,
}

/// Seal and sign one envelope. `plain` becomes the body.
pub fn seal_and_sign(
    mut env: Envelope,
    plain: &[u8],
    sealer: &dyn Sealer,
    signer: &dyn Signer,
) -> Result<Sealed, WireError> {
    env.body = Vec::new();
    let aad = aad_of(&env);
    env.body = sealer.seal(&env.to, &aad, plain);
    env.check()?;
    let signature = signer.sign(&env.canonical());
    Ok(Sealed {
        envelope: env,
        signature,
    })
}

/// What a sealed body is bound to: every field of the envelope except the body itself.
pub fn aad_of(env: &Envelope) -> Vec<u8> {
    let mut bare = env.clone();
    bare.body = Vec::new();
    bare.canonical()
}

/// Verify the signature and the shape, then open the body.
pub fn verify_and_open(
    msg: &Sealed,
    verifier: &dyn Verifier,
    sealer: &dyn Sealer,
) -> Result<Vec<u8>, WireError> {
    msg.envelope.check()?;
    if !msg.envelope.via.is_empty() {
        return Err(WireError::NoRelayYet);
    }
    if !verifier.verify(
        &msg.envelope.from,
        &msg.envelope.canonical(),
        &msg.signature,
    ) {
        return Err(WireError::BadSignature);
    }
    sealer
        .open(&aad_of(&msg.envelope), &msg.envelope.body)
        .ok_or(WireError::BadSeal)
}

/// Carries sealed messages. The network is not trusted: a transport only moves bytes. The real ones are a connection the worker
/// dials out on (ADR 0042 section 2); [`crate::hub::mem::MemTransport`] is the in-memory one.
pub trait Transport: Send + Sync {
    fn send(&self, to: &str, msg: Sealed);
    fn recv(&self, who: &str) -> Option<Sealed>;
}

/// One end of a link to one peer: the names, the keys' fingerprints, and the three crypto seams.
pub struct Link<'a> {
    pub me: &'a str,
    pub peer: &'a str,
    /// The fingerprint of the key a message **to the peer** is sealed to (it goes into the envelope's domain).
    pub peer_fp: &'a str,
    /// The fingerprint of **this** end's receiving key, which every inbound message must name.
    pub my_fp: &'a str,
    pub epoch: u64,
    /// This end's level (0 for `main`, 1 for a worker).
    pub level: u8,
    pub signer: &'a dyn Signer,
    pub verifier: &'a dyn Verifier,
    pub sealer: &'a dyn Sealer,
    pub net: &'a dyn Transport,
}

impl Link<'_> {
    /// Build, seal, sign and send one message to the peer. Returns the envelope as sent.
    pub fn send(
        &self,
        kind: Kind,
        seq: u64,
        id: String,
        now: u64,
        plain: &[u8],
    ) -> Result<Envelope, WireError> {
        let env = Envelope {
            kind,
            from: self.me.to_string(),
            to: self.peer.to_string(),
            receiver_fp: self.peer_fp.to_string(),
            epoch: self.epoch,
            seq,
            id,
            ts_ms: now,
            level: self.level,
            via: Vec::new(),
            body: Vec::new(),
        };
        let sealed = seal_and_sign(env, plain, self.sealer, self.signer)?;
        let out = sealed.envelope.clone();
        self.net.send(self.peer, sealed);
        Ok(out)
    }

    /// Verify and open an inbound message: right receiver key, right epoch, from the peer, signed, opens.
    pub fn open(&self, msg: &Sealed) -> Result<(Envelope, Vec<u8>), WireError> {
        let e = &msg.envelope;
        if e.to != self.me
            || e.receiver_fp != self.my_fp
            || e.epoch != self.epoch
            || e.from != self.peer
        {
            return Err(WireError::BadName("addressing"));
        }
        let plain = verify_and_open(msg, self.verifier, self.sealer)?;
        Ok((e.clone(), plain))
    }
}
