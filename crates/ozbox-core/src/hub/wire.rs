//! The worker channel's profile of the shared envelope ([`crate::channel`]; ADR 0042 sections 1 and 6).
//!
//! What lives here is what is **specific to the hub**: the closed list of message kinds and who may send which, the `ext` it signs
//! (the sender's level in the tree and the relay hops) and the transport the in-memory fleet uses. The envelope, its canonical
//! bytes, sessions, ordering, replay and acknowledgement are the channel's, so a fix there is made once.
//!
//! The kinds, `level` and `via` are pinned by golden vectors in `hub/tests.rs` (computed by a separate script). The format freezes
//! when the first real transport ships; until then it is revised with new vectors.

use serde::{Deserialize, Serialize};

use crate::approval_subject::Encoder;
use crate::channel::wire::{Profile, Sealed};

/// The domain tag of the worker channel. A message of the mesh never verifies here, and the reverse.
pub const ENVELOPE_TAG: &str = "ozbox-hub-envelope-v1";

/// The depth of the tree: `main` is level 0, its workers 1, their workers 2. Nothing deeper exists (ADR 0042 section 14).
pub const MAX_LEVEL: u8 = 2;

/// The largest body one envelope carries. Bigger things travel as an artifact the hub pulls, by name, size and hash.
pub const MAX_BODY: usize = 256 * 1024;

/// The most relay hops an `ext` may name (the schema is present; this release sends none and refuses any).
pub const MAX_HOPS: usize = 4;

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
    /// The channel's own control kind (`hello`); carried by [`crate::channel::wire::KIND_HELLO`], never sequenced.
    Hello,
    Heartbeat,
    Bye,
    /// The channel's own cumulative acknowledgement with nothing else to say.
    Ack,
    /// The hub asks a worker for the state of its tasks, after a restart or a gap.
    Resync,
    /// The hub tells a worker to stop a task (the conductor's `task_stop`).
    TaskStop,
    /// The hub tells a worker a task has ended, so the worker deletes that task's keys (ADR 0042 section 5.3).
    TaskEnd,
}

impl Kind {
    pub const ALL: [Kind; 27] = [
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
        Kind::Ack,
        Kind::Resync,
        Kind::TaskStop,
        Kind::TaskEnd,
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
            Kind::Ack => "ack",
            Kind::Resync => "resync",
            Kind::TaskStop => "task.stop",
            Kind::TaskEnd => "task.end",
        }
    }

    pub fn parse(name: &str) -> Option<Kind> {
        Kind::ALL.into_iter().find(|k| k.name() == name)
    }

    /// Whether the channel sequences and acknowledges a message of this kind (every kind but its own `hello` and `ack`).
    pub fn acknowledged(self) -> bool {
        !matches!(self, Kind::Hello | Kind::Ack)
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
                | Kind::Resync
                | Kind::TaskStop
                | Kind::TaskEnd
        )
    }
}

/// The application kinds of the profile: [`Kind::ALL`] without the channel's own `hello` and `ack`.
const APPLICATION_KINDS: [&str; 25] = [
    "task.assign",
    "question",
    "answer",
    "status",
    "blocked",
    "contract.changed",
    "result",
    "approval.request",
    "approval.decision",
    "keys.deliver",
    "keys.revoke",
    "lease.renew",
    "pins.set",
    "laptop.relay",
    "shard.assign",
    "shard.result",
    "artifact.offer",
    "artifact.pull",
    "audit.head",
    "audit.segments",
    "heartbeat",
    "bye",
    "resync",
    "task.stop",
    "task.end",
];

/// The worker channel as a profile of [`crate::channel`].
pub static PROFILE: Profile = Profile {
    tag: ENVELOPE_TAG,
    audit: "hub",
    kinds: &APPLICATION_KINDS,
    max_body: MAX_BODY,
    check_ext: |_, ext| Ext::decode(ext).is_some(),
};

/// One hop of a relayed message (a sub-hub adds one). Present in the schema now so the envelope never changes shape when nested
/// hubs ship; this release sends none and a receiver at level 1 refuses any.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hop {
    pub box_id: String,
    pub key_fp: String,
}

/// What the hub signs in the envelope's `ext`: the sender's level in the tree and the relay hops. Encoded with ADR 0041's framing
/// under its own tag, so the bytes are as canonical as the envelope's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ext {
    pub level: u8,
    pub via: Vec<Hop>,
}

const EXT_TAG: &str = "ozbox-hub-ext-v1";

impl Ext {
    pub fn at(level: u8) -> Ext {
        Ext {
            level,
            via: Vec::new(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new(EXT_TAG);
        e.u64(u64::from(self.level)).count(self.via.len());
        for h in &self.via {
            e.text(&h.box_id).text(&h.key_fp);
        }
        e.bytes().to_vec()
    }

    /// The reverse of [`Ext::encode`], strictly: any other bytes are not an `Ext`.
    pub fn decode(b: &[u8]) -> Option<Ext> {
        let mut r = Reader { b, at: 0 };
        if r.take(1)? != [crate::approval_subject::ENCODING_VERSION]
            || r.field()? != EXT_TAG.as_bytes()
        {
            return None;
        }
        let level = u8::try_from(r.u64()?).ok().filter(|l| *l <= MAX_LEVEL)?;
        let n = usize::try_from(r.u64()?).ok().filter(|n| *n <= MAX_HOPS)?;
        let mut via = Vec::new();
        for _ in 0..n {
            let box_id = String::from_utf8(r.field()?.to_vec()).ok()?;
            let key_fp = String::from_utf8(r.field()?.to_vec()).ok()?;
            via.push(Hop { box_id, key_fp });
        }
        (r.at == b.len()).then_some(Ext { level, via })
    }
}

struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.b.get(self.at..self.at.checked_add(n)?)?;
        self.at += n;
        Some(s)
    }

    fn field(&mut self) -> Option<&'a [u8]> {
        let len = u32::from_be_bytes(self.take(4)?.try_into().ok()?);
        self.take(usize::try_from(len).ok()?)
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.field()?.try_into().ok()?))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    Channel(crate::channel::wire::WireError),
    BadLevel,
    NoRelayYet,
    /// The transport could not take the message.
    SendFailed,
}

impl From<crate::channel::wire::WireError> for WireError {
    fn from(e: crate::channel::wire::WireError) -> Self {
        WireError::Channel(e)
    }
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WireError::Channel(e) => write!(f, "{e}"),
            WireError::BadLevel => f.write_str("the level is deeper than the tree allows"),
            WireError::NoRelayYet => {
                f.write_str("relayed messages are not accepted in this release")
            }
            WireError::SendFailed => f.write_str("the message could not be sent"),
        }
    }
}

/// Carries sealed messages. The network is not trusted: a transport only moves bytes. The real ones are a connection the worker
/// dials out on (ADR 0042 section 2); [`crate::hub::mem::MemTransport`] is the in-memory one.
pub trait Transport: Send + Sync {
    fn send(&self, to: &str, msg: Sealed) -> Result<(), WireError>;
    fn recv(&self, who: &str) -> Option<Sealed>;
}
