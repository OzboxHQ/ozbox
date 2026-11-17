//! A channel end's public identity (ADR 0042 section 1): the four purpose keys, and the two fingerprints that name them.
//!
//! Key purposes are separate keys, not separate labels. A secrets service holds one key per purpose:
//!
//! * **channel signing** (Ed25519): signs envelopes and an enrolment proof, each under its own domain tag;
//! * **channel sealing** (X25519): message bodies are sealed to it, with HPKE `info` fixed to [`CHANNEL_PURPOSE`];
//! * **key delivery** (X25519): values for a worker's task are sealed to it, with `info` fixed to [`DELIVERY_PURPOSE`];
//! * **handshake** (Ed25519): the one private operation `ozbox-hubd` may ask for, under [`HANDSHAKE_TAG`].
//!
//! The **channel fingerprint** is the fingerprint of the sealing key's bytes, the one function every key uses
//! ([`ozbox_core::channel::wire::fingerprint`]). It is what the envelope's receiver field and the hub's roster carry. The
//! **identity fingerprint** covers all four public keys in a fixed encoding, so a pin of it fixes every key at once: a worker
//! pins the hub's identity fingerprint at first boot, and an attestation names the worker's.

use ozbox_core::approval_subject::Encoder;
use ozbox_core::channel::wire::{fingerprint, normalize_hex, unhex};
use serde::{Deserialize, Serialize};

/// The identity's own encoding tag.
pub const IDENTITY_TAG: &str = "ozbox-hub-identity-v1";
/// The tag a worker's enrolment proof is signed under (its channel signing key).
pub const ENROL_PROOF_TAG: &str = "ozbox-hub-enrol-proof-v1";
/// The tag the handshake signature is made under (ADR 0042 section 1).
pub const HANDSHAKE_TAG: &str = "ozbox-hub-handshake-v1";
/// The tag a registrar signs an attestation under.
pub const ATTESTATION_TAG: &str = "ozbox-hub-attestation-v1";
/// The tag an enrolment token is MACed under. The hub keeps only the tag, never the token.
pub const TOKEN_MAC_TAG: &str = "ozbox-hub-enrol-token-v1";
/// The HPKE purpose of a message body. Fixed by the operation; a caller cannot pass another.
pub const CHANNEL_PURPOSE: &str = "hub-channel-body";
/// The HPKE purpose of a delivered key value (H3 owns delivery; the purpose is fixed here so the two never meet).
pub const DELIVERY_PURPOSE: &str = "hub-key-delivery";

/// The bytes every message under `tag` starts with: the encoding's version byte and the tag as a length-prefixed field.
pub fn tag_prefix(tag: &str) -> Vec<u8> {
    Encoder::new(tag).bytes().to_vec()
}

/// The four public keys of one end, in lower-case hex. Public; never a private half.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    /// Ed25519: envelopes and the enrolment proof.
    pub sign_public: String,
    /// X25519: message bodies.
    pub seal_public: String,
    /// X25519: delivered key values.
    pub delivery_public: String,
    /// Ed25519: the handshake.
    pub handshake_public: String,
}

impl Identity {
    /// The same identity in its one stored form, or `None` when a key is not the right shape.
    pub fn checked(&self) -> Option<Identity> {
        let ed = |s: &str| normalize_hex(s).filter(|h| h.len() == 64);
        let x = |s: &str| {
            normalize_hex(s).filter(|h| h.len() == 64 && ozbox_seal::public_from_hex(h).is_ok())
        };
        let id = Identity {
            sign_public: ed(&self.sign_public)?,
            seal_public: x(&self.seal_public)?,
            delivery_public: x(&self.delivery_public)?,
            handshake_public: ed(&self.handshake_public)?,
        };
        // four purposes, four keys: an identity that reuses one key for two purposes is not one
        let all = [
            &id.sign_public,
            &id.seal_public,
            &id.delivery_public,
            &id.handshake_public,
        ];
        for (i, a) in all.iter().enumerate() {
            if all[i + 1..].contains(a) {
                return None;
            }
        }
        Some(id)
    }

    /// The fingerprint of the sealing key: the envelope's receiver field and the roster's `key_fp`.
    pub fn channel_fp(&self) -> String {
        unhex(&self.seal_public)
            .map(|b| fingerprint(&b))
            .unwrap_or_default()
    }

    /// The fingerprint of the delivery key.
    pub fn delivery_fp(&self) -> String {
        unhex(&self.delivery_public)
            .map(|b| fingerprint(&b))
            .unwrap_or_default()
    }

    /// The identity fingerprint: all four keys, in a fixed order, under [`IDENTITY_TAG`].
    pub fn identity_fp(&self) -> String {
        let mut e = Encoder::new(IDENTITY_TAG);
        e.text(&self.sign_public)
            .text(&self.seal_public)
            .text(&self.delivery_public)
            .text(&self.handshake_public);
        fingerprint(e.bytes())
    }
}
