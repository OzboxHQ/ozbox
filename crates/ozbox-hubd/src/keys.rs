//! The secrets service's side of the hub's keys: the private halves, and the few operations it answers with them.
//!
//! This module is what runs **inside** the secrets service (`ozbox secrets serve`, user `ozbox-secrets`). The private keys are
//! made on first use, stored in the encrypted store under names that begin with [`KEY_PREFIX`] (the box socket can neither read
//! nor write them), and never leave this process. The operations, and who may ask for which, are fixed here:
//!
//! | Operation | Supervisor socket | Hub socket (`ozbox-hubd`) | Admin socket |
//! |---|---|---|---|
//! | `hub_identity` (the public keys) | yes | yes | yes |
//! | `hub_sign` an envelope or an enrolment proof | yes | no | no |
//! | `hub_sign` a handshake | no | yes | no |
//! | `hub_open` a message body | yes | no | no |
//! | `hub_mac` an enrolment token | no | yes | no |
//!
//! A signature is made only over bytes that begin with the purpose's own domain tag, so the channel key can never be asked to
//! sign an approval, a decision or anything else. `hub_open` opens only a body sealed with the channel purpose: a delivered key
//! value (the delivery purpose) does not open here, by the key and by the `info` both. No value, key or plaintext is ever put in
//! an error.

use ozbox_core::approval_subject::Encoder;
use ozbox_core::channel::wire::{hex, unhex};
use ring::hmac;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::identity::{
    tag_prefix, Identity, CHANNEL_PURPOSE, ENROL_PROOF_TAG, HANDSHAKE_TAG, TOKEN_MAC_TAG,
};

/// Every name the hub's keys are stored under starts with this. Reserved: the box socket can neither read nor write one.
pub const KEY_PREFIX: &str = "hub-key-";
pub const NAME_CHANNEL_SIGN: &str = "hub-key-channel-sign";
pub const NAME_CHANNEL_SEAL: &str = "hub-key-channel-seal";
pub const NAME_DELIVERY_SEAL: &str = "hub-key-delivery-seal";
pub const NAME_HANDSHAKE_SIGN: &str = "hub-key-handshake-sign";
pub const NAME_TOKEN_MAC: &str = "hub-key-token-mac";
/// The five names, in the order they are made.
pub const NAMES: [&str; 5] = [
    NAME_CHANNEL_SIGN,
    NAME_CHANNEL_SEAL,
    NAME_DELIVERY_SEAL,
    NAME_HANDSHAKE_SIGN,
    NAME_TOKEN_MAC,
];

/// Whether a store name belongs to the hub's keys.
pub fn is_reserved(name: &str) -> bool {
    name.starts_with(KEY_PREFIX)
}

/// The envelope tag of the worker channel: the only envelopes this key signs.
pub const HUB_ENVELOPE_TAG: &str = ozbox_core::hub::wire::ENVELOPE_TAG;

/// Where the private halves are kept. The secrets service adapts its encrypted store to this.
pub trait KeyStore {
    fn get(&self, name: &str) -> Result<Option<Zeroizing<String>>, String>;
    fn set(&self, name: &str, value: &str) -> Result<(), String>;
}

/// What a signature is for. Each purpose fixes the key and the domain tag the bytes must begin with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignPurpose {
    /// A worker-channel envelope (`ozbox-hub-envelope-v1`), with the channel key.
    Envelope,
    /// A worker's enrolment proof (`ozbox-hub-enrol-proof-v1`), with the channel key.
    EnrolProof,
    /// The handshake (`ozbox-hub-handshake-v1`), with the handshake key.
    Handshake,
}

impl SignPurpose {
    pub fn word(self) -> &'static str {
        match self {
            SignPurpose::Envelope => "envelope",
            SignPurpose::EnrolProof => "enrol-proof",
            SignPurpose::Handshake => "handshake",
        }
    }

    pub fn parse(s: &str) -> Option<SignPurpose> {
        [
            SignPurpose::Envelope,
            SignPurpose::EnrolProof,
            SignPurpose::Handshake,
        ]
        .into_iter()
        .find(|p| p.word() == s)
    }

    pub fn tag(self) -> &'static str {
        match self {
            SignPurpose::Envelope => HUB_ENVELOPE_TAG,
            SignPurpose::EnrolProof => ENROL_PROOF_TAG,
            SignPurpose::Handshake => HANDSHAKE_TAG,
        }
    }

    /// Whether `bytes` are a message of this purpose (they begin with its tag).
    pub fn admits(self, bytes: &[u8]) -> bool {
        bytes.starts_with(&tag_prefix(self.tag()))
    }
}

/// Which socket a request came in on, as the hub's operations see it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Caller {
    /// The supervisor's own socket on `main` (or the hub agent's on a worker): signs and opens the channel.
    Supervisor,
    /// The socket only `ozbox-hubd`'s user may enter: the handshake and the token tag.
    Hub,
    /// Root's socket: the public identity.
    Admin,
    /// Any other socket: nothing.
    Other,
}

/// The private keys, held in this value only. Never printed.
pub struct HubKeys {
    channel_sign: Ed25519KeyPair,
    channel_seal: ozbox_seal::ServiceKey,
    delivery: ozbox_seal::ServiceKey,
    handshake: Ed25519KeyPair,
    mac: hmac::Key,
    identity: Identity,
}

impl std::fmt::Debug for HubKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HubKeys({})", self.identity.identity_fp())
    }
}

fn ed25519_new() -> Result<Zeroizing<String>, String> {
    let doc = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .map_err(|_| "no random numbers are available".to_string())?;
    Ok(Zeroizing::new(hex(doc.as_ref())))
}

fn x25519_new() -> Result<Zeroizing<String>, String> {
    let k = ozbox_seal::ServiceKey::generate().map_err(|e| e.to_string())?;
    Ok(Zeroizing::new(hex(&k.secret_bytes()[..])))
}

fn mac_new() -> Result<Zeroizing<String>, String> {
    let mut b = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(b.as_mut()).map_err(|_| "no random numbers are available".to_string())?;
    Ok(Zeroizing::new(hex(&b[..])))
}

const DAMAGED: &str = "the hub's keys in the store are damaged";

impl HubKeys {
    /// The keys from the store, made (and stored) the first time. All five exist or none does: a store holding some of them is
    /// damaged and is an error, never filled in, because a new key silently changes the identity every worker pinned.
    pub fn load_or_create(store: &dyn KeyStore) -> Result<HubKeys, String> {
        let mut found = Vec::new();
        for n in NAMES {
            found.push(store.get(n)?);
        }
        let present = found.iter().filter(|v| v.is_some()).count();
        if present == 0 {
            let made = [
                ed25519_new()?,
                x25519_new()?,
                x25519_new()?,
                ed25519_new()?,
                mac_new()?,
            ];
            for (n, v) in NAMES.iter().zip(made.iter()) {
                store.set(n, v)?;
            }
            return Self::from_hex(&made.each_ref().map(|v| v.as_str()));
        }
        if present != NAMES.len() {
            return Err(DAMAGED.into());
        }
        let vals: Vec<Zeroizing<String>> = found.into_iter().flatten().collect();
        let refs: Vec<&str> = vals.iter().map(|v| v.trim()).collect();
        let arr: [&str; 5] = refs.try_into().map_err(|_| DAMAGED.to_string())?;
        Self::from_hex(&arr)
    }

    fn from_hex(v: &[&str; 5]) -> Result<HubKeys, String> {
        let raw = |s: &str| {
            unhex(s)
                .map(Zeroizing::new)
                .ok_or_else(|| DAMAGED.to_string())
        };
        let channel_sign =
            Ed25519KeyPair::from_pkcs8(&raw(v[0])?).map_err(|_| DAMAGED.to_string())?;
        let channel_seal = ozbox_seal::ServiceKey::from_secret_bytes(&raw(v[1])?)
            .map_err(|_| DAMAGED.to_string())?;
        let delivery = ozbox_seal::ServiceKey::from_secret_bytes(&raw(v[2])?)
            .map_err(|_| DAMAGED.to_string())?;
        let handshake = Ed25519KeyPair::from_pkcs8(&raw(v[3])?).map_err(|_| DAMAGED.to_string())?;
        let mac_raw = raw(v[4])?;
        if mac_raw.len() != 32 {
            return Err(DAMAGED.into());
        }
        let mac = hmac::Key::new(hmac::HMAC_SHA256, &mac_raw);
        let identity = Identity {
            sign_public: hex(channel_sign.public_key().as_ref()),
            seal_public: ozbox_seal::public_to_hex(&channel_seal.public()),
            delivery_public: ozbox_seal::public_to_hex(&delivery.public()),
            handshake_public: hex(handshake.public_key().as_ref()),
        };
        let identity = identity.checked().ok_or_else(|| DAMAGED.to_string())?;
        Ok(HubKeys {
            channel_sign,
            channel_seal,
            delivery,
            handshake,
            mac,
            identity,
        })
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Sign `bytes` for `purpose`. Refused unless they begin with the purpose's tag.
    pub fn sign(&self, purpose: SignPurpose, bytes: &[u8]) -> Result<Vec<u8>, &'static str> {
        if !purpose.admits(bytes) {
            return Err("those bytes are not a message this key signs");
        }
        let pair = match purpose {
            SignPurpose::Envelope | SignPurpose::EnrolProof => &self.channel_sign,
            SignPurpose::Handshake => &self.handshake,
        };
        Ok(pair.sign(bytes).as_ref().to_vec())
    }

    /// Open a message body sealed to this end's channel key. A body sealed with any other purpose, to any other key, or changed
    /// on the way, does not open.
    pub fn open_channel(
        &self,
        aad: &[u8],
        sealed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, &'static str> {
        const NO: &str = "that message could not be opened";
        if sealed.len() < ozbox_seal::KEY_LEN {
            return Err(NO);
        }
        let (enc, ct) = sealed.split_at(ozbox_seal::KEY_LEN);
        let info = channel_info(&self.identity.channel_fp());
        self.channel_seal.open(&info, aad, enc, ct).map_err(|_| NO)
    }

    /// The tag of an enrolment token. The hub keeps this, never the token.
    pub fn mac(&self, bytes: &[u8]) -> Vec<u8> {
        let mut e = Encoder::new(TOKEN_MAC_TAG);
        e.field(bytes);
        hmac::sign(&self.mac, e.bytes()).as_ref().to_vec()
    }

    /// The fingerprint of the delivery key (for a test that a delivery ciphertext does not open as a body).
    pub fn delivery_public(&self) -> [u8; ozbox_seal::KEY_LEN] {
        self.delivery.public()
    }
}

/// The HPKE `info` of a message body sealed to the key whose fingerprint is `receiver_fp`.
pub fn channel_info(receiver_fp: &str) -> Vec<u8> {
    ozbox_seal::info(CHANNEL_PURPOSE, receiver_fp)
}

/// The HPKE `info` of a delivered value sealed to the delivery key whose fingerprint is `delivery_fp`.
pub fn delivery_info(delivery_fp: &str) -> Vec<u8> {
    ozbox_seal::info(crate::identity::DELIVERY_PURPOSE, delivery_fp)
}

const NOT_HERE: &str = "that is not allowed on this socket";

fn hex_arg(req: &Value, field: &str, max: usize) -> Result<Vec<u8>, String> {
    let s = req[field].as_str().unwrap_or_default();
    if s.len() > max * 2 {
        return Err("that request is too large".into());
    }
    unhex(s).ok_or_else(|| "that request is not valid".to_string())
}

/// The largest message the channel operations take, before hex (a body plus its envelope).
pub const MAX_OP_BYTES: usize = 400 * 1024;

/// Answer one of the hub's operations (`hub_identity`, `hub_sign`, `hub_open`, `hub_mac`) for a caller. The secrets service
/// calls this for any request whose `op` starts with `hub_`.
pub fn handle(keys: &HubKeys, caller: Caller, req: &Value) -> Result<Value, String> {
    let op = req["op"].as_str().unwrap_or_default();
    match (op, caller) {
        ("hub_identity", Caller::Supervisor | Caller::Hub | Caller::Admin) => {
            let id = keys.identity();
            Ok(json!({
                "identity": id,
                "channel_fp": id.channel_fp(),
                "identity_fp": id.identity_fp(),
            }))
        }
        ("hub_sign", Caller::Supervisor | Caller::Hub) => {
            let purpose = SignPurpose::parse(req["purpose"].as_str().unwrap_or_default())
                .ok_or_else(|| "that request is not valid".to_string())?;
            let allowed = match purpose {
                SignPurpose::Envelope | SignPurpose::EnrolProof => caller == Caller::Supervisor,
                SignPurpose::Handshake => caller == Caller::Hub,
            };
            if !allowed {
                return Err(NOT_HERE.into());
            }
            let data = Zeroizing::new(hex_arg(req, "data", MAX_OP_BYTES)?);
            let sig = keys.sign(purpose, &data).map_err(str::to_string)?;
            Ok(json!({ "sig": hex(&sig) }))
        }
        ("hub_open", Caller::Supervisor) => {
            if req["purpose"]
                .as_str()
                .unwrap_or(crate::identity::CHANNEL_PURPOSE)
                != crate::identity::CHANNEL_PURPOSE
            {
                // a delivered value is the worker service's `store_delivery`, never opened for a caller
                return Err(NOT_HERE.into());
            }
            let aad = hex_arg(req, "aad", MAX_OP_BYTES)?;
            let sealed = hex_arg(req, "sealed", MAX_OP_BYTES)?;
            let plain = keys.open_channel(&aad, &sealed).map_err(str::to_string)?;
            Ok(json!({ "plain": hex(&plain) }))
        }
        ("hub_mac", Caller::Hub) => {
            let data = Zeroizing::new(hex_arg(req, "data", 1024)?);
            Ok(json!({ "tag": hex(&keys.mac(&data)) }))
        }
        ("hub_identity" | "hub_sign" | "hub_open" | "hub_mac", _) => Err(NOT_HERE.into()),
        _ => Err("that operation is not known".into()),
    }
}
