//! What the service knows about each laptop key beyond its public half (ADR 0041 §3): its type, whether an attestation
//! proved it needs a touch, the application or relying party it was made for, and when it may start deciding.
//!
//! The record is `approval-key.<id>.meta` in the encrypted store, beside `approval-key.<id>` (the public half) and
//! `approval-key.<id>.via`. All three are under the keys' own prefix, so the box socket can neither write, read nor list them.
//! A key with no meta record is an Ed25519 software key (every key enrolled before this version), with no presence.
//!
//! [`load_key_view`] is the only way a request operation learns about a key: by id, from the store, never from the caller's
//! word. The ingress arm calls it, and a test feeds it a key that really is in a store.

use std::sync::Mutex;

use ozbox_core::approval::{KeyType, KeyView};
use ozbox_core::approval_subject::{key_enrol_challenge, Ids};
use ozbox_core::approval_verify::ExpectedRp;
use serde::{Deserialize, Serialize};

use crate::approval_key::{id_ok, KEY_PREFIX};
use crate::secrets::SecretStore;

pub fn meta_name(id: &str) -> String {
    format!("{KEY_PREFIX}{id}.meta")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyMeta {
    pub key_type: String,
    /// Set only by the attestation verifier, never by a request.
    #[serde(default)]
    pub presence_proved: bool,
    #[serde(default)]
    pub attestation_digest: Option<String>,
    /// The SHA-256 of the pinned root the attestation chained to.
    #[serde(default)]
    pub attested_root: Option<String>,
    #[serde(default)]
    pub application: Option<String>,
    #[serde(default)]
    pub rp: Option<ExpectedRp>,
    #[serde(default)]
    pub enrolled_ms: u64,
    /// A key enrolled from the dashboard after a first one exists waits 24 hours before it may decide.
    #[serde(default)]
    pub active_from_ms: u64,
}

impl KeyMeta {
    /// The record of a key with no attestation: a software key of this type.
    pub fn software(key_type: &str, now_ms: u64) -> Self {
        KeyMeta {
            key_type: key_type.to_string(),
            presence_proved: false,
            attestation_digest: None,
            attested_root: None,
            application: None,
            rp: None,
            enrolled_ms: now_ms,
            active_from_ms: 0,
        }
    }
}

pub fn read_meta(store: &dyn SecretStore, id: &str) -> Result<Option<KeyMeta>, String> {
    match store.get(&meta_name(id)).map_err(|e| e.0)? {
        None => Ok(None),
        // a damaged record is not read as "a software key": that would hide what it was; the key decides nothing
        // hex of the JSON: the store keeps plain visible characters only
        Some(t) => ozbox_core::approval_subject::from_hex(&t)
            .and_then(|b| serde_json::from_slice(&b).ok())
            .map(Some)
            .ok_or_else(|| "that key's record is damaged".to_string()),
    }
}

pub fn write_meta(store: &dyn SecretStore, id: &str, m: &KeyMeta) -> Result<(), String> {
    let t =
        serde_json::to_vec(m).map_err(|_| "the key's record could not be written".to_string())?;
    store
        .set(&meta_name(id), &ozbox_core::approval_subject::to_hex(&t))
        .map_err(|e| e.0)
}

/// The key as the service's own records have it. `None` when no key of that id is enrolled (so a revoked key decides
/// nothing). A key type the record names that this version does not know, or a type that disagrees with the public half's
/// length, is an error: the key decides nothing.
pub fn load_key_view(store: &dyn SecretStore, id: &str) -> Result<Option<KeyView>, String> {
    if !id_ok(id) {
        return Err("that key name is not valid".into());
    }
    let Some(public_half) = store.get(&format!("{KEY_PREFIX}{id}")).map_err(|e| e.0)? else {
        return Ok(None);
    };
    let meta = read_meta(store, id)?;
    let (key_type, proved, digest, app, rp) = match &meta {
        None => (KeyType::Ed25519, false, None, None, None),
        Some(m) => (
            KeyType::parse(&m.key_type).ok_or("that key's type is not one this version knows")?,
            m.presence_proved,
            m.attestation_digest.clone(),
            m.application.clone(),
            m.rp.clone(),
        ),
    };
    let want_len = match key_type {
        KeyType::Ed25519 | KeyType::SkEd25519 => 64,
        KeyType::EcdsaSk | KeyType::WebauthnP256 => 130,
    };
    if public_half.len() != want_len {
        return Err("that key's record is damaged".into());
    }
    // presence is a FIDO2 key whose attestation verified, and nothing else
    let proved = proved && key_type.is_fido2() && digest.is_some();
    Ok(Some(KeyView {
        id: id.to_string(),
        key_type,
        presence_proved: proved,
        attestation_digest: digest,
        public_half,
        active: true,
        application: app,
        rp,
    }))
}

/// One line of what the dashboard lists about a key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KeyInfo {
    pub id: String,
    pub key_type: String,
    pub presence: &'static str,
    pub enrolled_via: Option<String>,
    pub attested: bool,
    pub active_from_ms: Option<u64>,
}

pub fn list_keys(
    store: &crate::secrets_enc::EncryptedSecrets,
    now_ms: u64,
) -> Result<Vec<KeyInfo>, String> {
    let mut out = Vec::new();
    for n in store.names(KEY_PREFIX).map_err(|e| e.0)? {
        let Some(id) = n.strip_prefix(KEY_PREFIX).filter(|i| id_ok(i)) else {
            continue;
        };
        let view = load_key_view(store, id)?;
        let Some(v) = view else { continue };
        let meta = read_meta(store, id)?;
        out.push(KeyInfo {
            id: id.to_string(),
            key_type: match v.key_type {
                KeyType::Ed25519 => "ed25519",
                KeyType::SkEd25519 => "sk-ssh-ed25519",
                KeyType::EcdsaSk => "ecdsa-sk",
                KeyType::WebauthnP256 => "webauthn-p256",
            }
            .to_string(),
            presence: if v.presence_proved { "proved" } else { "none" },
            enrolled_via: store
                .get(&format!("{KEY_PREFIX}{id}.via"))
                .map_err(|e| e.0)?,
            attested: v.attestation_digest.is_some(),
            active_from_ms: meta.map(|m| m.active_from_ms).filter(|t| *t > now_ms),
        });
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
}

// ---- the enrolment challenge ---------------------------------------------------------------------------------------------

const ENROL_TTL_MS: u64 = 10 * 60_000;
/// One pool for each class of socket (the box user's, the laptop's, the supervisor's and root's), as the signing challenges
/// have, so the dashboard cannot use up the laptop's enrolment challenges.
fn enrol_cap(class: crate::approval_key::Class) -> usize {
    use crate::approval_key::Class;
    match class {
        Class::BoxUser => 4,
        Class::Laptop | Class::Supervisor | Class::Root => 16,
    }
}

struct Live {
    id: String,
    challenge: [u8; 32],
    expires_ms: u64,
    class: crate::approval_key::Class,
}

/// The challenges the service issued for an attestation to be made over (`ssh-keygen -O challenge=`, or a WebAuthn
/// `create()`). In memory only, one use each. The challenge is service-issued: the attestation's own digest is in the
/// `signer-enroll` subject, so a challenge that contained the subject digest would have to contain itself.
#[derive(Default)]
pub struct EnrolChallenges {
    live: Mutex<Vec<Live>>,
}

impl EnrolChallenges {
    /// Issue one: its id and the 32 bytes to make the key over. A pool for each class of socket.
    pub fn issue(
        &self,
        ids: &Ids,
        class: crate::approval_key::Class,
        now_ms: u64,
    ) -> Result<(String, [u8; 32], u64), String> {
        let mut raw = [0u8; 16];
        getrandom::getrandom(&mut raw)
            .map_err(|_| "no random numbers are available".to_string())?;
        let id = ozbox_core::audit::hex(&raw);
        let challenge = key_enrol_challenge(ids, &id, &[0u8; 32]);
        let mut l = self.live.lock().unwrap_or_else(|e| e.into_inner());
        l.retain(|c| c.expires_ms > now_ms);
        let n = l.iter().filter(|c| c.class == class).count();
        if n >= enrol_cap(class) {
            return Err("too many key enrolments are waiting: try again in a few minutes".into());
        }
        let expires_ms = now_ms + ENROL_TTL_MS;
        l.push(Live {
            id: id.clone(),
            challenge,
            expires_ms,
            class,
        });
        Ok((id, challenge, expires_ms))
    }

    /// Take one (once): the challenge an attestation must have been made over.
    pub fn take(&self, id: &str, now_ms: u64) -> Result<[u8; 32], String> {
        let mut l = self.live.lock().unwrap_or_else(|e| e.into_inner());
        l.retain(|c| c.expires_ms > now_ms);
        match l.iter().position(|c| c.id == id) {
            Some(i) => Ok(l.remove(i).challenge),
            None => Err("that enrolment challenge is not valid, was used, or has expired: ask for a new one".into()),
        }
    }
}
