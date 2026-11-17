//! A key on the operator's laptop that signs an approval, instead of the dashboard (ADR 0023's "laptop-key path", ADR 0028).
//!
//! An approval is the short-lived, single-use, scoped code a change to a box's secrets needs once a second factor exists
//! (`secrets_approval`). The dashboard mints one after a fresh passkey. This is the second way to get the same thing: an
//! **Ed25519 key that lives in the operator's laptop keychain** signs a challenge the box's secrets service issued, and the
//! service, which holds only the key's public half, mints the same kind of code. The code is then used exactly as one from
//! the dashboard, and the record says how it was confirmed (`laptop-key:<id>`).
//!
//! * **Pin** the first key: the box user is the party a second factor guards against, so a box that has no approver yet
//!   cannot be given one by anything the box user can reach (it would enrol its own key and approve everything itself).
//!   The first key arrives the way the box's own configuration does, written by root at first boot from what the laptop
//!   gave when the box was made (`ozbox create` puts the laptop key's public half in the box's `ozbox-approver` label,
//!   and first boot writes it to [`PIN_FILE`]). The service enrols it at start, once, and records it as `pinned`.
//! * **Enrol** another key: the public half goes to the service (`approval_key_enroll`). Enrolling is itself a gated change
//!   (scope `signer-enroll`): it needs an approval from the dashboard or from a key already enrolled, and on a box with no
//!   second factor yet it is **refused** on every socket but root's (it is never allowed as `bootstrap`). Root (the admin
//!   socket) may enrol and revoke directly. Enrolling a key counts as a second factor existing, so the box leaves bootstrap
//!   mode. Every enrolment records the socket it came in on.
//! * **Sign**: the laptop asks for a challenge naming a scope, project and environment (`approval_challenge`), signs
//!   `ozbox-approval\n<scope>\n<project>\n<env>\n<key id>\n<nonce>\n<expires>`, and sends the signature
//!   (`approval_redeem`). A challenge is good once, for sixty seconds, for the one scope it names, and is spent by any answer,
//!   right or wrong. Nothing a process on the box can do produces the signature: the private half never leaves the laptop.
//! * **Revoke**: removes the public half; challenges for it stop being issued, and an old signature stops verifying.
//!
//! Every answer is a sentence or a code. The private key is never in a request, an answer, an error or a log line.

use std::sync::Mutex;

use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use serde_json::{json, Value};

use crate::secrets::SecretStore;
use crate::secrets_service::{Gates, Policy};

/// The service's name for an enrolled public key: `approval-key.<id>` holds 64 hex digits.
pub const KEY_PREFIX: &str = "approval-key.";
/// The laptop keychain's name for the private seed: `approval-key-<id>`.
pub const KEYCHAIN_PREFIX: &str = "approval-key-";
pub const CHALLENGE_TTL_MS: u64 = 60_000;
/// Challenges waiting for a signature, one pool and one cap for each class of socket: the box user's, the laptop's (the
/// ingress account), the supervisor's (the dashboard) and root's. A process that fills its own pool cannot stop another
/// class's path, so the dashboard can never use up the laptop's challenges (ADR 0041 §2).
const MAX_LIVE_BOX_USER: usize = 8;
const MAX_LIVE_LAPTOP: usize = 16;
const MAX_LIVE_SUPERVISOR: usize = 16;
const MAX_LIVE_ROOT: usize = 16;
const DOMAIN: &str = "ozbox-approval";

/// Where first boot puts the key pinned when the box was made: `<id> <public key in lowercase base32>`, root-owned.
pub const PIN_FILE: &str = "/etc/ozbox/approval-keys";
/// The id a pinned key is enrolled under when the file does not name one.
pub const PIN_ID: &str = "laptop";
/// Root's flag files for two settings (a plain file only root can write; present means the setting is as named).
/// `approvals.legacy_codes_off`: scope-only approval codes are no longer minted or accepted beside requests (ADR 0041 section
/// 10). Codes are ON by default until phase 3 (owner, 2026-11-13); phase 3 turns them off everywhere and removes this file.
/// Presence keys: a verified attestation makes a presence key (off until a real key has been proved on a box).
pub const LEGACY_CODES_OFF_FLAG: &str = "/etc/ozbox/approvals-legacy-codes-off";
pub const PRESENCE_KEYS_FLAG: &str = "/etc/ozbox/approvals-presence-keys";

/// What a root flag file says: not there, there and root's, or there but not trustworthy (not owned by root, writable by
/// others, or not a plain file). An untrusted file is ignored, and said so loudly at start (phase 2 re-check NL9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagState {
    Absent,
    On,
    Untrusted,
}

pub fn root_flag_state(path: &std::path::Path) -> FlagState {
    match std::fs::symlink_metadata(path) {
        Err(_) => FlagState::Absent,
        Ok(m) if pin_file_trusted(&m, 0) => FlagState::On,
        Ok(_) => FlagState::Untrusted,
    }
}

/// Whether the dashboard's socket may not mint a code for this scope: on a box that takes requests it never makes its own
/// enrolment code.
pub fn dashboard_mint_refused(gates: &crate::secrets_service::Gates, scope: &str) -> bool {
    scope == "signer-enroll" && gates.requests_guarded()
}

/// The sentence for a key still serving its wait, the same on every path that would use it (phase 2 re-check NM1).
pub const IN_WAIT: &str =
    "that key was enrolled from the dashboard and is still in its 24-hour wait";

/// Whether the key `id` is still in the 24-hour wait it serves after a code enrolment on a box that has had a key.
/// A record that cannot be read is an error, so the key does nothing (the stricter reading).
pub fn in_wait(store: &dyn SecretStore, id: &str, now: u64) -> Result<bool, String> {
    Ok(crate::approval_keystore::read_meta(store, id)?.is_some_and(|m| m.active_from_ms > now))
}

/// Whether this box has had a laptop key, read from the store alone: the marker, or any key record. Used when the request
/// journal did not open, so the 24-hour wait and the other protections do not depend on it (phase 2 re-check NL1).
pub fn ever_key_in_store(store: &crate::secrets_enc::EncryptedSecrets) -> Result<bool, String> {
    let names = store.names("").map_err(|e| e.0)?;
    Ok(names.iter().any(|n| {
        n == crate::approval_requests::EVER_KEY_MARKER
            || n.strip_prefix(KEY_PREFIX)
                .is_some_and(|rest| id_ok(rest.strip_suffix(".via").unwrap_or(rest)))
    }))
}

/// The label that carries the pinned key from `ozbox create` to the box's first-boot configuration.
pub const PIN_LABEL: &str = ozbox_core::APPROVER_LABEL;
/// What the store remembers about the pin it has already applied (a digest of the file), so a key the owner revoked is
/// not enrolled again at the next start. Not the box user's to write, delete or list.
pub const PIN_APPLIED: &str = "approval-pin-applied";

/// Where the store records how a key came to be trusted (`pinned`, `root`, or the approval that enrolled it). Under the
/// keys' own prefix, so the box socket can neither write nor read it; never a valid key id (an id has no dot).
fn via_name(id: &str) -> String {
    format!("{KEY_PREFIX}{id}.via")
}

/// Whether a secret's name is one of the laptop keys' own (the box socket may not write, delete or list these).
pub fn is_reserved(name: &str) -> bool {
    name.starts_with(KEY_PREFIX)
        || name == PIN_APPLIED
        || crate::approval_requests::RESERVED.contains(&name)
}

/// Remember that this box has had a laptop key (ADR 0041 §3.1, "first key means first ever"). The marker lives with the
/// bootstrap marker, is not the box user's to write, delete or list, and revoking every key does not clear it; only root
/// does.
fn note_key_enrolled(store: &dyn SecretStore) -> Result<(), String> {
    store
        .set(crate::approval_requests::EVER_KEY_MARKER, "1")
        .map_err(|e| e.0)
}

/// The wait a key enrolled from the dashboard serves before it may decide (ADR 0041 section 3).
pub const ENROL_WAIT_MS: u64 = 24 * 3_600_000;
const PENDING_PREFIX: &str = "approval-key.pending.";
const PENDING_KEEP_MS: u64 = 7 * 24 * 3_600_000;
const MAX_PENDING: usize = 8;

#[derive(serde::Serialize, serde::Deserialize)]
struct Pending {
    public: String,
    at_ms: u64,
    meta: crate::approval_keystore::KeyMeta,
    /// The class of socket that filed the enrolment.
    #[serde(default)]
    class: String,
}

/// An attestation verified when its enrolment was filed: the challenge it was made over lives ten minutes
/// in memory and the enrolment may be spent a day later, so the verdict is kept, keyed by the attestation's digest, and the
/// enrolment only has to find it. Under the keys' own prefix, so the box socket can neither write nor read it.
fn stash_pending(
    store: &crate::secrets_enc::EncryptedSecrets,
    digest: &str,
    public: &str,
    meta: &crate::approval_keystore::KeyMeta,
    class: &str,
    now: u64,
) -> Result<(), String> {
    // each class of socket has a cap of its own (a route that fills its own cannot stop another's), counted over what has
    // not gone stale; a stash whose request has ended is pruned by the service (`prune_stashes`), so the cap is on live ones
    let live = store
        .names(PENDING_PREFIX)
        .map_err(|e| e.0)?
        .into_iter()
        .filter_map(|n| read_pending(store, &n))
        .filter(|p| now.saturating_sub(p.at_ms) < PENDING_KEEP_MS && p.class == class)
        .count();
    if live >= MAX_PENDING {
        return Err(
            "too many key enrolments are waiting from this route: cancel one, or let it expire, first"
                .into(),
        );
    }
    let p = Pending {
        public: public.to_string(),
        at_ms: now,
        meta: meta.clone(),
        class: class.to_string(),
    };
    let t = serde_json::to_vec(&p).map_err(|_| "the enrolment could not be kept".to_string())?;
    store
        .set(
            &format!("{PENDING_PREFIX}{digest}"),
            &ozbox_core::audit::hex(&t),
        )
        .map_err(|e| e.0)
}

/// Delete every kept verdict whose attestation no live request names, and every one gone stale (phase 2 re-check NL4).
pub fn prune_stashes(
    store: &crate::secrets_enc::EncryptedSecrets,
    live_digests: &std::collections::HashSet<String>,
    now: u64,
) {
    let Ok(names) = store.names(PENDING_PREFIX) else {
        return;
    };
    for n in names {
        let digest = n.strip_prefix(PENDING_PREFIX).unwrap_or("");
        let stale =
            read_pending(store, &n).is_none_or(|p| now.saturating_sub(p.at_ms) >= PENDING_KEEP_MS);
        if stale || !live_digests.contains(digest) {
            let _ = store.delete(&n);
        }
    }
}

fn read_pending(store: &crate::secrets_enc::EncryptedSecrets, name: &str) -> Option<Pending> {
    let t = store.get(name).ok()??;
    serde_json::from_slice(&unhex(&t)?).ok()
}

/// The verdict kept for this attestation and this key, if there is one that has not gone stale.
fn pending_meta(
    store: &crate::secrets_enc::EncryptedSecrets,
    digest: &str,
    public: &str,
    now: u64,
) -> Result<crate::approval_keystore::KeyMeta, String> {
    read_pending(store, &format!("{PENDING_PREFIX}{digest}"))
        .filter(|p| p.public == public && now.saturating_sub(p.at_ms) < PENDING_KEEP_MS)
        .map(|p| p.meta)
        .ok_or_else(|| "that attestation was not verified when the enrolment was filed (or it is too old): file it again".to_string())
}

/// An attestation that verified at filing, waiting to be kept once the book has admitted the filing.
pub struct Staged {
    digest: String,
    public: String,
    meta: crate::approval_keystore::KeyMeta,
}

/// Verify an enrolment's attestation when its `signer-enroll` request is filed. A filing whose attestation does not
/// verify is refused, so nothing unverified ever waits for an approval. Nothing is written here: the verdict is kept by
/// [`keep_staged`] after the filing is admitted, so a filing that is refused leaves nothing in the store (phase 2 re-check NL4).
/// `None` when the subject needs no attestation, or its verdict is already kept.
pub fn verify_at_filing(
    store: &crate::secrets_enc::EncryptedSecrets,
    gates: &Gates,
    se: &ozbox_core::approval_subject::SignerEnroll,
    v: &Value,
    now: u64,
) -> Result<Option<Staged>, String> {
    use ozbox_core::approval::KeyType;
    use ozbox_core::approval_subject::EnrolAction;
    if se.action != EnrolAction::Enrol || se.attestation_digest.is_empty() {
        return Ok(None);
    }
    let ktype =
        KeyType::parse(&se.key_type).ok_or("that kind of key is not one this version knows")?;
    if pending_meta(store, &se.attestation_digest, &se.public_half, now).is_ok() {
        return Ok(None);
    }
    let meta = build_meta(gates, v, ktype, &se.key_type, &se.public_half, now)?;
    if meta.attestation_digest.as_deref() != Some(se.attestation_digest.as_str()) {
        return Err("the attestation is not the one the request names".into());
    }
    Ok(Some(Staged {
        digest: se.attestation_digest.clone(),
        public: se.public_half.clone(),
        meta,
    }))
}

/// Keep a verified verdict, for the class of socket that filed it.
pub fn keep_staged(
    store: &crate::secrets_enc::EncryptedSecrets,
    staged: &Staged,
    class: &str,
    now: u64,
) -> Result<(), String> {
    stash_pending(
        store,
        &staged.digest,
        &staged.public,
        &staged.meta,
        class,
        now,
    )
}

const B32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Lowercase RFC 4648 base32 without padding: the only form of a public key that fits a Hetzner label (63 characters,
/// letters and digits) as well as an AWS tag.
pub fn base32(bytes: &[u8]) -> String {
    let mut out = String::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for b in bytes {
        buf = (buf << 8) | u32::from(*b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((buf >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

pub fn unbase32(s: &str) -> Option<Vec<u8>> {
    let (mut buf, mut bits, mut out) = (0u32, 0u32, Vec::new());
    for c in s.bytes() {
        let v = B32.iter().position(|x| *x == c)? as u32;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    // the bits left over must be the zero padding of the last character, or the text is not one encoding of the bytes
    (buf & ((1 << bits) - 1) == 0).then_some(out)
}

/// The label value that pins a public key (hex) on a box.
pub fn pin_label(public_hex: &str) -> Option<String> {
    unhex(public_hex)
        .filter(|b| b.len() == 32)
        .map(|b| base32(&b))
}

/// Read the pin file: the key id and its public key in hex. The file must be a plain file owned by root that no one else
/// may write (the box user must not be able to place one); anything else is ignored and said so.
pub fn read_pin(path: &std::path::Path) -> Result<Option<(String, String)>, String> {
    read_pin_owned_by(path, 0)
}

/// [`read_pin`] with the owner the file must have (root on a box; the test's own user in a test).
pub fn read_pin_owned_by(
    path: &std::path::Path,
    owner: u32,
) -> Result<Option<(String, String)>, String> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(format!(
                "the pinned approval key could not be read ({})",
                e.kind()
            ))
        }
    };
    if !pin_file_trusted(&meta, owner) {
        return Err("the pinned approval key file is not a root-owned file only root can write, so it was ignored".into());
    }
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("the pinned approval key could not be read ({})", e.kind()))?;
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'));
    let Some(line) = line else { return Ok(None) };
    let mut words = line.split_whitespace();
    let (id, key) = match (words.next(), words.next(), words.next()) {
        (Some(k), None, None) => (PIN_ID, k),
        (Some(i), Some(k), None) => (i, k),
        _ => return Err("the pinned approval key file is not in the expected shape".into()),
    };
    let pk = unbase32(key).filter(|b| b.len() == 32);
    match (id_ok(id), pk) {
        (true, Some(pk)) => Ok(Some((id.to_string(), ozbox_core::audit::hex(&pk)))),
        _ => Err("the pinned approval key file is not in the expected shape".into()),
    }
}

#[cfg(unix)]
fn pin_file_trusted(m: &std::fs::Metadata, owner: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    m.is_file() && m.uid() == owner && m.mode() & 0o022 == 0
}

#[cfg(not(unix))]
fn pin_file_trusted(_: &std::fs::Metadata, _: u32) -> bool {
    false
}

/// Enrol the key pinned when the box was made, once. Run by the service at start. A key the owner revoked afterwards is not
/// enrolled again: the store remembers which pin it applied. Returns the id enrolled, if one was.
pub fn apply_pin(
    store: &crate::secrets_enc::EncryptedSecrets,
    gates: &Gates,
    pin: Option<(String, String)>,
) -> Result<Option<String>, String> {
    let Some((id, pk)) = pin else { return Ok(None) };
    let digest = crate::secrets_recover::pin_digest(&id, &pk);
    if store.get(PIN_APPLIED).map_err(|e| e.0)?.as_deref() == Some(digest.as_str()) {
        return Ok(None);
    }
    // A revocation is also kept outside the store (on /work, beside its copy), so a store started anew after a recovery
    // does not bring back a key its owner revoked.
    if gates
        .pin_record
        .get()
        .is_some_and(|d| crate::secrets_recover::pin_revoked(d, &digest))
    {
        store.set(PIN_APPLIED, &digest).map_err(|e| e.0)?;
        return Ok(None);
    }
    let name = format!("{KEY_PREFIX}{id}");
    match store.get(&name).map_err(|e| e.0)? {
        // the same key is already there (enrolled by root, or by an earlier pin): nothing to add
        Some(have) if have == pk => {}
        // another key holds that name: it is not replaced from a file; root decides
        Some(_) => {
            gates.audit_event(store, "secrets.signer.pin-refused", &id, "why=name-taken");
            store.set(PIN_APPLIED, &digest).map_err(|e| e.0)?;
            return Ok(None);
        }
        None => {
            store.set(&name, &pk).map_err(|e| e.0)?;
            note_key_enrolled(store)?;
            if let Some(svc) = gates.requests.get() {
                svc.note_key(false)?;
            }
            store.set(&via_name(&id), "pinned").map_err(|e| e.0)?;
            store
                .set(crate::secrets_approval::ENROLLED_MARKER, "1")
                .map_err(|e| e.0)?;
            gates.audit_event(
                store,
                "secrets.signer.enrolled",
                &id,
                "via=pinned socket=first-boot",
            );
        }
    }
    store.set(PIN_APPLIED, &digest).map_err(|e| e.0)?;
    Ok(Some(id))
}

pub fn id_ok(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 32
        && !id.starts_with('-')
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn seg_ok(s: &str) -> bool {
    s.is_empty()
        || (s.len() <= 32
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'))
}

/// What the laptop signs. Every part that scopes the approval is in it, so a signature cannot be moved to another scope,
/// project, environment, key or challenge.
pub fn message(
    scope: &str,
    project: &str,
    env: &str,
    key_id: &str,
    nonce: &str,
    expires_ms: u64,
) -> String {
    format!("{DOMAIN}\n{scope}\n{project}\n{env}\n{key_id}\n{nonce}\n{expires_ms}")
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

/// A new key pair: the seed (what the laptop keychain keeps) and the public key, both in hex.
pub fn generate() -> Result<(zeroize::Zeroizing<String>, String), String> {
    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    getrandom::getrandom(seed.as_mut())
        .map_err(|_| "no random numbers are available".to_string())?;
    let kp = Ed25519KeyPair::from_seed_unchecked(seed.as_ref())
        .map_err(|_| "the key could not be made".to_string())?;
    Ok((
        zeroize::Zeroizing::new(ozbox_core::audit::hex(seed.as_ref())),
        ozbox_core::audit::hex(kp.public_key().as_ref()),
    ))
}

/// The public key of a seed, in hex.
pub fn public_of(seed_hex: &str) -> Result<String, String> {
    let seed = zeroize::Zeroizing::new(unhex(seed_hex).ok_or("the key is damaged")?);
    let kp =
        Ed25519KeyPair::from_seed_unchecked(&seed).map_err(|_| "the key is damaged".to_string())?;
    Ok(ozbox_core::audit::hex(kp.public_key().as_ref()))
}

/// Sign `msg` with a seed; the signature in hex.
pub fn sign(seed_hex: &str, msg: &str) -> Result<String, String> {
    let seed = zeroize::Zeroizing::new(unhex(seed_hex).ok_or("the key is damaged")?);
    let kp =
        Ed25519KeyPair::from_seed_unchecked(&seed).map_err(|_| "the key is damaged".to_string())?;
    Ok(ozbox_core::audit::hex(kp.sign(msg.as_bytes()).as_ref()))
}

/// Whether `sig_hex` is `pk_hex`'s signature of `msg` (also used by the root helper's store recovery, with the service down).
pub fn verify(pk_hex: &str, msg: &str, sig_hex: &str) -> bool {
    match (unhex(pk_hex), unhex(sig_hex)) {
        (Some(pk), Some(sig)) => UnparsedPublicKey::new(&ED25519, pk)
            .verify(msg.as_bytes(), &sig)
            .is_ok(),
        _ => false,
    }
}

struct Challenge {
    nonce: String,
    key_id: String,
    scope: String,
    project: String,
    env: String,
    expires_ms: u64,
    /// The class of socket it was issued on.
    class: Class,
}

/// The sockets that ask for challenges, by who is behind them. Each has its own pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Class {
    BoxUser,
    Laptop,
    Supervisor,
    Root,
}

impl Class {
    pub(crate) fn cap(self) -> usize {
        match self {
            Class::BoxUser => MAX_LIVE_BOX_USER,
            Class::Laptop => MAX_LIVE_LAPTOP,
            Class::Supervisor => MAX_LIVE_SUPERVISOR,
            Class::Root => MAX_LIVE_ROOT,
        }
    }
}

#[derive(Default)]
struct State {
    live: Vec<Challenge>,
}

/// The class a socket word (`Policy::word`) belongs to. A word that is none of the known ones is treated as the box
/// user's, the smallest pool.
pub(crate) fn class_of(word: &str) -> Class {
    match word {
        "ingress" => Class::Laptop,
        "supervisor" => Class::Supervisor,
        "admin" | "runner" => Class::Root,
        _ => Class::BoxUser,
    }
}

/// The challenges waiting for a signature. In memory only: a restart forgets them, so a signature for one is worthless.
#[derive(Default)]
pub struct Challenges {
    state: Mutex<State>,
}

impl Challenges {
    fn issue(
        &self,
        socket: &str,
        key_id: &str,
        scope: &str,
        project: &str,
        env: &str,
        now: u64,
    ) -> Result<(String, u64), String> {
        if !crate::secrets_approval::SCOPES.contains(&scope) || !seg_ok(project) || !seg_ok(env) {
            return Err("that approval is not valid".into());
        }
        let mut raw = [0u8; 16];
        getrandom::getrandom(&mut raw)
            .map_err(|_| "no random numbers are available".to_string())?;
        let nonce = ozbox_core::audit::hex(&raw);
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        st.live.retain(|c| c.expires_ms > now);
        let class = class_of(socket);
        let pool = st.live.iter().filter(|c| c.class == class).count();
        if pool >= class.cap() {
            return Err("too many approvals are waiting to be signed".into());
        }
        let expires_ms = now + CHALLENGE_TTL_MS;
        st.live.push(Challenge {
            nonce: nonce.clone(),
            key_id: key_id.to_string(),
            scope: scope.to_string(),
            project: project.to_string(),
            env: env.to_string(),
            expires_ms,
            class,
        });
        Ok((nonce, expires_ms))
    }

    /// The challenge named by `nonce`, removed whether or not what follows succeeds: one try per challenge. **A wrong answer
    /// locks nothing**: a signature cannot be guessed and a nonce is 128 random bits, so a counter (which used to be global)
    /// could only ever be used to lock the owner out (ADR 0041 §2).
    fn take(&self, key_id: &str, nonce: &str, now: u64) -> Result<Challenge, String> {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        st.live.retain(|c| c.expires_ms > now);
        let found = st
            .live
            .iter()
            .position(|c| c.nonce == nonce && c.key_id == key_id);
        match found {
            Some(i) => Ok(st.live.remove(i)),
            None => Err(
                "that challenge is not valid, has been used, or has expired: ask for a new one"
                    .into(),
            ),
        }
    }
}

/// A change to who may approve, from a socket other than root's: never as `bootstrap`. Before any second factor exists the
/// box user cannot be told apart from the owner, so the change is refused and the refusal recorded.
fn require_signer_change(
    store: &crate::secrets_enc::EncryptedSecrets,
    gates: &Gates,
    policy: Policy,
    id: &str,
    approval: &str,
    now: u64,
) -> Result<String, String> {
    use crate::secrets_service::Refusal;
    // whether this may happen with no second factor is the scope's rule (`secrets_approval::SCOPE_RULES`: refused)
    gates
        .require_typed(store, "signer-enroll", id, "", approval, now)
        .map_err(|r| match r {
            Refusal::NoApprover(m) => {
                gates.audit_event(
                    store,
                    "secrets.signer.refused",
                    id,
                    &format!("why=no-approver socket={}", policy.word()),
                );
                m
            }
            Refusal::Approval(m) => m,
        })
}

fn public_key(store: &dyn SecretStore, id: &str) -> Result<Option<String>, String> {
    if !id_ok(id) {
        return Err("that key name is not valid".into());
    }
    store.get(&format!("{KEY_PREFIX}{id}")).map_err(|e| e.0)
}

/// The record of a key being enrolled, with its attestation verified when one came with it. A FIDO2 key that comes with no
/// attestation is a software key of that type; one whose attestation does not verify is refused (not quietly downgraded: the
/// owner asked for a presence key and should be told it is not one).
fn build_meta(
    gates: &Gates,
    v: &Value,
    ktype: ozbox_core::approval::KeyType,
    kt: &str,
    pk: &str,
    now: u64,
) -> Result<crate::approval_keystore::KeyMeta, String> {
    use crate::approval_keystore::KeyMeta;
    use ozbox_core::approval::KeyType;
    let mut meta = KeyMeta::software(kt, now);
    let text = |o: &Value, k: &str| o[k].as_str().unwrap_or("").to_string();
    if ktype == KeyType::WebauthnP256 {
        // a WebAuthn key's assertions are held to the relying party it was made for
        let (rp_id, origin) = (text(&v["rp"], "rp_id"), text(&v["rp"], "origin"));
        if rp_id.is_empty() || origin.is_empty() || rp_id.len() > 253 || origin.len() > 253 {
            return Err(
                "a WebAuthn key is enrolled with its relying party (rp id and origin)".into(),
            );
        }
        meta.rp = Some(ozbox_core::approval_verify::ExpectedRp { rp_id, origin });
    }
    if matches!(ktype, KeyType::SkEd25519 | KeyType::EcdsaSk) {
        let app = v["application"].as_str().unwrap_or("ssh:");
        if app.is_empty() || app.len() > 64 || !app.bytes().all(|b| (0x21..0x7f).contains(&b)) {
            return Err("that key's application is not valid".into());
        }
        meta.application = Some(app.to_string());
    }
    let att = &v["attestation"];
    if att.is_null() {
        return Ok(meta);
    }
    if !ktype.is_fido2() {
        return Err("only a FIDO2 key has an attestation".into());
    }
    let challenge = gates
        .enrol_challenges
        .take(v["enrol_id"].as_str().unwrap_or(""), now)?;
    let hexd = |k: &str| -> Result<Vec<u8>, String> {
        ozbox_core::approval_subject::from_hex(att[k].as_str().unwrap_or(""))
            .filter(|b| !b.is_empty() && b.len() <= 16 * 1024)
            .ok_or_else(|| "that attestation is not valid".to_string())
    };
    let roots = gates
        .fido_roots
        .get()
        .cloned()
        .unwrap_or_else(crate::attestation::roots_for_service);
    let now_s = i64::try_from(now / 1000).unwrap_or(0);
    let attested = match (ktype, att["kind"].as_str().unwrap_or("")) {
        (KeyType::SkEd25519 | KeyType::EcdsaSk, "openssh") => {
            let blob = hexd("blob_hex")?;
            let app = meta.application.clone().unwrap_or_default();
            crate::attestation::verify(
                &crate::attestation::Container::OpenSsh {
                    blob: &blob,
                    application: &app,
                },
                &challenge,
                pk,
                &roots,
                now_s,
            )?
        }
        (KeyType::WebauthnP256, "webauthn") => {
            let (object, client) = (hexd("object_hex")?, hexd("client_data_hex")?);
            let rp = meta
                .rp
                .clone()
                .ok_or("a WebAuthn key is enrolled with its relying party")?;
            crate::attestation::verify(
                &crate::attestation::Container::Webauthn {
                    object: &object,
                    client_data_json: &client,
                    rp_id: &rp.rp_id,
                    origin: &rp.origin,
                },
                &challenge,
                pk,
                &roots,
                now_s,
            )?
        }
        _ => return Err("that attestation does not belong to that kind of key".into()),
    };
    // an attestation that verified is recorded either way, but it makes a presence key only where root has turned that on: a
    // real key has not been proved on a box yet, so by default every key is a software key
    meta.presence_proved = gates.presence_keys_on();
    meta.attestation_digest = Some(attested.digest);
    meta.attested_root = Some(attested.root_sha256);
    Ok(meta)
}

/// Answer one request about laptop keys. `Ok(value)` is the `result` of a good answer; `Err` is the sentence to show.
pub fn handle(
    store: &crate::secrets_enc::EncryptedSecrets,
    gates: &Gates,
    policy: Policy,
    v: &Value,
    now: u64,
) -> Result<Value, String> {
    let may = matches!(
        policy,
        Policy::Unsealed | Policy::Supervisor | Policy::Admin
    );
    if !may {
        return Err("that is not allowed on this socket".into());
    }
    let id = v["key_id"].as_str().unwrap_or("");
    let s = |k: &str| v[k].as_str().unwrap_or("").to_string();
    match v["op"].as_str().unwrap_or("") {
        "approval_keys" => {
            let ids: Vec<String> = store
                .names(KEY_PREFIX)
                .map_err(|e| e.0)?
                .into_iter()
                .filter_map(|n| n.strip_prefix(KEY_PREFIX).map(str::to_string))
                .filter(|i| id_ok(i))
                .collect();
            // How each key came to be trusted (additive). A key with none was enrolled by a version that did not record
            // it, which let the box user enrol one before any second factor existed: `ozbox upgrade` lists those.
            let mut via = serde_json::Map::new();
            for i in &ids {
                via.insert(
                    i.clone(),
                    store
                        .get(&via_name(i))
                        .map_err(|e| e.0)?
                        .map_or(Value::Null, Value::String),
                );
            }
            let mut info = crate::approval_keystore::list_keys(store, now)?;
            // presence follows root's flag as it stands now, not as it stood at enrolment (phase 2 re-check NL2)
            if !gates.presence_keys_on() {
                for k in &mut info {
                    k.presence = "none";
                }
            }
            Ok(json!({"keys": ids, "via": via, "info": info}))
        }
        "approval_key_enrol_challenge" => {
            let ids = gates.requests.get().map(|r| r.ids()).ok_or(
                "this service does not keep approval requests, so a key cannot be attested here",
            )?;
            let (enrol_id, challenge, expires_ms) =
                gates
                    .enrol_challenges
                    .issue(&ids, class_of(policy.word()), now)?;
            Ok(
                json!({"enrol_id": enrol_id, "challenge": ozbox_core::audit::hex(&challenge), "expires_ms": expires_ms}),
            )
        }
        "approval_key_enroll" => {
            use ozbox_core::approval::KeyType;
            let kt = v["key_type"].as_str().unwrap_or("ed25519");
            let ktype =
                KeyType::parse(kt).ok_or("that kind of key is not one this version knows")?;
            let pk = s("public_key");
            let want_len = match ktype {
                KeyType::Ed25519 | KeyType::SkEd25519 => 64,
                KeyType::EcdsaSk | KeyType::WebauthnP256 => 130,
            };
            if !id_ok(id) || pk.len() != want_len || unhex(&pk).is_none() {
                return Err("that key is not valid".into());
            }
            if public_key(store, id)?.is_some() {
                return Err("a key with that name is already enrolled: revoke it first".into());
            }
            // what the key was made for, and whether an attestation proves it needs a touch. Presence is proved
            // here and nowhere else: a laptop's claim of it is not read.
            let request_id = s("request_id");
            // by request, the attestation was verified when the request was filed: only the kept verdict is read here
            let by_request = !request_id.is_empty() && v["attestation"].is_null();
            let attested_digest = s("attestation_digest");
            let mut meta = if by_request && !attested_digest.is_empty() {
                pending_meta(store, &attested_digest, &pk, now)?
            } else {
                build_meta(gates, v, ktype, kt, &pk, now)?
            };
            let digest = meta.attestation_digest.clone().unwrap_or_default();
            // a second factor that can approve its own enrolment would let the box user add one: so the first is never
            // enrolled from a socket the box user can reach, and every later one needs an approval it cannot make: a code
            // from before, or an approved `signer-enroll` request spent here
            // a key enrolled by a code, on a box that has had one before, serves the 24-hour wait too
            let ever_key = match gates.requests.get() {
                Some(svc) => svc.ctx(store).map(|(c, _)| c.ever_key)?,
                None => ever_key_in_store(store)?,
            };
            let via = if policy == Policy::Admin {
                "root".to_string()
            } else if !request_id.is_empty() {
                let svc = gates
                    .requests
                    .get()
                    .ok_or("this service does not keep approval requests")?;
                let subject = ozbox_core::approval_subject::Subject::SignerEnroll(
                    ozbox_core::approval_subject::SignerEnroll {
                        action: ozbox_core::approval_subject::EnrolAction::Enrol,
                        key_name: id.to_string(),
                        key_type: kt.to_string(),
                        public_half: pk.clone(),
                        attestation_digest: digest.clone(),
                    },
                );
                let r = svc.spend(
                    store,
                    gates,
                    ozbox_core::approval::SpendVia::Inside,
                    &request_id,
                    &subject,
                    now,
                )?;
                let who = r
                    .decision
                    .as_ref()
                    .map_or_else(|| "request".to_string(), |d| d.factor_label.clone());
                format!("request:{who}")
            } else {
                // the dashboard's socket enrols by an approved request only; a code is the ingress route's, and only while
                // the legacy setting allows codes at all
                if policy == Policy::Supervisor && gates.requests_guarded() {
                    return Err("a key is enrolled from the dashboard by an approved request, not by a code".into());
                }
                let via = require_signer_change(store, gates, policy, id, &s("approval"), now)?;
                if ever_key {
                    meta.active_from_ms = now + ENROL_WAIT_MS;
                }
                via
            };
            // the meta first and the public half last, so a failure in between leaves no key with no record (L4); the marker
            // and the `.via` record follow
            crate::approval_keystore::write_meta(store, id, &meta)?;
            if let Err(e) = store.set(&format!("{KEY_PREFIX}{id}"), &pk) {
                let _ = store.delete(&crate::approval_keystore::meta_name(id));
                return Err(e.0);
            }
            if let Err(e) = note_key_enrolled(store) {
                let _ = store.delete(&format!("{KEY_PREFIX}{id}"));
                let _ = store.delete(&crate::approval_keystore::meta_name(id));
                return Err(e);
            }
            if by_request && !attested_digest.is_empty() {
                let _ = store.delete(&format!("{PENDING_PREFIX}{attested_digest}"));
            }
            if let Some(svc) = gates.requests.get() {
                svc.note_key(meta.presence_proved)?;
                if !request_id.is_empty() {
                    let _ = svc.finish_inside(&request_id, now);
                }
            }
            store.set(&via_name(id), &via).map_err(|e| e.0)?;
            // from now on a gated change needs an approval
            store
                .set(crate::secrets_approval::ENROLLED_MARKER, "1")
                .map_err(|e| e.0)?;
            gates.audit_event(
                store,
                "secrets.signer.enrolled",
                id,
                &format!(
                    "via={via} socket={} type={kt} presence={}",
                    policy.word(),
                    if meta.presence_proved {
                        "proved"
                    } else {
                        "none"
                    }
                ),
            );
            Ok(
                json!({"via": via, "presence": if meta.presence_proved { "proved" } else { "none" }}),
            )
        }
        "approval_key_revoke" => {
            if public_key(store, id)?.is_none() {
                return Err("no key with that name is enrolled".into());
            }
            let request_id = s("request_id");
            let via = if policy == Policy::Admin {
                "root".to_string()
            } else if policy == Policy::Supervisor && v["dashboard_stepup"].as_bool() == Some(true)
            {
                // the dashboard's own operation (an owner, with a passkey shown a moment ago, both checked by the supervisor):
                // no code is made for it, so no code can be reused to enrol a key
                "dashboard-stepup".to_string()
            } else if !request_id.is_empty() {
                let svc = gates
                    .requests
                    .get()
                    .ok_or("this service does not keep approval requests")?;
                let have = public_key(store, id)?.unwrap_or_default();
                let meta = crate::approval_keystore::read_meta(store, id)?;
                let subject = ozbox_core::approval_subject::Subject::SignerEnroll(
                    ozbox_core::approval_subject::SignerEnroll {
                        action: ozbox_core::approval_subject::EnrolAction::Revoke,
                        key_name: id.to_string(),
                        key_type: meta
                            .as_ref()
                            .map_or_else(|| "ed25519".to_string(), |m| m.key_type.clone()),
                        public_half: have,
                        attestation_digest: meta
                            .and_then(|m| m.attestation_digest)
                            .unwrap_or_default(),
                    },
                );
                let r = svc.spend(
                    store,
                    gates,
                    ozbox_core::approval::SpendVia::Inside,
                    &request_id,
                    &subject,
                    now,
                )?;
                let who = r
                    .decision
                    .as_ref()
                    .map_or_else(|| "request".to_string(), |d| d.factor_label.clone());
                format!("request:{who}")
            } else {
                require_signer_change(store, gates, policy, id, &s("approval"), now)?
            };
            let pk = public_key(store, id)?.unwrap_or_default();
            store
                .delete(&format!("{KEY_PREFIX}{id}"))
                .map_err(|e| e.0)?;
            let _ = store.delete(&via_name(id));
            let _ = store.delete(&crate::approval_keystore::meta_name(id));
            if let Some(svc) = gates.requests.get() {
                if !request_id.is_empty() {
                    let _ = svc.finish_inside(&request_id, now);
                }
            }
            if let Some(d) = gates.pin_record.get() {
                crate::secrets_recover::record_pin(
                    d,
                    "revoked",
                    &crate::secrets_recover::pin_digest(id, &pk),
                );
            }
            gates.audit_event(
                store,
                "secrets.signer.revoked",
                id,
                &format!("via={via} socket={}", policy.word()),
            );
            Ok(json!({"via": via}))
        }
        "approval_challenge" => {
            if !gates.codes_allowed() {
                return Err(crate::secrets_service::CODES_REFUSED.into());
            }
            if public_key(store, id)?.is_none() {
                return Err("that key is not enrolled on this box".into());
            }
            // a key still in its wait makes no code, here or at redeem (phase 2 re-check NM1)
            if in_wait(store, id, now)? {
                return Err(IN_WAIT.into());
            }
            let (nonce, expires_ms) = gates.challenges.issue(
                policy.word(),
                id,
                &s("scope"),
                &s("project"),
                &s("env"),
                now,
            )?;
            Ok(json!({"nonce": nonce, "expires_ms": expires_ms}))
        }
        "approval_redeem" => {
            if !gates.codes_allowed() {
                return Err(crate::secrets_service::CODES_REFUSED.into());
            }
            let ch = gates.challenges.take(id, &s("nonce"), now)?;
            let refuse = |why: &str| {
                // bounded, never a lockout: a bad signature on a live nonce can be sent as often as a process likes
                gates.audit_event_bounded(
                    store,
                    "secrets.signer.refused",
                    id,
                    &format!("why={why}"),
                    now,
                );
                Err::<Value, String>("that signature is not valid: no approval was made".into())
            };
            let Some(pk) = public_key(store, id)? else {
                return refuse("not-enrolled");
            };
            // the wait is read again here: the record can change between the challenge and the answer
            if in_wait(store, id, now)? {
                gates.audit_event_bounded(store, "secrets.signer.refused", id, "why=in-wait", now);
                return Err(IN_WAIT.into());
            }
            let msg = message(
                &ch.scope,
                &ch.project,
                &ch.env,
                id,
                &ch.nonce,
                ch.expires_ms,
            );
            if !verify(&pk, &msg, &s("signature")) {
                return refuse("bad-signature");
            }
            let via = format!("laptop-key:{id}");
            let code = gates.approvals.mint(
                &ch.scope,
                &ch.project,
                &ch.env,
                &via,
                now,
                crate::secrets_approval::DEFAULT_TTL_MS,
            )?;
            gates.audit_event(
                store,
                "secrets.approval.minted",
                &ch.scope,
                &format!("project={} env={} via={via}", ch.project, ch.env),
            );
            Ok(
                json!({"code": code, "scope": ch.scope, "project": ch.project, "env": ch.env,
                "expires_in_seconds": crate::secrets_approval::DEFAULT_TTL_MS / 1000}),
            )
        }
        _ => Err("that is not allowed on this socket".into()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::secrets_enc::{EncryptedSecrets, KeyProvider, LocalKekProvider};
    use std::sync::Arc;

    const NOW: u64 = 1_000_000;

    struct Rig {
        store: Arc<EncryptedSecrets>,
        gates: Gates,
        dir: std::path::PathBuf,
        _t: tempfile::TempDir,
    }

    fn rig() -> Rig {
        let t = tempfile::tempdir().unwrap();
        let p: Arc<dyn KeyProvider> = Arc::new(LocalKekProvider::random("local").unwrap());
        let store = Arc::new(EncryptedSecrets::new(t.path().join("s.json"), "box-a", p).unwrap());
        let gates = Gates::default();
        let dir = t.path().join("audit");
        gates
            .audit
            .set(Arc::new(crate::audit_service::AuditCfg::new(
                &dir,
                t.path().join("anchor"),
            )))
            .ok()
            .unwrap();
        Rig {
            store,
            gates,
            dir,
            _t: t,
        }
    }

    impl Rig {
        fn call(&self, p: Policy, v: Value, now: u64) -> Result<Value, String> {
            handle(&self.store, &self.gates, p, &v, now)
        }
        fn enroll(&self, id: &str, pk: &str) -> Result<Value, String> {
            self.call(
                Policy::Admin,
                json!({"op":"approval_key_enroll","key_id":id,"public_key":pk}),
                NOW,
            )
        }
        /// The whole laptop side: challenge, sign, redeem.
        fn approve(
            &self,
            seed: &str,
            id: &str,
            scope: &str,
            project: &str,
            env: &str,
            now: u64,
        ) -> Result<Value, String> {
            let ch = self.call(Policy::Unsealed, json!({"op":"approval_challenge","key_id":id,"scope":scope,"project":project,"env":env}), now)?;
            let nonce = ch["nonce"].as_str().unwrap();
            let exp = ch["expires_ms"].as_u64().unwrap();
            let sig = sign(seed, &message(scope, project, env, id, nonce, exp)).unwrap();
            self.call(
                Policy::Unsealed,
                json!({"op":"approval_redeem","key_id":id,"nonce":nonce,"signature":sig}),
                now + 1,
            )
        }
        fn chain(&self) -> String {
            std::fs::read_to_string(self.dir.join("tasks.audit.jsonl")).unwrap_or_default()
        }
    }

    /// The approval primitive signs a dashboard sign-in replacement for exactly one settings digest, with the binding the root helper
    /// recomputes from the staged file. (No command makes this approval with the laptop key: it is made in the dashboard.)
    #[test]
    fn the_laptop_key_approves_a_dashboard_sign_in_replacement_for_one_settings_digest_only() {
        let r = rig();
        let (seed, pk) = generate().unwrap();
        r.enroll("laptop", &pk).unwrap();
        let (a, b) = ("ab".repeat(16), "cd".repeat(16));
        let out = r
            .approve(&seed, "laptop", "dashboard-auth", "", &a, NOW)
            .unwrap();
        let code = out["code"].as_str().unwrap().to_string();
        assert!(r
            .gates
            .require(&r.store, "dashboard-auth", "", &b, &code, NOW + 5)
            .is_err());
        assert_eq!(
            r.gates
                .require(&r.store, "dashboard-auth", "", &a, &code, NOW + 6)
                .unwrap(),
            "laptop-key:laptop"
        );
        assert!(
            r.gates
                .require(&r.store, "dashboard-auth", "", &a, &code, NOW + 7)
                .is_err(),
            "single use"
        );
    }

    #[test]
    fn a_signed_challenge_makes_the_same_single_use_scoped_code_the_dashboard_does() {
        let r = rig();
        let (seed, pk) = generate().unwrap();
        r.enroll("laptop", &pk).unwrap();
        let out = r
            .approve(&seed, "laptop", "import", "app", "staging", NOW)
            .unwrap();
        let code = out["code"].as_str().unwrap().to_string();
        // it is spent by the one change it names, with the honest record of how it was confirmed
        assert!(r
            .gates
            .require(&r.store, "import", "other", "staging", &code, NOW + 5)
            .is_err());
        assert!(r
            .gates
            .require(&r.store, "import", "app", "prod", &code, NOW + 5)
            .is_err());
        let via = r
            .gates
            .require(&r.store, "import", "app", "staging", &code, NOW + 5)
            .unwrap();
        assert_eq!(via, "laptop-key:laptop");
        assert!(
            r.gates
                .require(&r.store, "import", "app", "staging", &code, NOW + 6)
                .is_err(),
            "single use"
        );
        // the chain says how it was confirmed, and holds no code, signature or nonce
        let chain = r.chain();
        assert!(chain.contains("secrets.approval.minted") && chain.contains("laptop-key:laptop"));
        assert!(chain.contains("secrets.approval.spent"));
        assert!(!chain.contains(&code.replace('-', "")) && !chain.contains(&code));
    }

    #[test]
    fn a_challenge_is_good_once_for_one_scope_and_for_sixty_seconds() {
        let r = rig();
        let (seed, pk) = generate().unwrap();
        r.enroll("laptop", &pk).unwrap();
        let ch = r
            .call(Policy::Unsealed, json!({"op":"approval_challenge","key_id":"laptop","scope":"import","project":"app","env":"staging"}), NOW)
            .unwrap();
        let (nonce, exp) = (
            ch["nonce"].as_str().unwrap().to_string(),
            ch["expires_ms"].as_u64().unwrap(),
        );
        assert_eq!(exp, NOW + CHALLENGE_TTL_MS);
        // a signature over another scope (or project, environment, key or nonce) does not verify, and spends the challenge
        let wrong = sign(
            &seed,
            &message("policy", "app", "staging", "laptop", &nonce, exp),
        )
        .unwrap();
        let e = r
            .call(
                Policy::Unsealed,
                json!({"op":"approval_redeem","key_id":"laptop","nonce":nonce,"signature":wrong}),
                NOW + 1,
            )
            .unwrap_err();
        assert!(e.contains("not valid"), "{e}");
        // replaying the right signature now fails: the challenge is gone
        let right = sign(
            &seed,
            &message("import", "app", "staging", "laptop", &nonce, exp),
        )
        .unwrap();
        assert!(r.call(Policy::Unsealed, json!({"op":"approval_redeem","key_id":"laptop","nonce":nonce,"signature":right.clone()}), NOW + 2).is_err());
        // an expired challenge is refused even with a right signature
        let ch2 = r
            .call(Policy::Unsealed, json!({"op":"approval_challenge","key_id":"laptop","scope":"import","project":"app","env":"staging"}), NOW)
            .unwrap();
        let (n2, e2) = (
            ch2["nonce"].as_str().unwrap(),
            ch2["expires_ms"].as_u64().unwrap(),
        );
        let s2 = sign(
            &seed,
            &message("import", "app", "staging", "laptop", n2, e2),
        )
        .unwrap();
        assert!(r
            .call(
                Policy::Unsealed,
                json!({"op":"approval_redeem","key_id":"laptop","nonce":n2,"signature":s2}),
                NOW + CHALLENGE_TTL_MS + 1
            )
            .is_err());
        let chain = r.chain();
        assert!(chain.contains("secrets.signer.refused") && chain.contains("why=bad-signature"));
        assert!(!chain.contains(&right));
    }

    #[test]
    fn another_key_an_unenrolled_key_and_a_revoked_key_cannot_make_an_approval() {
        let r = rig();
        let (seed, pk) = generate().unwrap();
        let (other, _) = generate().unwrap();
        r.enroll("laptop", &pk).unwrap();
        // a key the box does not know gets no challenge at all
        assert!(r
            .call(
                Policy::Unsealed,
                json!({"op":"approval_challenge","key_id":"nobody","scope":"import"}),
                NOW
            )
            .is_err());
        // someone else's private key signs for the enrolled name: refused
        assert!(r
            .approve(&other, "laptop", "import", "app", "staging", NOW)
            .is_err());
        // revoked between challenge and redeem: refused
        let ch = r.call(Policy::Unsealed, json!({"op":"approval_challenge","key_id":"laptop","scope":"import","project":"app","env":"staging"}), NOW).unwrap();
        let (nonce, exp) = (
            ch["nonce"].as_str().unwrap().to_string(),
            ch["expires_ms"].as_u64().unwrap(),
        );
        r.call(
            Policy::Admin,
            json!({"op":"approval_key_revoke","key_id":"laptop"}),
            NOW + 1,
        )
        .unwrap();
        let sig = sign(
            &seed,
            &message("import", "app", "staging", "laptop", &nonce, exp),
        )
        .unwrap();
        assert!(r
            .call(
                Policy::Unsealed,
                json!({"op":"approval_redeem","key_id":"laptop","nonce":nonce,"signature":sig}),
                NOW + 2
            )
            .is_err());
        assert!(r
            .call(Policy::Unsealed, json!({"op":"approval_keys"}), NOW + 3)
            .unwrap()["keys"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn enrolling_needs_an_approval_once_a_second_factor_exists_and_the_box_socket_cannot_do_any_of_it(
    ) {
        let r = rig();
        let (_, pk1) = generate().unwrap();
        let (_, pk2) = generate().unwrap();
        // the box user's socket may do none of this
        for op in [
            "approval_keys",
            "approval_key_enroll",
            "approval_key_revoke",
            "approval_challenge",
            "approval_redeem",
        ] {
            for p in [
                Policy::Box,
                Policy::BoxLocked,
                Policy::Runner,
                Policy::Import,
                Policy::Ingress,
            ] {
                let e = r
                    .call(p, json!({"op":op,"key_id":"x","public_key":pk1}), NOW)
                    .unwrap_err();
                assert!(e.contains("not allowed"), "{op} {p:?}");
            }
        }
        // before any second factor, no socket the box user can reach may enrol the first key, nor revoke one
        for p in [Policy::Unsealed, Policy::Supervisor] {
            let e = r
                .call(
                    p,
                    json!({"op":"approval_key_enroll","key_id":"laptop","public_key":pk1}),
                    NOW,
                )
                .unwrap_err();
            assert!(e.contains("no approver yet"), "{p:?}: {e}");
        }
        assert!(r.store.get("approval-key.laptop").unwrap().is_none());
        assert!(!r
            .store
            .exists(crate::secrets_approval::ENROLLED_MARKER)
            .unwrap());
        assert!(r.chain().contains("why=no-approver socket=ingress"));
        // root may (the admin socket), and the record says which socket it came in on
        let v = r
            .call(
                Policy::Admin,
                json!({"op":"approval_key_enroll","key_id":"laptop","public_key":pk1}),
                NOW,
            )
            .unwrap();
        assert_eq!(v["via"], "root");
        assert!(r.chain().contains("via=root socket=admin"));
        // ... and from then on a second key needs an approval, which the box user cannot make for itself
        let e = r
            .call(
                Policy::Unsealed,
                json!({"op":"approval_key_enroll","key_id":"mine","public_key":pk2}),
                NOW + 1,
            )
            .unwrap_err();
        assert!(e.contains("approval"), "{e}");
        assert!(r.store.get("approval-key.mine").unwrap().is_none());
        // one from the dashboard (or an enrolled key) for exactly this enrolment lets it through, once
        let code = r
            .gates
            .approvals
            .mint("signer-enroll", "mine", "", "dashboard-stepup", NOW, 60_000)
            .unwrap();
        let v = r.call(Policy::Unsealed, json!({"op":"approval_key_enroll","key_id":"mine","public_key":pk2,"approval":code}), NOW + 2).unwrap();
        assert_eq!(v["via"], "dashboard-stepup");
        // a name cannot be enrolled twice
        assert!(r
            .call(
                Policy::Admin,
                json!({"op":"approval_key_enroll","key_id":"mine","public_key":pk2}),
                NOW + 3
            )
            .is_err());
        // a malformed key or name is refused
        assert!(r
            .call(
                Policy::Admin,
                json!({"op":"approval_key_enroll","key_id":"Bad Name","public_key":pk2}),
                NOW
            )
            .is_err());
        assert!(r
            .call(
                Policy::Admin,
                json!({"op":"approval_key_enroll","key_id":"ok","public_key":"zz"}),
                NOW
            )
            .is_err());
    }

    /// The finding this closes: on a fresh box the agent enrolled its own key through the import socket and from then on
    /// approved everything itself. Its whole attack, step by step, must fail.
    #[test]
    fn on_a_fresh_box_the_agent_cannot_enrol_its_own_key_and_approve_for_itself() {
        let r = rig();
        let (seed, pk) = generate().unwrap();
        assert!(r
            .call(
                Policy::Unsealed,
                json!({"op":"approval_key_enroll","key_id":"agent","public_key":pk}),
                NOW
            )
            .is_err());
        assert!(r
            .approve(&seed, "agent", "import", "app", "staging", NOW + 1)
            .is_err());
        // the box is still in bootstrap: nothing was recorded as a second factor
        assert!(!r
            .store
            .exists(crate::secrets_approval::ENROLLED_MARKER)
            .unwrap());
    }

    #[test]
    fn base32_round_trips_and_a_pin_fits_a_hetzner_label() {
        for n in 0..40usize {
            let b: Vec<u8> = (0..n as u8).map(|i| i.wrapping_mul(37)).collect();
            assert_eq!(unbase32(&base32(&b)).unwrap(), b);
        }
        let (_, pk) = generate().unwrap();
        let label = pin_label(&pk).unwrap();
        assert_eq!(label.len(), 52);
        assert!(label.len() <= 63 && label.bytes().all(|c| c.is_ascii_alphanumeric()));
        assert!(unbase32("a!").is_none());
        // a last character with stray low bits is not an encoding of anything
        assert!(unbase32("ab").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn the_key_pinned_at_creation_is_enrolled_once_and_a_revocation_sticks() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let r = rig();
        let (seed, pk) = generate().unwrap();
        let file = r.dir.with_file_name("approval-keys");
        std::fs::write(&file, format!("laptop {}\n", pin_label(&pk).unwrap())).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        let me = std::fs::metadata(&file).unwrap().uid();
        // a file someone else owns (on a box: not root) is ignored
        assert!(read_pin_owned_by(&file, me + 1).is_err());
        // a file others may write is ignored
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(read_pin_owned_by(&file, me).is_err());
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        let pin = read_pin_owned_by(&file, me).unwrap();
        assert_eq!(pin, Some(("laptop".to_string(), pk.clone())));
        assert_eq!(
            apply_pin(&r.store, &r.gates, pin.clone())
                .unwrap()
                .as_deref(),
            Some("laptop")
        );
        assert!(r
            .store
            .exists(crate::secrets_approval::ENROLLED_MARKER)
            .unwrap());
        assert!(r.chain().contains("via=pinned"));
        // the pinned key approves
        assert!(r
            .approve(&seed, "laptop", "import", "app", "staging", NOW)
            .is_ok());
        // revoked by root, it is not enrolled again at the next start
        r.call(
            Policy::Admin,
            json!({"op":"approval_key_revoke","key_id":"laptop"}),
            NOW + 2,
        )
        .unwrap();
        assert_eq!(apply_pin(&r.store, &r.gates, pin).unwrap(), None);
        assert!(r.store.get("approval-key.laptop").unwrap().is_none());
        // a missing file pins nothing
        assert_eq!(read_pin_owned_by(&r.dir.join("none"), me).unwrap(), None);
        // and the box socket may neither touch nor see the pin's record
        assert!(!crate::secrets_service::box_may_write(PIN_APPLIED));
    }

    /// A security review (2026-11-11): the record that a pinned key was applied lived only in the store, so a store
    /// started anew after a recovery enrolled again a pinned key its owner had revoked. The revocation is now also kept on
    /// /work beside the store's copy, which a recovery does not touch.
    #[test]
    fn a_new_store_after_a_recovery_does_not_bring_back_a_revoked_pin() {
        let r = rig();
        let persist = r.dir.with_file_name("persist");
        let _ = r.gates.pin_record.set(persist.clone());
        let (_, pk) = generate().unwrap();
        let pin = Some(("laptop".to_string(), pk.clone()));
        assert_eq!(
            apply_pin(&r.store, &r.gates, pin.clone())
                .unwrap()
                .as_deref(),
            Some("laptop")
        );
        r.call(
            Policy::Admin,
            json!({"op":"approval_key_revoke","key_id":"laptop"}),
            NOW,
        )
        .unwrap();
        // the store is set aside: a new, empty one with the same record on /work
        let fresh = rig();
        let _ = fresh.gates.pin_record.set(persist.clone());
        assert_eq!(
            apply_pin(&fresh.store, &fresh.gates, pin.clone()).unwrap(),
            None
        );
        assert!(fresh.store.get("approval-key.laptop").unwrap().is_none());
        // a pin that was never revoked is enrolled in the new store as it was in the old one
        let other = rig();
        let _ = other
            .gates
            .pin_record
            .set(other.dir.with_file_name("persist"));
        assert!(apply_pin(&other.store, &other.gates, pin)
            .unwrap()
            .is_some());
    }

    #[test]
    fn the_private_key_is_never_in_a_request_an_answer_or_the_chain() {
        let r = rig();
        let (seed, pk) = generate().unwrap();
        assert_eq!(public_of(&seed).unwrap(), pk);
        r.enroll("laptop", &pk).unwrap();
        let out = r
            .approve(&seed, "laptop", "import", "app", "staging", NOW)
            .unwrap();
        assert!(!out.to_string().contains(seed.as_str()));
        assert!(!r.chain().contains(seed.as_str()));
        assert!(!format!("{:?}", r.store.names("")).contains(seed.as_str()));
        // the stored value is the public half
        assert_eq!(r.store.get("approval-key.laptop").unwrap().unwrap(), pk);
    }

    /// ADR 0041 §12 tests: garbage never locks the signature path, and a box-user process that fills its pool
    /// of challenges cannot stop the supervisor's or root's.
    #[test]
    fn wrong_signatures_lock_nothing_and_a_right_one_works_straight_after() {
        let r = rig();
        let (seed, pk) = generate().unwrap();
        r.enroll("laptop", &pk).unwrap();
        for i in 0..200 {
            let _ = r.call(Policy::Unsealed, json!({"op":"approval_redeem","key_id":"laptop","nonce":format!("n{i}"),"signature":"00"}), NOW + i as u64);
        }
        assert!(r
            .approve(&seed, "laptop", "import", "app", "staging", NOW + 300)
            .is_ok());
    }

    /// Regression: with the lockout gone, every bad signature on a live nonce was a chain line,
    /// each one taking the store's lock. A flood of them is bounded now, counted, and never locks anything.
    #[test]
    fn a_flood_of_bad_signatures_on_live_nonces_writes_a_bounded_number_of_chain_lines() {
        let r = rig();
        let (seed, pk) = generate().unwrap();
        r.enroll("laptop", &pk).unwrap();
        for i in 0..1000u64 {
            let t = NOW + i % 30_000;
            let ch = r
                .call(
                    Policy::Unsealed,
                    json!({"op":"approval_challenge","key_id":"laptop","scope":"import","project":"app","env":"staging"}),
                    t,
                )
                .unwrap();
            let nonce = ch["nonce"].as_str().unwrap();
            let bad = r.call(
                Policy::Unsealed,
                json!({"op":"approval_redeem","key_id":"laptop","nonce":nonce,"signature":"00"}),
                t,
            );
            assert!(bad.is_err());
        }
        let lines = r
            .chain()
            .lines()
            .filter(|l| l.contains("secrets.signer.refused"))
            .count();
        assert!(
            lines <= crate::secrets_service::REFUSED_LINES_PER_KIND_PER_MINUTE as usize,
            "the chain got {lines} refused lines for 1000 bad redeems in one minute"
        );
        assert!(lines > 0, "the first ones are still recorded");
        // nothing is locked: a right signature straight after works, and the next minute says how many were left out
        assert!(r
            .approve(&seed, "laptop", "import", "app", "staging", NOW + 30_000)
            .is_ok());
        let _ = r.call(
            Policy::Unsealed,
            json!({"op":"approval_redeem","key_id":"laptop","nonce":"zz","signature":"00"}),
            NOW + 90_000,
        );
        let ch = r
            .call(
                Policy::Unsealed,
                json!({"op":"approval_challenge","key_id":"laptop","scope":"import","project":"app","env":"staging"}),
                NOW + 90_000,
            )
            .unwrap();
        let _ = r.call(
            Policy::Unsealed,
            json!({"op":"approval_redeem","key_id":"laptop","nonce":ch["nonce"],"signature":"00"}),
            NOW + 90_001,
        );
        assert!(
            r.chain().contains("coalesced="),
            "the count of lines left out is written once"
        );
    }

    /// Since the ingress route (ADR 0029 Amendment 9) no socket the box user can reach takes a challenge at all, so it cannot
    /// fill a pool; the box-user pool stays as a floor in case one ever does. The laptop's (ingress), the supervisor's and
    /// root's paths are unaffected.
    #[test]
    fn a_box_user_process_cannot_ask_for_challenges_and_the_other_sockets_still_can() {
        let r = rig();
        let (seed, pk) = generate().unwrap();
        r.enroll("laptop", &pk).unwrap();
        let ask = |p: Policy, i: u64| {
            r.call(
                p,
                json!({"op":"approval_challenge","key_id":"laptop","scope":"import","project":"app","env":"staging"}),
                NOW + i,
            )
        };
        for i in 0..(MAX_LIVE_BOX_USER as u64 * 2) {
            assert!(ask(Policy::Import, i).is_err());
            assert!(ask(Policy::Box, i).is_err());
        }
        assert!(ask(Policy::Unsealed, 100).is_ok());
        assert!(ask(Policy::Supervisor, 100).is_ok());
        assert!(ask(Policy::Admin, 101).is_ok());
        let _ = seed;
    }

    /// A count of refusals left out is written when the window has closed, by any later call, and not only by another refusal
    /// of the same kind that may never come.
    #[test]
    fn a_closed_refusal_window_is_flushed_by_a_later_call_and_only_once() {
        let r = rig();
        for _ in 0..15 {
            r.gates
                .audit_event_bounded(&*r.store, "secrets.signer.refused", "x", "why=t", NOW);
        }
        assert!(!r.chain().contains("coalesced"), "the window is still open");
        r.gates.flush_refused(&*r.store, NOW + 1_000, None);
        assert!(
            !r.chain().contains("coalesced"),
            "not before the minute is up"
        );
        r.gates.flush_refused(&*r.store, NOW + 60_000, None);
        assert!(r.chain().contains("coalesced=5"), "{}", r.chain());
        r.gates.flush_refused(&*r.store, NOW + 120_000, None);
        assert_eq!(r.chain().matches("coalesced").count(), 1);
    }

    /// The laptop's challenges (the ingress account) have a pool of their own: the dashboard's (supervisor) filling its pool
    /// and root's filling theirs leave the laptop able to ask, and the other way round.
    #[test]
    fn each_class_of_socket_has_its_own_pool_so_the_dashboard_cannot_use_up_the_laptops() {
        let r = rig();
        let (_seed, pk) = generate().unwrap();
        r.enroll("laptop", &pk).unwrap();
        let ask = |p: Policy| {
            r.call(
                p,
                json!({"op":"approval_challenge","key_id":"laptop","scope":"import","project":"app","env":"staging"}),
                NOW,
            )
        };
        for _ in 0..MAX_LIVE_SUPERVISOR {
            assert!(ask(Policy::Supervisor).is_ok());
        }
        assert!(
            ask(Policy::Supervisor).is_err(),
            "the supervisor's pool is full"
        );
        for _ in 0..MAX_LIVE_ROOT {
            assert!(ask(Policy::Admin).is_ok());
        }
        assert!(ask(Policy::Admin).is_err(), "root's pool is full");
        // the laptop still gets all of its own
        for _ in 0..MAX_LIVE_LAPTOP {
            assert!(ask(Policy::Unsealed).is_ok());
        }
        assert!(ask(Policy::Unsealed).is_err(), "the laptop's pool is full");
        // and a full laptop pool did not take the supervisor's back
        assert!(ask(Policy::Supervisor).is_err());
    }
}
