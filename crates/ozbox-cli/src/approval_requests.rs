//! The secrets service's request operations (ADR 0041, phase 1): the **request journal**, the **epoch**, the long wait and
//! the operations `file`, `get`, `list`, `await`, `decide_challenge`, `decide`, `spend`, `finish`, `cancel`,
//! `decider_revoked` and `new_epoch`, each answered only on the sockets that may use it.
//!
//! The model itself (the state machine, the rule table, the subject digest) is `ozbox_core::approval` and
//! `ozbox_core::approval_subject`; this file is the I/O around it.
//!
//! * **The journal is not the secrets file.** A request holds names, digests and counts only, and it is kept in a file of
//!   its own with its own lock, sealed with AES-256-GCM under a key the secrets store holds. Request churn therefore never
//!   touches the lock `resolve` takes. Nothing here is called by `resolve` or `exec`.
//! * **The epoch and the spent ledger are kept beside the journal in a file of their own** (`approval-state.json`, no
//!   secret in it). A restore that brings back an old journal brings back an old epoch, and the request is void; a journal
//!   copied back inside one epoch cannot revive a request the ledger says was spent.
//! * **`await` is a long poll**, held at most 60 seconds, capped per uid and per request, on a condition variable, never a
//!   busy loop. The caps are what keep `resolve` and the broker answering when a box user opens thousands of them.
//! * **Decided and spent fail closed**: the state changes, then the audit line is written, and if the chain cannot be
//!   written the change is undone. Deny, revoke and cancel fail safe: the state changes at once and the line is retried
//!   later, marked late.
//! * **Reachable now that deciders ship (phase 2).** The service answers these operations only when
//!   [`Gates::enable_requests`] was called (`ozbox secrets serve` does, with a journal directory beside the store and the
//!   state directory beside it); the deciders are the supervisor's passkey route and the laptop's sealed route.
//!
//! No answer to the box socket carries a code, a value or a derived fingerprint: ids, states, expiries and digests only.

// Phase 1 of ADR 0041: the service turns these operations on only when a decider ships (`Gates::enable_requests`), so
// outside tests part of this module is not reached yet. The dispatch in `secrets_service` is.
#![cfg_attr(not(test), allow(dead_code))]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use ozbox_core::approval::{
    op_allowed, Ctx, DecideInput, Decision, Derived, Evidence, Factor, Filing, Op, Outcome,
    Request, RequestBook, Requester, Role, Scope, SignedEnvelope, SocketClass, SpendBy, SpendVia,
    State, Surface, AWAITS_PER_REQUEST, AWAITS_PER_UID, AWAIT_MAX_MS, MAX_REQUESTS, RULES,
};
use ozbox_core::approval_subject::{sanitize_display, to_hex, Ids, Subject};

use crate::secrets::SecretStore;
use crate::secrets_enc::EncryptedSecrets;
use crate::secrets_service::Gates;

/// The store names this module keeps. None is the box user's to write, delete, read or list.
pub const JOURNAL_KEY: &str = "approval-journal-key";
pub const STORE_ID: &str = "approval-store-id";
pub const ENVELOPE_KEY: &str = "approval-envelope-key";
/// This box has ever had a laptop key (set when one is enrolled; cleared only by root).
pub const EVER_KEY_MARKER: &str = "approval-ever-key";
/// This box has ever had a laptop key with proved presence (the sticky marker; set by the attestation verifier of phase 2,
/// cleared only by root).
pub const EVER_PRESENCE_MARKER: &str = "approval-ever-presence-key";
/// Retired (owner decision B): a software key NEVER decides an owner-only scope, and there is no setting that says
/// otherwise. The name stays reserved so the box user cannot write it, and nothing reads it.
pub const SOFTWARE_KEYS_MARKER: &str = "approval-software-key-scopes";
pub const RESERVED: &[&str] = &[
    JOURNAL_KEY,
    STORE_ID,
    ENVELOPE_KEY,
    EVER_KEY_MARKER,
    EVER_PRESENCE_MARKER,
    SOFTWARE_KEYS_MARKER,
];

pub const JOURNAL_FILE: &str = "approval-requests.journal";
pub const STATE_FILE: &str = "approval-state.json";
const SEAL_AAD: &[u8] = b"ozbox-approval-journal-v1";
const KEEP_FINISHED_MS: u64 = 24 * 3_600_000;
const REFUSED_LINES_PER_MINUTE: usize = 60;
const MAX_EVIDENCE_FIELD: usize = 8192;

#[derive(Serialize, Deserialize, Default)]
struct StateFile {
    epoch: String,
    /// Request id to the time after which it no longer matters.
    #[serde(default)]
    spent: BTreeMap<String, u64>,
    /// This box has ever had a laptop key / a laptop key with proved presence (ADR 0041 §3.1). Kept here, beside
    /// the epoch, and not in the secrets store: a new store (a recovery, an adopt, a replace) must not reset them. Cleared
    /// only by root (`areq_clear_markers`).
    #[serde(default)]
    ever_key: bool,
    #[serde(default)]
    ever_presence_key: bool,
    /// The store this state belongs to. A state folder opened beside another store (a recovery, an adopt, a blue-green replace)
    /// starts a new epoch: whatever the journal held is void, and the spent ledger still stands.
    #[serde(default)]
    store_id: String,
}

/// The two "has ever had" markers, in memory (loaded from the state file, written back whenever they change).
#[derive(Default, Clone, Copy)]
struct Markers {
    ever_key: bool,
    ever_presence_key: bool,
}

struct Inner {
    book: RequestBook,
    ledger: BTreeMap<String, u64>,
    /// Lines for a deny, revoke or cancel the chain could not take yet: written later, marked late.
    late: Vec<(String, String, String)>,
}

#[derive(Default)]
struct Caps {
    per_uid: BTreeMap<String, usize>,
    per_request: BTreeMap<String, usize>,
}

/// Holds one place in the await caps and gives it back on drop.
struct AwaitSlot {
    caps: Arc<Mutex<Caps>>,
    uid: String,
    id: String,
}

impl AwaitSlot {
    fn take(caps: &Arc<Mutex<Caps>>, uid: &str, id: &str) -> Result<Self, String> {
        let mut c = caps.lock().unwrap_or_else(|e| e.into_inner());
        if c.per_uid.get(uid).copied().unwrap_or(0) >= AWAITS_PER_UID {
            return Err("too many requests are being waited on: try again in a moment".into());
        }
        if c.per_request.get(id).copied().unwrap_or(0) >= AWAITS_PER_REQUEST {
            return Err("that request is already being waited on".into());
        }
        *c.per_uid.entry(uid.to_string()).or_insert(0) += 1;
        *c.per_request.entry(id.to_string()).or_insert(0) += 1;
        Ok(AwaitSlot {
            caps: caps.clone(),
            uid: uid.to_string(),
            id: id.to_string(),
        })
    }
}

impl Drop for AwaitSlot {
    fn drop(&mut self) {
        let mut c = self.caps.lock().unwrap_or_else(|e| e.into_inner());
        let c = &mut *c;
        give_back(&mut c.per_uid, &self.uid);
        give_back(&mut c.per_request, &self.id);
    }
}

fn give_back(map: &mut BTreeMap<String, usize>, k: &str) {
    if let Some(n) = map.get_mut(k) {
        *n = n.saturating_sub(1);
        if *n == 0 {
            map.remove(k);
        }
    }
}

/// A verdict that could not be kept ends the request THIS filing made, so nothing waits that no one could approve. A filing that
/// joined a request that was already live made nothing: that request has its own history and is left as it is (phase 2 RL3).
/// The end of keeping a verdict at filing: success passes through; a failure cancels the request this filing made (never one it
/// joined) and is handed back to the caller.
fn settle_kept(
    requests: &mut [Request],
    id: &str,
    existing: bool,
    kept: Result<(), String>,
) -> Result<(), String> {
    if kept.is_err() {
        cancel_if_new(requests, id, existing);
    }
    kept
}

fn cancel_if_new(requests: &mut [Request], id: &str, existing: bool) {
    if existing {
        return;
    }
    if let Some(x) = requests.iter_mut().find(|x| x.id == id) {
        x.state = State::Cancelled;
    }
}

/// The request service of one box.
pub struct RequestService {
    journal_dir: PathBuf,
    state_dir: PathBuf,
    ids: Ids,
    key: [u8; 32],
    inner: Mutex<Inner>,
    cv: Condvar,
    caps: Arc<Mutex<Caps>>,
    refused_lines: Mutex<Vec<u64>>,
    markers: Mutex<Markers>,
}

fn random_b32(n: usize) -> Result<String, String> {
    let mut raw = vec![0u8; n];
    getrandom::getrandom(&mut raw).map_err(|_| "no random numbers are available".to_string())?;
    Ok(crate::approval_key::base32(&raw))
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    ozbox_core::approval_subject::from_hex(s)
}

fn seal(key: &[u8; 32], plain: &[u8]) -> Result<Vec<u8>, String> {
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce).map_err(|_| "no random numbers are available".to_string())?;
    let unbound =
        UnboundKey::new(&AES_256_GCM, key).map_err(|_| "encryption failed".to_string())?;
    let k = LessSafeKey::new(unbound);
    let mut buf = plain.to_vec();
    k.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(SEAL_AAD),
        &mut buf,
    )
    .map_err(|_| "encryption failed".to_string())?;
    let mut out = vec![1u8];
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&buf);
    Ok(out)
}

fn open_sealed(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>, String> {
    let damaged = || "the request journal is damaged or was not written by this box".to_string();
    if blob.len() < 1 + 12 + 16 || blob[0] != 1 {
        return Err(damaged());
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&blob[1..13]);
    let unbound = UnboundKey::new(&AES_256_GCM, key).map_err(|_| damaged())?;
    let k = LessSafeKey::new(unbound);
    let mut buf = blob[13..].to_vec();
    let plain = k
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(SEAL_AAD),
            &mut buf,
        )
        .map_err(|_| damaged())?;
    Ok(plain.to_vec())
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|_| "the request journal could not be written".to_string())?;
    f.write_all(bytes)
        .and_then(|()| f.sync_all())
        .map_err(|_| "the request journal could not be written".to_string())?;
    std::fs::rename(&tmp, path).map_err(|_| "the request journal could not be written".to_string())
}

/// A caller-chosen request id as it is written to a log line: cut to the length of a real id and cleaned.
fn log_id(id: &str) -> String {
    sanitize_display(id, 26)
}

fn short(d: &str) -> String {
    d.chars().take(16).collect()
}

impl RequestService {
    /// Open the journal in `journal_dir` and the epoch and spent ledger in `state_dir` (made if they are not there), with
    /// the key and the store id the secrets store holds (made on first use). Two directories on purpose: the state must be
    /// somewhere a restore of the journal does not reach (the journal belongs beside the store's private data, which a
    /// backup never holds and a restore never puts back, `backup_scope`).
    ///
    /// A journal that cannot be opened (damaged, or sealed under another store's key because the store was replaced) is
    /// **set aside** and a new epoch starts: every request in it is void, nothing is revived, and the box can approve again.
    /// The spent ledger of the state file still holds what was spent. A refusal here would leave a box that can never be
    /// approved again until someone deletes a file as root.
    pub fn open(
        store: &EncryptedSecrets,
        journal_dir: &Path,
        state_dir: &Path,
        box_id: &str,
        now_ms: u64,
    ) -> Result<Self, String> {
        let get_or_make = |name: &str, bytes: usize| -> Result<String, String> {
            if let Some(v) = store.get(name).map_err(|e| e.0)? {
                return Ok(v);
            }
            let mut raw = vec![0u8; bytes];
            getrandom::getrandom(&mut raw)
                .map_err(|_| "no random numbers are available".to_string())?;
            let hex = to_hex(&raw);
            store.set(name, &hex).map_err(|e| e.0)?;
            Ok(hex)
        };
        let store_id = get_or_make(STORE_ID, 16)?;
        let ids = Ids {
            box_id: box_id.to_string(),
            store_id,
        };
        ids.validate().map_err(|e| e.0)?;
        let key_bytes =
            unhex(&get_or_make(JOURNAL_KEY, 32)?).ok_or("the journal key is damaged")?;
        let key: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| "the journal key is damaged".to_string())?;
        // made here, once, so no request operation ever writes the secrets store
        if store.get(ENVELOPE_KEY).map_err(|e| e.0)?.is_none() {
            let (seed, _) = crate::approval_key::generate()?;
            store.set(ENVELOPE_KEY, &seed).map_err(|e| e.0)?;
        }
        for d in [journal_dir, state_dir] {
            std::fs::create_dir_all(d)
                .map_err(|_| "the request journal's directory could not be made".to_string())?;
        }

        // if the file cannot be kept for root, refuse to open: a new journal would overwrite the one that should be kept
        let set_aside = |path: &Path| -> Result<(), String> {
            let to = path.with_extension(format!("void-{now_ms}"));
            std::fs::rename(path, to)
                .map_err(|_| "a damaged request journal could not be set aside".to_string())
        };
        let state_path = state_dir.join(STATE_FILE);
        let fresh = || -> Result<StateFile, String> {
            Ok(StateFile {
                epoch: random_b32(16)?,
                spent: BTreeMap::new(),
                ever_key: false,
                ever_presence_key: false,
                store_id: String::new(),
            })
        };
        let mut state: StateFile = match std::fs::read(&state_path) {
            Ok(b) => match serde_json::from_slice(&b) {
                Ok(s) => s,
                Err(_) => {
                    set_aside(&state_path)?;
                    fresh()?
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => fresh()?,
            Err(_) => return Err("the request state file could not be read".into()),
        };
        state.spent.retain(|_, until| *until > now_ms);
        if !state.store_id.is_empty() && state.store_id != ids.store_id {
            state.epoch = random_b32(16)?;
        }
        state.store_id = ids.store_id.clone();
        let jpath = journal_dir.join(JOURNAL_FILE);
        let mut book = match std::fs::read(&jpath) {
            Ok(b) => match open_sealed(&key, &b).and_then(|p| {
                serde_json::from_slice::<RequestBook>(&p).map_err(|_| "damaged".to_string())
            }) {
                Ok(book) => book,
                Err(_) => {
                    // not this box's journal, or damaged: set aside, and a new epoch voids whatever it held
                    set_aside(&jpath)?;
                    state.epoch = random_b32(16)?;
                    RequestBook::new(state.epoch.clone())
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                RequestBook::new(state.epoch.clone())
            }
            Err(_) => return Err("the request journal could not be read".into()),
        };
        // a journal of another epoch came back from a backup: every live request in it is void
        if book.epoch != state.epoch {
            book.new_epoch(state.epoch.clone(), now_ms);
        }
        book.apply_spent_ledger(state.spent.keys().map(String::as_str));
        // A box that had a key before this state file existed (an upgrade), or whose state folder was lost, still has the
        // store's own record of it: seed the markers from it now, so a later new store (a recovery) cannot reset them
        // (this also covers keys revoked before the upgrade).
        let stored = store.names("").map_err(|e| e.0)?;
        let has = |n: &str| stored.iter().any(|x| x == n);
        let any_key = stored.iter().any(|n| {
            n.strip_prefix(crate::approval_key::KEY_PREFIX)
                .is_some_and(|rest| {
                    crate::approval_key::id_ok(rest.strip_suffix(".via").unwrap_or(rest))
                })
        });
        let markers = Markers {
            ever_key: state.ever_key || has(EVER_KEY_MARKER) || any_key,
            ever_presence_key: state.ever_presence_key || has(EVER_PRESENCE_MARKER),
        };
        let svc = RequestService {
            journal_dir: journal_dir.to_path_buf(),
            state_dir: state_dir.to_path_buf(),
            ids,
            key,
            inner: Mutex::new(Inner {
                book,
                ledger: state.spent,
                late: Vec::new(),
            }),
            cv: Condvar::new(),
            caps: Arc::new(Mutex::new(Caps::default())),
            refused_lines: Mutex::new(Vec::new()),
            markers: Mutex::new(markers),
        };
        {
            let g = svc.inner.lock().unwrap_or_else(|e| e.into_inner());
            svc.persist_state(&g)?;
            svc.persist(&g, now_ms)?;
        }
        Ok(svc)
    }

    /// Remember that this box has had a laptop key (and, when `presence`, one whose attestation verified). Written to the
    /// state file at once; nothing but root clears it.
    pub fn note_key(&self, presence: bool) -> Result<(), String> {
        {
            let mut m = self.markers.lock().unwrap_or_else(|e| e.into_inner());
            if m.ever_key && (m.ever_presence_key || !presence) {
                return Ok(());
            }
            m.ever_key = true;
            m.ever_presence_key |= presence;
        }
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        self.persist_state(&g)
    }

    /// Root only: forget both markers (a box whose owner starts over).
    fn clear_markers(&self) -> Result<(), String> {
        *self.markers.lock().unwrap_or_else(|e| e.into_inner()) = Markers::default();
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        self.persist_state(&g)
    }

    /// The generation of `project`/`environment`: a number derived from the rows as they stand (every name and the digest of
    /// its value), bound into an import's digest so an approved import cannot be replayed after any writer changed a value
    /// (§4). Derived, never counted, so no writer can forget to move it, a failed write cannot lose it
    /// and a restored state folder cannot set it back. 48 bits, so a browser reads it exactly. A value that cannot be read
    /// counts as another generation, the stricter reading.
    pub fn import_generation(&self, store: &EncryptedSecrets, project: &str, env: &str) -> u64 {
        use ring::digest::{digest, Context, SHA256};
        let prefix = format!("workload.{project}.{env}.");
        let mut names = store.names(&prefix).unwrap_or_default();
        names.sort();
        if names.is_empty() {
            return 0;
        }
        let mut ctx = Context::new(&SHA256);
        for n in &names {
            ctx.update(n.as_bytes());
            ctx.update(&[0]);
            match store.get(n) {
                Ok(Some(v)) => ctx.update(digest(&SHA256, v.as_bytes()).as_ref()),
                _ => ctx.update(b"unreadable"),
            }
        }
        let d = ctx.finish();
        let b = d.as_ref();
        u64::from_be_bytes([0, 0, b[0], b[1], b[2], b[3], b[4], b[5]])
    }

    /// The box and store ids this service names in every challenge.
    pub fn ids(&self) -> Ids {
        self.ids.clone()
    }

    fn persist(&self, g: &Inner, now_ms: u64) -> Result<(), String> {
        let mut book = g.book.clone();
        // finished requests are kept for a day, and at most half the journal
        book.requests.retain(|r| {
            !r.state.is_terminal() || now_ms.saturating_sub(r.filed_at_ms) < KEEP_FINISHED_MS
        });
        if book.requests.len() > MAX_REQUESTS {
            book.requests.truncate(MAX_REQUESTS);
        }
        let plain = serde_json::to_vec(&book)
            .map_err(|_| "the request journal could not be written".to_string())?;
        write_atomic(
            &self.journal_dir.join(JOURNAL_FILE),
            &seal(&self.key, &plain)?,
        )
    }

    fn persist_state(&self, g: &Inner) -> Result<(), String> {
        let m = *self.markers.lock().unwrap_or_else(|e| e.into_inner());
        let s = StateFile {
            epoch: g.book.epoch.clone(),
            spent: g.ledger.clone(),
            ever_key: m.ever_key,
            ever_presence_key: m.ever_presence_key,
            store_id: self.ids.store_id.clone(),
        };
        write_atomic(
            &self.state_dir.join(STATE_FILE),
            &serde_json::to_vec(&s).map_err(|_| "state".to_string())?,
        )
    }

    /// What the service knows about the box for the rules: its own store's markers, never a request's word. **One** read of
    /// the store's names (one acquisition of the store's lock), shared with whatever else the operation needs from it.
    pub(crate) fn ctx(&self, store: &EncryptedSecrets) -> Result<(Ctx, Vec<String>), String> {
        let names = store.names("").map_err(|e| e.0)?;
        let has = |n: &str| names.iter().any(|x| x == n);
        let any_key = names.iter().any(|n| {
            n.strip_prefix(crate::approval_key::KEY_PREFIX)
                .is_some_and(crate::approval_key::id_ok)
        });
        let m = *self.markers.lock().unwrap_or_else(|e| e.into_inner());
        let ctx = Ctx {
            ids: self.ids.clone(),
            enrolled: has(crate::secrets_approval::ENROLLED_MARKER),
            ever_key: m.ever_key || has(EVER_KEY_MARKER) || any_key,
            ever_presence_key: m.ever_presence_key || has(EVER_PRESENCE_MARKER),
        };
        Ok((ctx, names))
    }

    /// Clear the kept attestation verdicts that no live signer-enroll request names (one that was denied, cancelled, expired,
    /// refused or superseded has none), and the ones gone stale (phase 2 re-check NL4).
    fn prune_pending(&self, store: &EncryptedSecrets, g: &Inner, now: u64) {
        let live: std::collections::HashSet<String> = g
            .book
            .requests
            .iter()
            .filter(|r| !r.state.is_terminal())
            .filter_map(|r| match &r.subject {
                Subject::SignerEnroll(se) if !se.attestation_digest.is_empty() => {
                    Some(se.attestation_digest.clone())
                }
                _ => None,
            })
            .collect();
        crate::approval_key::prune_stashes(store, &live, now);
    }

    fn audit_soft(
        &self,
        gates: &Gates,
        store: &dyn SecretStore,
        action: &str,
        subject: &str,
        detail: &str,
    ) {
        gates.audit_event(store, action, subject, detail);
    }

    /// A refused answer is a line too, but a flood of refusals must not flood the chain: past a budget they are dropped.
    fn audit_refused(&self, gates: &Gates, store: &dyn SecretStore, now: u64, detail: &str) {
        let mut l = self.refused_lines.lock().unwrap_or_else(|e| e.into_inner());
        l.retain(|t| now.saturating_sub(*t) < 60_000);
        if l.len() >= REFUSED_LINES_PER_MINUTE {
            return;
        }
        l.push(now);
        drop(l);
        gates.audit_event(store, "secrets.approval.request.refused", "", detail);
    }

    fn audit_closed(
        &self,
        gates: &Gates,
        store: &dyn SecretStore,
        action: &str,
        subject: &str,
        detail: &str,
    ) -> Result<(), String> {
        match gates.audit.get() {
            None => Ok(()),
            Some(c) => c.try_record(store, action, subject, detail).map_err(|_| {
                "the change was not made because the audit chain could not be written".to_string()
            }),
        }
    }

    fn flush_late(&self, gates: &Gates, store: &dyn SecretStore, g: &mut Inner) {
        if g.late.is_empty() {
            return;
        }
        let pending = std::mem::take(&mut g.late);
        for (action, subject, detail) in pending {
            let d = format!("{detail} late=true");
            let ok = match gates.audit.get() {
                None => true,
                Some(c) => c.try_record(store, &action, &subject, &d).is_ok(),
            };
            if !ok {
                g.late.push((action, subject, detail));
            }
        }
    }

    /// The audit line's detail. The chain caps a detail at 200 characters, so the fields a reader needs most (who, where,
    /// how) come before the requester and the state, and the scope is the line's subject, not repeated here.
    fn detail(r: &Request) -> String {
        format!(
            "id={} digest={} req={}:{} state={}",
            r.id,
            short(&r.subject_digest),
            r.requester.kind.as_str(),
            r.requester
                .uid
                .map_or_else(|| "-".to_string(), |u| u.to_string()),
            r.state.as_str(),
        )
    }

    fn decision_detail(r: &Request) -> String {
        match &r.decision {
            Some(d) => format!(
                "id={} digest={} decider={} surface={} factor={} req={}:{} state={}",
                r.id,
                short(&r.subject_digest),
                d.decider.chars().take(32).collect::<String>(),
                d.surface.as_str(),
                d.factor_label,
                r.requester.kind.as_str(),
                r.requester
                    .uid
                    .map_or_else(|| "-".to_string(), |u| u.to_string()),
                r.state.as_str(),
            ),
            None => Self::detail(r),
        }
    }

    /// The signed envelope of a request: the signed text and the signature, and nothing else. The key a verifier
    /// checks it against is its own pin, taken at pairing from [`RequestService::envelope_key`].
    fn envelope(&self, store: &dyn SecretStore, r: &Request) -> Result<SignedEnvelope, String> {
        // the key was made when the journal was opened: no request operation writes the secrets store
        let seed = store
            .get(ENVELOPE_KEY)
            .map_err(|e| e.0)?
            .ok_or("the envelope key is not there")?;
        let canonical = SignedEnvelope::canonical_of(&r.envelope(&self.ids))?;
        let msg = SignedEnvelope::signed_message(&canonical);
        Ok(SignedEnvelope {
            signature: crate::approval_key::sign(&seed, &msg)?,
            alg: "ed25519".into(),
            canonical,
        })
    }

    /// The public half of the envelope key, for a verifier to pin when it is paired with this box.
    pub fn envelope_key(&self, store: &dyn SecretStore) -> Result<String, String> {
        let seed = store
            .get(ENVELOPE_KEY)
            .map_err(|e| e.0)?
            .ok_or("the envelope key is not there")?;
        crate::approval_key::public_of(&seed)
    }

    /// Answer one request operation. `Ok(value)` is the `result`; `Err` is the sentence to show.
    pub fn handle(
        &self,
        store: &EncryptedSecrets,
        gates: &Gates,
        class: SocketClass,
        uid: Option<u32>,
        v: &Value,
        now: u64,
    ) -> Result<Value, String> {
        let op = match v["op"].as_str().unwrap_or("") {
            "areq_capabilities" => Op::Capabilities,
            "areq_file" => Op::File,
            "areq_get" => Op::Get,
            "areq_list" => Op::List,
            "areq_await" => Op::Await,
            "areq_decide_challenge" => Op::DecideChallenge,
            "areq_decide" => Op::Decide,
            "areq_spend" => Op::Spend,
            "areq_finish" => Op::Finish,
            "areq_cancel" => Op::Cancel,
            "areq_decider_revoked" => Op::DeciderRevoked,
            "areq_new_epoch" => Op::NewEpoch,
            "areq_clear_markers" => Op::ClearMarkers,
            _ => return Err("that request is not valid".into()),
        };
        if !op_allowed(class, op) {
            return Err("that is not allowed on this socket".into());
        }
        let id = v["id"].as_str().unwrap_or("");
        // a caller-chosen id of any other shape names no request of this service (phase 2 re-check NM2)
        if matches!(
            op,
            Op::Await
                | Op::Get
                | Op::DecideChallenge
                | Op::Decide
                | Op::Spend
                | Op::Finish
                | Op::Cancel
        ) && !ozbox_core::approval::request_id_ok(id)
        {
            return Err(ozbox_core::approval::NOT_FOUND.to_string());
        }
        match op {
            Op::Capabilities => Ok(json!({
                "request_ops": true,
                "version": 1,
                "ids": {"box_id": self.ids.box_id, "store_id": self.ids.store_id},
                "scopes": RULES.iter().filter(|r| r.journal).map(|r| r.key).collect::<Vec<_>>(),
                // B4-27 (additive): a declaration is filed with its text, and the root helper's gate spends an approved
                // request (`req-<id>`) for these scopes
                "policy_requests": true,
                "gate_requests": ["tunnel-token", "box-secrets"],
                "pending_ms": ozbox_core::approval::PENDING_MS,
                "approved_ms": ozbox_core::approval::APPROVED_MS,
                "await_max_ms": AWAIT_MAX_MS,
            })),
            Op::Await => self.await_request(
                store,
                gates,
                class,
                uid,
                id,
                v["wait_ms"].as_u64().unwrap_or(AWAIT_MAX_MS),
                now,
            ),
            Op::File => self.file(store, gates, class, uid, v, now),
            Op::Get => {
                let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                self.sweep_audit(gates, store, &mut g, now);
                if class == SocketClass::Box {
                    let r = g
                        .book
                        .box_get(uid, id)
                        .ok_or(ozbox_core::approval::NOT_FOUND)?;
                    return Ok(json!({"request": r}));
                }
                let r = g
                    .book
                    .get(id)
                    .cloned()
                    .ok_or(ozbox_core::approval::NOT_FOUND)?;
                drop(g);
                if v["envelope"].as_bool() == Some(true) {
                    return Ok(
                        json!({"request": r, "signed_envelope": self.envelope(store, &r)?, "envelope_key": self.envelope_key(store)?}),
                    );
                }
                if class == SocketClass::Supervisor {
                    let (ctx, _) = self.ctx(store)?;
                    return Ok(json!({"request": with_can(&r, role_of(v), &ctx)}));
                }
                Ok(json!({"request": r}))
            }
            Op::List => {
                let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                self.sweep_audit(gates, store, &mut g, now);
                if class == SocketClass::Box {
                    return Ok(json!({"requests": g.book.box_list(uid)}));
                }
                let mut all: Vec<Request> = g.book.requests.clone();
                let epoch = g.book.epoch.clone();
                drop(g);
                all.sort_by_key(|r| std::cmp::Reverse(r.filed_at_ms));
                all.truncate(200);
                if class == SocketClass::Supervisor {
                    let (ctx, _) = self.ctx(store)?;
                    let role = role_of(v);
                    let cards: Vec<Value> = all.iter().map(|r| with_can(r, role, &ctx)).collect();
                    return Ok(json!({"requests": cards, "epoch": epoch,
                        "markers": {"ever_key": ctx.ever_key, "ever_presence_key": ctx.ever_presence_key}}));
                }
                Ok(json!({"requests": all, "epoch": epoch}))
            }
            Op::DecideChallenge => {
                let (ctx, _) = self.ctx(store)?;
                let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                self.sweep_audit(gates, store, &mut g, now);
                let r = g.book.get(id).ok_or(ozbox_core::approval::NOT_FOUND)?;
                // the challenge names the outcome: an assertion made to deny is not one that approves, and a revoke (of
                // an approved request) is a word of its own
                let outcome = match v["outcome"].as_str().unwrap_or("approve") {
                    "approve" => Outcome::Approve,
                    "deny" => Outcome::Deny,
                    "revoke" => Outcome::Revoke,
                    _ => return Err("that request is not valid".into()),
                };
                match (r.state, outcome) {
                    (State::Pending, Outcome::Approve | Outcome::Deny)
                    | (State::Approved, Outcome::Revoke) => {}
                    (State::Pending, Outcome::Revoke) => {
                        return Err("there is nothing approved to revoke".into())
                    }
                    // an approved request is withdrawn with a revoke; any other word is told who decided it
                    _ => return Err(r.state_sentence()),
                }
                let c = g.book.challenge_for(&ctx, id, outcome)?;
                Ok(
                    json!({"challenge": to_hex(&c), "outcome": outcome.word(), "subject_digest": r.subject_digest}),
                )
            }
            Op::Decide => self.decide(store, gates, class, uid, v, now),
            Op::Spend => {
                // the hook recomputes the subject: a guard override's matches are the service's own scan of the text it sends
                let mut raw = v["subject"].clone();
                if raw["scope"].as_str() == Some("guard-override") {
                    derive_guard_fields(store, gates, &mut raw, v["scanned_text"].as_str(), now)?;
                }
                let subject: Subject = serde_json::from_value(raw)
                    .map_err(|_| "that request's subject is not valid".to_string())?;
                self.spend(
                    store,
                    gates,
                    SpendVia::Socket { class, uid },
                    id,
                    &subject,
                    now,
                )
                .map(|r| json!({"request": r.box_view()}))
            }
            Op::Finish => self.finish(store, gates, class, uid, id, now),
            Op::Cancel => {
                let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                self.flush_late(gates, store, &mut g);
                let r = g.book.cancel(now, id, class)?;
                self.after_fail_safe(
                    gates,
                    store,
                    &mut g,
                    "secrets.approval.request.cancelled",
                    &r,
                    now,
                )?;
                self.prune_pending(store, &g, now);
                self.cv.notify_all();
                Ok(json!({"request": r}))
            }
            Op::DeciderRevoked => {
                let person = sanitize_display(v["person"].as_str().unwrap_or(""), 64);
                if person.is_empty() {
                    return Err("that request is not valid".into());
                }
                let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                let ids = g.book.decider_revoked(&person);
                for i in &ids {
                    if let Some(r) = g.book.get(i).cloned() {
                        self.after_fail_safe(
                            gates,
                            store,
                            &mut g,
                            "secrets.approval.request.revoked",
                            &r,
                            now,
                        )?;
                    }
                }
                self.persist(&g, now)?;
                self.cv.notify_all();
                Ok(json!({"voided": ids}))
            }
            Op::ClearMarkers => {
                self.clear_markers()?;
                self.audit_soft(
                    gates,
                    store,
                    "secrets.approval.markers.cleared",
                    "",
                    "by=root",
                );
                Ok(json!({"cleared": true}))
            }
            Op::NewEpoch => {
                let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                let voided = g.book.new_epoch(random_b32(16)?, now);
                g.ledger.retain(|_, until| *until > now);
                self.persist_state(&g)?;
                self.persist(&g, now)?;
                self.audit_soft(
                    gates,
                    store,
                    "secrets.approval.request.epoch",
                    "",
                    &format!("voided={}", voided.len()),
                );
                self.cv.notify_all();
                Ok(json!({"voided": voided}))
            }
        }
    }

    /// Move time forward, and write `.expired` lines (best effort, at most 20 a pass).
    fn sweep_audit(&self, gates: &Gates, store: &EncryptedSecrets, g: &mut Inner, now: u64) {
        self.flush_late(gates, store, g);
        gates.flush_refused(store, now, None);
        let expired = g.book.sweep(now);
        if !expired.is_empty() {
            self.prune_pending(store, g, now);
        }
        for id in expired.iter().take(20) {
            if let Some(r) = g.book.get(id) {
                self.audit_soft(
                    gates,
                    store,
                    "secrets.approval.request.expired",
                    r.scope.as_str(),
                    &Self::detail(r),
                );
            }
        }
    }

    /// Deny, revoke and cancel fail safe: the state is already changed; the line is retried later if the chain is down.
    fn after_fail_safe(
        &self,
        gates: &Gates,
        store: &dyn SecretStore,
        g: &mut Inner,
        action: &str,
        r: &Request,
        now: u64,
    ) -> Result<(), String> {
        let detail = Self::decision_detail(r);
        let ok = match gates.audit.get() {
            None => true,
            Some(c) => c
                .try_record(store, action, r.scope.as_str(), &detail)
                .is_ok(),
        };
        if !ok {
            g.late
                .push((action.to_string(), r.scope.as_str().to_string(), detail));
        }
        self.persist(g, now)
    }

    fn file(
        &self,
        store: &EncryptedSecrets,
        gates: &Gates,
        class: SocketClass,
        uid: Option<u32>,
        v: &Value,
        now: u64,
    ) -> Result<Value, String> {
        let mut raw = v["subject"].clone();
        // the matches of a guard override are the service's own scan of the text, never the filer's list
        if raw["scope"].as_str() == Some("guard-override") {
            derive_guard_fields(store, gates, &mut raw, v["scanned_text"].as_str(), now)?;
        }
        // A declaration change (B4-27) is filed with the declaration itself, never a subject: the service parses it, checks it
        // as the `policy` operation would, and works out the digests and the sensitivity from it and the declaration it holds.
        // A filer's own fields are not read.
        let mut policy_reason = None;
        let mut subject: Subject = if raw["scope"].as_str() == Some("policy") {
            let project = v["project"].as_str().unwrap_or("");
            crate::workload_policy::secret_name(project)
                .map_err(|_| "that request's subject is not valid".to_string())?;
            let p = crate::workload_policy::Policy::parse(v["policy_text"].as_str().unwrap_or(""))
                .and_then(|p| p.check_before_write().map(|_| p))
                .map_err(|e| e.0)?;
            policy_reason = Some(format!(
                "declaration for project {project} ({} command(s))",
                p.commands.len()
            ));
            crate::secrets_service::declaration_subject(store, project, &p)?
        } else {
            serde_json::from_value(raw)
                .map_err(|_| "that request's subject is not valid".to_string())?
        };
        // a key's attestation is verified now and the verdict kept: the challenge it was made over does not live as long as the
        // approval's wait
        let staged = match &subject {
            Subject::SignerEnroll(se) => {
                crate::approval_key::verify_at_filing(store, gates, se, v, now)?
            }
            _ => None,
        };
        // an import is bound to the generation the service holds now, never the filer's number
        if let Subject::Import(i) = &mut subject {
            i.store_generation = self.import_generation(store, &i.project, &i.environment);
        }
        let (ctx, names) = self.ctx(store)?;
        let mut requester = Requester::new(class.requester_kind(), uid);
        requester.claimed = v["claimed"]
            .as_str()
            .map(|c| sanitize_display(c, 64))
            .filter(|c| !c.is_empty());
        let reason = policy_reason.or_else(|| v["reason"].as_str().map(str::to_string));
        // facts the service derives itself, from the one read of the store's names above: a replacement is a value already
        // stored (a name that cannot be looked up counts as stored, which is the stricter reading)
        let derived = match &subject {
            Subject::Import(i) => Derived {
                replaces_existing: i.names.iter().any(|n| {
                    crate::secrets_enc::workload_name(&i.project, &i.environment, &n.name)
                        .map_or(true, |w| names.contains(&w))
                }),
                ..Derived::default()
            },
            // the service's own reading (`declaration_subject`), never a filer's label
            Subject::Policy(p) => Derived {
                policy_sensitivity: Some(p.sensitivity),
                ..Derived::default()
            },
            _ => Derived::default(),
        };
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        self.sweep_audit(gates, store, &mut g, now);
        let new_id = random_b32(16)?;
        let filed = match g.book.file(
            &ctx,
            now,
            Filing {
                id: new_id.clone(),
                subject,
                requester,
                reason: reason.as_deref(),
                derived,
            },
        ) {
            Ok(f) => f,
            Err(e) => {
                drop(g);
                self.audit_refused(
                    gates,
                    store,
                    now,
                    &format!("op=file why={}", sanitize_display(&e, 80)),
                );
                return Err(e);
            }
        };
        let r = filed.request.clone();
        // the verdict is kept only now that the book has admitted the filing, after the stashes of requests that have ended are
        // cleared (phase 2 re-check NL4)
        if let Some(st) = &staged {
            self.prune_pending(store, &g, now);
            let kept = crate::approval_key::keep_staged(store, st, &format!("{class:?}"), now);
            settle_kept(&mut g.book.requests, &r.id, filed.existing, kept)?;
        }
        if !filed.existing {
            let superseded: Vec<String> = g
                .book
                .requests
                .iter()
                .filter(|o| o.superseded_by.as_deref() == Some(r.id.as_str()))
                .map(|o| o.id.clone())
                .collect();
            let mut d = Self::detail(&r);
            if let Some(rep) = &r.replaces {
                d.push_str(&format!(" replaces={rep}"));
            }
            self.audit_soft(
                gates,
                store,
                "secrets.approval.request.filed",
                r.scope.as_str(),
                &d,
            );
            for s in &superseded {
                self.audit_soft(
                    gates,
                    store,
                    "secrets.approval.request.superseded",
                    r.scope.as_str(),
                    &format!("id={s} by={}", r.id),
                );
            }
            // a box with no approver yet is decided as `bootstrap`: the decision is a line that fails closed
            if r.state == State::Approved {
                if let Err(e) = self.audit_closed(
                    gates,
                    store,
                    "secrets.approval.request.decided",
                    r.scope.as_str(),
                    &Self::decision_detail(&r),
                ) {
                    if let Some(x) = g.book.requests.iter_mut().find(|x| x.id == r.id) {
                        x.state = State::Cancelled;
                    }
                    return Err(e);
                }
            }
        }
        self.persist(&g, now)?;
        self.cv.notify_all();
        let out = if class == SocketClass::Box {
            json!({"request": r.box_view(), "existing": filed.existing})
        } else {
            json!({"request": r, "existing": filed.existing})
        };
        Ok(out)
    }

    #[allow(clippy::too_many_arguments)]
    fn await_request(
        &self,
        store: &EncryptedSecrets,
        gates: &Gates,
        class: SocketClass,
        uid: Option<u32>,
        id: &str,
        wait_ms: u64,
        now: u64,
    ) -> Result<Value, String> {
        let who = format!(
            "{class:?}:{}",
            uid.map_or_else(|| "-".to_string(), |u| u.to_string())
        );
        // visibility first: a caller who cannot see a request must not be able to hold a place in its cap, and
        // the per-request cap is per socket class, so one class cannot starve another's wait on the same id
        {
            let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            let visible = if class == SocketClass::Box {
                g.book.box_get(uid, id).is_some()
            } else {
                g.book.get(id).is_some()
            };
            if !visible {
                return Err(ozbox_core::approval::NOT_FOUND.into());
            }
        }
        let _slot = AwaitSlot::take(&self.caps, &who, &format!("{class:?}:{id}"))?;
        let wait = wait_ms.min(AWAIT_MAX_MS);
        let start = Instant::now();
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            let elapsed = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
            self.sweep_audit(gates, store, &mut g, now.saturating_add(elapsed));
            let (view, state, digest) = if class == SocketClass::Box {
                let b = g
                    .book
                    .box_get(uid, id)
                    .ok_or(ozbox_core::approval::NOT_FOUND)?;
                (json!(b), b.state, b.subject_digest)
            } else {
                let r = g.book.get(id).ok_or(ozbox_core::approval::NOT_FOUND)?;
                (json!(r), r.state, r.subject_digest.clone())
            };
            if state != State::Pending || elapsed >= wait {
                if state == State::Approved {
                    self.audit_soft(
                        gates,
                        store,
                        "secrets.approval.request.delivered",
                        "",
                        &format!("id={id} digest={} to={who}", short(&digest)),
                    );
                }
                return Ok(json!({"request": view, "waiting": state == State::Pending}));
            }
            let slice = Duration::from_millis((wait - elapsed).min(1000));
            let (g2, _) = self
                .cv
                .wait_timeout(g, slice)
                .unwrap_or_else(|e| e.into_inner());
            g = g2;
        }
    }

    /// Check a dashboard person's authenticator-app code against their own authenticator secret in this store (the one the
    /// dashboard set up for them), allowing one step of clock drift, and refusing a step this person already used to decide.
    /// Returns the step, which the book keeps as the person's counter. The code is never logged and no error carries it.
    fn check_authenticator(
        &self,
        store: &EncryptedSecrets,
        person: &str,
        code: &str,
        now: u64,
    ) -> Result<ozbox_core::approval::AuthenticatorEvidence, String> {
        let refused = || crate::messages::t("approval.authenticator_refused", &[]);
        let secret = store
            .get(&crate::serve::auth::totp::secret_name(person))
            .map_err(|_| refused())?
            .map(zeroize::Zeroizing::new)
            .ok_or_else(|| crate::messages::t("approval.authenticator_none", &[]))?;
        let last = {
            let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            g.book
                .counters
                .get(&format!("totp:{person}"))
                .map(|s| u64::from(*s))
        };
        let step = crate::serve::auth::totp::verify(&secret, code, now / 1000, last)
            .ok_or_else(refused)?;
        Ok(ozbox_core::approval::AuthenticatorEvidence { step })
    }

    fn decide(
        &self,
        store: &EncryptedSecrets,
        gates: &Gates,
        class: SocketClass,
        uid: Option<u32>,
        v: &Value,
        now: u64,
    ) -> Result<Value, String> {
        #[derive(Deserialize, Default)]
        struct Wire {
            #[serde(default)]
            person: String,
            #[serde(default)]
            role: Option<Role>,
            #[serde(default)]
            surface: String,
            #[serde(default)]
            factor: String,
            #[serde(default)]
            evidence: Evidence,
            /// The relying party the supervisor verified the passkey assertion against.
            #[serde(default)]
            rp: Option<ozbox_core::approval_verify::ExpectedRp>,
            /// An authenticator-app code (`factor: authenticator`): checked here, against the person's own secret in this
            /// store, and never kept, logged or echoed.
            #[serde(default)]
            code: String,
        }
        let id = v["id"].as_str().unwrap_or("");
        let outcome = match v["outcome"].as_str().unwrap_or("") {
            "approve" => Outcome::Approve,
            "deny" => Outcome::Deny,
            // a revoke is signed as one, over its own word; only the laptop and root name it
            "revoke" if matches!(class, SocketClass::Ingress | SocketClass::Admin) => {
                Outcome::Revoke
            }
            _ => return Err("that request is not valid".into()),
        };
        let mut w: Wire = serde_json::from_value(v.clone())
            .map_err(|_| "that decision is not valid".to_string())?;
        // the code is a credential for a minute: held where it is wiped when this decision is done
        let code = zeroize::Zeroizing::new(std::mem::take(&mut w.code));
        if let Some(p) = &w.evidence.passkey {
            for f in [
                &p.credential_id,
                &p.authenticator_data,
                &p.client_data,
                &p.signature,
            ] {
                if f.len() > MAX_EVIDENCE_FIELD {
                    return Err("that decision is not valid".into());
                }
            }
        }
        let input = match class {
            // root decides as root: the factor, the surface and the name are not the client's to choose
            SocketClass::Admin => DecideInput {
                class,
                outcome,
                surface: Surface::Root,
                factor: Factor::Root,
                decider: "root".into(),
                role: None,
                evidence: Evidence::default(),
                key: None,
                passkey_rp: None,
                via_fleet: None,
            },
            // the supervisor verified the person and their assertion (v1); the service checks the assertion is for this
            // request, this digest and this box, and keeps the evidence
            SocketClass::Supervisor => {
                let surface = match w.surface.as_str() {
                    "dashboard" => Surface::Dashboard,
                    // a chat app only notifies: it never approves, denies or cancels a request (owner decision)
                    "telegram" => return Err(
                        "a chat app only notifies: open the request in the dashboard to decide it"
                            .into(),
                    ),
                    _ => return Err("that decision is not valid".into()),
                };
                let factor = match w.factor.as_str() {
                    "passkey" => Factor::Passkey,
                    "authenticator" if outcome == Outcome::Approve => Factor::Authenticator,
                    "chat-deny" => Factor::ChatDeny,
                    // a signed-in session may stop things (deny, revoke), never approve
                    "session" if outcome != Outcome::Approve => Factor::Session,
                    "laptop-key" => {
                        return Err(
                            "a laptop key decides over the sealed route from the laptop".into()
                        )
                    }
                    _ => return Err("that decision is not valid".into()),
                };
                let person = sanitize_display(&w.person, 64);
                if person.is_empty() || w.role.is_none() {
                    return Err("that decision is not valid".into());
                }
                // the code is checked by this service, never taken on the supervisor's word, and the evidence it keeps is the
                // step it checked; whatever the wire said about an authenticator is ignored
                let authenticator = if factor == Factor::Authenticator {
                    Some(self.check_authenticator(store, &person, &code, now)?)
                } else {
                    None
                };
                DecideInput {
                    class,
                    outcome,
                    surface,
                    factor,
                    decider: person,
                    role: w.role,
                    evidence: Evidence {
                        passkey: if factor == Factor::Passkey {
                            w.evidence.passkey
                        } else {
                            None
                        },
                        laptop: None,
                        authenticator,
                    },
                    key: None,
                    passkey_rp: w.rp,
                    via_fleet: None,
                }
            }
            // the laptop, over the sealed route: the key is the service's own record of it, loaded by id; the signature is
            // checked by the book over this request's own message and outcome word. A key still in its
            // cooling-off decides nothing.
            SocketClass::Ingress => {
                let key_id = v["key_id"].as_str().unwrap_or("");
                let key = crate::approval_keystore::load_key_view(store, key_id)?
                    .ok_or("that key is not enrolled on this box")?;
                if crate::approval_key::in_wait(store, key_id, now)? {
                    return Err(crate::approval_key::IN_WAIT.into());
                }
                // presence follows root's flag as it stands now, not as it stood at enrolment (phase 2 re-check NL2)
                let mut key = key;
                key.presence_proved &= gates.presence_keys_on();
                DecideInput {
                    class,
                    outcome,
                    surface: Surface::Laptop,
                    factor: Factor::LaptopKey,
                    decider: key.id.clone(),
                    role: None,
                    evidence: Evidence {
                        passkey: None,
                        laptop: w.evidence.laptop,
                        authenticator: None,
                    },
                    key: Some(key),
                    passkey_rp: None,
                    via_fleet: None,
                }
            }
            _ => return Err("this route is not available in this release".into()),
        };
        let (ctx, _) = self.ctx(store)?;
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        self.sweep_audit(gates, store, &mut g, now);
        let snapshot = g.book.clone();
        let r = match g.book.decide(&ctx, now, id, input) {
            Ok(r) => r,
            Err(e) => {
                drop(g);
                self.audit_refused(
                    gates,
                    store,
                    now,
                    &format!(
                        "op=decide id={} why={}",
                        log_id(id),
                        sanitize_display(&e, 80)
                    ),
                );
                return Err(e);
            }
        };
        let approved = r
            .decision
            .as_ref()
            .is_some_and(|d| d.outcome == Outcome::Approve);
        if approved {
            // approve fails closed: no chain line, no approval
            if let Err(e) = self.audit_closed(
                gates,
                store,
                "secrets.approval.request.decided",
                r.scope.as_str(),
                // root's socket is reachable by the secrets user as well: the kernel's peer uid is part of the line, so the
                // record does not say "root" for a decision that came from another account
                &if class == SocketClass::Admin {
                    format!(
                        "{} peer_uid={}",
                        Self::decision_detail(&r),
                        uid.map_or_else(|| "-".to_string(), |u| u.to_string())
                    )
                } else {
                    Self::decision_detail(&r)
                },
            ) {
                g.book = snapshot;
                return Err(e);
            }
            // a journal that cannot be written must not leave an approval live in memory only
            if let Err(e) = self.persist(&g, now) {
                g.book = snapshot;
                return Err(e);
            }
        } else {
            let action = match r.decision.as_ref().map(|d| d.outcome) {
                Some(Outcome::Revoke) => "secrets.approval.request.revoked",
                _ => "secrets.approval.request.decided",
            };
            self.after_fail_safe(gates, store, &mut g, action, &r, now)?;
            self.prune_pending(store, &g, now);
        }
        self.cv.notify_all();
        Ok(json!({"request": r}))
    }

    /// Spend an approval (the first half): `approved` becomes `spending`, durably, and the audit line is written before
    /// the caller does the effect. A line that cannot be written puts the request back. The caller then calls
    /// [`RequestService::finish`] (or, for a scope spent inside its own operation, [`RequestService::finish_inside`]).
    pub fn spend(
        &self,
        store: &EncryptedSecrets,
        gates: &Gates,
        via: SpendVia,
        id: &str,
        subject: &Subject,
        now: u64,
    ) -> Result<Request, String> {
        // an id that is not the service's shape names no request: refused before any lock, journal or counter is touched
        // (phase 2 re-check NM2)
        if !ozbox_core::approval::request_id_ok(id) {
            return Err(ozbox_core::approval::NOT_FOUND.to_string());
        }
        let (ctx, _) = self.ctx(store)?;
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        self.sweep_audit(gates, store, &mut g, now);
        let active = |d: &Decision| match d.factor {
            // a laptop key revoked since is a decider no longer valid
            Factor::LaptopKey => store
                .exists(&format!("{}{}", crate::approval_key::KEY_PREFIX, d.decider))
                .unwrap_or(false),
            _ => true,
        };
        let r = match g.book.begin_spend(&ctx, now, id, via, subject, &active) {
            Ok(r) => r,
            Err(e) => {
                let detail = if e.differs.is_empty() {
                    format!(
                        "op=spend id={} why={}",
                        log_id(id),
                        sanitize_display(&e.message, 80)
                    )
                } else {
                    format!("op=spend id={} differs={}", log_id(id), e.differs.join(","))
                };
                // the journal is rewritten only for a refusal that changed something
                if e.changed {
                    let _ = self.persist(&g, now);
                }
                drop(g);
                self.audit_refused(gates, store, now, &detail);
                return Err(e.message);
            }
        };
        // durable before the effect, in two places: the ledger first, so a journal that comes back from a backup cannot
        // revive this request
        g.ledger.insert(r.id.clone(), r.expires_at_ms);
        let undo = |this: &Self, g: &mut Inner| {
            g.book.abort_spend(&r.id);
            g.ledger.remove(&r.id);
            let _ = this.persist_state(g);
            let _ = this.persist(g, now);
        };
        if let Err(e) = self.persist_state(&g).and_then(|()| self.persist(&g, now)) {
            undo(self, &mut g);
            return Err(e);
        }
        if let Err(e) = self.audit_closed(
            gates,
            store,
            "secrets.approval.request.spent",
            r.scope.as_str(),
            &Self::decision_detail(&r),
        ) {
            undo(self, &mut g);
            return Err(e);
        }
        Ok(r)
    }

    /// The effect happened: `spending` becomes `spent`. A scope spent from a socket is finished from the same class and uid.
    fn finish(
        &self,
        store: &EncryptedSecrets,
        gates: &Gates,
        class: SocketClass,
        uid: Option<u32>,
        id: &str,
        now: u64,
    ) -> Result<Value, String> {
        let _ = (store, gates);
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let req = g
            .book
            .get(id)
            .cloned()
            .ok_or(ozbox_core::approval::NOT_FOUND)?;
        let rule = RULES.iter().find(|r| r.key == req.scope.as_str());
        let ok = match rule.map(|r| r.spend_by) {
            Some(SpendBy::BoxSocket) => {
                class == SocketClass::Box && req.requester.uid == uid && uid.is_some()
            }
            Some(SpendBy::AdminSocket) => class == SocketClass::Admin,
            _ => false,
        };
        if !ok {
            return Err(ozbox_core::approval::NOT_FOUND.into());
        }
        let r = g.book.finish_spend(id)?;
        self.persist(&g, now)?;
        self.cv.notify_all();
        Ok(json!({"request": r.box_view()}))
    }

    /// The effect of a scope spent inside its own operation happened.
    pub fn finish_inside(&self, id: &str, now: u64) -> Result<Request, String> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let r = g.book.finish_spend(id)?;
        self.persist(&g, now)?;
        self.cv.notify_all();
        Ok(r)
    }

    /// A copy of the book, for tests and for the supervisor's own reads.
    #[cfg(test)]
    pub fn book(&self) -> RequestBook {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .book
            .clone()
    }
}

impl Gates {
    /// Turn the request operations on (they answer "not available" until then). Phase 2 ships the deciders (the dashboard's
    /// passkey route on the supervisor socket, the laptop on the sealed route), so `ozbox secrets serve` calls this at start;
    /// a service that has not been given a journal directory still answers `areq_capabilities` with `request_ops: false`.
    pub fn enable_requests(
        &self,
        store: &EncryptedSecrets,
        journal_dir: &Path,
        state_dir: &Path,
        box_id: &str,
        now_ms: u64,
    ) -> Result<(), String> {
        let svc = RequestService::open(store, journal_dir, state_dir, box_id, now_ms)?;
        self.requests
            .set(Arc::new(svc))
            .map_err(|_| "the request operations are already on".to_string())
    }
}

/// A guard override as the service files it. The filer names the repository, the hook and the tree (or the
/// remote and the refs) and sends the **unified diff the hook scanned** as `scanned_text`; the service runs the guard's own
/// scanner over it, over the box's stored values as well as the shapes, and writes `matches` and `scanned_text_hash`
/// itself. A filer that sends either of those, or whose list is too long to bind, is refused: its word is never used.
fn derive_guard_fields(
    store: &EncryptedSecrets,
    gates: &Gates,
    raw: &mut Value,
    scanned_text: Option<&str>,
    now: u64,
) -> Result<(), String> {
    use ozbox_core::approval_subject::{GuardMatch, RULE_PRODUCTION_LOOKING};
    let obj = raw
        .as_object_mut()
        .ok_or("that request's subject is not valid")?;
    if obj.contains_key("matches") || obj.contains_key("scanned_text_hash") {
        return Err(
            "the service works out a guard override's matches itself: send the text it should scan"
                .into(),
        );
    }
    let text = scanned_text.ok_or("a guard override carries the text that was scanned")?;
    if text.is_empty() || text.len() > (1 << 20) {
        return Err("the scanned text is empty or too long to bind".into());
    }
    if !gates.scan_allowed(now) {
        return Err("too many scans: wait a minute".into());
    }
    struct ServiceScanner<'a> {
        store: &'a EncryptedSecrets,
        memory: Option<&'a Arc<EncryptedSecrets>>,
    }
    impl crate::guard::Scanner for ServiceScanner<'_> {
        fn scan(&self, text: &str) -> Result<Vec<String>, String> {
            crate::secrets_service::scan_text(self.store, self.memory, text).map_err(|e| e.0)
        }
        fn override_ok(&self, _code: &str, _bind: &crate::guard::Binding) -> Result<(), String> {
            Err("not here".into())
        }
    }
    let memory = gates.memory.get();
    let verdict = crate::guard::check_diff(text, Some(&ServiceScanner { store, memory }))?;
    let mut found: Vec<GuardMatch> = Vec::new();
    for f in &verdict.findings {
        found.push(GuardMatch {
            path: f.file.clone(),
            line: u64::from(f.line),
            rule: f.rule.clone(),
            key_id: String::new(),
        });
        // a live-mode payment key is Production-looking whether or not the box stores it
        if f.rule == "payment-provider-key" {
            found.push(GuardMatch {
                path: f.file.clone(),
                line: u64::from(f.line),
                rule: RULE_PRODUCTION_LOOKING.into(),
                key_id: String::new(),
            });
        }
    }
    for hit in &verdict.stored {
        let (name, file) = (&hit.name, &hit.file);
        let value = memory
            .and_then(|m| m.get(name).ok().flatten())
            .or_else(|| store.get(name).ok().flatten())
            .map(zeroize::Zeroizing::new);
        // `workload.<project>.<env>.<NAME>`: the box's own rule decides whether the value looks like Production
        let mut parts = name.splitn(4, '.');
        let (env, var) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some("workload"), Some(_), Some(env), Some(var)) => (env, var),
            _ => ("", name.as_str()),
        };
        let live = value
            .as_ref()
            .is_none_or(|v| crate::workload::live_reason(var, v, env).is_some());
        found.push(GuardMatch {
            path: file.clone(),
            line: u64::from(hit.line),
            rule: if live {
                RULE_PRODUCTION_LOOKING
            } else {
                "stored-value"
            }
            .into(),
            key_id: name.clone(),
        });
    }
    found.sort();
    found.dedup();
    if found.len() > 512 {
        return Err(
            "there are too many matches to bind to one approval: remove the keys and commit again"
                .into(),
        );
    }
    obj.insert(
        "matches".into(),
        serde_json::to_value(&found).map_err(|_| "matches".to_string())?,
    );
    obj.insert(
        "scanned_text_hash".into(),
        Value::String(ozbox_core::approval_subject::sha256_hex(text)),
    );
    Ok(())
}

fn role_of(v: &Value) -> Option<ozbox_core::approval::Role> {
    match v["role"].as_str() {
        Some("owner") => Some(ozbox_core::approval::Role::Owner),
        Some("member") => Some(ozbox_core::approval::Role::Member),
        Some("viewer") => Some(ozbox_core::approval::Role::Viewer),
        _ => None,
    }
}

/// A request as the supervisor shows it: the record, and what the signed-in viewer may do with it right now, from the same
/// rule `decide` applies (so a card never offers what the service would refuse).
fn with_can(r: &Request, role: Option<ozbox_core::approval::Role>, ctx: &Ctx) -> Value {
    let one = |res: Result<(), String>| match res {
        Ok(()) => json!({"allowed": true, "reason": null}),
        Err(why) => json!({"allowed": false, "reason": why}),
    };
    let mut v = serde_json::to_value(r).unwrap_or(Value::Null);
    v["can"] = json!({
        "approve": one(ozbox_core::approval::dashboard_can_approve(r, role, ctx)),
        "deny": one(ozbox_core::approval::dashboard_can_deny(r, role)),
    });
    v
}

/// The scopes the journal files, as words (for the capabilities answer and the parity tests).
pub fn journal_scopes() -> Vec<&'static str> {
    Scope::ALL
        .iter()
        .filter(|s| RULES.iter().any(|r| r.key == s.as_str() && r.journal))
        .map(|s| s.as_str())
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
