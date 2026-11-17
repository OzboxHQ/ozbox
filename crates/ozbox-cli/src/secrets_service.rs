//! The secrets service of a box: the one process that holds the key-encryption key and opens the store. It runs as the
//! system user `ozbox-secrets`, which has no login and owns the store's directory; the box user, and every agent that
//! runs as it, can reach only the sockets this service offers, and each socket is a different set of powers (ADR 0018).
//!
//! * the **box socket** (the box user may connect): write-only (`set`, `exists`, `delete`, `names`), `mac` (the tag of a
//!   token under the internal keys, which never leave), and `get` for a short list of names the dashboard itself sends
//!   with. Never `get` for a tunnel token, a restic key, a web-IDE password, a workload secret or the keys.
//! * the **runner socket** (the box agent's runner may connect): `resolve`, which fills `{{secret:NAME}}` references for
//!   one project and environment from the command's allow-list, and refuses a production key.
//! * the **broker socket** (the box user may connect): the credential broker (ADR 0017) runs inside this process, so a
//!   model key is opened here and nowhere else. The socket issues and revokes per-run tokens, hands back the usage the
//!   broker counted, and runs the free "list models" and "test connection" checks. It also runs the few exact restic
//!   commands the box daemon needs, with the backup credentials opened here. It never returns a key or a credential.
//! * the **import socket** (the box user may connect): takes a project's `.env` keys and its command declaration, and
//!   returns names only. It cannot read anything back, and a production-looking key is stored only when named.
//! * the **admin socket** (root and `ozbox-secrets` only): everything, for provisioning by the root helper, and what the
//!   root launcher reads a project's declaration and values through.
//!
//! Who may connect is decided by the file permissions of the socket's directory, not by the program: no peer
//! credential calls, no `unsafe`. A request is one JSON line and so is the answer.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::broker::{Broker, BrokerUsage, IssuedToken, RunBroker};
use crate::netguard::UreqClient;
use crate::secrets::{SecretError, SecretStore};
use crate::secrets_enc::EncryptedSecrets;
use crate::serve::auth::b64::{decode_std, encode_std};
use crate::settings::{ModelProvider, ModelsConfig};
use crate::tokenmac::TokenMac;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    Box,
    /// The box socket once a supervisor socket exists: the box user may ask whether a secret is set and list names, and
    /// nothing else. It cannot write, read or ask for a tag.
    BoxLocked,
    Runner,
    Admin,
    Broker,
    /// The broker socket once a supervisor socket exists: only the proxy port and the exact restic commands remain.
    BrokerLocked,
    Import,
    /// The supervisor's own socket (a directory only its user may enter): what the box socket and the broker socket offer,
    /// without a claim, plus asking for an approval and saying a second factor exists.
    Supervisor,
    /// The ingress socket (a folder only the secrets user and the `ozbox-ingress` account may enter): the service's public
    /// key and sealed requests, nothing else (see `secrets_ingress`).
    Ingress,
    /// A request that arrived sealed on the ingress socket and was opened. Never bound to a socket: only the ingress
    /// handler makes it. It carries the powers the import socket held before (a project's keys and declaration, a signer's
    /// enrolment, an approval's challenge and signature), now reachable only through the account a person's computer uses.
    Unsealed,
}

impl Policy {
    /// A word for the audit line: which socket a request came in on.
    pub fn word(self) -> &'static str {
        match self {
            Policy::Box | Policy::BoxLocked | Policy::Broker | Policy::BrokerLocked => "box",
            Policy::Runner => "runner",
            Policy::Admin => "admin",
            Policy::Import => "import",
            Policy::Supervisor => "supervisor",
            Policy::Ingress | Policy::Unsealed => "ingress",
        }
    }
}

/// Names the box user's side may read back over the box socket for now, because the dashboard sends with them. A secret
/// of any other kind is never answered there. This list shrinks as the credential broker takes each over.
const BOX_GET_PREFIXES: &[&str] = &[
    "email-api-key",
    "telegram-bot-token",
    "slack-webhook-url",
    "discord-webhook-url",
    "teams-webhook-url",
    "smtp-password",
    "sms-",
    "whatsapp-token",
    "google-client-secret",
    "vapid-private-key",
    "push-",
    "webhook-url-",
    "webhook-secret-",
    "trigger-secret-",
    "totp-",
];

/// Names whose writes are not the box user's to make over the box socket: a tunnel token decides where the dashboard is
/// reached from. The write goes through the root helper's admin action instead, which is recorded, and which the
/// dashboard and the command line put behind a fresh passkey and an explicit confirmation.
pub fn box_may_write(name: &str) -> bool {
    !name.starts_with("tunnel-token-")
        && name != crate::secrets_approval::ENROLLED_MARKER
        && !crate::audit_service::is_audit_secret(name)
        && !crate::approval_key::is_reserved(name)
        && !crate::secrets_ingress::is_reserved(name)
}

/// The store's own keys and records: not something the owner or an agent put there.
pub fn is_system_name(name: &str) -> bool {
    name == "store-kek"
        || name == "internal-hmac-keys"
        || name == crate::secrets_approval::ENROLLED_MARKER
        || crate::audit_service::is_audit_secret(name)
        || crate::approval_key::is_reserved(name)
        || crate::secrets_ingress::is_reserved(name)
        || name.starts_with("workload-policy.")
}

/// How many secrets the owner or an agent put in the store.
pub fn user_name_count(store: &EncryptedSecrets) -> Option<u32> {
    let names = store.names("").ok()?;
    u32::try_from(names.iter().filter(|n| !is_system_name(n)).count()).ok()
}

pub fn box_may_get(name: &str) -> bool {
    BOX_GET_PREFIXES.iter().any(|p| name.starts_with(p))
}

#[derive(Deserialize, Default)]
struct Req {
    op: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    value: String,
    /// A value that the plain rule does not hold, as base64 (the `set` op, from the root helper only).
    #[serde(default)]
    value_b64: String,
    /// `resolve`: hand over `name` exactly as stored (an environment variable), not as text for a command line.
    #[serde(default)]
    exact: bool,
    /// `resolve` with `exact`: the value must carry the public mark (ADR 0029 Amendment 12); `allowed` is the declared public names.
    #[serde(default)]
    public: bool,
    #[serde(default)]
    msg: String,
    #[serde(default)]
    prefix: String,
    #[serde(default)]
    project: String,
    #[serde(default)]
    env: String,
    #[serde(default)]
    text: String,
    #[serde(default)]
    allowed: Vec<String>,
    #[serde(default)]
    lines: Vec<ImportLine>,
    /// An approval code from the dashboard (see `secrets_approval`).
    #[serde(default)]
    approval: String,
    /// An approved `import` request (ADR 0041), instead of a code, and the laptop's per-import salt that its digest binds
    /// each value by.
    #[serde(default)]
    request_id: String,
    #[serde(default)]
    salt: String,
    #[serde(default)]
    scope: String,
    #[serde(default)]
    items: Vec<LoadItem>,
}

#[derive(Deserialize, Default)]
struct LoadItem {
    project: String,
    env: String,
    name: String,
    value: String,
}

#[derive(Deserialize, Default)]
struct ImportLine {
    name: String,
    /// The value itself, when the plain rule holds it.
    #[serde(default)]
    value: String,
    /// Any other value, as base64 (what a laptop sends for a value with spaces, quotes or several lines). The receiver
    /// decodes it and decides again what it is; the sender's word about it is never taken.
    #[serde(default)]
    value_b64: Option<String>,
    /// The person marked this value PUBLIC (`ozbox secrets import --public`).
    #[serde(default)]
    public: bool,
}

/// The exact value of an import line, or `None` for a line that is not valid (both forms given, or bad base64/UTF-8).
fn import_value(l: &ImportLine) -> Option<String> {
    match &l.value_b64 {
        None => Some(l.value.clone()),
        Some(_) if !l.value.is_empty() => None,
        Some(b) => String::from_utf8(decode_std(b)?).ok(),
    }
}

#[derive(Serialize)]
struct Resp {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    names: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    flag: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    held: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    invalid: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl Resp {
    fn ok() -> Self {
        Resp {
            ok: true,
            value: None,
            names: None,
            tags: None,
            flag: None,
            held: None,
            invalid: None,
            result: None,
            error: None,
        }
    }
    fn fail(e: &str) -> Self {
        Resp {
            error: Some(e.to_string()),
            ok: false,
            ..Resp::ok()
        }
    }
}

/// What the service remembers between requests, in memory only: the approvals waiting to be used and a budget for the
/// content scan that stops it being used as a guessing oracle.
/// Why a gated change was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// No second factor is enrolled and this scope is not one a box may change before one is.
    NoApprover(String),
    /// The approval was missing, wrong, spent or for something else.
    Approval(String),
}

#[derive(Default)]
pub struct Gates {
    pub approvals: crate::secrets_approval::ApprovalGate,
    scans: std::sync::Mutex<Vec<u64>>,
    /// Refused-answer lines written in the current minute, per kind of refusal (see `audit_event_bounded`).
    refused_window: std::sync::Mutex<std::collections::HashMap<String, RefusedWindow>>,
    /// The box's own secrets, loaded from the provider's secret store and kept in a store on tmpfs (see `box_secrets`).
    /// Offered like an imported `.env`, looked at before the persistent store, never written to a disk.
    pub memory: std::sync::OnceLock<Arc<EncryptedSecrets>>,
    /// The audit chain this service writes (ADR 0028). Without it the service records nothing in a chain.
    pub audit: std::sync::OnceLock<Arc<crate::audit_service::AuditCfg>>,
    /// Challenges a laptop key has been asked to sign (see `approval_key`).
    pub challenges: crate::approval_key::Challenges,
    /// Challenges issued for a key's attestation to be made over (see `approval_keystore`).
    pub enrol_challenges: crate::approval_keystore::EnrolChallenges,
    /// The roots an attestation may chain to: the pinned vendor roots and any root added in a file only root writes. Unset,
    /// only the pinned ones count (tests set their own).
    pub fido_roots: std::sync::OnceLock<Vec<Vec<u8>>>,
    /// Where the service records, on `/work` beside its store's copy, that the owner revoked the pinned key, so a new store
    /// (after a recovery) does not enrol it again (see `secrets_recover::PIN_RECORD`).
    pub pin_record: std::sync::OnceLock<std::path::PathBuf>,
    /// The key sealed requests are made to, and the ids already used (see `secrets_ingress`).
    pub ingress: std::sync::OnceLock<Arc<crate::secrets_ingress::Ingress>>,
    /// The first-time dashboard code the supervisor handed over, held in memory until it expires.
    pub setup_code: crate::secrets_ingress::SetupCode,
    /// Where a file-kept store key is, when this box keeps it in one (so the owner can escrow a copy off the box).
    pub kek_file: std::sync::OnceLock<std::path::PathBuf>,
    /// The approval requests (ADR 0041): a journal of their own, off the lock `resolve` takes. Unset until a decider
    /// ships (see `approval_requests`); a service with it unset answers the request operations "not available".
    pub requests: std::sync::OnceLock<Arc<crate::approval_requests::RequestService>>,
    /// Set when this version's request journal did not open at start. The protections that belong to this version (the
    /// dashboard makes no enrolment code, a code enrolment serves its 24-hour wait) then still hold, rather than falling
    /// back to what the version before did (phase 2 re-check NL1).
    pub requests_failed: std::sync::OnceLock<()>,
    /// `approvals.legacy_codes_off` (ADR 0041 section 10): whether scope-only approval codes are refused on a service that
    /// has request operations. Codes are on by default until phase 3 (owner, 2026-11-13); root's off-switch file turns them
    /// off (set at start); unset reads as on.
    pub legacy_codes_off: std::sync::OnceLock<bool>,
    /// Whether a key whose attestation verified counts as a presence key. Off until a real key has been proved on a box
    /// (root's flag file turns it on); unset reads as off, so every key is a software key.
    pub presence_keys: std::sync::OnceLock<bool>,
}

/// What a call says when the connection itself failed: the socket is missing or nothing is listening on it (the service is not
/// there, or restarting). This is the one failure the commit hooks treat as an outage and degrade for (ADR 0029 Amendment 15).
/// It is worth waiting out. An answer that says no is a refusal, and fails at once.
pub const SERVICE_DOWN: &str = "the box's secrets service is not reachable";

/// What a call says when it could not get an answer although it may well be there: a socket that refuses this user, a service too
/// busy to accept, a read that timed out, a write that failed, or a reply that is not one. Worth waiting out like
/// [`SERVICE_DOWN`], but NOT an outage: the hooks hold the change for it, as they did before the outage rule, because a service
/// that is up and slow or confused must not be a way to commit unscanned.
pub const SERVICE_NO_ANSWER: &str = "the box's secrets service did not answer";

/// Whether a call's error is one of the two "no answer" kinds (the ones a poll waits out).
pub fn is_no_answer(e: &str) -> bool {
    e == SERVICE_DOWN || e == SERVICE_NO_ANSWER
}

/// What a refused code is told: this box takes approvals as requests.
pub const CODES_REFUSED: &str = "this box takes approvals as requests, not as codes: ask for the change so it is filed, then approve that request on the Approvals page or from your computer (a code that is not tied to a request is not made or accepted here)";

/// One minute of one kind of refusal: how many lines went to the chain and how many were left out.
#[derive(Default)]
struct RefusedWindow {
    start_ms: u64,
    written: u32,
    dropped: u32,
}

/// How many lines of one kind of refusal reach the chain in a minute. The rest are counted and written as one line.
pub const REFUSED_LINES_PER_KIND_PER_MINUTE: u32 = 10;

const SCANS_PER_MINUTE: usize = 120;
const MAX_SCAN_BYTES: usize = 1 << 20;

impl Gates {
    /// One line in the audit chain about something this service did. Names, scopes and counts only; never a value or a
    /// code. Best effort: the change it describes has happened, and the line also goes to the plain log beside the store.
    pub fn audit_event(&self, store: &dyn SecretStore, action: &str, subject: &str, detail: &str) {
        if let Some(cfg) = self.audit.get() {
            cfg.record(store, action, subject, detail);
        }
    }

    /// A refusal line a hostile process can cause as often as it likes (a bad signature on a live nonce, a wrong approval
    /// code). Nothing is locked out: the first few lines of a minute are written, the rest are only counted, and the next
    /// minute opens with one line saying how many were left out. The count lock is a map update, never held while the
    /// chain is written, so a flood does not queue on the store's lock that `resolve` takes.
    pub fn audit_event_bounded(
        &self,
        store: &dyn SecretStore,
        action: &str,
        subject: &str,
        detail: &str,
        now_ms: u64,
    ) {
        // a refusal of any kind also closes the windows of the others that have ended (phase 1 N4)
        self.flush_refused(store, now_ms, Some(action));
        let (write, summary) = {
            let mut m = self
                .refused_window
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let w = m.entry(action.to_string()).or_default();
            let mut summary = 0;
            if now_ms.saturating_sub(w.start_ms) >= 60_000 || w.start_ms > now_ms {
                summary = w.dropped;
                *w = RefusedWindow {
                    start_ms: now_ms,
                    ..RefusedWindow::default()
                };
            }
            let write = w.written < REFUSED_LINES_PER_KIND_PER_MINUTE;
            if write {
                w.written += 1;
            } else {
                w.dropped += 1;
            }
            (write, summary)
        };
        if summary > 0 {
            self.audit_event(
                store,
                action,
                "",
                &format!("coalesced={summary} left out in the last minute"),
            );
        }
        if write {
            self.audit_event(store, action, subject, detail);
        }
    }

    /// Whether a scope-only approval code may be minted or spent now. A service with no request operations has nothing else;
    /// one that has them takes codes until root's `approvals.legacy_codes_off` flag is set (ADR 0041 section 10; default on
    /// until phase 3).
    pub fn codes_allowed(&self) -> bool {
        self.requests.get().is_none() || !self.legacy_codes_off.get().copied().unwrap_or(false)
    }

    /// Whether this version's approval protections apply: the request service is on, or it was meant to be and failed to open.
    pub fn requests_guarded(&self) -> bool {
        self.requests.get().is_some() || self.requests_failed.get().is_some()
    }

    /// Whether a verified attestation makes a key a presence key on this box.
    pub fn presence_keys_on(&self) -> bool {
        self.presence_keys.get().copied().unwrap_or(false)
    }

    /// Write the "left out" line of every window that has ended with refusals dropped, so a count is never kept waiting for a
    /// later refusal of the same kind that may never come. Called by every bounded refusal and by the
    /// request service's sweep (which the dashboard's alert tick reaches every few seconds). `except` is a window the
    /// caller is about to reopen itself.
    pub fn flush_refused(&self, store: &dyn SecretStore, now_ms: u64, except: Option<&str>) {
        let due: Vec<(String, u32)> = {
            let mut m = self
                .refused_window
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            m.iter_mut()
                .filter(|(k, w)| {
                    except != Some(k.as_str())
                        && w.dropped > 0
                        && now_ms.saturating_sub(w.start_ms) >= 60_000
                })
                .map(|(k, w)| {
                    let n = w.dropped;
                    w.dropped = 0;
                    (k.clone(), n)
                })
                .collect()
        };
        for (action, n) in due {
            self.audit_event(
                store,
                &action,
                "",
                &format!("coalesced={n} left out in the last minute"),
            );
        }
    }

    pub(crate) fn scan_allowed(&self, now_ms: u64) -> bool {
        let mut s = self.scans.lock().unwrap_or_else(|e| e.into_inner());
        s.retain(|t| now_ms.saturating_sub(*t) < 60_000);
        if s.len() >= SCANS_PER_MINUTE {
            return false;
        }
        s.push(now_ms);
        true
    }

    /// The audit record of one gate decision: `allowed`, `refused`, or `kept` (the approval was good, the write it was for was
    /// refused, and the approval is still usable).
    #[allow(clippy::too_many_arguments)]
    fn gate_line(
        &self,
        store: &EncryptedSecrets,
        what: &str,
        scope: &str,
        project: &str,
        env: &str,
        via: &str,
        now_ms: u64,
    ) {
        crate::workload::audit(
            store.path(),
            &format!("approval {what} scope={scope} project={project} env={env} via={via}"),
        );
        let action = match (what, via) {
            ("refused", _) => "secrets.approval.refused",
            ("kept", _) => "secrets.approval.kept",
            (_, crate::secrets_approval::VIA_BOOTSTRAP) => "secrets.approval.bootstrap",
            _ => "secrets.approval.spent",
        };
        let detail = format!("project={project} env={env} via={via}");
        if what == "refused" {
            // a wrong code can be sent as often as a process likes: bounded, never a lockout
            self.audit_event_bounded(store, action, scope, &detail, now_ms);
        } else {
            self.audit_event(store, action, scope, &detail);
        }
    }

    /// [`Gates::require`] for a write: `effect` runs once the approval is known good and the approval is spent only if it
    /// succeeds. A write the box refuses (storage, a limit) leaves the person's single-use code usable; a write that happened
    /// can never be repeated with the same code, because the approval is taken under the lock before the write and put back only
    /// if the write fails ([`crate::secrets_approval::ApprovalGate::consume_then`]), the lock not held across the write. Check everything that does not depend on the approval BEFORE
    /// calling this, so a doomed request is refused without even looking at the code. On a box with no second factor the rules
    /// of [`crate::secrets_approval::SCOPE_RULES`] apply exactly as for `require`.
    ///
    /// `declared` says what the caller knows of the change: it touches Production (a declaration with a Production command), so a
    /// code a software key made is refused for it (ADR 0041 §3). It can only make the gate stricter.
    #[allow(clippy::too_many_arguments)]
    pub fn require_then<T>(
        &self,
        store: &EncryptedSecrets,
        scope: &str,
        project: &str,
        env: &str,
        approval: &str,
        declared: bool,
        now_ms: u64,
        effect: impl FnOnce(&str) -> Result<T, String>,
    ) -> Result<T, String> {
        use crate::secrets_approval::ConsumeThen;
        let line =
            |what: &str, via: &str| self.gate_line(store, what, scope, project, env, via, now_ms);
        if !store
            .exists(crate::secrets_approval::ENROLLED_MARKER)
            .map_err(|e| e.0)?
        {
            use crate::secrets_approval::{in_bootstrap, InBootstrap};
            if in_bootstrap(scope) == InBootstrap::Refused {
                line("refused", "none why=no-approver");
                return Err(crate::secrets_approval::bootstrap_refusal(scope));
            }
            let out = effect(crate::secrets_approval::VIA_BOOTSTRAP)?;
            line("allowed", crate::secrets_approval::VIA_BOOTSTRAP);
            return Ok(out);
        }
        if !self.codes_allowed() {
            line("refused", "none why=codes-off");
            return Err(CODES_REFUSED.to_string());
        }
        match self
            .approvals
            .consume_then_tiered(approval, scope, project, env, declared, now_ms, |via| {
                let out = effect(via)?;
                line("allowed", via);
                Ok(out)
            }) {
            Ok(out) => Ok(out),
            Err(ConsumeThen::Effect(e)) => {
                line("kept", "none");
                Err(e)
            }
            Err(ConsumeThen::Signer(e)) => {
                line("refused", "none why=software-key-production");
                Err(e)
            }
            Err(ConsumeThen::Approval(e)) => {
                line("refused", "none");
                Err(if approval.is_empty() {
                    "this change needs a fresh approval from the dashboard (your passkey or authenticator code): ask for one there and run the command again with --approval CODE".to_string()
                } else {
                    e
                })
            }
        }
    }

    /// Whether a change to the box's secrets is allowed by a fresh second factor. Returns how it was allowed, for the
    /// audit line. Never a value in what it records.
    pub fn require(
        &self,
        store: &EncryptedSecrets,
        scope: &str,
        project: &str,
        env: &str,
        approval: &str,
        now_ms: u64,
    ) -> Result<String, String> {
        self.require_typed(store, scope, project, env, approval, now_ms)
            .map_err(|r| match r {
                Refusal::NoApprover(m) | Refusal::Approval(m) => m,
            })
    }

    /// [`Gates::require`], saying whether a refusal is because no second factor exists yet (the rules for that are
    /// [`crate::secrets_approval::SCOPE_RULES`], and nothing else decides them).
    pub fn require_typed(
        &self,
        store: &EncryptedSecrets,
        scope: &str,
        project: &str,
        env: &str,
        approval: &str,
        now_ms: u64,
    ) -> Result<String, Refusal> {
        self.require_typed_tiered(store, scope, project, env, approval, false, now_ms)
    }

    #[allow(clippy::too_many_arguments)]
    fn require_typed_tiered(
        &self,
        store: &EncryptedSecrets,
        scope: &str,
        project: &str,
        env: &str,
        approval: &str,
        declared: bool,
        now_ms: u64,
    ) -> Result<String, Refusal> {
        use crate::secrets_approval::ConsumeThen;
        let line =
            |what: &str, via: &str| self.gate_line(store, what, scope, project, env, via, now_ms);
        if !store
            .exists(crate::secrets_approval::ENROLLED_MARKER)
            .map_err(|e| Refusal::Approval(e.0))?
        {
            use crate::secrets_approval::{in_bootstrap, InBootstrap};
            if in_bootstrap(scope) == InBootstrap::Refused {
                line("refused", "none why=no-approver");
                return Err(Refusal::NoApprover(
                    crate::secrets_approval::bootstrap_refusal(scope),
                ));
            }
            line("allowed", crate::secrets_approval::VIA_BOOTSTRAP);
            return Ok(crate::secrets_approval::VIA_BOOTSTRAP.to_string());
        }
        if !self.codes_allowed() {
            line("refused", "none why=codes-off");
            return Err(Refusal::Approval(CODES_REFUSED.to_string()));
        }
        match self
            .approvals
            .consume_tiered(approval, scope, project, env, declared, now_ms)
        {
            Ok(via) => {
                line("allowed", &via);
                Ok(via)
            }
            Err(ConsumeThen::Signer(e)) => {
                line("refused", "none why=software-key-production");
                Err(Refusal::Approval(e))
            }
            Err(e) => {
                let e = e.into_message();
                line("refused", "none");
                Err(Refusal::Approval(if approval.is_empty() {
                    "this change needs a fresh approval from the dashboard (your passkey or authenticator code): ask for one there and run the command again with --approval CODE".to_string()
                } else {
                    e
                }))
            }
        }
    }
}

/// Spend an approved `import` request for exactly these rows (ADR 0041 §4). The subject is recomputed here from
/// the rows as they stand: every name, its classification, the digest of its value under the laptop's salt, the environment
/// and the project's generation. A row changed, added or left out after the approval is another digest, and the spend is
/// refused without burning the approval. Where the service sees the values it also refuses an import whose values say
/// Production while the subject does not (`check_import_values`). Returns how it was approved, for the audit line.
#[allow(clippy::too_many_arguments)]
fn spend_import_request(
    store: &EncryptedSecrets,
    gates: &Gates,
    project: &str,
    env: &str,
    lines: &[crate::workload::EnvLine],
    request_id: &str,
    salt: &str,
    now: u64,
) -> Result<String, String> {
    use ozbox_core::approval_subject::{
        import_value_digest, is_production_environment, Classification, Import, ImportName, Subject,
    };
    let svc = gates
        .requests
        .get()
        .ok_or("this service does not keep approval requests: send an approval code")?;
    if salt.len() < 16 || salt.len() > 128 || !salt.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("an import by request carries the salt its digest was made with".into());
    }
    let mut names: Vec<ImportName> = lines
        .iter()
        .map(|l| ImportName {
            name: l.name.clone(),
            // phase 3 marks values public by name; until then every value is a secret, the stricter reading
            classification: Classification::Secret,
            value_digest: import_value_digest(salt, &l.value),
        })
        .collect();
    names.sort();
    let subject = Subject::Import(Import {
        project: project.to_string(),
        environment: env.to_string(),
        production: is_production_environment(env),
        names,
        store_generation: svc.import_generation(store, project, env),
    });
    subject
        .check_import_values(lines.iter().map(|l| (l.name.as_str(), l.value.as_str())))
        .map_err(|e| e.0)?;
    let r = svc.spend(
        store,
        gates,
        ozbox_core::approval::SpendVia::Inside,
        request_id,
        &subject,
        now,
    )?;
    Ok(format!(
        "request:{}",
        r.decision
            .as_ref()
            .map_or("approved", |d| d.factor_label.as_str())
    ))
}

/// Answer one request under a policy, with a fresh gate state (tests that need none of it).
#[cfg(test)]
pub fn handle(store: &EncryptedSecrets, mac: &TokenMac, policy: Policy, line: &str) -> String {
    handle_with(store, mac, &Gates::default(), policy, line)
}

/// Answer one request under a policy. Pure apart from the store and the gates, so it is tested without a socket.
#[cfg(test)]
pub fn handle_with(
    store: &EncryptedSecrets,
    mac: &TokenMac,
    gates: &Gates,
    policy: Policy,
    line: &str,
) -> String {
    handle_from(store, mac, gates, policy, None, line)
}

/// [`handle_with`] for a request whose sender the kernel named (`SO_PEERCRED`): the audit chain records that user.
pub fn handle_from(
    store: &EncryptedSecrets,
    mac: &TokenMac,
    gates: &Gates,
    policy: Policy,
    peer_uid: Option<u32>,
    line: &str,
) -> String {
    let now = crate::tokenmac::now_ms();
    // the ingress socket takes a public key request and sealed ones; an opened one is answered as `Policy::Unsealed`
    if policy == Policy::Ingress {
        return crate::secrets_ingress::handle_outer(store, gates, line, now, &|inner| {
            handle_from(store, mac, gates, Policy::Unsealed, peer_uid, inner)
        });
    }
    // the audit chain's own operations (ADR 0028) carry arrays the plain request does not
    if line.contains("\"audit_") {
        if let Ok(v) = serde_json::from_str::<Value>(line) {
            if v["op"].as_str().is_some_and(|o| o.starts_with("audit_")) {
                let out = match gates.audit.get() {
                    None => {
                        json!({"ok": false, "error": "this service does not keep an audit chain"})
                    }
                    Some(cfg) => match cfg.respond(store, policy, peer_uid, &v) {
                        Ok(r) => json!({"ok": true, "result": r}),
                        Err(e) => json!({"ok": false, "error": e}),
                    },
                };
                return out.to_string();
            }
        }
    }
    // the approval requests' operations (ADR 0041) are answered by their own module, on their own journal
    if line.contains("\"areq_") {
        if let Ok(v) = serde_json::from_str::<Value>(line) {
            if v["op"].as_str().is_some_and(|o| o.starts_with("areq_")) {
                let class = match policy {
                    Policy::Box | Policy::BoxLocked => Some(ozbox_core::approval::SocketClass::Box),
                    Policy::Supervisor => Some(ozbox_core::approval::SocketClass::Supervisor),
                    Policy::Admin => Some(ozbox_core::approval::SocketClass::Admin),
                    // a sealed request the ingress socket opened: the laptop, whose signature is the credential
                    Policy::Unsealed => Some(ozbox_core::approval::SocketClass::Ingress),
                    _ => None,
                };
                let out = match (class, gates.requests.get()) {
                    (None, _) => {
                        json!({"ok": false, "error": "that is not allowed on this socket"})
                    }
                    (Some(_), None) if v["op"] == "areq_capabilities" => {
                        json!({"ok": true, "result": {"request_ops": false}})
                    }
                    (Some(_), None) => {
                        json!({"ok": false, "error": "this service does not keep approval requests yet"})
                    }
                    (Some(c), Some(svc)) => match svc.handle(store, gates, c, peer_uid, &v, now) {
                        Ok(r) => json!({"ok": true, "result": r}),
                        Err(e) => json!({"ok": false, "error": e}),
                    },
                };
                return out.to_string();
            }
        }
    }
    // a laptop key's operations (ADR 0028) are answered by their own module
    if line.contains("\"approval_") {
        if let Ok(v) = serde_json::from_str::<Value>(line) {
            if v["op"].as_str().is_some_and(|o| o.starts_with("approval_")) {
                let out = match crate::approval_key::handle(store, gates, policy, &v, now) {
                    Ok(r) => json!({"ok": true, "result": r}),
                    Err(e) => json!({"ok": false, "error": e}),
                };
                return out.to_string();
            }
        }
    }
    let r: Req = match serde_json::from_str(line) {
        Ok(r) => r,
        Err(_) => return json!({"ok": false, "error": "that request is not valid"}).to_string(),
    };
    let denied = || Resp::fail("that is not allowed on this socket");
    // a workload secret and a project's declaration are never the box socket's to read, write or list
    let boxy = |name: &str| !name.starts_with("workload");
    let resp = match (policy, r.op.as_str()) {
        (Policy::Box | Policy::Supervisor | Policy::Admin, "set")
            if (boxy(&r.name) && box_may_write(&r.name)) || policy == Policy::Admin =>
        {
            let stored = if r.value_b64.is_empty() {
                store.set(&r.name, &r.value)
            } else if policy != Policy::Admin || !r.value.is_empty() {
                // an exact (encoded) value is the root helper's to store; a box's own names stay on the plain rule
                Err(crate::secrets::SecretError(
                    "that value is not accepted on this socket".into(),
                ))
            } else {
                decode_std(&r.value_b64)
                    .and_then(|b| String::from_utf8(b).ok())
                    .ok_or_else(|| crate::secrets::SecretError("that request is not valid".into()))
                    .and_then(|v| {
                        store
                            .set_exact_with_meta(&r.name, &v, crate::secrets_enc::Meta::default())
                            .map(|_| ())
                    })
            };
            match stored {
                Ok(()) => {
                    gates.audit_event(
                        store,
                        "secrets.set",
                        &r.name,
                        &format!("via={}", policy.word()),
                    );
                    Resp::ok()
                }
                Err(e) => Resp::fail(&e.0),
            }
        }
        (Policy::Box | Policy::BoxLocked | Policy::Supervisor | Policy::Admin, "exists") => {
            match store.exists(&r.name) {
                Ok(b) => Resp {
                    flag: Some(b),
                    ..Resp::ok()
                },
                Err(e) => Resp::fail(&e.0),
            }
        }
        (Policy::Box | Policy::Supervisor | Policy::Admin, "delete")
            if (boxy(&r.name) && box_may_write(&r.name)) || policy == Policy::Admin =>
        {
            match store.delete(&r.name) {
                Ok(()) => {
                    gates.audit_event(
                        store,
                        "secrets.delete",
                        &r.name,
                        &format!("via={}", policy.word()),
                    );
                    Resp::ok()
                }
                Err(e) => Resp::fail(&e.0),
            }
        }
        (Policy::Box | Policy::BoxLocked | Policy::Supervisor | Policy::Admin, "names")
            if !r.prefix.starts_with("workload") || policy == Policy::Admin =>
        {
            let mut all = store.names(&r.prefix);
            if let (Ok(v), Some(m), Policy::Admin) = (&mut all, gates.memory.get(), policy) {
                if let Ok(more) = m.names(&r.prefix) {
                    v.extend(more);
                    v.sort();
                    v.dedup();
                }
            }
            match all {
                Ok(n) => Resp {
                    names: Some(
                        n.into_iter()
                            .filter(|n| {
                                policy == Policy::Admin
                                    || (boxy(n)
                                        && n != crate::secrets_approval::ENROLLED_MARKER
                                        && !crate::audit_service::is_audit_secret(n)
                                        && !crate::approval_key::is_reserved(n))
                            })
                            .collect(),
                    ),
                    ..Resp::ok()
                },
                Err(e) => Resp::fail(&e.0),
            }
        }
        (Policy::Box | Policy::Supervisor | Policy::Admin, "mac") => match decode_std(&r.msg) {
            Some(m) => Resp {
                tags: Some(mac.tags_hex(&m, crate::tokenmac::now_ms())),
                ..Resp::ok()
            },
            None => Resp::fail("that request is not valid"),
        },
        (Policy::Box | Policy::Supervisor, "get") if box_may_get(&r.name) => {
            match store.get(&r.name) {
                Ok(v) => Resp {
                    value: v,
                    ..Resp::ok()
                },
                Err(e) => Resp::fail(&e.0),
            }
        }
        (Policy::Admin, "get") => {
            let held = gates
                .memory
                .get()
                .filter(|_| r.name.starts_with("workload."))
                .and_then(|m| m.get(&r.name).ok().flatten());
            match held
                .map(|v| Ok(Some(v)))
                .unwrap_or_else(|| store.get(&r.name))
            {
                Ok(v) => Resp {
                    value: v,
                    ..Resp::ok()
                },
                Err(e) => Resp::fail(&e.0),
            }
        }
        // Nothing is resolved for a command on a box with no second factor: a declaration written before this rule (or a marker
        // cleared by root) must not hand a key to a command the box user could have declared.
        (Policy::Runner | Policy::Admin, "resolve")
            if !store.exists(crate::secrets_approval::ENROLLED_MARKER).unwrap_or(false) =>
        {
            Resp::fail(NO_SECRET_DECLARATION)
        }
        (Policy::Runner | Policy::Admin, "resolve") => {
            // the box's own secrets first; a name only the imported store has falls through to it
            let resolve = |s: &EncryptedSecrets| {
                if r.exact && r.public {
                    // only the imported store carries a person's public mark: the box's own secrets never do
                    s.resolve_public(&r.project, &r.env, &r.name, &r.allowed)
                } else if r.exact {
                    // an environment variable: exactly what was stored, whatever it holds
                    s.resolve_exact(&r.project, &r.env, &r.name, &r.allowed, false)
                } else {
                    s.resolve_refs(&r.project, &r.env, &r.text, &r.allowed, false)
                }
            };
            let from_memory = gates
                .memory
                .get()
                .filter(|_| !r.public)
                .and_then(|m| resolve(m).ok());
            let resolved = match from_memory {
                Some(v) => Ok(v),
                None => resolve(store),
            };
            // a command that names no reference resolves nothing worth a line
            if r.exact || r.text.contains("{{secret:") {
                gates.audit_event(
                    store,
                    if resolved.is_ok() {
                        "secrets.resolve"
                    } else {
                        "secrets.resolve.refused"
                    },
                    &r.project,
                    &format!("env={}", r.env),
                );
            }
            match resolved {
                Ok(v) => Resp {
                    value: Some(v.to_string()),
                    ..Resp::ok()
                },
                Err(e) => Resp::fail(&e.0),
            }
        }
        // What this service takes, so a laptop never sends it a form it cannot read: a service from before encoded values
        // answers "not allowed" to this op, and the laptop sends it plain values only. It comes sealed, like the import it
        // comes before (ADR 0029 Amendment 9).
        (Policy::Unsealed, "capabilities") => Resp {
            result: Some(json!({"encoded_values": true, "declaration_v2": true, "declaration_records": true, "runner_uids": true, "public_values": true})),
            ..Resp::ok()
        },
        (Policy::Unsealed, "import") => {
            use crate::workload::{apply_marked, EnvLine};
            let public: Vec<String> = r
                .lines
                .iter()
                .filter(|l| l.public)
                .map(|l| l.name.clone())
                .collect();
            let decoded: Option<Vec<EnvLine>> = r
                .lines
                .iter()
                .enumerate()
                .map(|(i, l)| {
                    import_value(l).map(|v| EnvLine {
                        name: l.name.clone(),
                        value: zeroize::Zeroizing::new(v),
                        line: i + 1,
                        malformed: None,
                    })
                })
                .collect();
            let lines = decoded.unwrap_or_default();
            if lines.is_empty() || lines.len() > 500 {
                Resp::fail("that request is not valid")
            } else if !public.is_empty()
                && !store.exists(crate::secrets_approval::ENROLLED_MARKER).unwrap_or(false)
            {
                // a public value cannot be handed out before a second factor exists, and a mark planted now would outlive that
                // day: it would reach plain environment of any command that names it once the box is enrolled
                Resp::fail("this box has no second factor enrolled yet, so a value cannot be marked public from the box. Import it as an ordinary value now, or enrol a passkey in the dashboard (or make the box with `ozbox create` from a computer with a keychain) and mark it then")
            } else if let Some(n) = overwritten_before_enrolment(store, &r.project, &r.env, &lines) {
                // a stored value a command's key may be sent to (a URL), replaced by the box user, is a way to aim an approved
                // command at the agent's own host once a second factor exists: before then a value is set once
                Resp::fail(&format!("{n} is already stored for this project and environment, and this box has no second factor enrolled, so it cannot be replaced from the box. Enrol a passkey in the dashboard (or make the box with `ozbox create` from a computer with a keychain), then import it with an approval"))
            } else {
                let gate = if r.request_id.is_empty() {
                    gates.require(store, "import", &r.project, &r.env, &r.approval, now)
                } else {
                    spend_import_request(store, gates, &r.project, &r.env, &lines, &r.request_id, &r.salt, now)
                };
                match gate {
                    Err(e) => Resp::fail(&e),
                    Ok(via) => {
                        match apply_marked(store, &r.project, &r.env, &lines, &r.allowed, &public, &r.text) {
                            Ok(a) => {
                                // names only: which of the stored values carry the public mark
                                let marked = a
                                    .stored
                                    .iter()
                                    .filter(|n| public.contains(n))
                                    .cloned()
                                    .collect::<Vec<_>>()
                                    .join(",");
                                // the request is spent only now that the effect happened (§2: spending, effect, spent)
                                if !r.request_id.is_empty() {
                                    if let Some(svc) = gates.requests.get() {
                                        let _ = svc.finish_inside(&r.request_id, now);
                                    }
                                }
                                crate::workload::audit(
                                    store.path(),
                                    &format!(
                                        "import project={} env={} stored={} held={} public={marked} via={via}",
                                        r.project,
                                        r.env,
                                        a.stored.len(),
                                        a.held_back.len()
                                    ),
                                );
                                gates.audit_event(
                                    store,
                                    "secrets.import",
                                    &r.project,
                                    &format!(
                                        "env={} stored={} held={} public={marked} via={via}",
                                        r.env,
                                        a.stored.len(),
                                        a.held_back.len()
                                    ),
                                );
                                Resp {
                                    names: Some(a.stored),
                                    held: Some(a.held_back),
                                    invalid: Some(a.invalid),
                                    ..Resp::ok()
                                }
                            }
                            Err(e) => Resp::fail(&e.0),
                        }
                    }
                }
            }
        }
        (Policy::Unsealed, "policy") => {
            // Everything that can be decided without the approval is decided first, so a declaration the box would refuse (its
            // shape, its secret rules, its size once written out) never touches the person's single-use code. The approval is then
            // spent together with the write ([`Gates::require_then`]): a write that fails leaves the code usable.
            match crate::workload_policy::Policy::parse(&r.text)
                .and_then(|p| p.check_before_write().map(|_| p))
                .map_err(|e| e.0)
                .and_then(|p| policy_bootstrap_gate(store, &r.project, &p).map(|()| p))
            {
                Err(e) => Resp::fail(&e),
                Ok(p) => match gates.require_then(
                    store,
                    "policy",
                    &r.project,
                    "",
                    &r.approval,
                    // a declaration that touches Production is never approved by a key kept on a computer (ADR 0041 §3); one
                    // whose current declaration cannot be read is treated as touching it, the stricter reading
                    crate::workload_policy::load(store, &r.project).map_or(true, |cur| {
                        crate::secrets_signer::declaration_touches_production(&p, cur.as_ref())
                    }),
                    now,
                    |via| {
                        crate::workload_policy::save(store, &r.project, &p).map_err(|e| e.0)?;
                        Ok(via.to_string())
                    },
                ) {
                    Err(e) => Resp::fail(&e),
                    Ok(via) => {
                        crate::workload::audit(
                            store.path(),
                            &format!("policy project={} via={via}", r.project),
                        );
                        gates.audit_event(
                            store,
                            "secrets.policy.write",
                            &r.project,
                            &format!("via={via}"),
                        );
                        Resp::ok()
                    }
                },
            }
        }
        // The commit barrier asks whether text holds a stored secret. It learns a count and the names of the keys it
        // matched, never a value, and it is rate-limited so it cannot be used to guess one.
        (Policy::Import, "scan") => {
            if r.text.len() > MAX_SCAN_BYTES {
                Resp::fail("that is too much text to scan at once")
            } else if !gates.scan_allowed(now) {
                Resp::fail("too many scans: wait a minute")
            } else {
                match scan_text(store, gates.memory.get(), &r.text) {
                    Ok(names) => Resp {
                        names: Some(names),
                        ..Resp::ok()
                    },
                    Err(e) => Resp::fail(&e.0),
                }
            }
        }
        // A guard override is a recorded one-off: the approval is spent here and the hook is told yes or no.
        (Policy::Import, "override") => {
            // The code is for one change (ADR 0041): the hook names the repository and a digest of the tree, or of the
            // range of commits, it read, and the code must have been made for exactly that. A scope-only code is refused here.
            let hex16 = |s: &str| s.len() == 16 && s.bytes().all(|b| b.is_ascii_hexdigit());
            if !hex16(&r.project) || !hex16(&r.env) {
                Resp::fail("a guard override is for one change: it names the repository and the change it was approved for")
            } else {
                match gates.require(store, "guard-override", &r.project, &r.env, &r.approval, now) {
                    Ok(via) => {
                        crate::workload::audit(
                            store.path(),
                            &format!("guard-override project={} change={} via={via}", r.project, r.env),
                        );
                        gates.audit_event(
                            store,
                            "secrets.guard.override",
                            "",
                            &format!("project={} change={} via={via}", r.project, r.env),
                        );
                        Resp::ok()
                    }
                    Err(e) => Resp::fail(&e),
                }
            }
        }
        // The dashboard's first-time code goes to the person's computer through the ingress route, never to a log the box
        // user can read: the supervisor hands it here, and only a sealed request from the owner's computer reads it back.
        (Policy::Supervisor, "setup_code_put") => {
            match gates
                .setup_code
                .put(&r.value, r.msg.parse().unwrap_or(0), now)
            {
                Ok(()) => Resp::ok(),
                Err(e) => Resp::fail(e),
            }
        }
        (Policy::Unsealed, "setup_code") => match gates
            .require(store, "setup-code", "", "", &r.approval, now)
            .and_then(|_| gates.setup_code.get(now).ok_or_else(|| "none".to_string()))
        {
            Ok(code) => {
                gates.audit_event(store, "secrets.setup-code.read", "", "via=ingress");
                Resp {
                    value: Some(code),
                    ..Resp::ok()
                }
            }
            Err(e) if e == "none" => Resp::fail(
                "there is no first-time code waiting: the dashboard makes one only while nobody has enrolled a passkey, and it lasts 30 minutes (restart the dashboard to get another)",
            ),
            Err(e) => Resp::fail(&e),
        },
        // A copy of the file-kept store key for the owner's keychain, so an upgrade that replaces the system disk can put it
        // back (ADR 0029 Amendment 6 section 9). Only a sealed request from the owner's computer; recorded; never logged.
        (Policy::Unsealed, "kek_export") => match (
            gates.require(store, "kek-export", "", "", &r.approval, now),
            gates.kek_file.get(),
        ) {
            (Err(e), _) => Resp::fail(&e),
            (Ok(_), None) => Resp::fail(
                "this box's store key is not kept in a file (it is held by a key service, a TPM or a passphrase), so there is nothing to escrow",
            ),
            (Ok(_), Some(p)) => match std::fs::read_to_string(p) {
                Ok(t) => {
                    gates.audit_event(store, "secrets.kek.exported", "", "via=ingress");
                    Resp {
                        value: Some(t.trim().to_string()),
                        ..Resp::ok()
                    }
                }
                Err(_) => Resp::fail("the store's key file could not be read"),
            },
        },
        // Only the supervisor, once it has checked a fresh passkey or authenticator code, may ask for an approval.
        (Policy::Supervisor, "approve_mint") if !gates.codes_allowed() => Resp::fail(CODES_REFUSED),
        // the dashboard's socket never makes its own enrolment code on a box that takes requests: a key is enrolled from the
        // dashboard by an approved `signer-enroll` request only
        (Policy::Supervisor, "approve_mint")
            if crate::approval_key::dashboard_mint_refused(gates, &r.scope) =>
        {
            Resp::fail(
                "a key is enrolled from the dashboard by an approved request, not by a code",
            )
        }
        (Policy::Supervisor, "approve_mint") => {
            match gates.approvals.mint(
                &r.scope,
                &r.project,
                &r.env,
                &crate::secrets_signer::Signer::Dashboard,
                now,
                crate::secrets_approval::DEFAULT_TTL_MS,
            ) {
                Ok(code) => {
                    crate::workload::audit(
                        store.path(),
                        &format!(
                            "approval minted scope={} project={} env={}",
                            r.scope, r.project, r.env
                        ),
                    );
                    gates.audit_event(
                        store,
                        "secrets.approval.minted",
                        &r.scope,
                        &format!("project={} env={} via=dashboard-stepup", r.project, r.env),
                    );
                    Resp {
                        value: Some(code),
                        ..Resp::ok()
                    }
                }
                Err(e) => Resp::fail(&e),
            }
        }
        // What the dashboard shows as recent uses: scope, project, environment, how and when. The audit log holds nothing else.
        (Policy::Supervisor | Policy::Admin, "recent_approvals") => Resp {
            result: Some(json!({
                "enrolled": store.exists(crate::secrets_approval::ENROLLED_MARKER).unwrap_or(false),
                "recent": recent_approvals(store.path(), 30),
            })),
            ..Resp::ok()
        },
        // The dashboard says a second factor exists. From then on every gated change needs an approval, and nothing but
        // root can say otherwise.
        (Policy::Supervisor | Policy::Admin, "enroll") => {
            match store.set(crate::secrets_approval::ENROLLED_MARKER, "1") {
                Ok(()) => {
                    gates.audit_event(
                        store,
                        "secrets.second-factor.enrolled",
                        "",
                        &format!("via={}", policy.word()),
                    );
                    Resp::ok()
                }
                Err(e) => Resp::fail(&e.0),
            }
        }
        (Policy::Supervisor | Policy::Admin | Policy::Import | Policy::Unsealed, "enrolled") => {
            match store.exists(crate::secrets_approval::ENROLLED_MARKER) {
                Ok(b) => Resp {
                    flag: Some(b),
                    ..Resp::ok()
                },
                Err(e) => Resp::fail(&e.0),
            }
        }
        (Policy::Admin, "unenroll") => match store.delete(crate::secrets_approval::ENROLLED_MARKER)
        {
            Ok(()) => Resp::ok(),
            Err(e) => Resp::fail(&e.0),
        },
        // The box's secrets loader (the secrets user, on the admin socket) hands over what the provider holds for this
        // box's role. The service keeps it in its tmpfs store and forgets what the provider no longer lists.
        (Policy::Admin, "box_load") => match gates.memory.get() {
            None => Resp::fail("this service has no memory store"),
            Some(mem) => {
                let items: Vec<crate::box_secrets::Item> = r
                    .items
                    .into_iter()
                    .map(|i| crate::box_secrets::Item {
                        project: i.project,
                        env: i.env,
                        name: i.name,
                        value: zeroize::Zeroizing::new(i.value),
                    })
                    .collect();
                // the same refusal an import makes: nothing production-looking, whatever the loader says
                if items.iter().any(|i| {
                    !crate::box_secrets::ENVS.contains(&i.env.as_str())
                        || crate::workload::live_reason(&i.name, &i.value, &i.env).is_some()
                }) {
                    Resp::fail("a production-looking key is never loaded")
                } else {
                    match crate::box_secrets::replace_memory(mem, &r.scope, &items) {
                        Ok(n) => {
                            crate::workload::audit(
                                store.path(),
                                &format!("box-secrets loaded role={} count={n}", r.scope),
                            );
                            gates.audit_event(
                                store,
                                "secrets.box.loaded",
                                &r.scope,
                                &format!("count={n}"),
                            );
                            Resp {
                                names: Some(vec![n.to_string()]),
                                ..Resp::ok()
                            }
                        }
                        Err(e) => Resp::fail(&e.0),
                    }
                }
            }
        },
        // The root helper asks this before it stores a tunnel token (it cannot judge a code itself).
        (Policy::Admin, "gate") => {
            match gates.require(store, &r.scope, &r.project, &r.env, &r.approval, now) {
                Ok(via) => Resp {
                    value: Some(via),
                    ..Resp::ok()
                },
                Err(e) => Resp::fail(&e),
            }
        }
        _ => denied(),
    };
    serde_json::to_string(&resp).unwrap_or_else(|_| "{\"ok\":false}".into())
}

/// A declaration decides which commands receive a project's secrets, and before a second factor exists the box user (and every
/// agent it runs) cannot be told apart from the owner. So on such a box NO declaration may give a command a secret, whether it is a
/// first one or a replacement (ADR 0029 Amendment 10, revision 2): the squat (an agent declares first, then the keys arrive) and the
/// replacement are one hole, and the only thing a box can safely accept without a second factor is a declaration that hands out
/// nothing. A plain build or test command, a service, and a declaration that REMOVES secrets are accepted. Once a second factor
/// is enrolled the gate returns to an approval.
fn policy_bootstrap_gate(
    store: &EncryptedSecrets,
    project: &str,
    new: &crate::workload_policy::Policy,
) -> Result<(), String> {
    let enrolled = store
        .exists(crate::secrets_approval::ENROLLED_MARKER)
        .map_err(|e| e.0)?;
    if enrolled {
        return Ok(()); // an approval is required, and checked, by the gate
    }
    let _ = project;
    if new
        .commands
        .values()
        .any(crate::workload_policy::CommandPolicy::bears_secrets)
    {
        return Err(NO_SECRET_DECLARATION.to_string());
    }
    Ok(())
}

/// Why a command cannot be given a secret on a box with no second factor, and what to do. (The same words in every place that
/// refuses: the declaration, the launcher, and the `resolve` op.)
pub const NO_SECRET_DECLARATION: &str = "this box has no second factor enrolled, so no command can be given a secret yet: the box user asking is not an approval, and an agent on the box could declare a command of its own and receive the keys. Enrol a passkey in the dashboard, or make the box with `ozbox create` from a computer with a keychain (`ozbox upgrade` pins that computer's key on a box that has none), then declare the command. A declaration with no secrets (plain build and test commands) is accepted now";

/// On a box with no second factor: the first name this import would REPLACE (None when enrolled, or when it only adds).
fn overwritten_before_enrolment(
    store: &EncryptedSecrets,
    project: &str,
    env: &str,
    lines: &[crate::workload::EnvLine],
) -> Option<String> {
    if store
        .exists(crate::secrets_approval::ENROLLED_MARKER)
        .unwrap_or(false)
    {
        return None;
    }
    lines.iter().find_map(|l| {
        let full = crate::secrets_enc::workload_name(project, env, &l.name).ok()?;
        let held = store.get(&full).ok().flatten()?;
        (held != *l.value).then(|| l.name.clone())
    })
}

/// The last `n` approval lines of the audit log, newest first, as plain records. The log is `<ms> approval <what> scope=..
/// project=.. env=.. via=..`; nothing else of it is read and nothing in it is a value or a code.
fn recent_approvals(store_path: &Path, n: usize) -> Vec<Value> {
    let path = store_path.with_file_name("workload-audit.log");
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let mut out = Vec::new();
    for line in text.lines().rev() {
        let mut it = line.split(' ');
        let (Some(ms), Some("approval"), Some(what)) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        let field = |k: &str| {
            line.split(' ')
                .find_map(|w| w.strip_prefix(&format!("{k}=")))
                .unwrap_or("")
                .to_string()
        };
        out.push(json!({
            "at_ms": ms.parse::<u64>().unwrap_or(0),
            "outcome": what,
            "scope": field("scope"),
            "project": field("project"),
            "env": field("env"),
            "via": field("via"),
        }));
        if out.len() >= n {
            break;
        }
    }
    out
}

/// Whether a stored value is public in fact, so the commit barrier does not look for it. Two ways in, and both still run every
/// rule of [`crate::workload_policy::public_mark_refusal`] on the value: it carries the person's public mark (sealed with the
/// value), or it sits under a name of a known public kind (`NEXT_PUBLIC_*`, `VITE_*`, ...). A Production-looking value is never
/// public, whatever it is called, and a key-shaped value under a public name stays a secret.
fn is_public_in_fact(store: &EncryptedSecrets, name: &str, value: &str) -> bool {
    // `workload.<project>.<env>.<NAME>`: the box's own rule decides whether the value looks like Production
    let mut parts = name.splitn(4, '.');
    let (env, var) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some("workload"), Some(_), Some(env), Some(var)) => (env, var),
        _ => ("", name),
    };
    if crate::workload::live_reason(var, value, env).is_some() {
        return false;
    }
    let marked = store
        .meta(name)
        .ok()
        .flatten()
        .is_some_and(|m| m.public && !m.production);
    let by_name = crate::workload_policy::is_public_kind_name(var);
    // An address with a query (`...:443?transport=tcp`) is not public by its name: it is held as a stored value, and the owner's
    // explicit decision is what lets it through.
    (marked || by_name) && crate::workload_policy::public_mark_refusal(var, value, false).is_none()
}

/// A stored value shorter than this is not looked for in a commit (ADR 0041 section 9): a region, a port or a boolean ("us-east-1",
/// "true") would hold every file that says it. It is still stored, and still redacted from output; only the barrier skips it.
pub(crate) const SCAN_FLOOR_CHARS: usize = 12;

/// The names of the stored secrets whose value appears in `text`, in any form a value is hidden in (see
/// `workload::redact`). The internal keys and the declarations are not secrets a person committed and are skipped.
pub(crate) fn scan_text(
    store: &EncryptedSecrets,
    memory: Option<&Arc<EncryptedSecrets>>,
    text: &str,
) -> Result<Vec<String>, SecretError> {
    let mut hit = Vec::new();
    let stores: Vec<&EncryptedSecrets> = std::iter::once(store)
        .chain(memory.map(|m| m.as_ref()))
        .collect();
    for (store, name) in stores.iter().flat_map(|s| {
        s.names("")
            .unwrap_or_default()
            .into_iter()
            .map(move |n| (*s, n))
    }) {
        if name == "store-kek"
            || name == "internal-hmac-keys"
            || name == crate::secrets_approval::ENROLLED_MARKER
            || crate::audit_service::is_audit_secret(&name)
            || crate::approval_key::is_reserved(&name)
            || crate::secrets_ingress::is_reserved(&name)
            || name.starts_with("workload-policy.")
        {
            continue;
        }
        if let Some(v) = store.get(&name)? {
            let v = zeroize::Zeroizing::new(v);
            if v.chars().count() < SCAN_FLOOR_CHARS {
                continue;
            }
            // a value that is public in fact is configuration, not a key (ADR 0041 section 9): a stored public URL or a
            // dictionary-word `NEXT_PUBLIC_*` value would otherwise hold every file that says it
            if is_public_in_fact(store, &name, &v) {
                continue;
            }
            if !crate::workload::hits(text, std::slice::from_ref(&v)).is_empty() {
                hit.push(name);
            }
        }
    }
    Ok(hit)
}

fn serve_one(
    store: Arc<EncryptedSecrets>,
    mac: Arc<TokenMac>,
    broker: Option<Arc<Broker>>,
    gate: Arc<IssuerGate>,
    gates: Arc<Gates>,
    policy: Policy,
    s: UnixStream,
) {
    let mut line = String::new();
    // A request is small; a longer one is refused rather than buffered. The broker's carries the provider list, the
    // import socket's a page of text to scan.
    let limit = if matches!(
        policy,
        Policy::Broker
            | Policy::BrokerLocked
            | Policy::Supervisor
            | Policy::Import
            | Policy::Ingress
            | Policy::Admin
    ) {
        crate::secrets_ingress::MAX_LINE_BYTES
    } else {
        64 * 1024
    };
    let mut rd = BufReader::new((&s).take_bounded(limit));
    if rd.read_line(&mut line).is_err() || line.is_empty() {
        return;
    }
    let audit = gates
        .audit
        .get()
        .map(|a| (a.as_ref(), store.as_ref() as &dyn SecretStore));
    let out = match (policy, &broker) {
        (Policy::Broker, Some(b)) => {
            handle_broker_with(b, &gate, BrokerAccess::Claimed, audit, line.trim_end())
        }
        (Policy::BrokerLocked, Some(b)) => {
            handle_broker_with(b, &gate, BrokerAccess::Locked, audit, line.trim_end())
        }
        (Policy::Broker | Policy::BrokerLocked, None) => {
            json!({"ok": false, "error": "that is not allowed on this socket"}).to_string()
        }
        // The supervisor's socket is its own: the broker's operations without a claim, then the rest.
        (Policy::Supervisor, Some(b)) if is_broker_op(line.trim_end()) => {
            handle_broker_with(b, &gate, BrokerAccess::Trusted, audit, line.trim_end())
        }
        _ => handle_from(&store, &mac, &gates, policy, peer_uid(&s), line.trim_end()),
    };
    let mut w = &s;
    let _ = w.write_all(out.as_bytes());
    let _ = w.write_all(b"\n");
}

/// The user the kernel says is on the other end of a connection. Linux only; elsewhere the service names no user.
#[cfg(target_os = "linux")]
fn peer_uid(s: &UnixStream) -> Option<u32> {
    rustix::net::sockopt::socket_peercred(s)
        .ok()
        .map(|c| c.uid.as_raw())
}

#[cfg(not(target_os = "linux"))]
fn peer_uid(_: &UnixStream) -> Option<u32> {
    None
}

trait TakeBounded {
    fn take_bounded(self, n: u64) -> std::io::Take<Self>
    where
        Self: Sized + std::io::Read;
}
impl<T: std::io::Read> TakeBounded for T {
    fn take_bounded(self, n: u64) -> std::io::Take<Self> {
        std::io::Read::take(self, n)
    }
}

/// Bind `path` for `policy`. The directory is made first with `dir_mode` (it is what decides who may connect), and the
/// socket is `0660` inside it, **in the directory's group**.
///
/// A socket takes the group of the process that binds it (`ozbox-secrets`), not of its directory (there is no setgid bit),
/// and connecting to a socket needs write permission on it. So a socket left in the service's own group could not be
/// reached by the box user or the supervisor at all, whatever its directory allowed. The group is set to the directory's
/// (the service holds `CAP_CHOWN` for this), and a socket whose group or mode cannot be set is not served.
pub fn listen(path: &Path, dir_mode: u32) -> std::io::Result<UnixListener> {
    use std::os::unix::fs::MetadataExt;
    let dir = path
        .parent()
        .ok_or_else(|| std::io::Error::other("a socket path needs a directory"))?;
    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(dir_mode))?;
    let dir_gid = std::fs::metadata(dir)?.gid();
    let _ = std::fs::remove_file(path);
    let l = UnixListener::bind(path)?;
    std::os::unix::fs::chown(path, None, Some(dir_gid))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    Ok(l)
}

/// The owner, group and mode of a socket: what `stat -c '%U:%G %a'` shows, as numbers.
#[cfg(test)]
pub fn socket_access(path: &Path) -> std::io::Result<(u32, u32, u32)> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::symlink_metadata(path)?;
    Ok((m.uid(), m.gid(), m.mode() & 0o7777))
}

/// Serve every listener until the process is stopped. One thread per listener, one short-lived thread per connection.
#[cfg(test)]
pub fn serve(
    store: Arc<EncryptedSecrets>,
    listeners: Vec<(UnixListener, Policy)>,
    broker: Option<Arc<Broker>>,
    memory: Option<Arc<EncryptedSecrets>>,
) {
    serve_with_audit(store, listeners, broker, memory, None);
}

/// [`serve`] with the audit chain this service writes (ADR 0028).
#[cfg(test)]
pub fn serve_with_audit(
    store: Arc<EncryptedSecrets>,
    listeners: Vec<(UnixListener, Policy)>,
    broker: Option<Arc<Broker>>,
    memory: Option<Arc<EncryptedSecrets>>,
    audit: Option<Arc<crate::audit_service::AuditCfg>>,
) {
    serve_gates(store, listeners, broker, gates_for(memory, audit));
}

/// The state the service keeps between requests, with the box's memory store and its audit chain.
pub fn gates_for(
    memory: Option<Arc<EncryptedSecrets>>,
    audit: Option<Arc<crate::audit_service::AuditCfg>>,
) -> Arc<Gates> {
    let gates = Arc::new(Gates::default());
    if let Some(m) = memory {
        let _ = gates.memory.set(m);
    }
    if let Some(a) = audit {
        let _ = gates.audit.set(a);
    }
    gates
}

/// [`serve_with_audit`] with gates made by the caller (the service applies the pinned approval key to them first).
pub fn serve_gates(
    store: Arc<EncryptedSecrets>,
    listeners: Vec<(UnixListener, Policy)>,
    broker: Option<Arc<Broker>>,
    gates: Arc<Gates>,
) {
    let mac = Arc::new(TokenMac::new(store.clone() as Arc<dyn SecretStore>));
    let gate = Arc::new(IssuerGate::default());
    let mut handles = Vec::new();
    for (l, policy) in listeners {
        let (store, mac, broker, gate, gates) = (
            store.clone(),
            mac.clone(),
            broker.clone(),
            gate.clone(),
            gates.clone(),
        );
        handles.push(std::thread::spawn(move || {
            for c in l.incoming().flatten() {
                let (store, mac, broker, gate, gates) = (
                    store.clone(),
                    mac.clone(),
                    broker.clone(),
                    gate.clone(),
                    gates.clone(),
                );
                std::thread::spawn(move || serve_one(store, mac, broker, gate, gates, policy, c));
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }
}

/// Who may issue run tokens and change the model settings: the one supervisor process (`ozbox serve`). It claims a secret
/// from the service when it starts, keeps it in its own memory only (never in a file, an argument or the environment) and
/// shows it with every request. Another process of the box user can still connect to the socket, but cannot make a
/// request that counts without that secret, and Yama keeps it from reading the supervisor's memory. The claim is held for
/// as long as the supervisor keeps proving it is alive; if it goes quiet for [`RECLAIM_AFTER_MS`] the next claimant
/// takes over, so a restarted supervisor recovers by itself. The limit: a process that can stop the supervisor and wait
/// that long can take the claim (same user). Moving the supervisor to a user of its own closes that.
#[derive(Default)]
pub struct IssuerGate {
    held: std::sync::Mutex<Option<(zeroize::Zeroizing<String>, u64)>>,
}

pub const RECLAIM_AFTER_MS: u64 = 45_000;
const CLAIM_NEEDED: &str = "a claim is needed";

impl IssuerGate {
    pub fn claim(&self, now_ms: u64) -> Result<String, String> {
        let mut g = self.held.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((_, seen)) = g.as_ref() {
            if now_ms.saturating_sub(*seen) < RECLAIM_AFTER_MS {
                return Err(
                    "the supervisor already holds this box's right to issue run tokens".into(),
                );
            }
        }
        let mut raw = [0u8; 32];
        getrandom::getrandom(&mut raw)
            .map_err(|_| "no random numbers are available".to_string())?;
        let secret = crate::serve::auth::b64::encode_url(&raw);
        *g = Some((zeroize::Zeroizing::new(secret.clone()), now_ms));
        Ok(secret)
    }

    /// Whether `proof` is the claimed secret (compared in constant time); a good proof also marks the holder alive.
    pub fn check(&self, proof: &str, now_ms: u64) -> bool {
        let mut g = self.held.lock().unwrap_or_else(|e| e.into_inner());
        match g.as_mut() {
            Some((s, seen))
                if crate::serve::auth::b64::ct_eq_bytes(s.as_bytes(), proof.as_bytes()) =>
            {
                *seen = now_ms;
                true
            }
            _ => false,
        }
    }
}

/// Answer one request on the broker socket. The broker holds the store, so a key is read here and goes only to the
/// provider; what comes back is a run token, a count or a plain result.
/// How the socket a broker request arrived on is trusted.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BrokerAccess {
    /// The box user's socket on a box with no supervisor user: spending needs the claim.
    Claimed,
    /// The same socket once the supervisor has its own: only the proxy port and the exact restic commands.
    Locked,
    /// The supervisor's own socket: the directory is the proof, so no claim is asked for.
    Trusted,
}

const BROKER_OPS: &[&str] = &[
    "claim",
    "ping",
    "port",
    "models",
    "issue",
    "revoke",
    "usage",
    "restic",
    "list_models",
    "test_connection",
];

/// Whether a request line names one of the broker's operations (the supervisor socket serves those itself).
pub fn is_broker_op(line: &str) -> bool {
    serde_json::from_str::<Value>(line)
        .ok()
        .and_then(|v| v["op"].as_str().map(|o| BROKER_OPS.contains(&o)))
        .unwrap_or(false)
}

#[cfg(test)]
pub fn handle_broker(
    broker: &Broker,
    gate: &IssuerGate,
    access: BrokerAccess,
    line: &str,
) -> String {
    handle_broker_with(broker, gate, access, None, line)
}

/// What a broker request records in the audit chain: ids, provider names and counts, never a token or a key.
type AuditSink<'a> = Option<(&'a crate::audit_service::AuditCfg, &'a dyn SecretStore)>;

pub fn handle_broker_with(
    broker: &Broker,
    gate: &IssuerGate,
    access: BrokerAccess,
    audit: AuditSink<'_>,
    line: &str,
) -> String {
    let out = handle_broker_inner(broker, gate, access, line);
    if let Some((cfg, store)) = audit {
        if let Ok(v) = serde_json::from_str::<Value>(line) {
            let ok = serde_json::from_str::<Value>(&out)
                .ok()
                .and_then(|o| o["ok"].as_bool())
                .unwrap_or(false);
            let run = v["run_id"].as_str().unwrap_or("");
            let provider = v["provider"]["id"].as_str().unwrap_or("");
            let how = match access {
                BrokerAccess::Trusted => "supervisor",
                _ => "box",
            };
            match v["op"].as_str().unwrap_or("") {
                "issue" => cfg.record(
                    store,
                    if ok {
                        "secrets.token.issued"
                    } else {
                        "secrets.token.refused"
                    },
                    run,
                    &format!("provider={provider} via={how}"),
                ),
                "revoke" if ok => {
                    cfg.record(store, "secrets.token.revoked", run, &format!("via={how}"))
                }
                "claim" => cfg.record(
                    store,
                    if ok {
                        "secrets.claim.granted"
                    } else {
                        "secrets.claim.refused"
                    },
                    "",
                    &format!("via={how}"),
                ),
                "restic" if ok => cfg.record(
                    store,
                    "secrets.restic",
                    v["args"][0].as_str().unwrap_or(""),
                    "",
                ),
                _ => {}
            }
        }
    }
    out
}

fn handle_broker_inner(
    broker: &Broker,
    gate: &IssuerGate,
    access: BrokerAccess,
    line: &str,
) -> String {
    let v: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(_) => return json!({"ok": false, "error": "that request is not valid"}).to_string(),
    };
    let fail = |e: &str| json!({"ok": false, "error": e}).to_string();
    let provider = || serde_json::from_value::<ModelProvider>(v["provider"].clone()).ok();
    let op = v["op"].as_str().unwrap_or("");
    let now = crate::serve::unix_ms();
    if access == BrokerAccess::Locked && !matches!(op, "port" | "restic") {
        return fail("that is not allowed on this socket");
    }
    if op == "claim" {
        // On the supervisor's own socket there is nothing to prove: say so, and let it carry on.
        if access == BrokerAccess::Trusted {
            return json!({"ok": true, "proof": "supervisor"}).to_string();
        }
        return match gate.claim(now) {
            Ok(p) => json!({"ok": true, "proof": p}).to_string(),
            Err(e) => fail(&e),
        };
    }
    // what spends money or changes who is paid is the supervisor's alone
    if access != BrokerAccess::Trusted
        && matches!(op, "ping" | "models" | "issue" | "revoke" | "usage")
        && !gate.check(v["proof"].as_str().unwrap_or(""), now)
    {
        return fail(CLAIM_NEEDED);
    }
    match op {
        "ping" => json!({"ok": true}).to_string(),
        "port" => json!({"ok": true, "port": broker.port()}).to_string(),
        "models" => match serde_json::from_value::<ModelsConfig>(v["models"].clone()) {
            Ok(m) => {
                broker.set_models(&m);
                json!({"ok": true}).to_string()
            }
            Err(_) => fail("that request is not valid"),
        },
        "issue" => {
            let (Some(p), Some(run)) = (provider(), v["run_id"].as_str()) else {
                return fail("that request is not valid");
            };
            let cap = v["cap_micros"].as_u64();
            let now = v["now_ms"].as_u64().unwrap_or_else(crate::serve::unix_ms);
            // the provider the run will use is the one the broker will find at request time
            broker.upsert_provider(&p);
            match broker.issue(run, &p, cap, now) {
                Ok(IssuedToken { token, base_url }) => {
                    json!({"ok": true, "token": token, "base_url": base_url}).to_string()
                }
                Err(e) => fail(&e),
            }
        }
        "revoke" => match v["run_id"].as_str() {
            Some(r) => {
                broker.revoke_run(r);
                json!({"ok": true}).to_string()
            }
            None => fail("that request is not valid"),
        },
        "usage" => match v["run_id"].as_str() {
            Some(r) => {
                let rows: Vec<Value> = broker
                    .drain_usage(r)
                    .into_iter()
                    .map(|u| {
                        json!({"run_id": u.run_id, "provider_id": u.provider_id, "model": u.model,
                            "input": u.input_tokens, "output": u.output_tokens, "cached": u.cached_input_tokens})
                    })
                    .collect();
                json!({"ok": true, "usage": rows}).to_string()
            }
            None => fail("that request is not valid"),
        },
        // One of the few exact restic commands the box daemon runs, with the credentials opened here (see secrets_restic).
        "restic" => {
            let args: Vec<String> = v["args"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            let bin = std::env::var("OZBOX_RESTIC_BIN").unwrap_or_else(|_| "restic".into());
            let cache = std::env::var("OZBOX_RESTIC_CACHE")
                .unwrap_or_else(|_| "/var/lib/ozbox-secrets/restic-cache".into());
            // an optional bound on how long restic may run (the daemon's repository check sets one; a backup does not)
            let timeout = v["timeout_secs"]
                .as_u64()
                .map(|s| std::time::Duration::from_secs(s.clamp(1, 900)));
            match crate::secrets_restic::run(
                broker.secrets().as_ref(),
                &bin,
                &cache,
                &args,
                timeout,
            ) {
                Ok(o) => json!({"ok": true, "status": o.status, "stdout": o.stdout}).to_string(),
                Err(e) => fail(&e),
            }
        }
        op @ ("list_models" | "test_connection") => {
            let Some(p) = provider() else {
                return fail("that request is not valid");
            };
            if let Err(e) = broker.endpoint_ok(&p) {
                return fail(&e);
            }
            let secrets = broker.secrets();
            let out = if op == "list_models" {
                crate::models::list_models(&UreqClient, secrets.as_ref(), &p)
                    .and_then(|r| serde_json::to_value(r).map_err(|e| e.to_string()))
            } else {
                let model = v["model"].as_str().unwrap_or("");
                crate::models::test_connection(&UreqClient, secrets.as_ref(), &p, model)
                    .and_then(|r| serde_json::to_value(r).map_err(|e| e.to_string()))
            };
            match out {
                Ok(r) => json!({"ok": true, "result": r}).to_string(),
                Err(e) => fail(&e),
            }
        }
        _ => fail("that is not allowed on this socket"),
    }
}

/// The run side's view of the broker that lives in the secrets service. Holding it gives the right to ask for a run
/// token (it claims that right from the service and keeps proving it); the key itself is out of reach.
pub struct RemoteBroker {
    shared: Arc<Shared>,
}

struct Shared {
    path: PathBuf,
    port: std::sync::Mutex<Option<u16>>,
    proof: std::sync::Mutex<Option<zeroize::Zeroizing<String>>>,
}

impl Shared {
    fn proof(&self) -> Result<zeroize::Zeroizing<String>, String> {
        let mut g = self.proof.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(p) = g.as_ref() {
            return Ok(p.clone());
        }
        let v = ask(&self.path, &json!({"op": "claim"}))?;
        let p = zeroize::Zeroizing::new(v["proof"].as_str().unwrap_or("").to_string());
        *g = Some(p.clone());
        Ok(p)
    }

    /// A request that needs the claim. If the service lost it (it restarted, or reassigned it), claim again once.
    fn proved(&self, mut req: Value) -> Result<Value, String> {
        for attempt in 0..2 {
            req["proof"] = json!(self.proof()?.as_str());
            match ask(&self.path, &req) {
                Err(e) if e == CLAIM_NEEDED && attempt == 0 => {
                    *self.proof.lock().unwrap_or_else(|e| e.into_inner()) = None;
                }
                r => return r,
            }
        }
        Err("the box's credential broker did not accept this supervisor".into())
    }
}

fn ask(path: &Path, req: &Value) -> Result<Value, String> {
    let down = || "the box's credential broker is not reachable".to_string();
    let mut s = UnixStream::connect(path).map_err(|_| down())?;
    s.set_read_timeout(Some(std::time::Duration::from_secs(60)))
        .ok();
    s.write_all(format!("{req}\n").as_bytes())
        .map_err(|_| down())?;
    let mut line = String::new();
    BufReader::new(&s)
        .read_line(&mut line)
        .map_err(|_| down())?;
    let v: Value = serde_json::from_str(&line).map_err(|_| down())?;
    if v["ok"].as_bool() == Some(true) {
        Ok(v)
    } else {
        Err(v["error"]
            .as_str()
            .unwrap_or("the request was refused")
            .to_string())
    }
}

/// One request line to a socket and the answer line as it came, whatever it says (`ok` true or false). For the ingress
/// account's forced command, which hands the owner's computer the service's own words, code included.
pub fn ask_raw(path: &Path, line: &str) -> Result<String, String> {
    let down = || "the box's secrets service is not reachable".to_string();
    let mut s = UnixStream::connect(path).map_err(|_| down())?;
    s.set_read_timeout(Some(std::time::Duration::from_secs(60)))
        .ok();
    s.write_all(line.trim_end().as_bytes())
        .map_err(|_| down())?;
    s.write_all(b"\n").map_err(|_| down())?;
    let mut out = String::new();
    BufReader::new((&s).take_bounded(1 << 20))
        .read_line(&mut out)
        .map_err(|_| down())?;
    if out.is_empty() {
        return Err(down());
    }
    Ok(out.trim_end().to_string())
}

/// The broker of this box's secrets service, when this process is configured to reach it (the dashboard's unit sets
/// `OZBOX_SECRET_STORE=socket`).
pub fn remote_broker_from_env() -> Option<RemoteBroker> {
    if std::env::var("OZBOX_SECRET_STORE").ok().as_deref() != Some("socket") {
        return None;
    }
    let box_socket = std::env::var("OZBOX_SECRET_SOCKET").ok()?;
    Some(RemoteBroker::new(
        SocketSecrets::new(PathBuf::from(box_socket)).broker_socket(),
    ))
}

impl RemoteBroker {
    pub fn new(path: PathBuf) -> Self {
        let shared = Arc::new(Shared {
            path,
            port: std::sync::Mutex::new(None),
            proof: std::sync::Mutex::new(None),
        });
        // Claim at start, then keep showing the holder is alive, so a restart of the service or of this process recovers.
        let weak = Arc::downgrade(&shared);
        std::thread::spawn(move || loop {
            let Some(sh) = weak.upgrade() else { return };
            let _ = sh.proved(json!({"op": "ping"}));
            drop(sh);
            std::thread::sleep(std::time::Duration::from_secs(RECLAIM_AFTER_MS / 3000));
        });
        Self { shared }
    }
}

impl RunBroker for RemoteBroker {
    fn port(&self) -> u16 {
        let mut g = self.shared.port.lock().unwrap_or_else(|e| e.into_inner());
        if g.is_none() {
            *g = ask(&self.shared.path, &json!({"op": "port"}))
                .ok()
                .and_then(|v| v["port"].as_u64())
                .and_then(|p| u16::try_from(p).ok());
        }
        g.unwrap_or(0)
    }
    fn set_models(&self, cfg: &ModelsConfig) {
        let _ = self.shared.proved(json!({"op": "models", "models": cfg}));
    }
    fn issue(
        &self,
        run_id: &str,
        provider: &ModelProvider,
        cap_micros: Option<u64>,
        now_ms: u64,
    ) -> Result<IssuedToken, String> {
        let v = self.shared.proved(
            json!({"op": "issue", "run_id": run_id, "provider": provider,
                "cap_micros": cap_micros, "now_ms": now_ms}),
        )?;
        let (Some(token), Some(base_url)) = (v["token"].as_str(), v["base_url"].as_str()) else {
            return Err("the box's credential broker answered badly".into());
        };
        Ok(IssuedToken {
            token: token.to_string(),
            base_url: base_url.to_string(),
        })
    }
    fn revoke_run(&self, run_id: &str) {
        let _ = self
            .shared
            .proved(json!({"op": "revoke", "run_id": run_id}));
    }
    fn drain_usage(&self, run_id: &str) -> Vec<BrokerUsage> {
        let Ok(v) = self.shared.proved(json!({"op": "usage", "run_id": run_id})) else {
            return Vec::new();
        };
        v["usage"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .map(|u| BrokerUsage {
                run_id: u["run_id"].as_str().unwrap_or_default().to_string(),
                provider_id: u["provider_id"].as_str().unwrap_or_default().to_string(),
                model: u["model"].as_str().unwrap_or_default().to_string(),
                input_tokens: u["input"].as_u64().unwrap_or(0),
                output_tokens: u["output"].as_u64().unwrap_or(0),
                cached_input_tokens: u["cached"].as_u64().unwrap_or(0),
            })
            .collect()
    }
}

/// A `SecretStore` that talks to the service's box socket. Holding it gives only what that socket allows.
pub struct SocketSecrets {
    path: PathBuf,
    /// Where the free checks and the supervisor's own operations go, when it is not found from the environment.
    probe_path: Option<PathBuf>,
}

impl SocketSecrets {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            probe_path: None,
        }
    }

    /// A client of the supervisor's own socket, which serves the box socket's operations and the broker's both (and
    /// approvals), so every call goes to the one path with nothing taken from the environment.
    pub fn supervisor(path: PathBuf) -> Self {
        Self {
            probe_path: Some(path.clone()),
            path,
        }
    }

    /// The broker's socket: `OZBOX_BROKER_SOCKET`, else the `broker` directory beside the box socket's own.
    pub fn broker_socket(&self) -> PathBuf {
        if let Some(p) = &self.probe_path {
            return p.clone();
        }
        match std::env::var("OZBOX_BROKER_SOCKET") {
            Ok(p) if !p.is_empty() => PathBuf::from(p),
            _ => self
                .path
                .parent()
                .and_then(Path::parent)
                .map(|d| d.join("broker/broker.sock"))
                .unwrap_or_else(|| PathBuf::from("/run/ozbox-secrets/broker/broker.sock")),
        }
    }

    /// The supervisor's socket, when this process is the supervisor (the unit sets `OZBOX_SUPERVISOR_SOCKET`).
    fn supervisor_socket() -> Option<PathBuf> {
        std::env::var("OZBOX_SUPERVISOR_SOCKET")
            .ok()
            .filter(|p| !p.is_empty())
            .map(PathBuf::from)
    }

    /// An approval for the root helper's tunnel-token change, from the supervisor's own socket, bound to `binding` (the digest
    /// of the token being stored, or empty for a removal). `None` for any other caller.
    fn mint_tunnel_approval(&self, which: &str, binding: &str) -> Option<String> {
        let sock = self.probe_path.clone().or_else(Self::supervisor_socket)?;
        ask(
            &sock,
            &json!({"op": "approve_mint", "scope": "tunnel-token", "project": which, "env": binding}),
        )
        .ok()
        .and_then(|v| v["value"].as_str().map(str::to_string))
    }

    pub(crate) fn call(&self, req: Value) -> Result<Value, SecretError> {
        // only a connection that could not be made at all (no socket, nothing listening) is "down"; everything after it, and a
        // connect that fails for any other reason, is a service that did not answer
        let silent = || SecretError(SERVICE_NO_ANSWER.into());
        let mut s = UnixStream::connect(&self.path).map_err(|e| {
            if connect_means_down(e.kind()) {
                SecretError(SERVICE_DOWN.into())
            } else {
                silent()
            }
        })?;
        s.set_read_timeout(Some(std::time::Duration::from_secs(20)))
            .ok();
        s.write_all(format!("{req}\n").as_bytes())
            .map_err(|_| silent())?;
        let mut line = String::new();
        BufReader::new(&s)
            .read_line(&mut line)
            .map_err(|_| silent())?;
        let v: Value = serde_json::from_str(&line).map_err(|_| silent())?;
        if v["ok"].as_bool() == Some(true) {
            Ok(v)
        } else {
            Err(SecretError(
                v["error"]
                    .as_str()
                    .unwrap_or("the request was refused")
                    .to_string(),
            ))
        }
    }
}

/// Whether a failed `connect` means nobody is there: the socket file is missing (`ENOENT`) or nothing is listening on it
/// (`ECONNREFUSED`). A refusal of this user (`EACCES`), a full backlog and the rest are not an outage.
pub(crate) fn connect_means_down(kind: std::io::ErrorKind) -> bool {
    matches!(
        kind,
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
    )
}

/// An approval code a person brought for the next tunnel-token change (`ozbox tunnel setup --approval`, or the dashboard
/// installer's `--approval`): signed by the key their computer pinned (`ozbox secrets approve --scope tunnel-token`), single
/// use, and spent by the box's secrets service. It is taken once, so a second change in the same process asks again.
static GIVEN_TUNNEL_APPROVAL: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Hold an approval code for the next tunnel-token change this process makes.
pub fn give_tunnel_approval(code: &str) {
    if let Ok(mut g) = GIVEN_TUNNEL_APPROVAL.lock() {
        // one canonical word (`XXXX-XXXX-XXXX-XXXX`), so a code typed with spaces or in lower case is not several words in the
        // helper's request line
        *g =
            Some(crate::secrets_approval::canonical_code(code).unwrap_or_else(|| code.to_string()));
    }
}

fn take_given_tunnel_approval() -> Option<String> {
    GIVEN_TUNNEL_APPROVAL.lock().ok().and_then(|mut g| g.take())
}

/// The flag by which `ozbox-admin-request` reads an approval code from standard input instead of an argument.
pub const APPROVAL_STDIN_FLAG: &str = "--approval-stdin";

/// Whether this box's request program knows [`APPROVAL_STDIN_FLAG`] (a program from an older image does not, and would take
/// the flag for an action name). Read from the program's own text, which is a plain script on the box.
fn request_helper_reads_code_on_stdin(helper: &str) -> bool {
    std::fs::read(helper)
        .map(|b| String::from_utf8_lossy(&b).contains(APPROVAL_STDIN_FLAG))
        .unwrap_or(false)
}

/// The reason the root helper gave, from its answer (`status=…` then the action's own lines): the first `error:` line, else
/// the last line that is not the status. The helper never prints the token (it reads it from a file and only says whether
/// the store took it), and the result is cut to one short line, so it is safe to show.
fn helper_reason(out: &str) -> Option<String> {
    let lines: Vec<&str> = out
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("status="))
        .collect();
    let pick = lines
        .iter()
        .find(|l| l.starts_with("error:"))
        .or_else(|| lines.last())?;
    let reason = pick.trim_start_matches("error:").trim();
    (!reason.is_empty()).then(|| reason.chars().take(300).collect())
}

/// A tunnel token is stored and removed through the root helper's admin action (see `box_may_write`). The token goes in a
/// private file of the box user that the helper reads once and removes; the request line carries only words.
fn admin_tunnel(svc: &SocketSecrets, name: &str, value: Option<&str>) -> Result<(), SecretError> {
    let dir = std::env::var("OZBOX_ADMIN_DIR").unwrap_or_else(|_| "/run/ozbox-admin".into());
    let helper = std::env::var("OZBOX_ADMIN_REQUEST")
        .unwrap_or_else(|_| "/usr/local/bin/ozbox-admin-request".into());
    admin_tunnel_with(svc, name, value, &dir, &helper)
}

fn admin_tunnel_with(
    svc: &SocketSecrets,
    name: &str,
    value: Option<&str>,
    dir: &str,
    helper: &str,
) -> Result<(), SecretError> {
    use std::os::unix::fs::OpenOptionsExt;
    let which = name.strip_prefix("tunnel-token-").unwrap_or("");
    if which.is_empty()
        || !which
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return Err(SecretError("that is not a tunnel token".into()));
    }
    // The supervisor has checked a fresh passkey or authenticator code before it gets here, so it asks for its own approval;
    // anyone else has none of its own, so it uses one the person brought (`--approval`), and the helper refuses a change
    // with neither once a second factor exists. The approval is for THIS token: its digest is signed into the code, and the
    // root helper reads the token itself, hashes it, and only then asks the gate (see ozbox-admin.sh).
    let binding = value
        .map(crate::secrets_approval::tunnel_token_binding)
        .unwrap_or_default();
    let approval = svc
        .mint_tunnel_approval(which, &binding)
        .or_else(take_given_tunnel_approval);
    let mut cmd = Command::new(helper);
    // The code goes on standard input, never in this process's arguments or environment (the box user can list both). A
    // helper from before the flag existed takes it as an argument; that is the only case the argument is used.
    let code_on_stdin = approval.is_some() && request_helper_reads_code_on_stdin(helper);
    if code_on_stdin {
        cmd.arg(APPROVAL_STDIN_FLAG);
    }
    let mut file = None;
    match value {
        Some(v) => {
            let mut raw = [0u8; 8];
            getrandom::getrandom(&mut raw)
                .map_err(|_| SecretError("no random numbers are available".into()))?;
            let id: String = raw.iter().map(|b| format!("{b:02x}")).collect();
            let path = PathBuf::from(dir)
                .join("requests")
                .join(format!("{id}.tok"));
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .and_then(|mut f| f.write_all(v.as_bytes()))
                .map_err(|_| SecretError("the box's admin helper is not reachable".into()))?;
            file = Some(path);
            cmd.args(["replace-tunnel-token", which, &id]);
        }
        None => {
            cmd.args(["clear-tunnel-token", which]);
        }
    }
    if let (Some(code), false) = (&approval, code_on_stdin) {
        cmd.arg(code);
    }
    cmd.env("OZBOX_ADMIN_DIR", dir)
        .stdin(if code_on_stdin {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        })
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let out = cmd.spawn().and_then(|mut child| {
        if let (true, Some(code), Some(mut stdin)) = (code_on_stdin, &approval, child.stdin.take())
        {
            let _ = stdin.write_all(format!("{code}\n").as_bytes());
        }
        child.wait_with_output()
    });
    if let Some(f) = file {
        let _ = std::fs::remove_file(f);
    }
    match out {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => {
            let text = format!(
                "{}\n{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            );
            Err(SecretError(match helper_reason(&text) {
                Some(r) => format!("the box's admin helper did not take the tunnel token: {r}"),
                None => "the box's admin helper did not take the tunnel token".into(),
            }))
        }
        Err(_) => Err(SecretError(
            "the box's admin helper did not take the tunnel token".into(),
        )),
    }
}

impl SecretStore for SocketSecrets {
    fn set(&self, name: &str, value: &str) -> Result<(), SecretError> {
        crate::secrets::check_value(value)?;
        if !box_may_write(name) {
            return admin_tunnel(self, name, Some(value));
        }
        self.call(json!({"op": "set", "name": name, "value": value}))
            .map(|_| ())
    }
    fn set_exact(&self, name: &str, value: &str) -> Result<(), SecretError> {
        if crate::secrets::check_value(value).is_ok() {
            return self.set(name, value);
        }
        if !box_may_write(name) {
            // a tunnel token and the like keep the strict rule: a script reads them
            return Err(SecretError(
                "that value cannot be stored under that name".into(),
            ));
        }
        self.call(json!({"op": "set", "name": name, "value_b64": encode_std(value.as_bytes())}))
            .map(|_| ())
    }
    fn get(&self, name: &str) -> Result<Option<String>, SecretError> {
        Ok(self.call(json!({"op": "get", "name": name}))?["value"]
            .as_str()
            .map(str::to_string))
    }
    fn exists(&self, name: &str) -> Result<bool, SecretError> {
        Ok(self.call(json!({"op": "exists", "name": name}))?["flag"].as_bool() == Some(true))
    }
    fn delete(&self, name: &str) -> Result<(), SecretError> {
        if !box_may_write(name) {
            return admin_tunnel(self, name, None);
        }
        self.call(json!({"op": "delete", "name": name})).map(|_| ())
    }
    fn gates_replacement(&self) -> bool {
        true
    }
    fn label(&self) -> &'static str {
        "the secrets service on this box"
    }
    /// A model key is not readable here, so the free provider checks run where the key is.
    fn probe(&self, op: &str, args: &Value) -> Option<Result<Value, SecretError>> {
        let mut req = args.clone();
        req["op"] = json!(op);
        // the approval requests are decided on the supervisor's socket, which is not the broker's
        let path = if op.starts_with("areq_") || op.starts_with("approval_") {
            Self::supervisor_socket().unwrap_or_else(|| self.broker_socket())
        } else {
            self.broker_socket()
        };
        Some(
            ask(&path, &req)
                .map(|v| {
                    if v.get("result").is_some() {
                        v["result"].clone()
                    } else {
                        json!({"value": v["value"], "flag": v["flag"]})
                    }
                })
                .map_err(SecretError),
        )
    }
    fn mac_tags(&self, msg: &[u8]) -> Result<Option<Vec<[u8; 32]>>, SecretError> {
        let v = self.call(json!({"op": "mac", "msg": encode_std(msg)}))?;
        let mut out = Vec::new();
        for t in v["tags"].as_array().cloned().unwrap_or_default() {
            let hex = t.as_str().unwrap_or("");
            let mut a = [0u8; 32];
            if hex.len() != 64 {
                return Err(SecretError("the secrets service answered badly".into()));
            }
            for (i, b) in a.iter_mut().enumerate() {
                *b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16)
                    .map_err(|_| SecretError("the secrets service answered badly".into()))?;
            }
            out.push(a);
        }
        Ok(Some(out))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::secrets_enc::{KeyProvider, LocalKekProvider};

    const SENTINEL: &str = "SENTINEL-sk-live-0123456789abcdef";

    fn svc(dir: &Path) -> (Arc<EncryptedSecrets>, Arc<TokenMac>) {
        let p: Arc<dyn KeyProvider> = Arc::new(LocalKekProvider::random("local").unwrap());
        let s = Arc::new(EncryptedSecrets::new(dir.join("s.json"), "box-a", p).unwrap());
        let m = Arc::new(TokenMac::new(s.clone() as Arc<dyn SecretStore>));
        (s, m)
    }

    /// A box that has a second factor enrolled (what the resolve op and a secret declaration need).
    fn svc_enrolled(dir: &Path) -> (Arc<EncryptedSecrets>, Arc<TokenMac>) {
        let (s, m) = svc(dir);
        s.set(crate::secrets_approval::ENROLLED_MARKER, "1")
            .unwrap();
        (s, m)
    }

    /// A declaration whose one command receives a secret and meets every rule (a pinned file, an environment).
    fn secret_decl(cmd: &str) -> String {
        format!(
            r#"{{"dir":"/work/projects/app","commands":{{"{cmd}":{{"allow":["API_KEY"],"env":["API_KEY"],"argv":["node","t.mjs"],"envs":["staging"],"pin":[{{"file":"t.mjs","sha256":"{}"}}]}}}}}}"#,
            "a".repeat(64)
        )
    }

    fn ask(s: &EncryptedSecrets, m: &TokenMac, p: Policy, v: Value) -> Value {
        serde_json::from_str(&handle(s, m, p, &v.to_string())).unwrap()
    }

    #[test]
    fn the_box_socket_can_write_but_not_read_back_high_value_secrets() {
        let d = tempfile::tempdir().unwrap();
        let (s, m) = svc(d.path());
        for n in [
            "tunnel-token-cloudflare",
            "restic-password",
            "ide-password-dev",
            "store-kek",
            "internal-hmac-keys",
        ] {
            assert!(
                ask(
                    &s,
                    &m,
                    Policy::Box,
                    json!({"op":"set","name":n,"value":SENTINEL})
                )["ok"]
                    .as_bool()
                    == Some(true)
                    || n == "store-kek"
                    || n == "internal-hmac-keys"
                    || n == "tunnel-token-cloudflare"
            );
            let r = ask(&s, &m, Policy::Box, json!({"op":"get","name":n}));
            assert_eq!(r["ok"], false, "{n}");
            assert!(!r.to_string().contains(SENTINEL));
        }
        // a tunnel token cannot be replaced or removed over the box socket at all: that goes through the root helper
        for op in ["set", "delete"] {
            let r = ask(
                &s,
                &m,
                Policy::Box,
                json!({"op":op,"name":"tunnel-token-ide","value":SENTINEL}),
            );
            assert_eq!(r["ok"], false, "{op}");
        }
        assert!(!s.exists("tunnel-token-ide").unwrap());
        // the dashboard's own send keys may be read back for now
        s.set("telegram-bot-token", SENTINEL).unwrap();
        assert_eq!(
            ask(
                &s,
                &m,
                Policy::Box,
                json!({"op":"get","name":"telegram-bot-token"})
            )["value"],
            SENTINEL
        );
        // and the existence check never carries a value
        let e = ask(
            &s,
            &m,
            Policy::Box,
            json!({"op":"exists","name":"restic-password"}),
        );
        assert_eq!(e["flag"], true);
        assert!(!e.to_string().contains(SENTINEL));
    }

    #[test]
    fn the_box_socket_never_touches_workload_secrets_and_the_runner_resolves_by_allow_list() {
        let d = tempfile::tempdir().unwrap();
        let (s, m) = svc_enrolled(d.path());
        let n = crate::secrets_enc::workload_name("app", "staging", "API_KEY").unwrap();
        s.set(&n, SENTINEL).unwrap();
        assert_eq!(
            ask(&s, &m, Policy::Box, json!({"op":"get","name":n}))["ok"],
            false
        );
        assert_eq!(
            ask(
                &s,
                &m,
                Policy::Box,
                json!({"op":"set","name":n,"value":"x"})
            )["ok"],
            false
        );
        assert_eq!(
            ask(&s, &m, Policy::Box, json!({"op":"delete","name":n}))["ok"],
            false
        );
        assert!(
            !ask(&s, &m, Policy::Box, json!({"op":"names","prefix":""}))["names"]
                .to_string()
                .contains("workload.")
        );
        let r = ask(
            &s,
            &m,
            Policy::Runner,
            json!({"op":"resolve","project":"app","env":"staging","text":"{{secret:API_KEY}}","allowed":["API_KEY"]}),
        );
        assert_eq!(r["value"], SENTINEL);
        let r = ask(
            &s,
            &m,
            Policy::Runner,
            json!({"op":"resolve","project":"app","env":"staging","text":"{{secret:API_KEY}}","allowed":[]}),
        );
        assert_eq!(r["ok"], false);
        // the runner socket has nothing else
        assert_eq!(
            ask(&s, &m, Policy::Runner, json!({"op":"get","name":n}))["ok"],
            false
        );
        assert_eq!(
            ask(
                &s,
                &m,
                Policy::Runner,
                json!({"op":"set","name":"x","value":"y"})
            )["ok"],
            false
        );
    }

    #[test]
    fn mac_answers_with_tags_and_never_the_keys() {
        let d = tempfile::tempdir().unwrap();
        let (s, m) = svc(d.path());
        let r = ask(
            &s,
            &m,
            Policy::Box,
            json!({"op":"mac","msg": encode_std(b"token")}),
        );
        assert_eq!(r["tags"].as_array().unwrap().len(), 1);
        let keys = s.get(crate::tokenmac::KEYS_SECRET).unwrap().unwrap();
        assert!(!r.to_string().contains(keys.split('.').nth(2).unwrap()));
        assert_eq!(
            ask(
                &s,
                &m,
                Policy::Box,
                json!({"op":"get","name":"internal-hmac-keys"})
            )["ok"],
            false
        );
    }

    /// A socket must be in its directory's group, or the box user (and the supervisor) cannot connect to it at all: a
    /// socket takes the binder's group, and connecting needs write permission on the socket itself.
    #[test]
    fn a_socket_takes_its_directorys_group_so_the_users_the_directory_admits_can_connect() {
        use std::os::unix::fs::MetadataExt;
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("box");
        std::fs::create_dir_all(&dir).unwrap();
        // a group this user is in other than its own primary one, when it has one: the case the bug hid
        let groups = std::process::Command::new("id").arg("-G").output().unwrap();
        let primary = std::fs::metadata(d.path()).unwrap().gid();
        let other = String::from_utf8_lossy(&groups.stdout)
            .split_whitespace()
            .filter_map(|g| g.parse::<u32>().ok())
            .find(|g| *g != primary);
        if let Some(g) = other {
            std::os::unix::fs::chown(&dir, None, Some(g)).unwrap();
        }
        let want = std::fs::metadata(&dir).unwrap().gid();
        let sock = dir.join("box.sock");
        let _l = listen(&sock, 0o750).unwrap();
        let (_, gid, mode) = socket_access(&sock).unwrap();
        assert_eq!(gid, want, "the socket is in the directory's group");
        assert_eq!(mode & 0o777, 0o660);
    }

    #[test]
    fn a_socket_round_trip_works_and_the_directory_decides_who_can_connect() {
        let d = tempfile::tempdir().unwrap();
        let (s, _m) = svc(d.path());
        let sock = d.path().join("run/box.sock");
        let l = listen(&sock, 0o750).unwrap();
        let mode = std::fs::metadata(sock.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o750);
        std::thread::spawn(move || serve(s, vec![(l, Policy::Box)], None, None));
        let c = SocketSecrets::new(sock);
        c.set("telegram-bot-token", SENTINEL).unwrap();
        assert!(c.exists("telegram-bot-token").unwrap());
        assert_eq!(
            c.get("telegram-bot-token").unwrap().as_deref(),
            Some(SENTINEL)
        );
        c.set("restic-password", "pw-12345678").unwrap();
        assert!(c.get("restic-password").is_err());
        assert_eq!(c.mac_tags(b"x").unwrap().unwrap().len(), 1);
        c.delete("telegram-bot-token").unwrap();
        assert!(SocketSecrets::new(d.path().join("none.sock"))
            .get("a")
            .is_err());
    }

    /// Only a connection that could not be made at all is "down" (the one failure the commit hooks degrade for); a service that
    /// accepts and then says nothing useful, or a socket that refuses this user, "did not answer" and holds the change.
    #[test]
    fn only_a_failed_connection_is_down_everything_after_it_did_not_answer() {
        use std::os::unix::net::UnixListener;
        let d = tempfile::tempdir().unwrap();
        // no socket file: down
        let none = SocketSecrets::new(d.path().join("none.sock"));
        assert_eq!(none.call(json!({"op": "x"})).unwrap_err().0, SERVICE_DOWN);
        // a socket file nothing listens on (ECONNREFUSED): down
        let stale = d.path().join("stale.sock");
        drop(UnixListener::bind(&stale).unwrap());
        assert_eq!(
            SocketSecrets::new(stale)
                .call(json!({"op": "x"}))
                .unwrap_err()
                .0,
            SERVICE_DOWN
        );
        // a service that accepts and hangs up, and one that answers with something that is not a reply: did not answer
        for reply in [None, Some("this is not json\n")] {
            let sock = d.path().join(format!("r{}.sock", reply.is_some()));
            let l = UnixListener::bind(&sock).unwrap();
            std::thread::spawn(move || {
                if let Ok((mut c, _)) = l.accept() {
                    let mut line = String::new();
                    let _ = BufReader::new(&c).read_line(&mut line);
                    if let Some(r) = reply {
                        let _ = c.write_all(r.as_bytes());
                    }
                }
            });
            assert_eq!(
                SocketSecrets::new(sock)
                    .call(json!({"op": "x"}))
                    .unwrap_err()
                    .0,
                SERVICE_NO_ANSWER
            );
        }
        // a socket that refuses this user (EACCES): not an outage either
        use std::os::unix::fs::PermissionsExt;
        let locked = d.path().join("locked.sock");
        let _l = UnixListener::bind(&locked).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::metadata(&locked).is_ok()
            && UnixStream::connect(&locked)
                .err()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied)
        {
            assert_eq!(
                SocketSecrets::new(locked)
                    .call(json!({"op": "x"}))
                    .unwrap_err()
                    .0,
                SERVICE_NO_ANSWER
            );
        }
        assert!(connect_means_down(std::io::ErrorKind::NotFound));
        assert!(connect_means_down(std::io::ErrorKind::ConnectionRefused));
        assert!(!connect_means_down(std::io::ErrorKind::PermissionDenied));
        assert!(!connect_means_down(std::io::ErrorKind::WouldBlock));
        assert!(!connect_means_down(std::io::ErrorKind::TimedOut));
    }

    /// The box socket store with every hostile value: stored through the admin socket as base64 and read back exactly;
    /// the box's own socket keeps the plain rule; an import carries `value_b64`; a runner resolves an environment value
    /// exactly and a command-line reference only when it is plain.
    /// The laptop's list of sealed operations and the box's are one constant, and the box answers every one of them under the
    /// policy a sealed request is opened with: none is a word the service does not know. (An operation the list names but the
    /// service does not handle would be one the laptop sends and the box refuses.)
    #[test]
    fn every_sealed_operation_is_one_the_service_answers_after_opening() {
        let d = tempfile::tempdir().unwrap();
        let (s, m) = svc(d.path());
        for op in crate::secrets_ingress::SEALED_OPS {
            let out = handle(&s, &m, Policy::Unsealed, &json!({"op": op}).to_string());
            assert!(
                !out.contains("not allowed on this socket") && !out.contains("unknown"),
                "{op}: {out}"
            );
        }
        let out = handle(
            &s,
            &m,
            Policy::Unsealed,
            &json!({"op": "set", "name": "x", "value": "y"}).to_string(),
        );
        assert!(
            out.contains("not allowed") || out.contains("\"ok\":false"),
            "{out}"
        );
    }

    #[test]
    fn the_box_socket_carries_any_value_exactly_and_only_where_it_is_meant_to() {
        let d = tempfile::tempdir().unwrap();
        let (s, m) = svc(d.path());
        let admin = d.path().join("admin/a.sock");
        let boxs = d.path().join("box/b.sock");
        let (la, lb) = (
            listen(&admin, 0o750).unwrap(),
            listen(&boxs, 0o750).unwrap(),
        );
        let s2 = s.clone();
        std::thread::spawn(move || {
            serve(s2, vec![(la, Policy::Admin), (lb, Policy::Box)], None, None)
        });
        let (ca, cb) = (SocketSecrets::new(admin), SocketSecrets::new(boxs));
        for (i, v) in crate::secrets_enc::hostile::values().iter().enumerate() {
            ca.set_exact("restic-env", v).unwrap();
            assert_eq!(
                ca.get("restic-env").unwrap().as_deref(),
                Some(v.as_str()),
                "{i}"
            );
            // the box's own socket does not take an encoded value, and stores nothing
            if crate::secrets::check_value(v).is_err() {
                assert!(cb.set_exact("telegram-bot-token", v).is_err(), "{i}");
                assert!(cb.set("telegram-bot-token", v).is_err());
            }
        }
        assert!(cb.get("telegram-bot-token").unwrap().is_none());
        // a tunnel token keeps the strict rule on every socket
        assert!(ca.set_exact("tunnel-token-ide", "has space").is_err());
        // an import: value_b64 for the encoded, value for the plain; the receiver decides again what each is
        let vals = crate::secrets_enc::hostile::values();
        let lines: Vec<Value> = vals
            .iter()
            .enumerate()
            .map(|(i, v)| {
                if crate::secrets::check_value(v).is_err() {
                    json!({"name": format!("H{i}"), "value_b64": encode_std(v.as_bytes())})
                } else {
                    json!({"name": format!("H{i}"), "value": v})
                }
            })
            .collect();
        let out = handle(
            &s,
            &m,
            Policy::Unsealed,
            &json!({"op":"capabilities"}).to_string(),
        );
        assert!(out.contains("\"encoded_values\":true"));
        // a declaration over about 2 KB needs this: the laptop refuses it for a box that does not say so
        assert!(out.contains("\"declaration_records\":true"));
        // the box user's import socket takes neither now: both come sealed through the ingress account (ADR 0029 A9)
        for op in ["capabilities", "import"] {
            let out = handle(&s, &m, Policy::Import, &json!({"op": op}).to_string());
            assert!(
                !out.contains("encoded_values") && !out.contains("\"ok\":true"),
                "{op}: {out}"
            );
        }
        let out = handle(
            &s,
            &m,
            Policy::Unsealed,
            &json!({"op":"import","project":"app","env":"staging","allowed":[],"text":"me","lines":lines}).to_string(),
        );
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(
            v["names"]
                .as_array()
                .unwrap_or_else(|| panic!("{out}"))
                .len(),
            vals.len(),
            "{out}"
        );
        assert!(!out.contains("evil") && !out.contains("PRIVATE"));
        // both forms at once is not a valid line, and bad base64 stores nothing
        for bad in [
            json!({"name":"X","value":"a","value_b64":"YQ=="}),
            json!({"name":"X","value_b64":"!!not base64!!"}),
            json!({"name":"X","value_b64":encode_std(&[0xff, 0xfe])}),
        ] {
            let out = handle(&s, &m, Policy::Unsealed, &json!({"op":"import","project":"app","env":"staging","allowed":[],"text":"me","lines":[bad]}).to_string());
            assert!(out.contains("not valid"), "{out}");
        }
        assert!(s.get("workload.app.staging.X").unwrap().is_none());
        s.set(crate::secrets_approval::ENROLLED_MARKER, "1")
            .unwrap();
        // the runner's resolve: exact for an environment value, plain-only inside a command line
        let allow: Vec<String> = (0..vals.len()).map(|i| format!("H{i}")).collect();
        for (i, v) in vals.iter().enumerate() {
            let out = handle(
                &s,
                &m,
                Policy::Runner,
                &json!({"op":"resolve","project":"app","env":"staging","name":format!("H{i}"),"exact":true,"text":format!("{{{{secret:H{i}}}}}"),"allowed":allow}).to_string(),
            );
            let r: Value = serde_json::from_str(&out).unwrap();
            assert_eq!(r["value"].as_str(), Some(v.as_str()), "{i}");
            let out = handle(
                &s,
                &m,
                Policy::Runner,
                &json!({"op":"resolve","project":"app","env":"staging","text":format!("{{{{secret:H{i}}}}}"),"allowed":allow}).to_string(),
            );
            let r: Value = serde_json::from_str(&out).unwrap();
            assert_eq!(
                r["ok"] == true,
                crate::secrets::check_value(v).is_ok(),
                "{i}"
            );
        }
        // the runner socket still reads no workload secret by name
        let out = handle(
            &s,
            &m,
            Policy::Runner,
            &json!({"op":"get","name":"workload.app.staging.H0"}).to_string(),
        );
        assert!(out.contains("not allowed"));
    }

    // ---- the credential broker inside the service -------------------------------------------------------------

    fn anth() -> ModelProvider {
        serde_json::from_value(
            json!({"id":"anth","kind":"anthropic","label":"A","base_url":null,
            "local_endpoint":false,"monthly_cap_usd":null}),
        )
        .unwrap()
    }

    fn compat(base: &str) -> ModelProvider {
        serde_json::from_value(
            json!({"id":"oc","kind":"openai_compatible","label":"C","base_url":base,
            "local_endpoint":false,"monthly_cap_usd":null}),
        )
        .unwrap()
    }

    #[test]
    fn the_box_user_cannot_read_a_model_key_but_the_broker_in_the_service_uses_it() {
        let d = tempfile::tempdir().unwrap();
        let (s, m) = svc(d.path());
        s.set("model-key-anth", SENTINEL).unwrap();
        // the box socket no longer answers a model key, whatever the name
        let r = ask(
            &s,
            &m,
            Policy::Box,
            json!({"op":"get","name":"model-key-anth"}),
        );
        assert_eq!(r["ok"], false);
        assert!(!r.to_string().contains(SENTINEL));
        assert!(!box_may_get("model-key-anth"));
        // the broker (inside the service) issues a token over its own socket and the token carries no key
        let up = Arc::new(crate::broker::tests::FakeUpstream::default());
        let b = Broker::start_with(s.clone() as Arc<dyn SecretStore>, up.clone(), None).unwrap();
        let sock = d.path().join("b/broker.sock");
        let l = listen(&sock, 0o750).unwrap();
        let (s2, b2) = (s.clone(), b.clone());
        std::thread::spawn(move || serve(s2, vec![(l, Policy::Broker)], Some(b2), None));
        let remote = RemoteBroker::new(sock.clone());
        assert_eq!(remote.port(), b.port());
        let t = remote
            .issue("run-1", &anth(), Some(5_000_000), crate::serve::unix_ms())
            .unwrap();
        assert!(t.token.starts_with("ozrt_") && !t.token.contains("SENTINEL"));
        assert!(!format!("{t:?}").contains(&t.token));
        // the provider sees the real key; the run side never did
        up.reply(
            200,
            "application/json",
            r#"{"model":"m","usage":{"input_tokens":10,"output_tokens":5}}"#,
        );
        let c = reqwest_free_call(b.port(), &t.token);
        assert_eq!(c, 200);
        let sent = up.sent.lock().unwrap();
        assert!(sent[0]
            .headers
            .iter()
            .any(|(k, v)| k == "x-api-key" && v == SENTINEL));
        drop(sent);
        let u = remote.drain_usage("run-1");
        assert_eq!(u.len(), 1);
        assert_eq!((u[0].input_tokens, u[0].output_tokens), (10, 5));
        // revoking ends the token
        remote.revoke_run("run-1");
        assert_eq!(reqwest_free_call(b.port(), &t.token), 401);
        // nothing on this socket ever returns a key
        let all = ask_line(&sock, json!({"op":"get","name":"model-key-anth"}));
        assert!(all.contains("not allowed") && !all.contains(SENTINEL));
    }

    /// One POST through the broker's loopback port with a run token; the status code.
    fn reqwest_free_call(port: u16, token: &str) -> u16 {
        use std::io::Read;
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        let body = "{}";
        write!(s, "POST /anth/v1/messages HTTP/1.1\r\nHost: x\r\nx-api-key: {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        out.split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .unwrap_or(0)
    }

    fn ask_line(sock: &Path, v: Value) -> String {
        let mut st = UnixStream::connect(sock).unwrap();
        st.write_all(format!("{v}\n").as_bytes()).unwrap();
        let mut line = String::new();
        BufReader::new(&st).read_line(&mut line).unwrap();
        line
    }

    #[test]
    fn a_key_is_never_sent_to_an_address_it_was_not_first_used_with() {
        let d = tempfile::tempdir().unwrap();
        let (s, _) = svc(d.path());
        s.set("model-key-oc", SENTINEL).unwrap();
        let up = Arc::new(crate::broker::tests::FakeUpstream::default());
        let b = Broker::start_with(
            s.clone() as Arc<dyn SecretStore>,
            up,
            Some(d.path().join("pins.json")),
        )
        .unwrap();
        let now = crate::serve::unix_ms();
        assert!(b
            .issue("r1", &compat("https://models.example.com"), None, now)
            .is_ok());
        // a hostile process renames the provider's address to its own host: refused, and the message holds no key
        let e = b
            .issue("r2", &compat("https://evil.example.net"), None, now)
            .unwrap_err();
        assert!(e.contains("address changed") && !e.contains(SENTINEL));
        // the owner saving the key again is the confirmation that the address may change
        s.set("model-key-oc", "SENTINEL-new-key-9876543210")
            .unwrap();
        assert!(b
            .issue("r3", &compat("https://evil.example.net"), None, now)
            .is_ok());
        // pins survive a restart
        let again = Broker::start_with(
            s.clone() as Arc<dyn SecretStore>,
            Arc::new(crate::broker::tests::FakeUpstream::default()),
            Some(d.path().join("pins.json")),
        )
        .unwrap();
        assert!(again
            .issue("r4", &compat("https://models.example.com"), None, now)
            .is_err());
    }

    #[test]
    fn only_the_supervisor_that_claimed_may_issue_tokens_and_a_quiet_holder_can_be_replaced() {
        let d = tempfile::tempdir().unwrap();
        let (s, _) = svc(d.path());
        let up = Arc::new(crate::broker::tests::FakeUpstream::default());
        let b = Broker::start_with(s.clone() as Arc<dyn SecretStore>, up, None).unwrap();
        let g = IssuerGate::default();
        let now = crate::serve::unix_ms();
        let issue = |proof: &str| {
            serde_json::from_str::<Value>(&handle_broker(
                &b,
                &g,
                BrokerAccess::Claimed,
                &json!({"op":"issue","run_id":"r","provider":anth(),"proof":proof}).to_string(),
            ))
            .unwrap()
        };
        // no claim yet, and a guess: refused
        assert_eq!(issue("")["error"], CLAIM_NEEDED);
        let secret = g.claim(now).unwrap();
        assert_eq!(issue("guess")["ok"], false);
        // a second claimant is refused while the holder is alive
        assert!(g.claim(now + 1_000).is_err());
        assert!(g.check(&secret, now + 2_000));
        assert!(g.claim(now + 2_000 + RECLAIM_AFTER_MS - 1).is_err());
        // once the holder has been quiet long enough, the next claimant takes over and the old secret stops working
        let next = g.claim(now + 2_000 + RECLAIM_AFTER_MS + 1).unwrap();
        assert_ne!(next, secret);
        assert!(!g.check(&secret, now + 100_000) && g.check(&next, now + 100_000));
        // the other powers need it too, and the free ones do not
        for op in ["models", "revoke", "usage", "ping"] {
            let r = handle_broker(
                &b,
                &g,
                BrokerAccess::Claimed,
                &json!({"op":op,"run_id":"r"}).to_string(),
            );
            assert!(r.contains(CLAIM_NEEDED), "{op}");
        }
        assert!(
            handle_broker(&b, &g, BrokerAccess::Claimed, r#"{"op":"port"}"#)
                .contains("\"ok\":true")
        );
    }

    #[test]
    fn a_projects_declaration_is_not_the_box_sockets_to_touch() {
        let d = tempfile::tempdir().unwrap();
        let (s, m) = svc(d.path());
        for op in [
            json!({"op":"set","name":"workload-policy.app","value":"aa"}),
            json!({"op":"get","name":"workload-policy.app"}),
            json!({"op":"delete","name":"workload-policy.app"}),
        ] {
            assert_eq!(ask(&s, &m, Policy::Box, op)["ok"], false);
        }
    }

    /// an agent is the box user, so what it can reach is the box, supervisor-less box-locked,
    /// runner and import sockets. None of them may set or replace a declaration without the policy-scope approval; before a
    /// second factor exists the first declaration of a project is the box's own first setting and a CHANGE is refused.
    #[test]
    fn an_agent_cannot_set_or_change_a_declaration_on_any_socket_it_reaches() {
        let d = tempfile::tempdir().unwrap();
        let (s, m) = svc(d.path());
        let g = Gates::default();
        let text = secret_decl;
        let declare = |t: &str, approval: &str| {
            // the laptop's request, opened from the ingress route (the box user's import socket takes no declaration)
            ask_with(
                &s,
                &m,
                &g,
                Policy::Unsealed,
                json!({"op":"policy","project":"app","text":t,"approval":approval}),
            )
        };
        assert!(
            !ok(&ask_with(
                &s,
                &m,
                &g,
                Policy::Import,
                json!({"op":"policy","project":"app","text":secret_decl("t")})
            )),
            "the box user's socket takes no declaration"
        );
        // every other socket: no write path to the declaration's name, whatever the op
        for p in [
            Policy::Box,
            Policy::BoxLocked,
            Policy::Runner,
            Policy::Broker,
            Policy::BrokerLocked,
            Policy::Supervisor,
            Policy::Import,
        ] {
            for op in [
                json!({"op":"set","name":"workload-policy.app","value":"aa"}),
                json!({"op":"set","name":"workload-policy.app","value_b64":"YWE="}),
                json!({"op":"delete","name":"workload-policy.app"}),
                json!({"op":"get","name":"workload-policy.app"}),
            ] {
                assert!(!ok(&ask_with(&s, &m, &g, p, op.clone())), "{p:?} {op}");
            }
        }
        // no second factor yet: a declaration that gives a command a secret is refused, first or replacement (G5 second review,
        // N-C1: an agent that declares before the owner does would otherwise receive every key the owner imports). A declaration
        // that hands out nothing is accepted, and so is one that REMOVES the secrets of an earlier one.
        let refused = declare(&text("t"), "");
        assert!(!ok(&refused), "{refused}");
        assert!(
            refused["error"].as_str().unwrap().contains("second factor"),
            "{refused}"
        );
        assert!(
            crate::workload_policy::load(&*s, "app").unwrap().is_none(),
            "nothing was stored"
        );
        let plain = r#"{"dir":"/work/projects/app","commands":{"build":{"allow":[],"argv":["npm","run","build"]}}}"#;
        assert!(ok(&declare(plain, "")));
        assert!(
            !ok(&declare(&text("exfil"), "")),
            "a replacement that gives a secret is refused too"
        );
        assert!(crate::workload_policy::load(&*s, "app")
            .unwrap()
            .unwrap()
            .commands
            .contains_key("build"));
        // a second factor exists: a change needs an approval for THIS project's declaration, spent once
        assert!(ok(&ask_with(
            &s,
            &m,
            &g,
            Policy::Supervisor,
            json!({"op":"enroll"})
        )));
        assert!(!ok(&declare(&text("exfil"), "")));
        let code = ask_with(
            &s,
            &m,
            &g,
            Policy::Supervisor,
            json!({"op":"approve_mint","scope":"policy","project":"other"}),
        )["value"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(
            !ok(&declare(&text("exfil"), &code)),
            "an approval for another project does not change this one"
        );
        let code = ask_with(
            &s,
            &m,
            &g,
            Policy::Supervisor,
            json!({"op":"approve_mint","scope":"policy","project":"app"}),
        )["value"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(ok(&declare(&text("exfil"), &code)));
        assert!(
            !ok(&declare(&text("t"), &code)),
            "an approval is spent by use"
        );
    }

    /// A person's approval code is made by hand for one use. A declaration the box refuses (its shape, its size) never touches it, so
    /// the same code then saves a valid one; a save that happened spends it.
    #[test]
    fn a_declaration_the_box_refuses_leaves_the_approval_unused_and_a_saved_one_spends_it() {
        use crate::workload_policy::realistic_declaration;
        let d = tempfile::tempdir().unwrap();
        let (s, m) = svc_enrolled(d.path());
        let g = Gates::default();
        let mint = || {
            ask_with(
                &s,
                &m,
                &g,
                Policy::Supervisor,
                json!({"op":"approve_mint","scope":"policy","project":"app"}),
            )["value"]
                .as_str()
                .unwrap()
                .to_string()
        };
        let declare = |t: &str, approval: &str| {
            ask_with(
                &s,
                &m,
                &g,
                Policy::Unsealed,
                json!({"op":"policy","project":"app","text":t,"approval":approval}),
            )
        };
        let code = mint();
        // too big once written out: refused with the size and the limit
        let big = realistic_declaration(64, 64, 16);
        let r = declare(&big, &code);
        assert!(
            !ok(&r) && r["error"].as_str().unwrap().contains("256 KB"),
            "{r}"
        );
        // a declaration that breaks a rule of its shape, and one that breaks a rule of a secret command
        let no_pin = secret_decl("x").replace("\"pin\"", "\"pins\"");
        let bad_var = r#"{"dir":"/work/projects/app","commands":{"a":{"allow":[],"vars":{"NODE_OPTIONS":"--x"}}}}"#;
        let renamed =
            r#"{"dir":"/work/projects/app","commands":{"a":{"allow":["K"],"env":["K"]}}}"#;
        for bad in [no_pin.as_str(), bad_var, "not json", renamed] {
            assert!(!ok(&declare(bad, &code)), "{bad}");
        }
        assert!(crate::workload_policy::load(&*s, "app").unwrap().is_none());
        // the same code still works for a declaration the box keeps: a realistic one, about 7 KB
        let good = realistic_declaration(1, 45, 11);
        assert!(good.len() > 6000);
        let r = declare(&good, &code);
        assert!(ok(&r), "{r}");
        let want = crate::workload_policy::Policy::parse(&good).unwrap();
        assert_eq!(
            crate::workload_policy::load(&*s, "app").unwrap().unwrap(),
            want
        );
        // that save spent it
        let again = declare(&good, &code);
        assert!(!ok(&again), "{again}");
    }

    /// G5 second review, N-C1: on a box with no second factor the agent could declare first (or squat before the owner), then receive
    /// every key the owner imports. Nothing is resolved there, and a stored value cannot be replaced from the box.
    #[test]
    fn with_no_second_factor_nothing_is_resolved_and_a_stored_value_cannot_be_replaced() {
        let d = tempfile::tempdir().unwrap();
        let (s, m) = svc(d.path());
        let g = Gates::default();
        let import = |v: &str| {
            ask_with(
                &s,
                &m,
                &g,
                Policy::Unsealed,
                json!({"op":"import","project":"shop","env":"staging","allowed":[],"text":"me",
                "lines":[{"name":"SUPABASE_URL","value":v},{"name":"SERVICE_ROLE_KEY","value":SENTINEL}]}),
            )
        };
        assert!(
            ok(&import("https://owner.example.com")),
            "the first import of a name is the box's own first setting"
        );
        assert!(
            ok(&import("https://owner.example.com")),
            "the same value again changes nothing"
        );
        // an agent repoints the stored URL an approved command sends its key to: refused until a second factor exists
        let r = import("https://agent.example.net");
        assert!(
            !ok(&r) && r["error"].as_str().unwrap().contains("second factor"),
            "{r}"
        );
        assert_eq!(
            s.get("workload.shop.staging.SUPABASE_URL")
                .unwrap()
                .as_deref(),
            Some("https://owner.example.com")
        );
        // a declaration written before this rule (it is stored, so the squat is the point) gets nothing from the resolve op
        for p in [Policy::Runner, Policy::Admin] {
            let r = ask_with(
                &s,
                &m,
                &g,
                p,
                json!({"op":"resolve","project":"shop","env":"staging","name":"SERVICE_ROLE_KEY","exact":true,
                "text":"","allowed":["SERVICE_ROLE_KEY"]}),
            );
            assert!(!ok(&r) && !r.to_string().contains(SENTINEL), "{p:?} {r}");
            assert!(
                r["error"].as_str().unwrap().contains("second factor"),
                "{r}"
            );
        }
        // enrolled: the same request resolves
        s.set(crate::secrets_approval::ENROLLED_MARKER, "1")
            .unwrap();
        let r = ask_with(
            &s,
            &m,
            &g,
            Policy::Runner,
            json!({"op":"resolve","project":"shop","env":"staging","name":"SERVICE_ROLE_KEY","exact":true,
            "text":"","allowed":["SERVICE_ROLE_KEY"]}),
        );
        assert_eq!(r["value"], SENTINEL);
    }

    /// The squat: an agent declares a project before the owner does. A declaration that gives a command a secret is refused on a box
    /// with no second factor, whether it is the first or a replacement; one that gives nothing is accepted and can be replaced by a
    /// declaration that gives nothing.
    #[test]
    fn an_agent_cannot_squat_a_project_with_a_declaration_that_receives_keys() {
        let d = tempfile::tempdir().unwrap();
        let (s, m) = svc(d.path());
        let g = Gates::default();
        // the review's own attack: an unpinned `npm test` that is given the service-role key
        let squat = r#"{"dir":"/work/projects/shop","commands":{"x":{"allow":["SERVICE_ROLE_KEY"],"env":["SERVICE_ROLE_KEY"],"argv":["npm","test"]}}}"#;
        let r = ask_with(
            &s,
            &m,
            &g,
            Policy::Unsealed,
            json!({"op":"policy","project":"shop","text":squat}),
        );
        assert!(!ok(&r), "{r}"); // refused for the missing pin, and would be for the missing second factor
        assert!(crate::workload_policy::load(&*s, "shop").unwrap().is_none());
        // a fully pinned one is refused for the same reason: the box cannot tell the agent from the owner
        let r = ask_with(
            &s,
            &m,
            &g,
            Policy::Unsealed,
            json!({"op":"policy","project":"shop","text":secret_decl("mint")}),
        );
        assert!(
            !ok(&r) && r["error"].as_str().unwrap().contains("second factor"),
            "{r}"
        );
        assert!(crate::workload_policy::load(&*s, "shop").unwrap().is_none());
    }

    /// a key stored as production is never handed to a runner (or the root helper's `resolve`),
    /// by the exact path an environment variable takes or the reference path, from the box's store or the imported one.
    #[test]
    fn a_production_key_is_never_resolved_for_a_declared_command() {
        use crate::secrets_enc::{workload_name, Meta};
        let d = tempfile::tempdir().unwrap();
        let (s, m) = svc_enrolled(d.path());
        let g = Gates::default();
        let prod = workload_name("app", "staging", "STRIPE_KEY").unwrap();
        s.set_with_meta(
            &prod,
            SENTINEL,
            Meta {
                owner: "me".into(),
                production: true,
                ..Default::default()
            },
        )
        .unwrap();
        let plain = workload_name("app", "staging", "API_KEY").unwrap();
        s.set_with_meta(
            &plain,
            "staging-value-1234",
            Meta {
                owner: "me".into(),
                production: false,
                ..Default::default()
            },
        )
        .unwrap();
        for p in [Policy::Runner, Policy::Admin] {
            for exact in [true, false] {
                let r = ask_with(
                    &s,
                    &m,
                    &g,
                    p,
                    json!({"op":"resolve","project":"app","env":"staging","name":"STRIPE_KEY","exact":exact,
                    "text":"{{secret:STRIPE_KEY}}","allowed":["STRIPE_KEY"]}),
                );
                assert!(
                    !ok(&r) && !r.to_string().contains(SENTINEL),
                    "{p:?} exact={exact} {r}"
                );
                assert!(r["error"].as_str().unwrap().contains("production"), "{r}");
            }
            let r = ask_with(
                &s,
                &m,
                &g,
                p,
                json!({"op":"resolve","project":"app","env":"staging","name":"API_KEY","exact":true,"text":"","allowed":["API_KEY"]}),
            );
            assert_eq!(
                r["value"], "staging-value-1234",
                "a staging key still resolves"
            );
        }
        // the box's own store refuses, and so does the imported store a name falls through to
        let g2 = Gates::default();
        let d2 = tempfile::tempdir().unwrap();
        let (mem, _) = svc(d2.path());
        mem.set_with_meta(
            &prod,
            SENTINEL,
            Meta {
                owner: "me".into(),
                production: true,
                ..Default::default()
            },
        )
        .unwrap();
        g2.memory.set(mem).ok();
        let r = ask_with(
            &s,
            &m,
            &g2,
            Policy::Runner,
            json!({"op":"resolve","project":"app","env":"staging","name":"STRIPE_KEY","exact":true,"text":"","allowed":["STRIPE_KEY"]}),
        );
        assert!(!ok(&r) && !r.to_string().contains(SENTINEL), "{r}");
    }

    // ---- the supervisor's socket, approvals and the content scan -------------------------------------------------------

    fn ask_with(s: &EncryptedSecrets, m: &TokenMac, g: &Gates, p: Policy, v: Value) -> Value {
        serde_json::from_str(&handle_with(s, m, g, p, &v.to_string())).unwrap()
    }

    fn ok(v: &Value) -> bool {
        v["ok"].as_bool() == Some(true)
    }

    #[test]
    fn the_supervisors_approve_mint_for_a_signer_enrol_code_is_refused_through_the_real_handler() {
        let mint = |g: &Gates, s: &EncryptedSecrets, m: &TokenMac, scope: &str| {
            ask_with(
                s,
                m,
                g,
                Policy::Supervisor,
                json!({"op":"approve_mint","scope":scope,"project":"","env":""}),
            )
        };
        // a service with no request operations is what `main` was: the dashboard still makes the code
        let d = tempfile::tempdir().unwrap();
        let (s, m) = svc(d.path());
        assert!(ok(&mint(&Gates::default(), &s, &m, "signer-enroll")));
        // requests on, codes on (the default): every scope but the enrolment mints
        let d = tempfile::tempdir().unwrap();
        let (s, m) = svc(d.path());
        let g = Gates::default();
        g.enable_requests(
            &s,
            &d.path().join("req"),
            &d.path().join("state"),
            "box-1",
            1_000,
        )
        .unwrap();
        let refused = mint(&g, &s, &m, "signer-enroll");
        assert!(!ok(&refused));
        assert!(
            refused["error"]
                .as_str()
                .unwrap_or("")
                .contains("by an approved request"),
            "{refused}"
        );
        assert!(ok(&mint(&g, &s, &m, "import")));
        // the box user cannot mint either way
        assert!(!ok(&ask_with(
            &s,
            &m,
            &g,
            Policy::Box,
            json!({"op":"approve_mint","scope":"import"})
        )));
        // codes off: nothing mints, and the sentence is the codes one (that arm comes first)
        let d = tempfile::tempdir().unwrap();
        let (s, m) = svc(d.path());
        let g = Gates::default();
        g.enable_requests(
            &s,
            &d.path().join("req"),
            &d.path().join("state"),
            "box-1",
            1_000,
        )
        .unwrap();
        let _ = g.legacy_codes_off.set(true);
        for scope in ["signer-enroll", "import"] {
            let r = mint(&g, &s, &m, scope);
            assert!(!ok(&r));
            assert!(
                r["error"]
                    .as_str()
                    .unwrap_or("")
                    .contains("approvals as requests"),
                "{r}"
            );
        }
        // the journal did not open: this version's refusal still holds
        let d = tempfile::tempdir().unwrap();
        let (s, m) = svc(d.path());
        let g = Gates::default();
        let _ = g.requests_failed.set(());
        assert!(!ok(&mint(&g, &s, &m, "signer-enroll")));
        assert!(ok(&mint(&g, &s, &m, "import")));
    }

    #[test]
    fn once_the_supervisor_has_its_own_socket_the_box_user_can_only_ask_whether_a_secret_exists() {
        let d = tempfile::tempdir().unwrap();
        let (s, m) = svc(d.path());
        let g = Gates::default();
        // the supervisor writes and reads the dashboard's own keys, and asks for a tag
        assert!(ok(&ask_with(
            &s,
            &m,
            &g,
            Policy::Supervisor,
            json!({"op":"set","name":"email-api-key","value":SENTINEL})
        )));
        let got = ask_with(
            &s,
            &m,
            &g,
            Policy::Supervisor,
            json!({"op":"get","name":"email-api-key"}),
        );
        assert_eq!(got["value"], SENTINEL);
        assert!(ok(&ask_with(
            &s,
            &m,
            &g,
            Policy::Supervisor,
            json!({"op":"mac","msg":encode_std(b"x")})
        )));
        // the box user's socket now says only whether and what is named
        let box_ = |v: Value| ask_with(&s, &m, &g, Policy::BoxLocked, v);
        assert_eq!(
            box_(json!({"op":"exists","name":"email-api-key"}))["flag"],
            true
        );
        assert!(ok(&box_(json!({"op":"names","prefix":"email"}))));
        for denied in [
            json!({"op":"get","name":"email-api-key"}),
            json!({"op":"set","name":"email-api-key","value":"x"}),
            json!({"op":"delete","name":"email-api-key"}),
            json!({"op":"mac","msg":encode_std(b"x")}),
            json!({"op":"approve_mint","scope":"import"}),
            json!({"op":"enroll"}),
        ] {
            let r = box_(denied);
            assert!(!ok(&r) && !r.to_string().contains(SENTINEL), "{r}");
        }
        // and the box user's other ways in cannot mint an approval or say a factor exists either
        for p in [Policy::Box, Policy::Import, Policy::Runner] {
            assert!(!ok(&ask_with(
                &s,
                &m,
                &g,
                p,
                json!({"op":"approve_mint","scope":"import"})
            )));
            assert!(!ok(&ask_with(&s, &m, &g, p, json!({"op":"enroll"}))));
        }
    }

    #[test]
    fn with_a_second_factor_enrolled_a_key_import_and_a_declaration_need_an_approval_that_is_good_once(
    ) {
        let d = tempfile::tempdir().unwrap();
        let (s, m) = svc(d.path());
        let g = Gates::default();
        let import = |approval: &str| {
            ask_with(
                &s,
                &m,
                &g,
                Policy::Unsealed,
                json!({"op":"import","project":"app","env":"staging",
                "approval":approval,"lines":[{"name":"API_KEY","value":SENTINEL}]}),
            )
        };
        let policy_text = secret_decl("t");
        let policy_text = policy_text.as_str();
        let declare = |approval: &str| {
            ask_with(
                &s,
                &m,
                &g,
                Policy::Unsealed,
                json!({"op":"policy","project":"app","text":policy_text,"approval":approval}),
            )
        };
        // before anyone has a second factor, a change is allowed and the record says so
        assert!(ok(&import("")));
        assert!(std::fs::read_to_string(d.path().join("workload-audit.log"))
            .unwrap()
            .contains("via=bootstrap"));
        // the dashboard enrols its second factor: from now on, no approval, no change
        assert!(ok(&ask_with(
            &s,
            &m,
            &g,
            Policy::Supervisor,
            json!({"op":"enroll"})
        )));
        let refused = import("");
        assert!(!ok(&refused) && refused["error"].as_str().unwrap().contains("--approval"));
        assert!(!ok(&declare("")));
        assert!(!ok(&import("AAAA-AAAA-AAAA-AAAA")));
        // an approval is for one project and environment and is spent by use
        let code = ask_with(
            &s,
            &m,
            &g,
            Policy::Supervisor,
            json!({"op":"approve_mint","scope":"import","project":"app","env":"staging"}),
        )["value"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(
            !ok(&declare(&code)),
            "an import approval does not declare a project"
        );
        assert!(ok(&import(&code)));
        assert!(!ok(&import(&code)), "an approval is good once");
        let pc = ask_with(
            &s,
            &m,
            &g,
            Policy::Supervisor,
            json!({"op":"approve_mint","scope":"policy","project":"app"}),
        )["value"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(ok(&declare(&pc)));
        // the box user cannot take the marker away, by any socket it can reach
        for p in [Policy::Box, Policy::Supervisor] {
            let r = ask_with(
                &s,
                &m,
                &g,
                p,
                json!({"op":"delete","name":crate::secrets_approval::ENROLLED_MARKER}),
            );
            assert!(!ok(&r));
        }
        assert_eq!(
            ask_with(&s, &m, &g, Policy::Admin, json!({"op":"enrolled"}))["flag"],
            true
        );
        // the audit log names scope, project and how, and holds no value and no code
        let log = std::fs::read_to_string(d.path().join("workload-audit.log")).unwrap();
        assert!(log.contains(
            "approval allowed scope=import project=app env=staging via=dashboard-stepup"
        ));
        assert!(log.contains("approval refused"));
        assert!(!log.contains(SENTINEL) && !log.contains(&code) && !log.contains(&pc));
        // the stored value is still only ever opened inside the service
        assert!(!import("").to_string().contains(SENTINEL));
    }

    /// Found on a real box (2026-11-12): the helper's answer was thrown away, so the person read only "did not take the
    /// tunnel token" while the real reason (a fresh approval was needed) sat in a root-owned results file.
    #[test]
    fn the_helpers_reason_is_shown_and_its_status_line_is_not() {
        let out = "status=failed\nerror: this change needs a fresh approval from the dashboard (your passkey or \
                   authenticator code): ask for one there and run the command again with --approval CODE\n";
        let r = helper_reason(out).unwrap();
        assert!(r.starts_with("this change needs a fresh approval"), "{r}");
        assert!(!r.contains("status="));
        assert_eq!(
            helper_reason("status=failed\nthe token has an unexpected shape\n").as_deref(),
            Some("the token has an unexpected shape")
        );
        assert_eq!(helper_reason("status=failed\n\n"), None);
        assert!(
            helper_reason(&format!("error: {}", "x".repeat(900)))
                .unwrap()
                .len()
                <= 300
        );
    }

    /// ADR 0029 Amendment 12 (owner, 2026-11-13): a public mark cannot be planted from the box before a second factor exists
    /// (it would outlive enrolment), and once enrolled the audit line names which names were marked public, never a value.
    #[test]
    fn a_public_mark_is_refused_before_enrolment_and_named_in_the_audit_line_after() {
        let d = tempfile::tempdir().unwrap();
        let (s, m) = svc(d.path());
        let g = Gates::default();
        let import = |approval: &str, lines: Value| {
            ask_with(
                &s,
                &m,
                &g,
                Policy::Unsealed,
                json!({"op":"import","project":"app","env":"staging","allowed":[],"text":"me",
                "approval":approval,"lines":lines}),
            )
        };
        let lines = json!([
            {"name":"NEXT_PUBLIC_APP_URL","value":"https://staging.example.com","public":true},
            {"name":"OTHER_URL","value":"https://other.example.com"}
        ]);
        // no second factor yet: a public mark is refused, whole, and nothing is stored
        let r = import("", lines.clone());
        assert!(
            !ok(&r)
                && r["error"]
                    .as_str()
                    .unwrap()
                    .contains("cannot be marked public"),
            "{r}"
        );
        assert!(s
            .get("workload.app.staging.NEXT_PUBLIC_APP_URL")
            .unwrap()
            .is_none());
        assert!(s.get("workload.app.staging.OTHER_URL").unwrap().is_none());
        // the same lines without a mark are the box's first setting and are accepted
        let plain = json!([{"name":"NEXT_PUBLIC_APP_URL","value":"https://staging.example.com"}]);
        assert!(ok(&import("", plain)));
        assert!(
            !s.meta("workload.app.staging.NEXT_PUBLIC_APP_URL")
                .unwrap()
                .unwrap()
                .public
        );
        // enrolled: the mark is accepted with an approval, and the audit line names the marked name only
        assert!(ok(&ask_with(
            &s,
            &m,
            &g,
            Policy::Supervisor,
            json!({"op":"enroll"})
        )));
        let code = ask_with(
            &s,
            &m,
            &g,
            Policy::Supervisor,
            json!({"op":"approve_mint","scope":"import","project":"app","env":"staging"}),
        )["value"]
            .as_str()
            .unwrap()
            .to_string();
        let r = import(&code, lines);
        assert!(ok(&r), "{r}");
        assert!(
            s.meta("workload.app.staging.NEXT_PUBLIC_APP_URL")
                .unwrap()
                .unwrap()
                .public
        );
        let log = std::fs::read_to_string(d.path().join("workload-audit.log")).unwrap();
        let line = log
            .lines()
            .rev()
            .find(|l| l.contains(" import project=app"))
            .unwrap_or_else(|| panic!("{log}"));
        assert!(
            line.contains("public=NEXT_PUBLIC_APP_URL ") && !line.contains("OTHER_URL"),
            "{line}"
        );
        assert!(!log.contains("staging.example.com"), "never a value");
    }

    /// The import socket takes no import, with or without an approval: a key import arrives sealed on the ingress route
    /// (`Policy::Unsealed`), where the test above proves it is refused without an approval and spent once with one.
    #[test]
    fn the_import_socket_refuses_an_import_with_or_without_an_approval() {
        let d = tempfile::tempdir().unwrap();
        let (s, m) = svc(d.path());
        let g = Gates::default();
        for approval in ["", "AAAA-AAAA-AAAA-AAAA"] {
            let r = ask_with(
                &s,
                &m,
                &g,
                Policy::Import,
                json!({"op":"import","project":"app","env":"staging","approval":approval,
                "lines":[{"name":"API_KEY","value":SENTINEL}]}),
            );
            assert!(!ok(&r));
            assert!(r["error"]
                .as_str()
                .unwrap()
                .contains("not allowed on this socket"));
        }
    }

    /// An approval a person brought is spent by the next tunnel change only: a second change in the same process asks again.
    #[test]
    fn a_brought_tunnel_approval_is_taken_once() {
        give_tunnel_approval("ABCD-EFGH-JKMN-PQRS");
        assert_eq!(
            take_given_tunnel_approval().as_deref(),
            Some("ABCD-EFGH-JKMN-PQRS")
        );
        assert_eq!(take_given_tunnel_approval(), None);
    }

    /// The approval is for one token: a code made for the digest of token A is refused for token B (and stays good for A),
    /// and a code made without a digest approves no store at all.
    #[test]
    fn a_tunnel_token_approval_is_bound_to_the_token_it_was_made_for() {
        use crate::secrets_approval::tunnel_token_binding as bind;
        let d = tempfile::tempdir().unwrap();
        let (s, m) = svc(d.path());
        let g = Gates::default();
        ask_with(&s, &m, &g, Policy::Admin, json!({"op":"enroll"}));
        let mint = |env: &str| {
            ask_with(
                &s,
                &m,
                &g,
                Policy::Supervisor,
                json!({"op":"approve_mint","scope":"tunnel-token","project":"cloudflare","env":env}),
            )["value"]
                .as_str()
                .unwrap()
                .to_string()
        };
        let gate = |code: &str, token: &str| {
            ask_with(
                &s,
                &m,
                &g,
                Policy::Admin,
                json!({"op":"gate","scope":"tunnel-token","project":"cloudflare","env":bind(token),"approval":code}),
            )
        };
        let code = mint(&bind("token-a-aaaaaaaaaaaaaaaaaaaa"));
        // the swapped-in token is refused, and the refusal does not spend the owner's code
        assert!(!ok(&gate(&code, "token-b-bbbbbbbbbbbbbbbbbbbb")));
        assert!(ok(&gate(&code, "token-a-aaaaaaaaaaaaaaaaaaaa")));
        // a code made for no token (an unbound one) does not approve storing one
        let unbound = mint("");
        assert!(!ok(&gate(&unbound, "token-a-aaaaaaaaaaaaaaaaaaaa")));
    }

    /// The code reaches the request helper on standard input, never in its arguments, when the helper can read it there;
    /// a helper from before the flag gets it as an argument (the only case), and the token is never an argument.
    #[test]
    fn the_approval_code_is_not_in_the_request_helpers_arguments() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("run/requests")).unwrap();
        let fake =
            |name: &str, knows_flag: bool| {
                let p = d.path().join(name);
                std::fs::write(
                    &p,
                    format!(
                    "#!/bin/sh\n# {}\necho \"$@\" > '{1}/{name}.args'\ncat > '{1}/{name}.stdin'\n",
                    if knows_flag { APPROVAL_STDIN_FLAG } else { "no flag" },
                    d.path().display()
                ),
                )
                .unwrap();
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
                p.to_string_lossy().to_string()
            };
        let dir = d.path().join("run").to_string_lossy().to_string();
        let code = "ABCD-EFGH-JKMN-PQRS";
        let token = "tok-SENTINELSENTINELSENTINEL";
        let svc = SocketSecrets::new(d.path().join("none.sock"));
        let new = fake("new", true);
        give_tunnel_approval(code);
        admin_tunnel_with(&svc, "tunnel-token-cloudflare", Some(token), &dir, &new).unwrap();
        let args = std::fs::read_to_string(d.path().join("new.args")).unwrap();
        assert!(
            args.starts_with("--approval-stdin replace-tunnel-token cloudflare "),
            "{args}"
        );
        assert!(!args.contains(code) && !args.contains(token), "{args}");
        assert_eq!(
            std::fs::read_to_string(d.path().join("new.stdin"))
                .unwrap()
                .trim(),
            code
        );
        let old = fake("old", false);
        give_tunnel_approval(code);
        admin_tunnel_with(&svc, "tunnel-token-cloudflare", Some(token), &dir, &old).unwrap();
        let args = std::fs::read_to_string(d.path().join("old.args")).unwrap();
        assert!(
            !args.contains("--approval-stdin") && args.trim_end().ends_with(code),
            "{args}"
        );
        assert!(!args.contains(token));
    }

    #[test]
    fn the_root_helper_asks_the_gate_before_it_stores_a_tunnel_token() {
        let d = tempfile::tempdir().unwrap();
        let (s, m) = svc(d.path());
        let g = Gates::default();
        let gate = |code: &str| {
            ask_with(
                &s,
                &m,
                &g,
                Policy::Admin,
                json!({"op":"gate","scope":"tunnel-token","project":"cloudflare","approval":code}),
            )
        };
        assert_eq!(gate("")["value"], "bootstrap");
        ask_with(&s, &m, &g, Policy::Admin, json!({"op":"enroll"}));
        assert!(!ok(&gate("")));
        let code = ask_with(
            &s,
            &m,
            &g,
            Policy::Supervisor,
            json!({"op":"approve_mint","scope":"tunnel-token","project":"cloudflare"}),
        )["value"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(gate(&code)["value"], "dashboard-stepup");
        assert!(!ok(&gate(&code)));
        // the box user's sockets have no gate op
        assert!(!ok(&ask_with(
            &s,
            &m,
            &g,
            Policy::Box,
            json!({"op":"gate","scope":"tunnel-token"})
        )));
    }

    #[test]
    fn the_scan_names_the_secret_a_text_holds_in_any_form_and_never_the_value() {
        let d = tempfile::tempdir().unwrap();
        let (s, m) = svc(d.path());
        let g = Gates::default();
        ask_with(
            &s,
            &m,
            &g,
            Policy::Unsealed,
            json!({"op":"import","project":"app","env":"staging",
            "lines":[{"name":"API_KEY","value":SENTINEL}]}),
        );
        s.set("model-key-x", "SENTINEL-model-key-ffeeddccbbaa")
            .unwrap();
        let scan = |t: &str| ask_with(&s, &m, &g, Policy::Import, json!({"op":"scan","text":t}));
        let r = scan(&format!(
            "const k = \"{SENTINEL}\";\nconst z = \"{}\"",
            encode_std(b"SENTINEL-model-key-ffeeddccbbaa")
        ));
        let names: Vec<String> = serde_json::from_value(r["names"].clone()).unwrap();
        assert!(
            names.contains(&"workload.app.staging.API_KEY".to_string())
                && names.contains(&"model-key-x".to_string())
        );
        assert!(!r.to_string().contains(SENTINEL));
        assert_eq!(scan("nothing to see")["names"], json!([]));
        // not on the box user's other sockets, and bounded
        assert!(!ok(&ask_with(
            &s,
            &m,
            &g,
            Policy::Box,
            json!({"op":"scan","text":SENTINEL})
        )));
        assert!(!ok(&scan(&"x".repeat(MAX_SCAN_BYTES + 1))));
        let mut refused = false;
        for _ in 0..(SCANS_PER_MINUTE + 5) {
            refused |= !ok(&scan("hello"));
        }
        assert!(refused, "a scan budget stops guessing");
    }

    /// ADR 0041 section 9 (the 2026-11-13 hold on a 30-line cookie helper): a value stored under a public-kind name that is public in
    /// fact is configuration, so the barrier does not look for it. A key-shaped value under the same kind of name still is held.
    #[test]
    fn a_public_value_under_a_public_name_is_not_scanned_for_and_a_key_under_one_still_is() {
        let d = tempfile::tempdir().unwrap();
        let (s, m) = svc(d.path());
        let g = Gates::default();
        // built by concatenation: no key-shaped literal in this file
        let key = format!("{}{}", "sk_li", "ve_a1B2c3D4e5F6g7H8i9J0k1L2m3N4");
        for (name, value) in [
            (
                "workload.app.staging.NEXT_PUBLIC_TURN_USERNAME",
                "demo-turn-user",
            ),
            (
                "workload.app.staging.VITE_API_BASE",
                "https://api.example.test/v1",
            ),
            ("workload.app.staging.TURN_USERNAME", "other-turn-user"),
            ("workload.app.staging.NEXT_PUBLIC_BAD", key.as_str()),
            (
                "workload.app.staging.NEXT_PUBLIC_API_SECRET",
                "plainlookingvalue",
            ),
            (
                "workload.app.prod.NEXT_PUBLIC_URL",
                "https://prod.example.test/x",
            ),
        ] {
            s.set(name, value).unwrap();
        }
        let scan = |t: &str| -> Vec<String> {
            let r = ask_with(&s, &m, &g, Policy::Import, json!({"op":"scan","text":t}));
            serde_json::from_value(r["names"].clone()).unwrap()
        };
        // a ts file and a docs file that use the public values and name the variable: not held
        assert!(
            scan("export const user = \"demo-turn-user\"; // NEXT_PUBLIC_TURN_USERNAME").is_empty()
        );
        assert!(scan("Set `NEXT_PUBLIC_TURN_USERNAME` to demo-turn-user and VITE_API_BASE to https://api.example.test/v1").is_empty());
        // the same sort of value under a name that is not a public kind is still held
        assert_eq!(
            scan("user other-turn-user"),
            vec!["workload.app.staging.TURN_USERNAME"]
        );
        // a key under a public name, a name that says it is secret, and a production-looking value are all still held
        assert_eq!(
            scan(&format!("x = {key}")),
            vec!["workload.app.staging.NEXT_PUBLIC_BAD"]
        );
        assert_eq!(
            scan("plainlookingvalue"),
            vec!["workload.app.staging.NEXT_PUBLIC_API_SECRET"]
        );
        assert_eq!(
            scan("https://prod.example.test/x"),
            vec!["workload.app.prod.NEXT_PUBLIC_URL"]
        );
    }

    /// ADR 0041 section 9, the floor: a stored value under twelve characters (a region, a port) is not looked for in a commit
    /// (`AWS_REGION` alone held 77 files). And the address rule: under a public name a plain
    /// address passes, but an address with user info, a webhook, or ANY query (a name encoded or comma-joined cannot hide a
    /// credential parameter, because no query passes) is held as a stored value.
    #[test]
    fn a_short_value_is_not_scanned_for_and_only_a_plain_address_passes_under_a_public_name() {
        let d = tempfile::tempdir().unwrap();
        let (s, m) = svc(d.path());
        let g = Gates::default();
        let hook = [
            "https://hooks.slack.com/",
            "services/T0000000/B0000000/abcdefghijklmnopqrstuvwx",
        ]
        .concat();
        for (name, value) in [
            ("workload.app.staging.AWS_REGION", "us-east-1"),
            ("workload.app.staging.PORT", "8080"),
            ("workload.app.staging.ELEVEN_CHARS", "abcdefghij1"),
            ("workload.app.staging.TWELVE_CHARS", "abcdefghij12"),
            (
                "workload.app.staging.NEXT_PUBLIC_API_URL",
                "https://api.example.test/v1",
            ),
            (
                "workload.app.staging.NEXT_PUBLIC_TURN_URL",
                "turns:turn.example.test:443?transport=tcp",
            ),
            (
                "workload.app.staging.NEXT_PUBLIC_ENC_URL",
                "https://api.example.test/v1?%74oken=abcdef123456",
            ),
            (
                "workload.app.staging.NEXT_PUBLIC_JOIN_URL",
                "https://api.example.test/v1?a=1,token=abcdef123456",
            ),
            (
                "workload.app.staging.NEXT_PUBLIC_USERINFO_URL",
                "https://admin:pass1234word@api2.example.test/v1",
            ),
            ("workload.app.staging.NEXT_PUBLIC_HOOK_URL", hook.as_str()),
            (
                "workload.app.staging.TURN_URL",
                "turns:turn2.example.test:443?transport=udp",
            ),
            (
                "workload.app.staging.PUBLIC_API_HOST",
                "https://svelte.example.test/api?region=eu",
            ),
        ] {
            s.set(name, value).unwrap();
        }
        let scan = |t: &str| -> Vec<String> {
            let r = ask_with(&s, &m, &g, Policy::Import, json!({"op":"scan","text":t}));
            serde_json::from_value(r["names"].clone()).unwrap()
        };
        // short values: not matched, whatever they are
        assert!(scan("region us-east-1 port 8080 and abcdefghij1").is_empty());
        assert_eq!(
            scan("abcdefghij12"),
            vec!["workload.app.staging.TWELVE_CHARS"]
        );
        // a plain address under a public name: public
        assert!(scan("https://api.example.test/v1").is_empty());
        // a query (a TURN transport, an encoded or comma-joined credential name), user info, a webhook, a non-public name and the
        // bare PUBLIC_ prefix: held
        for (text, held) in [
            (
                "turns:turn.example.test:443?transport=tcp",
                "NEXT_PUBLIC_TURN_URL",
            ),
            (
                "https://api.example.test/v1?%74oken=abcdef123456",
                "NEXT_PUBLIC_ENC_URL",
            ),
            (
                "https://api.example.test/v1?a=1,token=abcdef123456",
                "NEXT_PUBLIC_JOIN_URL",
            ),
            (
                "https://admin:pass1234word@api2.example.test/v1",
                "NEXT_PUBLIC_USERINFO_URL",
            ),
            (hook.as_str(), "NEXT_PUBLIC_HOOK_URL"),
            ("turns:turn2.example.test:443?transport=udp", "TURN_URL"),
            (
                "https://svelte.example.test/api?region=eu",
                "PUBLIC_API_HOST",
            ),
        ] {
            assert_eq!(
                scan(text),
                vec![format!("workload.app.staging.{held}")],
                "{held}"
            );
        }
        assert!(!crate::workload_policy::is_public_kind_name(
            "PUBLIC_API_HOST"
        ));
    }

    #[test]
    fn on_the_supervisor_socket_the_directory_is_the_proof_and_on_the_box_users_socket_spending_is_closed(
    ) {
        let d = tempfile::tempdir().unwrap();
        let (s, _) = svc(d.path());
        let up = Arc::new(crate::broker::tests::FakeUpstream::default());
        let b = Broker::start_with(s.clone() as Arc<dyn SecretStore>, up, None).unwrap();
        let g = IssuerGate::default();
        let run = |a: BrokerAccess, v: Value| -> Value {
            serde_json::from_str(&handle_broker(&b, &g, a, &v.to_string())).unwrap()
        };
        let issue = json!({"op":"issue","run_id":"r","provider":anth()});
        // no claim, no proof: the supervisor's socket answers, the box user's socket asks for a claim, the locked one refuses
        assert_ne!(
            run(BrokerAccess::Trusted, issue.clone())["error"],
            CLAIM_NEEDED
        );
        assert_eq!(
            run(BrokerAccess::Claimed, issue.clone())["error"],
            CLAIM_NEEDED
        );
        assert!(!ok(&run(BrokerAccess::Locked, json!({"op":"claim"}))));
        for op in [
            "claim",
            "ping",
            "models",
            "issue",
            "revoke",
            "usage",
            "list_models",
            "test_connection",
        ] {
            assert!(
                !ok(&run(
                    BrokerAccess::Locked,
                    json!({"op":op,"run_id":"r","provider":anth()})
                )),
                "{op}"
            );
        }
        assert!(ok(&run(BrokerAccess::Locked, json!({"op":"port"}))));
        assert!(
            is_broker_op(r#"{"op":"issue"}"#)
                && !is_broker_op(r#"{"op":"set"}"#)
                && !is_broker_op("junk")
        );
    }

    #[test]
    fn the_boxs_own_secrets_are_offered_to_a_command_never_read_by_the_box_and_found_by_the_scan() {
        use crate::secrets_enc::{KeyProvider, LocalKekProvider};
        let d = tempfile::tempdir().unwrap();
        let (s, m) = svc_enrolled(d.path());
        let p: Arc<dyn KeyProvider> = Arc::new(LocalKekProvider::random("local").unwrap());
        let mem = Arc::new(EncryptedSecrets::new(d.path().join("mem.json"), "box-a", p).unwrap());
        let g = Gates::default();
        g.memory.set(mem.clone()).ok().unwrap();
        let load = |items: Value| {
            ask_with(
                &s,
                &m,
                &g,
                Policy::Admin,
                json!({"op":"box_load","scope":"main","items":items}),
            )
        };
        let item = |env: &str, name: &str, v: &str| json!({"project":"app","env":env,"name":name,"value":v});
        // only the admin socket loads, and a production-looking key is refused whatever the loader says
        assert!(!ok(&ask_with(
            &s,
            &m,
            &g,
            Policy::Box,
            json!({"op":"box_load","scope":"main","items":[]})
        )));
        assert!(!ok(&load(json!([item("production", "K", SENTINEL)]))));
        assert!(!ok(&load(json!([item(
            "staging",
            "K",
            &format!("sk_{}_abcdef123456", "live")
        )]))));
        assert!(ok(&load(json!([item("staging", "API_KEY", SENTINEL)]))));
        // a command's resolver gets it by its allow-list; another name is refused
        let r = |allowed: Value| {
            ask_with(
                &s,
                &m,
                &g,
                Policy::Runner,
                json!({"op":"resolve","project":"app","env":"staging","text":"{{secret:API_KEY}}","allowed":allowed}),
            )
        };
        assert_eq!(r(json!(["API_KEY"]))["value"], SENTINEL);
        assert!(!ok(&r(json!([]))));
        // the box user's sockets never return it, and it is not on the persistent disk
        for p in [
            Policy::Box,
            Policy::BoxLocked,
            Policy::Supervisor,
            Policy::Import,
        ] {
            let v = ask_with(
                &s,
                &m,
                &g,
                p,
                json!({"op":"get","name":"workload.app.staging.API_KEY"}),
            );
            assert!(!v.to_string().contains(SENTINEL));
            let n = ask_with(&s, &m, &g, p, json!({"op":"names","prefix":"workload"}));
            assert!(!ok(&n) || !n.to_string().contains("API_KEY"));
        }
        assert!(!std::fs::read_to_string(d.path().join("s.json"))
            .unwrap()
            .contains(SENTINEL));
        assert!(!std::fs::read_to_string(d.path().join("mem.json"))
            .unwrap()
            .contains(SENTINEL));
        // the root launcher can list it for output redaction
        let names = ask_with(
            &s,
            &m,
            &g,
            Policy::Admin,
            json!({"op":"names","prefix":"workload.app."}),
        );
        assert!(names.to_string().contains("workload.app.staging.API_KEY"));
        assert_eq!(
            ask_with(
                &s,
                &m,
                &g,
                Policy::Admin,
                json!({"op":"get","name":"workload.app.staging.API_KEY"})
            )["value"],
            SENTINEL
        );
        // a commit holding it is stopped
        let sc = ask_with(
            &s,
            &m,
            &g,
            Policy::Import,
            json!({"op":"scan","text":format!("k={SENTINEL}")}),
        );
        assert!(sc.to_string().contains("API_KEY") && !sc.to_string().contains(SENTINEL));
        // a refresh without it removes it
        assert!(ok(&load(json!([]))));
        assert!(!ok(&r(json!(["API_KEY"]))));
        // the audit line has a count and a role, no value
        let log = std::fs::read_to_string(d.path().join("workload-audit.log")).unwrap();
        assert!(log.contains("box-secrets loaded role=main count=1") && !log.contains(SENTINEL));
    }
}
