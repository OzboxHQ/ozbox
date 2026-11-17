//! One approval model (ADR 0041): a request the box files, a person decides where they are, and the box hands the decision
//! to the waiting operation.
//!
//! This module is the pure part, with no I/O, no clock and no random numbers (the caller passes `now_ms` and each new id):
//!
//! * the **request object** and its **envelope**, and the **decision record** with every field the ADR's §1 and §3 ask for
//!   (the key type, the signature format, the authenticator data and flags, the counter, the attestation digest, the
//!   factor and the presence class). The record formats are frozen here, so a later move of the check into the service
//!   changes no format;
//! * the **state machine** (`pending`, `approved`, `spending`, `spent`, `denied`, `cancelled`, `superseded`, `expired`),
//!   with compare-and-set decisions, one slot per operation key, an approval that a lookalike request can neither burn nor
//!   swap, a spend that recomputes the subject digest and keeps the approval when it differs, and an epoch that voids
//!   whatever a restore brings back;
//! * the **rule table** as data (scope by surface by factor by role, [`RULES`]), with its TypeScript export
//!   ([`rule_table_ts`]) that a test compares with the dashboard's copy.
//!
//! The subject digest and its encoding are in [`crate::approval_subject`]. Persistence, sockets, the audit chain and the
//! long wait are the secrets service's (`ozbox-cli`, `approval_requests`).
//!
//! **Nothing here is on the path of `resolve` or `exec`.** A request is filed only after a gate has refused; the book is
//! kept in a journal of its own, so request churn never touches the lock the secrets store takes.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::approval_subject::{
    decide_challenge, from_hex, sanitize_display, to_hex, DisplayField, EnrolAction, Ids,
    PolicySensitivity, Subject,
};
use crate::approval_verify::{verify_laptop, verify_passkey_bytes, Expected};

/// A request waits this long for a decision (owner decision 1).
pub const PENDING_MS: u64 = 30 * 60_000;
/// Once approved, a request is good this long, and for one use.
pub const APPROVED_MS: u64 = 15 * 60_000;
/// A laptop key enrolled from the dashboard cannot approve until this has passed (ADR 0041 §3.1).
pub const COOLING_OFF_MS: u64 = 24 * 3_600_000;
pub const MAX_REASON: usize = 200;
/// Pending requests of one scope on the box socket (a flood bound; person-originated paths are outside it).
pub const MAX_PENDING_PER_SCOPE: usize = 8;
/// Filings an hour from one box-user uid.
pub const FILINGS_PER_HOUR: usize = 30;
/// Refused spends an hour from one box-user uid: a flood of refused spends cannot be used to flood.
pub const REFUSED_SPENDS_PER_HOUR: usize = 30;
/// A ceiling for one uid across every request id it names, and one for the whole list: the per-request count alone is keyed
/// on a caller-chosen id, so it cannot bound the list (phase 2 re-check NM2).
pub const REFUSED_SPENDS_PER_UID_PER_HOUR: usize = 120;
pub const REFUSED_SPENDS_MAX: usize = 1024;

/// Whether `id` has the shape of a request id the service made (`random_b32(16)`: 26 characters of lowercase base32). Anything
/// else names no request, so a refusal for it costs no journal space (phase 2 re-check NM2).
pub fn request_id_ok(id: &str) -> bool {
    id.len() == 26
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
}
/// Requests kept in a journal, live and finished.
pub const MAX_REQUESTS: usize = 512;
/// The longest the service holds one `await`, and the caps that keep it bounded (ADR 0041 §6).
pub const AWAIT_MAX_MS: u64 = 60_000;
pub const AWAITS_PER_UID: usize = 16;
pub const AWAITS_PER_REQUEST: usize = 4;
const MAX_SEEN: usize = 1024;

// ---------------------------------------------------------------------------------------------------------------------
// scopes, surfaces, factors, roles
// ---------------------------------------------------------------------------------------------------------------------

/// Every scope a request can be for. `SecretUse` is a Production use (ADR 0029): it appears in the table and the inbox,
/// but its store is the issuer's, so it is never filed here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Scope {
    Import,
    Policy,
    TunnelToken,
    GuardOverride,
    SignerEnroll,
    BoxSecrets,
    HostGuard,
    SetupCode,
    KekExport,
    WorkerKeys,
    SecretUse,
}

impl Scope {
    pub const ALL: [Scope; 11] = [
        Scope::Import,
        Scope::Policy,
        Scope::TunnelToken,
        Scope::GuardOverride,
        Scope::SignerEnroll,
        Scope::BoxSecrets,
        Scope::HostGuard,
        Scope::SetupCode,
        Scope::KekExport,
        Scope::WorkerKeys,
        Scope::SecretUse,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Import => "import",
            Scope::Policy => "policy",
            Scope::TunnelToken => "tunnel-token",
            Scope::GuardOverride => "guard-override",
            Scope::SignerEnroll => "signer-enroll",
            Scope::BoxSecrets => "box-secrets",
            Scope::HostGuard => "host-guard",
            Scope::SetupCode => "setup-code",
            Scope::KekExport => "kek-export",
            Scope::WorkerKeys => "worker-keys",
            Scope::SecretUse => "secret-use",
        }
    }

    pub fn parse(s: &str) -> Option<Scope> {
        Scope::ALL.into_iter().find(|x| x.as_str() == s)
    }
}

/// Who asks, as the kernel and the socket class say, never as the client claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RequesterKind {
    BoxUser,
    Supervisor,
    RootHelper,
    HubAgent,
    LaptopKey,
}

impl RequesterKind {
    pub fn as_str(self) -> &'static str {
        match self {
            RequesterKind::BoxUser => "box-user",
            RequesterKind::Supervisor => "supervisor",
            RequesterKind::RootHelper => "root-helper",
            RequesterKind::HubAgent => "hub-agent",
            RequesterKind::LaptopKey => "laptop-key",
        }
    }
}

/// The socket a request came in on. The service maps its policies to these; ingress and the hub agent have no socket in
/// this build yet (phases 2 and 4), but their rows are here so the table is whole and tested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SocketClass {
    Box,
    Supervisor,
    Admin,
    Ingress,
    HubAgent,
}

impl SocketClass {
    pub fn requester_kind(self) -> RequesterKind {
        match self {
            SocketClass::Box => RequesterKind::BoxUser,
            SocketClass::Supervisor => RequesterKind::Supervisor,
            SocketClass::Admin => RequesterKind::RootHelper,
            SocketClass::Ingress => RequesterKind::LaptopKey,
            SocketClass::HubAgent => RequesterKind::HubAgent,
        }
    }
}

/// The operations of the request service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Capabilities,
    File,
    Get,
    List,
    Await,
    DecideChallenge,
    Decide,
    Spend,
    Finish,
    Cancel,
    DeciderRevoked,
    NewEpoch,
    ClearMarkers,
}

/// Which operations a socket class offers (ADR 0041 §7). The box socket can file, wait, read its own and spend a
/// `guard-override`; it never decides. The supervisor's socket decides (after it has verified the assertion) but neither
/// files nor spends. Root files, waits, spends and decides as `root`. Ingress is the laptop's sealed route. The hub agent
/// relays: it lists, reads, and relays a decision.
pub fn op_allowed(class: SocketClass, op: Op) -> bool {
    use Op::*;
    use SocketClass::*;
    matches!(
        (class, op),
        (_, Capabilities)
            | (Box, File | Get | List | Await | Spend | Finish)
            | (
                Supervisor,
                List | Get | DecideChallenge | Decide | Cancel | DeciderRevoked
            )
            | (
                Admin,
                File | Get
                    | List
                    | Await
                    | Spend
                    | Finish
                    | Decide
                    | Cancel
                    | NewEpoch
                    | ClearMarkers
            )
            | (
                Ingress,
                File | Get | List | Await | DecideChallenge | Decide | Cancel
            )
            | (HubAgent, List | Get | Decide)
    )
}

/// Where a decision was made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Surface {
    Dashboard,
    Laptop,
    Telegram,
    Root,
    Bootstrap,
    HubRelay,
}

impl Surface {
    pub fn as_str(self) -> &'static str {
        match self {
            Surface::Dashboard => "dashboard",
            Surface::Laptop => "laptop",
            Surface::Telegram => "telegram",
            Surface::Root => "root",
            Surface::Bootstrap => "bootstrap",
            Surface::HubRelay => "hub-relay",
        }
    }
}

/// How it was confirmed. Honest in the record: never "chat", and never `passkey` for an authenticator code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Factor {
    Passkey,
    LaptopKey,
    Root,
    Bootstrap,
    /// A Deny relayed from a chat: no credential at all (a Deny is fail safe).
    ChatDeny,
    /// A signed-in dashboard session with no passkey: it may only deny or revoke (both fail safe), never approve. The record
    /// says so, so it is never read as a passkey decision.
    Session,
    /// An authenticator-app code (RFC 6238) of a signed-in dashboard person who has no passkey, checked by the secrets service
    /// itself against that person's authenticator secret in its own store. Unlike a passkey it is not bound to the request
    /// (a six-digit code cannot sign a digest), so the record says `authenticator` and never `passkey`. The service accepts
    /// each time step once per person (the step is kept as the counter).
    Authenticator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    Viewer,
    Member,
    Owner,
}

/// The kinds of laptop key (ADR 0041 §3). A Secure Enclave key is `Ed25519` or `WebauthnP256` without a verified
/// attestation, so it is a software key by the rule of presence being proved, never declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyType {
    Ed25519,
    SkEd25519,
    EcdsaSk,
    WebauthnP256,
}

impl KeyType {
    pub fn parse(s: &str) -> Option<KeyType> {
        match s {
            "ed25519" => Some(KeyType::Ed25519),
            "sk-ssh-ed25519" => Some(KeyType::SkEd25519),
            "ecdsa-sk" => Some(KeyType::EcdsaSk),
            "webauthn-p256" => Some(KeyType::WebauthnP256),
            _ => None,
        }
    }
    pub fn is_fido2(self) -> bool {
        !matches!(self, KeyType::Ed25519)
    }
}

/// The shape of a signature, recorded and never assumed: a FIDO2 or `sk` signature covers `authData || H(message)`, not
/// the message alone (ADR 0041 §1, check K1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignatureFormat {
    /// An Ed25519 signature over the message.
    Ed25519Message,
    /// An `sk-ssh-ed25519` / `ecdsa-sk` signature over `application || flags || counter || H(message)`.
    SshSk,
    /// A WebAuthn assertion: a signature over `authData || H(clientData)`.
    WebauthnAssertion,
}

/// The presence class of a key, recorded on enrolment and on every decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PresenceClass {
    /// A FIDO2 key whose attestation verified: it needs a touch.
    Proved,
    /// Every other key.
    NoPresence,
    /// A passkey, root or bootstrap: the class does not apply.
    NotApplicable,
}

/// A laptop key as the service knows it (read from its own records, never from the laptop's claim).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyView {
    pub id: String,
    pub key_type: KeyType,
    /// Set only when a verifier accepted the key's attestation at enrolment (format `packed` with an `x5c` chain, or
    /// `fido-u2f`, to a pinned vendor root, bound to the enrolment challenge). Never set by a request.
    pub presence_proved: bool,
    pub attestation_digest: Option<String>,
    /// The key's public half in hex, from the service's own record of it (never from the evidence). The signature of a
    /// laptop decision is verified with it (see `approval_verify`).
    pub public_half: String,
    /// False once the key was revoked: an approval it gave then dies at spend (§2).
    pub active: bool,
    /// An `sk` key's application (`ssh:` unless it was made with another): what its signature hashes.
    #[serde(default)]
    pub application: Option<String>,
    /// A `webauthn-p256` key's relying party, recorded at enrolment: its assertions must be for it.
    #[serde(default)]
    pub rp: Option<crate::approval_verify::ExpectedRp>,
}

/// The evidence of a passkey assertion, as the supervisor verified it in this release. The service stores it so a later
/// move of the check into the service (phase 5) makes old decisions verifiable. The challenge, the flags and the counter
/// are read from `client_data` and `authenticator_data` (both in hex), never sent as fields of their own.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PasskeyEvidence {
    pub credential_id: String,
    pub authenticator_data: String,
    pub client_data: String,
    pub signature: String,
}

/// The evidence of a laptop key's signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaptopEvidence {
    pub key_id: String,
    pub key_type: KeyType,
    pub signature_format: SignatureFormat,
    /// The message that was signed, in hex (bounded): the decide message, or a WebAuthn clientDataJSON.
    pub signed_message: String,
    pub signature: String,
    /// The authenticator data in hex, where the format has it (see `approval_verify` for each format). The flags and the
    /// counter are read from it, never sent as fields of their own.
    #[serde(default)]
    pub authenticator_data: Option<String>,
    /// The digest of the attestation the key was enrolled with.
    #[serde(default)]
    pub attestation_digest: Option<String>,
}

/// The evidence of an authenticator-app code, as the **service** verified it: the time step the code was for. Never the code
/// itself, and never taken from the wire (the service builds it after its own check of the code).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatorEvidence {
    pub step: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Evidence {
    #[serde(default)]
    pub passkey: Option<PasskeyEvidence>,
    #[serde(default)]
    pub laptop: Option<LaptopEvidence>,
    /// Set only by the secrets service after it checked the code itself (see [`Factor::Authenticator`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticator: Option<AuthenticatorEvidence>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    Approve,
    Deny,
    /// A deny of an approved, unspent request.
    Revoke,
}

impl Outcome {
    /// The word a challenge and a message name (see `approval_subject::DECIDE_OUTCOMES`).
    pub fn word(self) -> &'static str {
        match self {
            Outcome::Approve => "approve",
            Outcome::Deny => "deny",
            Outcome::Revoke => "revoke",
        }
    }
}

/// The decision record (ADR 0041 §1 `decision`): who, through which surface, which factor, the key's presence class,
/// when, and the evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub outcome: Outcome,
    /// A person id, a laptop key id, `root` or `bootstrap`.
    pub decider: String,
    pub role: Option<Role>,
    pub surface: Surface,
    pub factor: Factor,
    pub presence: PresenceClass,
    /// `passkey`, `laptop-key:<id>`, `laptop-key:<id> (no user presence)`, `root`, `bootstrap`.
    pub factor_label: String,
    pub at_ms: u64,
    pub evidence: Evidence,
    /// What the signature proved, read from the signed bytes by the verifier (display only: no rule reads it back).
    #[serde(default)]
    pub proven: Option<Proven>,
    /// Set when the decision came from `main` for a worker: `fleet:<main id>`.
    #[serde(default)]
    pub via_fleet: Option<String>,
}

/// User presence, user verification and the counter, as parsed from the signed bytes of a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proven {
    pub up: bool,
    pub uv: bool,
    pub counter: Option<u32>,
}

impl Decision {
    /// How much a decision outranks another (a revoke needs the same or higher authority).
    pub fn authority(&self) -> u8 {
        match (self.factor, self.presence, self.role) {
            (Factor::Root, _, _) => 5,
            (Factor::LaptopKey, PresenceClass::Proved, _) => 4,
            (Factor::Passkey | Factor::Authenticator | Factor::Session, _, Some(Role::Owner)) => 3,
            (Factor::Passkey | Factor::Authenticator | Factor::Session, _, Some(Role::Member)) => 2,
            (Factor::LaptopKey, _, _) => 1,
            _ => 0,
        }
    }
}

/// The factor word of the record.
pub fn factor_label(factor: Factor, key: Option<&KeyView>) -> String {
    match (factor, key) {
        (Factor::Passkey, _) => "passkey".into(),
        (Factor::LaptopKey, Some(k)) if k.presence_proved => format!("laptop-key:{}", k.id),
        (Factor::LaptopKey, Some(k)) => format!("laptop-key:{} (no user presence)", k.id),
        (Factor::LaptopKey, None) => "laptop-key:unknown (no user presence)".into(),
        (Factor::Root, _) => "root".into(),
        (Factor::Bootstrap, _) => "bootstrap".into(),
        (Factor::ChatDeny, _) => "chat-deny".into(),
        (Factor::Session, _) => "dashboard session (no passkey)".into(),
        (Factor::Authenticator, _) => "authenticator".into(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum State {
    Pending,
    Approved,
    /// Being spent: a crash here leaves the request refused and shown, never spent twice (fails closed).
    Spending,
    Spent,
    Denied,
    Cancelled,
    Superseded,
    Expired,
}

impl State {
    pub fn is_terminal(self) -> bool {
        !matches!(self, State::Pending | State::Approved | State::Spending)
    }
    pub fn as_str(self) -> &'static str {
        match self {
            State::Pending => "pending",
            State::Approved => "approved",
            State::Spending => "spending",
            State::Spent => "spent",
            State::Denied => "denied",
            State::Cancelled => "cancelled",
            State::Superseded => "superseded",
            State::Expired => "expired",
        }
    }
}

/// Who filed, from the kernel's word.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Requester {
    pub kind: RequesterKind,
    pub uid: Option<u32>,
    /// For a laptop-filed request: the key id.
    #[serde(default)]
    pub key_id: Option<String>,
    #[serde(default)]
    pub run_id: Option<String>,
    #[serde(default)]
    pub engine: Option<String>,
    /// What the client claims about itself; kept as `claimed=` and never believed.
    #[serde(default)]
    pub claimed: Option<String>,
}

impl Requester {
    pub fn new(kind: RequesterKind, uid: Option<u32>) -> Self {
        Requester {
            kind,
            uid,
            key_id: None,
            run_id: None,
            engine: None,
            claimed: None,
        }
    }
}

/// Facts the service derives (never the filer) and the rules read. In the record, so a decision is judged by what was
/// known when the request was filed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Derived {
    /// An import replaces a value already stored (a replacement needs the owner).
    #[serde(default)]
    pub replaces_existing: bool,
    /// A policy change's sensitivity as the service computed it from the old and the new policy (see
    /// `approval_subject::policy_sensitivity`). The filer's own label is only ever compared with this.
    #[serde(default)]
    pub policy_sensitivity: Option<PolicySensitivity>,
}

/// One request (ADR 0041 §1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub id: String,
    pub scope: Scope,
    /// `local`, or the hub's id when the request was filed on a worker and is shown on `main` (ADR 0042).
    pub origin: String,
    pub subject: Subject,
    /// The subject digest in hex, computed by [`Subject::digest`].
    pub subject_digest: String,
    pub display: Vec<DisplayField>,
    /// From the requester, at most 200 characters, shown quoted and labelled "from the box".
    pub reason: Option<String>,
    pub requester: Requester,
    /// `(requester kind and uid, scope, operation key)`.
    pub slot: String,
    pub epoch: String,
    pub filed_at_ms: u64,
    /// Pending: filing plus 30 minutes. Approved: the decision (or the end of a cooling-off) plus 15 minutes.
    pub expires_at_ms: u64,
    /// Not before: a laptop key enrolled from the dashboard waits 24 hours (ADR 0041 §3.1).
    #[serde(default)]
    pub not_before_ms: u64,
    pub state: State,
    pub decision: Option<Decision>,
    pub derived: Derived,
    /// The request this one replaces: "replaces a request Alice approved at 12:03".
    #[serde(default)]
    pub replaces: Option<String>,
    #[serde(default)]
    pub superseded_by: Option<String>,
    #[serde(default)]
    pub void_reason: Option<String>,
    /// Refused spends against this request (counted, never burning it).
    #[serde(default)]
    pub wrong_answers: u32,
}

impl Request {
    /// What to say about a request that is no longer pending: who decided it and how, or its state.
    pub fn state_sentence(&self) -> String {
        self.decision.as_ref().map_or_else(
            || format!("the request is {}", self.state.as_str()),
            decided_sentence,
        )
    }

    /// The envelope the service signs so the hub can carry it (ADR 0042): the box and the store it is for, and where the
    /// request came from, are inside it, so a verifier can recompute the subject digest from the signed fields alone.
    pub fn envelope(&self, ids: &Ids) -> Envelope {
        Envelope {
            box_id: ids.box_id.clone(),
            store_id: ids.store_id.clone(),
            origin: self.origin.clone(),
            id: self.id.clone(),
            scope: self.scope,
            subject: self.subject.clone(),
            subject_digest: self.subject_digest.clone(),
            requester: self.requester.clone(),
            expires_at_ms: self.expires_at_ms,
            state: self.state,
            epoch: self.epoch.clone(),
        }
    }

    /// What the box user's socket may see of its own request: id, scope, state, expiry and the digest. Never a
    /// fingerprint, a "changed" flag or anything derived from a value.
    pub fn box_view(&self) -> BoxView {
        BoxView {
            id: self.id.clone(),
            scope: self.scope,
            state: self.state,
            expires_at_ms: self.expires_at_ms,
            subject_digest: self.subject_digest.clone(),
        }
    }
}

/// The envelope: the box id, the store id, the origin, then id, scope, subject, digest, requester, expiry, state and epoch.
/// The service signs its canonical JSON (compact, this field order) with an Ed25519 key it holds, so the hub can carry it.
/// Unknown fields are refused, so an extra field cannot ride along unsigned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub box_id: String,
    pub store_id: String,
    pub origin: String,
    pub id: String,
    pub scope: Scope,
    pub subject: Subject,
    pub subject_digest: String,
    pub requester: Requester,
    pub expires_at_ms: u64,
    pub state: State,
    pub epoch: String,
}

/// A signed envelope. It holds the exact signed text and the signature, and nothing a verifier could read instead: the
/// body is whatever [`SignedEnvelope::verify`] parses out of `canonical`, and the key is the verifier's own pin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEnvelope {
    /// The exact JSON text of the envelope that was signed (compact, the field order of [`Envelope`]).
    pub canonical: String,
    /// `ed25519`.
    pub alg: String,
    /// The signature, in hex, over the hex of `digest_fields(ENVELOPE_TAG, [canonical])`.
    pub signature: String,
}

impl SignedEnvelope {
    /// The message the signature is over: the hex of the tagged digest of the canonical text.
    pub fn signed_message(canonical: &str) -> String {
        to_hex(&crate::approval_subject::digest_fields(
            crate::approval_subject::ENVELOPE_TAG,
            &[canonical.as_bytes()],
        ))
    }

    /// The canonical text of an envelope: compact, the field order of [`Envelope`].
    pub fn canonical_of(envelope: &Envelope) -> Result<String, String> {
        serde_json::to_string(envelope).map_err(|_| "the envelope could not be written".to_string())
    }

    /// The only way to read an envelope. Checks the signature against the **pinned** key (never one the envelope carries),
    /// parses the signed text (not any copy beside it), requires that text to be the canonical form, requires the box and
    /// store it names to be `ids`, and recomputes the subject digest from the signed subject. Refuses anything else.
    pub fn verify(&self, pinned_key_hex: &str, ids: &Ids) -> Result<Envelope, String> {
        if self.alg != "ed25519" {
            return Err("that envelope's algorithm is not known".into());
        }
        let key = from_hex(pinned_key_hex).ok_or("the pinned key is not valid")?;
        let sig = from_hex(&self.signature).ok_or("the signature is not valid")?;
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key)
            .verify(Self::signed_message(&self.canonical).as_bytes(), &sig)
            .map_err(|_| "that envelope's signature is not valid".to_string())?;
        let env: Envelope = serde_json::from_str(&self.canonical)
            .map_err(|_| "that envelope is not valid".to_string())?;
        if Self::canonical_of(&env)? != self.canonical {
            return Err("that envelope is not in its canonical form".into());
        }
        if env.box_id != ids.box_id || env.store_id != ids.store_id {
            return Err("that envelope is for another box or another store".into());
        }
        if env.subject.digest_hex(ids).map_err(|e| e.0)? != env.subject_digest
            || env.subject.scope() != env.scope.as_str()
        {
            return Err("that envelope's digest is not its subject's".into());
        }
        Ok(env)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoxView {
    pub id: String,
    pub scope: Scope,
    pub state: State,
    pub expires_at_ms: u64,
    pub subject_digest: String,
}

// ---------------------------------------------------------------------------------------------------------------------
// the rule table
// ---------------------------------------------------------------------------------------------------------------------

/// What the dashboard's one assertion may decide (ADR 0041 §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dash {
    /// Owner or member.
    OwnerOrMember,
    /// New names in a non-Production environment, none public, none a replacement: owner or member. Anything else: owner.
    ImportRule,
    Owner,
    /// Owner, only until a presence key has ever been enrolled (the sticky narrowing, Delegated decision 1).
    OwnerUntilPresenceKey,
    /// Owner; a policy that turns software keys on, or (after a presence key) widens a guarded scope, is not decidable here.
    PolicyRule,
    /// Revoke: owner, any time. Enrol: owner; a later key (not the first ever) waits 24 hours.
    EnrolRule,
    /// Not on the dashboard at all.
    NotDecidable,
    /// The issuer's (ADR 0029), not decided here.
    Issuer,
    /// Another store's (the agent's permission engine, tool requests): the row is for the inbox.
    OwnStore,
}

impl Dash {
    pub fn as_str(self) -> &'static str {
        match self {
            Dash::OwnerOrMember => "owner-or-member",
            Dash::ImportRule => "import-rule",
            Dash::Owner => "owner",
            Dash::OwnerUntilPresenceKey => "owner-until-presence-key",
            Dash::PolicyRule => "policy-rule",
            Dash::EnrolRule => "enrol-rule",
            Dash::NotDecidable => "not-decidable",
            Dash::Issuer => "issuer",
            Dash::OwnStore => "own-store",
        }
    }
}

/// What a software laptop key (no proved presence) may decide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Soft {
    /// What a member may decide: never Production.
    MemberLevel,
    /// New non-Production names only; never Production.
    NewNonProductionNames,
    /// Never, not even opted in.
    Never,
    NotApplicable,
}

impl Soft {
    pub fn as_str(self) -> &'static str {
        match self {
            Soft::MemberLevel => "member-level",
            Soft::NewNonProductionNames => "new-non-production-names",
            Soft::Never => "never",
            Soft::NotApplicable => "not-applicable",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Telegram {
    /// Every row, with no exception (owner decision, 2026-11-12): a chat app sends a message with the request's details and a
    /// link to the dashboard's approval page, and **never approves, denies, cancels or stops** anything, the ordinary agent
    /// action on the ask list included.
    NotifyOnly,
}

impl Telegram {
    pub fn as_str(self) -> &'static str {
        match self {
            Telegram::NotifyOnly => "notify-only",
        }
    }
}

/// Which socket class recomputes the digest, and so is the only one that may spend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpendBy {
    /// The box user's hook, on the box socket.
    BoxSocket,
    /// The root helper, on the admin socket.
    AdminSocket,
    /// Inside the operation itself (the service recomputes), never as a separate `spend`.
    Inside,
    NotApplicable,
}

impl SpendBy {
    pub fn as_str(self) -> &'static str {
        match self {
            SpendBy::BoxSocket => "box-socket",
            SpendBy::AdminSocket => "admin-socket",
            SpendBy::Inside => "inside",
            SpendBy::NotApplicable => "not-applicable",
        }
    }
}

/// What a box with no approver yet may do in a scope (mirrors `secrets_approval::SCOPE_RULES`; a test keeps them equal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Boot {
    Allowed,
    FirstSettingOnly,
    Refused,
}

impl Boot {
    pub fn as_str(self) -> &'static str {
        match self {
            Boot::Allowed => "allowed",
            Boot::FirstSettingOnly => "first-setting-only",
            Boot::Refused => "refused",
        }
    }
}

/// One row of the table. Data, so the dashboard and the chat bridge read the same rows ([`rule_table_ts`]).
#[derive(Debug, Clone, Copy)]
pub struct Rule {
    pub key: &'static str,
    /// Filed in this journal. False for rows whose store is another's (agent actions, Production use).
    pub journal: bool,
    pub filers: &'static [RequesterKind],
    pub dashboard: Dash,
    /// A laptop key with proved presence may decide it.
    pub laptop_presence: bool,
    pub software: Soft,
    pub telegram: Telegram,
    pub spend_by: SpendBy,
    pub bootstrap: Boot,
}

use RequesterKind as K;

/// The rule table (ADR 0041 §3.1). A scope that is not in it is refused everywhere.
pub const RULES: &[Rule] = &[
    Rule {
        key: "import",
        journal: true,
        filers: &[K::LaptopKey, K::RootHelper],
        dashboard: Dash::ImportRule,
        laptop_presence: true,
        software: Soft::NewNonProductionNames,
        telegram: Telegram::NotifyOnly,
        spend_by: SpendBy::Inside,
        bootstrap: Boot::Allowed,
    },
    Rule {
        key: "policy",
        journal: true,
        filers: &[K::Supervisor, K::LaptopKey, K::RootHelper],
        dashboard: Dash::PolicyRule,
        laptop_presence: true,
        software: Soft::Never,
        telegram: Telegram::NotifyOnly,
        spend_by: SpendBy::Inside,
        // with no second factor a declaration that hands a command a secret is refused (ADR 0029 Amendment 10, N-C1); the
        // secrets service's SCOPE_RULES says the same, and a test holds the two together
        bootstrap: Boot::FirstSettingOnly,
    },
    Rule {
        key: "tunnel-token",
        journal: true,
        filers: &[K::RootHelper, K::LaptopKey],
        dashboard: Dash::OwnerUntilPresenceKey,
        laptop_presence: true,
        software: Soft::Never,
        telegram: Telegram::NotifyOnly,
        spend_by: SpendBy::AdminSocket,
        bootstrap: Boot::Allowed,
    },
    Rule {
        key: "guard-override",
        journal: true,
        filers: &[K::BoxUser],
        dashboard: Dash::OwnerOrMember,
        laptop_presence: true,
        software: Soft::MemberLevel,
        telegram: Telegram::NotifyOnly,
        spend_by: SpendBy::BoxSocket,
        // a box with no second factor refuses it: the box user would be approving its own override; the secrets
        // service's SCOPE_RULES says the same, and a test holds the two together
        bootstrap: Boot::Refused,
    },
    Rule {
        key: "signer-enroll",
        journal: true,
        filers: &[K::Supervisor, K::LaptopKey, K::RootHelper],
        dashboard: Dash::EnrolRule,
        laptop_presence: true,
        software: Soft::Never,
        telegram: Telegram::NotifyOnly,
        spend_by: SpendBy::Inside,
        bootstrap: Boot::Refused,
    },
    Rule {
        key: "box-secrets",
        journal: true,
        filers: &[K::RootHelper, K::LaptopKey],
        dashboard: Dash::Owner,
        laptop_presence: true,
        software: Soft::Never,
        telegram: Telegram::NotifyOnly,
        spend_by: SpendBy::AdminSocket,
        bootstrap: Boot::FirstSettingOnly,
    },
    Rule {
        key: "host-guard",
        journal: true,
        filers: &[K::RootHelper],
        dashboard: Dash::OwnerUntilPresenceKey,
        laptop_presence: true,
        software: Soft::Never,
        telegram: Telegram::NotifyOnly,
        spend_by: SpendBy::AdminSocket,
        bootstrap: Boot::Refused,
    },
    Rule {
        key: "setup-code",
        journal: true,
        filers: &[K::LaptopKey],
        dashboard: Dash::NotDecidable,
        laptop_presence: true,
        software: Soft::Never,
        telegram: Telegram::NotifyOnly,
        spend_by: SpendBy::Inside,
        // ADR 0029 A9 §6 M1: with no second factor on the box it is allowed, as the other first settings are, and recorded
        bootstrap: Boot::Allowed,
    },
    Rule {
        key: "kek-export",
        journal: true,
        filers: &[K::LaptopKey],
        dashboard: Dash::NotDecidable,
        laptop_presence: true,
        software: Soft::Never,
        telegram: Telegram::NotifyOnly,
        spend_by: SpendBy::Inside,
        // ADR 0029 A9 refused before a second factor exists (an escrow anyone with only the SSH key can take
        // protects nothing), as `secrets_approval::SCOPE_RULES` says
        bootstrap: Boot::Refused,
    },
    Rule {
        key: "worker-keys",
        journal: true,
        // fails closed today: `op_allowed(HubAgent, File)` is false until phase 4 (ADR 0042) gives the hub its own filing
        // socket, which is where this is made true; it is not made true by widening the hub socket
        filers: &[K::HubAgent],
        dashboard: Dash::Owner,
        laptop_presence: true,
        software: Soft::Never,
        telegram: Telegram::NotifyOnly,
        spend_by: SpendBy::Inside,
        bootstrap: Boot::Refused,
    },
    // the issuer's own store (ADR 0029): a row for the inbox and the audit words, never filed here
    Rule {
        key: "secret-use",
        journal: false,
        filers: &[],
        dashboard: Dash::Issuer,
        laptop_presence: true,
        software: Soft::Never,
        telegram: Telegram::NotifyOnly,
        spend_by: SpendBy::NotApplicable,
        bootstrap: Boot::Refused,
    },
    // the supervisor's permission engine and tool requests keep their stores; the envelope, table, inbox and audit words are shared
    Rule {
        key: "agent-action",
        journal: false,
        filers: &[],
        dashboard: Dash::OwnStore,
        laptop_presence: false,
        software: Soft::NotApplicable,
        telegram: Telegram::NotifyOnly,
        spend_by: SpendBy::NotApplicable,
        bootstrap: Boot::Refused,
    },
    Rule {
        key: "agent-action-protected",
        journal: false,
        filers: &[],
        dashboard: Dash::OwnStore,
        laptop_presence: false,
        software: Soft::NotApplicable,
        telegram: Telegram::NotifyOnly,
        spend_by: SpendBy::NotApplicable,
        bootstrap: Boot::Refused,
    },
    Rule {
        key: "agent-action-production",
        journal: false,
        filers: &[],
        dashboard: Dash::OwnStore,
        laptop_presence: false,
        software: Soft::NotApplicable,
        telegram: Telegram::NotifyOnly,
        spend_by: SpendBy::NotApplicable,
        bootstrap: Boot::Refused,
    },
];

/// The row for a scope, or `None` for a scope this version does not know (refused everywhere).
pub fn rule_for(scope: &str) -> Option<&'static Rule> {
    RULES.iter().find(|r| r.key == scope)
}

/// The rule table as TypeScript, for the dashboard (`packages/dashboard/src/api/approval-rules.ts`). A Rust test
/// compares the file with this text, as it does for `APPROVAL_SCOPES`, so a row added here is offered there.
pub fn rule_table_ts() -> String {
    let q = |v: &[&str]| {
        v.iter()
            .map(|s| format!("'{s}'"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut s = String::new();
    s.push_str("// Generated from crates/ozbox-core/src/approval.rs (RULES). Do not edit by hand: a Rust test compares this file\n");
    s.push_str("// with the table and fails when they differ. Regenerate with `OZBOX_WRITE_APPROVAL_RULES=1 cargo test -p ozbox-cli the_dashboards_copy_of_the_rule_table`.\n\n");
    s.push_str("export interface ApprovalRule {\n  scope: string;\n  journal: boolean;\n  filers: readonly string[];\n  dashboard: string;\n  laptopPresence: boolean;\n  software: string;\n  telegram: string;\n  spendBy: string;\n  bootstrap: string;\n}\n\n");
    s.push_str("export const APPROVAL_RULES: readonly ApprovalRule[] = [\n");
    for r in RULES {
        let filers: Vec<&str> = r.filers.iter().map(|k| k.as_str()).collect();
        s.push_str(&format!(
            "  {{ scope: '{}', journal: {}, filers: [{}], dashboard: '{}', laptopPresence: {}, software: '{}', telegram: '{}', spendBy: '{}', bootstrap: '{}' }},\n",
            r.key,
            r.journal,
            q(&filers),
            r.dashboard.as_str(),
            r.laptop_presence,
            r.software.as_str(),
            r.telegram.as_str(),
            r.spend_by.as_str(),
            r.bootstrap.as_str(),
        ));
    }
    s.push_str("] as const;\n\n");
    let journal: Vec<&str> = RULES.iter().filter(|r| r.journal).map(|r| r.key).collect();
    s.push_str(&format!(
        "export const APPROVAL_REQUEST_SCOPES = [{}] as const;\n",
        q(&journal)
    ));
    s
}

// ---------------------------------------------------------------------------------------------------------------------
// the book: the state machine
// ---------------------------------------------------------------------------------------------------------------------

/// What the service knows about the box that the rules read. Built by the service from its own store, never from a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ctx {
    pub ids: Ids,
    /// A second factor exists (the bootstrap marker is set). False: the box has no approver yet.
    pub enrolled: bool,
    /// This box has ever had a laptop key. Cleared only by root, carried over a replace or a recovery.
    pub ever_key: bool,
    /// This box has ever had a presence key (the sticky marker; not a policy field).
    pub ever_presence_key: bool,
}

/// What a decision carries in. The service builds it from the socket class, its own key records and what the supervisor
/// verified; a wire request names only the outcome, the person and the evidence.
#[derive(Debug, Clone)]
pub struct DecideInput {
    pub class: SocketClass,
    pub outcome: Outcome,
    pub surface: Surface,
    pub factor: Factor,
    pub decider: String,
    pub role: Option<Role>,
    pub evidence: Evidence,
    /// The laptop key as the service's own records have it (laptop factor only).
    pub key: Option<KeyView>,
    /// The relying party the dashboard passkey assertion must be for (the supervisor's word until phase 5).
    pub passkey_rp: Option<crate::approval_verify::ExpectedRp>,
    pub via_fleet: Option<String>,
}

/// A request's journal and the counters beside it. Pure data; the service persists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestBook {
    pub epoch: String,
    pub requests: Vec<Request>,
    /// Hashes of assertions and signatures already used (an assertion decides one request, once).
    #[serde(default)]
    pub seen: Vec<String>,
    /// The last counter per credential or key; a non-zero counter that goes back is refused.
    #[serde(default)]
    pub counters: BTreeMap<String, u32>,
    /// Filings by a box-user uid, in the last hour.
    #[serde(default)]
    pub filings: Vec<(String, u64)>,
    #[serde(default)]
    pub refused_spends: Vec<(String, u64)>,
}

/// What a filer brings: the new id (random, from the caller), the typed subject, who the kernel says it is, the reason and
/// the facts the service derived.
#[derive(Debug, Clone)]
pub struct Filing<'a> {
    pub id: String,
    pub subject: Subject,
    pub requester: Requester,
    pub reason: Option<&'a str>,
    pub derived: Derived,
}

/// What `file` answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filed {
    pub request: Request,
    /// The same digest in the same slot: the request that was already there.
    pub existing: bool,
}

fn hhmm(ms: u64) -> String {
    let s = ms / 1000;
    format!("{:02}:{:02} UTC", (s / 3600) % 24, (s / 60) % 60)
}

fn decided_sentence(d: &Decision) -> String {
    let what = match d.outcome {
        Outcome::Approve => "approved",
        Outcome::Deny => "denied",
        Outcome::Revoke => "revoked",
    };
    format!(
        "already {what} by {} on the {} ({}), {}",
        d.decider,
        d.surface.as_str(),
        d.factor_label,
        hhmm(d.at_ms)
    )
}

impl RequestBook {
    pub fn new(epoch: String) -> Self {
        RequestBook {
            epoch,
            requests: Vec::new(),
            seen: Vec::new(),
            counters: BTreeMap::new(),
            filings: Vec::new(),
            refused_spends: Vec::new(),
        }
    }

    pub fn get(&self, id: &str) -> Option<&Request> {
        self.requests.iter().find(|r| r.id == id)
    }

    fn get_mut(&mut self, id: &str) -> Option<&mut Request> {
        self.requests.iter_mut().find(|r| r.id == id)
    }

    /// Move time forward: a request of another epoch is void (a restore brought it back), a pending one past 30 minutes
    /// and an approved one past its 15 are expired. Returns the ids that expired, for the audit line.
    pub fn sweep(&mut self, now_ms: u64) -> Vec<String> {
        let epoch = self.epoch.clone();
        let mut expired = Vec::new();
        for r in &mut self.requests {
            if r.state.is_terminal() {
                continue;
            }
            if r.epoch != epoch {
                r.state = State::Expired;
                r.void_reason = Some("requests were reset by a restore".into());
                expired.push(r.id.clone());
            } else if matches!(r.state, State::Pending | State::Approved)
                && now_ms >= r.expires_at_ms
            {
                r.state = State::Expired;
                expired.push(r.id.clone());
            }
        }
        self.filings
            .retain(|(_, t)| now_ms.saturating_sub(*t) < 3_600_000);
        self.refused_spends
            .retain(|(_, t)| now_ms.saturating_sub(*t) < 3_600_000);
        expired
    }

    /// Once a second factor is enrolled, a request that was approved as `bootstrap` (no approver existed) is void: the box
    /// now has someone who decides, so an approval it gave itself must not outlive that. Returns the ids.
    pub fn void_bootstrap_if_enrolled(&mut self, ctx: &Ctx) -> Vec<String> {
        let mut out = Vec::new();
        if !ctx.enrolled {
            return out;
        }
        for r in &mut self.requests {
            if r.state == State::Approved
                && r.decision
                    .as_ref()
                    .is_some_and(|d| d.factor == Factor::Bootstrap)
            {
                r.state = State::Denied;
                r.void_reason = Some(
                    "a second factor was enrolled since: a bootstrap approval ends there".into(),
                );
                out.push(r.id.clone());
            }
        }
        out
    }

    /// A new epoch (a store recovery, an adopt, a restore, a blue-green replace): every non-terminal request of an older
    /// epoch is void, and a record that comes back from a backup in state `approved` cannot be spent.
    pub fn new_epoch(&mut self, epoch: String, now_ms: u64) -> Vec<String> {
        self.epoch = epoch;
        self.sweep(now_ms)
    }

    /// Mark every request whose id the spent ledger (kept outside the journal) holds as spent: a journal copied back from
    /// a backup within one epoch cannot revive what was already spent.
    pub fn apply_spent_ledger<'a>(&mut self, ids: impl Iterator<Item = &'a str>) -> usize {
        let mut n = 0;
        for id in ids {
            if let Some(r) = self.get_mut(id) {
                // a request caught mid-spend stays `spending` (refused and shown); a live one is spent
                if matches!(r.state, State::Pending | State::Approved) {
                    r.state = State::Spent;
                    r.void_reason = Some("already used (the spent ledger holds it)".into());
                    n += 1;
                }
            }
        }
        n
    }

    fn slot_of(requester: &Requester, scope: Scope, subject: &Subject) -> String {
        format!(
            "{}:{}:{}:{}",
            requester.kind.as_str(),
            requester
                .uid
                .map_or_else(|| "-".to_string(), |u| u.to_string()),
            scope.as_str(),
            subject.operation_key()
        )
    }

    /// File a request. The same digest in the same slot returns the request already there. A different digest in the slot
    /// supersedes the older **pending** one, and never an approved one: the new request is a card of its own
    /// that says what it replaces.
    pub fn file(&mut self, ctx: &Ctx, now_ms: u64, filing: Filing<'_>) -> Result<Filed, String> {
        let Filing {
            id,
            subject,
            requester,
            reason,
            derived,
        } = filing;
        self.sweep(now_ms);
        self.void_bootstrap_if_enrolled(ctx);
        let scope = Scope::parse(subject.scope()).ok_or("that scope is not known")?;
        let rule = rule_for(scope.as_str()).ok_or("that scope is not known")?;
        if !rule.journal {
            return Err(format!(
                "a {} request is kept by its own gate, not here",
                scope.as_str()
            ));
        }
        if !rule.filers.contains(&requester.kind) {
            return Err(format!(
                "a {} request cannot be filed by the {}",
                scope.as_str(),
                requester.kind.as_str()
            ));
        }
        subject.validate().map_err(|e| e.0)?;
        // a policy's sensitivity is the service's reading of the old and the new policy, never the filer's label
        if let Subject::Policy(p) = &subject {
            if derived.policy_sensitivity != Some(p.sensitivity) {
                return Err("a policy change's sensitivity is worked out by the service from the old and the new policy, and this one does not match".into());
            }
        }
        // a Production-looking value is released through a Production use, never an override, bootstrap or not
        if subject.production_looking() {
            return Err("a Production-looking value is released through a Production use (ADR 0029), not an override".into());
        }
        let digest = subject.digest_hex(&ctx.ids).map_err(|e| e.0)?;
        let slot = Self::slot_of(&requester, scope, &subject);

        // a box with no approver yet: the scope's own first-setting rule, decided as `bootstrap`
        let bootstrap_ok = if ctx.enrolled {
            false
        } else {
            match rule.bootstrap {
                Boot::Refused => return Err(bootstrap_refusal(scope)),
                Boot::FirstSettingOnly => {
                    if !matches!(&subject, Subject::BoxSecrets(b) if b.first_setting) {
                        return Err(bootstrap_refusal(scope));
                    }
                    true
                }
                Boot::Allowed => true,
            }
        };

        // the same change in the same slot is the same request (a hook run again, a looping agent)
        if let Some(r) = self.requests.iter().find(|r| {
            r.slot == slot
                && r.epoch == self.epoch
                && r.subject_digest == digest
                && matches!(r.state, State::Pending | State::Approved)
        }) {
            return Ok(Filed {
                request: r.clone(),
                existing: true,
            });
        }

        // a flood bound for the box user's socket; person-originated paths are outside it
        if requester.kind == RequesterKind::BoxUser {
            let who = requester
                .uid
                .map_or_else(|| "-".to_string(), |u| u.to_string());
            let pending = self
                .requests
                .iter()
                .filter(|r| r.scope == scope && r.state == State::Pending)
                .count();
            if pending >= MAX_PENDING_PER_SCOPE {
                return Err("too many requests of this kind are waiting for a decision".into());
            }
            let mine = self.filings.iter().filter(|(w, _)| *w == who).count();
            if mine >= FILINGS_PER_HOUR {
                return Err(
                    "too many requests were filed in the last hour: wait, or ask the owner".into(),
                );
            }
            self.filings.push((who, now_ms));
        }

        if self.requests.len() >= MAX_REQUESTS {
            // drop the oldest finished requests first; live ones are never dropped to make room
            let mut finished: Vec<(u64, String)> = self
                .requests
                .iter()
                .filter(|r| r.state.is_terminal())
                .map(|r| (r.filed_at_ms, r.id.clone()))
                .collect();
            finished.sort();
            let drop: Vec<String> = finished
                .into_iter()
                .take(self.requests.len() - MAX_REQUESTS + 1)
                .map(|(_, i)| i)
                .collect();
            self.requests.retain(|r| !drop.contains(&r.id));
            if self.requests.len() >= MAX_REQUESTS {
                return Err("too many requests are waiting".into());
            }
        }

        // older pending requests in the slot are superseded; an approved one is left alone and named
        let mut replaces = None;
        for r in &mut self.requests {
            if r.slot == slot && r.epoch == self.epoch {
                match r.state {
                    State::Pending => {
                        r.state = State::Superseded;
                        r.superseded_by = Some(id.clone());
                    }
                    State::Approved => replaces = Some(r.id.clone()),
                    _ => {}
                }
            }
        }

        let reason = reason
            .map(|r| sanitize_display(r.trim(), MAX_REASON))
            .filter(|r| !r.is_empty());
        let req = Request {
            id,
            scope,
            origin: "local".into(),
            display: subject.display(),
            subject,
            subject_digest: digest,
            reason,
            requester,
            slot,
            epoch: self.epoch.clone(),
            filed_at_ms: now_ms,
            expires_at_ms: now_ms + PENDING_MS,
            not_before_ms: 0,
            state: State::Pending,
            decision: None,
            derived,
            replaces,
            superseded_by: None,
            void_reason: None,
            wrong_answers: 0,
        };
        let idx = self.requests.len();
        self.requests.push(req);
        if bootstrap_ok {
            let r = &mut self.requests[idx];
            r.state = State::Approved;
            r.expires_at_ms = now_ms + APPROVED_MS;
            r.decision = Some(Decision {
                outcome: Outcome::Approve,
                decider: "bootstrap".into(),
                role: None,
                surface: Surface::Bootstrap,
                factor: Factor::Bootstrap,
                presence: PresenceClass::NotApplicable,
                factor_label: "bootstrap".into(),
                at_ms: now_ms,
                evidence: Evidence::default(),
                proven: None,
                via_fleet: None,
            });
        }
        Ok(Filed {
            request: self.requests[idx].clone(),
            existing: false,
        })
    }

    /// The challenge a dashboard assertion for this request is made over, built here and never chosen by the dashboard.
    pub fn challenge_for(&self, ctx: &Ctx, id: &str, outcome: Outcome) -> Result<[u8; 32], String> {
        let r = self.get(id).ok_or(NOT_FOUND)?;
        let d = from_hex(&r.subject_digest).ok_or("the request is damaged")?;
        let mut digest = [0u8; 32];
        if d.len() != 32 {
            return Err("the request is damaged".into());
        }
        digest.copy_from_slice(&d);
        Ok(decide_challenge(&ctx.ids, id, &digest, outcome.word()))
    }

    /// Decide a request: a compare-and-set on `pending` (two people at once: the first wins, the second is told who and
    /// how). A deny of an approved, unspent request is a revoke, from an approver of the same or higher authority.
    pub fn decide(
        &mut self,
        ctx: &Ctx,
        now_ms: u64,
        id: &str,
        input: DecideInput,
    ) -> Result<Request, String> {
        self.sweep(now_ms);
        self.void_bootstrap_if_enrolled(ctx);
        let idx = self
            .requests
            .iter()
            .position(|r| r.id == id)
            .ok_or(NOT_FOUND)?;
        let req = self.requests[idx].clone();
        if req.epoch != self.epoch {
            return Err("requests were reset by a restore: ask again".into());
        }
        // who may decide at all: the box user never does, and a hub agent only relays a Deny (phase 4 verifies the rest)
        match input.class {
            SocketClass::Box => {
                return Err("the box user cannot decide a request, least of all its own".into())
            }
            SocketClass::HubAgent
                if input.outcome != Outcome::Deny || req.state != State::Pending =>
            {
                return Err("a decision from another box is verified by that box's own service (not built in this release)".into());
            }
            _ => {}
        }
        match (req.state, input.outcome) {
            (State::Pending, Outcome::Approve | Outcome::Deny) => {}
            (State::Approved, Outcome::Deny | Outcome::Revoke) => {}
            (State::Pending, Outcome::Revoke) => {
                return Err("there is nothing approved to revoke".into())
            }
            (State::Approved, Outcome::Approve) | (State::Denied, _) => {
                return Err(req.decision.as_ref().map_or_else(
                    || format!("the request is {}", req.state.as_str()),
                    decided_sentence,
                ))
            }
            (s, _) => return Err(format!("the request is {}", s.as_str())),
        }
        let key = input.key.as_ref();
        let mut presence = match (input.factor, key) {
            (Factor::LaptopKey, Some(k)) if k.presence_proved && k.key_type.is_fido2() => {
                PresenceClass::Proved
            }
            (Factor::LaptopKey, _) => PresenceClass::NoPresence,
            _ => PresenceClass::NotApplicable,
        };
        let revoking = req.state == State::Approved;
        let outcome = if revoking {
            Outcome::Revoke
        } else {
            input.outcome
        };
        let mut new_counter: Option<(String, u32)> = None;
        let mut new_seen: Option<String> = None;
        let mut proven: Option<Proven> = None;

        if input.outcome == Outcome::Approve {
            let c = self.check_approval(ctx, &req, &input, presence)?;
            new_counter = c.counter;
            new_seen = Some(c.seen);
            proven = c.proven;
        } else {
            // a Deny is fail safe, but still comes from someone the box knows
            check_deny_actor(&input, key)?;
            // over the sealed route a deny or a revoke is signed like an approval, over its own outcome word, so a key id
            // someone only names cannot take down an approval. A revoke is signed as `revoke`.
            if input.class == SocketClass::Ingress {
                let word = if revoking {
                    Outcome::Revoke
                } else {
                    Outcome::Deny
                };
                let k = key.ok_or("that key is not enrolled on this box")?;
                let e = input
                    .evidence
                    .laptop
                    .as_ref()
                    .ok_or("a laptop deny or revoke carries its signature")?;
                if e.key_id != k.id || e.key_type != k.key_type {
                    return Err("the signature is not from the key it names".into());
                }
                let digest = from_hex(&req.subject_digest)
                    .filter(|d| d.len() == 32)
                    .ok_or("the request is damaged")?;
                let mut d32 = [0u8; 32];
                d32.copy_from_slice(&digest);
                let want = Expected::new(&ctx.ids, &req.id, &d32, word.word());
                let v = verify_laptop(k, e, &want)?;
                // a key's presence class counts only when this signature was made with a touch
                if presence == PresenceClass::Proved {
                    if !v.up() {
                        presence = PresenceClass::NoPresence;
                    } else if let Some(c) = v.counter() {
                        let kc = format!("key:{}", k.id);
                        self.check_counter(&kc, c)?;
                        new_counter = Some((kc, c));
                    }
                }
                new_seen = Some(assertion_hash(&k.id, &req.id, word));
                proven = Some(Proven {
                    up: v.up(),
                    uv: v.uv(),
                    counter: v.counter(),
                });
            }
            if revoking {
                let mine = Decision {
                    outcome,
                    decider: input.decider.clone(),
                    role: input.role,
                    surface: input.surface,
                    factor: input.factor,
                    presence,
                    factor_label: String::new(),
                    at_ms: now_ms,
                    evidence: Evidence::default(),
                    proven: None,
                    via_fleet: None,
                }
                .authority();
                let theirs = req.decision.as_ref().map_or(0, Decision::authority);
                if input.factor == Factor::ChatDeny || mine < theirs {
                    return Err(
                        "an approval is revoked by an approver of the same or higher authority"
                            .into(),
                    );
                }
            }
        }

        if let Some(s) = new_seen {
            if self.seen.contains(&s) {
                return Err("that assertion was already used".into());
            }
            self.seen.push(s);
            if self.seen.len() > MAX_SEEN {
                self.seen.remove(0);
            }
        }
        if let Some((k, c)) = new_counter {
            if c != 0 {
                self.counters.insert(k, c);
            }
        }

        let label = match (input.factor, key) {
            (Factor::LaptopKey, Some(k)) if presence == PresenceClass::Proved => {
                format!("laptop-key:{}", k.id)
            }
            (Factor::LaptopKey, Some(k)) => format!("laptop-key:{} (no user presence)", k.id),
            _ => factor_label(input.factor, key),
        };
        // a laptop key's decider is the key's own id, from the service's record, never what the caller named
        let decider = match (input.factor, key) {
            (Factor::LaptopKey, Some(k)) => k.id.clone(),
            _ => input.decider.clone(),
        };
        let decision = Decision {
            outcome,
            decider,
            role: input.role,
            surface: input.surface,
            factor: input.factor,
            presence,
            factor_label: label,
            at_ms: now_ms,
            evidence: input.evidence.clone(),
            proven,
            via_fleet: input.via_fleet.clone(),
        };
        let cooling = outcome == Outcome::Approve
            && matches!(&req.subject, Subject::SignerEnroll(s) if s.action == EnrolAction::Enrol)
            && input.factor == Factor::Passkey
            && ctx.ever_key;
        let slot = req.slot.clone();
        {
            let r = &mut self.requests[idx];
            r.state = match outcome {
                Outcome::Approve => State::Approved,
                Outcome::Deny | Outcome::Revoke => State::Denied,
            };
            if outcome == Outcome::Approve {
                r.not_before_ms = if cooling { now_ms + COOLING_OFF_MS } else { 0 };
                r.expires_at_ms = r.not_before_ms.max(now_ms) + APPROVED_MS;
            }
            r.decision = Some(decision);
        }
        // approving the new request supersedes the approved one it replaced
        if outcome == Outcome::Approve {
            for r in &mut self.requests {
                if r.id != id && r.slot == slot && r.state == State::Approved {
                    r.state = State::Superseded;
                    r.superseded_by = Some(id.to_string());
                }
            }
        }
        Ok(self.requests[idx].clone())
    }

    /// The rules for an approval: the factor, the surface, the role, the scope's cell and the evidence. Returns the counter
    /// and the assertion hash to remember once the decision is taken, and what the signature proved.
    fn check_approval(
        &self,
        ctx: &Ctx,
        req: &Request,
        input: &DecideInput,
        presence: PresenceClass,
    ) -> Result<Checked, String> {
        let rule = rule_for(req.scope.as_str()).ok_or("that scope is not known")?;
        if input.surface == Surface::Telegram {
            return Err("Telegram never approves a request: open the card in the dashboard".into());
        }
        if req.subject.production_looking() {
            return Err("a Production-looking value is released through a Production use (ADR 0029), not an override".into());
        }
        match input.factor {
            Factor::Passkey => {
                if input.class != SocketClass::Supervisor || input.surface != Surface::Dashboard {
                    return Err("a passkey decides on the dashboard, through the supervisor".into());
                }
                let role = input.role.ok_or("the person's role is not known")?;
                if role == Role::Viewer {
                    return Err("a viewer cannot decide a request".into());
                }
                let p = input
                    .evidence
                    .passkey
                    .as_ref()
                    .ok_or("a dashboard decision carries its passkey assertion")?;
                if p.credential_id.is_empty() || p.signature.is_empty() {
                    return Err("the assertion is incomplete".into());
                }
                // the challenge, the flags and the counter come out of the signed bytes, never from separate fields
                let want = self.challenge_for(ctx, &req.id, Outcome::Approve)?;
                let rp = input
                    .passkey_rp
                    .as_ref()
                    .ok_or("the dashboard's relying party is not known")?;
                let v = verify_passkey_bytes(p, &want, rp)?;
                dashboard_cell(req, role, ctx)?;
                // an owner-only change needs user verification as well as a touch, as it does for a laptop key
                if owner_only(req) && !v.uv() {
                    return Err("this change needs user verification as well as a touch".into());
                }
                let key = format!("passkey:{}", p.credential_id);
                self.check_counter(&key, v.counter())?;
                Ok(Checked {
                    counter: Some((key, v.counter())),
                    seen: assertion_hash(&p.credential_id, &req.id, Outcome::Approve),
                    proven: Some(Proven {
                        up: v.up(),
                        uv: v.uv(),
                        counter: Some(v.counter()),
                    }),
                })
            }
            Factor::LaptopKey => {
                if input.class != SocketClass::Ingress || input.surface != Surface::Laptop {
                    return Err("a laptop key decides over the sealed route from the laptop".into());
                }
                let key = input
                    .key
                    .as_ref()
                    .ok_or("that key is not enrolled on this box")?;
                if !key.active {
                    return Err("that key was revoked".into());
                }
                let e = input
                    .evidence
                    .laptop
                    .as_ref()
                    .ok_or("a laptop decision carries its signature")?;
                if e.key_id != key.id || e.key_type != key.key_type {
                    return Err("the signature is not from the key it names".into());
                }
                if e.signed_message.is_empty() || e.signature.is_empty() {
                    return Err("the signature is incomplete".into());
                }
                // the signature is checked with the service's own record of the key, over this request's own message,
                // and the flags, the counter and the challenge are parsed from the signed bytes
                let digest = from_hex(&req.subject_digest)
                    .filter(|d| d.len() == 32)
                    .ok_or("the request is damaged")?;
                let mut d32 = [0u8; 32];
                d32.copy_from_slice(&digest);
                let want = Expected::new(&ctx.ids, &req.id, &d32, Outcome::Approve.word());
                let v = verify_laptop(key, e, &want)?;
                if req.requester.kind == RequesterKind::LaptopKey
                    && req.requester.key_id.as_deref() == Some(key.id.as_str())
                {
                    return Err("the requester never approves its own request".into());
                }
                if rule.key == "secret-use" || !rule.laptop_presence {
                    return Err("a laptop key does not decide that".into());
                }
                let mut counter = None;
                match presence {
                    PresenceClass::Proved => {
                        // attestation shows where a key lives, not that this signature was made with a touch
                        if !v.up() {
                            return Err(
                                "that signature was made without a touch (user presence)".into()
                            );
                        }
                        if owner_only(req) && !v.uv() {
                            return Err(
                                "this change needs user verification as well as a touch".into()
                            );
                        }
                        let k = format!("key:{}", key.id);
                        if let Some(c) = v.counter() {
                            self.check_counter(&k, c)?;
                            counter = Some((k, c));
                        }
                    }
                    _ => software_cell(req)?,
                }
                Ok(Checked {
                    counter,
                    seen: assertion_hash(&e.key_id, &req.id, Outcome::Approve),
                    proven: Some(Proven {
                        up: v.up(),
                        uv: v.uv(),
                        counter: v.counter(),
                    }),
                })
            }
            Factor::Root => {
                if input.class != SocketClass::Admin || input.surface != Surface::Root {
                    return Err("root decides on the admin socket".into());
                }
                if !rule.journal {
                    return Err("that is not decided here".into());
                }
                Ok(Checked {
                    counter: None,
                    seen: format!("root:{}:{}", req.id, req.subject_digest),
                    proven: None,
                })
            }
            Factor::Authenticator => {
                if input.class != SocketClass::Supervisor || input.surface != Surface::Dashboard {
                    return Err(
                        "an authenticator code decides on the dashboard, through the supervisor"
                            .into(),
                    );
                }
                let role = input.role.ok_or("the person's role is not known")?;
                if role == Role::Viewer {
                    return Err("a viewer cannot decide a request".into());
                }
                let a = input.evidence.authenticator.as_ref().ok_or(
                    "a dashboard decision carries the service's check of the authenticator code",
                )?;
                dashboard_cell(req, role, ctx)?;
                // one time step decides once per person: the step is the counter, and it must move forward
                let step =
                    u32::try_from(a.step).map_err(|_| "that code is not valid".to_string())?;
                if step == 0 {
                    return Err("that code is not valid".into());
                }
                let key = format!("totp:{}", input.decider);
                if self.counters.get(&key).is_some_and(|last| step <= *last) {
                    return Err(
                        "that authenticator code was already used: wait for the next one".into(),
                    );
                }
                Ok(Checked {
                    counter: Some((key, step)),
                    seen: assertion_hash(
                        &format!("totp:{}", input.decider),
                        &req.id,
                        Outcome::Approve,
                    ),
                    proven: Some(Proven {
                        up: true,
                        uv: true,
                        counter: Some(step),
                    }),
                })
            }
            Factor::Bootstrap | Factor::ChatDeny | Factor::Session => {
                Err("that is not a way to approve a request".into())
            }
        }
    }

    fn check_counter(&self, key: &str, counter: u32) -> Result<(), String> {
        // synced passkeys commonly report 0: checked when non-zero, refused if it goes back
        match (counter, self.counters.get(key)) {
            (0, _) => Ok(()),
            (c, Some(last)) if c <= *last => {
                Err("that assertion's counter went back: the key may have been cloned".into())
            }
            _ => Ok(()),
        }
    }

    /// Cancel (the person withdraws it, or an approver stops a pending enrolment during its cooling-off).
    pub fn cancel(&mut self, now_ms: u64, id: &str, class: SocketClass) -> Result<Request, String> {
        self.sweep(now_ms);
        if !op_allowed(class, Op::Cancel) {
            return Err("that is not allowed on this socket".into());
        }
        let r = self.get_mut(id).ok_or(NOT_FOUND)?;
        match r.state {
            State::Pending => {}
            // withdrawing an approval is a revoke, and a revoke needs the same or higher authority than whoever approved:
            // the only approved request anyone may cancel is an enrolment still in its cooling-off, and root,
            // whose authority is the highest, may cancel any
            State::Approved => {
                let cooling = now_ms < r.not_before_ms;
                if !cooling && class != SocketClass::Admin {
                    return Err("an approval is withdrawn by a revoke from an approver of the same or higher authority, not by a cancel".into());
                }
            }
            s => return Err(format!("the request is {}", s.as_str())),
        }
        r.state = State::Cancelled;
        r.void_reason = Some(format!("cancelled from the {class:?} socket"));
        Ok(r.clone())
    }

    /// The supervisor pushes this when a person is demoted or removed: what they approved and nobody spent is void.
    pub fn decider_revoked(&mut self, person: &str) -> Vec<String> {
        let mut out = Vec::new();
        for r in &mut self.requests {
            if r.state == State::Approved
                && r.decision.as_ref().is_some_and(|d| {
                    matches!(d.factor, Factor::Passkey | Factor::Authenticator)
                        && d.decider == person
                })
            {
                r.state = State::Denied;
                r.void_reason = Some("the person who approved it was removed or demoted".into());
                out.push(r.id.clone());
            }
        }
        out
    }

    /// Begin a spend: compare-and-set `approved` to `spending`. The caller recomputed its own subject; if it differs from
    /// what was approved the spend is refused, says which fields differ, and **the approval stays**. `decider_active` says
    /// whether whoever approved is still valid (a revoked laptop key voids it).
    pub fn begin_spend(
        &mut self,
        ctx: &Ctx,
        now_ms: u64,
        id: &str,
        via: SpendVia,
        subject: &Subject,
        decider_active: &dyn Fn(&Decision) -> bool,
    ) -> Result<Request, SpendRefusal> {
        self.sweep(now_ms);
        self.void_bootstrap_if_enrolled(ctx);
        // a refused spend from the box user's socket is counted, so a flood of them cannot be used to flood
        let refuse = |this: &mut Self, mut reason: SpendRefusal| -> SpendRefusal {
            if let SpendVia::Socket {
                class: SocketClass::Box,
                uid,
            } = via
            {
                // counted per uid and request: an agent that fails to spend requests of its own cannot lock the person's
                // own hook out of theirs. Only an id of the service's shape is added, and the list is
                // bounded per uid and in all, so fresh ids cannot grow it (phase 2 re-check NM2). The ceilings stop the
                // adding only; they never refuse a spend (round 4 RM1).
                let who = uid.map_or_else(|| "-".to_string(), |u| u.to_string());
                let mine = format!("{who}:");
                let n = this
                    .refused_spends
                    .iter()
                    .filter(|(w, _)| w.starts_with(&mine))
                    .count();
                if request_id_ok(id)
                    && n < REFUSED_SPENDS_PER_UID_PER_HOUR
                    && this.refused_spends.len() < REFUSED_SPENDS_MAX
                {
                    this.refused_spends.push((format!("{who}:{id}"), now_ms));
                    reason.changed = true;
                }
            }
            reason
        };
        if let SpendVia::Socket {
            class: SocketClass::Box,
            uid,
        } = via
        {
            // the only thing that refuses a spend is the count for this uid and this request. The per-uid and total ceilings
            // bound the list, never the answer: made-up ids must not lock the person's own hook out of its approved
            // request (phase 2 round 4 RM1).
            let who = uid.map_or_else(|| "-".to_string(), |u| u.to_string());
            let k = format!("{who}:{id}");
            if self.refused_spends.iter().filter(|(w, _)| *w == k).count()
                >= REFUSED_SPENDS_PER_HOUR
            {
                return Err(SpendRefusal::new(
                    "too many refused spends in the last hour: wait",
                ));
            }
        }
        let Some(idx) = self.requests.iter().position(|r| r.id == id) else {
            return Err(refuse(self, SpendRefusal::new(NOT_FOUND)));
        };
        let req = self.requests[idx].clone();
        let rule = rule_for(req.scope.as_str());
        if let SpendVia::Socket { class, uid } = via {
            // spend comes only from the socket class that recomputes
            let ok = match rule.map(|r| r.spend_by) {
                Some(SpendBy::BoxSocket) => class == SocketClass::Box,
                Some(SpendBy::AdminSocket) => class == SocketClass::Admin,
                _ => false,
            };
            if !ok {
                return Err(refuse(
                    self,
                    SpendRefusal::new(
                        "that scope is not spent from this socket; the approval is kept",
                    ),
                ));
            }
            if class == SocketClass::Box
                && (req.requester.uid.is_none() || req.requester.uid != uid)
            {
                return Err(refuse(self, SpendRefusal::new(NOT_FOUND)));
            }
        } else if rule.map(|r| r.spend_by) != Some(SpendBy::Inside) {
            // an operation inside the service spends only a scope that is spent inside
            return Err(refuse(
                self,
                SpendRefusal::new("that scope is spent from its own socket"),
            ));
        }
        if req.epoch != self.epoch {
            return Err(SpendRefusal::new(
                "requests were reset by a restore: ask again",
            ));
        }
        match req.state {
            State::Approved => {}
            State::Spending => {
                return Err(SpendRefusal::new(
                    "a spend of this request was interrupted: it is refused and shown, never spent twice",
                ))
            }
            State::Spent => return Err(refuse(self, SpendRefusal::new("this approval was already used"))),
            s => return Err(refuse(self, SpendRefusal::new(&format!("the request is {}", s.as_str())))),
        }
        if now_ms < req.not_before_ms {
            return Err(SpendRefusal::new(&format!(
                "this key cannot approve until {}",
                hhmm(req.not_before_ms)
            )));
        }
        if let Some(d) = &req.decision {
            if !decider_active(d) {
                let r = &mut self.requests[idx];
                r.state = State::Denied;
                r.void_reason =
                    Some("the key or person that approved it is no longer valid".into());
                let mut e =
                    SpendRefusal::new("the approver is no longer valid: the approval is void");
                e.changed = true;
                return Err(e);
            }
        }
        let digest = subject
            .digest_hex(&ctx.ids)
            .map_err(|e| SpendRefusal::new(&e.0))?;
        if digest != req.subject_digest || subject.scope() != req.scope.as_str() {
            let fields = req.subject.differing_fields(subject);
            let r = &mut self.requests[idx];
            r.wrong_answers = r.wrong_answers.saturating_add(1);
            let _ = refuse(self, SpendRefusal::new(""));
            return Err(SpendRefusal {
                message: "what is being done is not what was approved: the approval is kept for what it was for".into(),
                differs: fields,
                digest_mismatch: true,
                changed: true,
            });
        }
        let r = &mut self.requests[idx];
        r.state = State::Spending;
        Ok(r.clone())
    }

    /// Put a `spending` request back to `approved`: the audit line could not be written, so no effect happened.
    pub fn abort_spend(&mut self, id: &str) {
        if let Some(r) = self.get_mut(id) {
            if r.state == State::Spending {
                r.state = State::Approved;
            }
        }
    }

    /// The effect happened: `spending` becomes `spent`.
    pub fn finish_spend(&mut self, id: &str) -> Result<Request, String> {
        let r = self.get_mut(id).ok_or(NOT_FOUND)?;
        if r.state != State::Spending {
            return Err(format!(
                "the request is {}, not being spent",
                r.state.as_str()
            ));
        }
        r.state = State::Spent;
        Ok(r.clone())
    }

    /// What a box user may list: its own live requests, as the narrow view.
    pub fn box_list(&self, uid: Option<u32>) -> Vec<BoxView> {
        self.requests
            .iter()
            .filter(|r| {
                r.requester.kind == RequesterKind::BoxUser
                    && r.requester.uid == uid
                    && uid.is_some()
                    && !r.state.is_terminal()
            })
            .map(Request::box_view)
            .collect()
    }

    pub fn box_get(&self, uid: Option<u32>, id: &str) -> Option<BoxView> {
        self.get(id)
            .filter(|r| {
                r.requester.kind == RequesterKind::BoxUser
                    && uid.is_some()
                    && r.requester.uid == uid
            })
            .map(Request::box_view)
    }
}

/// What the rules took from a decision's evidence.
struct Checked {
    counter: Option<(String, u32)>,
    seen: String,
    proven: Option<Proven>,
}

pub const NOT_FOUND: &str = "that request could not be found";

/// How a spend arrives.
#[derive(Debug, Clone, Copy)]
pub enum SpendVia {
    /// A separate `spend` on a socket.
    Socket {
        class: SocketClass,
        uid: Option<u32>,
    },
    /// Inside the operation itself (`import`, `policy`, `signer-enroll`, `worker-keys`, `setup-code`, `kek-export`).
    Inside,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendRefusal {
    pub message: String,
    /// Which fields differ, by name, never a value.
    pub differs: Vec<&'static str>,
    pub digest_mismatch: bool,
    /// Whether the refusal changed the book (a counter moved, a request was voided): only then is the journal rewritten.
    pub changed: bool,
}

impl SpendRefusal {
    fn new(m: &str) -> Self {
        SpendRefusal {
            message: m.to_string(),
            differs: Vec::new(),
            digest_mismatch: false,
            changed: false,
        }
    }
}

/// What a decision is remembered by: the request, the key (or credential) and the outcome, **never the signature bytes**:
/// an ECDSA signature can be rewritten as `(r, n - s)` and still verify, so a seen-set keyed by the bytes would
/// call the rewrite new.
fn assertion_hash(key_id: &str, request_id: &str, outcome: Outcome) -> String {
    crate::approval_subject::sha256_hex(&format!("{key_id}\n{request_id}\n{}", outcome.word()))
}

/// Why a scope is refused before a second factor exists.
pub fn bootstrap_refusal(scope: Scope) -> String {
    format!(
        "this box has no second factor enrolled, so nothing here can approve a {} change (the box user asking is not an approval). Enrol a passkey in the dashboard, or make the box with `ozbox create` from a computer with a keychain, then ask again",
        scope.as_str()
    )
}

fn check_deny_actor(input: &DecideInput, key: Option<&KeyView>) -> Result<(), String> {
    match input.class {
        SocketClass::Supervisor => match input.role {
            Some(Role::Owner | Role::Member) => Ok(()),
            _ => Err("a viewer cannot decide a request".into()),
        },
        SocketClass::Admin => Ok(()),
        SocketClass::Ingress => match key {
            Some(k) if k.active => Ok(()),
            _ => Err("that key is not enrolled on this box".into()),
        },
        // a relayed Deny of a pending request needs no credential: `main` could deny by silence anyway
        SocketClass::HubAgent => Ok(()),
        SocketClass::Box => Err("the box user cannot decide a request".into()),
    }
}

/// Whether the change needs the owner (and so a laptop key's user verification), not a member.
fn owner_only(req: &Request) -> bool {
    match req.scope {
        Scope::GuardOverride => false,
        Scope::Import => !import_member_ok(req),
        _ => true,
    }
}

fn import_member_ok(req: &Request) -> bool {
    !req.subject.production() && !req.subject.any_public() && !req.derived.replaces_existing
}

fn sensitivity(req: &Request) -> PolicySensitivity {
    match &req.subject {
        Subject::Policy(p) => p.sensitivity,
        _ => PolicySensitivity::Ordinary,
    }
}

/// The dashboard cell of the table for one request and one role.
fn dashboard_cell(req: &Request, role: Role, ctx: &Ctx) -> Result<(), String> {
    let owner = role == Role::Owner;
    let need_owner = || {
        if owner {
            Ok(())
        } else {
            Err("this change is for the owner".to_string())
        }
    };
    match req.scope {
        Scope::GuardOverride => Ok(()),
        Scope::Import => {
            if import_member_ok(req) {
                Ok(())
            } else {
                need_owner()
            }
        }
        Scope::Policy => {
            need_owner()?;
            match sensitivity(req) {
                PolicySensitivity::WidensGuarded if ctx.ever_presence_key => Err("widening a guarded scope is decided by a laptop key with presence, or root, once one has been enrolled".into()),
                PolicySensitivity::WidensGuarded | PolicySensitivity::Ordinary => Ok(()),
            }
        }
        Scope::TunnelToken | Scope::HostGuard => {
            need_owner()?;
            if ctx.ever_presence_key {
                Err("a laptop key with presence has been enrolled on this box, so this is decided by that key or by root, not the dashboard".into())
            } else {
                Ok(())
            }
        }
        Scope::WorkerKeys if req.subject.production() => Err("a worker key whose name says production is decided by a laptop key with presence, or root, never the dashboard".into()),
        Scope::BoxSecrets | Scope::WorkerKeys => need_owner(),
        Scope::SignerEnroll => need_owner(),
        Scope::SetupCode | Scope::KekExport => Err("this is decided on the laptop with a presence key, or by root, never on the dashboard".into()),
        Scope::SecretUse => Err("a Production use is decided through its issuer".into()),
    }
}

/// Whether a viewer in `role` (`None`: a dashboard with no sign-in) may approve `req` from the dashboard right now, and if
/// not, the sentence to show. The same rule `decide` applies, so a card never offers what the service would refuse.
pub fn dashboard_can_approve(req: &Request, role: Option<Role>, ctx: &Ctx) -> Result<(), String> {
    let role = role.ok_or(
        "this dashboard has no sign-in, so nothing can be decided here: use the laptop or root",
    )?;
    if role == Role::Viewer {
        return Err("a viewer cannot decide a request".into());
    }
    if req.state != State::Pending {
        return Err(req.state_sentence());
    }
    if req.subject.production_looking() {
        return Err("a Production-looking value is released through a Production use (ADR 0029), not an override".into());
    }
    dashboard_cell(req, role, ctx)
}

/// Whether a viewer in `role` may deny a pending request, or revoke an approved one that nobody has spent.
pub fn dashboard_can_deny(req: &Request, role: Option<Role>) -> Result<(), String> {
    let role = role.ok_or(
        "this dashboard has no sign-in, so nothing can be decided here: use the laptop or root",
    )?;
    if role == Role::Viewer {
        return Err("a viewer cannot decide a request".into());
    }
    match req.state {
        State::Pending => Ok(()),
        State::Approved => {
            // a revoke needs the same or higher authority than whoever approved it
            let theirs = req.decision.as_ref().map_or(0, Decision::authority);
            let mine = match role {
                Role::Owner => 3,
                _ => 2,
            };
            if mine < theirs {
                Err("an approval is revoked by an approver of the same or higher authority".into())
            } else {
                Ok(())
            }
        }
        _ => Err(req.state_sentence()),
    }
}

/// The software-key cell: what a key with no proved presence may decide. Owner decision B: **never** an owner-only scope,
/// and there is no setting that turns that on.
fn software_cell(req: &Request) -> Result<(), String> {
    if req.subject.production() {
        return Err("a software key never decides Production: approve it in the dashboard (Approvals) with your passkey or authenticator code (an owner), with a laptop key that needs a touch, or as root".into());
    }
    match req.scope {
        Scope::GuardOverride => Ok(()),
        Scope::Import if import_member_ok(req) => Ok(()),
        Scope::Import
        | Scope::Policy
        | Scope::BoxSecrets
        | Scope::WorkerKeys
        | Scope::TunnelToken
        | Scope::HostGuard
        | Scope::SignerEnroll
        | Scope::SetupCode
        | Scope::KekExport
        | Scope::SecretUse => Err(
            "a software key does not decide this: approve it in the dashboard (Approvals) with your passkey or authenticator code (an owner), with a laptop key that needs a touch, or as root"
                .to_string(),
        ),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
